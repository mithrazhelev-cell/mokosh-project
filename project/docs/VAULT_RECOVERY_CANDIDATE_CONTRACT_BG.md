# MOKOSH — In-memory Vault Recovery Candidate Contract v1

Статус: Stage 2.6 — реализиран strict in-memory recovery candidate и
process-local one-shot authorization, без filesystem publish.

Този договор е следващата ограничена стъпка след Stage 2.4 recovery record и
Stage 2.5 private durable `.mokr` storage. Той създава нов encrypted Vault
candidate с изрично зададена нова парола, но не го записва като истинско Vault
поколение.

## 1. Смисъл за потребителя

Когато нормалната Vault парола е загубена, но потребителят притежава:

1. exact текущото durable Vault поколение;
2. exact private `.mokr` recovery record за това поколение;
3. отделния exact 32-byte recovery root;
4. нова парола, избрана изрично от него;

MOKOSH може да възстанови keyring-а вътрешно и да създаде в паметта нов
encrypted Vault candidate. Старият password не е необходим и няма fallback
към него.

Stage 2.6 още не записва candidate-а във Vault директорията. След операцията
истинската immutable history остава непроменена.

## 2. Trust и scope граница

Stage 2.6 стъпва върху замразените договори:

- Stage 2.2 — latest durable Vault receipt и clean contiguous history;
- Stage 2.3 — canonical schema-2 keyring с exact active/retired history;
- Stage 2.4 — authenticated recovery record и exact recovery root;
- Stage 2.5 — private single-link `.mokr` file и bounded double read.

Той не променя `MOKVLT1` Vault формата и не добавя recovery metadata в Vault
header или payload. Candidate-ът е нормален schema-2 Vault container.

## 3. Задължителни входове

`prepare_recovery_candidate` изисква:

- explicit canonical `.mokr` path;
- exact 32-byte recovery root;
- open `VaultStorage`;
- exact latest durable `VaultGenerationReceipt`;
- explicit new password;
- exact enum decision `AUTHORIZE_CANDIDATE`;
- Argon2id параметри и local `VaultKDFPolicy`;
- optional strict UTC `updated_utc`.

Няма параметър за old/current password, output path, publish, overwrite,
cleanup или key deletion.

Decision `PRESERVE`, text вместо enum, boolean или друг невалиден decision
отказват преди filesystem source read и преди Argon2id.

## 4. New-password и KDF policy

Новата парола следва frozen Vault format границата: валиден UTF-8 text от 1 до
1024 bytes. Stage 2.6 не твърди password-strength оценка; GUI policy и
потребителското потвърждение на паролата остават отделен бъдещ слой.

Argon2id `time_cost`, `memory_kib` и `parallelism` се проверяват срещу format
bounds и local resource policy преди четене на recovery sources и преди KDF.
Boolean не е integer. Няма silent clamp или downgrade.

## 5. Exact latest Vault prerequisite

Преди recovery decrypt операцията доказва:

1. clean, complete и contiguous Vault storage scan;
2. presented receipt е exact latest generation;
3. receipt и generation bytes съвпадат по directory/file identity, size,
   Vault ID, revision и SHA-256;
4. source payload schema е точно `2`;
5. revision не е изчерпал `MAX_VAULT_REVISION`.

Dirty history, gap, unknown object, forged/nonlatest receipt, mixed Vault или
revision exhaustion отказват преди recovery file decrypt.

Receipt не е независим anti-rollback trust anchor срещу attacker, който може
да върне назад цялата Vault директория и всички локални receipts. Това
ограничение от Stage 2.2 остава.

## 6. Recovery file prerequisite

Recovery file се отваря чрез Stage 2.5 strict private reader:

- canonical filename, свързан с authenticated Recovery ID;
- private `0700` parent без symlink;
- private owned `0600` regular file;
- точно един hard link;
- bounded exact read чрез descriptor;
- стабилни directory/file identities и mutation signature;
- strict Stage 2.4 parse.

Stage 2.4 rehearsal доказва exact Vault ID, source revision, source Vault
SHA-256 и recovery-root authentication. Stale, rollback, same-revision byte
conflict, mixed-vault, wrong root, tamper или malformed record отказват.

## 7. Internal keyring recovery

Само след успешната read-only rehearsal Stage 2.6 decrypt-ва keyring-а в
паметта чрез frozen Stage 2.4 AEAD contract.

Проверяват се отново:

- recovery header/payload binding;
- canonical schema-2 keyring;
- contiguous key versions;
- exact active/retired states и retirement timeline;
- unique wrapping-key material;
- exact keyring SHA-256 от rehearsal evidence.

Keyring не се връща от public verifier, не се записва на path и не се включва
в authorization evidence.

## 8. Candidate construction

Candidate-ът се създава чрез frozen schema-2 Vault sealing contract:

- Vault ID се запазва exact;
- първоначалният `created_utc` се запазва exact;
- revision става точно `source_revision + 1`;
- payload schema остава точно `2`;
- целият exact keyring се запазва без rotation, migration или deletion;
- `updated_utc` не може да предхожда source Vault или recovery record;
- генерират се нови CSPRNG 16-byte salt и 12-byte AES-GCM nonce;
- Argon2id извежда KEK от explicit new password;
- AES-256-GCM запечатва authenticated candidate payload.

Candidate-ът съществува само като immutable Python `bytes` в паметта. Не се
извиква Stage 2.2 publish и не се създава generation `R+1` на filesystem.

## 9. Independent candidate verification

Преди да бъде върнат prepared object, candidate-ът се проверява с новата
парола:

1. exact candidate SHA-256;
2. strict Vault parse и local KDF policy;
3. schema `2`, exact Vault ID и target revision;
4. exact timestamp и Argon2id parameters;
5. authenticated unlock с new password;
6. exact recovered keyring SHA-256, active version и key count.

Public `verify_recovery_candidate` връща само non-secret evidence. Wrong
password, candidate tamper, truncation, trailing bytes, schema mismatch,
rollback, KDF mismatch или keyring mismatch се отказват.

## 10. Non-secret evidence

`VaultRecoveryCandidateEvidence` съдържа:

- Recovery ID и Vault ID;
- source и target revision;
- source Vault, recovery record, keyring и candidate SHA-256;
- candidate `updated_utc` и exact Argon2id parameters;
- active key version и key count;
- recovery directory/file device и inode identities;
- recovery file encoded size.

Evidence не съдържа password, recovery root, keyring, wrapping key, plaintext,
path, filename или unencrypted candidate payload.

## 11. Две различни binding нива

Frozen Vault format cryptographically удостоверява само фактите, които са в
самия Vault container: Vault ID, target revision, timestamps, KDF policy и
encrypted keyring. Exact candidate digest обвързва всички candidate bytes.

Recovery ID, source Vault digest, `.mokr` digest и filesystem inode identities
не се добавят в Vault format. Те се обвързват от process-local authorization
след две exact source observations около candidate creation.

Затова source-only evidence не се представя като authenticated Vault header.
Това избягва недокументирана промяна на frozen формата и честно разделя
cryptographic proof от local workflow misuse prevention.

## 12. Double source verification

След candidate construction и password verification Stage 2.6:

1. чете `.mokr` файла повторно чрез Stage 2.5 strict reader;
2. доказва latest durable Vault повторно;
3. изпълнява recovery rehearsal повторно;
4. сравнява exact directory/file identities, size, digest и bytes;
5. сравнява exact current Vault bytes и rehearsal evidence.

Ако source се промени, candidate authorization не се създава. Candidate bytes
може временно да са съществували в процеса, но не са публикувани или върнати
като prepared success.

## 13. Process-local one-shot authorization

Едва след всички проверки се създава independent 16-byte CSPRNG authorization
ID и `PreparedVaultRecoveryCandidate`.

Authorization обвързва целия exact evidence object и изрично записва:

- user decision е потвърден;
- source и candidate verification са завършени;
- бъдещ executor трябва да направи нов rescan;
- claim е single-use;
- filesystem publish не е разрешен от Stage 2.6;
- key deletion и user-file mutation не са разрешени.

Prepared object и claimed object отказват copy, deepcopy и pickle. Candidate
може да се получи само чрез `claim_once`; втори claim отказва.

Това е process-local misuse-prevention contract, не digital signature, MAC или
защита срещу arbitrary code execution в същия компрометиран процес. Random
authorization ID сам по себе си не е cryptographic publish capability.

## 14. Fault и cancellation semantics

Fault при source verification, recovery decrypt, CSPRNG, Vault sealing,
candidate verification или second source verification:

- не променя Vault history;
- не променя recovery file;
- не създава output path;
- не връща prepared authorization;
- не изтрива ключ или потребителски файл.

Няма partial filesystem publish, защото Stage 2.6 няма filesystem mutation.
Cancellation преди success не се преобразува в false success.

## 15. Memory limitation

Python и общите OS среди не обещават доказуемо изтриване на всички временни
password, keyring, recovery-root или candidate copies от RAM, allocator, swap,
registers, crash dump или VM snapshot.

Stage 2.6 не пази password или recovery root в prepared/authorization objects,
ограничава secret lifetime и премахва локалните references best-effort. Това
не е абсолютна memory zeroization и не бива да се представя като такава.

## 16. Забранени действия

Stage 2.6 няма:

- filesystem Vault publish, generation create, overwrite, rename или replace;
- automatic recovery, latest-record selection или password guessing;
- key rotation, migration, retirement reversal, deletion или destruction;
- user-file decrypt/re-encrypt/mutation;
- GUI, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, update discovery, download или installation;
- server dependency.

## 17. Задължителни тестове

- exact next-revision round-trip с new password и wrong-old-password отказ;
- exact active/retired keyring preservation;
- explicit enum decision и invalid-input refusal преди source/KDF;
- KDF resource policy преди Argon2id;
- latest receipt, dirty history, stale, rollback, mixed-vault и byte-conflict
  отказ;
- wrong recovery root, tampered/noncanonical/hardlinked `.mokr` отказ;
- candidate tamper, truncation, trailing, wrong password и legacy-schema отказ;
- candidate header/KDF/keyring evidence mismatch отказ;
- deterministic candidate mutation corpus;
- double source change и fault injection без authorization success;
- one-shot claim, copy/deepcopy/pickle refusal;
- source inspection за липса на filesystem mutation, network и logging calls;
- доказателство, че prepared objects не пазят password или recovery root;
- доказателство, че Vault и recovery directories остават byte-for-byte
  непроменени.

Тестовете са вътрешно възпроизводимо доказателство за този contract. Те не са
независим одит, certification или доказателство за сигурна компрометирана OS.

## 18. Stage 2.7 integration boundary

Stage 2.7 реализира filesystem publish в отделен модул само с:

- нов explicit user publish decision;
- consumption на exact one-shot candidate;
- fresh double source/Vault rescan;
- exact previous receipt и target revision binding;
- Stage 2.2 no-clobber immutable publish;
- pre/post file и directory durability checks;
- uncertain semantics след publish boundary;
- никакво automatic key или old-generation deletion.

Stage 2.6 authorization с `filesystem_publish_permitted = false` не може сама
да се представя като завършено възстановяване. Stage 2.7 изисква нов exact enum
decision и сам консумира Stage 2.6 one-shot claim. Пълният договор е в
`docs/VAULT_RECOVERY_PUBLISH_CONTRACT_BG.md`.

## 19. Stage 2.8 reconciliation boundary

Stage 2.8 умишлено не приема prepared/claimed candidate. One-shot handoff-ът е
консумиран от Stage 2.7 и може да е изгубен при process interruption.

Вместо това observed `R+1` се проверява read-only чрез explicit old source
receipt, recovery record/root, new password и exact recovered keyring digest.
Това доказва surviving recovery invariants, но без запазен candidate digest не
се представя като byte-equality proof към изгубения ephemeral candidate.

Пълният договор е в
`docs/VAULT_RECOVERY_RECONCILIATION_CONTRACT_BG.md`.

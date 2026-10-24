# MOKOSH — Immutable Vault Recovery Publish Contract v1

Статус: Stage 2.7 — реализиран explicit no-clobber publish executor върху
замразените Stage 2.2–2.6 договори.

Този договор е първият recovery етап, който може да създаде истинско ново
Vault поколение. Той не променя recovery record формата, Vault container
формата или keyring lifecycle. Единствената разрешена mutation е Stage 2.2
immutable publish на exact проверения Stage 2.6 candidate.

## 1. Смисъл за потребителя

След загубена нормална Vault парола потребителят трябва вече да е създал
Stage 2.6 candidate чрез:

1. exact latest durable Vault поколение `R`;
2. exact private `.mokr` record за `R`;
3. отделния exact recovery root;
4. изрично избрана нова парола.

Stage 2.7 проверява всичко отново и при отделно изрично решение публикува
candidate-а като immutable поколение `R+1`. Новата парола отваря `R+1`, а
старият keyring с всички active и retired версии остава exact запазен.

Старото поколение `R` и `.mokr` файлът никога не се overwrite-ват или изтриват.

## 2. Trust и scope граница

Stage 2.7 стъпва върху:

- Stage 2.2 — private immutable generations и atomic no-clobber publish;
- Stage 2.3 — canonical schema-2 keyring history;
- Stage 2.4 — recovery-root authentication и exact source binding;
- Stage 2.5 — strict private `.mokr` read и durable recovery storage;
- Stage 2.6 — encrypted next-revision candidate и process-local one-shot
  authorization.

Той не е independent anti-rollback anchor. Attacker, който може съгласувано да
върне назад цялата Vault директория, recovery файловете и локалните receipts,
остава извън локалното receipt trust доказателство.

Stage 2.6 evidence обвързва source Vault ID/revision/digest, но не записва Vault
directory inode в candidate-а. Exact-byte clone със същия валиден receipt може
да бъде explicit избран storage target. Това не е скрито преместване: caller-ът
подава `VaultStorage`, а Stage 2.7 доказва exact content и no-clobber history.
Path/device identity не е cryptographically authenticated Vault metadata.

## 3. Задължителни входове

`publish_recovery_candidate` изисква:

- unclaimed `PreparedVaultRecoveryCandidate` от Stage 2.6;
- explicit canonical `.mokr` path;
- отделния exact 32-byte recovery root;
- open `VaultStorage`;
- exact latest durable source receipt за `R`;
- същата explicit new password, която отваря candidate-а;
- exact enum decision `AUTHORIZE_IMMUTABLE_PUBLISH`;
- local `VaultKDFPolicy`.

Няма output path, old/current password, overwrite, cleanup, rotation, migration,
key deletion или user-file параметър.

## 4. Explicit decision и one-shot consumption

`PRESERVE`, string вместо enum, boolean или друг невалиден decision отказват
преди candidate claim, filesystem source access и Argon2id.

Executor-ът сам извиква Stage 2.6 `claim_once`. Предварително claim-нат object
се отказва. След валидно publish решение claim се консумира дори ако следваща
source, password или publish проверка откаже. Retry изисква нов Stage 2.6
candidate от отново проверени exact sources.

Това е process-local misuse prevention, не цифров подпис, MAC или capability
срещу arbitrary code execution в компрометиран процес.

## 5. Input и KDF policy преди sources

Преди claim се проверяват:

- exact decision type/value;
- prepared object type и unclaimed state;
- `VaultStorage` и durable receipt types;
- recovery-root type и exact length;
- new-password frozen UTF-8 bounds;
- local KDF policy;
- candidate evidence bounds.

Candidate KDF трябва да е разрешен и от frozen default Stage 2.2 storage
policy. По-широк caller policy не може да накара Stage 2.7 да публикува Vault,
който frozen Stage 2.2 parser би отказал. Няма silent clamp или downgrade.

## 6. Exact Stage 2.6 handoff

След claim executor-ът доказва:

- exact `ClaimedVaultRecoveryCandidate` type;
- canonical Stage 2.6 authorization format/version/ID;
- authorization и claimed evidence са exact равни на prepared evidence;
- всички Stage 2.6 verification flags са true;
- Stage 2.6 mutation permissions остават false;
- candidate е bounded immutable `bytes`;
- candidate SHA-256 съвпада exact с evidence.

Stage 2.7 publish правото идва само от новото enum решение. То не променя и не
претълкува Stage 2.6 authorization като предварително filesystem разрешение.

## 7. Fresh source Vault verification

Преди candidate unlock се доказват:

1. clean, complete и contiguous Vault history;
2. presented receipt е exact latest generation `R`;
3. receipt, file identity, size и bytes още съвпадат;
4. source е schema `2` с exact Vault ID и revision;
5. source SHA-256 съвпада със Stage 2.6 evidence.

Dirty history, gap, unknown object, stale/nonlatest/forged receipt, mixed Vault,
target collision или changed source отказват преди publish.

## 8. Fresh recovery-file verification

Strict Stage 2.5 reader отново изисква:

- canonical filename и authenticated Recovery ID;
- private owned `0700` parent без symlink;
- private owned `0600` regular single-link file;
- bounded descriptor read;
- stable directory/file identities и mutation signature;
- exact record bytes и SHA-256 от Stage 2.6 evidence.

Stage 2.4 rehearsal с предоставения recovery root трябва отново да докаже exact
Vault ID, source revision/hash, keyring digest, active version и key count.
Wrong root, hardlink, tamper, stale, rollback или malformed record отказват.

## 9. Candidate password и keyring verification

Candidate-ът се проверява и unlock-ва отново чрез new password:

- exact Vault ID и target revision `R+1`;
- schema `2`, timestamp и Argon2id parameters;
- authenticated AES-256-GCM payload;
- exact keyring SHA-256;
- exact active key version и key count.

Създава се краткоживееща unlocked `VaultSession`, защото frozen Stage 2.2
publish приема само authenticated unlocked session. Wrong new password или
candidate tamper отказват без filesystem publish. Old password няма fallback.

## 10. Втора pre-publish проверка

Непосредствено преди Stage 2.2 mutation executor-ът:

1. доказва latest source Vault втори път;
2. чете и rehearses `.mokr` втори път;
3. сравнява exact source bytes;
4. сравнява recovery directory/file identities, size, digest и bytes;
5. сравнява rehearsal evidence;
6. прави fresh clean storage scan.

След това frozen `VaultStorage.publish` прави собствен scan и receipt binding.
Промяна във всеки prerequisite отказва fail-closed.

## 11. Единствена разрешена mutation

Stage 2.7 не отваря и не записва filesystem обекти директно. Единственият
mutation call е:

`VaultStorage.publish(candidate_session, previous=source_receipt)`.

Stage 2.2:

- създава private same-directory temporary с exclusive create;
- записва и `fsync`-ва exact candidate;
- прави exact readback;
- публикува с no-clobber hard link;
- `fsync`-ва директорията;
- премахва само собствения temporary link;
- `fsync`-ва отново;
- връща durable receipt след exact verification.

Final target никога не се overwrite-ва, rename-ва или replace-ва.

## 12. Publish boundary и uncertain semantics

Преди hard-link publish failure означава „не е потвърдено ново поколение“.
Owned single-link temporary може да бъде почистен само от Stage 2.2 при exact
identity match.

След като final hard link може да е станал видим, всеки fault се връща като
`VaultRecoveryPublishUncertainError`. Няма false success и няма rollback,
unlink или automatic cleanup на `R+1`.

При uncertain caller-ът трябва да спре mutation операциите и да използва
отделна read-only reconciliation процедура. Повторно publish „на сляпо“ не е
разрешено.

## 13. Independent post-publish verification

След durable receipt, но преди success result, Stage 2.7 доказва:

- receipt Vault ID, revision, SHA-256, size и durable flag;
- exact readback на `R+1` equals candidate bytes;
- exact readback на `R` equals original source bytes;
- clean complete history е точно previous generations плюс `R+1`;
- `R+1` отново се unlock-ва с new password и exact keyring evidence;
- `.mokr` file е byte/identity exact непроменен;
- recovery root още authenticates record-а спрямо запазеното `R`.

Post-publish verification failure е uncertain, защото `R+1` може вече да е
durable. Executor-ът не се опитва да го изтрие.

## 14. Non-secret success result

`VaultRecoveryPublishResult` съдържа само:

- Stage 2.6 authorization ID;
- Recovery/Vault ID;
- source/target revisions;
- source/record/keyring/candidate SHA-256;
- durable Stage 2.2 receipt;
- explicit preservation/stale/no-deletion flags.

Резултатът не съдържа password, recovery root, candidate bytes, keyring,
wrapping key, path, filename, plaintext или user-file metadata.

## 15. Recovery record след успех

Старият `.mokr` остава физически непроменен, но е валиден само за source `R`.
След публикуването latest е `R+1`, затова старият record умишлено е `stale`.

Нов recovery record/root може да се създаде само чрез отделен explicit Stage
2.5 setup върху unlocked latest `R+1`. Stage 2.7 не го създава, не върти root и
не записва recovery key автоматично.

## 16. Key и user-data граница

Stage 2.7 запазва exact schema-2 keyring history. Няма:

- wrapping-key generation, rotation, retirement reversal или deletion;
- re-encryption на стари MOKOSH файлове;
- decrypt/encrypt/read/write на потребителски документи;
- original-file cleanup.

Recovery publish променя само latest Vault password wrapper чрез вече
проверения Stage 2.6 candidate.

## 17. Memory limitation

Python и общите OS среди не обещават доказуемо изтриване на всички password,
recovery-root, keyring, candidate или KDF copies от RAM, allocator, swap,
registers, crash dump или VM snapshot.

Candidate session се lock-ва/close-ва след success или failure и public result
не задържа secrets. Това е ограничаване на lifetime, не абсолютна zeroization.

## 18. Забранени действия

Stage 2.7 няма:

- overwrite, replace, rename или deletion на Vault generation;
- `.mokr` write, overwrite, cleanup или automatic new recovery setup;
- key rotation, migration, deletion или user-file mutation;
- automatic latest-record selection, password guessing или retry;
- GUI, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, update discovery, download или installation;
- server dependency.

## 19. Задължителни тестове

- exact `R+1` publish и new-password unlock;
- old-password refusal и exact keyring-history preservation;
- separate enum decision и invalid input отказ преди claim/source/KDF;
- executor-owned one-shot claim и preclaimed/reuse refusal;
- frozen Stage 2.2 KDF-policy compatibility;
- exact latest/receipt/source/record/candidate evidence binding;
- wrong password/root, stale, dirty, forged, target collision и tamper отказ;
- private permission, symlink/hardlink и changed-between-reads отказ;
- double source/recovery verification преди publish;
- private single-link final generation без temporary residue;
- source generation и recovery file byte/inode preservation;
- pre-link fault без false success;
- publish-boundary и post-verification fault като uncertain без rollback;
- candidate session close при success и failure;
- source inspection за точно един delegated publish call и липса на direct
  filesystem mutation, network и logging;
- result без password, root, candidate, keyring, path или user data.

Тестовете са собствено възпроизводимо evidence за този contract. Те не са
независим одит, filesystem certification или гаранция срещу компрометирана OS.

## 20. Stage 2.8 reconciliation boundary

Stage 2.8 реализира strict read-only reconciliation за uncertain Stage 2.7
outcome чрез:

- explicit old source receipt и очакван target revision;
- recovery record/root и new password re-verification;
- bounded classification: target absent, exact durable target или conflict;
- никакво publish, overwrite, rollback, cleanup или key deletion;
- non-secret evidence и ясно действие за потребителя, което не е mutation
  authorization.

Той не приема вече консумирания process-local candidate. Observed target се
доказва спрямо surviving source/recovery/password invariants; без запазен
candidate digest няма твърдение за byte-equality към изгубения ephemeral
candidate. Пълният договор е в
`docs/VAULT_RECOVERY_RECONCILIATION_CONTRACT_BG.md`.

GUI или automatic recovery не се допуска само въз основа на classification.

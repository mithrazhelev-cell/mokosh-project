# MOKOSH — Read-only Recovery Publish Reconciliation Contract v1

Статус: Stage 2.8 — реализиран strict read-only reconciliation за uncertain
Stage 2.7 publish outcome върху замразените Stage 2.2–2.7 договори.

Този договор не продължава publish операцията и не „поправя“ Vault storage.
Той проверява surviving exact inputs и връща една от три ограничени
класификации: target липсва, target е exact проверен, или има конфликт.

## 1. Смисъл за потребителя

Stage 2.7 може честно да върне uncertain, когато `R+1` може вече да е видим или
durable, но финалната проверка не е завършила. В този момент blind retry е
опасен: може да срещне вече съществуващо поколение или да прикрие конфликт.

Stage 2.8 приема изрично:

1. стария exact source receipt за `R`;
2. очаквания target revision точно `R+1`;
3. стария private `.mokr` record за `R`;
4. отделния exact recovery root;
5. новата парола, избрана за recovery target-а;
6. exact `VaultStorage` и local KDF policy.

След две read-only наблюдения той връща само non-secret evidence и ясно
следващо действие. Няма automatic retry, publish, rollback или cleanup.

## 2. Trust и scope граница

Stage 2.8 стъпва върху:

- Stage 2.2 — private immutable generation scan и receipt verification;
- Stage 2.3 — canonical schema-2 keyring history;
- Stage 2.4 — recovery-root authentication и exact source binding;
- Stage 2.5 — strict private `.mokr` descriptor read;
- Stage 2.6 — recovery target invariants и explicit new password;
- Stage 2.7 — uncertain publish boundary без rollback/deletion.

Той не е independent anti-rollback anchor. Съгласуван rollback на цялата Vault
директория, recovery materials и локалните receipts от same-user/OS attacker
остава извън доказателството.

## 3. Защо няма candidate handoff вход

Stage 2.6 prepared candidate е process-local и one-shot. Stage 2.7 го консумира
преди publish опита. При process interruption object-ът и неговите exact bytes
може вече да не съществуват.

Затова Stage 2.8 не изисква `PreparedVaultRecoveryCandidate`, authorization ID
или candidate bytes. Той доказва наблюдавания target спрямо surviving durable
source receipt, authenticated recovery record/root и новата парола.

`TARGET_EXACT_DURABLE` означава exact stable observed `R+1`, което изпълнява
всички surviving recovery invariants. Без запазен candidate digest това не е
твърдение, че bytes са равни на изгубен ephemeral candidate от предишен процес.

## 4. Input validation преди source access

Преди filesystem scan и преди Argon2id се проверяват:

- exact `VaultStorage` и durable `VaultGenerationReceipt` types;
- structural receipt bounds;
- plain integer target revision точно `source.revision + 1`;
- неизчерпан Vault revision counter;
- recovery-root bytes type и exact 32-byte length;
- frozen password UTF-8 bounds;
- exact local `VaultKDFPolicy` bounds.

Няма silent clamp, fallback, password guessing или автоматичен избор на source,
target, recovery record или directory.

## 5. Explicit old source receipt

Source receipt умишлено може да не е latest: ако publish е успял, latest вече
е `R+1`. Stage 2.8 доказва директно, че generation `R`:

- още принадлежи на exact отворената Vault directory;
- има същите device/inode/size receipt identities;
- има exact SHA-256 и Vault ID;
- parse-ва като schema-2 Vault с revision `R`;
- е разрешен от local KDF parser policy.

Forged, missing, replaced, malformed, mixed или policy-rejected source receipt
прекратява reconciliation без класификация и без mutation.

## 6. Recovery record/root verification

Strict Stage 2.5 reader изисква:

- canonical `.mokr` filename, свързан с authenticated Recovery ID;
- private owned `0700` real parent directory;
- private owned `0600` regular single-link file;
- bounded descriptor read и stable directory/file identity;
- canonical Stage 2.4 record.

Stage 2.4 rehearsal с отделния recovery root трябва да докаже exact source
Vault ID, revision, source SHA-256, keyring SHA-256, active key version и key
count. Wrong root, stale, rollback, tamper, hardlink или malformed record
прекратява reconciliation.

## 7. Bounded storage observation

Stage 2.8 използва frozen `VaultStorage.scan`, ограничен до максимум 512
подробни entries. Report signature включва:

- directory device/inode;
- сортирани fixed findings без path/name;
- exact generation receipts;
- omitted count и complete flag.

Source и recovery inputs се проверяват, изпълнява се първи scan, след което
source и recovery се проверяват отново и се изпълнява втори scan.

Findings не се връщат в public result. Връщат се само bounded counts и flags.

## 8. Класификация `TARGET_ABSENT`

`TARGET_ABSENT` се връща само когато и двете наблюдения са exact равни и:

- history е complete, clean, contiguous и single-Vault;
- exact source receipt е generation `R`;
- history завършва точно с `R`;
- няма `R+1`, invalid generation, temporary или unknown object.

Новата парола е само syntactically валидирана, защото няма target, върху който
да бъде authenticated. Следващото действие е нов Stage 2.6 candidate от fresh
sources. Консумиран стар candidate никога не се reuse-ва.

## 9. Класификация `TARGET_EXACT_DURABLE`

Преди exact target classification и двете наблюдения трябва да покажат една и
съща clean complete history точно през `R+1`. Target receipt/bytes се проверяват
два пъти и трябва да са stable.

Observed `R+1` трябва:

- да е private valid single-link Vault generation;
- да има exact source Vault ID и revision точно `R+1`;
- да пази original `created_utc`;
- да има `updated_utc`, който не предхожда source или recovery record;
- да е schema `2` и разрешен от local KDF policy;
- да се unlock-ва с explicit new password;
- да съдържа exact recovery keyring SHA-256, active version и key count.

Target, който не се отваря с new password или съдържа друг keyring, не се
представя като exact. Old password няма fallback.

„Durable“ има същата локална receipt/visibility граница като frozen Stage 2.2.
Това не е доказателство срещу compromised OS, device firmware или бъдеща
power-loss аномалия извън предоставените filesystem semantics.

## 10. Класификация `CONFLICT`

`CONFLICT` е безопасният резултат при валидни source/recovery prerequisites,
но липса на доказателство за exact absent или exact target. Примери:

- invalid или чужд `R+1`;
- present target с wrong new password или различен keyring;
- linked/unlinked temporary residue;
- unknown object, malformed generation, gap или mixed Vault ID;
- generation след очакваното `R+1`;
- incomplete scan с omitted entries;
- промяна между двете storage observations;
- target receipt/bytes/password verification, които не съвпадат между reads.

Conflict result не връща untrusted target receipt или target digest и не
разрешава mutation. Действието е stop и manual review.

## 11. Source/recovery промяна и fault semantics

Source Vault bytes/header и recovery file identity/size/digest/bytes плюс
rehearsal evidence трябва exact да съвпаднат между двете проверки.

Ако source или recovery material се промени, резултат не се връща като absent,
exact или „поправим“ conflict. Операцията прекратява със state/verification
error. Scan I/O failure или invalid report също не се преобразува в success.

`KeyboardInterrupt`, process termination и други `BaseException` не се
поглъщат и не се представят като класификация.

## 12. Recommended action не е authorization

Public result съдържа exact enum action:

- `PREPARE_NEW_CANDIDATE` само при stable target absent;
- `REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY` само при exact target;
- `STOP_FOR_MANUAL_REVIEW` при conflict.

Action е non-mutating guidance. `mutation_authorized` винаги е false. Нов
candidate, normal unlock, new Stage 2.5 recovery setup или друго действие
изисква собствените си отделни prerequisites и explicit user decisions.

## 13. Non-secret result

`VaultRecoveryReconciliationResult` съдържа само:

- classification и recommended action enums;
- Recovery/Vault ID и source/target revisions;
- source/record/keyring SHA-256;
- exact source receipt;
- exact target receipt/digest само при exact target;
- bounded generation/finding/omitted counts;
- complete/stable/verified и no-mutation flags.

Няма password, recovery root, candidate bytes, keyring, wrapping key, path,
filename, plaintext или user-file metadata.

## 14. Recovery freshness след exact target

Старият `.mokr` остава exact валиден за explicit source `R`, което позволява
reconciliation. Ако `R+1` бъде приет като latest, същият record е stale спрямо
latest по Stage 2.4 freshness правилото.

Stage 2.8 не създава нов record/root. След user review нов recovery setup може
да се направи само чрез отделно explicit Stage 2.5 действие върху normal
unlocked exact latest `R+1`.

## 15. Memory limitation

Python и общите OS среди не обещават доказуемо изтриване на всички password,
recovery-root, decrypted keyring или KDF copies от RAM, allocator, swap,
registers, crash dump или VM snapshot.

Stage 2.8 не връща secrets, освобождава краткоживеещите keyring references и не
създава дългоживееща unlocked session. Това е lifetime ограничение, не
абсолютна zeroization.

## 16. Забранени действия

Stage 2.8 няма:

- publish, create, write, fsync, overwrite, replace или rename;
- rollback, unlink, cleanup или automatic retry;
- candidate reuse или automatic candidate creation;
- new recovery record/root setup;
- key rotation, migration, deletion или user-file mutation;
- GUI, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, update discovery, download или installation;
- server dependency.

## 17. Задължителни тестове

- stable target absent и exact next-revision target classification;
- реален Stage 2.7 post-publish uncertain fault, последван от exact read-only
  reconciliation;
- source receipt, който е умишлено nonlatest при present `R+1`;
- new-password unlock и exact recovered keyring digest/history;
- invalid target, wrong password, unknown object, temporary residue, extra
  revision и incomplete scan като conflict;
- changed reports или target verification като conflict без mutation;
- wrong root, forged source, tampered/unsafe/hardlinked `.mokr` отказ;
- source/recovery change-between-reads и scan fault отказ;
- invalid inputs преди source read, scan и Argon2id;
- target outside caller KDF policy като conflict;
- result без secrets/paths и с всички mutation flags false;
- source inspection без filesystem mutation, publish, network или logging;
- exact byte/inode/entry preservation при absent, exact и conflict.

Тестовете са собствено възпроизводимо evidence. Те не са независим одит,
filesystem certification или гаранция срещу компрометирана операционна среда.

## 18. Условие за следващ етап

Преди GUI е нужен explicit recovery workflow state contract, който приема
reviewed Stage 2.8 result и:

- никога не третира recommended action като mutation authorization;
- при absent започва нов Stage 2.6 flow с ново user decision;
- при exact изисква normal unlock и отделен explicit Stage 2.5 recovery setup;
- при conflict остава terminal read-only stop;
- не пази password/root/keyring в дългоживеещ workflow state;
- няма automatic retry, repair, cleanup или key deletion.

## 19. Stage 2.9 handoff

Stage 2.9 изпълнява тази граница чрез
`docs/VAULT_RECOVERY_WORKFLOW_CONTRACT_BG.md`.

Той валидира exact reviewed Stage 2.8 result, обвързва го с fixed transcript
digest и допуска един explicit enum review transition. Absent, exact, conflict
и preserve routes съдържат само non-secret ordered gates. Те не са mutation,
candidate, unlock, recovery setup, publish, retry или cleanup authorization.

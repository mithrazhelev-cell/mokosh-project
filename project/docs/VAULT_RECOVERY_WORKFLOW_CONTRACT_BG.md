# MOKOSH — Recovery Workflow State Contract v1

Статус: Stage 2.9 — реализиран explicit bounded in-memory workflow state върху
замразения Stage 2.8 reconciliation result.

Този договор не изпълнява recovery действие. Той записва едно изрично
потребителско решение за един exact reviewed Stage 2.8 резултат и връща само
non-secret маршрут към бъдещ отделен gate.

## 1. Смисъл за потребителя

След uncertain Stage 2.7 publish, Stage 2.8 може да докаже едно от три:

- target `R+1` липсва;
- target `R+1` е exact durable и проверен;
- има conflict, който не позволява автоматично продължаване.

Препоръката в Stage 2.8 не е команда. Stage 2.9 отделя показването и review-а
на този резултат от всяко по-късно действие. Така future adapter не може да
превърне `recommended_action` директно в candidate creation, unlock, recovery
setup, publish, retry или cleanup.

## 2. Scope и trust граница

Stage 2.9 приема само exact `VaultRecoveryReconciliationResult`. Няма path,
Vault storage, recovery file/root, password, keyring, candidate или session
вход.

Договорът проверява structural и semantic consistency на in-process резултата.
Той не е digital signature, independent provenance, anti-rollback anchor или
доказателство срещу compromised caller/OS, който може да подмени паметта и
изпълнявания код.

## 3. Exact reviewed result

Преди workflow preparation се изискват:

- exact Stage 2.8 result type и exact classification/action enum types;
- exact 16-byte Recovery ID и Vault ID;
- exact 32-byte source, recovery-record, keyring и optional target SHA-256;
- source revision поне `1` и target revision точно `R+1`;
- bounded generation, finding и omitted counts;
- exact durable source receipt, който съвпада с Vault ID, revision и source
  digest;
- всички Stage 2.8 no-mutation flags в задължителното им състояние.

Subclass, string вместо enum, `bool` вместо integer, oversized integer,
неправилен digest размер или противоречив flag се отказват.

## 4. Classification invariants

### 4.1 `TARGET_ABSENT`

Изискват се:

- action `PREPARE_NEW_CANDIDATE`;
- stable и complete observation без omitted entries;
- clean counts, завършващи точно при source revision `R`;
- липса на target receipt/digest;
- `new_password_verified = false` и `keyring_verified = false`.

### 4.2 `TARGET_EXACT_DURABLE`

Изискват се:

- action `REVIEW_TARGET_THEN_SETUP_NEW_RECOVERY`;
- stable complete clean history точно през `R+1`;
- target receipt от същата Vault directory и със същия Vault ID;
- target revision точно `R+1` и exact target digest;
- `new_password_verified = true` и `keyring_verified = true`.

### 4.3 `CONFLICT`

Изискват се:

- action `STOP_FOR_MANUAL_REVIEW`;
- липса на untrusted target receipt/digest в public result;
- липса на password/keyring verification claim.

Conflict може честно да е stable или changed, complete или incomplete. Това не
го прави eligible за automatic repair.

## 5. Canonical in-memory result binding

След validation се създава domain-separated fixed binary transcript, който
обвързва:

- classification и recommended action;
- Recovery/Vault ID и source/target revisions;
- source, record, keyring и optional target digests;
- exact source и optional target receipt identities;
- bounded counts и всички Stage 2.8 safety flags.

SHA-256 на transcript-а се пази като `reconciliation_result_sha256` в
non-secret workflow evidence. Това е process-local mismatch detection, не
подпис и не independent authenticity proof.

## 6. Prepared workflow

`prepare_recovery_workflow(reviewed_result)` връща
`PreparedVaultRecoveryWorkflow` в state `AWAITING_USER_REVIEW`.

Prepared object:

- не пази original Stage 2.8 object;
- пази само bounded non-secret workflow evidence;
- не може да бъде copy, deep-copy или pickle;
- допуска точно един успешен `review_once` transition;
- няма callable, callback или reference към recovery executor.

## 7. Exact explicit решения

Приемат се само exact enum стойности:

- `PRESERVE_AND_STOP`;
- `ACKNOWLEDGE_TARGET_ABSENT`;
- `ACKNOWLEDGE_EXACT_TARGET`;
- `ACKNOWLEDGE_CONFLICT`.

String със същия текст, друг enum или implicit truthy value не се приема.
Classification-specific решение се допуска само за съответната exact
classification. `PRESERVE_AND_STOP` е разрешено за всяка classification.

## 8. Double result presentation и mismatch отказ

`review_once` приема reviewed result повторно. Той се валидира отново и неговият
canonical digest и bounded evidence трябва exact да съвпаднат с prepared
workflow evidence.

Променен receipt, count, flag, digest, classification или action се отказва
като mismatch. Валиден, но различен Stage 2.8 result не може да бъде използван
с prepared workflow за друг резултат.

Неуспешен invalid/mismatch опит не създава route state. Един успешен transition
затваря object-а; всеки следващ опит е replay отказ.

## 9. Route при target absent

`ACKNOWLEDGE_TARGET_ABSENT` връща state
`FRESH_CANDIDATE_DECISION_REQUIRED` и един ordered gate:

1. `STAGE_2_6_NEW_CANDIDATE_DECISION`.

Това не създава candidate и не разрешава Stage 2.6. Потребителят трябва отделно
да предостави fresh sources, new password и exact Stage 2.6 decision. Стар
consumed candidate никога не се reuse-ва.

## 10. Route при exact target

`ACKNOWLEDGE_EXACT_TARGET` връща state `NORMAL_UNLOCK_REQUIRED` и два ordered
gate-а:

1. `NORMAL_VAULT_UNLOCK`;
2. `STAGE_2_5_NEW_RECOVERY_SETUP_DECISION`.

Stage 2.9 не извършва и не разрешава unlock. След successful normal unlock на
exact latest Vault, нов recovery record/root изисква отделни Stage 2.5
prerequisites и explicit setup decision.

Старият `.mokr` record остава stale спрямо latest `R+1` и не се обновява
автоматично.

## 11. Route при conflict

`ACKNOWLEDGE_CONFLICT` връща terminal state `MANUAL_REVIEW_STOP` и gate
`MANUAL_REVIEW_ONLY`.

Няма retry, repair, cleanup, target removal или избор на „по-добро“ Vault
поколение. Всяко бъдещо продължаване започва от ново независимо наблюдение и
договор, а не от този terminal route.

## 12. Preserve route

`PRESERVE_AND_STOP` връща terminal state `PRESERVED_STOP` без downstream gate.
То не променя или изтрива нищо и не означава, че recovery проблемът е решен.

## 13. Non-secret state

`VaultRecoveryWorkflowEvidence` съдържа само:

- format/version и Stage 2.8 result digest;
- classification/action;
- Recovery/Vault ID и revisions;
- source/record/keyring/optional target SHA-256;
- complete/stable flags.

`VaultRecoveryWorkflowState` добавя само explicit decision, route state,
ordered gates и fixed safety flags.

Няма password, recovery root, decrypted keyring, wrapping key, candidate,
session, path, filename, plaintext, exception text или user-file metadata.

## 14. Route никога не е authorization

За всеки successful route:

- `mutation_authorized = false`;
- `candidate_creation_authorized = false`;
- `normal_unlock_authorized = false`;
- `recovery_setup_authorized = false`;
- `publish_authorized = false`;
- `retry_authorized = false`;
- `repair_authorized = false`;
- `cleanup_authorized = false`;
- `key_deletion_authorized = false`;
- `user_file_mutation_authorized = false`.

Ordered gate е изискване за нов отделен договор, не разрешение за извикване на
съответната операция.

## 15. Freshness limitation

Stage 2.9 не чете filesystem и не може да докаже, че Vault/recovery state не е
променен след Stage 2.8. Nonterminal route изрично изисква downstream
reverification. Existing Stage 2.5/2.6 contracts запазват собствените си fresh
source checks и explicit decisions.

Process restart губи one-shot object-а. Няма persisted workflow token, silent
resume или автоматично възстановяване на стар route.

## 16. Memory limitation

Workflow модулът не приема secrets и не пази original reconciliation object.
Python/OS средата все пак не дава доказателство за абсолютна RAM zeroization.
Тази граница не променя забраната password/root/keyring да бъдат workflow
fields.

## 17. Забранени действия

Stage 2.9 няма:

- filesystem read, scan, create, write, fsync, replace, rename или unlink;
- Vault parse/unlock, recovery rehearsal или password KDF;
- candidate preparation, recovery setup, publish или reconciliation retry;
- automatic transition, repair, rollback, cleanup или key deletion;
- user-file mutation;
- GUI, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, clock, randomness или background process;
- update discovery, download, installation или server dependency.

## 18. Задължителни тестове

- реални Stage 2.8 absent/exact/conflict results към exact routes;
- preserve route за всяка classification;
- exact enum decision и classification/action mapping откази;
- malformed IDs, hashes, revisions, receipts, counts и boolean flags;
- contradictory absent/exact/conflict result откази;
- canonical digest binding за receipt identity, counts, flags и digests;
- different valid result mismatch отказ;
- successful transition точно веднъж и replay отказ;
- wrong route без transition и без автоматично fallback;
- direct forged evidence/state policy отказ;
- state/evidence без secrets, paths или executor references;
- всички authority flags false;
- copy/deepcopy/pickle отказ на prepared workflow;
- static доказателство за липса на filesystem, executor, network, GUI,
  logging, clock и randomness imports/calls;
- byte/inode/entry preservation при real absent/exact/conflict integration.

Тестовете са собствено възпроизводимо evidence. Те не са независим одит,
filesystem certification или доказателство срещу compromised runtime.

## 19. Условие за следващ етап

Преди GUI е нужен non-secret recovery workflow presentation contract, който:

- преобразува само validated Stage 2.9 state в fixed message keys и ordered
  confirmation requirements;
- не приема password, root, keyring, path или exception text;
- няма callback, executor или mutation API;
- не представя route/gate като извършена или разрешена операция;
- показва ясно terminal stop, downstream reverification и отделните user
  decisions.

## 20. Отделна Stage 2.10 presentation граница

Това условие е реализирано като отделен договор в
`docs/VAULT_RECOVERY_PRESENTATION_CONTRACT_BG.md`.

Stage 2.9 остава непроменен source-of-truth за decision, route и gates.
Presentation layer не може да създава нов route, да прескача gate или да
превръща workflow state в operation authorization.

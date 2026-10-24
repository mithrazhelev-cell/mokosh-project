# MOKOSH — Recovery Workflow Presentation Contract v1

Статус: Stage 2.10 — реализиран bounded non-secret presentation model върху
validated Stage 2.9 workflow state.

Този договор не е GUI и не изпълнява recovery действие. Той преобразува един
exact Stage 2.9 state само във fixed localization message keys, видими ordered
gate keys и ordered confirmation requirements за бъдещ adapter.

## 1. Смисъл за потребителя

Stage 2.9 вече е записал едно изрично решение и е определил безопасния route.
Stage 2.10 гарантира, че бъдещ интерфейс ще покаже:

- каква classification е прегледана;
- кое потребителско решение е записано;
- дали route-ът е terminal stop;
- дали е нужна downstream reverification;
- кои отделни gates остават и в какъв ред;
- че не е извършена и не е разрешена операция.

Presentation моделът не превежда, не приема свободен текст и не избира действие
вместо потребителя.

## 2. Scope и trust граница

Единственият public вход е exact `VaultRecoveryWorkflowState` от Stage 2.9.
Stage 2.10 не приема:

- Stage 2.8 result или filesystem observation;
- password, recovery root, keyring, candidate или session;
- path, filename, user-file metadata или exception text;
- callback, executor, callable, mutation object или decision handler.

Input state се валидира отново спрямо Stage 2.9 schema, route и всички fixed
no-authority flags. Exact type е задължителен; subclass, mapping и string enum
се отказват.

## 3. Public API

Единствената public функция е:

`prepare_recovery_workflow_presentation(workflow_state)`

Тя връща immutable `VaultRecoveryWorkflowPresentation`. Няма втори аргумент за
решение, изпълнение, превод, callback или fallback.

## 4. Fixed presentation schema

Presentation съдържа само:

- fixed format и version;
- process-local `workflow_state_sha256`;
- classification, Stage 2.9 decision и route state;
- bounded ordered `message_keys`;
- bounded ordered `gate_message_keys`;
- bounded ordered `confirmation_requirements`;
- terminal и downstream-reverification flags;
- fixed safety flags, че state е валидиран, използвани са само message keys,
  няма raw text, operation outcome/authority или retained secrets.

Няма Recovery ID, Vault ID, source/target digest, receipt, revision, password,
root, keyring, path или filename в presentation object-а.

## 5. Fixed localization keys

`RecoveryPresentationMessageKey` е exact enum. Неговите стойности са stable
localization identifiers, не user-facing English/Bulgarian текст.

Presentation не съдържа template arguments или arbitrary string. Бъдещият
localization registry е отделен слой и не може да променя route, gate order или
authority flags.

Message tuple е unique, bounded и exact ordered. List, duplicate, missing key,
добавен key, string вместо enum или променен ред се отказват.

## 6. Canonical state binding

След Stage 2.9 validation се създава domain-separated fixed binary transcript,
който обвързва:

- Stage 2.9 reconciliation-result digest;
- classification и recommended action;
- Recovery/Vault IDs, revisions и non-secret digests;
- complete/stable flags;
- explicit decision, route state и ordered Stage 2.9 gates;
- всички Stage 2.9 validation, read-only и no-authority flags.

SHA-256 на transcript-а е `workflow_state_sha256`. Той открива process-local
mismatch и свързва presentation-а с exact input state.

Digest-ът не е digital signature, persisted token, OS trust proof, independent
provenance или anti-rollback anchor. Direct constructed presentation с
произволен 32-byte digest не доказва, че реален Stage 2.9 state е съществувал.

## 7. Общи задължителни съобщения

Всеки route съдържа fixed keys за:

1. reviewed workflow result;
2. exact classification;
3. exact recorded decision;
4. exact route;
5. `NO_OPERATION_PERFORMED`;
6. `NO_OPERATION_AUTHORIZED`.

Тези keys не могат да бъдат скрити от route-specific mapping.

## 8. Target absent presentation

За `ACKNOWLEDGE_TARGET_ABSENT` се изисква exact state
`FRESH_CANDIDATE_DECISION_REQUIRED`.

Показват се:

- downstream reverification required;
- `GATE_FRESH_STAGE_2_6_DECISION_REQUIRED`;
- fresh inputs required.

Ordered confirmations са:

1. no operation performed;
2. downstream reverification required;
3. fresh Stage 2.6 decision required.

Това не създава candidate и не разрешава Stage 2.6.

## 9. Exact target presentation

За `ACKNOWLEDGE_EXACT_TARGET` се изисква exact state
`NORMAL_UNLOCK_REQUIRED`.

Видимият gate order е:

1. `GATE_NORMAL_VAULT_UNLOCK_REQUIRED`;
2. `GATE_NEW_STAGE_2_5_SETUP_DECISION_REQUIRED`.

Показват се още downstream reverification и предупреждение, че старият
recovery record остава stale.

Ordered confirmations не извършват unlock и не създават recovery setup.

## 10. Conflict presentation

За `ACKNOWLEDGE_CONFLICT` се изисква terminal `MANUAL_REVIEW_STOP`.

Показват се:

- terminal stop;
- `GATE_MANUAL_REVIEW_ONLY`;
- no automatic retry, repair или cleanup.

Ordered confirmations признават stop-а и забраната за automatic repair. Те не
създават retry или conflict-resolution authority.

## 11. Preserve presentation

`PRESERVE_AND_STOP` е допустимо за всяка classification само с terminal
`PRESERVED_STOP` и без gate.

Показва се изрично, че recovery проблемът не е решен. Confirmation requirement
не е продължаване или silent resume.

## 12. Gate visibility и ред

Всеки Stage 2.9 gate има точно един fixed presentation key. Gate tuple трябва
exact да съответства на route-а и всеки gate key трябва да присъства видимо в
ordered message tuple.

Gate key означава „отделен договор е необходим“. Той никога не означава:

- prerequisite completed;
- operation permitted;
- operation started;
- operation succeeded.

## 13. Confirmation requirements

`RecoveryPresentationConfirmationKey` е bounded exact enum tuple. Той описва
какво бъдещ adapter трябва да поиска да бъде разбрано от потребителя.

Stage 2.10 няма confirmation API и не записва acknowledgement. Наличието на
requirement не е user response, authentication, authorization или consent за
криптографска/filesystem операция.

## 14. Exact route invariants

Presentation construction отказва:

- classification/decision mismatch;
- nonterminal route с terminal flag;
- terminal route с reverification flag;
- missing, extra, duplicate или reordered message/gate/confirmation key;
- raw string вместо exact enum;
- unsupported format/version или malformed digest;
- boolean integer вместо exact boolean;
- positive operation outcome/authority или retained-secret flag.

Няма automatic fallback към preserve или manual review.

## 15. Minimal disclosure

Presentation не запазва original workflow state или Stage 2.9 evidence object.
Единственият exact-state binding е SHA-256 digest; останалото са route enums,
fixed keys и safety flags.

Това намалява данните, които бъдещ GUI може случайно да log-не или включи в
exception/report. То не доказва absolute RAM zeroization на Python/OS runtime.

## 16. Freshness limitation

Stage 2.10 не чете filesystem и не доказва, че Vault/recovery state е същият
след Stage 2.8/2.9. Nonterminal presentation запазва
`downstream_reverification_required = true`.

Fresh checks и explicit decisions остават задължение на съответните Stage
2.5/2.6 договори. Presentation никога не може да ги замени.

## 17. No-execution граница

Presentation module няма callback, executor reference или mutation API.
`operation_performed` и `operation_authorized` винаги са false.

Нито localization key, нито confirmation requirement може да бъде подаден
директно към recovery executor като разрешение.

## 18. Забранени действия

Stage 2.10 няма:

- filesystem read, scan, create, write, fsync, replace, rename или unlink;
- Vault parse/unlock, password KDF или recovery rehearsal;
- candidate creation, recovery setup, publish или reconciliation retry;
- automatic transition, rollback, repair, cleanup или key deletion;
- user-file mutation;
- GUI toolkit, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, clock, randomness или background process;
- update discovery, download, installation или server dependency.

## 19. Задължителни тестове

- exact absent/exact/conflict/preserve Stage 2.9 states към fixed mappings;
- exact visible gate order и ordered confirmation requirements;
- every route показва no-operation/no-authority keys;
- deterministic digest за equivalent state и различен digest при changed
  evidence или route;
- non-state, subclass, forged schema/route/gates/flags и string enum откази;
- direct presentation с malformed schema, keys, order или flags отказ;
- bounded unique exact-enum tuples;
- output без secret, path, exception, callback или executor fields;
- единствен public prepare API с един state аргумент;
- static доказателство за липса на filesystem, mutation, executor, network,
  GUI, logging, clock и randomness imports/calls;
- доказателство, че input state не се променя.

Тестовете са собствено възпроизводимо evidence. Те не са независим одит,
usability study, localization certification или доказателство срещу
compromised runtime.

## 20. Реализирана Stage 2.11 acknowledgement граница

Stage 2.11 реализира отделен one-shot non-mutating acknowledgement contract в
`docs/VAULT_RECOVERY_ACKNOWLEDGEMENT_CONTRACT_BG.md`.

Той:

- валидира повторно exact Stage 2.10 presentation;
- приема само complete exact ordered confirmation tuple без free text;
- отказва skip, partial, reorder, duplicate, extra и cross-route keys;
- връща bounded acknowledgement receipt/state;
- допуска точно един concurrent-safe process-local success;
- не извиква gate, callback, executor или mutation API;
- не превръща acknowledgement в unlock, recovery setup, candidate или publish
  authorization.

Stage 2.11 само по себе си не е GUI/application adapter.

## 21. Реализирана Stage 2.12 UI adapter граница

Stage 2.12 реализира bounded non-mutating adapter contract в
`docs/VAULT_RECOVERY_UI_ADAPTER_CONTRACT_BG.md`.

Той превръща exact Stage 2.10 tuples в stable ordered visible message
items и separate required default-false confirmation controls. Exact visible
ordered events се предават само на private Stage 2.11 lifecycle.

Stage 2.12 още не render-ва localized text, не създава widget и
не изпълнява operational gate. Реалният GUI layer остава
отделен бъдещ етап.

## 22. Реализирана Stage 2.13 localization граница

Stage 2.13 реализира versioned fixed localization registry в
`docs/VAULT_RECOVERY_LOCALIZATION_CONTRACT_BG.md`.

Всички 24 message и 9 confirmation keys имат exact one-to-one `bg-BG` и
`en-GB` text. Missing, duplicate, mixed, altered, unsafe или unsupported
locale input се отказва без fallback.

Stage 2.13 localize-ва само exact validated Stage 2.12 view и запазва route,
gate order и confirmation semantics. Той не създава widget, не приема event,
не acknowledge-ва workflow и не изпълнява operation.

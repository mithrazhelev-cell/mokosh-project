# MOKOSH — Recovery Presentation Acknowledgement Contract v1

Статус: Stage 2.11 — реализиран one-shot non-mutating acknowledgement слой
върху exact validated Stage 2.10 presentation.

Този договор записва само, че всички fixed confirmation keys от една exact
presentation са подадени наведнъж и в правилния ред. Той не е GUI, operation
consent, authentication или recovery authorization.

## 1. Смисъл за потребителя

Stage 2.10 определя кои предупреждения и отделни бъдещи gates трябва да бъдат
видими. Stage 2.11 гарантира, че бъдещ adapter не може да отчете успешно
потвърждение, ако потребителят е пропуснал, разменил, повторил или подменил
някой required confirmation key.

Успешният acknowledgement означава единствено:

- exact presentation е валидирана повторно;
- exact ordered confirmation tuple е съвпаднал изцяло;
- този prepared in-memory object е използван успешно точно веднъж.

Това не означава, че Vault или filesystem състоянието още е fresh, че gate е
изпълнен или че recovery проблемът е решен.

## 2. Scope и trust граница

Единственият public prepare вход е exact
`VaultRecoveryWorkflowPresentation` от Stage 2.10.

One-shot transition приема само:

1. exact същата validated presentation или value-equivalent реконструкция;
2. exact tuple от `RecoveryPresentationConfirmationKey` в определения ред.

Не се приемат:

- raw user-facing text, checkbox labels или localization output;
- boolean „потвърдено“, free text, mapping, list или numeric choice;
- password, recovery root, keyring, candidate, session, path или filename;
- callback, callable, executor, gate handler или mutation object.

## 3. Public API

Public prepare функцията е:

`prepare_recovery_presentation_acknowledgement(presentation)`

Тя връща `PreparedVaultRecoveryPresentationAcknowledgement`.

Единственият transition метод е:

`acknowledge_once(presentation, confirmations)`

Няма аргумент за operation, authorization, fallback, translation, callback
или executor.

## 4. Prepared acknowledgement lifecycle

Новият prepared object започва в
`AWAITING_CONFIRMATIONS` и съдържа само bounded binding данни:

- SHA-256 на canonical presentation transcript;
- classification, recorded decision и route state;
- exact required confirmation tuple;
- terminal и downstream-reverification flags.

Той не пази original presentation, Stage 2.9 state или recovery evidence.

След един successful `acknowledge_once` state става `ACKNOWLEDGED` и се пази
само полученият bounded receipt. Втори опит винаги е replay отказ.

## 5. Exact Stage 2.10 revalidation

Prepare и всеки непрекратен acknowledgement attempt изискват exact
`VaultRecoveryWorkflowPresentation` type. Subclass, mapping и look-alike
object се отказват.

Stage 2.10 validation се изпълнява отново за:

- format, version и workflow-state digest;
- exact classification, decision и route state;
- fixed ordered message, gate и confirmation tuples;
- terminal/downstream route semantics;
- всички no-text, no-secret и no-authority flags.

Malformed или contradictory presentation не се превръща в preserve fallback.

## 6. Canonical presentation binding

След validation се създава domain-separated fixed binary transcript, който
обвързва:

- Stage 2.10 `workflow_state_sha256`;
- classification, decision и state;
- всеки ordered message key;
- всеки ordered visible gate key;
- всеки ordered confirmation requirement;
- terminal, reverification и всички Stage 2.10 safety flags;
- Stage 2.10 version.

SHA-256 на transcript-а е `presentation_sha256`. При acknowledgement exact
presentation се валидира и digest/binding се изчисляват отново. Digest compare
и full binding equality трябва едновременно да съвпаднат.

Това е process-local mismatch evidence, не digital signature, persisted token,
human-identity proof или independent anti-rollback anchor.

## 7. Exact ordered confirmations

`confirmations` трябва да бъде:

- exact tuple;
- с дължина от 1 до `MAX_PRESENTATION_CONFIRMATIONS`;
- само от exact `RecoveryPresentationConfirmationKey` enum members;
- без duplicate;
- byte-for-value exact равно на Stage 2.10 required tuple.

List, string enum values, partial tuple, reversed tuple, duplicate, extra key,
key от друг route или empty tuple се отказват.

Stage 2.11 не приема „потвърди всички“ boolean и не генерира confirmation от
локализиран текст.

## 8. Failed-attempt semantics

Malformed confirmation, presentation mismatch или unsupported input отказват
без success receipt и без консумиране на prepared object-а.

Това позволява бъдещ adapter да поправи локална input грешка и да представи
отново exact requirements. Няма automatic correction, reorder или completion.

След първия success prepared object е изгорен за всички следващи опити,
включително с различна presentation.

## 9. In-process concurrency

Transition-ът е защитен с process-local lock. При едновременни опити върху
един prepared object точно един може да успее; останалите получават replay
отказ.

Lock-ът не е cross-process coordination, persistent journal или OS trust
proof. Restart губи prepared object-а и receipt-ът не може да бъде използван
като durable authorization.

## 10. Target absent acknowledgement

Exact confirmations са:

1. no operation performed;
2. downstream reverification required;
3. fresh Stage 2.6 decision required.

Receipt запазва nonterminal route и reverification flag. Не създава Stage 2.6
candidate и не разрешава candidate decision.

## 11. Exact target acknowledgement

Exact confirmations са:

1. no operation performed;
2. downstream reverification required;
3. normal unlock required;
4. new Stage 2.5 setup decision required.

Редът unlock → separate setup decision остава задължителен. Acknowledgement не
unlock-ва Vault и не създава или публикува recovery record.

## 12. Conflict acknowledgement

Exact confirmations са:

1. no operation performed;
2. manual review stop;
3. no automatic repair.

Receipt остава terminal и няма downstream route. Не се създават retry, repair,
cleanup или conflict-resolution права.

## 13. Preserve acknowledgement

За всяка classification exact confirmations са:

1. no operation performed;
2. preserved stop;
3. recovery problem not resolved.

Receipt остава terminal без gate. Няма silent resume.

## 14. Bounded acknowledgement receipt

`VaultRecoveryPresentationAcknowledgementReceipt` съдържа само:

- fixed format/version и sequence `1`;
- `presentation_sha256`;
- classification, decision и route state;
- state `ACKNOWLEDGED`;
- exact acknowledged confirmation tuple и count;
- terminal и downstream-reverification flags;
- fixed validation, one-shot, read-only и no-authority flags.

Receipt не съдържа original presentation, message/gate tuples, Stage 2.9
evidence, Recovery/Vault IDs, revisions, source/target digests, receipts,
password, root, keyring, candidate, path, filename или exception text.

## 15. Acknowledgement никога не е authorization

Следните receipt flags са fixed false:

- `operation_performed`;
- `operation_authorized`;
- `gate_invoked`;
- `automatic_transition`;
- `secrets_retained`.

`presentation_validated`, `confirmation_order_validated` и
`all_confirmations_acknowledged` описват само Stage 2.11 input validation.
Никой от тях не може да бъде използван като capability за Stage 2.5, 2.6 или
2.7.

## 16. Direct-construction limitation

Receipt schema валидира route, confirmations, count, sequence и safety flags.
Direct constructed object с arbitrary 32-byte digest обаче не доказва, че
реална presentation е била показана или че човек я е разбрал.

Stage 2.11 е deterministic core contract за бъдещ adapter. То не е usability
study, biometric proof, legal consent record или независим audit evidence.

## 17. Freshness limitation

Stage 2.11 не чете filesystem и не доказва current Vault/recovery state.
Nonterminal receipt запазва `downstream_reverification_required = true`.

Fresh Stage 2.5/2.6 checks и отделните decisions остават задължителни. Receipt
не може да ги прескочи.

## 18. Memory и restart limitation

Prepared object и receipt са process-local Python objects. Copy, deep-copy и
pickle на prepared object се отказват, но това не доказва absolute RAM
zeroization или защита при compromised interpreter/OS.

След restart трябва да се създаде fresh workflow/presentation/acknowledgement
chain от валидни inputs. Няма persisted resume token.

## 19. Забранени действия

Stage 2.11 няма:

- filesystem read, scan, create, write, fsync, replace, rename или unlink;
- Vault parse/unlock, KDF или recovery rehearsal;
- candidate creation, recovery setup, publish или reconciliation retry;
- gate invocation, callback, executor или mutation API;
- automatic transition, rollback, repair, cleanup или key deletion;
- user-file mutation;
- GUI toolkit, Contacts, Guardian, shards или licensing integration;
- network, telemetry, logging, clock, randomness или background worker;
- update discovery, download, installation или server dependency.

Process-local lock сериализира само `acknowledge_once`; той не стартира thread.

## 20. Задължителни тестове

- exact absent/exact/conflict/preserve presentation acknowledgement;
- exact route confirmation order и bounded enum tuples;
- отказ на empty, list, string, partial, reordered, duplicate, extra и
  cross-route confirmations;
- exact Stage 2.10 type/schema/route/safety revalidation;
- presentation mismatch при changed digest, route или fixed keys;
- failed attempt без consumption и success с exactly-one transition;
- replay отказ след success, независимо от следващия input;
- concurrent attempts с точно един success;
- copy, deep-copy и pickle отказ на prepared object;
- deterministic route-bound presentation digest;
- strict receipt schema, route, count, sequence и boolean validation;
- receipt без secrets, IDs, paths, raw text, callbacks или executor fields;
- всички operation/authorization/gate/transition flags fixed false;
- static доказателство за липса на filesystem, executor, mutation, network,
  GUI, logging, clock и randomness imports/calls;
- доказателство, че input presentation не се променя.

Тестовете са собствено възпроизводимо evidence. Те не доказват, че реален GUI
е показал текста четливо или че compromised OS не е подменил интерфейса.

## 21. Условие за бъдещ adapter

Бъдещ GUI/application adapter трябва отделно да докаже:

- exact localization registry за всеки fixed key;
- отделно и видимо показване на confirmations в contract order;
- accessibility и keyboard-navigation поведение;
- без hidden pre-check, default acknowledgement или synthetic click;
- свежо изграждане на Stage 2.9–2.11 chain при всяко recovery review;
- receipt никога не се подава като executor authorization;
- UI cancellation и close оставят operations неизвършени;
- никакво logging/telemetry на secrets или raw recovery evidence.

Stage 2.11 само по себе си не реализира този adapter.

## 22. Реализирана Stage 2.12 adapter граница

Stage 2.12 реализира отделен bounded non-mutating UI adapter contract в
`docs/VAULT_RECOVERY_UI_ADAPTER_CONTRACT_BG.md`.

Той:

- валидира exact Stage 2.10 presentation и Stage 2.11 binding;
- създава stable ordered fixed-key message items;
- създава visible required individually selectable confirmation controls,
  всички default false;
- приема само exact visible/user-selected/user-initiated ordered events;
- делегира successful tuple само на private Stage 2.11 lifecycle;
- отказва hidden, default, partial, reordered, stale и cross-route input;
- не render-ва text, не създава GUI widget и не invoke-ва gate,
  callback, executor или mutation.

Реалният localization/widget layer и operational gates остават отделни
бъдещи етапи.

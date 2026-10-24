# MOKOSH — Recovery UI Adapter Contract v1

Статус: Stage 2.12 — реализиран bounded non-mutating application/UI
adapter contract върху exact Stage 2.10 presentation и private Stage 2.11
acknowledgement lifecycle.

Този модул описва какво един бъдещ локален прозорец трябва да
покаже и как да предаде отделните видими потвърждения. Той още не
създава Tkinter widget, не render-ва текст и не изпълнява recovery
операция.

## 1. Смисъл за потребителя

Stage 2.10 дава fixed message, gate и confirmation keys. Stage 2.11
приема точно целия ordered confirmation tuple.

Stage 2.12 добавя границата между тези данни и бъдещия
прозорец:

- всяко message има стабилен ordinal и fixed localization key;
- всяко confirmation е отделено, видимо и required;
- нито едно confirmation не е предварително отметнато;
- няма „потвърди всичко“ или hidden auto-accept;
- няма operational button, callback или executor.

Успешният UI acknowledgement означава само, че adapter-ът е
предал exact visible events в правилния ред и Stage 2.11 ги е
приел. Това не е отключване, recovery, authorization или доказано
човешко разбиране.

## 2. Scope и trust граница

Единственият public prepare input е exact
`VaultRecoveryWorkflowPresentation` от Stage 2.10.

Preparation:

1. валидира Stage 2.10 presentation отново;
2. създава exact Stage 2.11 acknowledgement private lifecycle;
3. създава bounded UI view с fixed items и controls;
4. обвързва view и acknowledgement към exact presentation digest и route.

Не се приемат:

- raw text, translation mapping, template argument или arbitrary label;
- password, recovery root, keyring, candidate, session, path или filename;
- callback, callable, executor, gate handler или operation object;
- filesystem handle, Vault storage или network/service reference.

## 3. Public API

Public prepare функцията е:

`prepare_recovery_ui_adapter(presentation)`

Тя връща `PreparedVaultRecoveryUIAdapter`.

Единственият transition метод е:

`acknowledge_visible_once(presentation, events)`

Няма public render, translate, unlock, setup, candidate, publish, retry,
repair, cleanup, callback, executor или dispatch функция.

## 4. Prepared lifecycle

Новият prepared adapter започва в `AWAITING_USER_CONFIRMATIONS`.
Той държи:

- bounded no-secret binding;
- immutable UI view;
- private Stage 2.11 prepared acknowledgement;
- process-local lock;
- липса на receipt преди success.

След един successful `acknowledge_visible_once` state става
`ACKNOWLEDGED`. Всеки следващ опит е replay отказ.

Prepared adapter не може да бъде copy, deep-copy или pickle.

## 5. Exact presentation binding

Stage 2.12 използва exact Stage 2.11 canonical
`presentation_sha256` binding. Full binding освен digest-а включва:

- classification, decision и workflow route state;
- exact ordered message keys;
- exact ordered gate-message keys;
- exact ordered confirmation keys;
- terminal-stop и downstream-reverification semantics.

При transition presentation и binding се валидират отново. Digest
compare и full equality трябва едновременно да съвпаднат.

Digest-ът е mismatch evidence, не signature, durable identity, persisted
consent token или independent anti-rollback proof.

## 6. Fixed message items

Всеки `RecoveryUIMessageItem` съдържа само:

- exact ordinal от `1` до bounded maximum;
- exact `RecoveryPresentationMessageKey`;
- exact boolean дали key-ът е gate message;
- fixed `visible = true`;
- fixed `accessible_label_key_bound = true`.

Items са точно в Stage 2.10 message order. Gate markers трябва да
възстановяват exact ordered gate tuple.

Модулът не пази и не приема локализирана човешка реч. Exact
localization registry и реалното rendering остават отделен бъдещ
етап.

## 7. Fixed confirmation controls

Всеки `RecoveryUIConfirmationControl` има:

- exact stable ordinal;
- exact `RecoveryPresentationConfirmationKey`;
- `visible = true`;
- `required = true`;
- `individually_selectable = true`;
- `default_selected = false`;
- `accessible_label_key_bound = true`.

Няма group checkbox, default check, hidden acknowledgement или auto-completion.
Всички controls са в exact Stage 2.10 order.

## 8. UI view

`VaultRecoveryUIAdapterView` съдържа:

- Stage 2.11 presentation digest;
- classification, decision и route state;
- exact ordered message items;
- exact ordered confirmation controls;
- terminal и downstream-reverification flags;
- state `AWAITING_USER_CONFIRMATIONS`;
- fixed visibility, accessibility-key, order и no-authority flags.

View изрично декларира:

- `auto_accept_available = false`;
- `operation_controls_included = false`;
- `raw_text_included = false`;
- `operation_authorized = false`;
- `secrets_retained = false`.

## 9. Confirmation events

Бъдещият widget adapter трябва да подаде exact tuple от
`RecoveryUIConfirmationEvent`.

Всеки event съдържа:

- exact ordinal;
- exact confirmation key;
- exact boolean `visible`;
- exact boolean `user_selected`;
- exact boolean `user_initiated`.

Успех е възможен само ако всички са true и ordinal/key са exact
ordered requirements. Hidden, unselected, synthetic-declared-false, partial,
reordered, duplicate, extra и cross-route input се отказват.

`user_initiated = true` е само bounded assertion на adapter-а. Модулът не
може да докаже човешка идентичност, attention, comprehension,
biometric action или absence на compromised UI/runtime.

## 10. Exact Stage 2.11 delegation

След собствената пълна validation Stage 2.12 извлича само exact
ordered confirmation keys от events и ги подава на private Stage 2.11
`acknowledge_once`.

Stage 2.11 receipt се валидира отново. Digest, route, keys, count,
terminal/reverification и всички no-authority flags трябва да
съвпадат с UI binding-а.

Не се подменя Stage 2.11 с boolean и не се създава втори
acknowledgement path.

## 11. Failed-attempt semantics

Невалидна presentation, stale binding, tampered view или invalid events:

- не връщат success receipt;
- не променят adapter state;
- не консумират Stage 2.11 acknowledgement;
- не попълват, reorder-ват или auto-correct-ват input;
- не започват операция.

При internal contradiction няма preserve fallback или silent continuation.

## 12. One-shot и concurrency

Prepared adapter и private Stage 2.11 lifecycle са process-local one-shot
objects. Adapter lock сериализира concurrent attempts.

Върху един prepared adapter точно един concurrent attempt може да
успее. Всички останали са replay отказ.

Lock-ът не е cross-process coordination, journal, durable state, clock
proof или OS trust boundary.

## 13. Route semantics

### 13.1 Target absent

- показва no-operation и downstream reverification;
- показва fresh Stage 2.6 decision gate;
- не създава candidate и не разрешава decision.

### 13.2 Exact durable target

- показва normal unlock преди separate Stage 2.5 setup decision;
- показва, че old recovery record остава stale;
- не unlock-ва Vault и не пише recovery record.

### 13.3 Conflict

- показва terminal manual-review stop;
- показва no automatic retry/repair/cleanup;
- не създава conflict-resolution authority.

### 13.4 Preserve

- показва terminal preserved stop;
- показва, че recovery проблемът не е решен;
- няма downstream gate или silent resume.

## 14. Bounded receipt

`VaultRecoveryUIAdapterReceipt` съдържа само:

- fixed format/version и sequence `1`;
- Stage 2.11 presentation digest;
- classification, decision и route state;
- state `ACKNOWLEDGED`;
- exact confirmation keys и count;
- terminal и downstream-reverification flags;
- fixed visibility, order, Stage 2.11 validation, read-only и no-authority
  flags.

Receipt не пази view, original presentation, message items, controls,
events, Stage 2.11 receipt object, workflow state/evidence, Recovery/Vault IDs,
revisions, source/target digests, password, root, keyring, candidate, path,
filename, callback или executor.

## 15. Receipt никога не е authorization

Fixed false са:

- `auto_accept_used`;
- `hidden_confirmation_used`;
- `operation_performed`;
- `operation_authorized`;
- `gate_invoked`;
- `automatic_transition`;
- `secrets_retained`.

Visibility, selection и Stage 2.11 validation flags описват само
adapter input validation. Те не са capability за Stage 2.5, 2.6 или
2.7.

## 16. Direct-construction и human-proof limitation

Direct constructed view или receipt с arbitrary valid-looking digest не
доказват, че реален прозорец е бил видим, че потребител е
разбрал текста или че event-ът е натиснат физически от човек.

Stage 2.12 е deterministic contract и testable seam. То не е usability
study, accessibility certification, biometric proof, legal consent record или
independent audit evidence.

## 17. Accessibility граница

Този core налага:

- stable ordered items;
- exact label localization keys;
- visible required controls;
- individual selection;
- no default selection;
- no auto-accept.

Реалният widget layer още трябва да докаже keyboard navigation,
focus order, screen-reader output, contrast, scaling, scrolling, full message
visibility и localized-text quality. Stage 2.12 не твърди, че тези
вече са тествани в реален GUI.

## 18. Freshness, memory и restart

Модулът не чете filesystem и не доказва current Vault/recovery
state. Nonterminal route запазва `downstream_reverification_required =
true`.

След restart трябва fresh Stage 2.8–2.12 chain. Няма persisted
view, acknowledgement, resume token или cross-process authority.

Отказът на copy/deep-copy/pickle не доказва absolute RAM
zeroization или защита при compromised interpreter/OS.

## 19. Забранени действия

Stage 2.12 няма:

- Tkinter/GUI widget creation, rendering, window event loop или screenshot
  control;
- localization catalog или raw user-facing text;
- filesystem read, scan, create, write, fsync, replace, rename или unlink;
- Vault parse/unlock, KDF или recovery rehearsal;
- candidate creation, recovery setup, publish или reconciliation retry;
- gate invocation, callback, executor или mutation API;
- automatic transition, rollback, repair, cleanup, key deletion или
  user-file mutation;
- Contacts, Guardian, shards, licensing или entitlement integration;
- network, telemetry, logging, clock, randomness или background worker;
- update discovery, download, installation или server dependency.

## 20. Задължителни тестове

- exact absent/exact/conflict/preserve view construction;
- exact ordered message/gate items и stable ordinals;
- visible, required, individually selectable, default-false confirmation
  controls;
- accessible label-key binding за всеки item/control;
- success само чрез exact Stage 2.11 acknowledgement;
- отказ на empty, list, mapping, string, partial, reordered,
  duplicate, extra и cross-route events;
- отказ на hidden, unselected, non-user-initiated и wrong-ordinal
  event;
- failed input без consumption, следван от exact success;
- presentation digest, schema, route и authority revalidation;
- tampered prepared view и different-route mismatch;
- replay, copy, deep-copy и pickle отказ;
- concurrent attempts с точно един success;
- strict view/item/control/event/receipt schema и exact boolean tests;
- receipt без secrets, IDs, paths, raw text, events, callback или
  executor reference;
- всички operation/authorization/gate/transition flags fixed false;
- static липса на filesystem, GUI, executor, mutation, network,
  logging, clock и randomness imports/calls;
- input presentation остава byte-for-field непроменена.

Тестовете са собствено reproducible evidence. Те не доказват
че реален GUI е четим, accessible или защитен от compromised
desktop.

## 21. Условие за реален widget adapter

Преди свързване към `mokosh_gui.py` трябва отделно да има:

- versioned exact localization registry за всеки message/confirmation key;
- fail-closed липсващ translation behavior;
- real widget visibility и no pre-check tests;
- keyboard/focus/screen-reader/scale tests;
- cancel/close behavior без acknowledgement и operation;
- fresh adapter при всяко отваряне, без persisted resume;
- UI receipt никога да не е executor capability;
- отделни бъдещи operational gates с fresh source revalidation;
- platform tests за Linux, Windows и macOS.

## 22. Честно ограничение

Stage 2.12 е последният pure core seam преди реаления локален
recovery review window. Той доказва точно какви structured items и
events са допустими.

Той не доказва как те изглеждат на екрана, не знае кой е
натиснал control-а и не изпълнява нито една recovery операция.

## 23. Реализирана Stage 2.13 localization граница

Stage 2.13 реализира първите две изисквания от раздел 21 чрез
`docs/VAULT_RECOVERY_LOCALIZATION_CONTRACT_BG.md`:

- exact allowlist `bg-BG` и `en-GB` без silent fallback;
- complete one-to-one registry за всички message/confirmation keys;
- bounded NFC text без control/format/bidi/template input;
- deterministic visible и identical accessible text records;
- exact Stage 2.12 view revalidation и locale isolation;
- никакъв widget, event, acknowledgement или operation authority.

Останалите real-widget, keyboard/focus/screen-reader/scale, cancellation и
platform tests остават задължителни преди връзка с `mokosh_gui.py`.

## 24. Реализиран Stage 2.14 isolated widget seam

Stage 2.14 реализира отделен real Tkinter `Toplevel` по
`docs/VAULT_RECOVERY_REVIEW_WINDOW_CONTRACT_BG.md`:

- exact Stage 2.10 presentation и fresh Stage 2.12 adapter се revalidate-ват;
- exact `bg-BG`/`en-GB` Stage 2.13 localized view се създава без fallback;
- messages и gate warnings се изграждат преди confirmation controls;
- всички checkboxes са individual, false и disabled преди visible report;
- final action е disabled до exact all-true selections;
- cancel, Escape и close не създават Stage 2.12 acknowledgement;
- success предава само exact visible ordered event tuple и връща bounded
  no-authority receipt;
- няма втори `Tk`, втори `mainloop`, filesystem, operation или main-GUI
  activation.

Stage 2.14 покрива code-level wrap/scroll/focus/keyboard wiring и headless
state/static tests. Реални screen-reader, theme/contrast, DPI и platform tests
за Linux, Windows и macOS остават задължителни преди public GUI claim.

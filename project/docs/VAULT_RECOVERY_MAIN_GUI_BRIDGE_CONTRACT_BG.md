# MOKOSH — договор за неактивен main-GUI recovery review bridge

Статус: Stage 2.17 — реализиран exact one-shot handoff към Stage 2.16 review
controller, без normal-startup activation и без истински recovery input.

## 1. Цел

Stage 2.17 поставя най-малката контролирана граница между основния MOKOSH GUI и
вече изолирания Stage 2.16 controller. Главният GUI вече познава само един
bounded bridge type и една неактивна функция за показване на предварително
подготвен read-only review.

Този етап не добавя бутон, меню, автоматично извикване или source preparation.
Обичайното `main()` стартиране не създава binding и не извиква recovery review.

## 2. Public API

Реализацията е в `mokosh_vault_recovery_main_gui_bridge.py`.

Единствената public module функция е:

```python
prepare_main_gui_recovery_review_binding(prepared_session, locale_id)
```

Тя приема само:

- exact fresh `PreparedVaultRecoveryReviewSession` от Stage 2.16;
- exact locale string `bg-BG` или `en-GB`.

Връща `PreparedMainGUIRecoveryReviewBinding`. Единственото действие върху него
е `show_once(parent)`.

`mokosh_gui.py` предоставя само неактивния seam:

```python
show_prepared_recovery_review(parent, prepared_binding)
```

Той отказва всеки non-exact binding и делегира само към `show_once`.

## 3. Exact locale и source binding

Stage 2.16 session-ът излага само bounded read-only `locale` property. Bridge-ът
изисква тя да съвпада точно с подадения allowlisted locale. Няма normalization,
OS locale, environment locale, translation fallback или избор след preparation.

Consumed, displaying, completed или failed Stage 2.16 session се отказва преди
GUI display. Mapping, subclass, workflow state, presentation, adapter или
произволен duck-typed object също се отказва.

## 4. One-shot lifecycle

Bridge lifecycle-ът е:

- `ready`;
- `displaying`;
- `completed`;
- `failed`.

Преходът `ready` към `displaying` става под process-local lock преди
делегирането. Concurrent или replay опит не може да стартира втори display.

Success и cancellation завършват като `completed`. Controller failure,
невалиден outcome или mismatch завършват като `failed`. Interrupt се пропуска
към caller-а, но binding-ът се консумира. Няма blind retry.

След terminal result или failure reference-ът към Stage 2.16 session се
премахва. Binding-ът не може да бъде copy, deepcopy или pickle/serialize.

## 5. Outcome граница

Bridge-ът приема само exact `VaultRecoveryReviewWindowOutcome`, реконструира го
чрез dataclass validation и изисква exact prepared locale. Stage 2.14/2.16
инвариантите продължават да изискват:

- `operation_authorized=False`;
- `operation_performed=False`;
- read-only и inspection-only резултат;
- exact acknowledgement receipt или exact cancellation reason;
- липса на source identifiers, secrets, paths, callbacks и capabilities.

Acknowledgement означава само, че фиксираните видими потвърждения са приети.
То не разрешава следваща операция.

## 6. Неактивност при normal startup

`mokosh_gui.main()` няма binding параметър, не подготвя session и не извиква
`show_prepared_recovery_review`. Launcher-ът остава непроменен. Няма нов widget
или промяна на geometry/layout.

Това е integration seam за бъдещ отделно прегледан event binding, а не
потребителски активирана recovery функция.

## 7. Забранени входове и действия

Stage 2.17 няма API или import към:

- password, recovery root, recovery record или keyring;
- Vault/recovery path, file picker или source loader;
- Stage 2.8 reconciliation или Stage 2.9 workflow preparation;
- unlock, candidate, setup, publish, retry, repair или cleanup;
- filesystem mutation, process, network или logging;
- Contacts, telemetry, Guardian, update или licensing;
- callback, executor, plugin, dynamic import, `eval` или `exec`.

`mokosh_gui.py` импортира само bounded Stage 2.17 bridge type. Той не импортира
recovery source, workflow, reconciliation или executor модул.

## 8. Safety mode

`SAFETY_MODE` остава exact `True`. Съществуващите encryption, cleanup, Contacts
и Sandbox забрани не се отслабват. Legacy decryption не се променя.

## 9. Задължителни тестове

- четирите route-а и двата locale-а;
- exact type, allowlist и locale mismatch отказ;
- consumed/nonfresh session отказ преди display;
- acknowledged и cancelled bounded outcomes;
- forged/non-outcome и wrong-locale отказ;
- source clearing при success и failure;
- replay отказ и concurrent точно един display;
- controller failure wrapping и interrupt consumption;
- copy/deepcopy/pickle отказ;
- outcome schema без secrets, identifiers или capability;
- static import/call boundary;
- main-GUI module import и exact seam forwarding без Tk activation;
- inactive main-GUI seam и липса на normal-main activation;
- `SAFETY_MODE=True` и липса на recovery-source import;
- пълен regression без skipped security тестове.

## 10. Ограничения и следваща граница

Stage 2.17 не е активна GUI функция, recovery success evidence, usability audit,
platform certification, legal review или production activation.

Stage 2.18 добавя отделно замразено conditional inspection-only widget/event
wiring и изисква visible Linux review. Normal-startup source preparation,
platform observations за всяка друга заявена система, истински Vault/recovery
input и всяка operation authority остават извън този bridge.

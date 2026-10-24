# MOKOSH Agent — Stage 2.40 source-inspection main-GUI bridge contract

## Статус

Този договор замразява Stage 2.40 като неактивен, one-shot handoff от main GUI
към exact fresh Stage 2.39 source-inspection review session. Той не активира
review flow, не добавя widget и не разширява recovery authority.

Няма accessibility, security, legal или standards certification claim.

## Единствен preparation вход

`prepare_main_gui_recovery_source_inspection_review_binding(prepared_session)`
приема само exact fresh
`PreparedVaultRecoverySourceInspectionReviewSession` от Stage 2.39.

Няма отделен `locale_id`. Locale се наследява само от вече bound Stage 2.39
session. Няма normalization, OS/environment locale, fallback или caller choice
след preparation.

Връщаният exact type е
`PreparedMainGUIRecoverySourceInspectionReviewBinding`. Единственото му
действие е `show_once(parent)`.

## One-shot lifecycle

Lifecycle-ът е:

`READY -> DISPLAYING -> COMPLETED | FAILED`.

Преходът от `READY` към `DISPLAYING` става под process-local lock преди
делегирането. Concurrent или replay опит не може да започне втори display.

Success и bounded cancellation завършват като `COMPLETED`. Controller failure,
невалиден/foreign outcome, locale mismatch или всяка друга post-transition
грешка завършват като `FAILED`. `BaseException`/interrupt се пропуска към
caller-а, но binding-ът остава terminal. Няма retry или reset.

## Exact session/outcome binding

Преди display bridge-ът изисква:

- exact Stage 2.39 session type;
- неизменена identity спрямо session reference, получена при preparation;
- exact `PREPARED` controller state;
- exact bound `RecoveryLocalizationLocale`;
- същата session reference, получена при preparation.

След display raw result се приема само ако:

- е exact `VaultRecoverySourceInspectionReviewWindowOutcome`;
- Stage 2.39 session е exact `COMPLETED`;
- `session.outcome is raw_result`;
- locale съвпада с предварително bound locale.

Raw result се reconstruct-ва чрез dataclass validation. Така всички Stage
2.37/2.38 authority, receipt, presentation-digest, cancellation и fixed-schema
инварианти се изпълняват отново. Caller получава revalidated outcome, а не
непроверен foreign object.

## Retention граница

Binding-ът задържа до terminal state само exact Stage 2.39 session и bound
locale. Не задържа GUI parent, Stage 2.32 outcome, recovery/vault IDs, path,
source descriptor/content, presentation, adapter, password, secret, callback,
executor или operation capability.

След `COMPLETED` или `FAILED` session reference се изчиства. Binding-ът не може
да бъде copy, deepcopy или pickle/serialize.

## Main-GUI seam и import isolation

`mokosh_gui.py` добавя само:

- `_recovery_source_inspection_review_bridge_contract()`;
- `show_prepared_recovery_source_inspection_review(parent, prepared_binding)`.

Private helper-ът прави обикновен explicit conditional import само когато
seam-ът бъде извикан. Няма module-level runtime import, `TYPE_CHECKING` промяна,
dynamic import, plugin loader или caller-controlled module name.

Normal `import mokosh_gui`, normal `main()` и launcher-ът не зареждат Stage
2.40 bridge-а, не създават binding и не извикват seam-а. `main()` signature,
widgets, text registries, geometry и layout остават непроменени.

## Забранени възможности

Stage 2.40 няма API/import/call към:

- filesystem/source open, read, write, stat или mutation;
- Vault storage, recovery storage, reconciliation или recovery execution;
- password, secret, recovery root/record, keyring или source path/content;
- Stage 2.8, candidate, publish, setup, unlock, cleanup или crypto;
- callback, executor, operation/recovery capability или automatic transition;
- process, network, logging, telemetry, Contacts, Guardian, update/licensing;
- dynamic import, `eval`, `exec`, plugin или string-selected module.

`SAFETY_MODE=True` остава. Legacy encryption, cleanup, Contacts и Sandbox
controls не се отслабват.

## Exact project scope

Stage 2.40 променя точно 19 tracked paths:

1. `mokosh_vault_recovery_source_inspection_main_gui_bridge.py`;
2. `tests/test_mokosh_vault_recovery_source_inspection_main_gui_bridge.py`;
3. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_MAIN_GUI_BRIDGE_CONTRACT_BG.md`;
4. `mokosh_gui.py`;
5. `PROJECT_STATUS_BG.md`;
6. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`;
7. `docs/SESSION_LOG_BG.md`;
8. `tests/test_mokosh_main_gui_visual_filesystem_claims.py`;
9. `tests/test_mokosh_vault_recovery_entry_request.py`;
10. `tests/test_mokosh_vault_recovery_entry_transition.py`;
11. `tests/test_mokosh_vault_recovery_locale.py`;
12. `tests/test_mokosh_vault_recovery_source_inspection_acknowledgement.py`;
13. `tests/test_mokosh_vault_recovery_source_inspection_execution.py`;
14. `tests/test_mokosh_vault_recovery_source_inspection_localization.py`;
15. `tests/test_mokosh_vault_recovery_source_inspection_preparation_request.py`;
16. `tests/test_mokosh_vault_recovery_source_inspection_presentation.py`;
17. `tests/test_mokosh_vault_recovery_source_inspection_request.py`;
18. `tests/test_mokosh_vault_recovery_source_inspection_ui_adapter.py`;
19. `tests/test_mokosh_vault_recovery_source_selection.py`.

Paths 8–19 променят 13 historical exact-hash очаквания за `mokosh_gui.py` от
Stage 2.39 SHA-256
`45d4448acee351dd596ef9aa5bb6591c48a7181c87a6dfac6cca07e013f6b22c`
към Stage 2.40 SHA-256
`67641634da332a730ebea3ee25b69541eccbd35fcdd29c2d3924e1da41a2e7a1`.
Тъй като localization тестът hash-ва UI-adapter test file, exact transitive
closure изисква и една predecessor-test hash актуализация от
`deae4405e86e2f45e05040cd8f3b1ad2ae4279f2b6057907caf7f883c539a8d2`
към
`95a8ad6ca729305c0b7cc02d15a4cbc39335223f6c7afad45b668c2f1c94b760`.
Няма skip, assertion removal или behavior/security weakening.

Stage 2.32–2.39 production modules, historical contracts/tags, launcher,
crypto core и runtime requirements остават byte-exact.

## Evidence gate

Новият test module съдържа точно 24 tests за:

- BG/EN fresh binding, exact type и nonfresh отказ;
- private session-substitution отказ чрез отделен preparation identity guard;
- absence на caller locale/authority input;
- cancel/acknowledge, exact session state/outcome identity и revalidation;
- non-outcome, foreign same-locale, wrong-locale и forged-authority отказ;
- replay, controller failure, interrupt и concurrency;
- terminal clearing, no-parent retention и bounded outcome schema;
- copy/deepcopy/pickle отказ;
- forbidden imports/calls и единствен public function;
- exact conditional main-GUI helper/seam;
- fresh normal-import inactivity и unchanged `main()` signature;
- critical hashes, `SAFETY_MODE=True`, no top-level/`TYPE_CHECKING` import.

Първият targeted cycle даде 22 PASS / 2 FAIL поради test-expectation defect:
два теста са изисквали reconstructed outcome да има identity на raw controller
outcome. Production bridge правилно проверява raw identity и след това връща
fresh revalidated dataclass. Само assertions са коригирани; повторният exact
targeted gate е 24/24 PASS.

Последващият independent test review откри втори test-only defect: test 17 е
обхождал имената на `__slots__`, вместо стойностите им, при no-parent-retention
проверката. Assertion-ът е коригиран да проверява exact slot values; production
кодът, path scope и броят от 24 теста не се променят.

High recovery review откри, че mutable private `_session` slot е позволявал
подмяна с друга fresh exact-type session със същия locale, въпреки frozen
изискването за същата preparation reference. Bridge-ът вече пази отделна
process-local identity стойност, проверява я преди display и изчиства и двете
стойности при terminal state. Отрицателният сценарий е добавен към съществуващ
test method; production authority, 19-path scope и броят от 24 теста остават
непроменени.

R1--R4 delivery artifacts са оттеглени и забранени. Replacement delivery
използва exact `.git`-free `git archive HEAD` candidate и отделя live baseline,
runtime, candidate, apply и rollback state. Няма candidate clone/fsck/dangling
policy или installer-specific ML-KEM API. Преди packaging неговите 33 internal
positive/negative tests са PASS, но това не е final package, laptop, full-suite
или live-apply evidence.

Очакваният authoritative full gate е 2012 tests, `expected failures=3`,
`skipped=0`, с exact baseline-relative bytecode state и clean worktree.

## Visual, standards и legal граница

Няма human visual gate, защото Stage 2.40 не променя видим GUI, widget, текст,
layout или geometry. Това не е usability/accessibility result.

NIST SSDF 1.1 остава final engineering baseline, а SSDF 1.2 остава tracked
draft. WCAG2ICT е informative traceability за бъдещи native-GUI промени. CRA
reporting milestone 2026-09-11 остава отделен product/distribution readiness
въпрос. Няма automatic applicability, conformity или legal-opinion claim.

## Commit/tag и следващ Stage

Commit и annotated tag се създават само след package self-tests, exact
allowlist/hash/mode checks, targeted/transitive/full regression, bytecode delta
gate, independent exact-diff factual review и clean live apply evidence.

След успешно затваряне на Stage 2.40 се изнасят HISTORY bundle, Stage 2.41
INPUT и HANDOFF и работата продължава в нов чат.

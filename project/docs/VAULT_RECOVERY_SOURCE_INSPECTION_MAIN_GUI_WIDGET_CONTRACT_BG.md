# MOKOSH Agent — Stage 2.41 source-inspection main-GUI widget contract

## Статус

Stage 2.41 добавя само условен, видим и еднократен main-GUI widget/event върху
exact fresh Stage 2.40
`PreparedMainGUIRecoverySourceInspectionReviewBinding`. Normal startup не
създава binding и не активира widget-а.

Това е inspection-only интеграция. Тя показва вече ограничения резултат от
source inspection; не избира, отваря, чете или променя recovery source и не
разрешава или извършва recovery операция. Няма security, accessibility, legal,
standards или platform certification claim.

## Точен вход и ordering

Сигнатурата е:

`main(prepared_recovery_review_binding=None, *,
prepared_recovery_source_inspection_review_binding=None)`.

Старият positional вход остава съвместим. Новият вход е keyword-only. Двата
conditional binding-а са взаимно изключващи се. Invalid, nonfresh или двойно
подаден binding се отказва преди `ensure_private_data_dir()` и `tk.Tk()`.
Locale се наследява само от exact Stage 2.40 binding; няма caller/OS locale,
fallback или normalization.

Stage 2.40 bridge остава извън module-level runtime imports. Той се зарежда
чрез обикновен conditional import само за explicit seam/conditional mode.
Normal import, `main()` и `run_mokosh_gui.sh` не зареждат bridge, не създават
widget и не извикват review.

## One-shot event

Lifecycle: `READY -> DISPLAYING -> COMPLETED | FAILED`.

Event-ът приема само exact fresh Stage 2.40 binding, допуска едно button
attach-ване, изчиства retained binding под lock и деактивира button-а преди
display. Success се приема само ако binding-ът е `COMPLETED` и
`binding.outcome is returned_outcome`. Failure, unexpected exception,
interrupt, replay и concurrent invocation са terminal; няма retry/reset.

GUI success/failure текстовете са фиксирани BG/EN и не показват exception,
path, source metadata или secret.

## Layout и controls

Новият banner/button е непосредствено след safety banner-а за видимост и
keyboard reachability при увеличен Tk scaling. Conditional geometry е
`820x560`, със стандартен resize. Normal recovery entry chain не се създава.
Language, Vault, password, nickname, login, encrypt/decrypt/cleanup, Contacts
и Sandbox controls са disabled. `SAFETY_MODE=True` остава.

## Filesystem и authority граница

Stage 2.41 не добавя recovery-source/user-file filesystem access или mutation.
Валиден conditional main GUI продължава съществуващия Stage 2.24
`ensure_private_data_dir()`, затова whole-process no-filesystem/no-mutation
твърдение е забранено.

Няма API/import/call за source/path/content, password/secret/keyring, Vault,
crypto, unlock, candidate/publish, recovery execution, callback/executor,
capability, automatic transition, process, network, logging, telemetry,
dynamic import или plugin loading.

## Fixed synthetic visual evidence

Pure core създава само deterministic non-secret Stage 2.32 outcomes и ги
предава през exact Stage 2.39 session и Stage 2.40 binding. Няма GUI,
filesystem, network, process, logging или operation capability в core-а.

Linux матрицата е:

1. `bg-BG`, 100%, Escape;
2. `en-GB`, 125%, Cancel;
3. `bg-BG`, 150%, child Window X;
4. `en-GB`, 200%, Acknowledge.

Шестте self-reported observations са: banner/button без clipping, disabled
unrelated controls, keyboard reachability/no trap, child front/modal, readable
localized layout и permanently disabled one-shot button.

Report-ът казва `runtime_directory_preparation_performed=true`, но
`recovery_source_filesystem_access_performed=false` и
`recovery_source_filesystem_mutation_performed=false`. Той не доказва
accessibility/legal conformity, human understanding или certification.

## Exact mutation allowlist

Stage 2.41 променя точно 24 tracked paths:

1. `mokosh_gui.py`;
2. `mokosh_vault_recovery_source_inspection_main_gui_visual_harness.py`;
3. `run_main_gui_recovery_source_inspection_review_visual_harness.py`;
4. `tests/test_mokosh_vault_recovery_source_inspection_main_gui_widget.py`;
5. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_MAIN_GUI_WIDGET_CONTRACT_BG.md`;
6. `PROJECT_STATUS_BG.md`;
7. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`;
8. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`;
9. `docs/SESSION_LOG_BG.md`;
10. `tests/test_mokosh_main_gui_visual_filesystem_claims.py`;
11. `tests/test_mokosh_vault_recovery_entry_request.py`;
12. `tests/test_mokosh_vault_recovery_entry_transition.py`;
13. `tests/test_mokosh_vault_recovery_locale.py`;
14. `tests/test_mokosh_vault_recovery_main_gui_widget.py`;
15. `tests/test_mokosh_vault_recovery_source_inspection_acknowledgement.py`;
16. `tests/test_mokosh_vault_recovery_source_inspection_execution.py`;
17. `tests/test_mokosh_vault_recovery_source_inspection_localization.py`;
18. `tests/test_mokosh_vault_recovery_source_inspection_main_gui_bridge.py`;
19. `tests/test_mokosh_vault_recovery_source_inspection_preparation_request.py`;
20. `tests/test_mokosh_vault_recovery_source_inspection_presentation.py`;
21. `tests/test_mokosh_vault_recovery_source_inspection_request.py`;
22. `tests/test_mokosh_vault_recovery_source_inspection_request_main_gui_widget.py`;
23. `tests/test_mokosh_vault_recovery_source_inspection_ui_adapter.py`;
24. `tests/test_mokosh_vault_recovery_source_selection.py`.

Stage 2.32–2.40 production layers, crypto core, runtime requirements, launch
shell и историческият Stage 2.40 contract остават byte-exact.

## Acceptance gates

- exact 36/36 Stage 2.41 tests;
- exact 24/24 Stage 2.40 predecessor tests;
- full 2048 tests, `expected failures=3`, `skipped=0` в lexical
  `~/venv_sys/bin/python3`;
- unchanged 4341-record baseline-relative bytecode digest;
- exact allowlist/modes, `git diff --check`, strict `git fsck`;
- complete four-case human matrix с шест PASS observations на case.

Automated PASS не замества human visual PASS. Commit и annotated tag се
създават само след всички gates.

## Нормативна граница

NIST SSDF 1.1 е final engineering reference; SSDF 1.2 остава draft. WCAG2ICT
2.2 е informative guidance, не самостоятелен conformance standard. CRA
applicability зависи от product/distribution role. Няма silent baseline switch,
automatic applicability, CE readiness или legal opinion.

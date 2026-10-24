# MOKOSH — Stage 2.42 normal-main-GUI recovery-chain layout audit

Статус: приет audit/pre-activation freeze върху exact Stage 2.41 checkpoint
`2f1e1ee6c799423f9461dd09c53ed3b71d51ab5a`. Този Stage не променя
production GUI и не активира следващ recovery слой.

## 1. Причина и цел

Stage 2.30 доказва normal-GUI четиристъпковата recovery request в BG/EN, но
матрицата му няма 100/125/150/200% Tk scaling. Stage 2.41 доказва тази scaling
матрица само за отделния conditional source-inspection review mode.

Преди пето normal-GUI действие или request-to-review activation Stage 2.42
проверява съществуващия `820x720` normal layout за:

- видимост и clipping на safety/recovery и останалите controls;
- четим BG/EN текст;
- keyboard reachability, visible focus, meaningful order и no trap;
- operability след enlarge/restore;
- липса на automatic dialog, picker, source access или recovery operation.

Това е bounded human layout audit, не accessibility evaluation или
conformity assessment.

## 2. Архитектурно решение

Директно Stage 2.29 -> Stage 2.41 свързване е извън freeze. Между тях остават
отделните Stage 2.31 preparation request, Stage 2.32 explicit one-secure-read
authorization/execution и Stage 2.39/2.40 review session/binding.

Stage 2.42 не добавя пето действие. Human matrix трябва първо да покаже дали
съществуващият normal layout е достатъчен. При FAIL/NOT_CHECKED activation
остава блокирана и се изисква explicit corrective re-freeze преди live apply.

## 3. Fixed matrix

Матрицата е exact:

1. `bg-BG`, 100%, `initial_keyboard`;
2. `en-GB`, 125%, `initial_keyboard`;
3. `bg-BG`, 150%, `resize_restore_keyboard`;
4. `en-GB`, 200%, `resize_restore_keyboard`.

Всеки case записва точно осем enum observations: `pass`, `fail` или
`not_checked`. Няма свободни notes, dimensions, coordinates, screen/host
metadata, screenshot или exception text. Само осем `pass` допускат human gate
PASS. FAIL е валидно наблюдение, но блокира candidate live apply и не се
преименува на PASS.

## 4. Runtime граница

Launcher-ът:

- използва normal `mokosh_gui.main()` без argument/binding;
- задава само fixed locale и Tk scaling преди normal construction;
- не извиква recovery actions и не използва `event_generate`/widget invoke;
- не отваря picker и не иска path, Vault, password или secret;
- не прави screen capture и не записва geometry/host metadata;
- restore-ва patched Tk factory и global locale във `finally`;
- връща `0` само при четири complete all-PASS reports, `2` при human
  FAIL/NOT_CHECKED, `1` при bounded launcher failure и `130` при cancel.

Normal `main()` продължава Stage 2.24 private runtime-directory preparation,
затова report-ът казва `runtime_directory_preparation_performed=true`. Това не
е whole-process no-filesystem claim. Recovery-source access/mutation остават
false.

## 5. Pure report core

Core-ът import-ва само `json`, `dataclasses`, `enum`, `typing` и
`__future__`. Той създава fixed cases, strict immutable reports и canonical
UTF-8 JSON до 4096 bytes.

Report-ът задължително отказва true claims за:

- true recovery input, picker или path metadata;
- recovery-source access/mutation;
- Stage 2.31 GUI wiring, Stage 2.32 secure read или Stage 2.41 normal
  activation;
- operation authority/performance, network или automatic event injection;
- screenshot/host/geometry recording;
- accessibility/legal conformity, platform certification или human
  understanding.

## 6. Exact frozen paths

Stage 2.42 променя точно осем paths:

1. `mokosh_main_gui_recovery_chain_layout_audit.py`;
2. `run_main_gui_recovery_chain_layout_audit.py`;
3. `tests/test_mokosh_main_gui_recovery_chain_layout_audit.py`;
4. `docs/MAIN_GUI_RECOVERY_CHAIN_LAYOUT_AUDIT_CONTRACT_BG.md`;
5. `PROJECT_STATUS_BG.md`;
6. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`;
7. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`;
8. `docs/SESSION_LOG_BG.md`.

`mokosh_gui.py`, production/recovery/crypto/storage modules, launch shell,
requirements и всички historical tests/contracts остават byte-exact.

## 7. Automated и human gates

- exact 32/32 Stage 2.42 tests, plain `OK`;
- exact 36/36 Stage 2.41 predecessor, plain `OK`;
- exact 24/24 Stage 2.40 predecessor, plain `OK`;
- full 2080 tests, expected failures=3, skipped=0;
- `git diff --check`, strict fsck, exact eight-path bytes/modes/owner/ACL;
- unchanged baseline-relative bytecode state;
- safe normalized package, GNU-tar zero-output extraction и rollback injection
  след всяка от осемте copy позиции;
- complete four-case/eight-observation human matrix от isolated dry-run
  candidate преди live apply.

Първоначалният test cycle даде 31 PASS/1 false fail, защото raw substring
проверка намери защитната дума `callback` в docstring. Root cause е lexical
test predicate вместо AST capability predicate. Test-only корекцията проверява
реални forbidden imports/calls и включва negative regression, че защитни думи
в docstring не fail-ват. Повторният exact gate е 32/32 PASS.

## 8. Standards и правна граница

NIST SSDF 1.1 остава final engineering baseline; SSDF 1.2 остава Initial
Public Draft. WCAG2ICT 2.2 е informative guidance. EN 301 549 V4.1.1
(2026-09) е публикуван, но няма автоматичен Official Journal, applicability,
presumption-of-conformity или MOKOSH conformity claim.

CRA Article 14 reporting започва на 2026-09-11 при приложим manufacturer и
product-with-digital-elements scope; Stage 2.42 local audit не е release или
placing on the market. Точната CRA/EAA/българска applicability оценка остава
отделен qualified pre-distribution gate.

## 9. Забранени твърдения

Stage 2.42 не доказва accessibility, usability за всички потребители,
screen-reader/assistive-technology support, legal compliance, certification,
platform support извън наблюдавания Linux setup, source authenticity,
recovery success или production readiness.

## 10. Corrective supersession след blocking human FAIL

Този раздел supersede-ва секции 6–7 само за текущия corrective candidate;
първоначалният осем-path audit-only freeze и неговият FAIL остават историческо
evidence. R1 не може да се използва за live apply.

Case 1 `bg-BG`/100%/initial доказа, че fixed `820x720` normal window показва
четирите дълги recovery actions, но скрива по-късните normal controls. User-ът
прие corrective re-freeze с exact 23-path allowlist:

1. първоначалните осем audit/evidence paths;
2. `mokosh_gui.py`;
3. дванадесетте dependent GUI-hash test paths;
4. `tests/test_mokosh_vault_recovery_main_gui_widget.py`;
5. `tests/test_mokosh_vault_recovery_source_inspection_main_gui_widget.py`.

Само normal mode получава adaptive vertical Canvas/Scrollbar viewport.
Wheel, PageUp/PageDown/Home/End и видимото автоматично reveal-ване при
Tab/Shift+Tab са navigation/layout behavior, не recovery action. Conditional
review modes, action order/text/state и всички source/picker/secret/Vault/
crypto/storage/recovery-operation boundaries остават непроменени.

Corrective automated gate е exact 48/48 target, 36/36 и 24/24 predecessors,
full 2096 при expected failures=3 и skipped=0, exact 23-path package/rollback
и unchanged baseline-relative bytecode. След това четирите human cases се
изпълняват отначало; всяка от 32 observations трябва да е `pass` преди live
apply. Един FAIL/NOT_CHECKED блокира целия candidate.

Corrective delivery R1 е невалиден за live apply: неговата обща `0644`
baseline проверка не зачита exact physical modes на шест existing test paths.
Replacement delivery задължително сравнява всеки от 19-те existing targets с
индивидуалния frozen mode и overlay-ва същия mode; safe R1 stop не е mutation
или human evidence.

## 11. R2 withdrawal и final 25-path supersession

R2 също е невалиден за live apply. Той мина targeted/predecessor gates, но
full 2096 regression блокира върху два legacy normal-main Tk mocks и един
stale transitive predecessor test hash. Няма live mutation или human report.

Този раздел supersede-ва 23-path броя от секция 10. Окончателният allowlist е
exact 25 paths: същите 23 плюс:

1. `tests/test_mokosh_vault_recovery_entry_main_gui_widget.py`;
2. `tests/test_mokosh_vault_recovery_entry_transition_main_gui_widget.py`.

Двата tests добавят само bounded `Canvas`/`Scrollbar` fake compatibility към
съществуващото normal-main construction evidence. Localization test-ът, който
вече е в allowlist-а, получава exact нов hash на UI-adapter test-а. Няма нова
production функция, authority или sensitive path. R3 изисква два
последователни post-documentation full 2096 PASS преди package construction.

## 12. R3 status-parser withdrawal

R3 не е валиден live apply въпреки automated и human PASS evidence, защото не
издаде final marker. Post-overlay status gate използваше `.strip()` върху Git
porcelain output и премахна значимия leading space на първия ` M` ред. Raw
25-line status е exact match; transaction rollback е изпълнен и проверен.

R4 не променя GUI или 25-path allowlist. Wrapper-ът сравнява raw
`stdout.splitlines()` и доказва в self-test/synthetic transaction exact
25-path overlay status и clean rollback status преди package issuance.

## 13. Authoritative R4 completion evidence boundary

R4 live transaction и independent post-apply gate са PASS за exact 25-path
candidate. Automated counts са 48/48, 36/36, 24/24 и full 2096 при expected
failures=3, skipped=0. Human matrix е 4/4 cases и 32/32 self-reported PASS.

Independent evidence включва exact raw Git status, package-equal bytes,
physical modes, owner/group, ACL, tracked-mode distribution, strict fsck и
unchanged baseline-relative bytecode. Това разрешава final evidence amendment
и pre-commit review, но не е само по себе си commit/tag или разширение към
пето recovery действие.

Няма accessibility/legal conformity, platform certification, assistive-
technology completeness, source authenticity, recovery success или
production-readiness claim. R1–R3 остават withdrawn historical evidence.

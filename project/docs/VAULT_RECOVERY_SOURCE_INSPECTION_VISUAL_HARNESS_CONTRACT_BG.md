# Stage 2.38 — договор за визуален harness на прегледа на проверката на източника

Дата на freeze: 2026-08-30  
Ниво: High  
Статус: implementation-gated; human Linux visual gate е задължителен преди commit/tag

## 1. Цел и trust boundary

Stage 2.38 добавя pure synthetic contract и отделен visible Linux launcher за
реалния Stage 2.37 `Toplevel`. Входовете са само фиксирани, детерминистични,
несекретни Stage 2.32 execution outcomes, преобразувани през реалните Stage
2.33 presentation, Stage 2.35 adapter, Stage 2.36 localization и Stage 2.37
review-window договори.

Core модулът няма Tk, filesystem, network, process, logging, source reader,
Vault, password, callback, executor, recovery или operation capability.
Launcher-ът не стартира `mokosh_gui.py`, не приема path/secret/source bytes и
не използва automatic GUI event injection. Във всеки от осемте cases първо
се проверяват трите default-false boxes, select-all-by-individual-actions,
uncheck/re-disable и recheck; едва след това се изпълнява frozen terminal action.

## 2. Exact визуална матрица

| № | Locale | Относителен Tk scale | Профил | Размер | Задължително крайно действие |
|---:|---|---:|---|---|---|
| 1 | bg-BG | 100% | small | 560×440 | Escape |
| 2 | en-GB | 125% | small | 560×440 | Cancel button |
| 3 | bg-BG | 150% | standard | 800×640 | WM close |
| 4 | en-GB | 200% | standard | 800×640 | acknowledgement |
| 5 | bg-BG | 125% | standard | 800×640 | Cancel button |
| 6 | en-GB | 150% | small | 560×440 | Escape |
| 7 | bg-BG | 200% | small | 560×440 | acknowledgement |
| 8 | en-GB | 100% | standard | 800×640 | WM close |

Всеки locale/scale/action се покрива по два пъти. `small` не е под Stage 2.37
minimum `560×440`.

Tk scaling е относително: launcher-ът прочита началната platform scaling
стойност и прилага `base_scaling × percent / 100`. Historical Stage 2.15
absolute `percent / 100` pattern не се копира, защото Tk scaling е pixels per
point, а не процент.

## 3. Mapping watchdog и ръчно взаимодействие

Launcher-ът проверява на всеки 25 ms до точно 80 пъти дали child window е
mapped. При timeout child се унищожава, няма report и process-ът отказва с
ненулев status. Timeout никога не се представя като успешно WM-close събитие.

Няма `event_generate`, programmatic button invocation, automatic checkbox
selection или автоматично terminal действие. Потребителят изпълнява exact
действието ръчно. Във всеки case първо проверява трите default-false
checkboxes, избира ги individually, маха един избор, потвърждава повторното
disable-ване и го избира отново. След това използва exact frozen terminal
action; при acknowledgement това е explicit final button.

След всеки mapped case се попълват точно шест наблюдения:

1. достижимост на всички messages/controls и scrolling;
2. wrapping без clipping, truncation или overlap;
3. логичен, видим и unobscured focus order;
4. keyboard-only Tab/Space/scroll/Escape без keyboard trap;
5. default-false и enable/re-disable поведение;
6. видими title/labels в очаквания locale.

`fail`, `not_checked`, terminal-action mismatch, malformed result, mapping
failure или runtime/display error дават ненулев status. Наблюденията са
self-reported и не са independent audit evidence.

## 4. Bounded report и честни claims

Нормалният stdout съдържа само един canonical bounded JSON object за всеки
успешно mapped case. Инструкциите и шестте наблюдения са в отделни,
преоразмеряеми и превъртаеми harness-only GUI фази; diagnostic text е на
stderr. JSON няма notes,
path, filename, hostname, environment dump, source bytes, secret, callback или
executor и не се записва автоматично във файл.

Report-ът изрично държи false за:

- platform certification и accessibility conformity;
- screen-reader, accessibility API и contrast verification;
- пълно прилагане на platform user preferences;
- human understanding, identity и informed consent proof;
- main-GUI activation, real Vault input, recovery/operation authority;
- filesystem mutation, network, retained secrets/source/path/capabilities.

Ръчният gate открива наблюдаеми проблеми само в текущата Linux/Wayland/Tk
среда. Не доказва Windows/macOS behavior, assistive-technology interoperability,
WCAG/EN/EAA conformity, legal compliance или сертификация.

## 5. Scope, evidence и stop rule

След приетия responsive-UI amendment се променят точно дванадесет paths:

1. `mokosh_vault_recovery_source_inspection_review_window.py`
2. `tests/test_mokosh_vault_recovery_source_inspection_review_window.py`
3. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_CONTRACT_BG.md`
4. `mokosh_vault_recovery_source_inspection_visual_harness.py`
5. `run_recovery_source_inspection_review_visual_harness.py`
6. `tests/test_mokosh_vault_recovery_source_inspection_visual_harness.py`
7. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_VISUAL_HARNESS_CONTRACT_BG.md`
8. `docs/VAULT_RECOVERY_PLATFORM_CHECKLIST_BG.md`
9. `PROJECT_STATUS_BG.md`
10. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
11. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
12. `docs/SESSION_LOG_BG.md`

Stage 2.37 targeted gate е точно 84 tests, а Stage 2.38 targeted gate е точно
90 tests. Expected authoritative full gate е 1955
tests, `OK (expected failures=3)`, skipped=0, 193 tracked files и 136 tracked
Python sources. Преди commit/tag са задължителни exact predecessor identity,
allowlist/hash/mode/source-manifest, compile, targeted/full regression,
isolated apply/rollback, clean worktree и human eight-case Linux visual PASS.

При визуално открит Stage 2.37 defect работата спира. Няма silent patch на
Stage 2.37; нужна е explicit impact report, amendment/new freeze и изрично
приемане.

Proposed annotated tag:
`stage2.38-vault-recovery-source-inspection-visual-harness`.

## 6. Standards и правен статус

Правният/стандартен ledger използва четири статуса:

1. приложима задължителна правна норма;
2. доброволно приет engineering standard;
3. неприложим с конкретен мотив;
4. нуждае се от квалифицирана правна/conformity оценка.

Предназначението за частни лица и използването по техен избор не са общо
освобождаване от приложим закон. CRA може да обхваща consumer software,
пуснат на пазара на ЕС; EAA зависи от exact product/service scope. За MOKOSH
не се твърди окончателна applicability classification без реален release,
business/distribution model и квалифицирана правна оценка.

Доброволните security/accessibility стандарти се следват безкомпромисно като
engineering baseline, но не се представят като certification. Към freeze:

- WCAG 2.2 е W3C Recommendation; WCAG2ICT 2.2 е informative, non-normative
  guidance за non-web documents/software;
- ETSI work item е `adopted for publication` от 2026-08-24 за EN 301 549
  V4.1.0; OJ/harmonisation не се предполага без отделна authoritative проверка;
- final NIST SSDF v1.1 остава baseline; SSDF 1.2 е Initial Public Draft;
- FIPS 203 future update и SP 800-38D Rev.1 work са watch items;
- CRA reporting readiness от 2026-09-11 е project-level deadline watch item.

Всяко future official/scientific/legal изменение минава primary-source review,
impact analysis, explicit disclosure, new minimal freeze и explicit acceptance.
Нищо не се прилага автоматично и неизвестно бъдещо съответствие не се обещава.

## 7. Responsive harness workflow и fail-fast ред

Първият R1 visual attempt стигна до case 1, но operator instruction остана
разделена между GUI и terminal. След ръчно acknowledgement terminal prompt-ът
не беше откриваем, а проверяваният прозорец не осигури достатъчно ясно
resize/reflow/scroll поведение. Matrix беше прекратена със status 130;
installer rollback-ът потвърди exact clean Stage 2.37 и липса на Stage 2.38
commit/tag/files.

Amended launcher използва точен ред:

1. scrollable/resizable harness-only инструкция с девет номерирани стъпки;
2. explicit „Започни случая“;
3. real Stage 2.37 child при frozen locale/scale/profile;
4. незабавна validation на exact terminal action;
5. само при match — scrollable/resizable GUI с шест observation rows;
6. всеки row започва без избор и изисква explicit PASS/FAIL/not-checked;
7. mismatch, FAIL, not-checked, cancel или close спира matrix fail-fast.

Няма stdin/readline prompt, automatic checkbox/action injection или
предварително избран PASS. Дългите инструкции, наблюдения и преводи са
вертикално подредени, dynamic-wrapped и keyboard/mouse-scroll reachable.
Това е engineering evidence, не accessibility/legal certification.

## 8. R3 sequential-case instruction model

Два последователни R2 опита доказаха, че operator може логично да възприеме
Cases 1–8 като условни действия според резултата, вместо като предварително
зададена последователност от route tests. В Case 2 беше използван Escape,
защото той беше разбран като общ начин за преминаване към въпросите, докато
fixed matrix изисква Cancel. R2 правилно отказа mismatch и rollback-на, но
instruction model-ът не беше достатъчно разбираем.

R3 изисква:

- един matrix overview преди Case 1: Cases са exact sequence 1→8, не branches;
- общите проверки и case-specific terminal action са визуално отделени;
- голям case/action banner, който не разчита само на цвят;
- Start е disabled до explicit unchecked-by-default acknowledgement на exact
  action;
- текстът изрично казва, че questions се отварят автоматично и Escape не е
  общ continue key;
- mismatch изписва bounded `CASE / EXPECTED / OBSERVED` в GUI и stderr;
- matching-action contract fault има отделна диагностика;
- action route остава независим от последващия PASS/FAIL observation.

R3 не добавя automatic events, real input, secrets, operation authority,
filesystem/network capability или свободен diagnostic payload.

## 9. R4 corrective ownership gate

Първият R3 laptop visual run мина automated gates, но спря преди да отвори
GUI с `NameError: name 'case' is not defined`. Case-specific action banner е
бил поставен погрешно в one-time matrix overview, а resize callback-ът на
case instruction го е използвал без локално създаване. Това е implementation
и test-design defect; не е operator error.

R4 мести banner-а единствено в `_show_case_instructions` и добавя два
регресионни structural tests: overview не може да зарежда case-specific
`case`/`action` или да извиква `_action_banner_text`, а case instruction
трябва да създаде banner-а преди resize употребата му. Няма промяна в
matrix semantics, данни, правомощия, стандарти или final 12-path allowlist.

## 10. R5 unified visible-regions и live geometry gate

R4 laptop automated gates преминаха, но human run установи общ layout defect:
overview/instruction/observation използваха page-level expanding `pack()`
преди footer controls. Footer-ът беше извън Canvas и scrolling не можеше да
го достигне. Case 4 е first 200% case и fixed `680×560` geometry направи
дефекта блокиращ. Трите по-ранни self-reported PASS JSON отчета са withdrawn
след explicit operator correction.

R5 изисква за overview, case instruction и observations:

- fixed short header row 0;
- единствен expanding/scrolling canvas row 1;
- fixed action footer row 2;
- само row 1 има vertical weight;
- дългите инструкции са в scroll content, не във fixed header/footer;
- live mapped check за exact regions и required footer controls;
- minimum 80-pixel usable middle viewport;
- bounded failure `PHASE/CASE/SCALE/PROFILE`, без dimensions/coordinates;
- gate преди acknowledgement wait, Start или observation input.

Stage 2.37 child има аналогичен live gate преди visible claim/control enable.
Exact R5 targeted evidence е 84 + 90 = 174 tests; full target е 1955,
expected failures=3, skipped=0. Human 1→8 matrix остава задължителна и започва
отначало. Няма automatic GUI events, real Vault/source, network/filesystem
operation, secret, accessibility certification или legal conformity claim.


## 11. Post-R5 runtime-resize corrective invariant

R5 historical evidence не се пренаписва. След последващ operator-reported
intermittent resize-operability finding и read-only D2/D3 diagnostics root cause
остава недоказана; corrective design не може да твърди focus, grab, Wayland,
window-manager, stale binding или друга конкретна причина без evidence.

Минималният corrective invariant е production-local и idempotent:

- само Toplevel `<Configure>` след completed initial activation може да schedule-не
  проверката; burst events се debounce-ват на 125 ms;
- след settle се повтаря exact mapped/nonzero/client-bounds/order/minimum-middle
  gate за header, canvas, footer, Cancel и Confirm;
- Confirm visual state се resync-ва единствено от already-authoritative
  `prepared.confirm_enabled`; resize не записва confirmation и не acknowledge-ва;
- ако вече focused widget е една от трите confirmations, scroll viewport може
  само да го reveal-не; resize guard не мести focus и не генерира key/mouse event;
- нарушена runtime layout invariant е bounded fail-closed DisplayError; pending
  debounce callback се cancel-ва при destroy;
- няма real Vault/source/secret/path, network/filesystem mutation, main-GUI
  activation, recovery execution/authority или automatic human acceptance.

Това е robustness/complete-mediation hardening срещу доказания initial-only
coverage gap, а не твърдение, че недоказана mechanical root cause е поправена.
Candidate behavioral evidence includes direct fake-runtime execution of debounce/state/focus/fail-closed paths in addition to structural checks.
Final Stage 2.38 acceptance изисква automated laptop PASS и отделен human
initial/enlarged/restored mouse+keyboard storyboard PASS.

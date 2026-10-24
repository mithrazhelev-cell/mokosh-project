# Stage 2.43 — normal-GUI source-inspection preparation-request transition

Статус: приет minimal freeze върху exact Stage 2.42 checkpoint
`98cbd53c132800a790c8fbd957dc0f913d264e9e`.

## 1. Цел и архитектурна граница

Stage 2.43 свързва exact positive Stage 2.29 inspection-request outcome към
вече съществуващия pure Stage 2.31 preparation-request contract чрез пето
отделно normal-GUI действие.

Това е само намерение за бъдеща secure-inspection preparation. Не е source
access, source preparation, identity proof, authorization, review activation
или recovery operation. Директно Stage 2.29 към Stage 2.32 или Stage 2.39–2.41
свързване е забранено, защото би прескочило отделните complete-mediation
граници.

## 2. Exact prerequisite и state machine

Петото действие започва `LOCKED`. Само fully revalidated exact positive Stage
2.29 outcome може еднократно да го премести в `READY`. Preserve, wrong type,
derived type, forged flag/path/schema или невалидна sequence не могат да го
отключат.

Първият valid click atomically преминава през `DECIDING` към terminal
`COMPLETED` или `FAILED`. Няма reset/retry; replay и concurrent втори consumer
са отказани. Failure при widget configuration или downstream arm не задържа
predecessor reference.

## 3. Пет отделни user actions

Normal recovery request chain е:

1. request recovery review;
2. proceed to future source selection;
3. select an untrusted local recovery-record path;
4. request future secure inspection;
5. request future secure-inspection preparation или preserve and stop.

Нито едно positive действие не извиква автоматично следващото. Четвъртото
само unlock-ва петото. Отделен explicit fifth click и отделен confirmation са
задължителни.

## 4. Conditional import и sensitive-reference lifecycle

Stage 2.27, Stage 2.29 и Stage 2.31 не се import-ват при fresh normal GUI
import. Stage 2.31 се зарежда само след explicit fifth click.

Преди Stage 2.31 loader и modal confirmation event-ът:

- disable-ва fifth button;
- clear-ва retained exact Stage 2.29 outcome от собственото си state;
- clear-ва bound locale;
- предава predecessor-а само на exact Stage 2.31 preparation function;
- премахва локалната predecessor reference преди confirmation dialog.

Stage 2.31 prepared object временно задържа само валидирания path, не
оригиналния Stage 2.29 object. Python `str` не предлага доказуема memory
zeroization. Затова `memory_zeroization_proven=false` и
`global_source_outcome_consumption_enforced=false` остават честни contract
твърдения.

При preserve Stage 2.31 outcome няма path metadata. При request bounded Stage
2.31 outcome съдържа process-local sensitive path metadata само за отделна
бъдеща стъпка. GUI не persist-ва, log-ва, hash-ва или показва path.

## 5. No-access и no-authority boundary

Stage 2.43 не:

- open/read/stat/lstat/resolve/realpath-ва recovery source;
- проверява existence, identity, authenticity, ownership или permissions;
- издава filesystem capability или source-access authorization;
- извиква Stage 2.5 secure reader или Stage 2.32 execution authorization;
- подготвя review session или активира Stage 2.39–2.41;
- приема password, recovery secret, Vault или key material;
- извършва recovery operation, user-file mutation, network, cloud, telemetry,
  logging или persistence;
- променя Vault, crypto, storage, Contacts или ML-KEM behavior.

Native picker е част от предходното трето действие и може да enumerate-ва
directories и filesystem metadata. Normal startup извършва съществуващата
private runtime-directory preparation. Следователно няма whole-process
no-filesystem-access claim.

## 6. Locale, presentation и layout

BG/EN banner, button, confirmation, requested, preserved и failure texts са
fixed, bounded и path-free. Те изрично разкриват process-local path retention,
липсата на доказуема Python-text zeroization и липсата на access/authority.

Locale се binding-ва от exact Stage 2.29 outcome при arming и не може да бъде
сменен за prepared fifth decision. Преди arming normal language control
обновява fixed fifth-action text.

Existing normal `820x720` geometry и Stage 2.42 adaptive vertical viewport се
запазват. Fifth control участва във focus-reveal controls. Conditional review
geometry остава `820x560` и не получава normal fifth action.

## 7. Visual evidence

Mandatory human matrix използва Stage 2.42 profiles:

1. `bg-BG`, 100%, initial keyboard;
2. `en-GB`, 125%, initial keyboard;
3. `bg-BG`, 150%, resize/restore keyboard;
4. `en-GB`, 200%, resize/restore keyboard.

Използва се само harmless non-sensitive synthetic file. Забранени са истински
recovery record, password, Vault и sensitive filename. Всички единадесет fixed
observations във всеки case трябва да са `pass`. Human evidence не е
system-call proof, screen-reader/assistive-technology coverage, accessibility
или legal conformity, platform certification, source authenticity или
recovery-success claim.

Първият R1 human attempt е валиден blocking usability result, не PASS: case 1
стигна до края на петте действия, но instruction-ите останаха в terminal,
picker-ът започна в `/tmp`, помощният wrapper създаде `.txt` вместо видимия по
default filter `.mokr`, а единадесетте terminal questions не бяха представени
като отделен GUI workflow. Operator-ът прекрати на първия въпрос; exit `130`
блокира live apply и independent laptop gate потвърди exact clean Stage 2.42
HEAD/tree/status и премахнат temporary fixture.

Corrective visual workflow не променя production behavior или 22-path scope:

- отделен, немодален `Stage 2.43 ПЪТЕВОДИТЕЛ` остава видим до normal MOKOSH и
  показва една от девет последователни инструкции;
- всеки action, confirmation, последващ `OK`, picker navigation, exact
  request/preserve route, keyboard и resize/restore задача имат explicit
  текуща инструкция;
- runner-ът създава exact empty non-secret `.mokr` fixture в physical
  `~/Downloads` с `O_EXCL`, `O_NOFOLLOW`, mode `0600`, current owner/group и
  inode identity; fixture-ът се revalidate-ва и unlink-ва преди report;
- fixture creation/deletion е explicit visual-runner filesystem mutation, не
  MOKOSH recovery-source mutation. Report v2 използва честното поле
  `application_recovery_source_filesystem_mutation_performed=false` и отделни
  true disclosure/cleanup fields; няма whole-process no-filesystem claim;
- след всеки main window се отваря graphical twelve-question wizard. Всеки
  отговор започва `not_checked`, `PASS` никога не е preselected и next/submit
  остава disabled до explicit human избор;
- `fail`, `not_checked`, cancel, fixture mismatch или guide/GUI error връща
  nonzero status и блокира live apply.

R2 също е blocking human-usability evidence, не PASS. Automated dry-run и
pre-human apply gates минаха, но guide-ът беше създаден преди normal main GUI и
остана зад него, а новият observation root също не беше изведен отпред. Case 1
беше прекратен безопасно с exit `130`; installer-ът блокира преди live apply и
отделният read-only gate потвърди exact clean Stage 2.42 и премахнат `.mokr`
fixture. R2 е withdrawn и не се retry-ва.

R3 създава guide-а на първия idle callback след построяването на normal main
GUI, държи го mapped/topmost чрез bounded 500 ms visibility watchdog и извежда
observation wizard-а topmost/focused. Report v3 не твърди guide visibility по
подразбиране: ново explicit human observation поле определя едновременно
`parallel_step_guide_visible` и `per_action_guidance_provided`. Matrix-ът става
12 observations на case, общо 48; production scope и behavior не се променят.

R3 human attempt също е blocking result. Guide-ът остана foreground, но
неговите manual navigation controls и wizard footer controls излязоха под
видимата work area; wizard body нямаше scrollbar. При destroy останалият
periodic callback произведе bounded `invalid command name ..._keep_visible`.
Safe cancel върна exit `130` и live apply остана блокиран. R3 е withdrawn.

R4 премахна periodic visibility callback и manual guide navigation, но human
attempt-ът откри нов blocking defect: след достигане до действие 3 guide-ът
остана на действие 1, защото валидното transient classic Tk state `active` беше
отхвърлено. Uncaught callback exception не е product exception, но прави
guide-а неприемлив. Safe cancel/exit `130` блокира live apply; R4 е withdrawn.

R5 passive polling допуска точно `normal`, `active` и `disabled` и се
синхронизира с най-далечното enabled действие, ако кратък междинен poll е
пропуснат. Current instruction е последвана от постоянен пълен шестфазен план в
scrollable guide-а. Истински invalid state се записва и затваря case-а
fail-closed; `_run_case` отказва преди observations/apply. Няма callback
wrapping, event injection, automatic action или automatic PASS. Wizard
`Cancel`, `Previous` и `Next/Save` controls остават фиксирани над отделен
scrollable body.

R5 human matrix не е приемлив PASS. Cases 1–3 бяха попълнени, но guide-ът
изискваше Tab/Shift+Tab проверка и после казваше само „Активирайте“, без да
посочи exact `Space` keystroke. Липсата беше компенсирана чрез chat, което
invalidates self-contained guide-usability evidence. Case 4 беше прекратен;
exit `130` блокира live apply и R5 е withdrawn.

R6 запазва production behavior и exact 22-path scope. Fifth instruction трябва
изрично и в този ред да изисква `Tab`, `Shift+Tab`, връщане с `Tab`, после
`натиснете Space, за да задействате петото действие чрез клавиатурата`.
Automated target и package payload verification блокират архив, ако exact
keystroke или purpose текстът липсва. Външна chat инструкция не е част от
human matrix и не може да поправя или валидира непълен guide.

Authoritative R6 evidence е успешно завършено: deterministic archive
`223721` bytes с SHA-256
`2bcb0b6f5aa1f0d470e0791fff52ec2e96b6d60f7d65a278ceed6d998090d69d`,
laptop dry-run, 4/4 cases и 48/48 human observations, post-human extracted
rollback, exact unstaged 22-path live overlay и post-overlay 2144/2144 tests.
Independent gate потвърди bytes/modes/owner/ACL/Git/fsck/physical manifest,
липса на fixture и непроменен bytecode преди/след още един full 2144 PASS.
Това не разширява capability или standards claims; commit/tag чакат final
evidence amendment и pre-commit gate.

## 8. Automated evidence

Точно 48 new test methods покриват prerequisite validation, forged outcomes,
state/order, request/preserve, locale binding, path/reference lifecycle,
generic errors, `BaseException`, replay, concurrency, петте отделни действия,
visual schema, fresh-import isolation, static no-capability/no-activation
граници и byte-exact critical predecessors.

Задължителни са Stage 2.43 48/48, Stage 2.42 48/48, Stage 2.41 36/36, Stage
2.40 24/24 и full 2144 regression при точно три legacy MOK1 expected failures
и zero skipped. Final candidate bytes минават повторно всички gates след
evidence updates.

## 9. Exact frozen scope

Exact scope е 22 paths: 18 modified и 4 new. `mokosh_gui.py` е единственият
production path. Новите paths са този contract, pure visual core, executable
launcher и 48-test module. Останалите modifications са четирите
status/evidence/session/crosswalk документа и тринадесетте доказани exact
`mokosh_gui.py` hash consumers.

Всеки допълнителен path блокира кандидата и изисква explicit re-freeze.
Existing target modes идват от машинно извлечения Stage 2.42 physical manifest;
new launcher е `0755`, другите new paths са `0644`.

## 10. Standards и правна граница към 2026-09-04

NIST SP 800-218 SSDF 1.1 остава final engineering baseline; Rev.1/SSDF 1.2
остава Initial Public Draft. WCAG2ICT 2.2 е informative W3C Group Note. ETSI
EN 301 549 V4.1.1 (2026-09) е публикуван, но publication не доказва Official
Journal citation, exact applicability или presumption of conformity.

CRA reporting датата 2026-09-11 и principal-obligations датата 2027-12-11 са
project-level readiness reminders, не автоматична applicability оценка.
EAA/GDPR/CRA и българската приложимост изискват отделен qualified
pre-distribution review.

Stage 2.43 не твърди accessibility, legal compliance, conformity,
certification, CE readiness или production readiness.

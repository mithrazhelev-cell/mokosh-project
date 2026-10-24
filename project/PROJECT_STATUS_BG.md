# MOKOSH Agent — текущо състояние

Последна проверка: 2026-09-20

## Git

- Клон: feature/mokosh-v2-core
- Stage 2.48 exact base commit:
  7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8
- Base tree: 3c30b84b10cb742ba4d08bc50d50361eaa953f06
- Baseline annotated tag:
  stage2.47-profile-recovery-phrase-password-replacement
- Stage 2.47 е committed и tagged в exact baseline по-горе. Stage 2.48 R1 е
  приложен и независимо проверен като exact 32-path unstaged state, но human
  Case 01 е `FAIL_REQUIRES_FIX_AND_RETEST`. На 2026-09-20 user-ът изрично
  разшири corrective scope-а на точно 34 paths чрез `mokosh_profile_ui.py` и
  `tests/test_mokosh_profile_ui.py`. Корекцията още е само в изолирано копие;
  няма corrective live apply, Stage PASS, commit или tag.
- Исторически Stage 2.46 остава exact 35-path delta върху Stage 2.45.2. R1 е оттеглен
  след fail-closed bytecode drift; R2 е приложен и проверен, а practical
  visual gates откриха locked-entry и first-run lifecycle defects преди
  commit. Приетите R3/R4/R5 корекции ги отстраниха и human BG/100 transition
  е 11/11 PASS. R6 documentation-only closure е приложен и независимо
  проверен на Python 3.12.3 с exact 35 unstaged paths, 4341 bytecode records
  и unchanged state. Completion amendment остава в същите пет документа;
  repository commit/tag се доказват само от отделния finalizer output.

## Тестове

Команда: python3 -m unittest discover -s tests -v

Stage 2.45.2 authoritative baseline: Ran 2217 tests — OK
(failures=0, errors=0, expected failures=0, skipped=0).

Stage 2.46 scratch new-suite candidate: Ran 62 tests — OK
(failures=0, errors=0, expected failures=0, skipped=0). Runtime е Python
3.12.14 / `cryptography 46.0.0`; това не замества pinned laptop gate.

Stage 2.46 scratch affected predecessor gate: 472/472 PASS с изрично
QA-only Argon2 API compatibility shim поради липсващ `argon2-cffi` в scratch.
Това доказва hash/static/recovery regression връзките, но не се представя като
авторитетно primitive или full-regression доказателство.

Stage 2.46 isolated exact-dependency full regression: Ran 2279 tests — OK
(failures=0, errors=0, expected failures=0, skipped=0), Python 3.12.14,
`cryptography 49.0.0`, `argon2-cffi 25.1.0`, Tkinter и real ML-KEM-768.
Това е силно local QA доказателство, но не замества exact laptop Python 3.12.3.

Stage 2.46 pre-issuance package QA: deterministic QA-profile dry-run и
exact-function disposable apply са PASS с `35/35` rollback injections,
candidate/live `62/62`, affected `472/472` и full `2279/2279`; zero non-pass,
staging или bytecode residue. Final-profile R1 self-test и authoritative laptop
dry-run са отделни gates; резултат от реалната машина още не се заявява.

Stage 2.46 R1 authoritative result: runtime/primitives PASS, после fail-closed
`bytecode baseline drift` преди payload/tests/mutation. Current snapshot е
`4341` records / SHA-256
`914e83be4f131de233a62dfca6da683485f6d48f1a1aacca96da1252db04d362`;
`crypto_core.pyc` е byte-identical с independent compile на exact tracked
source. R2 е package/evidence correction, не нов interface implementation.

Stage 2.46 R2 pre-issuance QA е PASS: 16 self-tests, `35/35` rollback,
candidate/disposable-live `62/62`, `472/472`, `2279/2279`, exact 35 unstaged,
zero staged и zero bytecode residue. Final documented bytes получиха fresh QA
и deterministic double build.

Stage 2.46 R2 authoritative laptop dry-run и live apply са PASS със същите
`62/62`, `472/472`, `2279/2279`. Independent post-apply verifier потвърди
package SHA-256, exact physical SHA-256
`54208fb61eaa7734c7c8fae89dc61338b8d7fa308f206ac502da2d21fdd340b2`,
4341 bytecode records, exact 35-path unstaged status и unchanged state. Външният
package mode е коригиран от browser-created `0664` на private `0600` преди
успешното повторение на verifier-а.

Първият practical visual Case 1 (`EN`, 100%, `LOCKED`) е `FAIL`: полетата са
enabled и caret-ът реагира, но всеки въведен знак се изчиства от общия activity
handler. Root cause засяга и production READY/LOCKED profile session. Exact
7-path R3 correction е приета; първите три event-routing regression теста
увеличават `tests.test_mokosh_profile_gui` до `14/14` и са PASS в scratch.
Exact-dependency R3 QA е PASS: target `65/65`, affected `472/472` и full
`2282/2282`, без non-pass или bytecode residue. Deterministic corrective
package, authoritative laptop gates и повторният human visual gate остават
pending.

## Завършени етапи

- Stage 0 — безопасна основа, спецификация и отрицателни тестове
- Stage 1.1 — строг v2 preamble/header codec
- Stage 1.2 — bounded frame codec и sequence validation
- Stage 1.3 — deterministic nonce и frame AAD binding
- Stage 1.4 — stateful in-memory AES-256-GCM frame engine
- Stage 1.5 — строг encrypted frame-0 manifest codec
- Stage 1.6 — in-memory manifest/frame integration
- Stage 1.7 — строг trailer и ciphertext transcript codec
- Stage 1.8 — in-memory Ed25519 signing и verification
- Stage 1.9 — строг key-slot schema и header validation
- Stage 1.10 — in-memory Argon2id password-slot wrapping
- Stage 1.11 — in-memory HKDF Key Vault slot wrapping
- Stage 1.12 — mandatory X25519 + ML-KEM-768 Contact slot wrapping

- Stage 1.13 — строг in-memory key-slot orchestration
- Stage 1.14 — пълна in-memory v2 envelope integration
- Stage 1.15 — bounded two-pass streaming envelope engine
- Stage 1.16 — safe filesystem source и quarantine primitives
- Stage 1.17 — verified deferred-publish файлов pipeline
- Stage 1.18 — контролиран lifecycle, cancellation и безопасни operation резултати

- Stage 1.19 — crash-safe journal и строго read-only quarantine reconciliation

- Stage 1.20 — bounded reconciliation evidence и non-mutating action planning

- Stage 1.21 — active-operation lease и fail-closed activity assessment

- Stage 1.22 — еднократен non-mutating cleanup authorization contract

- Stage 1.23 — строго ограничен one-shot cleanup executor

- Stage 2.1 — encrypted Key Vault формат и session state machine

- Stage 2.2 — immutable Vault generations и atomic no-clobber persistence

- Stage 2.3 — versioned Vault keyring и безопасна wrapping-key rotation

- Stage 2.4 — offline Vault recovery contract и read-only rehearsal

- Stage 2.5 — durable recovery-record export и read-only file rehearsal

- Stage 2.6 — explicit in-memory recovery Vault candidate и one-shot authorization

- Stage 2.7 — explicit immutable recovery publish с no-clobber и uncertain semantics

- Stage 2.8 — strict read-only recovery publish reconciliation

- Stage 2.9 — explicit non-mutating recovery workflow state

- Stage 2.10 — bounded non-secret recovery workflow presentation

- Stage 2.11 — one-shot non-mutating recovery presentation acknowledgement

- Stage 2.12 — bounded non-mutating recovery UI adapter contract

- Stage 2.13 — versioned bounded Bulgarian/English recovery localization

- Stage 2.14 — isolated local Tkinter recovery review window

- Stage 2.15 — isolated synthetic recovery review visual/platform harness

- Stage 2.16 — one-shot recovery review application-service controller

- Stage 2.17 — inactive one-shot main-GUI recovery review bridge

- Stage 2.18 — conditional inspection-only main-GUI recovery review widget/event

- Stage 2.19 — inactive one-shot non-secret recovery entry request

- Stage 2.20 — normal-startup one-shot non-secret recovery entry widget/event

- Stage 2.21 — inactive one-shot non-secret recovery entry transition contract

- Stage 2.22 — pure stdlib-only recovery locale leaf boundary

- Stage 2.23 — normal-main-GUI recovery import isolation boundary

- Stage 2.24 — explicit normal-main-GUI runtime path initialization boundary

- Stage 2.25 — separate normal-main-GUI recovery entry transition widget/event

- Stage 2.26 — precise normal-main-GUI visual filesystem claim semantics

- Stage 2.27 — inactive one-shot recovery source selection contract

- Stage 2.28 — separate normal-main-GUI recovery source-selection widget/event

- Stage 2.29 — inactive one-shot future secure-source inspection request

- Stage 2.30 — separate main-GUI recovery source-inspection request widget/event

- Stage 2.31 — inactive one-shot recovery source inspection preparation request

- Stage 2.32 — inactive one-shot secure recovery-source inspection execution

- Stage 2.33 — bounded non-secret recovery-source inspection presentation

- Stage 2.34 — one-shot non-mutating recovery-source inspection acknowledgement

- Stage 2.35 — bounded recovery source-inspection UI adapter core

- Stage 2.36 — fixed Bulgarian/English source-inspection localization

- Stage 2.37 — isolated local source-inspection review window

- Stage 2.38 R5 — technical synthetic Linux source-inspection visual/platform harness checkpoint; corrective quality acceptance pending

## MOKOSH Project Integrity and Full Disclosure Invariant

- Всяка открита грешка, deviation, assumption, риск, промяна, добавка,
  обновяване, standards revision или нормативен срок се съобщава и записва.
- Няма silent scope change, silent fallback, премълчано отслабване на security
  claim или автоматично приемане на draft като final standard.
- Решенията се проследяват чрез rationale, exact source/history, evidence и
  tests; blocker-ите остават fail-closed до отделно решение.
- Научните и официалните standards/errata/revisions се следят като reminders,
  проверяват се от първични източници преди релевантно решение и се прилагат
  чрез отделен review/freeze.
- Legal conformity, certification и independent audit не се твърдят без
  съответното квалифицирано външно доказателство.

## Правила за безопасност

- Основният интерфейс остава в safety mode.
- MOKOSH v2 още не се използва за истински ценни файлове.
- Stage 2.48 активира само local single-file V2 encrypt/decrypt след отключване;
  изтриване/почистване на оригинали остава изключено.
- Contacts и Sandbox операциите остават изключени.
- Legacy MOK1 не се преобразува или презаписва автоматично.
- Пароли, private keys и лични runtime файлове не се записват в Git.
- Преди публично активиране е задължителен подписан Integrity & Health Check по docs/INTEGRITY_HEALTH_CHECK_BG.md.
- Guardian и подписаната Recovery Capsule се реализират по docs/GUARDIAN_RECOVERY_CAPSULE_BG.md.
- Поверителното лицензиране и плащанията се подготвят по docs/PRIVACY_LICENSING_BG.md.
- Собствените възпроизводими проверки се подготвят по docs/SECURITY_EVIDENCE_AND_TESTING_BG.md.
- Устойчивото shard-based recovery се подготвя по docs/RESILIENT_RECOVERY_SHARDS_BG.md.
- Пътят до платена публична v1 се планира по docs/ROADMAP_TO_PUBLIC_V1_BG.md.
- Trusted update, integrity и recovery архитектурата се подготвя по docs/TRUSTED_UPDATE_RECOVERY_ARCHITECTURE_BG.md.
- Проследимостта към стандарти, тестове и доказателства се поддържа по docs/SECURITY_STANDARDS_CROSSWALK_BG.md.

## Stage 2.35 installer-gated стъпка

Върху exact Stage 2.34:

- frozen scope е точно седем paths: нов pure adapter, нов 49-test module, нов
  contract и четирите project/evidence/history документа;
- view-model има точно седем ordered visible message keys и три отделни,
  required, individually-selectable, default-unselected controls;
- приема се само exact ordered tuple от три visible/user-selected/
  user-initiated events за същата fully revalidated Stage 2.33 presentation;
- private Stage 2.34 binding се проверява изцяло и само то получава exact
  confirmation tuple;
- един terminal marker затваря interrupt boundary преди private delegation;
  pre-boundary malformed input е retryable, а всеки post-boundary failure е
  terminal `FAILED_CLOSED`;
- receipt е bounded, immutable, repr-hidden, non-serializable и няма authority;
- това не е GUI/renderer и не доказва actual rendering, accessibility, human
  understanding, identity, informed consent, provenance или authenticity;
- historical Stage 2.12 dual-state/interrupt-gap pattern е отделен
  pre-activation hardening reminder и не се променя в този freeze;
- първият 49-test cycle даде 1 failure/2 errors само в test harness; след
  explicit корекции повторният exact targeted gate е 49/49 PASS;
- authoritative full/laptop/package claim изисква 1723 tests, expected
  failures=3, skipped=0, 129 tracked Python sources, exact seven-path gate,
  isolated rollback и clean post-apply checkpoint;

- Stage 2.34 приема само fully revalidated exact Stage 2.33 presentation и
  complete exact ordered tuple от трите fixed confirmation enum tokens;
- one-shot receipt state се commit-ва с една reference assignment под lock;
- failed validation/confirmation/mismatch не consume-ва prepared object-а, а
  след success replay се отказва преди input validation;
- receipt не доказва human understanding, identity, informed consent,
  signature, provenance, authenticity, freshness или operation authority;
- следващият stage изисква отделен High review/freeze; Stage 2.34 не е GUI,
  localization renderer, review session или recovery разрешение;
- CRA Article 14 applicability/readiness е tracked project-level reminder за
  2026-09-11 и се оценява отделно според реалния release/market scope;

- full regression, visible Linux matrix, installer dry-run, rollback probe,
  exact staged-path/hash gates и annotated tag трябва да са PASS;
- преди следващ stage се правят fresh review и отделен minimal scope freeze;
- Windows/macOS наблюденията остават задължителни преди claim за съответната
  platform;
- native picker може да чете filesystem metadata, но application recovery
  кодът не отваря/чете source content и не променя избрания файл;
- selected path е само process-local sensitive metadata и не е source identity,
  access authorization или recovery proof;
- Stage 2.29 revalidate-ва exact positive Stage 2.27 selection и записва само
  one-shot request или preserve; request не е source identity или authority;
- Stage 2.30 добавя отделен fourth action, locked до exact positive Stage 2.27
  selection; Stage 2.29 се зарежда само след explicit fourth click;
- retained selection outcome/path се clear-ва преди Stage 2.29 preparation и
  confirmation; request/preserve резултатите са generic и path-free;
- recovery source preparation/open/read от application core, secret intake,
  Stage 2.8 reconciliation invocation и всяко свързване към review session
  остават забранени до отделен frozen и прегледан stage;
- преди всеки бъдещ freeze се прави transitive test-impact scan за hash,
  import, schema, geometry, evidence и installer dependencies;
- няма истински Vault/recovery input, unlock, candidate, setup, publish,
  user-file mutation, Contacts, network, telemetry, Guardian, software update
  или automatic recovery.

## Stage 2.36 installer-gated стъпка

- входът е exact clean Stage 2.35 commit/tree/tag с 1723-test baseline;
- frozen scope е точно седем paths: нов pure localization module, нов 58-test
  module, нов contract и четирите project/evidence/history документа;
- exact `bg-BG`/`en-GB` catalogs съдържат по седем messages и три confirmations;
- locale се взема само от fully revalidated Stage 2.35 view; няма caller
  override, fallback, OS locale, external catalog или interpolation;
- fixed NFC/UTF-8 bounded visible и accessible texts са identical;
- controls остават visible/required/individual/default-unselected без
  select-all; няма events, acknowledgement или operation capability;
- output не доказва real GUI, accessibility conformity, comprehension,
  identity, consent, signature, provenance, authenticity или authority;
- Stage 2.13, Stage 2.32–2.35, GUI, crypto и storage остават byte-exact;
- първият 58-test cycle даде 57 pass/1 test-vector failure; коригиран Latin
  decomposed NFC vector дава повторен 58/58 PASS;
- scratch full suite е non-authoritative 1752 tests, errors=3, skipped=7 поради
  липсващ `argon2`; authoritative laptop gate остава 1781 tests;
- tracked reminders включват WCAG 2.2, EN 301 549 V3.2.1/revision work и EAA
  applicability от 2025-06-28 при приложим scope, без conformity claim.

## Conversation lifecycle invariant

- Текущото постоянно правило е: след всеки успешно приложен и затворен Stage
  се създават и проверяват HISTORY bundle, next-stage INPUT и HANDOFF и се
  започва нов чат.
- Следващият чат започва на High с read-only baseline и fresh review; няма код
  преди нов приет freeze.
- Предишното правило за точно три последователни stage-а в един чат е
  superseded process history и вече не е действащ invariant.

## Stage 2.37 installer-gated стъпка

- входът е exact clean Stage 2.36 checkpoint `cc465b5`, tree `1737846` и
  authoritative 1781-test baseline;
- frozen scope е точно седем paths: isolated Tk child window/controller,
  точно 56 tests, contract и четирите evidence/status/history документа;
- locale идва само от exact Stage 2.35 adapter view през Stage 2.36; няма
  caller locale, fallback, OS locale, external catalog или interpolation;
- седем messages предхождат три separate disabled/default-false checkboxes;
  final button се разрешава само при трите individual selections и се
  забранява при uncheck; няма select-all, remembered state или auto-accept;
- няма window-wide Return; explicit final button acknowledgement, Escape/
  Cancel/WM close cancel без consuming на private adapter;
- един `_terminal` sentinel преди Stage 2.35 delegation прави Exception,
  BaseException, interrupt и post-delegate validation fault terminal
  `FAILED_CLOSED`; concurrency допуска точно един terminal резултат;
- outcome е bounded/immutable/repr-hidden/nonserializable и не задържа path,
  source material, secret, callback, executor или authority;
- targeted gate е 56/56 PASS след една изрично записана test-harness корекция;
  expected laptop full gate е 1837 tests, expected failures=3, skipped=0, 189
  tracked files и 133 tracked Python sources;
- real GUI rendering, accessibility, comprehension, identity, consent и legal
  conformity не се доказват; synthetic Linux visual/platform harness е Stage
  2.38;
- standards watch: WCAG 2.2; EN 301 549 revision с official 4.1.0/work-item и
  4.1.1/flyer numbering inconsistency; SSDF 1.2 IPD; SP 800-38D Rev.1 work;
  FIPS 203 future update; EAA applicability и CRA 2026-09-11 readiness;
- future official change се прилага само след primary-source impact review,
  explicit notification, new freeze и explicit acceptance; няма automatic
  baseline switch или legal/accessibility certification;
- legacy `contacts_core.py` ML-KEM result-order defect остава отделен inactive
  hardening risk и не се променя извън Stage 2.37 scope.

## Stage 2.38 implementation-gated стъпка

- входът е exact clean Stage 2.37 checkpoint `ba465fe`, tree `25a03227`,
  annotated tag и authoritative 1837-test baseline;
- frozen scope е точно осем paths: pure synthetic core, separate executable
  Linux launcher, точно 48 tests, contract и четирите evidence/status/history
  документа;
- fixed eight-case BG/EN matrix покрива 100/125/150/200% относителен Tk scale,
  560×440/800×640 и Escape/Cancel/WM-close/acknowledge по два пъти;
- scaling се изчислява от началната Tk platform стойност; historical Stage
  2.15 absolute scaling pattern не се копира;
- няма real source/Vault/secret/path, main GUI, automatic event injection,
  filesystem mutation, recovery, operation authority, network или auto-save;
- bounded mapping watchdog отказва без report при invisible/timeout child;
- шест exact manual observations са задължителни; `fail`/`not_checked` или
  action mismatch дават nonzero status;
- JSON evidence е canonical/bounded и съдържа explicit false certification,
  assistive-technology, contrast, identity, consent и authority claims;
- visual result е self-reported evidence само за текущата Linux/Wayland/Tk
  среда, не accessibility/legal certification или Windows/macOS claim;
- expected authoritative gate е 1885 tests, expected failures=3, skipped=0,
  193 tracked files и 136 tracked Python sources, плюс human 8-case visual PASS;
- ако се открие Stage 2.37 visual defect, работата спира до ново изрично
  freeze решение; няма silent predecessor patch;
- private-user/voluntary-use моделът не е автоматично законово изключение.
  Applicable law е mandatory; voluntary standards се приемат като строг
  engineering baseline без false certification claim.
- R0 installer-ът спира преди actual apply/GUI, защото общ Git helper прави
  `.strip()` и премахва първия значим leading space от porcelain ` M` status.
  Temporary diagnostic доказва exact correct eight-path allowlist, а real repo
  остава exact clean Stage 2.37. R1 използва raw porcelain lines; R0 е оттеглен.

## Stage 2.38 responsive-UI amendment

- Първият R1 laptop run премина parser/package/runtime/ML-KEM/legacy/base,
  isolated 48/1885 и actual 48/1885 automated gates.
- В human case 1 operator натисна acknowledgement, след което terminal
  observation prompt не беше ясно откриваем. Прозорецът не осигури достатъчно
  ясно resize/reflow/scroll поведение при малък размер. Matrix беше прекратена
  със status 130 и installer rollback PASS.
- Следващият read-only gate потвърди exact Stage 2.37 `ba465fe`/`25a03227`,
  clean worktree, absent Stage 2.38 paths/tag. Няма commit или частично
  прилагане.
- Fresh architecture/security/standards review прекласифицира minimum size,
  explicit resize, dynamic locale-aware wrap, scroll reachability, visible
  focus и clear step-by-step harness guidance като задължителни GUI строителни
  инварианти. User прие exact 12-path amended freeze.
- R2 Stage 2.37 window targeted gate е 68 tests; Stage 2.38 harness gate е
  64 tests; combined preliminary gate 132/132 PASS.
- R2 expected authoritative full gate е 1913 tests, expected
  failures=3, skipped=0; counts остават 193 tracked files и 136 Python.
- Harness instruction и observations са scrollable/resizable GUI phases.
  Няма stdin prompt, automatic event injection или предварително избран PASS.
  Terminal action се валидира преди observation phase; всяко несъответствие,
  FAIL/not-checked или cancel спира fail-fast.
- Няма ново установено official/scientific/legal standards изменение в този
  amendment. Променено е прилагането на вече следените reflow/focus/software
  accessibility principles; certification/conformity claim не се прави.

## Stage 2.38 R3 sequential-instruction и footer-grid amendment

- Exact Stage 2.37 rollback е потвърден след всеки R2 mismatch; няма
  Stage 2.38 commit/tag или остатъчен path.
- Case 1 е доказано PASS. Двата Case 2 опита са използвали Escape вместо
  frozen Cancel, защото Cases са били разбрани като условни ситуации и Escape
  като общ continue key. Това е instruction-model finding.
- Отделно е съобщено, че долните Cancel/Confirm бутони могат да не са видими
  при initial English/high-scale layout без resize; това е footer-layout
  finding и не се приема като PASS.
- User прие exact same 12-path R3 freeze. Stage 2.37 outer layout вече има
  reserved three-row grid; само middle review row се разширява/свива.
- Harness добавя sequential 1→8 overview, explicit per-case action banner,
  unchecked acknowledgement и disabled Start.
- Questions се описват като automatic after exact action; PASS/FAIL е отделна
  observation phase. Mismatch дава exact case/expected/observed diagnostic.
- Preliminary R3 targeted gate е 76 + 76 = 152/152 PASS.
- Действащият expected authoritative full gate е 1933 tests, expected
  failures=3, skipped=0; counts остават 193 tracked files и 136 Python.

## Stage 2.38 R4 corrective ownership amendment

- Първият R3 laptop run премина package/runtime/legacy/exact predecessor,
  76/76 + 76/76 targeted, 1933 full и isolated rollback gates.
- Manual phase спря преди GUI с exact `NameError` в
  `_show_matrix_overview`: `case`/`action` banner е попаднал в грешната
  функция. Installer-ът rollback-на и read-only gate потвърди exact clean
  Stage 2.37, без Stage 2.38 tag.
- Това е implementation/test-design defect, не user error. R3 е withdrawn.
- User прие R4 corrective freeze със същия final 12-path scope. Banner-ът е
  локален само за case instruction; overview няма case-specific free names.
- Добавени са два structural regression tests. Exact targeted gate става
  76 + 78 = 154 tests; authoritative full target става 1935 tests,
  expected failures=3, skipped=0. Counts остават 193 files/136 Python.
- Няма standards/cryptography/data/authority промяна и няма certification
  claim. Human eight-case visual gate остава задължителен преди commit/tag.

## Stage 2.38 R5 unified-layout amendment

- R4 authoritative automated gates преминаха: 76/76 Stage 2.37, 78/78
  Stage 2.38 и 1935 full, expected failures=3.
- Human R4 run произведе Case 1–3 six-PASS JSON, но operator впоследствие
  коригира evidence: harness footer controls са били скрити/недостижими.
  Case 4/200% instruction не показа acknowledgement/Start. Трите JSON reports
  са withdrawn; whole R4 visual matrix е FAIL.
- Status 130 и installer rollback PASS са последвани от exact read-only
  `ba465fe`/`25a03227`, clean worktree, absent Stage 2.38 files/tag, 106
  commits/65 tags и unchanged three unreachable blobs.
- Root cause: page-level pack competition, fixed geometry under 125–200%
  scaling и source-token tests без mapped client-bounds verification.
- User прие same 12-path R5 unified-layout freeze.
- Overview/instruction/review/observations използват fixed header, only
  expanding scroll middle и fixed footer. Live gates reject unmapped, zero,
  outside, overlapping или under-80px regions before user/visible claim.
- Exact preliminary targeted gate е 84/84 + 90/90 = 174/174 PASS. Full target
  е 1955, expected failures=3, skipped=0; 193 files/136 Python.
- Fresh standards ledger добавя WCAG2ICT 2025-12-11 и WCAG-EM 2.0
  2026-07-23 като informative guidance. EN 301 549 v4.1.0 остава
  adopted-for-publication/pending authoritative publication/OJ review.


## Stage 2.38 post-R5 resize-operability corrective candidate

- R5 commit `593e4451f16ac72207df614482b86b4d1796d96d` и annotated tag остават
  immutable historical evidence; Stage 2.39 остава PAUSED.
- След R5 operator докладва intermittent resize-operability finding: при някои
  увеличени, не непременно maximized размери final action понякога не реагира,
  а след restore отново реагира. Root cause не е доказана и не се измисля.
- D1 diagnostic е отхвърлен като root-cause evidence поради собствен callback
  teardown defect и invalid enlarged-action measurement.
- D2 след корекция даде валиден six-scenario OPERABLE run; raw Linux kernel
  input probe отчете exact 10 Tab press + 10 release + 0 repeat.
- D3 mouse-only multi-size probe покри initial, slight `668x531`, medium
  `904x660`, large non-maximized `1060x685` и restored `560x440`; всички пет
  дадоха press=1/release=1/command=1 и `REPOSITORY_UNCHANGED=PASS`.
- Следователно original human finding остава historical/real, но е currently
  non-reproducible. Няма speculative focus/grab/Wayland/geometry root-cause
  claim и няма оправдание за redesign.
- Доказаната architectural gap е, че production Stage 2.37 live layout gate е
  initial-only. Corrective candidate добавя debounced post-Configure recheck на
  exact header/canvas/footer/actions, controller-only Confirm state resync и
  reveal на вече focused confirmation без focus stealing. Нарушение fail-ва
  closed с DisplayError; няма auto-accept, event injection, network, filesystem
  operation, secret/source retention или recovery authority.
- Candidate targeted count е 97 Stage 2.37 review-window + 90 Stage 2.38
  visual-harness = 187. Expected full laptop count е 1968 tests, expected
  failures=3. Human acceptance остава отделно задължително след automated PASS.
- Този раздел описва pending corrective candidate и не е quality PASS, commit,
  tag, accessibility conformity, legal opinion или certification.

## Stage 2.39 frozen implementation candidate

- Authoritative input: Stage 2.38 corrective checkpoint `65721f43711a63f00c3f74d0faa2c6ccafd8a6df`, tree `7fd78e7d4007ff9886b33abc849c2249573ceb0c`, clean live worktree, 108 commits, 0 merges and 67/67 annotated tags.
- User explicitly accepted Stage 2.39 freeze before mutation.
- Scope: isolated source-inspection review controller over exact Stage 2.32 -> Stage 2.33 -> Stage 2.35 -> Stage 2.36 -> Stage 2.37/2.38 chain.
- Exactly one public preparation function accepts only the exact Stage 2.32 execution outcome; no caller locale.
- One-shot lifecycle is `PREPARED -> DISPLAYING -> COMPLETED|FAILED`; display transition is atomic and every post-transition fault consumes the session.
- Original Stage 2.32 outcome/source identifiers are not retained. Session retains only bounded presentation/adapter binding until terminal state, then clears both references.
- No filesystem, source reader, Vault, crypto, recovery execution, Stage 2.8, network, logging, dynamic import, Contacts, main-GUI wiring, callback/executor or operation authority.
- Frozen mutation allowlist remains exactly six tracked paths: controller, 20-test module, contract, `PROJECT_STATUS_BG.md`, `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`, `docs/SESSION_LOG_BG.md`.
- Exact search found the superseded three-stages-per-chat rule in the active `PROJECT_STATUS_BG.md` invariant and as historical Stage 2.36/session evidence in `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md` and `docs/SESSION_LOG_BG.md`. Only this active status invariant is rewritten to the one-stage-per-chat rule; historical evidence/log text remains unchanged and receives explicit supersession evidence. Preventive gate: exact search evidence before any claim about documentation inconsistency distribution.
- R1 wrapper dry-run proved the 20 targeted tests and full 1988-test candidate suite, but live apply false-failed after those PASS results because tooling incorrectly required zero bytecode anywhere under the repository. Rollback to exact `65721f4` baseline passed.
- R2 changed wrapper/tooling only: bytecode is now a baseline-relative exact-state invariant. Its live apply recorded 4341 pre-existing bytecode artifacts before mutation, then required exactly the same state after tests. Self-tests require unchanged pre-existing bytecode to pass and new/changed bytecode to fail closed. Authoritative R2 dry-run and live candidate apply both passed; live full suite remained 1988 tests with expected failures=3 and `LIVE_BYTECODE_STATE_UNCHANGED=PASS`. No commit or tag exists yet.
- Preventive tooling rule: residue gates for known pre-existing ignored artifacts compare exact baseline -> candidate delta; they must not silently redefine historical repository cleanliness as absolute absence.
- No certification/conformity claim and no automatic standards/legal baseline switch.

## Stage 2.40 accepted freeze and implementation candidate

- Authoritative input: exact clean Stage 2.39 commit
  `468ad7826e1c6f48d2f8a006f8fda2b303fddec9`, tree
  `e4c023360e15f0ce168cb67314439d50ee524528`, annotated Stage 2.39 tag,
  109 commits, 0 merges and 68/68 annotated tags.
- Comprehensive live baseline: handoff modes/hashes, protected legacy,
  Git/fsck, runtime and ignored-root shadow gates PASS; 4341 baseline bytecode
  records remained exact SHA-256
  `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`
  before/after 1988 tests, `OK (expected failures=3)`, skipped=0, clean.
- User accepted the initial seven-path freeze before initial mutation. A later
  mandatory transitive impact scan found 13 stale exact GUI-hash expectations
  in 12 historical security test paths; work stopped and the user explicitly
  accepted the minimal 19-path re-freeze before those additions.
- Scope: inactive, exact one-shot main-GUI bridge over a fresh Stage 2.39
  source-inspection review session; no caller locale and no normal activation.
- Main GUI gains only a conditional import helper and exact inactive seam.
  `main()` signature, widgets, texts, layout, geometry and launcher remain
  unchanged.
- Lifecycle is `READY -> DISPLAYING -> COMPLETED|FAILED`; raw outcome must be
  the exact completed session outcome and is reconstructed before return.
- No filesystem, source/path, Vault, crypto, recovery execution, Stage 2.8,
  network, logging, dynamic import, Contacts, callback/executor or operation
  authority.
- Exact mutation allowlist is 19 paths: the original seven plus 12 historical
  security test files. Those 12 files change 13 expected `mokosh_gui.py`
  hashes from the exact Stage 2.39 digest to the exact Stage 2.40 digest. One
  additional expected predecessor-test hash is updated because localization
  byte-hashes the changed UI-adapter test; no behavior assertion is removed,
  skipped or weakened.
- First targeted cycle was 22 PASS / 2 FAIL due solely to two incorrect test
  identity assertions. Production behavior was unchanged; corrected targeted
  gate is 24/24 PASS.
- Independent test review then found test 17 inspected `__slots__` names rather
  than values for parent retention. The assertion is corrected inside the same
  24-test path; production scope and test count stay unchanged.
- Expected full gate is 2012 tests, expected failures=3, skipped=0. No visual,
  accessibility, standards/legal conformity or certification claim.
- R1 laptop dry-run stopped before repository inspection or candidate tests:
  installer tooling resolved the lexical `venv_sys/bin/python3` symlink to
  `/usr/bin/python3.12`, bypassing venv isolation and loading system
  `cryptography` without ML-KEM. Live repository mutation did not occur.
- Preventive installer rule: executable entry paths for Python venvs are never
  canonicalized through `resolve()` before execution. Every future Stage
  installer must preserve the lexical venv path and self-test this symlink
  boundary, then prove exact `sys.executable`, `sys.prefix`, dist-packages
  isolation, dependency versions, OpenSSL backend and ML-KEM at runtime.
- R2 preserved the correct venv path but failed before candidate tests because
  its independently reconstructed ML-KEM probe used the nonexistent `ml_kem`
  import instead of the project's proven `mlkem` API. No live mutation
  occurred. R3 removes duplicate API knowledge: the probe invokes the exact
  baseline project `_mlkem_module()` boundary and performs a real
  encapsulate/decapsulate roundtrip. Future environment probes must reuse the
  application's proven dependency boundary rather than retype library APIs.
- R3 passed live venv/ML-KEM, exact repository and bytecode-baseline gates, then
  stopped before payload tests because the laptop local clone retained the
  three known unreachable blobs while the scratch clone had omitted them. No
  live mutation occurred. R4 uses the correct object-integrity model: live
  repository requires the exact known set; an isolated clone may omit any
  unreachable object but may contain only a subset of that known set. Unknown
  dangling objects or any fsck damage still fail. Positive/negative policy
  self-tests are mandatory for future installers.
- High recovery semantic review found that two foreign-outcome tests rejected
  on an earlier controller-state predicate instead of isolating identity and
  locale, and the GUI seam test did not assert exact parent forwarding. The
  same 24 methods now arrange all earlier predicates to pass and exercise only
  the named guard; no production path or authority changed.
- The same review proved a production exact-binding gap: replacing the private
  session slot with another fresh same-locale Stage 2.39 session passed the
  pre-display checks, contrary to the frozen same-reference contract. A
  separate process-local preparation identity is now checked before display
  and cleared with the session at every terminal state. The negative scenario
  is added inside an existing test method; scope stays 19 paths and 24 tests.
- R1--R4 delivery artifacts are withdrawn and forbidden. Full High post-mortem
  additionally proved that their targeted-result parser accepted expected
  failures and their self-tests never invoked package/candidate/apply/rollback
  boundaries. The replacement design uses exact `git archive HEAD` bytes and
  no candidate clone/object database or duplicated ML-KEM API.
- Before package construction, the replacement tool produced 33/33 internal
  positive and negative PASS covering exact summaries, safe archive/PAX
  metadata, payload, status, bytecode schema/delta, atomic copy, backup digest
  and rollback after every injected copy position. This remains preliminary
  scratch evidence only; it is not laptop full-regression, live apply, commit
  or tag evidence.

## Stage 2.41 accepted source-inspection main-GUI widget freeze

- Authoritative input: exact clean Stage 2.40 commit `b039b3b8fd1cbc5705201bbc6cd6aa8c93e5b7e8`, tree `a9bf594d8ab85964020ed58fb3f43ddac180eb0a`, annotated tag, 110 commits, 0 merges and 69 annotated tags.
- Laptop baseline: 24/24 predecessor and 2012 full tests PASS, expected failures=3, skipped=0; exact 4341 bytecode records retained SHA-256 `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`.
- User explicitly accepted the exact Stage 2.41 freeze before mutation.
- Scope: one conditional keyword-only Stage 2.40 binding, isolated one-shot event, BG/EN widget, fixed synthetic visual core/launcher and evidence updates. Normal startup and old positional conditional mode remain compatible.
- Invalid/mutually-exclusive bindings fail before runtime-directory preparation and Tk. Valid conditional startup retains the existing Stage 2.24 runtime-directory preparation; there is no whole-process no-filesystem claim.
- No recovery-source/user-file access or mutation, source/path, secret, crypto, Vault, network, process, callback/executor, capability, automatic transition or recovery-operation authority is added.
- Exact allowlist is 24 paths. Historical Stage 2.40 contract hashes remain immutable evidence.
- New target is 36 tests; authoritative full target is 2048 tests with expected failures=3 and skipped=0 in the laptop venv.
- Mandatory human matrix: BG/100/Escape, EN/125/Cancel, BG/150/child-X, EN/200/Acknowledge, each with six observations.
- Scratch candidate evidence is preliminary only; no live apply, human PASS, commit, tag, conformity or certification claim exists yet.

## Stage 2.41 authoritative laptop candidate evidence — 2026-09-03

- Горният preliminary запис е исторически и се supersede-ва от този раздел;
  не се пренаписва ретроактивно.
- Delivery R1 е withdrawn след безопасен pre-mutation false fail върху
  `.gitignore`: wrapper-ът неправилно е извел live физически режими от Git
  archive executable classes. Read-only диагностиката потвърди непокътнат
  Stage 2.40 и exact tracked mode distribution `61×0600`, `108×0644`,
  `24×0664`, `1×0700`, `5×0755`, owner/group `mitra` и zero extended ACL.
- Коригираният R2 package е `196231` bytes, SHA-256
  `a426adb7e224fc3a687fe880570ad44891b82999140dd70667c1a9ae0ae140f2`.
  Installer self-tests са 24/24; exact mode-map, payload, normalized metadata,
  clean extraction и rollback след всяка от 24 copy позиции са PASS.
- Authoritative laptop dry-run и live apply са PASS с exact 36/36 Stage 2.41,
  24/24 Stage 2.40 predecessor и 2048 full tests, expected failures=3,
  skipped=0. Independent post-apply повторението е също 36/36 и 2048 PASS.
- Post-apply evidence потвърждава exact 24 unstaged paths, package-equal bytes
  и modes, owner/group/ACL, strict fsck с трите известни dangling blobs и
  unchanged 4341-record bytecode SHA-256
  `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`.
- Human Linux matrix е self-reported 24/24 observations PASS: BG/100/Escape,
  EN/125/Cancel, BG/150/child-X и EN/200/Acknowledge. Всеки report потвърждава
  synthetic non-secret input, no operation, no recovery-source access/mutation,
  no network/secret/source/path retention и unchanged normal startup.
- Human evidence не доказва accessibility conformity, legal conformity,
  platform certification или human understanding. Няма такъв claim.
- Candidate-ът остава върху immutable Stage 2.40 HEAD `b039b3b`; няма Stage
  2.41 commit или tag преди final post-amendment pre-commit gate.

## Stage 2.42 accepted normal-main-GUI layout-audit freeze

- Authoritative input е exact clean Stage 2.41 checkpoint `2f1e1ee6c799423f9461dd09c53ed3b71d51ab5a`, tree `f39a7ebe2e066a0e5b6d4e14be1e08a23a9fc6b0`, annotated tag, 111 commits, 0 merges и 70/70 annotated tags.
- Read-only laptop baseline е 36/36 Stage 2.41, 24/24 Stage 2.40 и full 2048 PASS, expected failures=3, skipped=0, exact venv/runtime dependencies и clean final markers.
- Fresh review отхвърля директно Stage 2.29 -> Stage 2.41 свързване: Stage 2.31 request, Stage 2.32 privileged read и Stage 2.39/2.40 display binding остават отделни mediation boundaries.
- Normal Stage 2.30 GUI няма 100/125/150/200% scaling evidence; Stage 2.41 matrix покрива само conditional review mode. Преди пето действие е задължителен отделен normal-layout audit.
- Freeze-ът е точно осем paths: pure audit core, launcher, 32-test module, contract и четирите project/evidence документи. `mokosh_gui.py` и всички production/recovery/crypto/storage paths остават byte-exact.
- Fixed matrix е BG/100, EN/125, BG/150 и EN/200 с visibility, clipping, keyboard/focus/no-trap, resize/restore и no-auto-action observations.
- Human FAIL/NOT_CHECKED блокира live apply и изисква corrective re-freeze; не се преобразува в PASS.
- Няма Stage 2.31 wiring, Stage 2.32 secure read, Stage 2.41 normal activation, source/path/secret, picker, network, operation или conformity claim.
- Първият targeted cycle е 31/32 поради test-only lexical false fail върху защитен docstring; AST predicate + negative regression корекцията дава 32/32 PASS без production промяна.
- Pre-package semantic review откри, че launcher-ът погрешно изисква
  resize/restore и за двата `initial_keyboard` cases. Непубликуваният кандидат
  е коригиран: cases 1–2 остават на initial size, а cases 3–4 единствени
  изпълняват resize/restore; exact test пази разграничението.
- Първата wrapper inventory формула броеше осем allowlisted paths като осем
  нови и false-fail-на на 211 вместо exact `203 + 4 = 207` candidate files.
  Corrected formula и regression assertion са PASS преди package issuance.
- Първата ad-hoc bytecode проба преброи само 4086 `*.pyc` files. Exact verified
  exporter schema добавя 255 `__pycache__` directories и възстановява
  historical 4341-record digest contract; няма project bytecode loss claim.

## Stage 2.42 human FAIL и приет corrective re-freeze — 2026-09-03

- R1 audit-only dry-run мина automated gates: 14/14 installer self-tests,
  8/8 rollback injection, 32/32 target, 36/36 и 24/24 predecessor и full
  2080 PASS, expected failures=3, skipped=0.
- Case 1 `bg-BG`/100%/initial_keyboard е self-reported FAIL: safety banner и
  четирите recovery actions са видими, но следващите normal controls излизат
  извън непроменения `820x720` viewport. Останалите седем observations са
  `not_checked`. Gate-ът правилно блокира преди live apply; R1 е evidence-only
  и е забранен за live mutation.
- Root cause е fixed-height normal layout: четирите дълги recovery реда се
  pack-ват преди език/Vault/credential/status/main controls без vertical
  viewport. User-ът прие corrective re-freeze.
- Corrective scope е exact 23 paths: първоначалните осем, `mokosh_gui.py`, 12
  dependent hash tests и два пряко засегнати GUI mock/behavior tests. Няма
  промяна в action order/text/state, recovery mediation, source/picker,
  secret, Vault, crypto, storage или network boundary.
- Само normal startup получава вертикален Canvas/Scrollbar viewport. Mouse
  wheel и PageUp/PageDown/Home/End скролират; Tab/Shift+Tab focus автоматично
  reveal-ва достигнатата контрола. Conditional recovery-review modes запазват
  стария layout.
- Corrective target е 48 tests, full target е 2096, expected failures=3,
  skipped=0. Preliminary isolated gate е 48/48 плюс 61/61 засегнати GUI
  compatibility tests PASS; laptop venv и новата четири-case human matrix
  остават задължителни преди live apply.
- Corrective delivery R1 е withdrawn и забранен след safe pre-mutation
  baseline fail: installer-ът проверяваше всички 19 existing target modes като
  `0644`, въпреки frozen mode map с пет `0664` и един `0600` target. R2 трябва
  да извлича expected mode за всеки path от exact frozen map и да има
  all-19-target regression преди издаване.

## Stage 2.42 corrective R2 withdrawal и окончателна closure корекция

- R2 поправи exact physical modes и мина 14/14 self-tests, 23/23 rollback,
  48/48 target, 36/36 и 24/24 predecessors. Full 2096 gate обаче блокира в
  isolated candidate с два unadapted legacy Tk mocks и един stale predecessor
  test hash. Няма live apply или human run; R2 е withdrawn и забранен.
- Transitive reverse-hash анализът затвори GUI production/test graph до 17
  paths. Двата пропуснати mock consumers са
  `tests/test_mokosh_vault_recovery_entry_main_gui_widget.py` и
  `tests/test_mokosh_vault_recovery_entry_transition_main_gui_widget.py`.
- Окончателният corrective allowlist е exact 25 paths: първоначалните осем,
  `mokosh_gui.py`, 12 hash consumers и четири GUI mock/behavior tests. Stale
  UI-adapter test hash се поправя в вече allowlisted localization test.
- Scope/capability границите и counts остават 48 target и 2096 full при
  expected failures=3, skipped=0. Преди R3 package са задължителни два
  последователни full PASS върху post-documentation candidate bytes.

## Stage 2.42 R3 post-apply status false fail

- R3 laptop apply мина 14/14 installer, 25/25 rollback, 48/48 target, 36/36
  и 24/24 predecessors, full 2096 PASS, human 32/32 PASS и втори post-overlay
  full 2096 PASS. Final marker не е издаден: exact Git-status comparison
  false-fail-на и apply transaction-ът се rollback-на.
- Root cause е wrapper-only whitespace normalization. `git()` връща
  `.stdout.strip()`, което променя само първия porcelain ред от
  `" M PROJECT_STATUS_BG.md"` на `"M PROJECT_STATUS_BG.md"`. Суровият status
  е exact 25/25 match. R3 е withdrawn; няма приет live candidate.
- R4 използва raw porcelain lines без strip и добавя regression за first-line
  prefix, exact 25-path post-overlay set и clean 25-path rollback. Production,
  tests, human contract и exact 25-path scope не се разширяват.

## Stage 2.42 authoritative R4 live evidence — 2026-09-03

- R4 package е `212756` bytes, SHA-256
  `5249f40e9207af37a63c0b6ec5f749785c90308d7f88bdd01fe00109673223b0`;
  installer е `40975` bytes, mode `0700`, SHA-256
  `2942c6873903d33511703fb0272243db443a9843bd28a0da77d00dd915bfb309`.
- Package gate е 30/30 safe normalized members, 25/25 payload bytes/modes,
  21/21 existing-target mode map, 15/15 installer self-tests, restrictive
  `umask` positive/negative regression и full isolated apply/status/rollback
  simulation PASS.
- Laptop R4 live apply мина 25/25 rollback injection, 48/48 Stage 2.42,
  36/36 Stage 2.41, 24/24 Stage 2.40 и два full 2096 PASS cycles при expected
  failures=3, skipped=0. Final marker е
  `STAGE2_42_LIVE_APPLY=PASS_UNSTAGED_25_PATHS`.
- Human matrix е self-reported 32/32 PASS: BG/100 и EN/125 initial keyboard,
  BG/150 и EN/200 resize/restore keyboard. Няма automatic dialog, picker,
  source access, recovery operation, true input или network claim.
- Independent post-apply gate повтори 48/48, 36/36, 24/24 и full 2096 PASS,
  exact 25 status, payload bytes/modes/owner/ACL, tracked mode distribution,
  strict fsck и unchanged 4341-record bytecode baseline.
- Candidate остава unstaged върху immutable Stage 2.41 HEAD `2f1e1ee`; commit
  и annotated tag са забранени преди final evidence amendment и pre-commit
  gate. R1, R2 и R3 остават withdrawn.

## Stage 2.43 — accepted fifth preparation-request action freeze

- Авторитетен baseline е clean Stage 2.42 commit `98cbd53c132800a790c8fbd957dc0f913d264e9e`, tree `f851ca0809336a490b78e696fdef9d27f6719c50` и annotated tag `stage2.42-main-gui-recovery-chain-layout-audit`.
- Read-only laptop gate потвърди exact handoff/bundle/input, 207 tracked paths,
  112 commits, zero merges, 71 annotated tags, known three dangling blobs,
  exact physical manifest, 4341-record bytecode baseline, Python 3.12.3,
  pinned dependencies и ML-KEM-768 runtime.
- Baseline regression е 48/48 Stage 2.42, 36/36 Stage 2.41, 24/24 Stage 2.40
  и full 2096 PASS при expected failures=3 и skipped=0; repository, modes,
  owner/ACL и bytecode са непроменени преди/след.
- User-ът прие Stage 2.43 като exact 22-path freeze: единствен production
  target `mokosh_gui.py`, четири new contract/harness/launcher/test paths,
  тринадесет exact GUI-hash consumers и четири evidence документа.
- Петото normal-GUI действие започва locked, приема само fully revalidated
  exact positive Stage 2.29 outcome и при отделен explicit click извиква само
  pure Stage 2.31 preparation-request contract. Няма automatic transition,
  Stage 2.32 authorization, Stage 2.39–2.41 review activation или source read.
- Path metadata остава временно process-local; event-state reference се
  clear-ва преди Stage 2.31 loader, а локалната predecessor reference — след
  exact preparation и преди dialog. Python-text zeroization не се твърди.
  Няма path display/log/hash/serialization/persistence или network transfer.
- Preliminary isolated candidate target е 48/48 PASS. Authoritative package,
  laptop dry-run, full regression, human matrix, live apply, commit и tag са
  pending и не се подразбират.
- R1 package dry-run мина exact archive/runtime/baseline, 22/22 rollback,
  48/48 target, 48/36/24 predecessors и full 2144 PASS. Live apply не започна:
  първият human case беше cancelled на първия terminal observation, защото
  instruction/observation workflow-ът не беше използваем без chat guidance.
- Independent abort gate потвърди exact clean Stage 2.42 HEAD/tree/branch/tag,
  zero worktree changes и премахнат `.txt` fixture. R1 е withdrawn за apply;
  automated PASS не заменя failed human usability gate.
- Приетата corrective добавка запазва exact 22 paths и production bytes:
  visual runner-ът получава отделен nine-step guide beside MOKOSH, exact empty
  `.mokr` fixture и graphical wizard с default `not_checked` и
  explicit choice преди navigation. Visual report v2 разграничава runner
  fixture mutation от `application_*` source-mutation claim.
- R2 package dry-run и pre-human apply gates минаха, но guide-ът остана зад
  normal MOKOSH, а observation wizard-ът също не беше изведен отпред. Human
  case 1 беше cancelled с exit `130`; installer-ът блокира преди live apply.
  Read-only gate потвърди exact Stage 2.42 HEAD/tree/branch/tag, clean worktree
  и премахнат `.mokr` fixture. R2 е withdrawn и не се retry-ва.
- R3 correction създава guide-а след normal GUI build, държи guide и wizard
  mapped/topmost/focused и добавя explicit guide-usability observation.
  Report v3 извежда guide/per-action boolean claims от човешкия отговор, вместо
  да ги hardcode-ва. Matrix-ът е 12 observations на case, общо 48.
- R3 human case 1 беше cancelled: manual guide navigation и wizard footer
  controls останаха под видимата work area, wizard body нямаше scroll, а
  periodic guide callback остана pending при destroy и показа bounded
  `invalid command name`. Installer-ът отново блокира преди live apply; R3 е
  withdrawn и не се retry-ва.
- R4 премахна manual guide navigation и periodic visibility watchdog. Неговият
  dry-run мина 18/18 installer, 22/22 rollback, 48/48 target, 48/36/24
  predecessors и full 2144 PASS. Human case 1 обаче показа, че guide-ът остава
  на действие 1 след достигане на действие 3. Натиснатият classic Tk button
  временно е във валидно състояние `active`, а R4 допускаше само `normal` и
  `disabled`; uncaught observer exception прекрати полезното auto progression.
- Operator-ът прекрати безопасно. Launcher exit `130` блокира installer-а преди
  live overlay; R4 е withdrawn и не се retry-ва. Automated PASS не заменя този
  human failure и не се издава waiver.
- R5 corrective design приема точно трите classic Tk states `normal`, `active`
  и `disabled`, синхронизира маркера с най-далечното наблюдавано отключено
  действие и запазва пълния шестфазен план постоянно в scrollable guide-а.
  Observer validation failure вече се записва и затваря main root fail-closed,
  вместо да остава като uncaught Tk callback.
- Post-correction target е 48/48 PASS, включително четирите matrix cases,
  `active`, пропуснат междинен poll, директно достигане до действия 3/5,
  постоянния план и fail-closed observer simulation. Combined closure е
  156/156, full regression е 2144/2144 с точно три expected failures, а
  extracted candidate мина 22/22 rollback injection, overlay, повторните
  suites и exact rollback. Scratch няма display и `getfacl`; local ACL
  substitute провери липса на POSIX ACL xattr, но не заменя оригиналния
  installer gate. Authoritative laptop dry-run/guided matrix остават pending;
  няма live candidate, commit или Stage 2.43 tag.
- R5 laptop dry-run мина всички gates. Human cases 1–3 произведоха 36/36
  self-reported PASS, но по време на case 3 operator-ът установи, че keyboard
  instruction казва само да се активира действие 5 и не казва изрично да се
  натисне `Space`. Нужната конкретика беше дадена чрез chat, което нарушава
  изискването matrix-ът да е self-contained; трите report-а са invalidated.
- Case 4 беше прекратен безопасно. Exit `130` блокира live overlay; R5 е
  withdrawn без waiver. R6 изписва точната последователност
  `Tab → Shift+Tab → Tab → Space` и test/package gates изискват explicit
  `натиснете Space` и purpose текста преди издаване на архив.
- R6 deterministic archive е `223721` bytes, SHA-256
  `2bcb0b6f5aa1f0d470e0791fff52ec2e96b6d60f7d65a278ceed6d998090d69d`.
  Laptop dry-run мина 18/18 installer, exact 22-path payload/runtime/baseline,
  22/22 rollback, 48/48 target, 48/36/24 predecessors, full 2144 и extracted
  apply/test/rollback без live mutation.
- Authoritative R6 human matrix е 4/4 cases и 48/48 explicit observations:
  BG/100 request, EN/125 preserve, BG/150 preserve и EN/200 request. Всеки
  report остава human-observation-only и отказва accessibility/legal/platform,
  source-access, authorization, operation, review и zeroisation claims.
- След human PASS extracted candidate rollback мина, live overlay беше приложен
  като exact unstaged 22 paths и post-overlay suites отново са 48/48,
  48/36/24 и full 2144 PASS при точно три expected failures.
- Independent post-apply gate потвърди exact R6 bytes, modes, owner/group, ACL,
  Git status/no-staging/diff-check/fsck, Stage 2.42 HEAD/tree/branch, tracked
  physical manifest, липсващ synthetic fixture и непроменен 4341-record
  bytecode state преди/след още един full 2144 PASS. Evidence amendment,
  pre-commit gate, commit и annotated Stage 2.43 tag остават pending.

## Stage 2.44 — recovery-source reader hardening candidate

- Приет е exact 20-path scope с един production target:
  `mokosh_vault_recovery_storage.py`; GUI, locale strings, crypto, Vault
  operations, Contacts и network behavior остават byte-exact.
- Reader-ът вече задържа root-to-parent descriptor chain, отваря всеки
  component с no-follow semantics и revalidate-ва всяка identity преди success.
- Regular/current-user/0600/single-link/bounded проверката е преди
  content-capable open; file open включва `O_NONBLOCK`, а post-open type и
  identity проверките остават задължителни.
- Filename `recovery_id` е описан като structurally observed преди recovery
  secret authentication. Read-only claim означава липса на заявена application
  mutation и не обещава universal непроменен filesystem-managed `atime`.
- Candidate automated evidence включва stable FIFO, regular-to-FIFO race,
  ancestor rename/symlink race, post-parse replacement, `BaseException`
  descriptor cleanup и no-mutating-call проверки. Authoritative laptop apply,
  final regression, commit, tag и handoff още не се подразбират.

## Stage 2.44 — authoritative R1 live evidence

- Final R1 archive е `210357` bytes, SHA-256
  `c6553fc9c9e3dfdf8fd71a78e2e6ffe33805e08bf1857987bfba9df6df88b676`;
  installer-ът е `27600` bytes, SHA-256
  `93ea95534081198c0b19ee3a0ad62b86e0ef0b5e3020c0892f394e907443ce6f`.
- Laptop dry-run потвърди safe 26-member archive, exact Stage 2.43 baseline,
  20/20 rollback injection, 456/456 target и full 2152/2152 PASS при точно
  три expected failures и zero skipped, без live repository mutation.
- Transactional apply повтори pre-overlay gates, приложи exact 20 paths и
  повтори 456/456 target и 2152/2152 full PASS върху live overlay.
- Отделният verifier е `19044` bytes, SHA-256
  `c047a6d8b5551b4d6f47ad1f49bed60b3284820ca57ffcba5f8dc65ddb2955c7`.
  Той потвърди независимо package-to-live bytes, exact 20-path unstaged status,
  owner/modes/plain ACL, physical manifest, known-three-dangling strict fsck,
  unchanged 4341-record bytecode и още един 456/2152 PASS cycle.
- Няма GUI byte change и затова няма Stage 2.44 human visual matrix. Това не е
  waiver: GUI/accessibility behavior просто не е част от frozen delta.
- Този evidence amendment е authoritative само ако transactional gate издаде
  `STAGE2_44_FINAL_EVIDENCE_R1_LIVE_APPLY=PASS_UNSTAGED_20_PATHS` след нов
  456/2152 final-byte cycle и independent pre-commit gate също мине. Commit,
  annotated tag и handoff не се разрешават предварително от текста.

## Stage 2.45 — normal-GUI authorization readiness/privacy audit candidate

- User-ът прие audit-only exact six-path freeze върху clean Stage 2.44 commit
  `77c9432b519a8fd0c7ed7f446e39fbdc13547fb2`, tree
  `5b60a8520b7dfbbab4054a73766f60be6fda25b5` и annotated tag
  `stage2.44-vault-recovery-source-reader-hardening`.
- Scope-ът е един нов authorization-readiness/privacy audit contract, един нов
  32-test static audit module и допълнения само в четирите evidence/history
  документа. `mokosh_gui.py` и всички production/locale/launcher/crypto/Vault/
  storage/Contacts/network paths остават byte-exact.
- Одитният резултат е `GO WITH BLOCKERS`: current Stage 2.31 outcome може да се
  свърже архитектурно към съществуващата Stage 2.32 decision boundary само чрез
  бъдещо отделно шесто действие и отделно path-free default-negative
  confirmation. Това не разрешава bridge implementation или source read.
- Freeze-нати са locked → ready → deciding → terminal lifecycle, exact positive
  Stage 2.31 binding, pre-loader/pre-dialog reference clearing, Stage 2.32
  one-shot semantics, fail-closed replay/concurrency/errors и забрана за direct
  Stage 2.29 route или automatic Stage 2.39–2.41 review activation.
- Privacy contract-ът отказва path/content/logging/persistence/network claims,
  отличава structural parsing от cryptographic authentication, не твърди
  Python zeroization и записва POSIX `atime` caveat.
- Бъдещ human fixture трябва да е synthetic/non-secret, в runner-owned private
  `0700` directory, с exact regular/current-user/single-link `0600` canonical
  `.mokr`, exclusive/no-follow creation и identity-safe cleanup. Stage 2.45 няма
  GUI byte change и няма human visual matrix.
- Planned closure е 32 target + 33/44/48/48 predecessors = 205 tests и full
  2184 tests при точно три expected failures и zero skips, с exact allowlist,
  rollback, physical/ACL/Git/fsck/bytecode и independent gate. Authoritative
  laptop dry-run/apply, commit, tag и handoff остават pending.
- R1 laptop dry-run мина archive/runtime/baseline, 6/6 rollback, 32/205 target
  и full 2184 regression с точно три expected failures, zero skips и explicit
  `PASS_NO_LIVE_MUTATION`. След това installer top-level погрешно прихвана
  собствения успешен `SystemExit(0)` като failure и върна exit 1. R1 е withdrawn
  за apply; няма live mutation или waiver. R2 поправя само package installer-а,
  а exact six-path payload/frozen scope остават непроменени.

## Stage 2.45 — authoritative R2 live и independent evidence

- Final R2 audit package е `149309` bytes, SHA-256
  `5ed4b80a5ace17acfb400c8c6225eb849168764a8f0859260c559714aa0bd4c7`.
  Dry-run мина 12 installer self-tests, pinned runtime/ML-KEM, exact Stage 2.44
  baseline, 6/6 rollback, 32/32 target, 205/205 combined и full 2184/2184 при
  точно три expected failures и zero skips; live mutation няма.
- Transactional apply повтори candidate gates, приложи exact six unstaged
  audit/documentation paths и изпълни още един 32/205/2184 PASS cycle върху
  live bytes. `mokosh_gui.py` и всички production paths остават byte-exact.
- Independent verifier е `21027` bytes, SHA-256
  `02c72b8f401ae96b1cb2490c71c3a2141085170c784f89403551ce9397851d98`.
  Той потвърди package-to-live binding, exact 6-path status, 214 physical
  records/modes/owner/plain ACL, 8 critical production hashes, known-three-
  dangling fsck, unchanged 4341-record bytecode и трети 32/205/2184 PASS cycle.
- Audit result остава `GO WITH BLOCKERS`, не production bridge permission.
  Няма human visual matrix, защото GUI bytes са непроменени. Final evidence
  amendment, independent pre-commit gate, commit и annotated tag остават
  задължителни преди Stage 2.45 checkpoint.

## Stage 2.45 — final-evidence R1 extraction-validator incident

- Final-evidence R1 archive identity е `148782` bytes, SHA-256
  `178dabddb077e564ae0ff802e6e4caa70b33a44140cd3f8d49220243cec81d12`.
  Download owner/size/hash/mode и exact 10-member normalized archive inventory
  са минали преди extraction.
- Python 3.12 `tarfile` с `filter="data"` и wrapper `umask 0077` е извлякъл
  package directories като по-строгите `0700`, а regular files като `0644`.
  Външният post-extraction validator погрешно е изискал archived `0755` и е
  спрял с `REFUSED_EXTRACTED_METADATA_MISMATCH` преди installer execution.
- Това е wrapper false rejection, не product/test failure. Няма installer
  self-test, candidate test, live overlay или project mutation. Final-evidence
  R1 е withdrawn и не може да се използва за apply.
- R2 коригира само temp-extraction validation и добавя този permanent evidence
  record. Frozen six-path scope, R2 live bytes и `GO WITH BLOCKERS` решението
  остават непроменени; commit/tag продължават да са забранени.

## Stage 2.45 — final-evidence R2 pre-commit whitespace incident

- R2 final-evidence dry-run/apply и independent pre-commit gate са PASS върху
  exact R2 bytes. След staging отделният cached-diff gate откри точно три
  trailing spaces в редове 3–5 на новия audit документ.
- Причината за късното откриване е, че pre-staging `git diff --check` не включва
  untracked файла. Failure guard върна шестте файла unstaged; HEAD остава
  `77c9432`, а Stage 2.45 commit/tag не съществуват.
- Няма production/test byte промяна или security waiver. R2 е withdrawn като
  checkpoint candidate, а R3 е минимална documentation-only корекция с direct
  raw-byte whitespace gate за всички шест allowlisted paths.

## Stage 2.45 — final-evidence R3 strict-fsck safe stop

- R3 package (`152247` bytes, SHA-256
  `6e8af78dfe572d5cd235321c84ab6c54aef1ee09063a657be4b11aa306869ca3`)
  и byte-exact runner (`8726` bytes, SHA-256
  `2564d01712c187b9cec02871868884cf8bef9c8c32e023aa6e39b6a3d27b41bf`)
  преминаха runner/package extraction, 15 installer self-tests и pinned
  runtime, после спряха преди candidate/apply на strict fsck inventory.
- След failed R2 commit staging Git object store съдържа exact девет dangling
  blobs: трите исторически и шест blobs, чиито size/SHA-256 съвпадат точно с
  шестте R2 staged paths. Targeted unstage не изтрива unreachable objects.
- Read-only diagnostic потвърди baseline HEAD, exact six unstaged R2 bytes,
  липсващи commit/tag/staging и exact 9-object evidence. R3 не е извършил live
  overlay и е withdrawn без retry.
- R4 запазва тези forensic Git objects, pin-ва exact type/OID/size/SHA-256 и
  classification, и консолидира вече добавения raw-byte whitespace gate. Няма
  production/test scope промяна или restart на Stage 2.45.

## Stage 2.45.1 — legacy-contact fail-closed quarantine candidate

- Exact base е authoritative clean Stage 2.45 commit
  `6c5d14a18f2184d247a700154add1a02d39d3358`, tree
  `ec608c8a54db90e068fff7b36f8b6d01d6f0271f`.
- Read-only Gate 1–3 доказаха, че legacy `contacts_core.py` има broken ML-KEM
  binding/constructor/truncated unwrap, reciprocal identity defect, silent PQ
  fallback, unauthenticated contact/PQ metadata и private keys извън Key Vault.
- Практическата containment промяна е import-time fail-closed tombstone без
  path, data, filesystem или cryptographic-backend access.
- `mokosh_gui.py` и `mokosh_v2_contact_slots.py` остават byte-exact;
  `SAFETY_MODE=True`. Няма legacy data read/migration/delete/rewrite.
- Exact scope е 20 paths според
  `docs/LEGACY_CONTACT_CRYPTO_QUARANTINE_BG.md`. Десет predecessor hash gates
  запазват проверката си и сменят само разрешения `contacts_core.py` digest.
- Candidate/package/full authoritative tests, live apply, commit и tag не се
  твърдят предварително. Stage 2.46 localization остава paused.
- V2 contact service, vault-protected private keys, real two-party backend и
  GUI practical tests са последователни release blockers без waiver.
- Stage 2.45.1 release R1 dry-run е withdrawn: pinned runtime probes са PASS,
  но per-target baseline gate е използвал неправилно normalized-clone
  допускане `0644` за всичките 18 existing paths и е отказал върху физическия
  mode на `contacts_core.py`. Няма candidate/apply/project mutation. Exact live
  diagnostic и нов explicit correction scope са задължителни; R1 не се rerun-ва.
- Exact read-only diagnostic вече доказва `18/18` predecessor hashes и
  индивидуална mode карта `2×0600`, `11×0644`, `5×0664`, при clean Stage 2.45
  HEAD и zero residue. R1 дефектът повтаря документиран Stage 2.41/2.42
  physical-mode control failure; това е process-control recurrence.
- R2 tooling трябва да пази exact индивидуалните modes във baseline, payload,
  apply и rollback и да отказва path swap дори при непроменено aggregate mode
  count. До authoritative R2 laptop dry-run няма разрешение за apply и няма
  Stage 2.45.1 product PASS. Stage 2.46 остава paused.
- Authoritative R2 dry-run вече е PASS без mutation, но R2 е withdrawn за
  apply след pre-issuance temporary-repository failure: extracted-candidate
  whole-tree inventory проверката е била повторно използвана върху live repo и
  е отказала валидните `.git`/bytecode records. Installer rollback и cleanup са
  PASS; laptop project не е променян.
- R3 разделя exact extracted-candidate inventory от live selected-source
  snapshot и запазва отделните exact Git status, tracked, physical, fsck и
  bytecode gates. Няма scope expansion или предварителен apply/PASS claim.
- R3 temporary dry-run и apply QA са PASS върху scratch Python `3.12.14`, с
  два отделни candidate/live `10/494/2191` regression цикъла, 20/20 rollback,
  exact 20-path post-state и cleanup. Authoritative laptop R3 dry-run и live
  apply впоследствие са PASS с `10/494/2191`, exactly three historical
  expected failures и zero skips. Independent post-apply verifier потвърди
  exact 20 unstaged paths и no project mutation. Commit/tag остават pending.

## Stage 2.45.2 — MOK1 compatibility quarantine candidate

- Authoritative base вече е clean Stage 2.45.1 commit
  `74186e6832964031b92d571786e5a133b336df81`, tree
  `bd28ab195345f8e17b3b8724c23140ad53c7cef9`, annotated tag
  `stage2.45.1-legacy-contact-fail-closed-quarantine`. Това актуализира
  предходния pre-commit status; не променя историческите evidence записи.
- Read-only MOK1 runtime diagnostic потвърди valid historical roundtrip, но и
  plaintext/unauthenticated metadata, ignored algorithm, unknown-KDF fallback,
  unbounded header/whole-file reads, overwrite/symlink behavior, caller-umask
  output mode и password/nickname delimiter collision.
- Окончателният приет freeze е exact 30 paths. Първоначалният 28-path списък
  е бил непълен, защото едностепенната проверка е пропуснала два теста, които
  pin-ват хешове на променените predecessor tests. Няма user-repository
  mutation; recursive closure до неподвижна точка добавя само тези два tests.
  Окончателният граф съдържа 20 direct и 6 second-order hash edges; петте
  second-order замени са в двата добавени tests, а шестата е в вече включения
  localization test.
  Единствената production промяна е
  `crypto_core.py`; `mokosh_gui.py`, `contacts_core.py`, requirements и V2
  модулите остават byte-exact. Stage 2.46 localization остава paused.
- Нов MOK1 writer отказва fail-closed преди I/O/crypto. Legacy password и
  raw-key decrypt използват strict 65 536-byte parser, exact algorithm/KDF
  policy, bounded reads, two-pass payload authentication и private atomic
  no-clobber `0600` output.
- Историческите advisory header metadata и `password|nickname` ambiguity не се
  представят като поправени със задна дата. Те са containment-only и се
  премахват за ново копие единствено чрез отделно V2 повторно криптиране.
- Candidate/dry-run/apply/full regression/commit/tag PASS не се твърдят преди
  съответния gate. Няма compliance, certification, CE или legal claim.

## Stage 2.46 — protected profile/session normal-GUI candidate

- User-ът прие exact 35-path freeze върху clean `ce51ab1` / tree `a616b8b`.
- Авторитетният GUI/runtime остава `$HOME/venv_sys/bin/python3`; launcher-ът,
  requirements, `seed_manager.py`, `mokosh_paths.py`, contacts, crypto/V2/Key
  Vault cores остават byte-exact.
- Добавен е Linux-only fail-closed protected profile root с canonical public
  descriptor и existing schema-2 encrypted Key Vault в immutable generation.
  Descriptor се публикува последен само след fresh reopen/unlock verification.
- First run иска прякор, парола и повторение; след create остава заключено и
  изисква изричен `LOGIN`. Мастер фразата е ясно означена като незадължителна,
  но още нереализирана; modern recovery е Stage 2.47.
- Сесията изчиства password при отказ и двете полета при успех, има 15-minute
  inactivity, manual/panic/close и clock/suspend fail-safe locking.
- Capability registry разрешава само explicit historical one-file MOK1
  recovery след profile login. Encrypt, clean, contacts, contact crypto,
  sandbox, recovery phrase и network остават disabled.
- Обикновеното script стартиране от byte-exact launcher показва новия normal
  profile GUI. `mokosh_gui.main(...)` остава техническият recovery/evidence
  seam, достъпен от normal GUI чрез отделен `--maintenance` процес. Това пази
  приетите visual/recovery harness consumers без scope expansion.
- Новият normal GUI пази досегашната логика и симетрия: status, EN/BG, local
  folder, password/login, nickname, два реда по три action buttons, scrollbar,
  resize и аварийно `Ctrl+Shift+L`.
- Scratch new-suite е `62/62`; пет predecessor GUI suites са `133/133`, а
  exact 15-file hash/affected set е `472/472` под описания QA-only shim.
  След инсталиране на exact dependencies в отделен temporary venv целият
  regression е `2279/2279` с zero non-pass и real ML-KEM-768. In-memory
  compile и `git diff --check` са PASS. Exact Python 3.12.3 laptop regression,
  practical visual observation, package dry-run/apply и native Windows/macOS
  tests остават pending и не се твърдят предварително.
- Договорът, ограниченията, exact paths и следващите отделни stages са в
  `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`.
- Authoritative R2 dry-run/apply/independent verifier са PASS, но първият
  practical visual Case 1 на 2026-09-12 е blocking `FAIL`: locked activity
  routing изчиства nickname/password при всеки клавиш и не позволява login.
  R2 не се commit-ва. Приетият exact 7-path R3 correction пази първоначалния
  35-path freeze и всички capability граници; full QA и повторен visual test
  остават задължителни.
- R3 pre-issuance QA върху изолирана exact R2 база е PASS: `7/7` rollback,
  deterministic double build, wrapper dry-run без project mutation и
  disposable exact-function apply; candidate/live `65/472/2282` са без
  non-pass или residue и post-state остава exact 35 unstaged. Това е local
  Python 3.12.14 QA. След този evidence update следва fresh final-byte QA;
  авторитетният laptop Python 3.12.3 dry-run и повторният visual matrix още не
  се представят като PASS.

## Stage 2.46 — R4 first-run modal input correction

- Authoritative R3 live apply и independent post-apply verifier са PASS върху
  exact 35 unstaged paths, physical SHA-256
  `30c26c0a7b5a97cdd972c3877781f5562efc5719aa54050c577e160358db2842`
  и `65/472/2282` tests.
- Повторният human Case 1 потвърди поправката на главните login fields:
  typing retention, password/nickname masking toggle и EN/BG превключване са
  видимо работещи. BG screenshot разкри отделно clipped действие
  `Почистване на оригинали...`.
- Изолираният temporary first-run login опит беше спрян преди profile create,
  защото modal nickname/password/confirmation entry полетата не приемаха
  typing или paste. Не е заявен profile/data mutation или successful login.
- Причината е непокрит отделен Tk lifecycle: early `grab_set`, липсващ explicit
  initial focus и липса на тест, който изобщо отваря `FirstRunProfileWindow`.
  R3 normal-window tests и runner с `auto_first_run_prompt=False` не са могли
  да докажат този път.
- User-ът прие exact 12-path R4 corrective freeze. Той не променя established
  layout, crypto/storage/KDF/capabilities или recovery scope.
- Candidate-ът подрежда modal lifecycle като build → visible → focus → grab,
  пази една first-run инстанция, добавя bounded in-memory entry-transition
  visual route и приетия кратък BG текст `Почисти оригинали...`.
- Новите automated проверки включват exact modal call order, retained entries,
  idempotent secret clearing/close, duplicate-window refusal, complete visible
  login transition, bounded visual report и synthetic create/login/lock state.
- Local pre-documentation резултатите са target `76/76`, affected `472/472` и
  full `2293/2293`, zero failures/errors/expected failures/skips. Package,
  authoritative laptop apply, independent verifier, human transition PASS,
  commit и tag още не са изпълнени и не се твърдят.
- R4 pre-issuance wrapper dry-run върху exact R3 base е PASS: 16 self-tests,
  `12/12` rollback плюс success rollback и candidate `76/472/2293` без
  mutation/residue. Exact shipped apply функцията е PASS само върху
  disposable copy и повтори live `76/472/2293` с exact 35 unstaged paths.
  Това е QA Python 3.12.14, а не user Python 3.12.3; след този evidence update
  следва fresh deterministic final build и пълна final-byte QA.

## Stage 2.46 — R5 non-blocking first-run mapping correction

- R4 authoritative dry-run/apply/independent verifier са PASS с exact 35
  unstaged paths, `76/472/2293` и physical SHA-256
  `5895c0a318da4300e1c738c705afedc25490d39ed632d41768a3f19091c7a8ab`.
- R4 human entry-transition е blocking `FAIL`: след synthetic startup текста
  не се показа прозорец, prompt не се върна и `Ctrl+C` не прекрати Tk wait.
  User-ът спря процеса с `Ctrl+Z` и `kill %%`; няма profile/data mutation.
- Root cause е synchronous `wait_visibility()` в first-run конструктора.
  R4 test design погрешно е pin-нал wait → focus → grab, без да доказва, че
  конструкторът се връща и прозорците се map-ват. Няма R4 commit/tag.
- User-ът прие exact 10-path R5 freeze. Корекцията премахва всички blocking
  visibility calls, използва `<Map>` плюс idempotent `after_idle`, отменя
  pending activation при close и добавя три отделни terminal liveness markers.
- Отделен executable-constructor regression доказва, че няма synchronous
  focus/grab/wait/update/mainloop. Map, duplicate Map, temporarily unviewable,
  close-before-callback и marker idempotence са покрити.
- Pre-documentation резултатите са target `80/80`, affected `472/472`, full
  `2297/2297`, zero non-pass. Package/laptop/independent/human gates предстоят;
  crypto/storage/KDF/capability/recovery/network scope не се променя.

## Stage 2.46 — R6 final-evidence closure candidate

- Final R5 package е
  `MOKOSH_STAGE2_46_R5_NONBLOCKING_FIRST_RUN_MAPPING_ce51ab1_R1.pyz`,
  size `226610`, mode `0600`, SHA-256
  `d09601dcad502dc032b8687f336d9e7ff357eb0baf1b2f491a9220397deae755`.
- Authoritative Python 3.12.3 dry-run и live apply са PASS: 16 installer
  self-tests, `10/10` rollback плюс success rollback, candidate/live
  `80/472/2297`, zero non-pass/residue и exact 35 unstaged paths. R5
  post-apply physical SHA-256 е
  `78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`.
- Отделният verifier, size `39247`, mode `0600`, SHA-256
  `183479b26ac3de2f2098bbcb229109599264517050c04bddec3b42147b439000`,
  потвърди package/runtime/primitives, 217 tracked, exact status 35, 4341
  bytecode records, `80/472/2297` и identical state след проверката.
- Human BG/100 entry-transition е `PASS` с 11/11 observations: constructor
  return, двата Map events, един first-run dialog, typing и `Ctrl+V` paste,
  password confirmation/masking, create към locked, main login input,
  credential clearing, BG/EN unlocked status и manual lock. Трите non-secret
  terminal markers са изведени точно веднъж и process prompt се върна след X.
- `FIRST_RUN_MAPPED` преди `MAIN_MAPPED` е допустим observed window-manager
  event order; договорът изисква uniqueness и presence, не измислен ред.
- Touch single tap правилно само фокусира. Current Tk Entry няма реализирано
  application long-press menu; touch-native Paste не е заявено като PASS.
  Изрично Cut/Copy/Paste context menu остава бъдещо обсъждано cross-platform
  UX подобрение, не security control и не част от R6.
- User-ът прие exact 5-document R6 final-evidence freeze. Production code,
  localization, GUI behavior, crypto, KDF, storage, capabilities, recovery и
  network остават byte-exact спрямо успешно проверения R5.
- Този candidate запис сам по себе си не твърди R6 application, commit/tag,
  release readiness, certification, official audit или legal conformity.
  Тези състояния изискват отделни външни gates и доказателства.

## Stage 2.46 — R6 authoritative completion evidence

- Final R6 package
  `MOKOSH_STAGE2_46_R6_FINAL_EVIDENCE_CLOSURE_ce51ab1_R1.pyz` е `216370`
  bytes, mode `0600`, SHA-256
  `67229f0dac54d96a4f5c1d3ba44338baa7f0a897e88bd1b4b1cd1259f3a38e37`.
- User Python 3.12.3 dry-run е PASS върху exact R5 physical baseline
  `78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`:
  16 self-tests, `5/5` rollback плюс success rollback, candidate
  `80/472/2297`, zero non-pass/residue и no project mutation.
- Live apply е PASS с live `80/472/2297`, exact 35 unstaged paths и final
  tracked physical SHA-256
  `2ba8c8eeb024cad44df35d758d24e2d940411fbc8008158694e336dacdbc6255`.
- Independent verifier
  `MOKOSH_VERIFY_STAGE2_46_R6_POST_APPLY_ce51ab1_R1.py` е `39095` bytes,
  mode `0600`, SHA-256
  `e97c9d033a74c42fc508d330d53bf507133a0fe8bade17fc79ff3866da8c8955`.
  Той потвърди package/runtime/primitives, 217 tracked, status 35, physical
  digest, 4341 bytecode records, 165 Python и 1 shell source,
  `80/472/2297`, след което повторният snapshot е identical и
  `INDEPENDENT_STATE_UNCHANGED=PASS`.
- User-ът прие completion amendment в същите пет документа. Няма нов
  production, localization, test, GUI, crypto, KDF, storage, capability,
  recovery или network delta и human GUI run не се повтаря.
- Техническото Stage 2.46 завършване изисква exact 35-path commit и annotated
  tag от отделния finalizer. То не е certification, official audit, legal
  opinion, Windows/macOS native PASS или обща release-readiness декларация.

## Stage 2.47 — optional 25-word profile password recovery candidate

- User-ът прие exact scope freeze от 32 файла върху commit
  `3716a8ecdf9b546d39cbef750c97811e7bb77cef`, tree
  `6fc1059b3ecaf9c8cdb228981acc1a15c0d80cf0` и annotated tag
  `stage2.46-protected-profile-session-normal-gui`.
- Работата се извършва само в изолирано копие. Авторитетният
  `~/MOKOSH_Agent` не е променян.
- `MOKOSH-RP1` представя exact random 256-bit recovery root като 3 version
  bits + 256 root bits + 16 transcription-checksum bits = 25 цели думи от
  pinned 2 048-word English vocabulary. Форматът не е BIP39 wallet mnemonic.
- Setup е по желание, само след explicit login и current-password reauth.
  Първо се записва криптираният `.mokr`, после ползвателят избира отделен
  recovery-sheet device или хартия с пълно повторно въвеждане.
- File sheet-ът се записва директно само в user-selected нова private папка на
  отделен Linux filesystem device. FAT/exFAT се отказват; MOKOSH не форматира,
  mount-ва или изтрива носители и не пази фразата вътре в приложението.
- Forgotten-password workflow е достъпен само при заключен `READY` профил.
  Exact Vault, `.mokr`, фраза и нова парола се проверяват read-only; само едно
  финално yes/no разрешение публикува следващото immutable Vault поколение.
- Старото Vault поколение и `.mokr` се запазват. Това сменя latest профилната
  парола, но не revoke-ва вече копирани recovery материали. След publish
  профилът остава заключен и изисква explicit login с новата парола.
- EN/BG интерфейсът обяснява риска и следващото действие преди всяка стъпка.
  Phrase setup window се изчиства при lock/close; panic затваря и двата
  recovery прозореца. Няма clipboard, log, network или automatic destination.
- Local final-code evidence е target `138/138`, affected `472/472` и full
  `2374/2374`, с нула failures/errors/expected-failures/skips. Pre-release
  package rehearsal добавя `16/16` installer self-tests, `32/32` file rollback,
  `2/2` new-directory rollback и повторно `138/472/2374` PASS върху частно
  candidate копие. Това още не е user-machine, human-visual, live-apply или
  independent-verifier PASS.
- Новите договори са `docs/PROFILE_RECOVERY_PHRASE_CONTRACT_BG.md` и
  `docs/RECOVERY_PHRASE_STORAGE_CONTRACT_BG.md`. Stage 2.48 V2 encrypt/decrypt
  wiring остава отделно и всички unfinished normal actions са disabled.

## Stage 2.47 — приет коригиращ обхват (2026-09-15)

Практическата проверка на R1/R2 откри реални GUI/lifecycle дефекти; затова
предишните local counts са исторически evidence, а не приемане на Stage-а.
Корекцията добавя общ resizable/reflow/dialog договор, очи за всички password
полета, локализирани action labels, field-specific local validation и
fail-closed recovery-state gate. „Забравена парола…“ е активен само при
`CURRENT` комплект и заключен READY профил. След успешна смяна старият
комплект става `REPLACEMENT_REQUIRED`, бутонът е пасивен, статусът остава
видим и първите два успешни входа напомнят за нов `.mokr` и фраза.

Новият точен договор е `docs/PROFILE_RECOVERY_STATE_CONTRACT_BG.md`. Локалният
коригиращ scope suite е `181/181` PASS. Един по-широк discovery изпълни 2361
теста без test failure, но три модула не се import-наха, защото изолираният
анализатор няма `argon2`; това не е full-suite PASS. Exact 33-path R3
коригиращ пакет е изграден: installer self-tests са `17/17`, rollback
инжектирането мина всичките 33 позиции плюс success rollback, isolated
candidate е 254 файла / 181 Python / 1 shell и target suite е `181/181` без
остатък. Предстоят user-machine dry-run/apply, пълният suite в pinned runtime,
independent verifier и human GUI retest. Няма Stage PASS, commit или tag.

## Stage 2.47 — R3 apply status-gate incident и R4 корекция (2026-09-15)

User-machine R3 dry-run е PASS върху exact R1 baseline: runtime/primitives,
33-position rollback, static/delta, target `181/181`, affected `472/472`, full
`2416/2416`, no residue и повторен identical baseline. При отделния live apply
същите candidate проверки отново са PASS, но post-overlay gate спря с
`live exact 38-path status drift`; R3 не е приет и не се retry-ва.

Root cause е exact и локално възпроизведен: крайният Git status съдържа 40, а
не 38 пътя. R3 е включил шестте нови пътя, но е пропуснал двата реално
променени tracked файла, които са били чисти в R1:
`mokosh_profile_storage.py` и `tests/test_mokosh_profile_storage.py`.
Recovery/product тест не се е провалил; дефектът е в installer expected-state
модела. Вторият identical `EXACT_STAGE2_47_R1_BASELINE=PASS` след
`CANDIDATE_RESIDUE` в live-apply output доказва, че exception path е върнал и
проверил R1 преди крайния отказ. R4 dry-run ще повтори същия baseline gate
преди каквато и да е mutation.

R4 извежда candidate status от `R1_STATUS_PATHS ∪ CORRECTION_PATHS`, очаква
exact 40 paths и добавя installer regression, който pin-ва двата clean-tracked
correction paths. R3 е withdrawn. Няма Stage PASS, commit или tag; следват R4
package self-test/rehearsal, user dry-run, отделен apply, independent verifier
и practical GUI audit.

## Stage 2.47 — R4 приложен, practically audit и ограничен R5 (2026-09-15)

R4 е приложен успешно върху exact 40-path unstaged state. User-machine
target/affected/full са `181/472/2416` PASS, а независимият read-only verifier
повтори `181/472/2416`, потвърди tracked physical SHA-256
`6fc034535dad1d5bc6afd55bf7f8786368b95119d07f204efbfe170a58d614c6`
и не откри project mutation или test residue.

Следващият BG/100 human audit откри три незатворени practically дефекта:
горните контроли се изрязват при тесен основен прозорец; setup текстът използва
`Vault` без достатъчно човешко обяснение; указанието за отделния носител е
техническо и не казва пряко „отделна флашка или външен диск“ и защо FAT/exFAT
се отказва. Нормалното връщане на terminal prompt и трите harness mapping
маркера доказват само clean construction/exit, не PASS на тези наблюдения.

Ограниченият R5 кандидат добавя shared responsive pair layout за folder,
password, nickname и footer редовете, така че контролите да се подреждат под
полето преди изрязване. EN/BG текстовете вече обясняват Vault като криптирано
защитено хранилище за ключове и посочват отделна USB флашка/външен диск с Linux
файлова система; FAT/exFAT не може да ограничи аварийния лист само до
потребителя. Exact R4 comparison показва само девет умишлено променени пътя:
три product/test двойки и тези три evidence документа. Локалният target suite
е `184/184` PASS. Scratch runtime няма `argon2`, затова local affected run
изпълни 472 теста, но 10 import проверки не могат да се приемат за PASS;
pinned user-runtime dry-run трябва да повтори target/affected/full без waiver.

Human replay се води постоянно по една стъпка: една команда или едно GUI
действие, screenshot/описание, после изрична оценка PASS/FAIL/UNCLEAR преди
следващото действие. При FAIL се спира, записва се evidence, прави се
ограничена корекция и се повтаря само засегнатият checkpoint. Няма Stage PASS,
commit или tag.

## Stage 2.47 — R5 practical FAIL и изолиран R6-R3 PASS (2026-09-15)

User-machine R5 dry-run/apply и независимият post-apply verifier са PASS с
target/affected/full `184/472/2419`, exact 40-path unstaged state и tracked
physical SHA-256
`816c1ffc5f910f6af78381819d6a04efa3da77b92c950d570ef22a911c41609f`.
Тези резултати не покриват real-pixel геометрията. Practical BG/100 replay
доказа D07: nickname entry е само 99 px, а eye и create-profile controls са
принудени до еднакви 262 px от shared `uniform`.

STOP-THE-LINE real-Tk RED diagnostic възпроизведе дефекта без project
mutation. R6-R1 спря безопасно при прекалено строг 276 px criterion. R6-R2
погрешно обяви automated GREEN, но human screenshot го отхвърли: default
layout беше stacked, eye беше преместено под entry-то, а create-profile
control беше раздут от requested 262 до actual 650 px. Този false GREEN е
обезсилен и записан като test-contract defect.

Изолираният R6-R3 запазва entry и eye в един primary ред, ограничава
create-profile control до естествената му ширина и при narrow layout премества
само него. Новият gate измерва X/Y съседство, редове, actual/requested widths,
bounds и default/wide/narrow състояния и изрично отхвърля exact R5 и R6-R2
envelopes. User real-Tk резултатът е:

- default: `entry=278/req=206`, `eye=107/107`, `create=248/248`, inline;
- wide: `entry=558/req=206`, `eye=107/107`, `create=248/248`, inline;
- narrow: `entry=336/req=206`, eye остава до entry, `create=248/248` е
  единственият control на втория ред;
- всички са in-bounds; folder guard е PASS; automated contract, human
  screenshots и `CLOSED_NO_PROJECT_MUTATION` са PASS.

Това разрешава подготовка на R6 live installer/dry-run, но още няма live R6,
Stage PASS, commit или tag. Следват поотделно pinned-runtime dry-run, изрично
приет apply, independent post-apply verifier и повторен practical checkpoint.

## Stage 2.47 — R6-R1 installer baseline-mode safe stop (2026-09-16)

Първият user-machine R6 installer dry-run спря преди candidate copy, rollback
инжектиране, тестове или project mutation с
`R5 untracked mode drift: run_mokosh_profile_recovery_visual_harness.py`.
Причината е package-manifest дефект: builder-ът е записал `0600` за всичките
22 untracked файла, въпреки че exact applied-R5 runner-ът правилно е `0700`.
Product source и user repository не са виновни и не са променени.

R6-R1 installer е withdrawn. R6-R2 pin-ва пълната exact mode карта — 21 файла
`0600` и единствения runner `0700` — както в manifest validation, така и в
installer self-test. Локалният rehearsal вече трябва да извика и
`verify_untracked_baseline`, а не да сравнява само хешовете. Няма waiver,
Stage PASS, commit или tag; R2 започва от същия exact R5 baseline.

## Stage 2.47 — приложен R6 и ограничен R7 setup-reflow кандидат (2026-09-16)

R6-R2 dry-run, live apply и независимият post-apply verifier са PASS в pinned
user runtime. Финалният exact state е 40 unstaged paths, target/affected/full
`185/472/2420` и tracked physical SHA-256
`5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db`.
Това не е Stage PASS: практическата последователност продължава.

Physical BG/100 checkpoint потвърди move, Escape и X close-child behavior и
оттегли погрешната хипотеза за scroll дефект. Потвърдени са две UI находки:
при minimum-width setup реда бутонът „ПОДГОТВИ ВЪЗСТАНОВЯВАНЕ“ се изрязва, а
responsive warning текстът може да стигне практически до дясната стена.
След споделяне, обсъждане и изрично решение е разрешен само R7 UI scope.

R7 държи current-password entry и eye на един primary ред и премества само
prepare control-а на втори, дясно подравнен ред, когато real requested widths
не се събират. Бутонът остава с естествената си Tk ширина. Shared responsive
label вече изчислява wraplength от собствената си actual `<Configure>` ширина,
а не от по-широк padded parent. Няма промяна в crypto, storage, recovery
lifecycle, пароли, текстове, формати или user-data операции.

Локалният R7 target е `188/188` PASS. Affected invocation откри 472 теста, но
10 legacy imports са блокирани от липсващ `argon2`; резултатът не се приема за
affected PASS. Local full discovery изпълни 2368 теста с 3 import errors и 7
skips и също не се приема за PASS; pinned runtime трябва да повтори exact full
без non-pass. Изолираният package self-test доказва exact R6 10-path source,
двата R6 RED source shapes, два отрицателни и два положителни layout envelope-а
и no project mutation. User-machine real-Tk audit измери default, wide и
minimum BG/100 геометрии и завърши с `RECOVERY_SETUP_LAYOUT_AUDIT=PASS`.
При minimum entry и eye останаха на един ред, само prepare control-ът премина
на втори дясно подравнен ред с actual/requested ширина `314/314`, а трите
проверявани label-а запазиха договорения вътрешен wrap clearance. Human
прегледът обхвана последователно горната и долната част на целия тесен прозорец,
включително всичките 25 думи, трите стъпки и „Отказ“, и беше изрично приет за
визуален PASS. По-късният exact bytecode gate доказа, че preview-ът е оставил
игнорирани `.pyc` записи; неговият `CLOSED_NO_PROJECT_MUTATION` marker е
оттеглен. Това не обезсилва визуалния PASS, но обезсилва твърдението за
физическа неизменност.

Постоянният работен ред е: всяка находка, PASS, FAIL, обновяване или предложена
промяна първо се споделя, после се обсъжда, взема се изрично решение и едва
тогава се извършва действие или траен запис. След изричното решение е разрешена
само подготовка на guarded read-only R7 dry-run package. Няма R7 live mutation,
apply, Stage PASS, commit или tag.

## Stage 2.47 — R7-R1 bytecode safe stop и R2 корекция (2026-09-16)

Първият guarded R7-R1 dry-run спря преди payload, candidate tests или mutation:
очакваните `4345` bytecode records вече бяха `4351`. Read-only inventory показа
шест допълнителни records и 11 наскоро записани root `.pyc` файла. Времената им
съвпадат с user real-Tk preview-а. Exact forensic проверка сравни Python magic,
source timestamp/size и целия marshalled code payload на всичките 11 файла с
текущите проверени `.py` източници; резултатът е `11/11` PASS. Няма различен
код, symlink или special object. Преди/след snapshot-ът остана exact
`4351` / `83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.

Причината е tooling defect: preview runner-ът не е забранил bytecode преди
project imports. R7-R1 е withdrawn и не се retry-ва. Изрично приетият R7-R2
добавя ранно `sys.dont_write_bytecode`, subprocess regression без външна
environment помощ, exact count+digest baseline и expected/actual diagnostics.
Текущото доказано source-identical bytecode състояние се pin-ва, а не се трие
или „връща“ по предположение. Разрешена е само подготовка и последващ read-only
R2 dry-run; apply, Stage PASS, commit и tag остават неразрешени.

## Stage 2.47 — R7-R2 dry-run, live apply и независима проверка (2026-09-17)

R7-R2 guarded dry-run е изпълнен в pinned user runtime и завърши с exact R6
baseline PASS: 232 tracked файла, physical SHA-256
`5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db` и
непроменен bytecode snapshot `4351` / `83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.
Rollback injection покри всичките 40 позиции плюс success rollback. Candidate
static/delta е 254 source файла, 181 Python, 1 shell и точно 10 променени
пътя. Target/affected/full са `189/472/2424` PASS без failures, errors,
expected failures или skips; няма test residue и повторният baseline е
идентичен. Dry-run завърши с `PASS_NO_PROJECT_MUTATION`.

След споделяне, обсъждане и изрично приемане live apply повтори candidate
проверките и след записа повтори live target/affected/full `189/472/2424`
PASS. Крайното състояние е точно 40 unstaged paths върху непроменения HEAD
`3716a8ecdf9b546d39cbef750c97811e7bb77cef`; tracked physical SHA-256 е
`972aa7bfbe40878934118ab1a7a81ab89dff3ec0fa7bb017b40570ed24581e58`.

Отделният read-only post-apply verifier потвърди 254 source файла, 40 status
paths, 22 untracked и 232 tracked файла, повтори независимо
target/affected/full `189/472/2424`, намери нулев residue и потвърди същите
physical и bytecode отпечатъци преди и след проверката. Финалът е
`STAGE2_47_R7_POST_APPLY_READ_ONLY=PASS_NO_PROJECT_MUTATION`.

R7 implementation, real-Tk geometry и whole-window human checkpoint са
приети. Този запис не обявява целия Stage 2.47 за завършен: остават guarded
evidence amendment, commit/tag и отделна post-commit проверка. Няма извършен
commit или tag.

## Stage 2.48 — isolated local V2 candidate (2026-09-18)

Stage 2.47 вече е завършен извън горния исторически pre-final запис и е
закрепен с commit `7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8`, tree
`3c30b84b10cb742ba4d08bc50d50361eaa953f06` и annotated tag
`stage2.47-profile-recovery-phrase-password-replacement` (tag object
`480e3f8efa436e1be7322899d8163d19018e095f`). Stage 2.48 започва само от този
clean checkpoint.

User pre-mutation gate потвърди 254 tracked files и baseline full
`2424/2424` PASS на Python 3.12.3 с pinned Argon2, cryptography/ML-KEM, Tk и
OpenSSL. Приетият Stage 2.48 scope е exact 32 paths: 23 existing и 9 new.
Live repository не е променян; кандидатът е само в exact изолирано копие.

Кандидатът добавя:

- session-bound local service за един файл, точно един active Vault slot при
  encrypt и exact active/retired stored version при decrypt;
- unsigned local MOKOSH2 policy, `.mok2` за нов encrypt и magic-based decrypt;
- no overwrite, originals always kept и generic output suggestions;
- sole session key lease, cancellation при lock/panic/timeout/close и refusal
  на втори operation/unlock до drain;
- atomic hard-link boundary: всеки post-publish cleanup/sync/close проблем е
  success-with-warning и никога retryable failure;
- read-only residue scan, `CLEAR/CLEANABLE/BLOCKED` policy и explicit exact
  evidence cleanup без source/final-output deletion;
- `O_NONBLOCK` regular-to-FIFO отказ, 4096-entry fail-closed directory bound и
  exact magic→inspection→pipeline source identity chain;
- един GUI worker, Queue/after main-thread updates, cancel и close/drain;
- mutually-exclusive V2/recovery/MOK1 windows, MOK1 close при session lock и
  изключени Clean/Contacts/Sandbox/Network;
- 16-case EN/BG × 100/125/150/200 × Encrypt/Decrypt synthetic visual contract.

Targeted regression е `218/218` PASS. Scratch full discovery е `2497/2497`
PASS за 25.661 s без failures, errors, expected failures, unexpected successes
или skips върху Python 3.12.14, Tk 9.0, argon2-cffi 25.1.0,
cryptography 49.0.0, real ML-KEM-768 и OpenSSL 3.5.8.

Тези резултати не са authoritative apply evidence. Остават final-byte audit,
package self-tests, 32-position rollback, deterministic build, user Python
3.12.3 read-only dry-run, отделно изрично решение за live apply, independent
post-apply verification и human visual matrix. Няма Stage 2.48 commit/tag или
release claim.

## Stage 2.48 — D1–D4 accepted corrective overlay (2026-09-23)

Текущият user-machine checkpoint остава HEAD
`7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8`, tree
`3c30b84b10cb742ba4d08bc50d50361eaa953f06`, branch
`feature/mokosh-v2-core`, празен index, 25 modified tracked и 9 untracked
paths. Human Cases 1–4 са затворени като observations, но общият gate не е
PASS. Cases 2–4 възпроизведоха D1–D4; Case 4 има 12 PASS и 4 FAIL.

Изрично е приет само 11-path D1–D4 overlay: трите implementation paths
`mokosh_profile_ui.py`, `mokosh_v2_local_gui.py` и
`run_mokosh_v2_local_visual_harness.py`, трите им test paths и петте
contract/status/evidence/history документа. Completeness review не откри
необходима промяна в localization, service, session, filesystem, pipeline,
lifecycle, crypto, Vault, MOKOSH2 format или standards crosswalk.

Negative-first контролът върху непроменените D1–D4 bytes възпроизведе всички
четири дефекта в шест избрани test methods: 5 failures и 2 errors заради
subtests. След bounded корекцията същите шест са GREEN. Разширените scratch
резултати са:

```text
D1_D4_FOCUSED=PASS tests=49 failures=0 errors=0 skips=0
D1_D4_AFFECTED=NO_FAILURE_OR_ERROR tests=243 failures=0 errors=0 skips=1
D1_D4_AST_PARSE=PASS python_files=189
```

Affected skip-ът е само ML-KEM dependency ограничение на scratch средата.
Full scratch discovery изпълни 2452 теста без functional failure, но има 3
`argon2` import errors и 7 environment skips; следователно не е PASS.
Авторитетният read-only gate трябва да използва pinned user runtime Python
3.12.3, argon2-cffi 25.1.0, cryptography 49.0.0, real ML-KEM-768, Tk 8.6 и
OpenSSL 4.0.1 и да завърши с очаквани `243/2507`, zero non-pass.

Това следва reproducibility, negative-control, traceability, bounded-scope и
fail-closed дисциплина; не е formal verification, standards certification,
independent security audit или accessibility conformance. Live repository не
е променян от тази подготовка. Dry-run-only пакетът е изграден без apply mode,
мина package self-tests и byte-identical deterministic rebuild; той още не е
изпълнен на user-machine. Следват pinned read-only dry-run, отделно решение за
apply, independent post-apply verifier и задължителен affected human replay.
`HUMAN_VISUAL_GATE=PENDING_REQUIRED`,
`STAGE_PASS_ALLOWED=NO`, `COMMIT_TAG_ALLOWED=NO`.

## Stage 2.48 — D5–D7 accepted corrective overlay (2026-09-24)

D1–D4 live apply и independent post-apply verification на user machine са
PASS: exact 34 status paths, physical SHA-256
`554b6ea553625c2b1293ec534f9b0c774cb34716502fb040e9e9289be4c930b0`,
projected tree `b14dd36c7461fbc4389ae720dcccb6af5709a21b` и pinned
target/affected/full `49/243/2507` с нулев non-pass. Human gate обаче остава
blocking.

Продължението на Case 4 потвърди D5 stale focus след state-button click, D6
auto-scroll към същия stale focus при restore/reactivation и D7 липсваща
`Return` активация при работещ `Space`. Read-only producer/consumer inspection
локализира причините в synthetic state command route и shared
`ScrollableRegion.focus_in`; production local GUI използва shared helper-а, но
не изисква собствен byte delta.

User-ът прие exact 9-path D5–D7 overlay: два implementation, два test и пет
contract/status/evidence/history paths. Няма промяна в crypto, Vault, format,
service, session, filesystem, pipeline, lifecycle, localization или
`mokosh_v2_local_gui.py`.

В byte/tree-exact изолирано копие старите 30 релевантни теста са PASS.
Добавените D5–D7 negative controls първо падат върху непроменения код
(`failures=5`, `errors=2`, включително token subtests), след което минималната
корекция дава `32/32` PASS; разширеният target е `51/51` PASS. Affected
scratch suite изпълни 245 теста без failure/error и с един environment-only
ML-KEM skip. Full scratch discovery изпълни 2454 теста с 0 assertion
failures, 3 липсващи-`argon2` import errors и 7 environment skips. И двата
резултата правилно остават non-PASS; package, pinned user-machine dry-run и
human replay още не са заявени като PASS.

Подготвеният D5–D7 R1 transport е строго read-only: parser-ът няма apply
route, manifest-ът съдържа точно деветте приети payload paths, package
self-tests са PASS и повторният build е byte-identical. Това доказва package
integrity/determinism, не pinned user-machine regression или human PASS;
изпълнението на user machine остава следващият gate.

Записан е процесен пропуск
`ASSISTANT_PROCESS_DEVIATION_04=INCOMPLETE_VIEWPORT_INSPECTION_AFTER_WINDOW_STATE_CHANGE`.
Постоянното правило е след resize/maximize/restore/minimize/reactivation да се
проверяват и горната, и долната част преди визуален PASS. Няма Stage PASS,
commit или tag.

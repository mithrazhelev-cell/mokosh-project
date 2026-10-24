# MOKOSH Stage 2.46 + Stage 2.47 — защитен профил, сесия и recovery amendment

Статус: Stage 2.46 е авторитетно завършен при commit
`3716a8ecdf9b546d39cbef750c97811e7bb77cef`. Stage 2.47 има приет exact
32-файлов scope и реализиран изолиран кандидат. За Stage 2.47 няма твърдение
за live apply, commit, tag, Windows/macOS готовност, compliance, сертификация
или независим одит преди съответните отделни gates.

Дата на първоначалния договор: 2026-09-11
Дата на Stage 2.47 amendment-а: 2026-09-13
Stage 2.46 historical base commit: `ce51ab1cd6e2e6c950a25215f81cba0df56f94b5`
Stage 2.46 historical base tree: `a616b8bd4e6d458c1b9134ec3061d5b5fed9ad1c`
Stage 2.47 exact baseline commit: `3716a8ecdf9b546d39cbef750c97811e7bb77cef`
Stage 2.47 exact baseline tree: `6fc1059b3ecaf9c8cdb228981acc1a15c0d80cf0`
Stage 2.47 baseline tag: `stage2.46-protected-profile-session-normal-gui`

## 1. Цел на Stage 2.46

Единствената продуктова цел е да се въведе безопасният потребителски вход към
вече реализирания schema-2 encrypted Key Vault, без да се активират
незавършените криптиране, изтриване, контакти, споделяне, sandbox или network
дейности.

Stage 2.46 добавя:

- първоначално създаване на един локален защитен профил;
- отделни прякор, парола и изричен бутон `LOGIN/ВХОД`;
- изрично заключване и 15-минутна inactivity сесия;
- заключване при затваряне, аварийно `Ctrl+Shift+L`, clock anomaly или
  вероятно suspend/resume събитие;
- изчистване на паролата при неуспешен вход и на двете полета при успешен;
- отделен еднофайлов прозорец за историческо MOK1 възстановяване;
- нормален Tk интерфейс, който пази установените редове и симетричните два
  реда по три основни бутона;
- отделен технически recovery/evidence harness.

## 2. Авторитетен runtime и интерфейс

Единственият авторитетен runtime за package dry-run, apply и final regression
остава:

```text
$HOME/venv_sys/bin/python3
```

Очакваната идентичност е Python 3.12.3, isolated venv, `cryptography 49.0.0`,
`argon2-cffi 25.1.0`, Tkinter и ML-KEM-768. `run_mokosh_gui.sh` остава
byte-exact и по подразбиране стартира точно този runtime.

Текущият Linux/Tk изглед е визуалната основа. Windows и macOS трябва да пазят
същата логика, четимост, последователност и приблизително разположение, но
pixel-identical изглед не се обещава без native platform tests. Stage 2.46
умишлено отказва профилно хранилище извън Linux, вместо да използва недоказан
filesystem fallback.

## 3. Нормален прозорец и технически harness

Обикновеното изпълнение на `mokosh_gui.py` от непроменения launcher отваря
`mokosh_profile_gui.py`. Опцията `--maintenance` отваря съществуващия
технически recovery/evidence интерфейс.

Директният Python seam `mokosh_gui.main(...)` остава техническият harness.
Това е минимална корекция спрямо първоначалната идея за безусловно
пренасочване на `main()`: recursive consumer review намери вече приети visual
и recovery тестове, които използват този seam. Безусловното му пренасочване
би счупило доказателствения стенд или би разширило silent exact scope-а.
Потребителският launcher и видимият нормален интерфейс не се променят от тази
вътрешна граница.

Нормалният прозорец пази следния ред:

1. компактен profile/session status;
2. `EN/BG`;
3. избор и видим адрес на локална работна папка;
4. поле за парола, око и `LOGIN/LOCK`;
5. поле за прякор, око и first-run profile бутон;
6. симетричен ред `Encrypt / Decrypt / Clean originals`;
7. симетричен ред `Contacts & Sharing / Contact Encryption / Sandbox`;
8. отделна Stage 2.47 recovery секция с setup и forgotten-password действия;
9. отделен бутон към maintenance/evidence и подсказка за аварийно заключване.

Прозорецът има вертикален scrollbar, mouse-wheel/PageUp/PageDown/Home/End
управление, минимален размер и responsive ширина. EN/BG текстовете са в
отделен bounded каталог; `qps-ploc` съществува само за layout тестове.

## 4. First-run договор

Когато exact profile root отсъства, GUI предлага създаване на профил. Няма
автоматично създаване и няма автоматичен login.

Изискват се:

- прякор;
- парола;
- повторение на паролата.

След успешно създаване профилът е `LOCKED`. Потребителят въвежда данните
отново и избира изрично `LOGIN/ВХОД`. Ако root е partial, malformed, symlink,
с грешни права или съдържа неизвестен object, той никога не се третира като
нова инсталация и нищо не се поправя/изтрива автоматично.

В Stage 2.46 мастер фразата не е реализирана. Stage 2.47 amendment-ът запазва
first run без автоматично recovery: прозорецът само обяснява, че настройването
е по желание след първия изричен login. Няма фиктивна фраза или скрит
recovery key. Реалният setup изисква отключена сесия и повторно въвеждане на
текущата парола.

## 5. Прякор и парола

Прякорът е public UI metadata, не криптографска тайна и не участва в KDF:

- Unicode NFC;
- 1–64 знака;
- поне един видим знак;
- без control, private/unassigned и bidi-formatting знаци;
- записва се в canonical `profile.json` и може да се покаже в status-а.

Паролата:

- Unicode NFC, без trim;
- минимум 15 знака;
- максимум 1024 UTF-8 bytes според Key Vault bound;
- допуска интервали и Unicode;
- няма произволно изискване за главна/малка/цифра/символ;
- не се съхранява от profile/session слоя.

Не се прави password-strength, OWASP, NIST, FIPS или compliance claim само
заради тези параметри. Реалните KDF параметри остават тези на Key Vault.

## 6. Дисково състояние

Default root е:

```text
${MOKOSH_PROFILE_ROOT}
```

когато environment override е зададен, иначе:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/mokosh/profile-v1
```

Структурата е точно:

```text
profile-v1/                 mode 0700
├── profile.json            mode 0600, canonical bounded public metadata
└── key-vault/              mode 0700
    └── vault-r...mokv       mode 0600, immutable authenticated generation
```

`profile.json` съдържа само format/version, random profile id, прякор,
created UTC, exact `key-vault` relative name и Vault id. Няма парола, private
key, root key, recovery secret, избран работен файл или telemetry.

Създаването е no-clobber. Key Vault generation се публикува чрез съществуващия
`VaultStorage`; след това се отваря наново, проверява се receipt-ът и се прави
fresh password unlock. Public descriptor се публикува последен чрез private
temporary, `fsync` и same-directory hard-link no-clobber. Прекъсване преди
последната стъпка оставя видимо `PARTIAL` състояние, което блокира повторно
създаване.

Старите `seed_store.enc` и `seed_meta.json` се проверяват само с exact-name
`lstat` за информационен marker. Те не се отварят, четат, хешират, мигрират,
изтриват или презаписват от новия normal startup.

## 7. Сесия

State machine:

```text
LOCKED -> UNLOCKING -> UNLOCKED -> LOCKING -> LOCKED
                    \-> LOCKED (generic authentication refusal)
UNLOCKED -> CLOSED (чрез задължително lock/close)
```

Потребителският error е еднакъв при грешен прякор, грешна парола, invalid
credential form или authenticated Vault failure. GUI не показва path,
exception details или кое поле е грешно.

При `UNLOCKED` се следят monotonic и wall clock. Lock се задейства при:

- 900 секунди без потребителска активност;
- monotonic rollback;
- wall-clock rollback над tolerance;
- прекалено разминаване между двата часовника;
- poll gap от поне 30 секунди като fail-safe suspend/resume heuristic;
- `LOCK`, `Ctrl+Shift+L`, затваряне или вътрешна грешка.

При `LOCKED` въвеждането на прякор и парола е подготовка за изричния login,
а не активност на отключена сесия. Общото Tk event routing няма право да
извиква session `touch()`, да изчиства или да пренаписва credential полетата,
докато сесията вече е заключена. Ако `touch()` на отключена сесия установи
clock/suspend/internal anomaly и я заключи, двете полета се изчистват и
изгледът се обновява. Това пази едновременно използваемия explicit login и
fail-closed изчистването при реален преход `UNLOCKED -> LOCKED`.

Python не може да докаже пълно zeroisation на immutable strings и runtime
copies. Mutable Key Vault buffers използват съществуващия best-effort wipe;
интерфейсът изчиства credential полетата. Това е ограничение, не обещание за
доказана memory zeroisation.

## 8. Capability gate

| Действие | LOCKED | UNLOCKED |
|---|---:|---:|
| Historical MOK1 one-file recovery | не | да |
| Stage 2.47 recovery setup | не | да |
| Stage 2.47 forgotten-password recovery | да, само при READY профил | не |
| Ново локално V2 криптиране | не | не |
| Локално V2 декриптиране | не | не |
| Почистване на оригинали | не | не |
| Contacts & Sharing | не | не |
| Contact Encryption | не | не |
| Sandbox | не | не |
| Network/online | не | не |

Registry съдържа и отрицателните възможности. Следователно пропуснат UI
`state=` не може логически да превърне незавършена функция в разрешена.

Legacy `Decrypt...` отваря отделен прозорец и иска **старите данни на MOK1
файла**, независимо от новия профилен login. Избира се един source и един нов
output. Използва се hardened `crypto_core.decrypt_file`; output overwrite,
symlink publish и нов MOK1 writer остават забранени.

## 9. Тестов и evidence договор

Новите тестове покриват:

- exact localization ключове, EN/BG и pseudo expansion;
- Unicode/bounds policy;
- canonical/deduplicated descriptor parsing;
- 0700/0600, owner/type, symlink, malformed, partial, unknown object;
- no-clobber и injected interrupted create;
- fresh reopen/unlock преди descriptor publish;
- wrong password/nickname с еднакъв резултат;
- explicit login, field clearing, manual/panic/close locks;
- inactivity, suspend gap, backward/divergent clocks;
- exact capability registry;
- MOK1 authorization и exact legacy API wiring;
- launcher/runtime/core byte-exact boundaries;
- синтетична EN/BG матрица при 100/125/150/200%.

Local scratch резултатите са отделни от авторитетните. Final gate изисква с
`$HOME/venv_sys/bin/python3`:

1. exact runtime probes;
2. installer self-tests и exact baseline/mode/ACL/inventory gates;
3. rollback injection за всеки target;
4. candidate new/affected/full regression без failures, errors, expected
   failures, unexpected successes или skips;
5. dry-run без repository mutation;
6. отделен apply и повторен live full regression;
7. post-apply exact status, no bytecode/residue, commit и tag само след PASS.

## 10. Исторически Stage 2.46 exact 35-path freeze

Production/harness:

1. `mokosh_gui.py`
2. `mokosh_profile_localization.py`
3. `mokosh_profile_storage.py`
4. `mokosh_profile_session.py`
5. `mokosh_profile_gui.py`
6. `mokosh_legacy_mok1_recovery_gui.py`
7. `mokosh_profile_main_gui_visual_harness.py`
8. `run_mokosh_profile_main_gui_visual_harness.py`

Нови tests:

9. `tests/test_mokosh_profile_localization.py`
10. `tests/test_mokosh_profile_storage.py`
11. `tests/test_mokosh_profile_session.py`
12. `tests/test_mokosh_profile_gui.py`
13. `tests/test_mokosh_legacy_mok1_recovery_gui.py`
14. `tests/test_mokosh_profile_integration.py`
15. `tests/test_mokosh_profile_main_gui_visual_harness.py`

Documents:

16. `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`
17. `PROJECT_STATUS_BG.md`
18. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
19. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
20. `docs/SESSION_LOG_BG.md`

Recursive `mokosh_gui.py` hash consumers:

21. `tests/test_contacts_core_quarantine.py`
22. `tests/test_mokosh_main_gui_recovery_chain_layout_audit.py`
23. `tests/test_mokosh_main_gui_visual_filesystem_claims.py`
24. `tests/test_mokosh_vault_recovery_entry_request.py`
25. `tests/test_mokosh_vault_recovery_entry_transition.py`
26. `tests/test_mokosh_vault_recovery_locale.py`
27. `tests/test_mokosh_vault_recovery_source_inspection_acknowledgement.py`
28. `tests/test_mokosh_vault_recovery_source_inspection_execution.py`
29. `tests/test_mokosh_vault_recovery_source_inspection_localization.py`
30. `tests/test_mokosh_vault_recovery_source_inspection_normal_gui_authorization_readiness_audit.py`
31. `tests/test_mokosh_vault_recovery_source_inspection_preparation_request.py`
32. `tests/test_mokosh_vault_recovery_source_inspection_presentation.py`
33. `tests/test_mokosh_vault_recovery_source_inspection_request.py`
34. `tests/test_mokosh_vault_recovery_source_inspection_ui_adapter.py`
35. `tests/test_mokosh_vault_recovery_source_selection.py`

Никой друг project path няма право да се промени. Особено byte-exact остават
`seed_manager.py`, `mokosh_paths.py`, `run_mokosh_gui.sh`, requirements,
contacts, Key Vault/V2/crypto cores и historical recovery modules.

## 11. Следващи отделни етапи

- Stage 2.48: нормално V2 local encrypt/decrypt свързване;
- по-късни отделни stages: clean-original authorization, contacts/key
  lifecycle, двупосочни sandbox import/export, help/source/evidence windows,
  opt-in online boundary, payments/domain, signing suite и packaging;
- Windows/macOS: native storage semantics, signing/notarization и реални
  visual/functional/security tests, а не терминална симулация, представена
  като native PASS.

Всяка нова идея или съществена промяна се обсъжда и freeze-ва отделно. В
рамките на приет Stage може да се прави само корекция, необходима за
сигурността, доказуемостта или изпълнението на настоящия договор, като тя се
записва с причина и тест.

## 12. Stage transfer package

Stage 2.46 се пренася като един deterministic Python zip application (`.pyz`),
изпълняван само с exact `$HOME/venv_sys/bin/python3`. Това е контролиран stage
installer, а не Windows/macOS distribution packaging.

- По подразбиране се допуска само `--dry-run`; той не променя repository.
- Wrapper-ът намира repository по проверими корени или отваря отделен Tk
  directory chooser; не отгатва и не сканира произволни user данни.
- Exact baseline physical/ACL/Git/bytecode/runtime gates предхождат payload,
  rollback и project tests.
- Всички 35 target-а имат отделна rollback injection. Съществуващите mode bits
  се запазват само след exact physical-baseline match; 14 нови data/code/test
  paths са `0600`, а новият visual runner е `0700`.
- Live apply е отделен режим, отказва root и изисква втори exact confirmation
  token. Той не се предлага преди успешния user dry-run и преглед на изхода.
- Package self-test включва правилния public `mlkem` import и отрицателен
  predicate срещу погрешния `ml_kem` spelling преди repository access.
- Final archive bytes се изграждат поне два пъти и трябва да са SHA-256
  идентични; user-machine dry-run остава отделното авторитетно доказателство.

R1 е оттеглен след fail-closed authoritative bytecode mismatch без payload или
mutation. Normal GUI огледът след handoff е обновил валиден derived
`crypto_core.pyc`; exact source/rebuild validation е PASS. R2 запазва strict
4341-record invariant с новия доказан digest и не променя този Stage contract,
35-path freeze или интерфейс.

Authoritative R2 dry-run, live apply и независим post-apply gate са PASS с
exact 35 unstaged paths и `62/472/2279` теста. Първият human visual Case 1 на
2026-09-12 обаче откри, че прекалено широкият activity handler изчиства
credential полетата при всеки клавиш в `LOCKED`, което прави login невъзможен.
Case 1 е `FAIL`, R2 не се финализира и не се commit-ва. Приетият R3 corrective
freeze е exact седем вече разрешени пътя; той коригира event routing-а, добавя
регресионни тестове и записва доказателствената причина, без нова capability,
ново действие или разширяване извън първоначалните 35 пътя.

R3 е инкрементален пакет върху exact успешно приложения R2 worktree, а не
повторно прилагане върху clean Stage 2.45.2. Той pin-ва същите 35 unstaged
пътя, включително отделни size/SHA-256/mode проверки за 15-те untracked R2
пътя, и заменя само приетите седем съществуващи файла. Local pre-issuance QA
премина `7/7` rollback injections, deterministic double build, dry-run без
mutation и disposable exact-function apply с candidate/live `65/472/2282` и
zero non-pass/residue. След настоящия evidence update се изисква fresh final
QA върху точните издавани байтове; user Python 3.12.3 dry-run и повторният
human visual matrix остават отделни задължителни gates.

## 13. Stage 2.46 R4 first-run input corrective freeze

След authoritative R3 apply и independent post-apply PASS човешката проверка
потвърди, че главните locked login полета вече задържат въведения текст и че
маскирането, показването и EN/BG превключването работят. Следващият изолиран
first-run опит обаче отказа преди създаване на профил: трите полета в малкия
modal прозорец не приемаха нито клавиатурен вход, нито paste.

Това е отделна GUI lifecycle грешка и отделен пропуск в тестовото покритие.
`FirstRunProfileWindow` е изпълнявал `grab_set()` преди построяването и
показването на entry контролите и не е задавал начален focus. R3 тестовете са
покривали `ProfileMainWindow`, а synthetic runner-ът изрично е стартирал с
`auto_first_run_prompt=False`; backend first-run integration test не създава
Tk прозорец. Следователно automated PASS не е доказвал този видим път.

Приетият R4 договор е exact 12-path delta върху приложения R3:

1. `mokosh_profile_gui.py`
2. `mokosh_profile_localization.py`
3. `mokosh_profile_main_gui_visual_harness.py`
4. `run_mokosh_profile_main_gui_visual_harness.py`
5. `tests/test_mokosh_profile_gui.py`
6. `tests/test_mokosh_profile_localization.py`
7. `tests/test_mokosh_profile_main_gui_visual_harness.py`
8. `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`
9. `PROJECT_STATUS_BG.md`
10. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
11. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
12. `docs/SESSION_LOG_BG.md`

Корекцията запазва установения интерфейс и прави точно следното:

- първо построява entry контролите, после изчаква modal прозорецът да стане
  видим, насочва focus към nickname и едва тогава придобива local grab;
- пази една жива first-run инстанция, не допуска наслагване на два modal
  прозореца и изчиства трите полета при idempotent close;
- запазва native Tk Entry typing/paste и маскирането на двете password полета;
- добавя изцяло in-memory `--entry-transition` visual route без profile/data
  filesystem I/O: first run → create → locked → login → unlocked → manual lock;
- изисква девет отделни human observations, включително paste, field clearing,
  `ОТКЛЮЧЕНО`, `ЗАКЛЮЧИ` и връщане към `ЗАКЛЮЧЕНО`;
- сменя само дългия BG action label с приетото `Почисти оригинали...`, без да
  включва самото незавършено действие.

Local pre-documentation QA на R4 е PASS `76/472/2293`, zero non-pass. Това е
scratch доказателство, а не authoritative laptop, package, practical visual,
commit или tag PASS. След exact documentation bytes са задължителни повторни
target/affected/full suites, 12/12 rollback injection, deterministic package,
user Python 3.12.3 dry-run/apply, independent verification и успешен human
entry-transition test. Няма промяна в crypto, KDF, storage format, capability
registry, network policy или Stage 2.47 recovery границата.

### R4 pre-issuance package gate — 2026-09-12

Предварителният R4 wrapper върху отделна exact R3 база премина 16 installer
self-tests, `12/12` failure-position rollback плюс success rollback,
candidate `76/472/2293` и повторна byte-exact baseline проверка без mutation.
Exact shipped `live_apply` беше изпълнен само върху disposable repository и
повтори live `76/472/2293`, exact 35 unstaged paths и zero residue. Този
резултат не замества авторитетния Python 3.12.3 user dry-run/apply или human
проверката на реалния first-run прозорец. Понеже настоящият запис променя
payload bytes, final artifact задължително се изгражда и проверява наново.

## 14. Stage 2.46 R5 non-blocking first-run mapping correction

Авторитетният R4 dry-run/apply и независимият verifier са PASS на Python
3.12.3 с exact 35 unstaged paths, `76/472/2293`, 4341 bytecode records и
post-apply physical SHA-256
`5895c0a318da4300e1c738c705afedc25490d39ed632d41768a3f19091c7a8ab`.
Това не отменя human gate: първият R4 entry-transition опит отпечата началните
synthetic редове, но не показа нито main, нито first-run прозорец и остана в
блокиращо Tk изчакване. `Ctrl+C` не го прекрати; user-ът безопасно го спря с
`Ctrl+Z` и `kill %%`. Synthetic controller не извършва profile/data I/O.

Root cause е синхронното `wait_visibility()` в first-run конструктора,
извикан от main-window idle callback преди window manager mapping. R4
автоматичният тест е утвърдил реда wait → focus → grab, вместо да докаже
по-важното liveness изискване конструкторът винаги да се връща. Това е записан
assistant design/test error и R4 human result е `FAIL`; няма commit/tag.

User-ът прие exact 10-path R5 freeze: profile GUI, visual contract/runner,
двата им test файла и петте установени contract/status/evidence/crosswalk/log
документа. Няма localization, crypto, KDF, storage, capability, recovery или
network промяна.

R5 забранява synchronous visibility wait/update/mainloop в first-run
конструктора. Той само построява и bind-ва `<Map>`, след което се връща.
Реалният Map event планира една idempotent `after_idle` callback; тя проверява
`winfo_exists`/`winfo_viewable` и едва тогава задава nickname focus и local
grab. Close отменя pending callback, изчиства трите полета и прави закъснял
callback inert. Runner-ът отпечатва отделни `CONSTRUCTED`, `MAIN_MAPPED` и
`FIRST_RUN_MAPPED` PASS маркери, без credential/path стойности.

Pre-documentation target `80/80`, affected `472/472` и full `2297/2297` са
PASS с zero non-pass. Exact documentation-byte QA, 10/10 rollback,
deterministic package, user dry-run/apply, independent verifier и нов human
typing/paste transition остават задължителни.

## 15. Stage 2.46 R6 final-evidence closure

R5 final-byte package, authoritative user dry-run/apply и independent
post-apply verification са PASS. Live резултатът е exact 35 unstaged paths,
217 tracked files, 4341 baseline-relative bytecode records, physical SHA-256
`78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`
и target/affected/full `80/472/2297` без non-pass. Independent verifier-ът
повтори source/physical snapshot след suites и доказа unchanged state.

Human `--entry-transition --locale bg --scale 100` завърши успешно в същото
стартиране. Потвърдени са всичките 11 договорени observations: constructor
return; main и first-run Map; един фокусиран dialog; nickname typing и
`Ctrl+V` paste; password/confirmation input и masking; successful create към
locked main; main login input; clearing на двете login полета; visible
unlocked status/lock button; manual return към locked. BG/EN switch запази
unlocked state. След X процесът приключи и shell prompt се върна.

Terminal markers са точно по един `CONSTRUCTED`, `FIRST_RUN_MAPPED` и
`MAIN_MAPPED`. Observed first-run-before-main marker order е възможен Tk/window
manager event order и не нарушава contract-а, който изисква присъствие и
idempotence, а не фиксира inter-window order.

Практичният тест потвърди keyboard typing и `Ctrl+V` paste. Обикновеното touch
докосване трябва само да фокусира и не поставя clipboard съдържание
автоматично. Current application не реализира long-press/right-click
Cut/Copy/Paste context menu; touch-native Paste следователно остава явно
непроверена/нереализирана UX capability. Евентуално portable context menu
изисква отделен freeze, threat/usability review и Linux/Windows/macOS tests.

User-ът прие R6 като exact documentation-only delta по:

1. `PROJECT_STATUS_BG.md`
2. `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`
3. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
4. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
5. `docs/SESSION_LOG_BG.md`

Няма production, localization или test-source промяна и няма причина за
повторен human GUI run след byte-exact documentation-only apply. R6 package,
apply, independent verifier и repository commit/tag се удостоверяват външно;
този текст не ги предполага предварително и не е certification/compliance
declaration.

## 16. Stage 2.46 authoritative completion binding

R6 package (`216370` bytes, SHA-256
`67229f0dac54d96a4f5c1d3ba44338baa7f0a897e88bd1b4b1cd1259f3a38e37`)
премина authoritative Python 3.12.3 dry-run и live apply. Rollback е `5/5`
плюс success rollback; candidate/live suites са `80/472/2297` без non-pass
или residue. Post-apply tracked physical SHA-256 е
`2ba8c8eeb024cad44df35d758d24e2d940411fbc8008158694e336dacdbc6255`.

Отделният verifier (`39095` bytes, SHA-256
`e97c9d033a74c42fc508d330d53bf507133a0fe8bade17fc79ff3866da8c8955`)
потвърди package/runtime/primitives, exact 35-path state, 4341 bytecode
records, 165 Python и 1 shell source, повтори `80/472/2297` и доказа unchanged
state. Completion amendment е приет в същите пет документа и не променя този
contract или който и да е production/localization/test byte.

Следователно Stage 2.46 technical completion може да се закрепи с exact
35-path commit и annotated tag. В историческия Stage 2.46 това не активира
останалите capability gates: V2 encrypt/decrypt, clean, contacts, contact
crypto, sandbox, network и modern recovery остават disabled; optional master
recovery тогава е оставен за отделен Stage 2.47. Няма certification,
official-audit, legal-opinion или native Windows/macOS claim. Commit/tag се
удостоверяват само от външния finalizer output.

## 17. Stage 2.47 optional recovery amendment

Stage 2.47 добавя само доброволно локално възстановяване на профилната парола.
Точните format/storage договори са в
`docs/PROFILE_RECOVERY_PHRASE_CONTRACT_BG.md` и
`docs/RECOVERY_PHRASE_STORAGE_CONTRACT_BG.md`.

Session lifecycle-ът е:

```text
first run -> LOCKED -> explicit login -> UNLOCKED
UNLOCKED -> current-password reauth -> optional setup -> UNLOCKED
UNLOCKED -> manual/panic/inactivity/anomaly lock -> LOCKED
LOCKED -> read-only recovery preview -> explicit publish -> LOCKED
LOCKED -> explicit login with new password -> UNLOCKED
```

Setup прозорецът съдържа видима 25-словна тайна и затова се затваря и изчиства
при manual, panic, inactivity, clock/suspend anomaly или main-window close.
Forgotten-password прозорецът също се затваря при panic/exit и при успешен
нормален login. След recovery publish controller-ът затваря стария session
object, зарежда exact latest Vault и създава нова заключена сесия. Няма
автоматичен login.

Recovery setup capability в registry е `true` единствено при `UNLOCKED`.
Forgotten-password entry е отделен тесен GUI gate: exact `READY` profile плюс
`LOCKED` session. Това разделение не разрешава никоя от останалите unfinished
capabilities.

Потребителският ред е `.mokr` първо, после фраза на отделен filesystem device
или хартия, после exact rehearsal. Преди всяко действие има EN/BG обяснение.
Единственото допълнително yes/no потвърждение е непосредствено преди
неизменяемия publish на ново Vault поколение. Cancel не променя Vault или
парола; вече отчетени durable recovery файлове се запазват.

Password replacement запазва старото Vault поколение и `.mokr`; record-ът
става stale за latest workflow, но не е криптографски revoked. Следователно
старо копие на `.mokr` заедно с неговата фраза остава чувствително. Stage 2.47
не обещава key rotation или обезсилване на вече изнесени recovery комплекти.

Stage 2.47 delta е exact 32 файла: 11 production/harness, три pinned BIP39
vocabulary/license/provenance, десет test и осем contract/status/evidence
документа. Всички Stage 2.46 crypto, Vault, launcher, profile-storage и legacy
ядра остават byte-exact. Authoritative laptop package gates, practical GUI
transition, commit и annotated tag остават отделни до реален PASS output.

## 18. Коригиращ recovery-state gate — 2026-09-15

Самото наличие на READY профил вече не е достатъчно за „Забравена парола…“.
Gate-ът изисква `LOCKED` плюс `CURRENT` lifecycle receipt. `MISSING`,
`INVALID` и `REPLACEMENT_REQUIRED` са пасивни и имат видим статус. След
успешен recovery publish controller-ът refresh-ва latest заключена сесия;
следващите два успешни explicit login-а показват bounded напомняне за нов
комплект. Неуспешен login не изчиства прякора, изчиства паролата и не консумира
напомняне. Setup/recovery/popup прозорците следват общите window controls,
reflow, scroll, remask и localized-action правила.

## 19. Stage 2.48 local V2 session amendment

Stage 2.48 включва `V2_LOCAL_ENCRYPT` и `V2_LOCAL_DECRYPT` само при exact
`UNLOCKED`. `LEGACY_MOK1_DECRYPT` остава отделна capability и отделен GUI
control. Clean originals, Contacts, Contact crypto, Sandbox и Network остават
безусловно изключени.

В една сесия може да съществува точно един local V2 operation lease. Той е
вътрешен за session/service boundary, non-copyable, non-pickleable и не се
връща на GUI. Lease-ът държи bounded encoded keyring copy в mutable buffer,
извежда точно един active Vault slot за encrypt или exact credential за
записаната active/retired key version при decrypt и занулява buffer-а при
close. Липсваща version се отказва без fallback.

Explicit residue cleanup използва отделен keyless lease, но същия sole local-
operation exclusion/cancellation gate. Така cleanup не копира Vault keyring и
не може да се застъпва с encrypt/decrypt.

Manual lock, panic, inactivity, suspend/clock anomaly и close сигнализират
cancellation преди Vault lock/close. Докато старият lease не се освободи,
повторен unlock и втори local operation се отказват. GUI window се скрива при
close с active worker, но session cancellation остава активна и Tk root не се
унищожава преди worker drain.

Local V2, recovery setup и historical MOK1 прозорците не могат да бъдат
отворени едновременно. Manual lock, panic, inactivity/clock lock и main close
затварят MOK1 прозореца и изчистват неговите credential полета; старо
`authorized=True` състояние не остава използваемо след lock.

Тази amendment граница не предава password, keyring или wrapping key на UI,
не добавя network/telemetry и не променя Stage 2.47 recovery lifecycle. Пълният
файлов и residue договор е в
`docs/V2_LOCAL_ENCRYPT_DECRYPT_GUI_CONTRACT_BG.md`.

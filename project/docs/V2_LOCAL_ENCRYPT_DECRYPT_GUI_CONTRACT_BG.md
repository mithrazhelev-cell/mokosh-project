# MOKOSH Stage 2.48 — локално V2 криптиране и декриптиране

Статус: приет договор и изолиран кандидат върху exact Stage 2.47 checkpoint.
Това не е независим одит, release approval или разрешение за работа с
единствени ценни копия.

Дата на договора: 2026-09-18  
Exact baseline commit: `7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8`  
Exact baseline tree: `3c30b84b10cb742ba4d08bc50d50361eaa953f06`  
Baseline annotated tag:
`stage2.47-profile-recovery-phrase-password-replacement`

## 1. Цел и граница

Stage 2.48 свързва завършените MOKOSH2 streaming, filesystem, lifecycle и
Vault primitives с нормалния Linux GUI за точно един локален файл.

В този етап са разрешени само:

- ново локално MOKOSH2 криптиране с активния ключ на отключения профил;
- локално MOKOSH2 декриптиране с точно записаната Vault key version;
- worker progress, explicit cancel и безопасно затваряне;
- read-only преглед и отделно изрично почистване само на exact доказан
  quarantine residue;
- отделен, непроменен исторически MOK1 recovery entry.

Извън обхвата и изключени остават batch/folder операции, „Почисти оригинали“,
password slots, Contacts, signatures, Sandbox, network, telemetry,
Windows/macOS и автоматична MOK1 миграция.

## 2. Ново криптиране

Новият локален файл:

1. е винаги MOKOSH2 с exact magic `MOKOSH2\0`;
2. изисква explicit source и explicit нов output;
3. изисква output име с `.mok2`;
4. съдържа точно един `KEY_VAULT` slot;
5. използва само active Vault wrapping key version на текущата отключена
   профилна сесия;
6. е unsigned local envelope;
7. не съдържа password, Contact или signature slot;
8. не изтрива, премества или променя source файла;
9. никога не презаписва съществуващ output.

GUI предлага случайно generic име от вида
`MOKOSH-encrypted-<8 lowercase hex>.mok2`. Предложението не включва source
име, профилен nickname, път или друг потребителски текст. Оригиналното име,
ако присъства във формата, остава само в authenticated encrypted manifest.

## 3. Декриптиране

Декриптирането разпознава формата по exact magic bytes, не по filename
extension. Изходът е explicit нов файл с generic предложение
`MOKOSH-decrypted-<8 lowercase hex>` и няма автоматично възстановяване на
оригиналното име.

Локалният Stage 2.48 policy приема само unsigned envelope с точно един
`KEY_VAULT` slot. Signed, password, Contact, multi-slot и непознати policy
варианти се отказват без fallback.

Slot-ът избира точно своята записана `vault_key_version`. Active и retained
retired версии могат да декриптират собствените си файлове. Няма пробване на
друга версия, „най-близък“ ключ, password, Contact, MOK1 или произволен Vault.
Липсваща версия, грешен профил и authenticated tamper имат една обща
user-visible authentication грешка. Нито един от тези случаи не публикува
plaintext.

MOK1 остава отделна историческа recovery операция. Файл без MOKOSH2 magic се
отказва като „не е MOKOSH2“ и GUI насочва към отделното MOK1 действие; local
service не импортира и не извиква legacy reader.

## 4. Session-bound key access

GUI никога не получава Vault keyring или wrapping key. `SecureProfileSession`
издава точно един вътрешен, non-copyable и non-pickleable local-operation
lease. Lease-ът:

- се издава само при `UNLOCKED` session и след timeout/clock check;
- не допуска втори едновременен local V2 key owner;
- държи bounded encoded keyring copy в zeroizable `bytearray`;
- създава точно един active Vault slot или връща credential само за exact
  поискана key version;
- проверява cancellation преди key use;
- занулява mutable keyring buffer и освобождава operation ownership при close.

Manual lock, panic, inactivity, suspend/clock anomaly и window/session close
първо сигнализират active cancellation, после заключват/затварят Vault.
Заключена сесия не може да се отключи повторно, докато предишният lease не се
освободи. Това предотвратява застъпване на стар и нов unlocked lifetime.

## 5. Source, output и race защити

Source се отваря като regular file без symlink следване и се обвързва с exact
device/inode/mode/size/timestamp identity. Двупасовото криптиране изисква
същата identity при второто отваряне. Декриптирането обвързва public envelope
inspection с exact source identity, която pipeline-ът проверява повторно преди
private output. Magic probe, public inspection и pipeline са свързани в една
identity верига; подмяна между които и да е две стъпки се отказва. Source open
включва `O_NONBLOCK`, така че regular-to-FIFO race се отказва post-open, без да
блокира worker-а.

Output directory и quarantine objects използват вече установените private
mode, no-symlink, no-clobber, journal, inode и directory-fsync договори.
Съществуващ regular output, symlink или конкурентно появил се final name се
отказва; няма rename-overwrite или „replace“ вариант.

## 6. Cancellation и publication boundary

Операцията има bounded checkpoints около preflight, scan/read, verify,
encrypt/decrypt и преди publication. Cancel или fault преди atomic final
hard-link прекратява операцията, почиства само собствената verified private
quarantine двойка и не създава final output.

Atomic final hard-link е необратимата publication boundary. След успешното му
създаване операцията никога не се връща като retryable failure само защото
по-късно са се провалили:

- post-link identity verification;
- directory synchronization;
- quarantine или journal unlink;
- final cleanup synchronization;
- runtime descriptor/lease close;
- progress observer или късен cancel.

Тези случаи са `success-with-warning`: output вече може да съществува и GUI
изрично казва „Не повтаряйте операцията“. Резултатът съдържа само bounded
flags и stable warning code, без path или exception text. Неуспешно премахнат
residue се запазва за reconciliation.

Преди hard-link всеки fault остава failure и няма published output. Това
разделение е задължително, за да няма двойно криптиране/декриптиране или
погрешно презаписване след успешна публикация.

## 7. Residue review и cleanup

Преди операция output directory се сканира read-only. След придобиване на
единствения session lease scan-ът се повтаря, за да се затвори race между
preflight и key use.

Преди legacy reconciliation scan service-ът брои cancellation-aware най-много
4096 directory entries. По-голяма директория се маркира като incomplete
`BLOCKED`, без пълен list, key use или mutation. Това е fail-closed local
resource bound, не твърдение за hostile процес със същия OS account, който
състезателно променя директорията.

Резултатите са:

- `CLEAR`: complete scan без findings; операцията може да продължи;
- `CLEANABLE`: всеки finding е exact `INODE_MATCH`, има canonical evidence и
  exact operation ID; file operation остава блокирана до отделно решение;
- `BLOCKED`: incomplete scan, omitted finding, link-count conflict,
  post-publication ambiguity или друг non-exact finding; нищо не се трие и
  нова операция в папката се отказва.

Cleanup изисква видим review, explicit `AUTHORIZE_CLEANUP`, exact reviewed
operation ID, fresh rescan, exact evidence digest/sequence, directory/journal/
temporary identity и exclusive lease. Executor-ът може да премахне само exact
temporary и exact bound journal. Source и final output не са допустими цели.
`PRESERVE` не извършва mutation.

Частично cleanup състояние или final-sync uncertainty остава success с
warning и нов review, а не покана за сляп retry.

## 8. GUI и thread contract

Local window е non-modal singleton към главния прозорец. Encrypt и Decrypt
сменят mode на същата жива инстанция; historical MOK1 е отделен control.

- Tk widgets се създават и променят само от main thread.
- Има точно един worker-thread creation site.
- Worker-ът извиква само service и пише immutable progress/result messages в
  `queue.Queue`.
- Main thread чете queue чрез bounded `after` polling.
- Докато worker работи, source/output/run са disabled, cancel е enabled.
- `CLEANABLE`, `BLOCKED` и published-warning резултат заключват run действието
  до нов explicit source или output selection. `PRESERVE` и успешно затваряне
  на warning/decision dialog не отключват повторен run със същото UI
  състояние.
- Close, Escape, lock, panic, timeout и main-window close сигнализират cancel.
- Прозорец с жив worker се скрива и се унищожава едва след worker drain.
- Main root също изчаква local worker drain, вместо да унищожи Tk state под
  работещ thread.
- Local V2, recovery setup и historical MOK1 прозорците са взаимно
  изключващи се чувствителни маршрути. Lock, panic, timeout и close затварят и
  MOK1 прозореца, за да не остане старото еднократно authorization състояние.
- Shared action dialog запазва отделен non-shrinking action row при default и
  narrow geometry. След решение той връща, повдига и фокусира живия parent.
- Scroll canvas и scrollbar не са Tab stops. `PageUp`/`PageDown` остават
  достъпни от видимо фокусиран control в същия прозорец.
- Когато keyboard focus попадне върху descendant извън видимия вертикален
  viewport, shared scroll region го разкрива след idle geometry update с
  минимално необходимо преместване. Не се мести focus, не се реагира на
  несвързан widget и вече видим control не предизвиква scroll.
- Преди enabled action да стане disabled, keyboard focus се премества с
  нормален `focus_set` към видим и enabled логически наследник. Не се използва
  `focus_force` и не се оставя focus върху disabled действие.

В UI няма raw exception, stack trace, key, filename logging, clipboard,
network или telemetry. Видимите резултати са fixed EN/BG текстове по stable
codes.

## 9. Visual contract

Отделният visual harness е synthetic и non-secret. Той не създава профил,
файл, ключ, worker thread или crypto operation. Матрицата е 16 случая:

- EN и BG;
- 100%, 125%, 150% и 200%;
- Encrypt и Decrypt.

Всеки случай позволява видим преглед на ready, working, cleanable, blocked,
published-warning и not-MOKOSH2 states. Human observations проверяват reflow,
scroll, keyboard focus, explicit source/new output, generic имена,
original/no-overwrite текста, cancel, explicit cleanup confirmation,
„do not retry“ warning и отделния MOK1 маршрут. Synthetic visual evidence не
замества real file, race, fault-injection или full regression tests.

Synthetic state selection се показва с отделен persistent текстов индикатор и
sunken state control. Черното keyboard-focus очертание остава само индикация за
текущия Tab focus и не се използва като state marker. Run е disabled в
synthetic `CLEANABLE`, `BLOCKED` и `PUBLISHED`, както е в production policy.
Видимите state labels са explicit и не се извеждат механично от вътрешните
идентификатори; exact label за `not_v2` е `NOT V2`. Всеки synthetic chooser
показва собствено локализирано съобщение, че не отваря dialog и съответно не
чете source или не създава output. Това е видима harness обратна връзка, не
симулация на реален избор на файл.

## 10. Задължителни automated gates

Минимумът включва:

- exact baseline, scope и mode/hash проверка преди mutation;
- clean round-trip и extension-agnostic decrypt;
- exact one active Vault slot и unsigned envelope;
- key rotation: нов active encrypt и old retired decrypt;
- wrong profile/tamper generic authentication failure;
- отказ на non-V2, MOK1 fallback, signed и multi-slot envelope;
- output collision, suffix, symlink/source-replacement и no-original-delete;
- regular-to-FIFO open race, magic-to-inspection identity replacement и
  4096-entry directory bound;
- one-operation lease, lock/panic/timeout/close cancellation;
- residue scan/start race, exact cleanup authorization и ambiguous preserve;
- fault injection преди и след publication boundary;
- GUI one-worker, queue/main-thread, close/drain и fixed-message tests;
- shared-dialog action-row/parent-restore и scroll-chrome Tab-exclusion tests;
- shared-scroll FocusIn auto-reveal: off-screen descendant се разкрива
  минимално, visible descendant не се мести, unrelated widget се игнорира, а
  повторен FocusIn към същия stale target при window reactivation не мести
  ръчно избрания viewport;
- synthetic state action премества keyboard focus върху активирания state
  button преди промяната на displayed state; `Return` и `KP_Enter` го invoke-ват
  точно веднъж и прекъсват последващия class binding, а стандартният `Space`
  route остава наличен;
- production и synthetic focus handoff преди focused action да стане disabled;
- production и synthetic run-lock tests за cleanable, blocked и published;
- exact synthetic state terminology, включително `NOT V2`, и два distinct
  chooser routes с explicit no-I/O feedback;
- EN/BG catalogue parity и security wording;
- main/local integration и visual-contract tests;
- sensitive-window exclusivity и MOK1 close при session lock;
- full project discovery с `failures=0`, `errors=0`,
  `expected failures=0`, `unexpected successes=0`, `skips=0` в pinned runtime;
- unchanged exact repository state for every dry-run verifier.

## 11. Exact frozen corrective scope

Първоначалният 32-path scope е разширен изрично на 2026-09-20 след Case 01
`FAIL_REQUIRES_FIX_AND_RETEST`. Stage 2.48 има право да променя точно следните
34 paths и никой друг:

1. `mokosh_profile_session.py`
2. `mokosh_profile_gui.py`
3. `mokosh_profile_localization.py`
4. `mokosh_v2_filesystem.py`
5. `mokosh_v2_file_pipeline.py`
6. `mokosh_v2_operation_lifecycle.py`
7. `mokosh_profile_main_gui_visual_harness.py`
8. `run_mokosh_profile_main_gui_visual_harness.py`
9. `tests/test_mokosh_profile_session.py`
10. `tests/test_mokosh_profile_gui.py`
11. `tests/test_mokosh_profile_localization.py`
12. `tests/test_mokosh_profile_integration.py`
13. `tests/test_mokosh_v2_filesystem.py`
14. `tests/test_mokosh_v2_file_pipeline.py`
15. `tests/test_mokosh_v2_operation_lifecycle.py`
16. `tests/test_mokosh_profile_main_gui_visual_harness.py`
17. `MOKOSH_V2_FORMAT_SPEC_BG.md`
18. `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`
19. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
20. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
21. `docs/ROADMAP_TO_PUBLIC_V1_BG.md`
22. `PROJECT_STATUS_BG.md`
23. `docs/SESSION_LOG_BG.md`
24. `mokosh_v2_local_service.py` (new)
25. `mokosh_v2_local_gui.py` (new)
26. `mokosh_v2_local_visual_harness.py` (new)
27. `run_mokosh_v2_local_visual_harness.py` (new, executable)
28. `tests/test_mokosh_v2_local_service.py` (new)
29. `tests/test_mokosh_v2_local_gui.py` (new)
30. `tests/test_mokosh_v2_local_integration.py` (new)
31. `tests/test_mokosh_v2_local_visual_harness.py` (new)
32. `docs/V2_LOCAL_ENCRYPT_DECRYPT_GUI_CONTRACT_BG.md` (new)
33. `mokosh_profile_ui.py`
34. `tests/test_mokosh_profile_ui.py`

Всеки target извън списъка, staged change, baseline mismatch, dependency drift,
test non-pass или неочакван residue спира package fail-closed.

### 11.1. Exact D1–D4 corrective overlay freeze — 2026-09-23

Human Cases 2–4 потвърдиха четири допълнителни практически дефекта върху вече
приложения 34-path Stage 2.48 state: D1 — viewport-ът не следва off-screen
keyboard focus; D2 — focused action може да бъде disabled без предварителен
focus handoff; D3 — `not_v2` се визуализира като вътрешното `NOT_V2`; D4 —
synthetic source/output chooser controls са видимо безмълвни. Case 4 записа
12 PASS и 4 FAIL observations. Това е blocking human evidence, не частичен
human PASS.

След dependency, consumer, contract и documentation completeness review е
приет exact overlay от следните 11 paths, всички вътре в frozen 34-path scope:

1. `mokosh_profile_ui.py`
2. `mokosh_v2_local_gui.py`
3. `run_mokosh_v2_local_visual_harness.py`
4. `tests/test_mokosh_profile_ui.py`
5. `tests/test_mokosh_v2_local_gui.py`
6. `tests/test_mokosh_v2_local_visual_harness.py`
7. `docs/V2_LOCAL_ENCRYPT_DECRYPT_GUI_CONTRACT_BG.md`
8. `PROJECT_STATUS_BG.md`
9. `docs/ROADMAP_TO_PUBLIC_V1_BG.md`
10. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
11. `docs/SESSION_LOG_BG.md`

Shared consumers на `ScrollableRegion` се покриват чрез affected regression,
но не изискват собствен byte delta. `mokosh_v2_local_visual_harness.py` остава
непроменен, защото съдържа report/contract model, а не Tk widget construction.
Localization, service, session, filesystem, pipeline, lifecycle, crypto,
Vault, MOKOSH2 format и standards crosswalk също остават byte-exact
непроменени: D1–D4 не променят ключове, policy, persistence, publication
boundary или wire format.

Приемането разрешава само изолирана подготовка и последващ guarded read-only
dry-run. То не разрешава live apply, commit/tag, Stage PASS или пропускане на
пълния pinned-runtime и human replay gate.

### 11.2. Exact D5–D7 corrective overlay freeze — 2026-09-24

След D1–D4 live apply и independent post-apply PASS, продължението на physical
Case 4 откри три нови bounded interaction дефекта. D5: pointer activation на
synthetic state променя displayed state, но оставя keyboard focus върху стария
control. D6: restore/reactivation изпраща повторен `FocusIn` към същия stale
focused widget и shared scroll helper премества viewport-а към него. D7:
state button се активира със `Space`, но не и с `Return` в проверения Tk 8.6/X11
runtime. Това е blocking human evidence; Case 4 и общият visual gate остават
не-PASS.

Приетият D5–D7 overlay е точно девет paths, всички вътре във frozen 34-path
Stage 2.48 scope:

1. `mokosh_profile_ui.py`
2. `run_mokosh_v2_local_visual_harness.py`
3. `tests/test_mokosh_profile_ui.py`
4. `tests/test_mokosh_v2_local_visual_harness.py`
5. `docs/V2_LOCAL_ENCRYPT_DECRYPT_GUI_CONTRACT_BG.md`
6. `PROJECT_STATUS_BG.md`
7. `docs/ROADMAP_TO_PUBLIC_V1_BG.md`
8. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
9. `docs/SESSION_LOG_BG.md`

Корекцията допуска auto-reveal само при действителна смяна на descendant focus
target; повторно активиране на същия target не променя viewport-а. Synthetic
state command първо фокусира собствения си button, после сменя state, а explicit
instance bindings за `Return` и `KP_Enter` извикват button-а точно веднъж и
връщат `break`. `mokosh_v2_local_gui.py`, report model-ът, localization,
service, session, filesystem, pipeline, lifecycle, crypto, Vault и MOKOSH2
format остават byte-exact непроменени.

Isolated evidence за overlay-а е negative-first RED, после `32/32` focused и
`51/51` target PASS. Affected scratch изпълни 245 теста без failure/error и с
един environment-only ML-KEM skip; full scratch изпълни 2454 теста с 0
assertion failures, 3 липсващи-`argon2` import errors и 7 environment skips.
Те остават non-PASS и не заместват pinned user-machine `51/245/2509`
zero-non-pass gate.

R1 transport-ът за този overlay е read-only, няма apply route, съдържа точно
деветте приети paths и има PASS package self-tests плюс byte-identical rebuild.
Тези свойства не разрешават live mutation и не заменят human replay.

Human evidence rule: след всяко resize, maximize, restore, minimize или window
reactivation задължително се оглеждат и горният, и долният край на viewport-а
преди PASS. Проверка само на текущо видимата половина е непълна и не се брои.
Приемането разрешава isolated correction и read-only dry-run preparation, но
не разрешава live apply, commit/tag или Stage PASS.

## 12. Остатъчни ограничения

Този етап не доказва защита на компрометирана машина, secure physical erase,
native Windows/macOS behavior, accessibility conformance, formal verification,
certification или независим security audit. Original-ът нарочно остава.
Потребителят трябва да пази резервно копие и да не използва единствения екземпляр
на ценен файл преди отделно приетите package, practical и release gates.

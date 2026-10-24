# MOKOSH — собствена проверима програма за сигурност

Статус: задължително бъдещо изискване преди публичната beta. Документът описва
собствените тестове на проекта. Той не представлява външен одит, държавна
сертификация или независимо одобрение.

## 1. Цел

MOKOSH трябва да предоставя публично проверими доказателства за качеството и
сигурността на конкретна версия, без да преувеличава значението на собствените
тестове.

Целта е технически подготвен потребител или независим специалист да може:

- да разбере точно какво се проверява;
- да проследи проверката до публична спецификация или стандарт;
- да повтори теста в контролирана среда;
- да сравни очаквания и действителния резултат;
- да провери коя версия, build и платформа са тествани;
- да установи ограниченията и непокритите рискове;
- да провери подписа и целостта на публикувания evidence пакет.

## 2. Задължителна честност на твърденията

Разрешено публично описание:

> MOKOSH е проверен чрез собствена възпроизводима тестова програма, съпоставена
> с посочени публични стандарти. Тестовете, резултатите и ограниченията са
> достъпни за независима проверка.

Забранени са твърдения като:

- „държавно одобрен“;
- „военно сертифициран“;
- „FIPS validated“;
- „независимо одитиран“, когато няма действителен независим одит;
- „неразбиваем“, „напълно сигурен“ или „без уязвимости“;
- „съответства на всички закони и стандарти по света“.

Използването на публична методика не означава одобрение от организацията,
която я е публикувала. Успешните тестове са доказателство за конкретни свойства
при конкретни условия, а не доказателство за липса на неизвестни уязвимости.

## 3. Публични основи

Към момента на реализацията се проверяват актуалната версия, приложимостта и
лицензът на всеки източник. Минималната начална основа включва:

- NIST SP 800-218 Secure Software Development Framework — защитен жизнен цикъл,
  repository, build, release и vulnerability handling;
- NIST SP 800-115 — планиране и провеждане на технически security assessments;
- приложимите NIST FIPS и algorithm specifications, official test vectors и
  публикувани negative tests;
- NIST CMVP/CAVP/ACVP материалите само като технически ориентир, без твърдение
  за официална валидация;
- NCSC Secure Development and Deployment guidance;
- NCSC Software Security Code of Practice;
- CISA Secure by Design guidance;
- официалните спецификации на използваните алгоритми и формати;
- официалните security изисквания на Windows, macOS и Linux, приложими към
  подписване, installer, update, permissions и key storage.

Не се използват непубликувани, секретни, придобити неправомерно или неясно
приписани „военни“ тестове. Публични national-security профили могат да се
използват само за сравнителна gap оценка и никога като основание за твърдение,
че MOKOSH е одобрен за класифицирана информация.

## 4. Четири нива на проверка

### 4.1. Потребителски Integrity & Health Check

Безопасна локална проверка, която не използва истински пароли, private keys,
контакти или потребителски документи. Тя следва
`docs/INTEGRITY_HEALTH_CHECK_BG.md` и показва разбираеми резултати и действия.

### 4.2. Автоматизирана проектна тестова система

Изпълнява се при разработка и за всеки release candidate. Тя включва unit,
integration, negative, property, fuzz, fault-injection, regression,
cross-platform и packaging тестове.

### 4.3. Контролирана Attack Laboratory

Провежда реалистични атаки само срещу наши тестови файлове, машини и изолирани
среди. Преди всяка кампания се създава писмен Rules of Engagement документ с
разрешени цели, техники, срок, ограничения, stop условия и правила за данните.

Никога не се атакуват потребители, чужди системи, публични услуги или мрежи без
изрично писмено разрешение от техния собственик.

### 4.4. Бъдещи независими проверки

Външните проверки са отделени от собствената програма. Собствените резултати
могат да подготвят и намалят обхвата и цената на бъдещ review, но не го заменят.
Правилата са описани в `docs/GUARDIAN_RECOVERY_CAPSULE_BG.md`.

## 5. Задължителни категории тестове

### 5.1. Криптографска коректност

- known-answer и official-vector тестове, когато съществуват;
- encrypt/decrypt, wrap/unwrap и sign/verify round trips;
- wrong-key, wrong-password и wrong-recipient отказ;
- tamper, truncation, reordering, duplication и replay отказ;
- domain separation, nonce uniqueness и counter exhaustion;
- strict parser, canonical encoding и duplicate-field отказ;
- downgrade, algorithm confusion и cross-protocol отказ;
- key-slot isolation и единен DEK contract;
- signature validity отделно от trust към подписващия ключ;
- recovery и key rotation без тихо отслабване на защитата.

### 5.2. Файлова и операционна безопасност

- symlink, hardlink, path traversal и special-file отказ;
- TOCTOU и подмяна на inode;
- output collision и no-clobber поведение;
- atomic publish и unsupported-filesystem отказ;
- прекъсване на ток, процес или операция във всяка критична точка;
- disk-full, permission, read-only и I/O error сценарии;
- quarantine ownership и безопасен abort;
- проверка, че оригиналът не се изтрива преди пълна верификация;
- проверка, че незавършен plaintext не става видим като краен резултат.
- private no-clobber recovery-record export с exact latest durable Vault
  receipt, file/directory `fsync` и exact read-back;
- recovery import с double bounded read, canonical filename, private mode,
  single-link и inode/digest stability;
- partial recovery record след crash се отказва и никога не се overwrite-ва
  или представя като успешен export.

### 5.3. Malformed-input и fuzz проверки

- структурирано mutation fuzzing на preamble, header, slots, frames и trailer;
- произволни, прекалено големи, вложени и неканонични входове;
- memory, CPU, disk и parser resource limits;
- crash, hang и denial-of-service откриване;
- regression corpus за всеки поправен дефект;
- запазване на минималния възпроизвеждащ вход без лични данни.

### 5.4. Supply-chain, build и release

- заключени и проверени зависимости;
- SBOM за конкретния release;
- dependency vulnerability и license проверки;
- static analysis и secret scanning;
- provenance на source, build и package;
- възпроизводим build, когато е практически възможно;
- подписан release manifest и проверка на всеки компонент;
- защита срещу mix-and-match на модули;
- тест от чиста build среда;
- проверка на installer/uninstaller без достъп до потребителски ключове.

### 5.5. Update, Guardian и Recovery Capsule

- подпис, версия, manifest и component hash проверки;
- rollback, freeze, replay и mirror substitution атаки;
- compromised update server без компрометиране на offline signing key;
- неизвестен, оттеглен или изтекъл signing key;
- прекъснато и частично обновяване;
- възстановяване само към допустима подписана версия;
- забрана за mix-and-match и забранена уязвима версия;
- потвърждение от потребителя преди промяна на код;
- fail-closed режим при невалидно възстановяване;
- външна read-only проверка при съмнение за компрометиран Guardian или OS.

### 5.6. Key Vault, recovery и hardware option

- грешна парола и resource-policy отказ преди скъп KDF;
- повреден, стар или смесен Vault формат;
- wrong recovery root, authenticated tamper и malformed recovery payload;
- stale, rollback, same-revision conflict, mixed-vault и duplicate recovery
  record/ID отказ;
- bounded candidate set без смесване на Vault ID, revision или source hash;
- recovery rehearsal без връщане на keyring secrets и без промяна на Vault
  поколения или истински данни;
- recovery export записва само encrypted record; recovery key няма path/file
  API и не се записва автоматично върху същия носител;
- latest durable receipt, clean complete scan, private `0700` directory,
  `0600` file, no-clobber и uncertain fault semantics;
- explicit in-memory recovery candidate със същия Vault ID, exact next
  revision, preserved schema-2 keyring и fresh salt/nonce;
- new-password authenticated candidate verification без old-password fallback
  и без keyring secret в public evidence;
- one-shot process-local authorization, обвързано със source/record/keyring/
  candidate digests, KDF policy и recovery file identity;
- double source verification около candidate creation и fault отказ без Vault
  publish, recovery-file mutation или user-file mutation;
- separate exact enum recovery-publish decision и executor-owned one-shot
  Stage 2.6 claim;
- fresh double Vault/recovery verification, new-password candidate unlock и
  frozen Stage 2.2 policy compatibility преди mutation;
- immutable no-clobber `R+1` publish с exact receipt/readback, preserved `R`,
  preserved `.mokr` и clean history `old + R+1`;
- pre-link failure без success и post-link/post-verification fault като
  uncertain без rollback, unlink или automatic cleanup;
- доказателство, че старият recovery record остава byte-exact, но е stale
  спрямо новото latest поколение и не се обновява автоматично;
- strict read-only reconciliation на uncertain recovery publish с explicit old
  source receipt, exact target revision, recovery record/root и new password;
- stable double classification на target absent, exact durable target или
  conflict без blind retry, rollback, cleanup или target deletion;
- exact target unlock/keyring verification и conflict при wrong password,
  temporary residue, invalid/extra generation, incomplete или changed scan;
- non-secret reconciliation result с bounded counts, ясна action препоръка и
  изрично `mutation_authorized = false`;
- strict Stage 2.9 validation на reviewed reconciliation classification/action,
  receipts, revisions, digests, counts и no-mutation flags;
- domain-separated fixed transcript digest за exact process-local result
  binding и mismatch отказ без твърдение за digital signature;
- one-shot explicit workflow review с exact enum decision, wrong-route отказ и
  replay отказ;
- absent route само към нов Stage 2.6 decision, exact route само към normal
  unlock и отделен Stage 2.5 setup decision, conflict като terminal stop;
- доказателство, че workflow gate не е candidate/unlock/setup/publish/retry/
  cleanup authorization и че всички mutation authority flags са false;
- workflow state без password, recovery root, keyring, candidate, session,
  path или filename и без filesystem/executor/network/GUI imports;
- strict Stage 2.10 revalidation на exact Stage 2.9 state, route, ordered gates
  и всички no-authority flags;
- fixed bounded localization message keys, visible gate keys и ordered
  confirmation requirements без raw text или template arguments;
- domain-separated workflow-state digest, който обвързва evidence, decision,
  route, gates и flags без твърдение за signature или persisted token;
- absent/exact/conflict/preserve presentation mapping с ясни terminal и
  downstream-reverification semantics;
- доказателство, че every presentation показва no operation performed/no
  operation authorized и не съдържа callback, executor или mutation API;
- presentation output без Recovery/Vault IDs, receipts, revisions, source/
  target digests, password, root, keyring, path или exception text;
- strict Stage 2.11 revalidation и canonical binding на exact Stage 2.10
  presentation без raw text, callback, executor или operation input;
- one-shot acknowledgement само на complete exact ordered fixed-enum
  confirmation tuple с отказ на skip, partial, reorder, duplicate, extra,
  string, list и cross-route keys;
- failed acknowledgement без consumption, replay отказ след success и
  concurrent attempts с точно един success;
- bounded acknowledgement receipt без original presentation/state/evidence,
  Recovery/Vault IDs, revisions, source/target digests, secrets или paths;
- доказателство, че acknowledgement не invoke-ва gate, не извършва automatic
  transition и не дава candidate/unlock/setup/publish/retry/repair/cleanup
  authorization;
- strict Stage 2.12 revalidation на exact presentation, Stage 2.11 digest,
  route, ordered messages/gates/confirmations и no-authority flags;
- stable ordered fixed-key message items с exact gate markers, visibility и
  accessible-label-key binding;
- visible required individually-selectable confirmation controls с exact
  ordinals, fixed order, accessible-label-key binding и default false;
- отказ на hidden, unselected, non-user-initiated, wrong-ordinal,
  partial, reordered, duplicate, extra, mapping, string и cross-route events;
- failed UI input без consumption, replay/concurrency с exactly one success и
  exact delegation само към private Stage 2.11 acknowledgement;
- bounded UI adapter receipt без view, presentation, events, secrets, IDs,
  paths, callbacks, executor или operation capability;
- static доказателство, че Stage 2.12 няма GUI toolkit,
  localization rendering, filesystem, executor, mutation, network, logging,
  clock или randomness;
- exact Stage 2.13 locale allowlist `bg-BG`/`en-GB` без normalization,
  partial result или silent fallback;
- complete one-to-one immutable catalogs за всички 24 message и 9
  confirmation keys с exact order и locale isolation;
- отказ на missing, extra, duplicate, reordered, mixed-locale, altered и
  unsafe translation entries;
- bounded NFC text и отказ на control/format/bidi-override/template
  characters;
- domain-separated catalog digest за exact locale/key/text transcript без
  твърдение за signature или independent provenance;
- deterministic localization на exact validated Stage 2.12 view със stable
  ordinals, gates, visible/accessible text и default-false confirmations;
- доказателство, че localization не acknowledge-ва adapter lifecycle, не
  създава operation control и не запазва secrets;
- exact Stage 2.14 preparation само от matching Stage 2.10 presentation,
  fresh Stage 2.12 adapter и exact Stage 2.13 locale/view;
- реален child `tk.Toplevel` без втори `Tk` или втори `mainloop` и без промяна
  на основния MOKOSH GUI;
- ordered scrollable messages и gate warnings преди confirmation controls;
- всички checkboxes false/disabled преди visible-message report, отделни и
  без select-all, pre-check или remembered state;
- final acknowledgement disabled до exact all-true selections и повторно
  disabled след uncheck;
- cancel button, Escape и window close без Stage 2.12 acknowledgement;
- success само чрез exact ordered visible/user-selected/user-initiated Stage
  2.12 events и bounded no-authority receipt;
- one-shot/replay/concurrent terminal tests и отказ на wrong source, locale,
  ordinal, key, selection type, partial/reordered visibility и forged outcome;
- outcome без localized view, raw events, password, root, keyring, path,
  callback, executor или operation capability;
- static widget wiring за wrap, scroll, focus, keyboard и local grab, както и
  липса на filesystem/network/logging/dynamic execution;
- отделно отбелязване, че headless/static evidence не заменя реални Linux,
  Windows, macOS, screen-reader, DPI, contrast и keyboard-only tests;
- exact Stage 2.15 synthetic fixture matrix за `absent`, `exact`, `conflict`
  и `preserve` в `bg-BG` и `en-GB`, без истински Vault/recovery input;
- fixed scale allowlist `100`/`125`/`150`/`200` и bounded `520x420`/
  `800x640` window profiles;
- реално отваряне на Stage 2.14 `Toplevel` чрез отделен test launcher, без
  import или activation на `mokosh_gui.py`;
- fixed manual observation enums за scroll reachability, wrap, focus order и
  keyboard-only действие, без arbitrary notes;
- fixed Linux validation matrix с exact Escape, Cancel, window-manager close
  и acknowledgement expectations; mismatch, fail или not-checked блокира
  installer commit/tag gate;
- canonical bounded Stage 2.15 JSON report без password, recovery root,
  keyring, Vault path, filename, callback, executor или operation capability;
- forged case binding, locale/digest mismatch, false authority, mutation,
  network, secret и platform-certification claims се отказват fail-closed;
- отделен Windows/macOS checklist и explicit забрана Linux/headless резултат
  да се представя като cross-platform certification;
- static доказателство за липса на filesystem/environment locale, GUI,
  network, mutation, logging, clock, randomness и dynamic execution;
- exact Stage 2.16 application-service preparation само от strict Stage 2.9
  workflow state и exact `bg-BG`/`en-GB` locale;
- фиксирана композиция през Stage 2.10 presentation, fresh Stage 2.12 adapter,
  Stage 2.13 localization и Stage 2.14 preparation/display без alternate path;
- one-shot controller lifecycle `prepared`/`displaying`/`completed`/`failed`,
  който маркира display преди call и допуска точно един concurrent опит;
- success, cancel, display fault, forged outcome и KeyboardInterrupt консумират
  session-а без blind retry; нов опит изисква fresh full preparation;
- exact returned outcome type, locale и constant-time presentation-digest
  binding с повторна Stage 2.14 dataclass/receipt validation;
- wrong locale/digest, subclass, mapping, non-outcome и false authority се
  отказват fail-closed и не връщат partial result;
- controller session не задържа original Stage 2.9 state и след terminal
  result/failure премахва internal presentation/adapter references;
- copy, deepcopy и pickle отказ за process-local prepared session;
- единствен public prepare API без password, recovery root, keyring, path,
  callback, executor, operation, retry, repair или cleanup параметър;
- static доказателство за липса на filesystem, network, process, logging,
  dynamic execution, mutator/executor и `mokosh_gui.py` import/call;
- exact доказателство, че `mokosh_gui.py` остава непроменен, `SAFETY_MODE=True`
  и Stage 2.16 не активира main-GUI recovery feature;
- изрично доказателство, че path/device ID не доказва физически отделен offline
  носител и unsupported filesystem се отказва без silent downgrade;
- separation между licensing, telemetry и cryptographic secrets;
- бъдещият optional hardware token има отделен threat model и никога не е
  задължителен за стандартния режим.

### 5.7. Privacy и диагностични доклади

- липса на тайна телеметрия и скрит network access;
- offline работоспособност;
- журнал без пароли, ключове, recovery, plaintext, контакти и чувствителни
  абсолютни пътища;
- preview и изрично съгласие преди изпращане;
- проверка на exact allowlist за разрешени diagnostic fields;
- тестове, че support или license проблем не блокира декриптиране, recovery и
  безопасен export.

### 5.8. Cross-platform и потребителска безопасност

- отделна матрица за поддържаните Windows, macOS и Linux версии;
- filesystem, permissions, Unicode names, long paths и locale поведение;
- installer, update, uninstall и clean reinstall;
- sleep, suspend, restart, multiple-instance и cancellation сценарии;
- големи шрифтове, клавиатура, screen scaling и всички поддържани езици;
- дълги преводи, малки екрани и scrolling;
- ясни предупреждения и липса на подвеждащо „Успешно“ преди верификация.

## 6. Задължителен запис за всеки тест

Всеки тест има постоянен идентификатор и машинночетим запис със следните
полета:

- `test_id` и версия на теста;
- заглавие и проверявана заплаха;
- source standard, точна публикация, версия и приложим раздел;
- обяснение как изискването е интерпретирано за MOKOSH;
- preconditions и изолирана тестова среда;
- входни данни или генератор без реални потребителски тайни;
- точни стъпки или автоматична команда;
- очакван резултат и fail-closed критерий;
- действителен резултат и pass/fail/blocked статус;
- MOKOSH version, Git commit, source hash и build identifier;
- OS, architecture и поддържана platform версия;
- версии и hashes на използваните инструменти и зависимости;
- начало, край и продължителност;
- получени безопасни artifacts;
- ограничения, непокрити случаи и reviewer notes;
- връзка към defect и regression test при неуспех.

Ръчно променен резултат се счита за нов artifact и губи първоначалния подпис.

## 7. Release Evidence Bundle

За всеки release candidate се създава неизменяем пакет с приблизителна
структура:

```text
security/
├── README_BG.md
├── CLAIMS_AND_LIMITATIONS_BG.md
├── standards-mapping/
├── threat-models/
├── test-plans/
├── automated-tests/
├── cryptographic-vectors/
├── fuzz-corpus/
├── fault-injection/
├── attack-lab/
├── platform-matrix/
├── sbom/
├── build-provenance/
├── update-recovery/
├── results/
└── independent-reviews/
```

Папката `independent-reviews/` остава празна или съдържа ясно означено
`NOT_AUDITED.md`, докато няма действителен независим review. Собствени проверки
не се поставят в тази папка.

Пакетът съдържа:

- machine-readable manifest;
- SHA-256 на всеки artifact;
- подпис на manifest-а с отделен release-evidence signing key;
- public verification key и инструкции за независима проверка;
- human-readable summary;
- сурови резултати, когато публикуването им не създава нов риск;
- списък на пропуснати, блокирани и неуспешни тестове;
- ясни ограничения и exact version scope.

## 8. Възпроизводимост

Тестовият пакет трябва да може да се изпълни от чиста среда без достъп до
истински MOKOSH ключове или лични runtime файлове.

Задължителни са:

- документирани prerequisite версии;
- заключени dependency версии и hashes;
- deterministic fixtures, освен когато тестът проверява randomness;
- записан random seed за възпроизвеждане на неуспех;
- отделни public test keys, които никога не се използват за release signing;
- one-command runner или ясно еквивалентно platform-specific изпълнение;
- no-network режим за основните тестове;
- проверка, че тестовете не четат домашни папки и истински Vault данни;
- clean-environment повторение на публикувания резултат.

## 9. Управление на неуспехи

Неуспешен задължителен security тест блокира release-а. Той не се премахва,
преименува или маркира като expected failure без:

- документирана причина;
- риск оценка;
- изрично решение;
- временно ограничение и срок;
- regression test;
- повторно изпълнение след поправка.

`skip`, `xfail`, timeout, crash и непълен резултат се показват отделно и не се
броят като pass. Expected failure е допустим само за ясно изолиран legacy
компонент, който не участва в публичния защитен режим.

## 10. Attack Laboratory правила

Всеки adversarial сценарий има:

- собственик на тестовата система и изрично разрешение;
- точен scope и забранени цели;
- snapshot или recoverable backup;
- изолирана мрежа и synthetic data;
- прекъсвач и stop conditions;
- безопасно събиране на доказателства;
- проверка за остатъчни credentials и artifacts;
- отчет за експлоатираното условие и реалното въздействие;
- responsible-disclosure план, ако проблемът засяга външна зависимост.

„Реална атака“ означава контролирано възпроизвеждане на attacker поведение, а
не атака срещу реален потребител или чужда инфраструктура.

## 11. Потребителска секция „Състояние и сигурност“

Бъдещият интерфейс показва поне:

- release signature и integrity status;
- дата и версия на последната успешна проверка;
- бърза, пълна и offline проверка;
- точния засегнат компонент при проблем;
- кои функции са блокирани;
- безопасни следващи действия;
- проверка на Recovery Capsule по желание;
- export на минимален локален report;
- preview и изрично съгласие преди изпращане към MOKOSH Support;
- връзка към публичния evidence bundle за същата версия.

Интерфейсът не използва процент „сигурност“ и не показва зелен статус, ако
задължителна проверка е skipped, blocked, incomplete или stale.

## 12. Release gates

Публичен release не се подписва, ако липсва някое от следните:

- актуален threat model;
- чист build от контролирана среда;
- SBOM и dependency review;
- всички задължителни automated и negative тестове;
- platform matrix за заявените поддържани системи;
- installer/update/recovery проверка;
- Guardian и Integrity & Health Check резултати;
- подписан evidence bundle;
- claims-and-limitations документ;
- процедура за vulnerability reporting и безопасно обновяване.

Отделно решение определя кои gates важат за private development, alpha, beta,
stable и high-risk institutional release. Ниво без изпълнени изисквания не се
представя като по-високо.

## 13. Публичност и чувствителни подробности

По подразбиране тестовете, mapping-ите, безопасните fixtures и резултатите са
публични. Временно се задържат само подробности, които непосредствено биха
улеснили експлоатация на непоправена уязвимост, издаване на release private key
или разкриване на чужда поверителна информация.

След поправка се публикуват достатъчно технически данни за проверка на дефекта
и regression теста. Никога не се публикуват истински private keys, пароли,
recovery фрази, потребителски документи или контакти.

## 14. Изисквания преди реализация

Преди този модул да бъде активиран трябва да се подготвят и прегледат:

1. отделен threat model за evidence системата;
2. trust model и key hierarchy за release и evidence подписите;
3. lifecycle за издаване, rotation, revocation и offline backup на signing keys;
4. machine-readable test-result schema;
5. standard mapping registry с version pinning;
6. release-gate policy за alpha, beta и stable;
7. безопасна Attack Laboratory среда и Rules of Engagement template;
8. platform support matrix;
9. privacy review на diagnostic artifacts;
10. процедура за коригиране или оттегляне на погрешен evidence пакет;
11. security review на самия test runner, Guardian и verifier;
12. тест, че компрометиран основен MOKOSH процес не може сам да фалшифицира
    валиден външно подписан release evidence.

## 15. Критерий за завършеност

Изискването е изпълнено само когато технически подготвен човек на чиста машина
може да:

1. изтегли точния release и неговия evidence bundle;
2. провери подписите и hashes независимо от основното приложение;
3. изпълни публикувания задължителен тестов профил;
4. получи същите резултати или ясно обяснена platform разлика;
5. види всички fail, skip, blocked и ограничения;
6. потвърди, че докладът се отнася точно за тествания release;
7. установи, че няма твърдение за сертификат или независим одит, който не е
   действително получен.

Тази собствена програма е проверимо техническо доказателство за извършените
тестове. Тя не премахва необходимостта от поправки, responsible disclosure,
периодичен независим преглед и честно описание на остатъчния риск.

## 16. Официални начални източници

- NIST SP 800-218 SSDF: <https://csrc.nist.gov/pubs/sp/800/218/final>
- NIST SP 800-115: <https://csrc.nist.gov/pubs/sp/800/115/final>
- NIST CMVP: <https://csrc.nist.gov/projects/cryptographic-module-validation-program>
- NCSC Developers Collection: <https://www.ncsc.gov.uk/collection/developers-collection>
- NCSC Software Security Code of Practice guidance:
  <https://www.ncsc.gov.uk/collection/software-security-code-of-practice-implementation-guidance>
- CISA Secure by Design: <https://www.cisa.gov/securebydesign>

Точните версии и дати на всички външни източници се замразяват в evidence
manifest-а на съответния release, за да не се променя незабелязано основата на
теста.

## 17. Stage 2.17 bounded evidence

Stage 2.17 добавя 21 автоматизирани теста за inactive main-GUI recovery review
bridge. Те покриват exact Stage 2.16 session/locale binding, четирите route-а и
двата locale-а, nonfresh/mismatch отказ, acknowledged/cancelled outcomes,
forged/non-outcome отказ, replay, concurrency, interrupt, source clearing,
copy/serialization отказ и static trust boundary.

Main-GUI AST проверките доказват само за exact тестваната версия, че:

- `SAFETY_MODE=True`;
- `mokosh_gui.py` импортира bounded Stage 2.17 bridge, но не recovery source,
  workflow, reconciliation или executor;
- normal `main()` не извиква handoff seam-а;
- няма нов widget или visible layout промяна в този stage.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1203
теста, expected failures=3 само за legacy MOK1 и skipped=0. Всеки друг fail,
error, skip, count mismatch, main-GUI safety mismatch или staged-file mismatch
блокира commit/tag и възстановява exact Stage 2.17 файлове.

Това е собствено възпроизводимо engineering evidence. То не е независим одит,
platform certification, usability result, legal conclusion или доказателство за
recovery success. Бъдещо visible widget/event wiring изисква отделен Linux
visual review и platform observations за всяка заявена операционна система.

## 18. Stage 2.18 conditional main-GUI widget evidence

Stage 2.18 добавя 25 автоматизирани теста за conditional inspection-only
main-GUI recovery review widget/event. Те покриват exact fresh binding,
localized banner/button, disable-before-display, binding clearing,
acknowledged/cancelled outcome, generic failure, replay, concurrency,
interrupt, четири synthetic route-а, два locale-а, mismatch, false authority
claims, bounded JSON и static trust boundaries.

Main-GUI AST и byte checks доказват само за exact тестваната версия, че:

- `SAFETY_MODE=True`;
- normal module entrypoint извиква `main()` без binding;
- runtime main GUI не импортира recovery source, workflow, reconciliation,
  candidate, publish или storage модул;
- conditional session изключва unrelated input/action controls;
- `run_mokosh_gui.sh`, `crypto_core.py` и `requirements-runtime.txt` са
  byte-exact спрямо base `523af76`.

Synthetic harness core-ът няма filesystem, network, process, GUI, dynamic
import или logging API. Той създава fixed non-secret Stage 2.9 states и
подготвя exact Stage 2.16/2.17 chain само in-memory. Bounded report-ът отказва
forged normal-startup activation, true Vault input, operation authority,
mutation, network или certification claim.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1228
теста, expected failures=3 само за legacy MOK1 и skipped=0. След automated
pass той изисква реален Linux synthetic main-GUI review с `pass` за visible
banner/button, disabled unrelated controls, review opened in front и one-shot
button disabled след terminal review.

Тези резултати са собствено възпроизводимо engineering evidence. Human
observation-ът е валиден само за exact проверената Linux среда. Той не е
Windows/macOS evidence, accessibility/usability audit, independent security
audit, legal conclusion, recovery success или platform certification.

## 19. Stage 2.19 recovery entry request evidence

Stage 2.19 добавя 17 автоматизирани теста за inactive locale-bound one-shot
recovery entry request. Те покриват exact `bg-BG`/`en-GB`, двете exact enum
решения, invalid input без consumption, replay, concurrency, copy/serialization
отказ, bounded schema, forged authority/source/operation flags и static trust
boundary.

Static и byte checks доказват само за exact тестваната версия, че:

- request API приема единствено locale, а decision API — единствено exact enum;
- модулът няма filesystem, GUI, recovery source/workflow/controller/bridge,
  network, process, logging или dynamic-execution import/call;
- outcome няма secrets, source identifiers, paths, session, binding, callback
  или executor;
- всички source, preparation, display, operation, filesystem, network и
  automatic-transition claims са false;
- `mokosh_gui.py`, launcher, `crypto_core.py` и requirements са byte-exact
  спрямо base `3651c39`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1245
теста, expected failures=3 само за legacy MOK1 и skipped=0. Няма visual gate,
защото Stage 2.19 не променя GUI. Всеки fail, error, skip, count mismatch,
critical-file mismatch или staged-path mismatch блокира commit/tag и
възстановява exact baseline.

Тези резултати са собствено възпроизводимо engineering evidence. Request
outcome не доказва потребителска identity/comprehension, recovery success,
source authenticity, platform certification, independent audit или legal
compliance и не разрешава бъдеща операция.

## 20. Stage 2.20 normal-startup recovery entry widget evidence

Stage 2.20 добавя 23 автоматизирани теста за видим normal-startup one-shot
entry event към exact Stage 2.19 request contract. Те покриват двата locale-а,
Yes/No enum mapping, disable-before-prepare, replay, concurrency, missing или
destroyed widget, generic failure без exception text, interrupt propagation,
language update, separation от Stage 2.18 conditional review mode, bounded
visual report и static trust boundary.

Static, runtime-mock и byte checks доказват само за exact тестваната версия,
че:

- normal startup създава entry widget, но не създава request преди user event;
- event-ът извиква само Stage 2.19 preparation и exact one-shot decision;
- main GUI не импортира recovery source, storage, reconciliation, workflow,
  candidate или publish модул;
- conditional Stage 2.18 prepared-review session не показва normal entry;
- `SAFETY_MODE=True`;
- Stage 2.19 request module, launcher, `crypto_core.py` и runtime requirements
  са byte-exact спрямо base `10eb789`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1268
теста, expected failures=3 само за legacy MOK1 и skipped=0. След automated
pass той изисква два real normal-main-GUI Linux visual gates — `bg-BG` и
`en-GB` — с pass за visibility, confirmation boundary, bounded request result,
липса на source/review UI и one-shot disabled state.

Human observation потвърждава само видимото в exact Linux конфигурацията.
Техническата no-source/no-operation граница се проверява от code review,
negative/static тестовете и неизменните Stage 2.19 outcome flags. Нито едното
не е Windows/macOS evidence, usability/accessibility audit, independent
security audit, recovery success, legal conclusion или platform certification.

## 21. Stage 2.21 recovery entry transition evidence

Stage 2.21 добавя 21 автоматизирани теста за inactive one-shot non-secret
transition върху exact Stage 2.19 request outcome. Те покриват двата locale-а,
requested/preserve routes, exact proceed/preserve enum mapping, preserve-route
refusal без consumption, strict повторна Stage 2.19 validation, replay,
concurrency, copy/serialization отказ, bounded schema, forged authority/source/
operation flags и static trust boundary.

Static и byte checks доказват само за exact тестваната версия, че:

- public prepare API приема само exact Stage 2.19 outcome, а decision API —
  само exact Stage 2.21 enum;
- prepared transition не задържа original outcome и пази само locale, entry
  decision, lifecycle state, bounded outcome и process-local lock;
- модулът не импортира директно filesystem, GUI, storage, reconciliation,
  workflow, controller, bridge, candidate, publish, network, process, logging
  или dynamic-execution capability;
- outcome няма secrets, source identifiers, paths, storage, session, binding,
  callback или executor;
- всички source, preparation, display, operation, filesystem, network и
  automatic-transition claims са false;
- `mokosh_gui.py`, launcher, `crypto_core.py`, requirements и Stage 2.19
  request module са byte-exact спрямо base `51f26d3`;
- `SAFETY_MODE=True`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1289
теста, expected failures=3 само за legacy MOK1 и skipped=0. Няма visual gate,
защото Stage 2.21 не променя GUI. Всеки fail, error, skip, count mismatch,
critical-file mismatch или staged-path mismatch блокира commit/tag и
възстановява exact baseline.

Това е собствено възпроизводимо engineering evidence. Proceed outcome-ът е
само искане за бъдещ отделен source-selection boundary. Той не разрешава и не
извършва source access, filesystem read, reconciliation, review preparation
или recovery operation и не доказва identity/comprehension, source
authenticity, platform certification, independent audit или legal compliance.

## 22. Stage 2.22 recovery locale leaf evidence

Stage 2.22 добавя 18 автоматизирани теста за dependency isolation на exact
recovery locale identity. Те покриват exact двата enum members, values, order,
aliases, public export, shared type identity, Stage 2.19/2.21 behavior,
serialization identity, fresh-process import closure, blocked privileged
dependencies, AST boundary, catalog cardinality и critical-file hashes.

Fresh-process probes доказват за exact тестваната версия, че:

- leaf import зарежда само `mokosh_vault_recovery_locale`;
- Stage 2.19 import зарежда само request + leaf;
- Stage 2.21 import зарежда само transition + request + leaf;
- entry contract-ите import-ват без `cryptography`, `argon2`, `tkinter`, Vault
  storage, recovery storage, reconciliation, workflow, controller или bridge;
- Stage 2.13 re-export-ва същия enum object и запазва exact catalog cardinality;
- `mokosh_gui.py`, launcher, `crypto_core.py` и requirements са byte-exact;
- `SAFETY_MODE=True`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1307
теста, expected failures=3 само за legacy MOK1 и skipped=0. Няма visual gate,
защото Stage 2.22 не променя GUI. Всеки fail, error, skip, count mismatch,
critical-file mismatch или staged-path mismatch блокира commit/tag и
възстановява exact baseline.

Това evidence доказва import/dependency boundary, не cryptographic validation,
recovery success, source authenticity, platform certification, independent
audit или legal compliance. Stage 2.22 не избира source и не предоставя
operation authority.

## 23. Stage 2.23 normal-main-GUI recovery import isolation evidence

Stage 2.23 добавя 19 автоматизирани теста за normal-main-GUI import isolation.
Те покриват fresh-process exact MOKOSH module closure, bridge absence при normal
import, blocked privileged recovery dependencies, exact conditional type load,
module-level/`TYPE_CHECKING`/private-helper AST boundaries, no dynamic import,
default main guard, helper reachability, non-`None` guard, seam signature,
byte-exact text registries, `SAFETY_MODE`, no-source imports и critical hashes.

Fresh-process probes доказват за exact тестваната версия, че:

- normal `import mokosh_gui` зарежда само GUI, paths, Stage 2.19 request и
  Stage 2.22 locale leaf от MOKOSH module family;
- Stage 2.17 bridge и неговите controller/window/storage/workflow dependencies
  не са в `sys.modules` след normal import;
- normal import минава при explicit blocked privileged recovery modules;
- private conditional helper import-ва само exact Stage 2.17 binding/state/error
  types и запазва identity;
- existing conditional review и normal entry regression tests остават PASS;
- normal/conditional text registries са exact и `SAFETY_MODE=True`;
- launcher, crypto core, requirements, bridge/controller и entry contracts са
  byte-exact спрямо base `83aefb8`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1326
теста, expected failures=3 само за legacy MOK1 и skipped=0. Няма нов visual
gate, защото Stage 2.23 не променя widget text, layout, geometry или event
semantics. Това е bounded import evidence, не visual/platform certification.

Всеки fail, error, skip, count mismatch, critical-file mismatch или staged-path
mismatch блокира commit/tag и възстановява exact baseline. Stage 2.23 не
избира source, не подготвя session и не предоставя operation authority.

## 24. Stage 2.24 explicit runtime path initialization evidence

Stage 2.24 добавя 18 автоматизирани теста за import/startup filesystem
границата. Те покриват absent и existing runtime directory, direct paths и
normal GUI imports, explicit mkdir/chmod, binding/preparation/Tk ordering,
preparation failure, exact call reachability, stdlib-only paths imports,
byte-exact GUI texts, `SAFETY_MODE`, no-source imports и critical hashes.

Fresh-process probes доказват за exact тестваната версия, че:

- direct `import mokosh_paths` не създава absent `MOKOSH_DATA_DIR`;
- normal `import mokosh_gui` не създава absent runtime directory;
- normal import не chmod-ва existing runtime directory;
- explicit `ensure_private_data_dir()` създава absent directory с private
  mode и затяга existing directory до private mode в exact POSIX test lane;
- `main()` извиква preparation преди `tk.Tk()`;
- preparation failure не създава Tk root;
- invalid conditional binding се отказва преди filesystem preparation;
- GUI text registries, Stage 2.18/2.20 event behavior и `SAFETY_MODE=True`
  остават exact;
- launcher, crypto core, seed/contact modules, recovery contracts и runtime
  requirements са byte-exact спрямо base `5a4d30b`.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1344
теста, expected failures=3 само за legacy MOK1 и skipped=0. Няма нов visual
gate, защото Stage 2.24 не променя widget text, layout, geometry или event
semantics.

Всеки fail, error, skip, count mismatch, critical-file mismatch или staged-path
mismatch блокира commit/tag и възстановява exact baseline. Evidence-ът доказва
само explicit import/startup side-effect boundary. Той не одобрява legacy
seed/contact storage, не избира recovery source, не предоставя operation
authority и не е filesystem/platform certification, independent audit или
legal compliance.

## 25. Stage 2.25 main-GUI recovery entry transition evidence

Stage 2.25 добавя 31 автоматизирани теста за отделното visible Stage 2.21
transition действие. Те покриват exact локализирани locked controls,
positive-request arming, preserve-route refusal, липса на Stage 2.21
preparation преди второ натискане, Yes/No mapping, disable/clear ordering,
forged-source revalidation, replay, concurrency, widget faults, generic error,
process-level interruption, normal/conditional construction, language switch,
bounded visual evidence, static no-source boundary и critical hashes.

За exact тестваната версия evidence-ът изисква:

- Stage 2.25 button да започва disabled;
- Stage 2.19 `REQUEST_RECOVERY_REVIEW` само да го arm-ва;
- Stage 2.19 `PRESERVE_AND_STOP` да го оставя locked;
- `prepare_recovery_entry_transition()` да не се извиква преди отделното
  второ user action;
- second action да изчиства bounded Stage 2.19 outcome и да disable-ва button
  преди Stage 2.21 preparation;
- forged Stage 2.19 safety flag да бъде отказан от exact Stage 2.21
  revalidation;
- concurrent attempts да допускат точно един transition outcome;
- всеки Stage 2.21 outcome да има false source/operation/filesystem/network/
  automatic flags;
- Stage 2.25 visual report version 2 да отчита existing runtime-directory
  preparation като true и само recovery-source filesystem access/mutation
  като false;
- conditional Stage 2.18 review да не показва Stage 2.20/2.25 entry controls;
- normal GUI import да добавя само pure Stage 2.21 transition към Stage 2.19
  request/Stage 2.22 locale closure, без privileged recovery dependencies;
- `SAFETY_MODE=True`, launcher, runtime requirements, crypto, paths,
  seed/contact и Stage 2.19/2.21 core modules да остават exact.

Пълният installer gate изисква exact runtime `~/venv_sys/bin/python3`, 1375
теста, expected failures=3 само за legacy MOK1 и skipped=0. Поне `bg-BG` и
`en-GB` positive-transition visible observations трябва да са PASS на Linux.

Всеки fail, error, skip, count mismatch, visual failure, critical-file
mismatch или staged-path mismatch блокира commit/tag и възстановява exact
baseline. Evidence-ът доказва само bounded explicit mediation. Не доказва
recovery success, source authenticity, comprehension, accessibility,
cross-platform certification, independent audit или legal compliance.

## 26. Stage 2.26 main-GUI visual filesystem claim evidence

Fresh review след Stage 2.25 установи, че Stage 2.18, 2.20 и 2.25
normal-main-GUI visual reports използват generic
`filesystem_mutation_performed=false`, а Stage 2.25 и generic
`filesystem_access_performed=false`. Успешните им launcher-и обаче извикват
`mokosh_gui.main()`, който след Stage 2.24 explicit изпълнява
`ensure_private_data_dir()` преди `tk.Tk()`.

Stage 2.26 добавя 12 отделни automated tests и актуализира трите existing
report test families. Evidence-ът изисква:

- exact schema version `2` за Stage 2.18, 2.20 и 2.25 reports;
- `runtime_directory_preparation_performed=true`;
- `recovery_source_filesystem_access_performed=false`;
- `recovery_source_filesystem_mutation_performed=false`;
- липса на generic `filesystem_access_performed` и
  `filesystem_mutation_performed` в новите schemas/JSON;
- validator отказ на forged противоположни стойности;
- exact launcher disclosure преди `mokosh_gui.main()`;
- report cores без direct filesystem/network/process/logging/GUI import;
- byte-exact `mokosh_gui.py`, `mokosh_paths.py`, application launcher,
  requirements, crypto core и recovery storage core.

Очакваният full installer gate е 1387 теста: OK, expected failures=3 само за
legacy MOK1, skipped=0. Няма human visual gate, защото GUI text, layout,
geometry и event behavior остават byte-exact; stage-ът променя само evidence
schema/disclosure semantics.

Историческите version-1 reports и annotated tags не се променят. Generic
старите полета не трябва да се цитират като whole-process no-filesystem
доказателство. Stage 2.26 не е system-call instrumentation, filesystem или
platform certification, independent audit, recovery success или legal
conclusion.

## 27. Stage 2.27 recovery source selection evidence

Авторитетният вход е exact clean commit `9946ff7`. Full-history bundle и
source snapshot имат съответно SHA-256
`24051db042ec694d545a2b441c70ce337a3c1dee00bdc5d3897fe79394b51ca2` и
`ef6515207872cd07ef39af71c0ecc6011b5374c016a15ca28ab00c79c93ea2f6`.
Bundle verification, 57 refs, 95 commits, 0 merges, 54/54 annotated tags и
byte-for-byte snapshot/Git identity са PASS.

Fresh authoritative baseline на лаптопа е 1387 теста: OK, expected failures=3
само за legacy MOK1, skipped=0. Review на 109 Python files, 54 test files,
imports, dependency cycles, GUI/recovery trust boundaries, path/secret flow и
Stage 2.5 secure-read core е извършен преди scope freeze.

Stage 2.27 добавя точно 26 automated tests за:

- exact positive Stage 2.21 outcome revalidation и preserve-route отказ;
- Bulgarian/English selection и exact no-path preserve result;
- exact enum/signature/format/version/sequence contracts;
- strict absolute POSIX lexical path, 4096-byte UTF-8 bound и unsafe Unicode
  refusal;
- sensitive path redaction и copy/deepcopy/pickle refusal;
- invalid-input non-consumption, replay и concurrent exactly-one success;
- forged transition, path, route и authority claims;
- stdlib + Stage 2.19/2.21/2.22-only import closure;
- absence of filesystem, GUI, process, network, logging, callback, executor,
  secret, reconciliation и workflow capability;
- byte-exact critical GUI/path/launcher/requirements/crypto/entry/storage/
  reconciliation files и `SAFETY_MODE=True`.

Expected full installer gate е 1413 теста: OK, expected failures=3 само за
legacy MOK1, skipped=0. Няма visual gate, защото Stage 2.27 не променя GUI и
не отваря picker. Installer-ът трябва да изисква exact base, clean tree,
payload hashes/modes, exact seven-path allowlist, 26-test targeted gate,
rollback probe, full regression и annotated tag след всички PASS резултати.

Evidence-ът доказва само pure process-local path-selection contract. Path е
недоверено чувствително metadata и не доказва existence, identity,
authenticity, permissions или source access. Няма recovery secret, file read,
Stage 2.8 invocation, operation authority, platform certification, independent
audit или legal conclusion.

## 28. Stage 2.28 main-GUI recovery source-selection evidence

Авторитетният вход е exact clean commit `45a977e`. На лаптопа са потвърдени
1413 теста: OK, expected failures=3 само за legacy MOK1, skipped=0. Full
history, Git fsck, clean tree, exact tag/parent, source snapshot identity,
runtime dependencies и ML-KEM-768 availability са PASS преди scope freeze.

Stage 2.28 добавя 36 automated tests за:

- locked third action и exact Stage 2.21 positive arming;
- preserve/wrong-type/forged-schema/authority отказ;
- липса на Stage 2.27 preparation и picker преди third click;
- clear/disable-before-prepare/picker ordering;
- exact select/cancel mapping и unchanged Stage 2.27 lexical validation;
- locale binding към transition outcome;
- generic errors без path или exception leakage;
- ordinary exception, `BaseException`, replay и concurrent exactly-one;
- event без retained selected path/outcome след completion;
- conditional Stage 2.27 import и fresh normal-import isolation;
- static no-open/read/stat/operation boundary;
- exact visual report routes/schema и negative forged claims;
- critical core hashes и `SAFETY_MODE=True`.

Expected full gate е 1449 теста: OK, expected failures=3 само за legacy MOK1,
skipped=0. Mandatory visible Linux matrix е `bg-BG`/`en-GB` ×
`select`/`cancel`, като никога не се избира истински recovery record.

Evidence-ът изрично отчита native picker metadata access possibility и
existing runtime-directory preparation. Той доказва само, че application
selection event не отваря/чете source content, не identity-валидира или
подготвя source, не приема secret и не предоставя operation authority.

Fresh pre-freeze review откри, че пет historical test modules съдържат exact
GUI hash guards. Scope-ът беше спрян преди код и minimal re-freeze добави само
тези пет paths. Оттук нататък задължителен transitive test-impact scan търси
hash/import/schema/geometry/evidence/installer зависимости преди всеки freeze.
Това е process evidence срещу късни несъответствия, не формална гаранция, audit
или legal conformity conclusion.

## 29. Stage 2.29 recovery source inspection-request evidence

Авторитетният вход е exact clean commit `6613b2e`, tree `cadb430e` и annotated
Stage 2.28 tag. На лаптопа са потвърдени Git/history/fsck, exact runtime,
protected quarantine, locale-stable 114-source manifest и 1449 теста: OK,
expected failures=3 само за legacy MOK1, skipped=0.

Stage 2.29 добавя точно 30 automated tests за:

- BG/EN request и preserve routes;
- exact Stage 2.27 type/schema/positive-selection revalidation;
- forged path, route, sequence, format и authority claims;
- path redaction, non-serialization, exact-text retention и discard-on-stop;
- invalid-input non-consumption, terminal replay и concurrent exactly-one;
- exact constants/enums/signatures/bounded schema;
- AST import и no-filesystem/network/process/dynamic-capability граница;
- byte-exact GUI, Stage 2.27, storage, reconciliation, paths и dependency files.

Expected full installer gate е 1479 теста: OK, expected failures=3 само за
legacy MOK1, skipped=0. Няма human visual gate, защото Stage 2.29 не променя
GUI. Installer evidence трябва да включва exact seven-path allowlist, payload
hashes/modes, ignored root-level Python scan, `LC_ALL=C` exact source manifest,
tracked-source compile, isolated rollback и full regression преди commit/tag.

Evidence-ът доказва само pure process-local request contract. Той не доказва
source existence/identity/authenticity/permissions, secure read, memory
zeroization, recovery success, platform certification, independent audit или
legal conformity. Source open/read, secret intake, Stage 2.8 invocation,
review/session и operation authority остават забранени.

## 30. Stage 2.30 main-GUI source inspection-request evidence

Авторитетният вход е exact clean commit `0af7a6d`, tree `4923cfcf` и annotated
Stage 2.29 tag. Fresh laptop baseline е 1479 теста: OK, expected failures=3
само за legacy MOK1, skipped=0. Git/history/fsck, runtime, archived package,
protected quarantine и locale-stable 116-source manifest са проверени.

Fresh High architecture/security review и transitive-impact scan замразиха
точно 18 paths: четири документа, `mokosh_gui.py`, contract, pure visual core,
launcher, един new 42-test module, шест historical GUI-hash guards и три
historical normal-geometry guards.

Stage 2.30 добавя точно 42 automated tests за:

- locked fourth action и exact positive Stage 2.27 selection arming;
- preserve/wrong-type/forged-schema/authority отказ;
- conditional Stage 2.29 import само след отделен fourth click;
- clear-before-load/prepare/dialog ordering и bound locale;
- exact request/preserve mapping, generic path-free messages и errors;
- ordinary exception, `BaseException`, replay и concurrent exactly-one;
- four-action ordering и cancel/preserve fail-closed routes;
- BG/EN request/preserve bounded visual reports и forged-claim отказ;
- fresh-import isolation, static no-open/read/stat/operation boundary;
- exact critical hashes, geometry boundaries и `SAFETY_MODE=True`.

Expected full installer gate е 1521 теста: OK, expected failures=3 само за
legacy MOK1, skipped=0. Mandatory visible Linux matrix е `bg-BG`/`en-GB` ×
`request`/`preserve`, само с harmless synthetic file и никога с истински
recovery record.

Evidence-ът доказва само explicit process-local inspection request от normal
GUI. Native picker metadata access и existing runtime-directory preparation
остават explicit. Няма application source open/read/stat, identity validation,
access authorization, secret intake, Stage 2.5/2.8 invocation, review/session,
operation, recovery success, platform certification, independent audit или
legal conformity.

## 31. Stage 2.31 inspection preparation-request evidence

Авторитетният вход е exact clean commit `b07a617`, tree `bef01e3b` и annotated
Stage 2.30 tag. Baseline и post-runtime-repair regression са 1521 теста: OK,
expected failures=3 само за legacy MOK1, skipped=0. Runtime isolation,
ML-KEM-768, Tkinter, Git/fsck, protected quarantine и 119-source manifest са
проверени.

Stage 2.31 добавя точно 33 tests и точно осем project paths. Проверяват се
exact positive Stage 2.29 source, BG/EN request/preserve, forged route/schema/
authority claims, non-serialization, repr redaction, exact path-object
retention, per-object replay/concurrency, bounded schema, no privileged import
or AST capability, unchanged critical hashes и fresh normal-GUI isolation.

Expected full gate е 1554 теста: OK, expected failures=3, skipped=0. Няма visual
gate, защото GUI/text/layout са byte-exact. Installer evidence включва exact
allowlist/hash/mode, dry-run, isolated apply/rollback, tracked-source compile,
ignored-shadow scan и clean worktree checks.

Evidence-ът не твърди global consumption на caller-owned Stage 2.29 outcome,
Python `str` zeroization, source identity/access authorization, filesystem
capability, secure read, recovery success, audit, platform или legal
conformity. Тези privileged mediation свойства остават за отделен Stage 2.32.

## 32. Stage 2.32 secure source-inspection execution evidence

Авторитетният вход е exact clean commit `f375981`, tree `1fea5410` и annotated
Stage 2.31 tag. Laptop baseline identity, 121-source manifest и
`SAFETY_MODE=True` са потвърдени преди code work.

Stage 2.32 променя точно седем paths и добавя точно 42 tests. Проверяват се
exact positive Stage 2.31 revalidation, BG/EN inspect/preserve, conditional
Stage 2.5 storage import, zero-access preserve, clear-before-read, exactly-one
secure-reader call, terminal failure/replay/concurrency, bounded evidence,
repr/copy/serialization privacy, real 0700/0600 owner-only integration,
symlink/hardlink/mode/owner/canonical-name/malformed/change rejection,
read-only snapshot, fresh import isolation и unchanged critical hashes.

Expected full installer gate е 1596 теста: OK, expected failures=3, skipped=0,
123 tracked Python sources и exact locale-stable source manifest. Няма visual
gate, защото GUI/text/geometry са byte-exact. Installer-ът изисква exact
seven-path allowlist/hash/mode, isolated apply/rollback, targeted/full tests,
tracked-source compile, ignored-root shadow scan и clean worktree преди
commit/tag.

Evidence-ът доказва ограничена structural inspection чрез съществуващия Stage
2.5 POSIX secure reader. Не доказва ciphertext/tag authentication без recovery
secret, Python memory zeroization, future file identity, global source-outcome
consumption, recovery/rehearsal, Stage 2.8, review/session, operation authority,
platform certification, independent audit или legal conformity.

## 33. Stage 2.33 source-inspection presentation evidence

Авторитетният вход е exact clean commit `e1a92e7`, tree `3bdf6c36` и annotated
Stage 2.32 tag. Laptop Stage 2.32 gate е 1596 tests: OK, expected failures=3,
skipped=0; 123-source manifest, Git, package, quarantine и isolated runtime са
PASS.

Stage 2.33 променя точно седем paths и добавя точно 36 tests. Покрити са exact
positive Stage 2.32 source revalidation, BG/EN presentation, preserve/subclass/
forged отказ, domain-separated fixed transcript, binding на IDs/revision/size/
hashes/locale, exact enum type/order, strict boolean/schema claims, no raw
evidence retention, repr/copy/serialization privacy, no filesystem/secret/
recovery/Stage 2.8/GUI/authority capability, fresh import isolation и unchanged
critical hashes.

Expected full installer gate е 1632 tests: OK, expected failures=3, skipped=0,
125 tracked Python sources и exact source manifest. Няма visual gate, защото
GUI/text/geometry са byte-exact. Installer-ът изисква exact seven-path
allowlist/hash/mode, targeted/full tests, tracked-source compile, ignored-root
shadow scan и isolated apply/rollback преди commit/tag.

Evidence digest-ът е само process-local mismatch binding. Той не доказва
signature, provenance, ciphertext authenticity, source freshness, anti-rollback,
user acknowledgement, recovery success, platform certification, audit или
legal conformity.

## 34. Stage 2.34 source-inspection acknowledgement evidence

Авторитетният вход е exact clean commit `8b2a233`, tree `bdcdb4d4` и annotated
Stage 2.33 tag. Fresh laptop baseline е 1632 tests: OK, expected failures=3
само за legacy MOK1, skipped=0; runtime isolation, `pip check`, source manifest,
Git identity и `SAFETY_MODE=True` са PASS.

Fresh High review замрази точно седем paths: четири документа, нов contract,
нов pure acknowledgement module и нов 42-test module. Stage 2.34 revalidate-ва
exact Stage 2.33 schema и domain-separated canonical transcript обвързва
locale, evidence digest, fixed message/confirmation keys, всички safety flags,
format и version.

Prepared lifecycle използва един receipt reference като state commit под lock.
Failed validation/confirmation/mismatch и pre-commit `Exception`/
`BaseException` оставят fresh state; success е exactly-one и всички следващи
опити са replay. Private binding също се revalidate-ва изцяло.

Receipt е bounded, repr-hidden и non-serializable. То доказва само получени
exact confirmation tokens, не human understanding, user identity, informed
consent, signature, provenance, authenticity, source freshness, recovery или
operation authority. Няма original presentation, raw source evidence, path,
secret, callback, executor или gate capability.

Първият targeted cycle е 40 pass / 1 fail поради test-helper sentinel defect:
explicit `None` е било заменено с default valid presentation. Production API
не е причината; helper-ът е поправен и повторният exact gate е 42/42 PASS.

Scratch full-suite опитът е честно класифициран като non-authoritative failure:
локалният runtime няма `argon2`, три existing modules не се import-ват и
резултатът е 1645 tests, errors=3, skipped=7. Не е направен dependency bypass
или false PASS claim. Laptop installer-ът остава задължен да изпълни exact
1674-test gate чрез проверения `$HOME/venv_sys`.

Първият laptop dry-run спира fail-closed в protected-legacy gate преди clone,
patch или tests. Installer-ът resolve-ва `SHA256SUMS` entries спрямо quarantine
root вместо exact `files/` subdirectory и отчита четирите originals като
unreadable. Evidence/repo не са променени. R1 поправя само verifier working
directory, изисква private owner-only `files/` и запазва exact archive/manifest
checks. Incident-ът не се прикрива като package PASS.

Expected full installer gate е 1674 tests: OK, expected failures=3, skipped=0,
127 tracked Python sources и exact source manifest. Няма visual gate, защото
GUI/text/geometry са byte-exact. Installer-ът изисква exact seven-path
allowlist/hash/mode, targeted/full tests, compile, ignored-root shadow scan и
isolated dry-run/rollback преди commit/tag.

Project Integrity and Full Disclosure Invariant записва всички defects,
deviations, assumptions, changes и future standards/errata/revisions. SSDF
1.2 IPD, FIPS 203 future-update note, SP 800-38D Rev.1 pre-draft и EU CRA
2026-09-11/2027-12-11 milestones са tracked reminders, не final adoption,
self-certification или legal conformity claim.

## 35. Stage 2.35 source-inspection UI adapter evidence

Авторитетният вход е exact clean commit
`3a7d2a2479a0feeb447f8a8b8cbf66e626945e7d`, tree
`f1401057399ce3822c30864f51de1af753cc63cc` и annotated Stage 2.34 tag. Laptop
Stage 2.34 checkpoint е 1674 tests: OK, expected failures=3, skipped=0; 127
tracked Python sources, Git fsck, clean worktree и `SAFETY_MODE=True` са PASS.

Fresh High review замрази точно седем paths: четири документа, нов contract,
нов pure adapter module и нов 49-test module. GUI, localization renderer,
Stage 2.32–2.34, storage, crypto и privileged recovery code са byte-exact.

Adapter view съдържа точно седем ordered visible message enum keys и три
separate required/visible/individually-selectable/default-unselected controls.
Няма raw text, select-all, auto-accept, remembered state или operation control.
Success изисква exact ordered tuple от три visible, selected и user-initiated
event objects за същата fully revalidated Stage 2.33 presentation.

Private Stage 2.34 acknowledgement е изцяло binding-validated, а success
изисква exact private terminal state и receipt identity. Един
`_terminal` marker се задава непосредствено преди delegation: malformed input
преди marker-а е retryable; ordinary failure, unexpected exception или
`BaseException` след marker-а оставя `FAILED_CLOSED`; exact success заменя
marker-а с immutable receipt. Interrupt след private success не може да остави
outer adapter fresh. Lock-ът допуска точно една terminal delegation.

Receipt-ът доказва само bounded adapter assertions и валидиран Stage 2.34
receipt. То не доказва physical GUI rendering, accessibility conformance,
human understanding, identity, informed consent, signature, provenance,
authenticity, freshness, recovery или operation authority.

Historical Stage 2.12 dual `_receipt`/`_acknowledged` pattern и narrow nested-
success/outer-commit interrupt gap са записани като отделен pre-activation
hardening reminder. Path-ът е inactive, safety-gated и без authority; Stage
2.35 не го променя и бъдеща промяна изисква отделен High review/freeze.

Първият targeted cycle е 49 tests с 1 failure и 2 errors, всички в new test
harness: explicit `None` helper handling, `-I` subprocess path и неточен
critical-hash filename/hash. Production-module failure не е наблюдаван.
Harness-ът е поправен и повторният exact targeted gate е 49/49 PASS.

Scratch full regression е non-authoritative failure: 1694 tests, errors=3,
skipped=7, защото scratch runtime няма `argon2` и три existing test modules не
могат да се import-нат. Не е правен dependency bypass или false PASS claim.

Expected authoritative full installer gate е 1723 tests: OK, expected
failures=3 само за legacy MOK1, skipped=0, 129 tracked Python sources и exact
source manifest. Няма visual gate, защото това не е real GUI. Installer-ът
трябва да наложи exact seven-path allowlist/hash/mode, compile/source hygiene,
isolated apply/rollback, full regression и clean commit/tag transaction. До
успешния laptop gate този запис не твърди package/apply/final checkpoint PASS.

## 36. Stage 2.36 source-inspection localization evidence

Авторитетният вход е exact clean commit
`37bd8e446c7ff633a8c9ec1f1ce0cf87408ac047`, tree
`b80da694f645515eab04490546772f143f306010` и annotated Stage 2.35 tag.
Stage 2.35 laptop gate е 1723 tests: OK, expected failures=3, skipped=0;
exact 129-source manifest, safety mode, Git/fsck и clean worktree са PASS.

Fresh High review и corrected transitive-impact scan замразиха точно седем
paths. Новият pure registry е отделен от old Stage 2.13 localization; Stage
2.32–2.35, GUI, crypto, storage и historical tests остават byte-exact.

Двата catalogs покриват exact seven message и three confirmation enum keys за
`bg-BG`/`en-GB`. Source view locale е единственият selector. Няма fallback,
normalization, OS locale, external catalog, plugin или interpolation.

Text policy проверява exact `str`, NFC, 1–240 codepoints, до 768 UTF-8 bytes,
без whitespace boundary, Unicode control/bidi и template markers. Canonical
domain-separated digest обвързва locale, order, keys и exact text.

Localized records пазят stable ordinals, visible/accessibility-text equality и
separate required default-unselected controls. Те не съдържат selection event,
acknowledgement, source evidence, secret, callback, executor, gate или
operation capability и не доказват actual rendering/accessibility/consent.

Първият targeted cycle е 57 pass / 1 fail поради грешна Unicode test-vector
предпоставка за Cyrillic `е + combining acute`. Production validator не е
причината. Latin decomposed vector-ът е коригиран и 58/58 tests са PASS.

Scratch full suite е non-authoritative failure: 1752 tests, errors=3,
skipped=7, защото runtime-ът няма `argon2`; това са същите existing import
failures. Няма dependency bypass или false PASS claim.

Expected laptop installer gate е 1781 tests: OK, expected failures=3 само за
legacy MOK1, skipped=0, 131 tracked Python sources, exact seven-path/hash/mode/
tree manifest, compile, ignored-shadow scan и isolated rollback. Няма visual
gate; commit/tag идват само след authoritative PASS.

WCAG 2.2, EN 301 549 V3.2.1 плюс revision work и Directive (EU) 2019/882/EAA
са traceability reminders. Stage 2.36 не е accessibility/legal conformity
assessment.

Project workflow control вече изисква точно три stage-а на чат, после package
archive/history bundle/next input/handoff и нов High read-only chat. Текущият
chat е Stage 2.34–2.36; следващият започва със Stage 2.37.

## 37. Stage 2.37 source-inspection review-window evidence

Авторитетният вход е exact clean commit
`cc465b5b7d3c9188a9b0fbbd07987347c4e7c092`, tree
`1737846afb192dce4b8bd37a3917d629f95eda07` и annotated Stage 2.36 tag.
Laptop baseline е 1781 tests: OK, expected failures=3, skipped=0; 186 tracked
files, 131 tracked Python sources, fsck identity, safety mode и clean worktree
са PASS.

Fresh High review и explicit acceptance замразиха точно седем paths. Новият
controller приема само exact Stage 2.33 presentation и fresh exact Stage 2.35
adapter, локализира само през Stage 2.36 bound locale и създава точно един
`Toplevel` към existing parent. Няма second `Tk`, second `mainloop`, main-GUI
activation или window-wide Return binding.

Точно седем messages се създават преди три separate disabled/default-false
checkboxes. Controls се разрешават след exact visible-order report; final
button изисква трите individual selections и се disabled-ва при uncheck.
Cancel/Escape/WM close не acknowledge-ват и не consume-ват adapter-а.

Един `_terminal` marker се задава преди Stage 2.35 delegation. Fault injection
покрива RuntimeError, KeyboardInterrupt/SystemExit и post-delegate validation
failure: outer controller остава `FAILED_CLOSED`, включително когато inner
adapter вече е acknowledged. Replay и concurrent acknowledge/cancel имат
точно един terminal резултат.

Outcome не съдържа path/source bytes/secret/callback/executor/authority и е
frozen, repr-hidden за digest/receipt, non-copyable и non-serializable. Honest
flags остават false за physical rendering, accessibility, comprehension,
identity, consent, recovery и operation authority.

Първият exact targeted run даде 55 pass / 1 fail. Test №49 forged dataclass
чрез `object.__new__`, но не извика frozen-schema validator и очакваше
exception без validation. Коригиран е само harness-ът; production contract не
е променен. Повторният targeted gate е 56/56 PASS.

Expected authoritative full installer gate е 1837 tests: OK, expected
failures=3, skipped=0, 189 tracked files и 133 tracked Python sources. Нужни са
exact allowlist/hash/mode, critical predecessor hashes, compile/source hygiene,
isolated apply/rollback, full regression и clean post-apply checkpoint преди
commit/tag. GUI/platform claim е запазен за отделен Stage 2.38 harness.

Standards watch е обновен с ETSI adopted-for-publication work-item status от
2026-08-24 и explicit 4.1.0/work-item срещу 4.1.1/TC-HF-flyer numbering
inconsistency. Няма automatic baseline switch, harmonised/OJ или conformity
claim. WCAG 2.2, SSDF v1.1/1.2 IPD, SP 800-38D Rev.1 work, FIPS 203 update
note, EAA scope и CRA 2026-09-11 readiness остават traceability items.

## 37. Stage 2.38 source-inspection visual-harness evidence

Авторитетният вход е exact clean Stage 2.37 commit `ba465fe`, tree
`25a03227`, annotated tag и 1837 tests: OK, expected failures=3, skipped=0.
Fresh High review замрази точно осем paths и отдели pure synthetic core от
visible Linux/Tk launcher.

Fixed матрицата има осем случая: BG/EN, относителни 100/125/150/200% Tk
scale, 560×440/800×640 и Escape/Cancel/WM-close/acknowledge по два пъти.
Scaling използва initial platform value; bounded 25 ms × 80 mapping watchdog
отказва без report при timeout. Няма automatic event injection.

След всеки mapped case се изискват шест exact manual observations:
reachability/scrolling, wrapping/clipping/overlap, visible/unobscured focus
order, keyboard-only/no-trap, default-false/enable/re-disable и locale/title/
labels. `fail` и `not_checked` са explicit и правят matrix gate nonzero.

Core report е canonical JSON до 4096 UTF-8 bytes, без notes/path/hostname/
environment/source/secret/capability. Explicit false flags предотвратяват
platform/accessibility/screen-reader/API/contrast/preferences/comprehension/
identity/consent/authority claims. Evidence е self-reported за текущата
Linux/Wayland/Tk среда, не certification, independent audit или legal opinion.

Първият exact 48-test cycle даде 10 pass / 38 errors: новият Stage 2.38 core
погрешно използва return стойността на Stage 2.35 exception-based validator,
който по договор връща `None`. Stage 2.35–2.37 не са дефектни. Коригиран е само
новият core да валидира exact view и отделно да използва original reference;
повторният 48/48 gate е PASS.

Scratch няма user laptop path `$HOME/venv_sys`, затова първият local compile
probe към този path не е PASS. Наличният scratch Python изпълнява preliminary
compile/targeted gate; authoritative dependency/full/visual gate остава на
доказания `/home/mitra/venv_sys` runtime.

Scratch full regression е explicit failure: 1856 tests, errors=3, skipped=7.
Липсващият `argon2` блокира imports на `test_crypto_core`,
`test_crypto_core_negative` и `test_mokosh_vault_recovery_entry_main_gui_widget`;
затова 29 tests до expected 1885 не са изпълнени. Няма dependency bypass,
скрито инсталиране или false full-PASS claim.

Expected authoritative full gate е 1885 tests, expected failures=3, skipped=0,
193 tracked files и 136 tracked Python sources. Human eight-case visual PASS,
exact allowlist/hashes/modes, isolated apply/rollback и clean checkpoint са
задължителни преди commit/tag. Открит Stage 2.37 visual defect спира работата и
изисква ново explicit freeze решение.

Правният ledger не използва private-user/voluntary-choice като автоматично
освобождаване. Applicable law е mandatory; доброволните standards са строг
engineering baseline; мотивирана неприложимост и въпроси за квалифицирана
правна оценка се записват отделно. Няма self-certification или обещание за
неизвестно future conformity.

R0 authoritative installer attempt премина package structure/hashes/modes,
runtime/ML-KEM, protected legacy и exact Stage 2.37 identity, след което спря
в isolated apply преди tests, visual gate и actual repository mutation.
Причината е installer-only parsing defect: общият `_git()` helper връща
`.strip()` text и премахва значимия първи leading space от porcelain
` M PROJECT_STATUS_BG.md`. Observed temporary-clone status всъщност съвпада
точно с eight-path allowlist.

След failure read-only gate потвърждава exact Stage 2.37 HEAD/tree, clean
worktree, absent Stage 2.38 paths/tag и unchanged three-object fsck set.
Отделен temporary clone diagnostic показва exact four modified и four
untracked paths, след което real repo отново е clean. R0 е оттеглен. R1 чете
raw porcelain output без global strip и пази exact significant whitespace.

## 38. Stage 2.38 responsive-UI amendment evidence

R1 authoritative run премина 48 targeted и 1885 full tests два пъти
(isolated и actual apply), но visible case 1 разкри два отделни проблема:

1. tested Stage 2.37 window не осигури достатъчно ясно minimum-size
   reachability/resize/reflow/focus поведение;
2. harness раздели instruction и observations между GUI и terminal и провери
   terminal-action mismatch твърде късно.

Operator cancellation даде status 130; rollback и отделният read-only
checkpoint gate потвърдиха exact clean Stage 2.37, absent Stage 2.38 files/tag
и без нови unreachable objects. Това е валиден failed visual gate, не PASS.

След explicit 12-path amended freeze:

- Stage 2.37 window има explicit two-axis resize, dynamic 240–960 wrap,
  window-local wheel, PageUp/PageDown/Home/End, reading-region initial focus и
  FocusIn reveal; modal/transient/fail-closed semantics са запазени;
- long confirmation translations използват wrapping controls, без
  horizontal content scroll или silent abbreviation;
- harness instruction и six-observation form са отделни resizable/scrollable
  GUI phases; answers започват unset и submit остава disabled до шест exact
  selections;
- required terminal action се revalidate-ва преди observation collection;
  mismatch показва visible error и няма report; FAIL/not-checked/cancel спира
  matrix fail-fast;
- няма stdin/readline, event generation, programmatic checkbox/button
  invocation или preselected PASS.

Preliminary exact targeted evidence е 68/68 + 64/64 = 132/132 PASS.
R2 authoritative expected full gate е historical 1913 tests,
`OK (expected failures=3)`, skipped=0. Human eight-case gate, isolated
rollback и exact final checkpoint остават задължителни преди commit/tag.

## 39. Stage 2.38 R3 evidence

R2 case 1 има canonical PASS report за BG/100%/560×440/Escape и six exact
PASS observations. Case 2 няма report и observation form, защото два пъти е
наблюдаван Escape при expected Cancel; и двата опита завършват
`VaultRecoverySourceInspectionVisualHarnessError`, installer rollback PASS и
read-only exact clean Stage 2.37 checkpoint.

Това доказва action mismatch, но повторяемото conceptual misunderstanding е
instruction usability finding. R2 diagnostic показва само exception type в
stderr. R3 добавя bounded:

- `STAGE2_38_VISUAL_ACTION_MISMATCH CASE=n EXPECTED=x OBSERVED=y`;
- отделен `MATCHING_ACTION_CONTRACT_VALIDATION_FAILED` route;
- GUI expected/observed message без secret/path/environment data;
- sequential overview и explicit per-case acknowledgement.

Reported hidden initial footer се адресира чрез reserved grid rows, без
промяна на modal/fail-closed controller semantics. Exact preliminary R3
targeted evidence е 76/76 + 76/76 = 152/152 PASS. Current authoritative full
target е 1933 tests, expected failures=3, skipped=0.

## 40. Stage 2.38 R4 corrective evidence

R3 authoritative laptop automated gates преминаха, но manual launcher спря
преди GUI с `NameError` в `_show_matrix_overview`. Exact clean rollback е
доказан отделно. Root cause е неправилна function ownership на case-specific
banner и липса на structural test; няма data exposure, operation execution,
repository residue или user error.

R4 evidence добавя два negative/ordering regression contracts:

- AST на overview не зарежда `case` или `action` и не извиква
  `_action_banner_text`;
- case-instruction source създава `action_banner` преди resize callback да го
  използва и го свързва с exact `case.case_number`/`action`.

Expected exact targeted gate е 76/76 + 78/78 = 154/154. Authoritative full
target е 1935 tests, expected failures=3, skipped=0. Това е structural
regression evidence; human visual matrix остава отделно задължително
доказателство и не се заменя с автоматичен claim.

## 41. Stage 2.38 R5 live-layout evidence

R4 manual evidence е коригирано от operator: Cases 1–3 JSON с six PASS не са
валидни, защото footer/action controls са били скрити и извън scroll canvas.
Case 4/200% instruction блокира без acknowledgement/Start. Status 130,
rollback PASS и independent exact-clean Stage 2.37 gate са доказани.

R5 добавя pure geometry predicates и live mapped mediation. Exact checks са:
mapped/nonzero, within client bounds, ordered non-overlap, minimum 80-pixel
middle viewport и exact required footer controls. Stage 2.37 gate е преди
`mark_messages_visible_once`/control enable; harness gates са преди всеки
`wait_variable`. Failure diagnostic е bounded до phase/case/scale/profile и
не съдържа actual geometry, screen или host metadata.

Preliminary exact targeted evidence е 84/84 + 90/90 = 174/174 PASS.
Authoritative full target е 1955 tests, expected failures=3, skipped=0.
Това не е human visual PASS; complete 1→8 laptop matrix и installer isolated
rollback остават задължителни преди commit/tag.


## 42. Stage 2.38 post-R5 corrective diagnostic и runtime-guard evidence

Authoritative R5 `593e445` остава clean historical checkpoint, но не final
quality acceptance. Последващият operator resize-operability report е записан
като blocker. D1 не е root-cause authority. D2 валидира initial/enlarged/restored
mouse+keyboard operability в clean repeat; отделен raw kernel probe отчете 10/10
Tab press/release и 0 repeat. D3 валидира пет mouse geometries, включително
large non-maximized `1060x685`, с exact press/release/command и unchanged repo.
Така finding-ът е currently non-reproducible, не disproven.

Static R5 review доказва initial-only live layout mediation: `_finish_activation`
проверява regions преди visible claim/control enable, но runtime `<Configure>`
само resizes content/wrap. Corrective candidate добавя debounced runtime
mediation, idempotent controller-derived Confirm state resync, focused-checkbox
reveal и fail-closed DisplayError; не добавя authority/data/I/O/event injection.

Candidate targeted tests са 92 review-window + 90 visual-harness = 187/182 PASS
в build snapshot. Full expected laptop count е 1963. Sandbox partitioned regression
покри останалите tests без candidate regression; два fresh-import capability
probes са environment-incompatible в sandbox, но същите два tests падат
идентично и на unmodified R5 snapshot поради preloaded `tkinter` в `/opt/pyvenv`.
Те НЕ се skip-ват в laptop dry-run: `~/venv_sys` трябва да изпълни целия 1963
suite. Няма final automated или human PASS claim преди този laptop gate.

### Stage 2.39 review-controller evidence plan

- Frozen Stage 2.39 input is exact positive Stage 2.32 `VaultRecoverySourceInspectionExecutionOutcome`; no separate locale/path/secret/callback/executor input is allowed.
- Stage 2.39 delegates only to Stage 2.33 presentation, Stage 2.35 UI adapter, Stage 2.37 preparation validation and Stage 2.37/2.38 display path.
- Exact 20-test targeted gate covers source type/positive decision, no source retention, constructor mismatch, non-copy/serialization, acknowledged/cancel outcomes, digest/locale/authority revalidation, non-outcome rejection, replay/failure/interrupt/concurrency and static forbidden imports/calls/main-GUI isolation.
- Wrapper/installer remains a separate security-critical evidence object. R1 self-tests covered unexpected untracked path, staged mutation and tampered allowlisted file; R2 additionally covers unchanged pre-existing bytecode (positive) and new/changed bytecode (negative fail-closed).
- Authoritative pre-implementation baseline: 1968 tests, `OK (expected failures=3)`, clean before/after. R1 dry-run: 20/20 targeted and 1988 full tests PASS. R1 live apply repeated both PASS gates, then false-failed on an absolute bytecode-residue check and rolled back exactly to `65721f4`.
- R2 preventive correction snapshots exact live bytecode state before mutation and requires the same exact state after live tests. R2 apply recorded 4341 pre-existing bytecode artifacts before mutation. R2 dry-run: wrapper self-tests PASS, 20/20 targeted PASS, 1988 full tests `OK (expected failures=3)`, live repo unchanged. R2 apply: 20/20 targeted PASS, 1988 full tests `OK (expected failures=3)`, exact six-path hashes PASS, `LIVE_BYTECODE_STATE_UNCHANGED=PASS`, candidate left unstaged for review. No commit/tag yet.
- Superseded process rule correction: exact search located the old three-stage rule in the active `PROJECT_STATUS_BG.md` invariant and as historical Stage 2.36/session evidence in this document and `SESSION_LOG_BG.md`. Only the active `PROJECT_STATUS_BG.md` invariant is rewritten. Historical evidence text is preserved and explicitly superseded here by the current one-successfully-closed-Stage-per-chat rule.
- Preventive tooling rule: known pre-existing ignored residue is evaluated as an exact baseline-relative delta invariant; absolute-zero residue assertions are forbidden unless the baseline itself was first proved zero.
- No Stage 2.39 security/accessibility/legal certification claim is made. Standards/legal status remains subject to explicit fresh primary-source gates when relevant dates/statuses change.

## 43. Stage 2.40 inactive source-inspection main-GUI bridge evidence plan

- Exact live baseline is clean Stage 2.39 `468ad782` / `e4c0233`, annotated
  tag, 109 commits, 0 merges and 68 annotated tags. Three handoff files,
  protected legacy, runtime/ML-KEM, Git/fsck and ignored-root shadow gates are
  PASS.
- Baseline full regression is 1988 tests, `OK (expected failures=3)`, skipped=0.
  Exact 4341-record bytecode snapshot SHA-256
  `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`
  is unchanged before/after and the worktree remains clean.
- User accepted the initial seven-path freeze before initial mutation. A
  mandatory transitive impact scan then found 13 stale exact GUI-hash guards
  in 12 historical security test paths. Work stopped until the user accepted
  the minimal 19-path re-freeze. Stage 2.40 accepts only exact fresh Stage 2.39
  session and derives locale from it; no separate locale/path/source/secret/
  callback/executor input exists.
- One-shot state moves atomically `READY -> DISPLAYING -> COMPLETED|FAILED`.
  Raw outcome must be exact type, exact `session.outcome` identity and exact
  completed controller state, then passes dataclass/locale revalidation.
- Main GUI adds only conditional helper + exact inactive seam. Fresh normal
  import/main does not load the bridge or invoke the seam; no widget/text/
  geometry/launcher change exists.
- Exact 24-test module covers type/state/locale, raw identity, reconstruction,
  authority/schema, foreign/forged results, replay/concurrency/fault/interrupt,
  retention, static capability and normal-import boundaries.
- Initial 22 PASS / 2 FAIL are a disclosed test-expectation defect: reconstructed
  caller outcome was incorrectly required to be raw session object identity.
  Production code stayed unchanged; corrected exact result is 24/24 PASS.
- Independent review found a second test-only defect: test 17 inspected
  `__slots__` names instead of exact slot values in its parent-retention check.
  The assertion is corrected without production, path-count or test-count
  expansion.
- A 384-test transitive impact run before re-freeze produced exactly 13
  failures, all from the stale GUI digest in the 12 added historical paths; the
  other 371 tests passed. Scratch full discovery additionally had three
  environment-only import errors because that runtime lacks `argon2`; it is
  not authoritative full-regression evidence.
- After the 13 GUI-hash corrections, a broader 765-test run produced 764 PASS
  and one exact predecessor-test hash failure: localization also byte-hashes
  the changed UI-adapter test file. Full reference search proved this is the
  only second-level dependency. The user accepted that one-line amendment;
  path scope remains 19 and no behavior/security assertion is weakened.
- Required next gates: transitive GUI/review regressions, expected 2012 full
  suite with expected failures=3/skipped=0, bytecode delta invariant, exact
  19-path/hash/mode audit, wrapper negative self-tests, isolated rollback
  and independent factual-diff review before commit/tag.
- No visual, accessibility, security, legal or standards conformity claim.
  SSDF 1.2 remains draft; WCAG2ICT/CRA remain explicit traceability/readiness
  items rather than automatic adoption or applicability conclusions.
- R1 authoritative laptop dry-run fail-closed before Git/candidate tests. Root
  cause was installer-only: `.resolve()` converted the lexical
  `$HOME/venv_sys/bin/python3` symlink into `/usr/bin/python3.12`, bypassing the
  venv and importing system `cryptography` without ML-KEM. No live repository
  path changed. R2 preserves the lexical executable entry and verifies exact
  `sys.executable`, venv `sys.prefix`, absent system dist-packages, dependency
  versions, cryptography OpenSSL backend and ML-KEM. A symlink regression
  self-test forbids recurrence. This is now a mandatory future installer gate.
- R2 then reached the correct `$HOME/venv_sys` but stopped before Git/candidate
  tests because its separately reconstructed probe imported nonexistent
  `ml_kem` instead of the project's exact `mlkem` API. Again, no live mutation
  occurred. R3 imports the existing baseline `_mlkem_module()` dependency
  boundary and exercises its real `MLKEM768PrivateKey` roundtrip. Permanent
  rule: installer runtime probes reuse the application's proven API boundary;
  they do not duplicate external-library API spelling or call conventions.
- R3 proved the correct live venv, cryptography/ML-KEM roundtrip, exact live Git
  identity/fsck and 4341-record bytecode baseline, then stopped before payload
  tests. Its isolated local clone retained the three known unreachable blobs,
  unlike the scratch clone that omitted them. No live mutation occurred. R4
  requires the live repository to have the exact historical set and permits an
  isolated clone only zero or a subset of that set; any unknown dangling object
  or fsck damage fails. Positive/negative self-tests cover exact, subset and
  unknown-object cases. This clone-vs-live distinction is a mandatory future
  installer invariant.
- High recovery semantic review identified three green-but-insufficient test
  assertions: foreign identity and wrong locale were rejected by an earlier
  controller-state predicate, while the GUI seam did not assert exact parent
  forwarding. The same 24-test module now makes all earlier predicates valid
  and isolates the intended identity, locale and forwarding guards. This is a
  test-strengthening correction only; production behavior/scope is unchanged.
- High recovery production review then reproduced a separate exact-binding
  defect: direct substitution of the private session slot by another fresh
  same-locale exact-type session was accepted before display. Stage 2.40 now
  stores an independent process-local preparation identity, checks it before
  delegation and clears it with the session on every terminal route. The
  existing nonfresh-session test method also proves that the substitute stays
  PREPARED and is never displayed; path scope/test count remain 19/24.
- Consolidated R1--R4 control-flow review withdrew all four artifacts and found
  two additional tooling gaps not reached by the laptop failures: the shared
  parser accepted a targeted 24-test summary with expected failures, and the
  self-tests did not execute package validation, candidate inventory, atomic
  copy, backup, apply or rollback. No withdrawn installer code is reused.
- The replacement delivery contract separates exact live Git/runtime state,
  a `.git`-free `git archive HEAD` candidate, apply and rollback. It contains
  no candidate clone/fsck/dangling policy and no duplicated ML-KEM call. Its
  pre-package 33-test tool suite exercised positive/negative path, result,
  archive/PAX, package/payload, status, bytecode compatibility, candidate,
  copy, backup and rollback cases including failure after every copy position.
  This is scratch tool evidence, not authoritative laptop full-regression or
  live-apply PASS.

### Stage 2.41 main-GUI source-inspection review evidence plan

- Accepted input is exact Stage 2.40 `b039b3b`, with laptop 24/24 predecessor and 2012 full baseline PASS, expected failures=3, skipped=0.
- The new event consumes only exact fresh Stage 2.40 binding, disables the button and clears its retained binding before display, then requires exact completed binding/outcome identity.
- Failure, unexpected exception, interrupt, replay and concurrency are fail-closed/terminal. Fixed GUI errors expose no exception, source or path data.
- Mutual-exclusion and invalid-binding tests prove refusal before runtime-directory preparation and Tk. Valid conditional startup truthfully retains the existing runtime-directory mutation.
- Exact 36-test target covers lifecycle, concurrency, identity, authority/retention absence, old/normal-mode compatibility, ordering, disabled controls, lazy import, fixed matrix, report claims/bounds and critical hashes.
- Preliminary scratch gates: 36/36 target and 128/128 compatibility PASS. A 2048-test scratch run passes with three expected failures and seven build-runtime ML-KEM skips; this is not authoritative full evidence.
- Authoritative package/live gate must use lexical `~/venv_sys/bin/python3` and produce 2048 tests, expected failures=3, skipped=0. No skip waiver is allowed.
- Human four-case/six-observation evidence remains separate and mandatory. Automated PASS cannot replace it.
- Bytecode uses the exact 4341-record baseline-relative digest, never an absolute-zero residue assertion.
- No commit/tag or security/accessibility/legal certification is claimed at candidate stage.

### Stage 2.41 authoritative laptop and human evidence — 2026-09-03

- R1 е withdrawn/forbidden: неговият pre-mutation verifier false-fail-на на
  live `.gitignore` mode `0644`, защото преобразува Git `100644/100755` в
  измислени физически `0664/0775`. Repository bytes, index, refs и bytecode не
  са били променени.
- Независимата read-only mode/identity/ACL проверка замрази 199 tracked paths:
  `61×0600`, `108×0644`, `24×0664`, `1×0700`, `5×0755`; Stage 2.41 existing
  targets са `14×0644`, `5×0664`, `1×0600`; owner/group е `mitra:mitra`,
  групата има само effective member `mitra`, extended ACL count е zero.
- R2 package: `196231` bytes, SHA-256
  `a426adb7e224fc3a687fe880570ad44891b82999140dd70667c1a9ae0ae140f2`;
  installer: `40982` bytes, mode `0700`, SHA-256
  `e06f22fe1324dd5a49f9809934f47c3bd7074abd0af0b2c589291d78da706b55`.
  Final package audit: safe members 29/29, exact bytes/modes 25/25,
  normalized metadata, clean GNU-tar extraction, R1 false-fail regression,
  payload mode-drift negative test, syntax PASS и extracted rollback 24/24.
- Laptop dry-run: installer self-tests 24/24, exact Stage 2.40 baseline,
  rollback injection 24/24, Stage 2.41 36/36, predecessor 24/24 и full 2048
  PASS, expected failures=3, skipped=0.
- Live apply: exact baseline, 36/36, 24/24 и full 2048 PASS, expected failures=3,
  skipped=0; exact live candidate е 24 unstaged paths.
- Independent post-apply gate повтори 36/36 и full 2048 PASS, провери exact
  24 payload bytes/modes/owner/group/ACL, unchanged tracked mode distribution,
  exact three known dangling blobs, zero staged paths и exact before/after
  4341-record bytecode digest
  `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`.
- Human matrix produced four bounded canonical reports and 24/24 self-reported
  PASS observations. Exact outcomes са: case 1 `bg-BG`/100/Escape/cancelled,
  case 2 `en-GB`/125/Cancel/cancelled, case 3 `bg-BG`/150/child-X/cancelled и
  case 4 `en-GB`/200/Acknowledge/acknowledged. Presentation SHA-256 са
  `03704889d08911255f11ae6956c59decf7d89e08b99f4082a2ebffdd7f0744e0`,
  `98037fffa5be369ea9accf2037b087eb445b1431eac88bf6e1ad25599080e5aa`,
  `ef3711ca347d8f3b8c3d3ec8214de5af81e6dfcee7358aff2c5b17976af21fa7`
  и `c65cdd459bfd03240c61ccec918000937f4bdfaceba7afa60ffefe31c5964b60`.
- Всички reports казват `operation_authorized=false`,
  `operation_performed=false`, `true_vault_input_used=false`,
  `recovery_source_filesystem_access_performed=false`,
  `recovery_source_filesystem_mutation_performed=false`, `network_used=false`
  и no retention. `runtime_directory_preparation_performed=true` е точният
  съществуващ Stage 2.24 boundary, а не recovery-source mutation.
- Evidence е достатъчно за Stage 2.41 engineering gate, но не е screen-reader,
  contrast, assistive-technology, accessibility/legal conformity, platform
  certification или comprehension доказателство. Няма waiver или такъв claim.

### Stage 2.42 normal-main-GUI layout audit evidence plan

- Exact input е clean Stage 2.41 `2f1e1ee`, tree `f39a7ebe`; independent handoff bundle/input regeneration и laptop 36/36, 24/24, full 2048 baseline са PASS.
- Архитектурният review отказва да обедини Stage 2.29 intent, Stage 2.31 preparation request, Stage 2.32 privileged read и Stage 2.39–2.41 display activation.
- Evidence gap е bounded: Stage 2.30 normal mode няма 100–200% scaling matrix, а Stage 2.41 scaling evidence е само за conditional mode.
- Exact осем-path audit scope не променя `mokosh_gui.py`. Pure core/launcher/tests/contract и четири append-only evidence paths са единствените candidates.
- Matrix е BG/100, EN/125, BG/150, EN/200; всеки report има осем fixed observations и не съдържа notes, dimensions, coordinates, screen/host metadata, source/path/secret или exception text.
- Launcher-ът не inject-ва GUI events, не invoke-ва controls и не отваря picker. Existing Stage 2.24 runtime-directory preparation се отчита true; recovery-source access/mutation са false.
- Human FAIL/NOT_CHECKED е blocking evidence преди live apply. Automated gate не може да го замести.
- Exact target е 32 tests; predecessor gates са 36 и 24; full target е 2080, expected failures=3, skipped=0.
- Първият target run даде 31 PASS/1 test-only false fail: raw substring predicate откри `callback` в no-capability docstring. Корекцията използва AST call/import predicates и negative docstring regression; rerun е 32/32 PASS.
- Няма accessibility/usability/legal/platform certification или production-readiness claim.

### Stage 2.42 pre-package corrective tooling evidence

- Independent launcher review found that the two `initial_keyboard` cases had
  been instructed to resize, collapsing the frozen profile distinction. The
  unpublished candidate now keeps cases 1–2 at initial size and reserves
  resize/restore for cases 3–4; a source regression assertion covers both
  exact instructions.
- Initial wrapper inventory arithmetic expected 211 files by treating all
  eight allowlisted paths as new. Archive testing failed safely before package
  issuance; four paths modify baseline files and four are new, so the exact
  candidate inventory is `203 + 4 = 207`. The derived-count assertion prevents
  recurrence.
- An ad-hoc probe reported 4086 because it counted only regular `*.pyc` files.
  The hash-verified Stage 2.42 exporter proves that the historical schema also
  records 255 `__pycache__` directories with type/mode/uid/gid/size/mtime and
  digest fields. The delivery wrapper now reuses that exact 4341-record schema
  and static SHA-256 instead of inventing a replacement.

### Stage 2.42 blocking human evidence и corrective plan

- R1 audit-only package automated dry-run е PASS до human gate: 14/14
  self-tests, 8/8 rollback, 32/32 target, 36/36 и 24/24 predecessors и 2080
  full PASS при expected failures=3, skipped=0.
- Първият BG/100% initial case записва един `fail` и седем `not_checked`.
  Long recovery controls са видими, но later normal controls не са видими в
  initial `820x720` window. Това е валиден blocking result, не waiver или
  частичен PASS. Няма live apply.
- Accepted corrective re-freeze замества само осем-path/no-production-change
  ограничението: exact allowlist е 23 paths и включва normal-GUI adaptive
  vertical viewport плюс необходимата hash/mock compatibility closure.
- Automated corrective target е 48: wheel normalization, scroll region/width,
  PageUp/PageDown/Home/End, focus reveal/clamping, normal-only isolation и
  no-new-sensitive-capability проверки. Isolated evidence е 48/48 target и
  61/61 direct compatibility PASS.
- Authoritative gate остава laptop `~/venv_sys/bin/python3`: exact 48/48,
  predecessor 36/36 и 24/24, full 2096, expected failures=3, skipped=0,
  baseline-relative 4341 bytecode digest и рестартирана human matrix 32/32
  observations. Automated tests не заместват човешките observations.
- Corrective R1 installer self-tests 14/14 минаха, но live baseline gate спря
  преди candidate creation: `tests/test_mokosh_vault_recovery_source_inspection_acknowledgement.py`
  е frozen `0664`, а общата existing-target проверка изискваше `0644`.
  Няма mutation. R1 е withdrawn; replacement gate проверява индивидуално
  exact modes за всичките 19 existing targets, включително пет `0664` и един
  `0600`, и payload-ът запазва същите режими.

### Stage 2.42 R2 full-regression blocking evidence

- R2 individual-mode correction е доказана, но неговият laptop dry-run е
  блокиран след 48/48, 36/36 и 24/24 PASS от full 2096 gate: два normal-main
  construction tests използват реален `tk.Canvas` с `FakeWidget` parent, а
  localization predecessor map пази стария hash на вече променения
  UI-adapter test.
- Това са candidate test-compatibility/closure defects; няма live mutation,
  human observation или recovery operation. R2 е withdrawn и не може да се
  използва за apply.
- Complete reverse-hash graph и full-suite failure set разширяват exact scope
  само с двата entry/entry-transition main-GUI mock tests. Final allowlist е
  25 paths; production остава само `mokosh_gui.py`.
- Corrective tests mock-ват `Canvas` и `Scrollbar` със същия bounded fake
  interface като другите normal-main tests и обновяват един точен predecessor
  hash. Exact focused rerun е 51/51 PASS. R3 package се допуска само след два
  post-documentation full runs по 2096 PASS, expected failures=3, skipped=0.

### Stage 2.42 R3 transactional status-parser false fail

- R3 apply достигна post-overlay verification след два full 2096 PASS и
  human matrix 32/32 PASS, но не издаде live PASS marker. `apply_live()` catch
  изпълни и провери rollback.
- Independent reproduction доказва `set(raw_porcelain.splitlines()) ==
  expected_25`, но `git(...).strip().splitlines()` премахва значимия leading
  space само от първия unstaged-modification ред. Това е wrapper parser defect,
  не repository status mismatch.
- R4 status gate чете `run(...).stdout.splitlines()` директно. Regression
  изисква първи ред с exact two-column porcelain prefix, 25/25 expected set и
  clean status след 25-target rollback. R3 остава withdrawn.

### Stage 2.42 authoritative R4 apply и independent post-apply evidence

- Verified R4 package/installer identities са съответно
  `5249f40e9207af37a63c0b6ec5f749785c90308d7f88bdd01fe00109673223b0`
  (`212756`, mode `0600`) и
  `2942c6873903d33511703fb0272243db443a9843bd28a0da77d00dd915bfb309`
  (`40975`, mode `0700`). Archive audit е 30/30 members, 25/25 payload и
  exact normalized metadata/mode-map.
- Authoritative apply е PASS: 15/15 self-tests, 25/25 injected rollback,
  48/48 target, 36/36 и 24/24 predecessors, full 2096 before overlay и full
  2096 after overlay; expected failures=3, skipped=0.
- Четирите human reports съдържат 32/32 exact `pass` observations и explicit
  false claims за operation authority/performance, source access/mutation,
  picker, network, screenshots, conformity, certification и future-layer
  activation.
- Independent post-apply command потвърждава exact raw porcelain 25/25,
  package-equal target bytes, individual modes, owner/group, zero extended
  ACL, tracked mode distribution, known three dangling blobs и unchanged
  bytecode tuple `(4341, afc72643...e8011)`, след което повтаря full 2096 PASS.
- Това е bounded engineering evidence, не accessibility/legal conformity,
  usability за всички потребители, platform certification или production
  recovery-success доказателство.

## Stage 2.43 accepted preparation-request transition evidence plan

- Exact clean Stage 2.42 baseline е независимо доказан на laptop: 48/48,
  36/36, 24/24 и full 2096 PASS, expected failures=3, skipped=0, с непроменени
  physical manifest и bytecode tuple `(4341, afc72643...e8011)`.
- Exact scope е 22 paths и само `mokosh_gui.py` е production target. Stage 2.31
  contract, Stage 2.32 execution, Stage 2.39 controller, Stage 2.40 bridge,
  Stage 2.41 widget, Vault/crypto/storage/Contacts и requirements остават
  byte-exact.
- New 48-test target изисква exact positive Stage 2.29 validation, locked/
  ready/deciding/terminal ordering, separate fifth click, request/preserve,
  replay/concurrency rejection, generic path-free errors, clear-ване на
  event-state predecessor преди loader и clear-ване на локалната predecessor
  reference след exact preparation и преди dialog.
- Static tests отказват source open/read/stat/resolve, filesystem capability,
  authorization, Stage 2.32/2.41 activation, operation, persistence, logging и
  network calls. Fresh `mokosh_gui` import не зарежда Stage 2.27/2.29/2.31.
- Visual schema не съдържа path, filename, secret, callback или executor.
  Process-local retention и unproven Python-string zeroization са explicit;
  whole-process no-filesystem, accessibility/legal conformity и certification
  claims са false.
- Preliminary isolated 48/48 е candidate-only evidence. Final payload bytes
  трябва да минат target, 48/36/24 predecessors, full 2144 regression, exact
  reverse-dependency closure, package self-tests, apply/rollback simulation и
  human BG/EN 100–200% matrix преди live mutation.

### Stage 2.43 R1 blocking human-usability evidence и guided correction

- R1 laptop dry-run е exact PASS: 16/16 installer self-tests, 22/22 rollback
  injection, 48/48 target, 48/36/24 predecessors и full 2144 при expected
  failures=3, skipped=0. Това доказва candidate automation, не human usability.
- Apply wrapper изпълни същите pre-human gates, но case 1 беше cancelled с
  exit `130` на първия terminal observation. Guidance-ът не беше parallel с
  MOKOSH; picker-ът стартира в `/tmp`; wrapper fixture-ът беше `.txt`, скрит
  от default `*.mokr` filter; post-window questions останаха само в terminal.
- Human gate правилно блокира преди `live_apply()`. Последващият read-only gate
  доказа exact Stage 2.42 HEAD/tree/branch/tag, clean status и липсващ temporary
  fixture. Няма repository mutation, partial Stage 2.43 apply или waiver.
- Corrective runner създава един empty `.mokr` чрез exclusive/no-follow open,
  mode/owner/inode/size validation и exact cleanup преди report. Това е
  disclosed test-fixture filesystem mutation; MOKOSH application source open,
  read и mutation claims остават false.
- Немодален nine-step guide показва case/locale/scale/route и current action,
  confirmation, OK, exact picker Directory, keyboard и resize instruction.
  Няма event injection, automatic action invocation или automatic PASS.
- Graphical 11-question wizard започва всеки отговор като `not_checked` и
  disable-ва Next/Submit до explicit human selection. Cancel/FAIL/NOT_CHECKED
  е nonzero blocking result. Report schema version 2 записва guide/wizard,
  fixture disclosure/cleanup и точното
  `application_recovery_source_filesystem_mutation_performed=false`.
- Exact 22-path closure и единственият production target `mokosh_gui.py` не се
  разширяват. Нов package може да бъде издаден само след повторни 48/48,
  48/36/24, full 2144, archive/transaction/rollback и static boundary gates.

### Stage 2.43 R2 blocking stacking evidence и R3 correction

- R2 archive size е `212020`, SHA-256
  `54c95c688b32f1a86e54993fc509c6c0bd8a319aa9fdd3206328d7dcc2573a4a`.
  Dry-run и apply pre-human gates минаха 18/18 installer self-tests, 22/22
  rollback, 48/48 target, 48/36/24 predecessors и full 2144 regression.
- В BG/100 case 1 guide-ът се появи кратко, след което normal MOKOSH го покри.
  След затваряне observation wizard-ът също остана зад активния browser и беше
  намерен чрез window switching. Operator-ът използва explicit safe cancel;
  launcher exit `130` и installer fail-closed gate блокираха live apply.
- Последващият read-only gate доказа exact Stage 2.42 HEAD/tree/branch/tag,
  clean worktree и липсващ synthetic `.mokr`. Няма partial apply, waiver или
  скрит human PASS. R2 е withdrawn и не се retry-ва.
- Root cause е harness stacking/lifecycle order: guide `Toplevel` беше създаден
  преди normal main GUI construction и имаше само еднократен `lift`; wizard-ът
  нямаше explicit foreground invariant. R3 създава guide-а след main build,
  прилага mapped/topmost 500 ms watchdog без event injection и извежда wizard-а
  mapped/topmost/focused.
- R2 report v2 hardcode-ваше guide visibility, без отделно човешко observation.
  R3 report v3 добавя exact `parallel_step_guide_visible_and_usable` observation
  и извежда двата guide claims от него. Human matrix е 12 на case/48 общо;
  FAIL/NOT_CHECKED/cancel продължава да блокира преди live mutation.

### Stage 2.43 R3 clipped-controls evidence и R4 passive guide

- R3 archive size е `214655`, SHA-256
  `9bb059548948e57bf275b9ebda1aaf09f6d856641a389ee5944d34cd0e1ad535`.
  Dry-run мина 18/18 installer, 22/22 rollback, 48/48 target, 48/36/24
  predecessors и full 2144. Apply повтори същите pre-human PASS gates.
- В първия BG/100 case guide-ът остана foreground, но manual navigation control
  беше извън видимата work area. След main close graphical wizard се показа,
  но footer navigation/cancel controls останаха clipped при реалния desktop
  layout и body нямаше scrolling mechanism.
- Safe cancellation върна exit `130`; installer-ът блокира live apply.
  Показаното `invalid command name ..._keep_visible` е pending periodic Tk
  callback при destroy, не product exception, но остава blocking harness defect.
  R3 е withdrawn без retry или waiver.
- R4 guide използва six-phase auto progression от пасивно прочетени exact
  button `disabled`/`normal` states. Не променя command callbacks, не inject-ва
  input и не удостоверява PASS. Един root-owned 150 ms observer се cancel-ва
  explicit чрез `after_cancel` преди window release; няма recurring topmost
  callback върху унищожен Toplevel.
- R4 wizard поставя safe cancel и previous/next/save controls преди scrollable
  Canvas body. Question/choices имат visible vertical scrollbar; geometry се
  ограничава спрямо screen work area. Това е harness usability evidence, не
  accessibility/platform/legal certification.
- Preliminary R4 evidence е 48/48 target, 156/156 combined Stage 2.40–2.43,
  exact 22-path/diff/mode gates, headless four-scale structural layout 4/4 и
  pure passive transition sequence 6/6 PASS. Headless evidence не заменя
  authoritative human rendering на реалния desktop.

### Stage 2.43 R4 active-state failure и R5 resilient passive guide

- R4 deterministic archive е `218061` bytes, SHA-256
  `3680d1435bf96c45a58393d4205b9e3248323563374878e67e1a4e710c784952`.
  Laptop dry-run мина 18/18 installer, 22/22 rollback, 48/48 target,
  48/36/24 predecessors, full 2144 и extracted apply/test/rollback без live
  mutation. Apply повтори всички pre-human gates.
- В BG/100 case 1 operator-ът стигна до действие 3, докато guide marker-ът
  остана на действие 1. Observer-ът получи documented classic Tk transient
  button state `active`, което R4 validation погрешно отхвърли като invalid.
  Изключението беше uncaught вътре в Tk callback; user-ът прекрати matrix-а и
  exit `130` блокира live apply. Това е harness defect, не operator error.
- R5 допуска точно `normal`, `active` и `disabled`. Progress функцията избира
  най-далечния currently enabled action, така че пропуснат 150 ms intermediate
  poll не оставя guide-а назад. Fifth enabled state се помни и последващото му
  `disabled` преминава към финалната phase.
- Guide text съдържа current instruction и постоянен пълен шестфазен план в
  същия scrollable text widget; usable guidance не зависи само от timing-а на
  marker-а. Validation error се съхранява, main root се затваря fail-closed и
  `_run_case` отказва преди observation/apply, без uncaught callback traceback.
- Corrective 48-test target е PASS и симулира всичките четири cases, трите
  exact states, `active` на всяка последователна стъпка, прескачане до action
  3/5, full-plan content, invalid state/shape rejection и observer fail-closed
  path. Това остава automated evidence; реалната desktop matrix е задължителна.
- Final pre-package scratch closure е 156/156 Stage 2.40–2.43 и full
  2144/2144 PASS при точно три expected failures. Extracted candidate мина
  18/18 installer self-tests, 22/22 rollback injection, exact overlay, същите
  suites и exact rollback. Scratch средата няма `getfacl`, затова само този
  local read-only check използва еквивалентна липса на
  `system.posix_acl_access` xattr; distributed installer остава непроменен и
  ще изисква original `getfacl` gate на laptop-а. Scratch няма display, така че
  няма твърдение за actual rendered desktop PASS.

### Stage 2.43 R5 incomplete-keyboard-guidance failure и incident ledger

- R5 deterministic archive е `221299` bytes, SHA-256
  `bd59e6410c2f95a4422e46a28ce3d5c4dbaeb9ac569bff733c2f7eafc0b2ceed`.
  Laptop dry-run и apply pre-human gates минаха 18/18 installer, 22/22
  rollback, 48/48 target, 48/36/24 predecessors и full 2144 PASS.
- Cases 1–3 стигнаха до 36 human answers, записани като PASS. В case 3
  operator-ът посочи, че guide-ът описва `Tab`, `Shift+Tab` и връщане с `Tab`,
  но след това използва неясното „Активирайте“ без точната инструкция
  `натиснете Space`. Chat guidance е допълнила липсващата стъпка.
- Затова `parallel_step_guide_visible_and_usable=pass` и производните guide
  claims в трите JSON report-а не са приемливо self-contained evidence и са
  invalidated. Case 4 беше safe-cancelled; exit `130` блокира live apply.
  Няма partial overlay, accepted human matrix или waiver; R5 е withdrawn.

| Withdrawn revision | Наблюдаван дефект | Постоянна non-recurrence проверка |
| --- | --- | --- |
| R1 | terminal-only guidance/questions и невидим `.txt` fixture | GUI guide/wizard и exact visible `.mokr` |
| R2 | guide/wizard зад други прозорци | lifecycle order и explicit foreground presentation |
| R3 | clipped controls и pending callback | fixed top controls, scrollable body, cancelable observer |
| R4 | валидното `active` е отхвърлено; marker lag | exact three-state model и furthest-enabled recovery |
| R5 | липсва explicit `Space`; chat dependency | exact keystroke sequence и source/package token gate |

- От R6 human instruction completeness е release gate: всяко задължително
  operator input трябва да посочи exact control/key, реда и очаквания резултат.
  Chat не е част от harness-а и не може да допълва липсваща инструкция или да
  превръща такъв run в PASS. Target test изисква `Tab`, `Shift+Tab`, exact
  `натиснете Space`, purpose текста и правилния им ред и за двата fifth routes.

### Stage 2.43 authoritative R6 live и independent evidence

- R6 archive identity е size `223721`, SHA-256
  `2bcb0b6f5aa1f0d470e0791fff52ec2e96b6d60f7d65a278ceed6d998090d69d`.
  Deterministic scratch build беше byte-identical при две построявания и exact
  extracted package transaction мина 18/18 self-tests, 22/22 rollback
  injection, 48/48 target, 48/36/24 predecessors, full 2144 и rollback.
- Laptop dry-run повтори original `getfacl`, pinned Python/dependencies,
  ML-KEM-768, exact clean Stage 2.42 baseline, 22/22 rollback, всички suites и
  extracted apply/test/rollback; завърши с
  `STAGE2_43_DRY_RUN=PASS_NO_LIVE_MUTATION`.
- Apply pre-human gates повториха същите PASS резултати. Human matrix даде
  48/48 explicit PASS observations в exact cases: BG/100 initial/request,
  EN/125 initial/preserve, BG/150 resize-restore/preserve и EN/200
  resize-restore/request. Guide-ът беше self-contained, включително exact
  `Tab → Shift+Tab → Tab → Space`; synthetic `.mokr` беше премахнат преди
  всеки report.
- Четирите version-3 JSON report-а твърдят само bounded human observation.
  Те записват false за source open/read/mutation, capability, authorization,
  operation, Stage 2.32/2.41 activation, recovery secret, review preparation,
  memory-zeroisation proof и accessibility/legal/platform certification.
- След matrix-а extracted candidate rollback е PASS. Live overlay-ът беше
  приложен като `STAGE2_43_LIVE_APPLY=PASS_UNSTAGED_22_PATHS`; post-overlay
  target/predecessor/full suites отново са 48/48, 48/36/24 и 2144/2144 PASS
  при exactly three expected failures и zero skipped.
- Отделният post-apply gate потвърди exact 22 status без staged files, payload
  digests, modes, owner/group, plain ACL, diff-check, known-three-dangling
  strict fsck, unchanged Stage 2.42 HEAD/tree/branch, baseline tracked physical
  manifest, липсващ fixture и exact bytecode tuple преди/след още един full
  2144 PASS. Това е live candidate evidence; commit/tag остават забранени до
  final evidence amendment и отделен pre-commit gate.

## Stage 2.44 candidate evidence — secure reader hardening

- Проблемът е възпроизведен върху exact Stage 2.43 snapshot: стабилен canonical
  FIFO може да блокира стария reader; ancestor rename + symlink след lexical
  validation не се доказва от проверка само на final parent; POSIX read може да
  промени filesystem-managed `atime`.
- Поправката прави descriptor-relative root-to-parent traversal, задържа всички
  directory descriptors, revalidate-ва всеки link и затваря веригата в reverse
  order при success, ordinary exception и `BaseException`.
- Stable special file се отказва преди content-capable open. Race след pre-stat
  използва задължителен `O_NONBLOCK`, след което post-open regular-file и
  identity проверките отказват подменения object.
- Тестовете проверяват stable FIFO pre-open, deterministic FIFO race, ancestor
  rename/symlink interleaving, replacement по време на parse, terminal one-shot
  failure, descriptor cleanup и липса на заявени write/chmod/fsync/unlink/
  rename/replace/utime calls.
- `filesystem_mutation_performed=False` е application-call claim, не forensic
  no-atime-change гаранция. Structural parse не е AEAD authentication.
- Това е candidate engineering evidence. Final authoritative laptop package,
  exact physical/ACL gate и full regression остават задължителни.

## Stage 2.44 authoritative R1 package/apply evidence

- R1 archive identity: size `210357`, SHA-256
  `c6553fc9c9e3dfdf8fd71a78e2e6ffe33805e08bf1857987bfba9df6df88b676`;
  exact inventory е 26 safe normalized members с 20 payload files.
- Installer identity: size `27600`, SHA-256
  `93ea95534081198c0b19ee3a0ad62b86e0ef0b5e3020c0892f394e907443ce6f`.
  Runtime gate пази lexical `~/venv_sys/bin/python3` и използва baseline
  `_mlkem_module()` за real encapsulate/decapsulate roundtrip.
- Authoritative dry-run: Stage 2.43 HEAD/tree/branch/tag, 211 tracked paths,
  113 commits, zero merges, 72 annotated tags, exact three dangling prefixes,
  physical manifest, owner/modes/plain ACL и 4341-record bytecode са PASS.
  Rollback injection е 20/20; target е 456/456; full е 2152/2152 с точно три
  expected failures и zero skipped. Live mutation няма.
- Authoritative apply повтори candidate gates и след exact 20-path transaction
  даде post-overlay 456/456 и 2152/2152 PASS. Final marker е
  `STAGE2_44_R1_LIVE_APPLY=PASS_UNSTAGED_20_PATHS`.
- Independent verifier identity: size `19044`, SHA-256
  `c047a6d8b5551b4d6f47ad1f49bed60b3284820ca57ffcba5f8dc65ddb2955c7`.
  Той не използва apply transaction code и потвърди exact package/live binding,
  20-path status, no staging, diff-check, modes/owner/ACL, physical manifest,
  fsck, bytecode и още един 456/2152 PASS cycle.
- Scratch full discovery не беше authoritative, защото scratch runtime няма
  `argon2`; той изпълни 2123 теста и даде три import errors плюс седем skips.
  Точната laptop среда с `argon2-cffi 25.1.0` изпълни всички 2152 без skip.
- Два локални test invocations върху delta payload бяха невалидни orchestration
  опити: първият беше от грешна working directory, вторият — без останалите 192
  baseline files. Те не са product runs; corrected exact baseline-plus-overlay
  run е 456/456 PASS.
- Pre-release review хвана преди user execution две installer regressions от
  стара история: venv `.resolve()` и nonexistent `ml_kem`. Final archive е
  rebuild-нат с lexical path и project `mlkem` boundary; само тази final SHA-256
  identity е използвана на laptop-а.
- Няма hard real-time, forensic no-atime-change, kernel-compromise,
  accessibility, legal applicability/conformity или certification claim.
  Final evidence-document bytes трябва да минат нов regression преди commit.

## Stage 2.45 candidate evidence — normal-GUI authorization readiness/privacy audit

- Exact Stage 2.44 laptop baseline е read-only verified: commit `77c9432`, tree
  `5b60a85`, branch/tag/status, 212 tracked paths, 114 commits, zero merges, 73
  annotated tags, pinned Python 3.12.3/argon2-cffi 25.1.0/cryptography 49.0.0,
  ML-KEM-768 и full 2152 PASS при точно три expected failures и zero skips.
  Post-test physical/bytecode state е непроменен; fsck показа само exact трите
  известни dangling blobs. Project mutation не е извършена.
- Static архитектурният review потвърди, че normal-GUI петото действие връща
  Stage 2.31 outcome, без Stage 2.32 import/call/read, а Stage 2.32 вече съдържа
  отделния exact positive authorization decision и one-shot secure reader.
- Audit contract-ът изисква бъдещо отделно шесто действие/confirmation,
  exact-positive Stage 2.31 → Stage 2.32 binding, terminal fail-closed lifecycle,
  pre-loader/pre-dialog clearing, path-free errors/results и никаква automatic
  Stage 2.39–2.41 review activation.
- Privacy evidence границата отказва secret/path/content/log/network/persistence,
  cryptographic-authentication, recovery-proof, global-consumption и memory-
  zeroization claims. POSIX read може да промени filesystem-managed `atime`;
  observed identity не е future guarantee.
- Бъдещият human test не може да чете harmless empty file директно от shared-
  mode Downloads. Fixture contract изисква runner-owned `0700` subdirectory,
  structurally valid synthetic non-secret canonical `.mokr` с `0600`, exact
  type/owner/link/identity checks и fail-closed cleanup при всеки exit route.
- Candidate result е `GO WITH BLOCKERS`, не production authorization. Exact
  isolated candidate даде 32/32 new audit tests и 205/205 combined relevant
  tests. Scratch full discovery не е authoritative за pinned dependencies;
  deterministic package и authoritative laptop 2184-test dry-run/apply evidence
  остават pending и няма предварително PASS твърдение за тях.

### Stage 2.45 R1 withdrawn installer-exit incident

- Laptop R1 потвърди exact 12-member archive, pinned runtime, clean Stage 2.44
  baseline, 4341 bytecode records, known-three-dangling fsck, 6/6 rollback,
  32/32 target, 205/205 combined и 2184/2184 full regression при точно три
  expected failures и zero skips.
- Installer-ът издаде `STAGE2_45_R1_DRY_RUN=PASS_NO_LIVE_MUTATION`, след което
  top-level `except BaseException` прихвана собствения `SystemExit(0)` и го
  представи като `FAIL_SystemExit: 0`. Това е installer orchestration defect,
  не product/test failure; shell wrapper правилно не издаде final PASS.
- R1 е withdrawn и не може да се използва за apply. No-live-mutation gate-ът е
  завършил преди defect-а и project repository остава baseline. R2 трябва да
  отдели успешния return/`SystemExit` от exception handler и да повтори целия
  dry-run; няма waiver или credit/time shortcut.

### Stage 2.45 authoritative R2 package/apply/post-apply evidence

- R2 package identity е size `149309`, SHA-256
  `5ed4b80a5ace17acfb400c8c6225eb849168764a8f0859260c559714aa0bd4c7`;
  exact archive inventory е 12 safe normalized members с six-path payload.
- R2 dry-run потвърди 12/12 installer self-tests, Python 3.12.3,
  argon2-cffi 25.1.0, cryptography 49.0.0, ML-KEM-768, exact clean Stage 2.44
  baseline, 4341 bytecode records, known-three-dangling fsck и 6/6 injected
  rollback. Candidate suites са 32/32, 205/205 и full 2184/2184 при точно три
  expected failures и zero skips. Final marker доказва no live mutation.
- Transactional apply повтори всички candidate gates, приложи exact six paths
  unstaged и върху live overlay повтори 32/32, 205/205 и 2184/2184 със същите
  expected-failure/skip граници. Apply marker-ът е
  `STAGE2_45_R2_LIVE_APPLY=PASS_UNSTAGED_6_PATHS`.
- Independent verifier identity е size `21027`, SHA-256
  `02c72b8f401ae96b1cb2490c71c3a2141085170c784f89403551ce9397851d98`.
  Отделният read-only код потвърди exact package/live bytes, six-path status,
  no staging, Git diff-check, 214 physical records с frozen mode distribution,
  current owner/plain ACL, 8 critical production hashes, known-three-dangling
  fsck и baseline HEAD/tree/branch/tag/history.
- Independent target/combined/full suites отново са 32/205/2184 PASS, точно три
  expected failures и zero skips. Post-test physical/status и 4341-record
  bytecode snapshots са unchanged. Това е authoritative live-candidate
  evidence; final document bytes все още трябва да минат amendment regression
  и independent pre-commit gate.
- Няма source read, Stage 2.32 invocation, automatic Stage 2.39–2.41 activation,
  recovery/operation, GUI, crypto, Vault, Contacts или network промяна. Няма
  human visual waiver: human matrix не е приложима към byte-exact GUI delta.

### Stage 2.45 final-evidence R1 withdrawn extraction-validator incident

- Final-evidence R1 е `148782` bytes, SHA-256
  `178dabddb077e564ae0ff802e6e4caa70b33a44140cd3f8d49220243cec81d12`.
  Преди extraction wrapper-ът е потвърдил current-user regular archive, exact
  size/hash/mode и exact 10 safe normalized members без link/device/FIFO entry.
- При Python 3.12 `tarfile.extractall(filter="data")` directory modes не се
  пренасят като file modes. Под `umask 0077` трите package directories са
  създадени `0700`; седемте regular files са `0644`. Това е по-строга private
  extraction граница от archived `0755` directories.
- Външният post-extraction validator е сравнил directory modes с archive
  metadata `0755` и е издал `REFUSED_EXTRACTED_METADATA_MISMATCH`. Installer-ът
  не е стартиран; няма self-test/test/apply marker и няма repository mutation.
- R1 е withdrawn без retry или waiver. R2 приема/налага exact private `0700`
  extracted directories, продължава да изисква exact `0644` regular files и
  запазва safe member/type/owner/size/path проверките преди installer dry-run.

### Stage 2.45 final-evidence R2 withdrawn pre-commit whitespace incident

- R2 package/apply/independent suites са валидни за проверените exact bytes.
  Pre-commit transaction staging-ът обаче е направил новия audit документ
  видим за `git diff --cached --check`, който е отказал точно редове 3–5 за
  trailing spaces.
- Предишният `git diff --check` е проверил tracked diff, но не untracked audit
  файла. Това е verifier coverage gap; не е product failure и не разрешава
  заобикаляне на repository quality gate.
- Failure cleanup е изпълнил targeted unstage. Read-only follow-up потвърди
  baseline HEAD, липсващи commit/tag/staging, exact six R2 hashes и само трите
  очаквани whitespace findings.
- R3 трябва да премахне точно тези bytes, да запише инцидента и да изпълнява
  direct trailing-space/tab scan върху всички allowlisted files преди tests и
  след overlay. R2 не може да бъде преетикетиран с новите hashes.

### Stage 2.45 final-evidence R3 withdrawn strict-fsck incident

- R3 package identity е size `152247`, SHA-256
  `6e8af78dfe572d5cd235321c84ab6c54aef1ee09063a657be4b11aa306869ca3`;
  runner identity е size `8726`, SHA-256
  `2564d01712c187b9cec02871868884cf8bef9c8c32e023aa6e39b6a3d27b41bf`.
- Runner 12/12 self-tests, exact 10-member private extraction, installer 15/15
  self-tests и pinned runtime/ML-KEM са PASS. Baseline gate стигна до fsck и
  отказа, защото R3 все още pin-ваше historical three-blob inventory.
- Read-only independent classification установи exact девет dangling blobs.
  Historical са `554747253ca77d56227d22bee18daf50e714ba66`,
  `8c7cc588b5ece4a607a059951677d147029480c3` и
  `f645d4de7b9d4224d028af72455b82b2a2dafdf2`. Останалите шест са exact
  content matches за R2 staged audit/test/document bytes: `5ad5e3b9`,
  `76cb9782`, `823c35f0`, `c0b802cc`, `c62e9864`, `c9dcf69b`.
- Новите blobs са Git object-store side effect от failed pre-commit `git add`;
  worktree/index cleanup не ги премахва. R3 е спрял преди rollback candidate,
  tests или overlay и не е променил live project files.
- R4 не prune-ва и не скрива evidence. То валидира exact object type, пълен
  OID, size и content SHA-256 за деветте records и изисква точно шестте R2
  matches. Dynamic/unknown dangling acceptance остава забранено.

## Stage 2.45.1 — legacy contact security-stabilization evidence contract

Authoritative laptop read-only Gate 1–3 са изпълнени върху clean Stage 2.45
commit `6c5d14a18f2184d247a700154add1a02d39d3358` без project mutation.

- Gate 1: static inventory потвърждава active duplicate legacy definitions,
  липса на exact contact-core runtime test и отделен правилно реализиран V2
  contact-slot core. Name-reference inventory не се представя като defect
  count.
- Gate 2: pinned real `cryptography 49.0.0` execution потвърждава правилния
  ML-KEM-768 contract и три независими legacy defects: swapped encapsulate
  return binding, nonexistent private-key constructor и truncated unwrap tail.
  Synthetic X25519 helper round-trip PASS не е contact-flow PASS.
- Gate 3: isolated synthetic Alice/Bob execution потвърждава reciprocal-id
  failure, silent PQ-to-classic fallback, accepted removal/rewrite на
  unauthenticated metadata и Base64 private material извън Key Vault. Temp
  artifacts са изчистени и final repository е exact Stage 2.45.

Candidate verification трябва да доказва, без skip или expected-failure waiver:

1. exact 20-path delta и exact predecessor base;
2. tombstone AST без runtime imports/functions и unconditional typed raise;
3. fresh `-I -B` subprocess import refusal преди data-directory side effect;
4. byte-exact normal GUI и V2 contact-slot core;
5. exact нов tombstone SHA-256 във всичките десет съществуващи hash gates;
6. targeted quarantine/safety tests, засегнатите predecessor tests и full
   regression с точно историческите три MOK1 expected failures и zero skips;
7. rollback, diff-check, owner/mode/plain-ACL, fsck и bytecode invariants.

`PASS` на quarantine gate доказва единствено, че unsafe legacy capability е
недостъпна и няма observed side effect. То не доказва работещ V2 contact
application flow, key migration, Key Vault integration, GUI contact функция,
public-release readiness, compliance, certification или independent audit.

Първият affected candidate run е изпълнил 414 tests и е отказал точно един
second-order predecessor hash. Recursive baseline-hash graph е добавил точно
два test consumers към scope-а. Corrected 20-path re-freeze е приет преди
промяната им; assertions остават активни и получават exact recomputed child
hashes. Това е integrity dependency correction, не test waiver.

След re-freeze повторният affected gate е 414/414, двата newly admitted parent
audit модула са 80/80, а exact combined affected set е 494/494. Scratch full
regression е 2191/2191 с точно три historical MOK1 expected failures и zero
skips. Използваният scratch runtime е Python 3.12.14 с exact
`cryptography 49.0.0` и `argon2-cffi 25.1.0`; authoritative Python 3.12.3
laptop evidence остава задължително.

Първият local exact-delta predicate е отказал преди package build заради
грешно ръчно преписан expected baseline `contacts_core.py` digest. Няма
candidate mutation. Коригираният gate извлича digest-а директно от exact
baseline и потвърждава 20-path allowlist, 12 hash-consumer files и точно 14
предварително моделирани substitutions. Първият multi-document patch на този
record също е отказан изцяло без mutation поради несъвпадащ context; отделните
document patches запазват exact freeze.

Pre-package static review е отказал предложен lexical installer self-test,
който би намерил forbidden import spelling в собствения си diagnostic literal.
Той е заменен преди package issuance с AST проверка на действителните
asymmetric import aliases, включително negative forbidden-alias assertion.

Първият package build е спрял преди artifact creation, защото scratch runtime
няма `getfacl`. Release profile не приема fallback: той изисква real plain-ACL
inspection и exact authoritative physical digest. Само недоставяният QA
profile използва ясно означен mode-derived ACL model/local shim за end-to-end
control-flow testing; това не е laptop ACL evidence.

Първата local QA launch команда е отказана преди execution от workspace safety
policy, защото е съдържала shell recursive cleanup. Няма clone, package run или
project mutation. QA lifecycle е преместен в scoped `TemporaryDirectory`
driver; release runner bytes и frozen scope не са променени от тази корекция.

Първият изпълнен pre-issuance QA twin е отказал в installer self-tests поради
два синтактично незатворени unittest-summary regex литерала. Baseline read и
project mutation не са започвали, temporary home е изчистен, а build identities
`235610`/`1e018f9b…` и `12298`/`18668650…` са withdrawn преди user issuance.
Corrected template затваря patterns и добавя AST compilation gate за всички
literal regex-и. Това е correction failure 1; failure 2 задейства safe stop.

Correction QA twin 2 е минал 13 installer self-tests и реални pinned Argon2id,
ML-KEM-768, X25519 и AES-GCM probes, но exact physical baseline gate правилно е
отказал mode mismatch. QA clone creation е наследило `umask 0077` и е получило
`0600/0700`, докато QA manifest-ът моделира source clone `0644/0755`. Не са
стартирали rollback/candidate tests или project overlay; temporary residue е
zero. Identities `236519`/`d64f9248…` и `12298`/`6e418430…` са withdrawn.
Correction failure 2 задейства stop; няма трети package attempt без explicit
recovery decision. Release laptop profile не е изпълняван и не се твърди PASS.

След explicit recovery re-freeze mode-preserving QA copy и един fresh QA cycle
са PASS, включително 20/20 rollback и 10/494/2191 suites. Authoritative laptop
R1 въпреки това е отказал след runtime probes и преди candidate creation:
`contacts_core.py` не е physical mode `0644`. Release manifest-ът погрешно е
моделирал всички 18 existing targets от normalized Git clone. Git content mode
не носи физическата owner-read/write разлика, а QA fixture и verifier са
използвали един и същ неправилен oracle; следователно QA PASS не е доказвал
authoritative per-target modes.

Outer launch `line=73` е generic propagation line `bash "$runner"`; root cause
е вътрешният baseline gate. Archive `237250`/`76c01ea8…` и runner
`12298`/`1f0ae760…` са withdrawn. Failure control flow е преди candidate tests
или project overlay. Live exact-mode/no-mutation diagnostic и нов explicit
scope са задължителни преди correction.

Authoritative read-only diagnostic след R1 отказа потвърди clean HEAD
`6c5d14a18f2184d247a700154add1a02d39d3358`, zero status/residue и exact
content binding `18/18`. Физическите режими на съществуващите targets са
`2×0600`, `11×0644`, `5×0664`, всички с UID/GID `1000:1000`. Non-`0644`
targets са `contacts_core.py`, `tests/test_stage0_safety.py` и петте
source-inspection acknowledgement/execution/localization/presentation/
ui-adapter tests.

Това е повторение на вече документирания Stage 2.41/2.42 клас инцидент, а не
нова неизвестна особеност. Записаната превантивна мярка — individual physical
mode map и забрана Git `100644` да се тълкува като POSIX `0644` — не е била
приложена при Stage 2.45.1 R1. Това е process-control recurrence и R1 local QA
PASS е невалиден като доказателство за authoritative target metadata, защото
QA fixture, manifest и verifier са споделяли един и същ грешен oracle.

R2 correction не променя exact 20-path product scope. Manifest, installer и
outer wrapper съдържат и сравняват exact 18-path authoritative map;
baseline/apply/rollback запазват индивидуалния режим. Installer self-test
инжектира mode drift за всеки от 18-те paths. Отделен negative wrapper test
разменя един `0600` и един `0644` path при запазени aggregate counts и трябва
да откаже преди installer execution. Двата нови quarantine paths остават
explicit design decision `0600`, а не измерен baseline факт. Нито local QA,
нито този record заместват authoritative laptop dry-run/apply evidence.

Authoritative R2 laptop dry-run е PASS без mutation: wrapper exact mode map,
14 installer self-tests, pinned Python `3.12.3` primitives, physical baseline
`f4b57b…`, 20/20 rollback, `10/494/2191` suites, exactly three historical
expected failures, zero skips и zero candidate residue. Преди издаване на
apply wrapper отделен temporary-repository apply QA е отказал fail-closed след
candidate PASS. `verify_candidate_source` е приложил exact extracted-tree
inventory predicate върху live Git repository и правилно съществуващите
`.git`/bytecode records са били отчетени като inventory drift. Installer
rollback е възстановил baseline-а, temporary repository е изчистен и laptop
repository не е участвал.

R2 следователно остава валиден само като historical dry-run evidence и е
withdrawn/forbidden за apply. R3 разделя двата доказателствени домейна:
extracted candidate продължава да изисква exact whole-tree inventory, докато
live repository проверява exact selected 216 source paths заедно с отделните
Git status, tracked inventory, physical metadata, fsck и bytecode gates.
Regression self-test доказва, че live `.git`/pre-existing bytecode не се
представят като candidate source, а extracted candidate не може да ги приеме.

R3 pre-issuance QA върху private temporary repository е PASS за двата отделни
пътя. Dry-run изпълнява 15 installer self-tests, real pinned primitives,
20/20 rollback и candidate `10/494/2191`. Apply QA повтаря candidate
`10/494/2191`, прилага exact 20 unstaged paths и изпълнява отделни live
`10/494/2191`, exactly three historical expected failures и zero skips.
Post-apply wrapper потвърждава exact status, target bytes/modes/owner/group,
critical hashes, tracked count, no staging и diff-check. Temporary repository
cleanup е PASS. Runtime-ът е scratch Python `3.12.14`; резултатът не доказва
authoritative laptop Python `3.12.3`, physical baseline или live apply.

## Stage 2.45.2 MOK1 evidence contract

Authoritative read-only diagnostic върху clean Stage 2.45.1 възпроизвежда
валиден historical MOK1 roundtrip и отделно потвърждава всички заявени
negative свойства: unauthenticated/plaintext metadata, ignored algorithm,
unknown-KDF fallback, oversized header, overwrite, output symlink following,
caller-umask `0644`, delimiter collision и четири whole-file reads. Този PASS е
discovery evidence, а не security PASS на стария implementation.

Exact recursive dependency closure доказва 20 и само 20 direct predecessor
tests, които pin-ват SHA-256 на `crypto_core.py`, и още два second-order tests,
които pin-ват пет от променените predecessor tests. Шеста second-order edge е
между два tests, които вече са сред 20-те direct consumers. Окончателният
freeze е 30 paths и съдържа точно 26 hash edges, без външен consumer.
Първоначалният 28-path резултат е оттеглен като непълен преди project mutation.
Двата direct crypto test модула заменят production-writer roundtrips с
independent fixed historical Argon2id/PBKDF2/raw-key fixtures.

Задължителните practical gates за candidate и live state са:

- двата MOK1 writer entry points отказват преди source/output/KDF/randomness;
- exact historical fixtures се декриптират byte-for-byte;
- wrong password/key, ciphertext/tag tamper и source replacement не публикуват
  output и не оставят owned temp/journal residue;
- malformed/duplicate/oversized JSON, unknown alg/KDF и attacker-selected KDF
  costs се отказват преди expensive KDF или plaintext output;
- existing output и output/source/parent symlinks не се следват или променят;
- output е regular, one-link `0600` дори при caller `umask 0000`;
- multi-megabyte payload доказва bounded reads и exact result;
- tampered advisory metadata остава честно възпроизведена като historical
  limitation, но не управлява path, permissions, algorithm или trust;
- `unittest.expectedFailure` inventory за MOK1 става zero без твърдение, че
  старият header е ретроактивно authenticated;
- exact delta, rollback injection, targeted/affected/full regression, residue,
  Git/physical/ACL/fsck/bytecode и byte-exact GUI/contact boundaries минават
  отделни gates.

Local scratch evidence и package self-tests не заменят authoritative laptop
dry-run/apply. Няма предварителен PASS, standards conformity, certification
или market-release claim.

## Stage 2.46 protected profile/session evidence — 2026-09-11

### Проверени свойства на изолирания кандидат

- Profile descriptor е canonical bounded UTF-8 JSON с duplicate-key refusal,
  exact fields и public nickname metadata; няма password/private/recovery key.
- Profile root/descriptor/Key Vault generation са проверени за Linux object
  type, owner и exact `0700/0600` права. Symlink, unknown object, malformed,
  partial и insecure-mode състояния отказват без repair или overwrite.
- Existing schema-2 Key Vault се създава с Argon2id/AES-GCM core, публикува се
  чрез immutable no-clobber generation и се отваря/удостоверява наново преди
  public descriptor publication.
- Injected pre-Vault failure оставя explicit `PARTIAL`, което блокира retry и
  доказва, че interrupted create не се приема за clean first run.
- `SecureProfileSession` доказва explicit login, generic failure, password
  field clear, 15-minute inactivity policy, manual/panic/close lock и
  monotonic/wall-clock/suspend fail-safe paths.
- Capability registry изброява и отрицателните actions; само historical MOK1
  decrypt може да стане `true` след unlock.
- Legacy GUI boundary изисква exact boolean authorization и подава source,
  нов output, стара password и стар nickname към hardened
  `crypto_core.decrypt_file` в правилния API ред. Нов writer/delete/overwrite
  path не се добавя.
- Existing legacy `seed_store.enc` / `seed_meta.json` се маркират само чрез
  exact-name `lstat` и остават byte-exact. Normal profile modules не import-ват
  `seed_manager`.
- EN/BG каталогът има exact еднакви keys и strict format values. Test-only
  pseudo locale и human visual matrix покриват 100/125/150/200%, locked и
  unlocked изгледи без profile/file operation data.

### Реално изпълнено в scratch

- new Stage 2.46 suites: `62/62`, failures/errors/expected failures/skips `0`;
- пет съществуващи normal/recovery GUI suites: `133/133`, zero non-pass;
- 15 exact hash-consumer/affected suites: `472/472`, zero non-pass;
- isolated exact-dependency full discovery: `2279/2279`, failures/errors/
  expected failures/unexpected successes/skips `0`, с real ML-KEM-768;
- in-memory compile на всички 8 runtime/harness и 7 test files: PASS;
- `git diff --check`: PASS;
- recursive predecessor-hash closure: всички открити consumers са вътре в
  exact 35-path freeze; няма доказан outside-scope consumer.

Scratch runtime е Python 3.12.14 с `cryptography 46.0.0`; няма инсталиран
`argon2-cffi` и ML-KEM module. Новите profile storage tests използват реалния
`cryptography` Argon2id/AES-GCM. Предшествениковите suites, които import-ват
historical `crypto_core`, са изпълнени с ясно обозначен QA-only Argon2 API
compatibility shim, реализиран върху същия `cryptography` Argon2id. Това не е
release dependency, не е добавено в project files и не е authoritative
primitive/full-suite PASS.

За пълния QA е създаден отделен temporary venv върху същия Python 3.12.14 и са
инсталирани exact project dependencies `cryptography 49.0.0` и
`argon2-cffi 25.1.0`. Correct `cryptography.hazmat.primitives.asymmetric.mlkem`
probe и full discovery са PASS `2279/2279`. Този venv не е project artifact и
не променя изискванията. Разликата Python 3.12.14 срещу авторитетния 3.12.3
остава причина laptop gate да не може да бъде пропуснат.

### Оставащи задължителни gates

- exact `$HOME/venv_sys/bin/python3` identity: Python 3.12.3, isolated prefix,
  `cryptography 49.0.0`, `argon2-cffi 25.1.0`, Tkinter и ML-KEM-768;
- deterministic installer self-tests, exact baseline/mode/ACL/inventory и
  per-target rollback injection;
- повторение на new, affected и full `2279` regression с exact laptop Python
  3.12.3 без skip или expected failure;
- practical visual observations в реалния Tk runtime;
- dry-run доказано без live mutation, отделен explicit apply, post-apply full
  regression и independent verifier;
- Windows/macOS native filesystem, GUI, packaging/signing/notarization tests в
  бъдещи отделни stages.

Следователно текущото доказателство е `IMPLEMENTED-ISOLATED / LOCAL-QA-PASS`,
не Stage PASS, release readiness, independent audit, certification или legal
conformity.

### Pre-issuance package QA

Exact 35-path payload премина deterministic QA-profile wrapper/installer
self-tests, `35/35` per-target rollback injections и candidate regression
`62/62`, `472/472`, `2279/2279` без non-pass или residue. Baseline physical,
ACL, Git, dangling-object и bytecode evidence беше повторен byte-exact след
dry-run. Отделен disposable test извика exact shipped `live_apply` функцията,
после повтори live `62/62`, `472/472`, `2279/2279` и доказа exact 35 unstaged,
zero staged и zero bytecode residue.

Четири безопасни tooling stop-а не се скриват: Markdown trailing-space gate и
грешно име в critical immutable allowlist отказаха преди artifact; scratch
filesystem-ът отказа ownership remap на temporary non-root fixture. Последният
случай беше обходен само в QA driver, а не в издавания код: двата shipped root
refusal gate-а остават задължителни и се self-test-ват. Отделно първото
повторно QA dry-run извикване пропусна temporary `HOME` и exact interpreter
identity gate отказа преди extraction/repository access; explicit QA `HOME`
коригира invocation-а, без промяна или отслабване на gate-а.

QA runtime е Python 3.12.14 с exact dependency versions. Final R1 се изгражда
детерминистично след тези documentation bytes и има собствен source/archive
self-test, но авторитетният Python 3.12.3 dry-run и практичният Tk визуален
преглед остават задължителни. Няма предварително live apply, Stage PASS,
certification, audit или Windows/macOS native claim.

### Authoritative R1 bytecode stop и R2 correction

R1 user dry-run потвърди exact Python 3.12.3 и всички primitive versions, но
последният baseline bytecode gate отказа преди payload/test/mutation. Exact
diagnostic запази броя и типовете `4341 = 4086 files + 255 directories`, а
общият digest стана
`914e83be4f131de233a62dfca6da683485f6d48f1a1aacca96da1252db04d362`.

Доказателствената верига е конкретна: root cache directory и
`crypto_core.cpython-312.pyc` имат 2026-09-11 10:55:31 local mtime, 12 секунди
преди GUI снимката. Tracked `crypto_core.py` остава exact SHA-256
`a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62`;
cache е regular non-symlink `0600`, timestamp-based, embedded mtime/size
съвпадат и independent rebuild е byte-identical SHA-256
`b419ee7a1338d6f6dd395e95ae57fee748133cd00728cc49afbb36bd33046ba9`.

Следователно R1 е оттеглен за exact-baseline mismatch, а не за project или
crypto defect. R2 запазва strict invariant и exact 35-path freeze; коригира
само revision/baseline binding и evidence. При издаване той трябва да има нов
пълен local QA и двойно deterministic build. User dry-run с реалния Python
3.12.3 остава задължителен и live apply не се разрешава предварително.

Първият R2 pre-issuance cycle е PASS: 16 self-tests, `35/35` rollback,
candidate и disposable-live `62/62`, `472/472`, `2279/2279`, без non-pass,
staging или bytecode residue. Понеже този резултат се добавя в frozen evidence
bytes, final issuance изисква и получава отделен fresh QA cycle върху exact
documented payload; user Python 3.12.3 dry-run остава независим следващ gate.

### Authoritative R2 apply и human R3 correction gate — 2026-09-12

- Authoritative R2 dry-run и live apply на Python 3.12.3 са PASS: exact
  runtime/primitives, `35/35` rollback, candidate/live `62/62`, affected
  `472/472`, full `2279/2279`, zero non-pass и exact 35 unstaged paths.
- Независимият post-apply verifier потвърди exact package SHA-256, physical
  SHA-256 `54208fb61eaa7734c7c8fae89dc61338b8d7fa308f206ac502da2d21fdd340b2`,
  4341 bytecode records, source syntax, Git/history/fsck/ACL границите и
  unchanged state. Browser-created package mode `0664` беше fail-closed
  открит и ограничен до `0600` преди успешния verifier run.
- Practical visual Case 1 (`EN`, 100%, `LOCKED`) е blocking `FAIL`. Реалният
  caret и enabled state са видими, но всеки знак изчезва веднага. Source review
  доказа, че global `_user_activity` изчиства двете credential variables при
  всяка активност, когато READY profile има съществуваща locked session.
  Следователно дефектът засяга normal production route, не само synthetic
  harness-а.
- Предходните тестове доказват login резултатите и credential clearing след
  success/failure/lock, но не изпълняват Tk locked-entry event sequence.
  Автоматичният `2279/2279` PASS не заменя отрицателния human gate.
- User-ът прие exact 7-path R3 corrective freeze, изцяло вътре в вече приетите
  35 пътя. Activity timer се докосва само при `UNLOCKED`; locked credential
  entry се запазва; transition от unlocked към non-unlocked продължава да
  изчиства двете полета и да обновява изгледа. Добавени са три отделни logic
  regression теста; focused module е `14/14` PASS в scratch.
- Exact-dependency R3 target `65/65`, affected `472/472` и full `2282/2282`
  са PASS с zero non-pass и zero bytecode residue. Deterministic corrective
  package, authoritative dry-run/apply, независим post-apply и повторение на
  целия human visual matrix остават задължителни. Няма Stage PASS, commit/tag,
  release-readiness, certification или compliance claim.

### R3 pre-issuance corrective-package QA

- QA package валидира exact R2 worktree със същите 35 unstaged пътя, 217
  tracked и 15 отделно pin-нати untracked sources; R3 payload е exact седем
  съществуващи пътя и не създава нов файл.
- Wrapper dry-run премина 16 installer self-tests, pinned real primitives,
  `7/7` failure-position rollback плюс success rollback, candidate
  `65/65`, affected `472/472`, full `2282/2282` и повторно byte-exact
  доказана непроменена база.
- Две независими QA сглобки са byte-identical. QA-only driver извика exact
  shipped `live_apply` върху disposable repository; режимите се запазиха,
  status остана exact 35 unstaged и isolated post-apply suites повториха
  `65/472/2282` без non-pass или source/bytecode residue.
- QA runtime е Python 3.12.14 с exact dependency versions и не замества
  авторитетния `$HOME/venv_sys/bin/python3` 3.12.3. Понеже този запис променя
  frozen evidence bytes, final artifact се изгражда и проверява наново след
  него. Няма предварителен user apply, Stage PASS, commit или tag.

## Stage 2.46 R4 first-run modal corrective evidence — 2026-09-12

R3 independent post-apply е PASS, а повторният human main-window оглед
потвърди първата корекция. Следващият practical first-run тест откри отделен
blocking дефект: малкият modal прозорец показва caret, но неговите три entry
полета не приемат typing или paste. Тестът е спрян преди profile creation.

Root-cause и coverage evidence:

- `FirstRunProfileWindow.__init__` е придобивал Tk grab преди `_build()` и
  преди visibility и не е насочвал focus към initial entry;
- main visual runner е изключвал first run чрез
  `auto_first_run_prompt=False`;
- backend integration е доказвал storage create/locked/login state, но не е
  създавал Tk widgets;
- R3 regression тестовете са доказвали само главните login variables и global
  activity routing. Следователно 2282 automated PASS не се преинтерпретират
  като доказателство за непроверения modal input path.

R4 controls и проверки:

- modal activation има exact `wait_visibility` → nickname `focus_set` →
  `grab_set` ред след завършен `_build`;
- трите Entry обекта се пазят изрично; close изчиства nickname/password/
  confirmation, освобождава grab и е idempotent;
- main window пази най-много една жива first-run инстанция;
- synthetic controller изпълнява само in-memory create/login/lock и не вика
  `create_profile`, `load_profile`, file chooser, network или crypto operation;
- bounded visual evidence изисква девет observations за focus, typing, paste,
  masking, locked return, main input, post-login clearing, unlocked/lock UI и
  manual re-lock;
- отделен automatic visible-state test съчетава successful controller state,
  празни credential variables, BG `ОТКЛЮЧЕНО`, button `ЗАКЛЮЧИ`, disabled
  unlocked entries и обратно `ЗАКЛЮЧЕНО`/`ВХОД` след manual lock;
- localization test pin-ва `Почисти оригинали...`.

Първият scratch invocation на GUI tests спря при import, защото temporary QA
Python не намери собствената си `libtcl9tk9.0.so`. Седем localization tests
минаха, но частичният run не е броен като suite PASS. След възстановяване на
runtime-owned library path exact target е `76/76`, affected `472/472`, full
`2293/2293`, zero non-pass. Това е QA environment linkage incident преди
project execution, не product failure и не waiver. Exact final-document bytes,
package rollback/dry-run/apply и user-machine visual result остават pending.

### R4 pre-issuance corrective-package QA

- Един планиран fresh full-suite command не стартира, защото асистентът беше
  изписал погрешен QA interpreter path с фрагмент `344641lish`. Няма изпълнен
  тест или project mutation от тази команда и тя не е броена като PASS.
  Незабавното повторение с exact валидирания interpreter завърши
  `2293/2293`, zero non-pass. Preventive правило: interpreter path се pin-ва
  веднъж и се проверява като regular executable преди suite invocation.
- Предварителният exact R4 package dry-run върху отделна R3 база премина 16
  installer self-tests, pinned real primitives, `12/12` failure-position
  rollback плюс success rollback, candidate `76/76`, affected `472/472`, full
  `2293/2293`, zero non-pass, zero residue и повторна exact baseline проверка.
- QA-only driver извика exact shipped `live_apply` върху disposable copy.
  Static/delta gate, live `76/472/2293`, exact 35 unstaged paths и post-test
  source state са PASS; authoritative R3 source не е променян.
- QA runtime е Python 3.12.14 с exact dependency versions и не се представя
  като user-machine Python 3.12.3 evidence. След добавянето на този запис
  final payload bytes трябва да преминат fresh double deterministic build,
  wrapper dry-run и disposable exact-function apply. Human modal result,
  authoritative apply, independent verifier, Stage PASS, commit и tag остават
  pending.

## Stage 2.46 R5 non-blocking first-run evidence — 2026-09-12

Authoritative R4 evidence преди human gate:

- user Python 3.12.3 dry-run и live apply: 16 installer self-tests, `12/12`
  rollback, candidate/live `76/472/2293`, zero non-pass/residue и exact 35
  unstaged paths;
- independent verifier: package size/SHA, runtime/primitives, 217 tracked,
  35 status paths, 4341 bytecode records, source/physical state,
  `76/472/2293` и state unchanged са PASS;
- authoritative R4 post-apply physical SHA-256 е
  `5895c0a318da4300e1c738c705afedc25490d39ed632d41768a3f19091c7a8ab`.

Human gate и root cause:

- entry-transition runner отпечата само synthetic introduction; нямаше main
  или first-run прозорец и terminal prompt не се върна;
- два `Ctrl+C` сигнала не прекратиха вложеното Tk visibility wait. `Ctrl+Z`
  върна prompt, а exact `kill %%` завърши stopped job като `Terminated`;
- няма real profile, operation или project-data I/O по този synthetic route;
- source-localized blocker е `wait_visibility()` в
  `FirstRunProfileWindow.__init__`, достигнат от main `after_idle` преди
  window-manager mapping;
- R4 logic/static test е доказвал wait → focus → grab реда, но не constructor
  return или actual Map. Това е false assurance/coverage escape и human R4
  резултатът остава blocking `FAIL`.

R5 controls:

- exact 10-path freeze, без localization/crypto/storage/KDF/capability/
  recovery/network delta;
- constructor test изпълнява реалния `FirstRunProfileWindow.__init__` с fake
  Tk boundary и изисква незабавно връщане след build/protocol/Map bind;
- static contract забранява `wait_visibility`, `wait_window`, `update`,
  `update_idletasks`, `mainloop`, synchronous focus и grab в конструктора;
- `<Map>` планира точно една non-blocking `after_idle` activation; duplicate
  Map е idempotent, unviewable callback се отказва безопасно и следващ Map
  може да активира;
- close отменя pending callback, изчиства трите variables, освобождава grab и
  прави late callback inert;
- runner Map observer отпечатва по веднъж `CONSTRUCTED`, `MAIN_MAPPED` и
  `FIRST_RUN_MAPPED`; report schema v2 изисква 11 human observations.

Pre-documentation suites са target `80/80`, affected `472/472`, full
`2297/2297`, zero failures/errors/expected failures/skips и без bytecode
residue.

Assistant operator/process incidents, запазени за бъдещия handoff:

- след byte-identical R4 builds една излишна checksum-display команда съдържа
  malformed local path; тя не докосва artifact, а exact variable-based
  size/mode/SHA recheck е PASS;
- първият negative verifier QA command не е получил QA `HOME` и е отказал на
  runtime-path gate преди планирания package-mode gate. Коригираната isolated
  invocation доказва `PASS_FAIL_CLOSED` за mode drift;
- preventive rule: tool/runtime/artifact paths се задават веднъж във
  валидирани shell variables; human GUI не се стартира, докато constructor
  liveness и post-construction marker не са отделни automated contracts.

Exact final-document package QA, user apply, independent verifier, successful
human Map/typing/paste/login/lock, Stage PASS, commit и tag са pending.

## Stage 2.46 R5 authoritative и human evidence — 2026-09-12

Final artifact identity:

- package:
  `MOKOSH_STAGE2_46_R5_NONBLOCKING_FIRST_RUN_MAPPING_ce51ab1_R1.pyz`,
  `226610` bytes, `0600`, SHA-256
  `d09601dcad502dc032b8687f336d9e7ff357eb0baf1b2f491a9220397deae755`;
- independent verifier:
  `MOKOSH_VERIFY_STAGE2_46_R5_POST_APPLY_ce51ab1_R1.py`, `39247` bytes,
  `0600`, SHA-256
  `183479b26ac3de2f2098bbcb229109599264517050c04bddec3b42147b439000`.

Authoritative user Python 3.12.3 dry-run е PASS: exact R4 baseline physical
SHA-256
`5895c0a318da4300e1c738c705afedc25490d39ed632d41768a3f19091c7a8ab`,
16 self-tests, pinned Argon2id/cryptography/ML-KEM/X25519/AES-GCM primitives,
`10/10` injected rollback плюс success rollback, candidate `80/472/2297`,
zero non-pass/residue и no project mutation.

Live apply повтори static/delta и candidate gates, след което live
`80/472/2297` са PASS с zero expected failures/skips. Final state е exact 35
unstaged paths и physical SHA-256
`78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`.

Independent post-apply verifier е PASS: runtime/primitives и exact package,
217 tracked files, status 35, physical SHA-256, 4341 bytecode records, 165
Python и един shell source, `80/472/2297`, повторен identical source snapshot
и `INDEPENDENT_STATE_UNCHANGED=PASS`.

Human evidence в едно BG/100 synthetic in-memory стартиране е 11/11 PASS:

1. `ENTRY_TRANSITION_CONSTRUCTED=PASS` доказва constructor return;
2. main и first-run прозорците се показаха и двата Map markers присъстват;
3. видима беше точно една first-run dialog инстанция;
4. nickname прие едновременно manual typing и `Ctrl+V` paste;
5. password и confirmation приеха еднакъв synthetic test input;
6. двете password полета се маскираха и eye toggles показаха/скриха текста;
7. create издаде success notice, изчисти modal fields и върна locked main;
8. main password/nickname fields приеха synthetic login input;
9. successful login изчисти и двете главни credential полета;
10. BG и EN показаха unlocked profile/15-minute status и lock button;
11. manual lock върна locked status, login button и disabled action gates.

След main-window X shell prompt се върна нормално. Всеки marker е точно веднъж.
`FIRST_RUN_MAPPED` е наблюдаван преди `MAIN_MAPPED`; това е допустима реална
event delivery последователност и не е failure, защото няма fixed cross-window
ordering claim. Screenshots и user reports са human conversational evidence,
не cryptographically signed или independently witnessed certification.

Touch observation: single tap фокусира, а `Ctrl+V` paste работи; application
long-press Paste menu не е реализирано. Това не е security restriction и не се
представя като touch-native PASS. Отделно context-menu решение остава future
cross-platform usability work след explicit approval.

## Stage 2.46 R6 final-evidence closure boundary — 2026-09-12

User-ът прие exact пет документа: status, secure-profile contract, evidence,
standards crosswalk и session log. R6 не променя нито един production,
localization или test source. Затова R5 automated и human evidence остава
относимо и не се повтаря human GUI test след documentation-only overlay.

R6 package трябва да докаже exact R5 baseline binding, five-position rollback
плюс success rollback, deterministic bytes, `80/472/2297`, zero residue,
mode preservation и exact 35-path state. Authoritative apply, independent
post-apply, commit и annotated tag се приемат само от отделните им реални
изходи. Този embedded запис сам по себе си не твърди тяхното изпълнение,
Stage completion, certification, audit или legal conformity.

Първата intended R6 regression orchestration команда не е стартирана от
managed executor, защото съдържаше recursive temporary-directory cleanup.
Няма test process, candidate mutation или PASS claim от този опит. Коригирана
команда без destructive cleanup използва retained isolated scratch directory
и премина `80/472/2297`. Preventive правило: managed QA invocation не включва
recursive cleanup; bounded scratch residue се оставя на lifecycle механизма.

Първият вътрешен R6 wrapper dry-run също е fail-closed преди installer start:
tar inventory е exact 11 members, но адаптираният launcher е запазил R5
константа за 12 regular files вместо R6 модела от 7 regular files и 4
directories. Няма installer execution, project mutation или PASS claim.
Корекцията заменя свободния брояч с exact set equality за двата control файла
и петте payload документа; package revision преминава от вътрешен `R6-C1`
към `R6-C2`. Следващият вътрешен dry-run изпълни успешно всички gates, но
успешният baseline marker още носеше наследено име `R4_BASELINE`, въпреки че
проверяваше exact R5 bytes. Този output не е приет за final evidence;
`R6-C3` коригира marker-а на `R5_BASELINE` и изисква нов пълен QA цикъл.
Preventive правило: wrapper QA проверява имената и типовете на всеки archive
member, не само общия им брой, а pre-release review сканира и всички
stage/revision labels, не само digest и test резултатите.

Първото disposable-apply извикване на вътрешния `R6-C3` QA artifact пропусна
изолирания QA `HOME`. Runtime identity gate отказа с
`Python path is not lexical $HOME/venv_sys/bin/python3` след self-tests, но
преди baseline verification и преди `live_apply`. Byte/mode/status сравнение
потвърди, че disposable R5 repo е непроменено. Това е orchestration error, не
product waiver; `R6-C4` се проверява с explicit isolated `HOME`, минимален
environment и нов extraction target. Preventive правило: всяка вътрешна
wrapper/driver invocation pin-ва заедно `HOME`, executable path и `sys.prefix`.

## Stage 2.46 R6 authoritative completion evidence — 2026-09-12

Final package identity е `216370` bytes, mode `0600`, SHA-256
`67229f0dac54d96a4f5c1d3ba44338baa7f0a897e88bd1b4b1cd1259f3a38e37`.
Authoritative Python 3.12.3 dry-run потвърди exact R5 physical baseline
`78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`,
16 installer self-tests, `5/5` failure-position rollback плюс success rollback,
candidate `80/472/2297`, zero non-pass/residue и no project mutation.

Live apply повтори candidate gates, приложи само петте R6 документа и премина
live `80/472/2297`. Post-state е exact 35 unstaged paths, zero staged paths,
4341 unchanged bytecode records и tracked physical SHA-256
`2ba8c8eeb024cad44df35d758d24e2d940411fbc8008158694e336dacdbc6255`.

Независимият read-only verifier е `39095` bytes, mode `0600`, SHA-256
`e97c9d033a74c42fc508d330d53bf507133a0fe8bade17fc79ff3866da8c8955`.
Неговите 7 self-tests и отделна реализация потвърдиха exact package/archive/
manifest, runtime primitives, Git history/status/physical/source/ACL/modes,
165 Python и 1 shell source, `80/472/2297` и byte-identical state преди и след
verification. Final marker е
`STAGE2_46_R6_INDEPENDENT_POST_APPLY=PASS_UNSTAGED_EXACT_35_PATHS`.

User-ът прие completion amendment само в същите пет documentation paths.
Понеже production/localization/test bytes са unchanged спрямо независимо
проверения state, няма нов full-suite или human-GUI claim и няма повторно
изпълнение само заради документацията. Exact commit/tag са отделен finalizer
gate; embedded текстът не ги предполага и не е certification, official audit,
legal opinion или Windows/macOS native evidence.

## Stage 2.47 pre-package evidence — 2026-09-13

User-ът прие exact 32-file scope върху authoritative commit
`3716a8ecdf9b546d39cbef750c97811e7bb77cef`, tree
`6fc1059b3ecaf9c8cdb228981acc1a15c0d80cf0` и tag object
`455ff77c89e872087bccd403a178aa6a9d59cfee`. Реализацията е в retained
isolated copy; няма mutation в `~/MOKOSH_Agent` и няма предварително
commit/tag твърдение.

Новото доказателствено ядро покрива:

- exact `MOKOSH-RP1` layout: 3 version + 256 root + 16 checksum bits,
  25 × 11-bit word indices;
- fixed zero/all-one/sequential vectors и round-trip на всеки отделен root bit;
- pinned 2 048-word ASCII vocabulary, exact size/order/uniqueness/hash;
- strict 25 full words без fuzzy/prefix/case/Unicode поправяне;
- canonical bounded plain-text sheet и non-secret receipt/repr повърхност;
- user-selected new child, exact `0700/0600`, uid, regular type, link count,
  symlink refusal, no-clobber, bounded double read, fsync/read-back;
- separate `st_dev` за phrase спрямо `.mokr` и Vault, плюс explicit FAT/exFAT
  отказ;
- failure-position cleanup само на exact нов owned object и `UNCERTAIN` при
  недоказуем cleanup/durability;
- current-password reauthentication, `.mokr`-first setup, paper full reentry,
  optional cancel и final non-mutating rehearsal;
- locked-only forgotten-password route, exact source binding, new-password
  confirmation и read-only candidate preview;
- един final yes/no publish, no blind retry, read-only reconciliation,
  preserved old generation/record, stale-not-revoked semantics;
- отказ на старата парола за latest generation, explicit login с новата и
  manual/panic/inactivity close/lock behavior;
- EN/BG exact catalogue и synthetic 2 locales × 4 scales × 2 workflows;
- synthetic full transition без real profile, recovery file, secret, crypto
  key, network или user-data filesystem mutation.

Final-code local suites са exact target `138/138`, affected `472/472` и full
`2374/2374` PASS с failures/errors/expected-failures/skips `0`. По-ранните
подмножества recovery phrase/storage `30/30` и profile-prefixed `120/120`
не се сумират към тези exact counts. Всички резултати са local scratch QA,
не authoritative laptop evidence.

Няколко ранни test-runner invocation-и бяха спрени или дадоха import errors
заради активен `PYTHONSAFEPATH=1` и историческата non-package `tests/`
структура. Един от тях откри 2374 теста, но 29 subprocess проверки не виждаха
project root; след корекция без промяна на product bytes всички 2374 минаха.
Това са QA invocation/environment errors, не приети product резултати. Package
runner-ът изключва този inherited flag само в частното, byte-exact candidate
копие, без да приема user `PYTHONPATH` и без да изпълнява тестове върху user
data.

Pre-release package rehearsal мина installer self-tests `16/16`, exact
file-failure rollback `32/32`, new-directory rollback `2/2`, success rollback,
static inventory `248` files / `176` Python / `1` shell и повторно target
`138`, affected `472`, full `2374` с нулев non-pass. Авторитетните commit/tag
идентичности остават нарочно за проверка от user-machine dry-run.

След review беше затворен отделен error-normalization ръб: сурови
`OSError`/unsupported primitive грешки вече се преобразуват в bounded domain
results след safe cleanup, а несигурните операции остават `UNCERTAIN`.
Добавени са fault-injection тестове за post-create chmod, file fsync и
read-verification отказ. FAT/exFAT има отделно човешко съобщение; panic lock
затваря и setup, и forgotten-password прозореца.

Оставащи задължителни gates преди Stage PASS:

1. final deterministic no-clobber package и independent verifier bytes;
2. user Python 3.12.3 dry-run без project mutation;
3. отделен live apply само след приет dry-run;
4. independent post-apply physical/Git/runtime/full-suite verifier;
5. human BG/100 full setup → separation refusal → successful backup → cancel/
   lock → preview → final publish → old refusal → new login → lock transition;
6. commit и annotated tag само след всички приложими PASS outputs.

Няма FIPS/CMVP, AAL, BIP39, compliance, official-audit, legal-opinion,
public-release или Windows/macOS native claim.

## Stage 2.47 corrective evidence — 2026-09-15

Приетият corrective gate не зачита старите `138/472/2374` числа като
доказателство за поправения код. Новият exact scope suite изпълни `181/181`
PASS и включва lifecycle state, shared UI primitives и adversarial matrix:
corrupt/truncated/trailing/unsupported records, cross-profile mix-and-match,
concurrent/stale/replay, restart с точно две напомняния и short-write след
външни exports. GUI unit/static договорите проверяват всички password eyes,
remask/clear, precise local validation, anti-oracle core refusal, localized
action dialogs, cancel-by-default, minimize grab release, responsive 3/2/1
grids и липса на native messagebox/transient.

Широк local discovery изпълни 2361 теста; три допълнителни legacy модула не
се заредиха поради липсващ `argon2` в анализаторния Python. Това е записан
environment blocker и резултатът не се нарича full PASS. R3 трябва да повтори
пълния suite в pinned user runtime и да запази отделен human gate за WM,
геометрия, мащаб, keyboard/paste/focus и реални removable devices.

Exact 33-path R3 package rehearsal е отделно PASS за `17/17` installer
self-tests, всички 33 injected file positions плюс success rollback, exact
254-file candidate (`181` Python, `1` shell), `181/181` target и нулев source
residue. Това не замества липсващия pinned-runtime affected/full PASS и не
затваря practically GUI gate-а.

### Stage 2.47 R3 post-overlay status-model false fail и R4 regression

Authoritative R3 dry-run на user runtime премина exact R1 baseline,
runtime/primitives, rollback `33/33 + success`, static/delta, target
`181/181`, affected `472/472`, full `2416/2416`, no residue и повторен
identical physical baseline. Live apply повтори успешно всички candidate
gates, после отказа на `live exact 38-path status drift`. R3 е withdrawn и не
се изпълнява повторно.

Изолирана реконструкция от exact 232-file HEAD tree, R1 32-path payload и R3
payload доказва `R1_STATUS_COUNT=32` и `R3_STATUS_COUNT=40`. Symmetric-delta
анализът идентифицира точно два пропуснати expected-status пътя:
`mokosh_profile_storage.py` и `tests/test_mokosh_profile_storage.py`. И двата
са tracked и clean в R1, но са част от реалния 30-path corrective delta.
Предишната формула `R1_STATUS_PATHS ∪ NEW_PATHS` следователно е непълна.

R4 използва `R1_STATUS_PATHS ∪ CORRECTION_PATHS`, pin-ва exact count 40 и
добавя отделен self-test, че clean-tracked corrective subset е точно тези два
пътя и никой real correction path не липсва. Вторият identical
`EXACT_STAGE2_47_R1_BASELINE=PASS` след `CANDIDATE_RESIDUE` в live-apply output
е post-exception rollback verification и доказва възстановения R1. R4 dry-run
въпреки това повтаря exact baseline gate преди mutation. Това е
installer/test-design incident, не product, cryptographic или user error и не
разрешава waiver на post-apply status.

### Stage 2.47 R4 authoritative PASS и R5 practically regression scope

R4 live apply и отделният read-only post-apply verifier са authoritative PASS
в pinned user runtime: target `181`, affected `472`, full `2416`, нулев
non-pass и нулев test residue. Крайният tracked physical digest е
`6fc034535dad1d5bc6afd55bf7f8786368b95119d07f204efbfe170a58d614c6`;
Git state остава exact 40-path unstaged върху HEAD `3716a8e`.

Практическият BG/100 replay след това отвори три regression записа, които не
се покриват от mapping markers: D07 — horizontal clipping на горните main
controls при тесен resize; D09 — необяснен `Vault` в setup текста; D11 —
неясен и прекалено технически removable-media/FAT текст. R5 е ограничен до
responsive layout primitive и четирите main реда, EN/BG copy, точните unit/
static regressions и трите evidence документа. Няма промяна в recovery crypto,
storage format, lifecycle state, password publish или user-data операции.

R5 target е локално `184/184` PASS. Affected invocation откри точно 472 теста,
но 10 legacy layout проверки не се import-наха поради липсващ `argon2` в
scratch Python; това е environment blocker и не е affected PASS. Задължителният
pinned-runtime dry-run трябва да даде exact target `184`, affected `472` и
full `2419`, без failures/errors/expected-failures/skips и без mutation.

Practical evidence protocol е sequential: tester-ът получава точно едно
действие, връща screenshot или описание, а reviewer-ът записва
PASS/FAIL/UNCLEAR преди следващото. При FAIL няма продължаване към нов сценарий;
следват bounded fix и replay на засегнатия checkpoint. Това правило е част от
всеки следващ handoff.

### Stage 2.47 R5→R6 real-Tk RED/GREEN evidence

R5 source/logic suites и independent post-apply verifier са PASS
(`184/472/2419`), но не се използват като заместител на real-Tk geometry.
Отделен read-only desktop diagnostic даде exact RED за D07:
`container=787`, `entry=99`, `entry_req=16`, `toggle=262/req=107`,
`create=262/req=262`, `stacked=False`; folder control остана `262/262` PASS.

Двата първи изолирани R6 опита са запазени като отрицателно evidence:

- R6-R1 спря fail-closed, защото `entry=254` беше под тогавашния произволен
  276 px criterion; live source не беше променен;
- R6-R2 мина непълен автоматичен gate, но human review даде FAIL: при default
  `entry=653`, eye беше на втори ред, а create control беше `650/req=262`.
  Надписът automated GREEN е обезсилен. Причината е, че старият gate проверява
  само lower bounds/in-bounds/предварително очакван stacking, но не X/Y
  съседство и upper width bounds.

R6-R3 gate добавя точните липсващи assertions и package self-tests, които
трябва да отхвърлят R5 `entry=99`, R6-R2 `create=650`, преместено eye и
разтегнат create control. Structural/logic suite е `47/47` PASS. Авторитетният
user real-Tk BG/100 резултат е:

```text
DEFAULT container=787 entry=278/206 eye=107/107 create=248/248 stacked=False entry_eye_row=True entry_create_row=True in_bounds=True
WIDE    container=1067 entry=558/206 eye=107/107 create=248/248 stacked=False entry_eye_row=True entry_create_row=True in_bounds=True
NARROW  container=587 entry=336/206 eye=107/107 create=248/248 stacked=True entry_eye_row=True entry_create_row=False in_bounds=True
R6_R3_REAL_TK_AUTOMATED_CONTRACT=PASS
R6_R3_ISOLATED_PREVIEW=CLOSED_NO_PROJECT_MUTATION
```

Human screenshots потвърждават default inline ред и narrow reflow, при което
eye остава непосредствено до entry, а само create-profile control се премества
отдолу с нормална ширина. Оценка: **R6-R3 ISOLATED REAL-VISUAL PASS**. Това не
е live-apply или Stage PASS. R6 installer трябва да pin-не exact applied-R5
baseline и да повтори target/affected/full в user pinned runtime; след apply
се изискват independent verifier и practical replay.

### Stage 2.47 R6-R1 installer manifest-mode regression

Първият guarded R6 dry-run даде точен safe stop още в exact-R5 baseline gate:

```text
INSTALLER_SELF_TESTS=PASS_18
PINNED_RUNTIME_AND_PRIMITIVES=PASS ...
STAGE2_47_INSTALLER=FAIL: R5 untracked mode drift: run_mokosh_profile_recovery_visual_harness.py
STAGE2_47_WRAPPER=FAIL: inner installer stopped with code 1
```

Няма candidate test PASS и няма project mutation. Root cause е builder
hard-code `0600` за всеки baseline untracked record; executable runner-ът е
exact `0700`. Предишният local rehearsal е проверил 40/40 byte hashes, но не е
извикал metadata gate-а и затова не е покрил дефекта.

R6-R2 добавя exact baseline-mode contract: 21 untracked regular files са
`0600`, само `run_mokosh_profile_recovery_visual_harness.py` е `0700`.
Manifest load отказва всяко отклонение, self-test pin-ва цялата карта, а local
rehearsal задължително изпълнява `verify_untracked_baseline`. R6-R1 package е
withdrawn; всички target/affected/full и practical gates остават неизпълнени
за live R6 до отделен R2 dry-run.

### Stage 2.47 R6 practical evidence и R7 exact layout gate

R6-R2 е приложен и независимо проверен в pinned runtime с
`185/472/2420`, exact 40-path unstaged state и tracked physical digest
`5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db`.
Следващият human BG/100 checkpoint даде PASS за move, Escape и X close-child и
оттегли scroll finding-а. Той даде FAIL за clipped prepare control при minimum
setup width и потвърди near-wall wrap risk в yellow recovery notices.

R7 test contract не използва предварително избрана „достатъчна“ entry ширина.
Той измерва real Tk actual/requested widths и координати и изисква:

- entry и eye да останат на един ред във всички три геометрии;
- prepare да е inline при default/wide и единственият control на втория ред при
  minimum;
- prepare actual width да е в ±4 px от real requested width;
- всички три controls да са mapped и in-bounds;
- main recovery status, setup phrase warning и setup phrase help да имат
  wraplength не по-голям от actual label width минус двата вътрешни padding-а.

Exact R6 source трябва да е RED по две независими причини: setup използва един
неадаптивен packed ред и shared label измерва padded parent. Candidate source
трябва да е GREEN по structural gate и после по реалния Tk на user machine.
Локално target е `188/188` PASS. Affected invocation е 472 discovered с 10
`ModuleNotFoundError: argon2`; то не е PASS и няма waiver. Package self-tests
са `PASS_10_PATHS`, `PASS_DETECTED_2`, `PASS_2_RED_2_GREEN` и
`PASS_NO_PROJECT_MUTATION`. Последвалият user-machine real-Tk output е
`RECOVERY_SETUP_LAYOUT_AUDIT=PASS`: default/wide са inline, minimum е stacked
само за prepare, entry/eye остават на един ред, prepare е `314/314` px и всички
контроли са in-bounds. Измерените wrap стойности оставят договорените 30/40 px
clearance спрямо actual label width.

Human evidence използва две последователни снимки вместо оценка на половин
прозорец: горната и долната част на целия minimum-width setup бяха проверени,
включително всичките 25 думи, стъпки 1–3 и „Отказ“. След споделяне и обсъждане
user-ът изрично прие visual PASS. Финалните markers са
`RECOVERY_SETUP_LAYOUT_PREVIEW=CLOSED_NO_PROJECT_MUTATION` и
`R7_ISOLATED_REAL_TK=CLOSED_NO_PROJECT_MUTATION`, но последващият exact
bytecode gate доказа, че тяхното твърдение за физическа неизменност е невярно;
markers са оттеглени. Геометричните измервания и human visual PASS остават
валидни.

Local full discovery изпълни 2368 теста, но завърши с 3 import errors за
липсващ `argon2` и 7 skips. Този резултат е environment evidence, не full
PASS; pinned user runtime трябва да повтори очаквания R7 full count без
failures, errors, expected failures или skips.

Evidence workflow е постоянен: споделяне → обсъждане → изрично решение →
действие/траен запис. След human решението е разрешена само подготовката на
guarded read-only dry-run package; никой automated резултат не разрешава
самостоятелно live mutation, apply, Stage PASS, commit или tag.

### Stage 2.47 R7-R1 bytecode stop и source-match forensic evidence

R7-R1 user dry-run премина installer self-tests и pinned runtime primitives,
но exact-R6 baseline gate отказа при bytecode record count преди payload,
rollback injection, candidate tests или project mutation. Read-only inventory
даде `4351`, тоест `+6` спрямо историческите `4345`, само regular files и
directories. Най-новите 11 root `.pyc` timestamps съвпадат с R7 preview-а.

Отделната forensic проверка не изпълнява `.pyc` кода. Тя сравни magic/header,
source timestamp/size и exact marshalled compile payload срещу съответния
проверен source за всичките 11 файла. Резултатът е `11/11` PASS; snapshot-ът
преди и след е неизменен:

```text
records=4351
sha256=83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4
```

R7-R1 и неговите no-mutation markers са withdrawn. R7-R2 pin-ва count и digest,
показва expected/actual при drift, задава `sys.dont_write_bytecode` преди всички
project imports и добавя subprocess regression, който премахва външните Python
bytecode environment защити и въпреки това изисква zero residue. Няма source
rollback чрез предположение и няма crypto/storage/recovery-layout промяна.

### Stage 2.47 R7-R2 authoritative dry-run, apply и post-apply evidence

Authoritative user-machine R7-R2 dry-run е изпълнен с Python 3.12.3,
argon2-cffi 25.1.0, cryptography 49.0.0, ML-KEM и OpenSSL 4.0.1. Exact-R6
baseline gate потвърди 232 tracked файла, physical SHA-256
`5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db` и
bytecode snapshot `4351` / `83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.
Installer self-tests са `20/20`; rollback injection е `40/40 + success`;
candidate static/delta доказва 254 source файла, 181 Python, 1 shell, точно 10
променени пътя, нулеви hash consumers и нулеви substitutions.

Candidate target/affected/full са `189/472/2424` PASS без failures, errors,
expected failures или skips. Candidate residue е none, повторният exact
baseline е identical и dry-run wrapper-ът завърши с
`PASS_NO_PROJECT_MUTATION`. Тези резултати са от pinned user runtime, а не от
scratch средата с липсващи зависимости.

След изрично user решение live apply повтори същите candidate gates, приложи
само договорения R7 payload и повтори live target/affected/full
`189/472/2424` PASS. Крайният Git state е exact 40 unstaged paths върху HEAD
`3716a8ecdf9b546d39cbef750c97811e7bb77cef`; tracked physical SHA-256 е
`972aa7bfbe40878934118ab1a7a81ab89dff3ec0fa7bb017b40570ed24581e58`.

Отделният read-only post-apply verifier провери отново package/source delta,
получи `files=254`, `status_paths=40`, `untracked=22`, `tracked=232`, и
изпълни собствен target/affected/full run `189/472/2424`. Няма residue.
Физическият tracked digest остана `972aa7bfbe40878934118ab1a7a81ab89dff3ec0fa7bb017b40570ed24581e58`,
а bytecode snapshot-ът остана exact `4351` /
`83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.
Verifier-ът завърши с `PASS_NO_PROJECT_MUTATION`.

Техническите, real-Tk и human R7 gates са приети, но Stage 2.47 още няма
финален PASS: evidence amendment-ът, commit/tag и post-commit verifier остават
отделни fail-closed стъпки. Няма waiver и няма извършен commit или tag.

## Stage 2.48 isolated pre-package evidence — 2026-09-18

Authoritative pre-mutation gate на реалната машина потвърди exact checkpoint
`7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8`, tree
`3c30b84b10cb742ba4d08bc50d50361eaa953f06`, branch
`feature/mokosh-v2-core`, annotated Stage 2.47 tag object
`480e3f8efa436e1be7322899d8163d19018e095f`, clean status, 254 tracked файла
и exact 32-path freeze. Pinned runtime/primitives са Python 3.12.3,
argon2-cffi 25.1.0, cryptography 49.0.0, real ML-KEM-768, Tk 8.6 и OpenSSL
4.0.1. Baseline full regression е `2424/2424` PASS без failures, errors,
expected failures, unexpected successes или skips. Финалът е
`STAGE2_48_PRE_MUTATION_GATE=PASS_READ_ONLY`.

Изолираният кандидат е построен в отделно exact checkpoint копие; live
repository не е променян. Targeted service/GUI/integration/visual/session/
pipeline/filesystem/lifecycle suite е `218/218` PASS. След това full discovery
в scratch runtime Python 3.12.14, Tk 9.0, argon2-cffi 25.1.0,
cryptography 49.0.0, real ML-KEM-768 и OpenSSL 3.5.8 изпълни:

```text
Ran 2497 tests in 25.661s
OK
```

Това е local regression evidence: failures=0, errors=0, expected failures=0,
unexpected successes=0 и skips=0. То не заменя final-byte package self-tests,
rollback injection, deterministic build, user-machine Python 3.12.3 dry-run,
изрично приет live apply, independent post-apply verifier или human visual
matrix.

Новите/променени проверки доказват поне:

- one active session key lease, exact active encrypt slot и exact retired-key
  decrypt без fallback;
- wrong-profile/tamper generic refusal, non-V2/MOK1 separation, signed и
  multi-slot refusal;
- source identity binding, preflight-to-lease second residue scan и
  no-overwrite/no-original-delete;
- regular-to-FIFO race отказ чрез `O_NONBLOCK`, magic→inspection→pipeline
  identity binding и 4096-entry fail-closed directory limit;
- fault/cancel преди publication без output и fault/cancel след hard-link като
  success-with-warning без retry signal;
- exact evidence cleanup, link-count ambiguity preserve и post-cleanup rescan;
- exactly one GUI worker creation site, Queue/after main-thread delivery,
  close/hide/drain и main-root wait;
- keyless cleanup lease и mutually-exclusive V2/recovery/MOK1 windows, като
  lock/panic/timeout/close затварят историческия MOK1 authorization window;
- EN/BG fixed security wording и 16-case synthetic local visual contract без
  profile, key, file, worker или crypto operation.

До package gates и user решение няма Stage 2.48 apply, commit, tag или human
visual PASS claim.

## Stage 2.48 Case 01 FAIL и bounded corrective кандидат — 2026-09-20

R1 live apply и отделният post-apply verifier преди human прегледа са PASS:
`218/2497`, exact 32-path unstaged state, празен index и physical SHA-256
`756e45d42fa8595108ef68a864c0e0cfa9bcd50244afcfdb62c8036b952dff0c`.
Synthetic launcher-ът потвърди същото физическо състояние преди и след Case
01 и не извърши profile, key, file, worker или crypto операция.

Case 01 не е PASS. Потвърдените human findings са:

- cleanup decision actions не се виждат в default geometry;
- след `PRESERVE` живият parent не се връща видимо и с фокус;
- `CLEANABLE`, `BLOCKED` и `PUBLISHED` допускат повторен Encrypt transition;
- READY keyboard-focus outline може да се обърка със synthetic state marker;
- след `Close` има точно два невидими Tab stop-а преди READY.

Класификацията остава:

```text
CASE_01_HUMAN_RESULT=FAIL_REQUIRES_FIX_AND_RETEST
HUMAN_VISUAL_GATE=FAIL_REQUIRES_FIX_AND_RETEST
STAGE_PASS_ALLOWED=NO
COMMIT_TAG_ALLOWED=NO
```

След read-only R5 continuity проверка user-ът изрично прие exact 34-path
corrective scope: първоначалните 32 paths плюс `mokosh_profile_ui.py` и
`tests/test_mokosh_profile_ui.py`. Централният кандидат резервира отделен
action row, възстановява живия parent, изключва canvas/scrollbar от Tab реда
при запазени `PageUp`/`PageDown`, заключва run до explicit нов selection и
разделя synthetic state indication от keyboard focus.

Новите regression-и първо дадоха очакван RED върху старото поведение, после:

```text
CORRECTIVE_FOCUSED_UI=PASS tests=45 failures=0 errors=0 skips=0
CORRECTIVE_AFFECTED_UI_CONSUMERS=PASS tests=100 failures=0 errors=0 skips=0
```

Локалният по-широк run не е authoritative PASS: scratch runtime е с
cryptography 46.0.0, без argon2-cffi и без ML-KEM support. Той изпълни 2448
discovered placeholders/tests, но отчете 3 dependency import errors и 7
environment skips. Разширеният 239-test affected run има 0 failures/errors,
но 1 ML-KEM environment skip. Pinned Python 3.12.3 / cryptography 49.0.0 /
argon2-cffi 25.1.0 gate трябва да изпълни expected `239/2503` с нулев non-pass.

Няма corrective live apply, human replay, Stage PASS, commit или tag.

## Stage 2.48 Cases 2–4 D1–D4 evidence и accepted overlay — 2026-09-23

Human Cases 2–4 повторяемо показаха D1–D4: off-screen keyboard focus без
viewport follow; focused action, който се disable-ва без предварителен focus
handoff; programmatic `NOT_V2` вместо explicit `NOT V2`; и два synthetic
chooser controls без observable feedback. Case 4 приключи с 12 PASS и 4 FAIL,
затова целият human gate остава blocking.

Completeness review проследи producer, shared consumer, contract, tests и
evidence за всеки finding. Приетият overlay е exact 11 paths: три
implementation, три test и пет documentation paths. Той е подмножество на
frozen 34-path scope. Shared UI consumers се валидират с affected tests без
byte delta. `mokosh_v2_local_visual_harness.py` е непроменен, защото е pure
observation/report model. Няма промяна в localization, service, session,
filesystem, pipeline, lifecycle, crypto, Vault, format или standards
crosswalk.

Negative control върху старите exact bytes даде RED във всичките шест избрани
test methods (`failures=5`, `errors=2`, като subtests увеличават броя на
outcomes). След минималната корекция същите checks са 6/6 GREEN, target suite е
49/49 PASS, а affected suite изпълнява 243 теста без failure/error и с един
scratch-only ML-KEM skip. AST parse е 189/189 Python files.

Full scratch discovery не е authoritative PASS:

```text
Ran 2452 tests in 28.150s
FAILED (errors=3, skipped=7)
```

Трите errors са dependency import failures поради липсващ `argon2`; седемте
skips са environment ограничения. Няма отчетен functional assertion failure,
но non-pass резултатът остава non-pass. Authoritative package трябва да
потвърди exact baseline/status/physical hashes, 11-path candidate, rollback и
deterministic build, след което в pinned user runtime да изпълни target 49,
affected 243 и очакван full 2507 с нулев failure/error/skip/expected failure/
unexpected success и с непроменено live repository състояние.

Методът пази възпроизводимост (exact hashes/runtime), опровержимост
(предварителен RED), проследимост (D1–D4→код→тест→документ), bounded hypothesis
и fail-closed решение при всеки non-pass. Това е engineering evidence, не
formal proof, научна публикация, standards certification, independent audit
или human/accessibility conformance. Приемането разрешава само подготовка и
read-only dry-run. Live apply, post-apply verifier, affected human replay,
Stage PASS, commit и tag остават отделни задължителни gates.

Подготвеният R1 transport е dry-run-only: parser-ът няма `--apply`, package-ът
съдържа точно 11 payload paths и сглобява целия 263-file кандидат само под
private temporary root. Self-test валидира exact ZIP inventory/order/modes,
вътрешните SHA-256, canonical manifest, Git blob known-answer и tampered-tree
negative control. Две последователни build изпълнения са byte-identical. Това
доказва transport determinism, не user-machine test PASS; авторитетното
изпълнение още предстои.

## Stage 2.48 D5–D7 human evidence и accepted bounded overlay — 2026-09-24

D1–D4 guarded apply и independent post-apply verifier на user machine
потвърдиха exact 34-path state, projected tree
`b14dd36c7461fbc4389ae720dcccb6af5709a21b`, physical SHA-256
`554b6ea553625c2b1293ec534f9b0c774cb34716502fb040e9e9289be4c930b0` и
`49/243/2507` pinned tests без non-pass. Тези automated резултати не отменят
следващото human наблюдение.

Physical Case 4 откри:

- D5 — state click сменя displayed state, но keyboard focus остава върху
  предишния control;
- D6 — window restore/reactivation повтаря `FocusIn` към същия stale focused
  descendant и viewport-ът се auto-scroll-ва към него;
- D7 — `Space` invoke-ва state button, а `Return` не го invoke-ва в Tk 8.6/X11.

Read-only code/test inspection проследи D5 до direct `show_state` command, D6
до безусловното idle reveal при всеки descendant `FocusIn`, и D7 до липсата на
explicit `Return`/`KP_Enter` instance bindings. Existing tests не покриваха
pointer focus transfer, same-widget reactivation или Enter activation.

Accepted scope е exact 9 paths: `mokosh_profile_ui.py`,
`run_mokosh_v2_local_visual_harness.py`, двата им test файла и петте Stage 2.48
contract/status/evidence/history документа. Negative-first доказателството е:
baseline `30/30` PASS; новите проверки върху стария код дават `failures=5`,
`errors=2`; след bounded fix focused suite е `32/32`, а target suite е
`51/51` PASS. Affected scratch изпълни 245 теста без failure/error и с един
environment-only ML-KEM skip. Full scratch изпълни 2454 теста с 0 assertion
failures, 3 липсващи-`argon2` import errors и 7 environment skips. Тези два
резултата са non-PASS и не заместват pinned package, user-machine или human
PASS.

D5–D7 R1 transport-ът е dry-run-only и няма apply parser route. Package
self-tests валидират exact nine-path inventory, canonical manifest, вътрешни
digests, ZIP metadata/modes, Git blob known-answer и negative controls;
повторният build е byte-identical. Това не е user-machine regression PASS и
не променя blocking human status.

Корекцията пази стандартния `Space` route, добавя exactly-once `Return` и
`KP_Enter` invoke с `break`, прехвърля focus преди state change и не reveal-ва
повторен FocusIn към същия widget. Реална смяна на focus target продължава да
разкрива off-screen control-а минимално.

Процесният пропуск е записан като
`ASSISTANT_PROCESS_DEVIATION_04=INCOMPLETE_VIEWPORT_INSPECTION_AFTER_WINDOW_STATE_CHANGE`:
след window-state промяна е била проверена само видимата горна част, без
задължителния долен viewport. Оттук всеки resize, maximize, restore, minimize
или reactivation изисква top-and-bottom inspection преди PASS. Това е
evidence-integrity правило, не MOKOSH product defect. Human gate, Stage PASS,
commit и tag остават блокирани.

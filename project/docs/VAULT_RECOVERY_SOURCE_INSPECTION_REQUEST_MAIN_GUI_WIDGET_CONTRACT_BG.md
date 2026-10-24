# Stage 2.30 — main-GUI recovery source inspection-request widget contract

## 1. Цел

Stage 2.30 свързва pure Stage 2.29 request contract към normal main GUI чрез
четвърто отделно действие. Това е explicit request за бъдеща secure source
inspection, не source access, identity proof, operation authorization или
automatic recovery.

## 2. Exact prerequisite и state machine

Fourth action започва `LOCKED`. Само fully revalidated exact positive Stage
2.27 selection outcome може еднократно да го премести в `READY`. Preserve,
picker cancel, wrong type или forged claim не могат да го отключат.

Първият valid click преминава atomically през `DECIDING` към terminal
`COMPLETED` или `FAILED`. Няма reset/retry; replay и concurrent втори consumer
са отказани.

## 3. Separate user intent

Четирите действия остават отделни:

1. request recovery review;
2. proceed to future source selection;
3. select harmless local source path;
4. request future secure inspection или preserve.

Нито едно positive действие не стартира автоматично следващото. Picker cancel
оставя fourth action locked. Confirmation No или window-close е exact
`PRESERVE_AND_STOP`.

## 4. Conditional import и ordering

Stage 2.27 и Stage 2.29 не се import-ват при fresh normal GUI import. Stage
2.29 се зарежда само след explicit fourth click.

Преди contract loader, Stage 2.29 preparation и dialog processing event-ът:

- disable-ва fourth button;
- clear-ва retained Stage 2.27 outcome/path;
- clear-ва bound locale от event state.

Python `str` не предлага доказуема memory zeroization. Clear-ването ограничава
GUI retention, но не е secure erase claim.

## 5. Privacy и fixed presentation

BG/EN banner, button, confirmation, requested, preserved и failure texts са
fixed и bounded. Те не съдържат selected path, filename, exception detail,
secret или authority claim.

GUI event не log-ва, persist-ва, hash-ва или показва path. Visual report schema
няма path/filename/secret fields.

## 6. No-access boundary

Stage 2.30 не:

- open/read/stat/resolve-ва или parse-ва recovery source;
- проверява existence, identity, authenticity, ownership или permissions;
- разрешава source access/preparation;
- приема password, recovery secret, Vault или key material;
- извиква Stage 2.5 secure read, Stage 2.8 reconciliation, review/session,
  workflow, candidate или publish;
- извършва operation, user-file mutation, network, cloud, telemetry, logging
  или persistence.

Native picker може да enumerate-ва directories и да чете filesystem metadata.
Normal startup извършва existing private runtime-directory preparation.
Следователно няма whole-process no-filesystem-access claim.

## 7. Locale и geometry

Locale се binding-ва от exact Stage 2.27 outcome при arming и не може да бъде
сменен за prepared fourth decision. Преди arming normal language control
обновява fixed fourth-action text.

Normal GUI geometry е exact `820x720`. Prepared recovery-review window остава
exact `820x560`.

## 8. Visual evidence

Mandatory Linux observation matrix е:

- `bg-BG` × `request`;
- `bg-BG` × `preserve`;
- `en-GB` × `request`;
- `en-GB` × `preserve`.

Използва се само harmless non-sensitive synthetic file. Забранени са истински
recovery record, password, Vault и sensitive filename. Human observation не е
system-call proof, platform certification, independent audit или recovery
success.

## 9. Задължителни тестове

Точно 42 new test methods покриват state/order, exact prerequisite,
request/preserve, locale, privacy, forged claims, errors, `BaseException`,
replay, concurrency, four-action flow, visual schemas, fresh-import isolation,
static no-capability граница, critical hashes и geometry.

Expected full installer gate е 1521 теста: `OK`, expected failures=3 само за
legacy MOK1, `skipped=0`.

## 10. Exact frozen paths

Stage 2.30 променя точно 18 paths:

- четири status/evidence/session/crosswalk документа;
- този contract;
- `mokosh_gui.py`;
- pure visual core и executable launcher;
- един new 42-test module;
- шест historical exact GUI-hash test modules;
- три historical normal-GUI geometry test modules.

Storage, reconciliation, crypto, Stage 2.27 и Stage 2.29 implementations,
requirements и privileged recovery layers остават byte-exact.

## 11. Installer gates

Installer-ът изисква exact clean Stage 2.29 commit/tree/tag, exact 18-path
payload allowlist/hashes/modes, protected quarantine, ignored root-Python scan,
`LC_ALL=C` tracked-source manifest, exact compile, 42 targeted tests, 1521-test
full regression, isolated apply/rollback probe и visible BG/EN ×
request/preserve matrix. Commit и annotated tag се създават само след всички
PASS резултати.

`SAFETY_MODE=True` остава задължително. Stage 2.30 не твърди certification,
legal conformity или production readiness.

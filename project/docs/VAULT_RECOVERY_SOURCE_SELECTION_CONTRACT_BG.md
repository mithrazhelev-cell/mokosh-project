# MOKOSH — договор за recovery source selection

Статус: Stage 2.27 — inactive one-shot process-local избор на един недоверен
абсолютен POSIX path; няма GUI picker, filesystem access, source validation,
recovery secret, review session или operation authority.

## 1. Цел и trust boundary

Stage 2.25 позволява normal GUI да произведе exact положителен Stage 2.21
outcome, който съдържа само намерение за бъдещ source-selection boundary.
Stage 2.27 реализира самия pure selection contract, но не го свързва към GUI.

Contract-ът приема само exact положителен
`VaultRecoveryEntryTransitionOutcome`. Той записва точно едно от:

- `SELECT_LOCAL_RECOVERY_RECORD` с един caller-supplied path;
- `PRESERVE_AND_STOP` без path.

Selection не е source access. Caller-supplied path е недоверено и потенциално
чувствително metadata, а не доказана file identity, capability, consent или
разрешение за recovery операция.

## 2. Exact входна граница

`prepare_recovery_source_selection()` приема точно един параметър и извършва
пълна revalidation на Stage 2.21 outcome:

- exact class, format, version и completed state;
- exact `bg-BG` или `en-GB` locale;
- exact Stage 2.19 positive entry route;
- exact `PROCEED_TO_FUTURE_SOURCE_SELECTION` route;
- exact request/transition sequences;
- всички Stage 2.21 source, filesystem, review, operation, network и automatic
  flags остават `false`.

Stage 2.21 preserve outcome не може да подготви selection. Prepared object-ът
не задържа original transition outcome, path или друг caller object; преди
decision пази само locale и двете exact enum решения.

## 3. Path syntax и privacy граница

Положителният selection path трябва да бъде exact `str` и:

- абсолютен POSIX path, различен от `/`;
- не започва с `//` и не завършва с `/`;
- няма празни, `.` или `..` компоненти;
- strict UTF-8 е с размер най-много 4096 bytes;
- няма NUL, Unicode control или format/bidi-control символи.

Това е само lexical validation. Stage 2.27 не извиква `abspath`, `normpath`,
`realpath`, `resolve`, `stat`, `lstat`, `open` или друга filesystem функция.
Не твърди, че path-ът съществува, че е file, че е `.mokr`, че е private, че е
без symlink/hardlink или че сочи към същия inode по-късно.

Exact path се запазва само в process-local outcome поле с `repr=False`.
Prepared object и outcome отказват copy, deepcopy и pickle. Това намалява
случайното задържане, но не е secure memory erasure: Python `str` не може да
бъде доказуемо zeroized. Path не се хешира, логва, показва или persist-ва.

## 4. One-shot lifecycle

Prepared selection има exact states:

- `awaiting_selection_decision`;
- `completed`.

Wrong enum type, invalid path или path върху preserve route отказват без да
консумират fresh object-а. Първият валиден decision го консумира окончателно.
Lock сериализира concurrent callers така, че точно един може да получи
outcome; останалите получават replay отказ. Няма reset, retry или reuse.

## 5. Outcome semantics

При положителен избор outcome-ът доказва само:

- exact positive Stage 2.21 source revalidation;
- exact selection enum;
- exact lexical path validation;
- `source_selected=true` и наличие на чувствително path metadata.

Едновременно задължително остават:

- `source_opened=false`;
- `source_identity_validated=false`;
- `source_access_authorized=false`;
- `source_preparation_performed=false`;
- `recovery_secret_received=false`;
- `review_session_prepared=false`;
- `operation_authorized=false` и `operation_performed=false`;
- recovery-source filesystem access/mutation `false`;
- network и automatic transition `false`.

При preserve всички path/selection metadata flags са false и
`selected_path=None`.

## 6. Import и capability граница

Модулът използва само Python standard library плюс exact Stage 2.19, 2.21 и
2.22 leaf contracts. Няма import на GUI, storage, reconciliation, workflow,
controller, bridge, review, candidate, publish, crypto, process, network или
logging module.

Няма callback, executor, dynamic import, plugin, filesystem handle, descriptor
или caller-supplied object capability.

## 7. Връзка със secure source access

Stage 2.5 `mokosh_vault_recovery_storage` остава единственият реализиран POSIX
secure-read core. Неговите `O_NOFOLLOW`, owner/mode/link-count, descriptor/inode,
canonical filename, bounded double-read и changed-source проверки не се
дублират и не се отслабват тук.

Бъдещ access/preparation stage трябва да revalidate-не Stage 2.27 outcome и
след това да използва exact reviewed storage boundary. Изборът на path не може
сам да прескочи към Stage 2.8 reconciliation, workflow, review или publish.

## 8. Строго забранени действия

Stage 2.27 не:

- променя или import-ва `mokosh_gui.py` и не отваря picker;
- чете directory listing, metadata или file bytes;
- приема recovery key, password, new password, Vault session или keyring;
- подготвя candidate, publish, reconciliation, workflow или review session;
- извършва unlock, setup, retry, rollback, cleanup, encryption или deletion;
- използва persistence, logging, network, telemetry, Guardian или update;
- предоставя automatic transition или operation authority.

`SAFETY_MODE=True` и всички съществуващи disabled controls остават byte-exact.

## 9. Задължителни тестове

Точно 26 нови test methods покриват:

- Bulgarian/English positive selection и preserve;
- exact Stage 2.21 type/route/schema revalidation;
- forged transition and authority claims;
- exact public constants, enums и signatures;
- path type, absolute syntax, ambiguity, UTF-8 bound и unsafe Unicode;
- path redaction и отказ на copy/deepcopy/pickle;
- invalid-input non-consumption, replay и concurrent exactly-one success;
- forged outcome route/path/authority flags;
- AST import/capability boundary;
- exact hashes на GUI, paths, launcher, requirements, crypto, entry, storage и
  reconciliation core;
- full regression без skipped mandatory security tests.

Очакваният пълен резултат след Stage 2.27 е 1413 теста: `OK`, с трите
документирани expected failures само за legacy MOK1 и `skipped=0`.

## 10. Честни ограничения

Stage 2.27 не доказва source existence, identity, authenticity, privacy,
permissions, usability, accessibility, Windows/macOS behavior, recovery
success, independent audit, certification или legal compliance.

Actual GUI picker, source open/read, recovery-secret intake, Stage 2.8
invocation и review-session preparation изискват нов threat review и отделни
frozen stages.

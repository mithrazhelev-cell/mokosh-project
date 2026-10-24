# MOKOSH — договор за recovery source inspection request

Статус: Stage 2.29 — inactive one-shot искане за бъдеща сигурна инспекция;
няма source open/read/identity, access authorization, secret, recovery session
или operation authority.

## 1. Цел и trust boundary

Stage 2.29 поставя отделна pure граница между Stage 2.27 path selection и
всеки бъдещ privileged source-access слой. Той приема само exact положителен
`VaultRecoverySourceSelectionOutcome` и записва едно от две решения:

- `REQUEST_FUTURE_SECURE_SOURCE_INSPECTION`;
- `PRESERVE_AND_STOP`.

Искането е bounded process-local intent. То не е access authorization,
capability, legal consent, file identity или доказателство за recovery.

## 2. Exact вход и complete mediation

`prepare_recovery_source_inspection_request()`:

- изисква exact Stage 2.27 outcome type;
- изпълнява пълния Stage 2.27 schema validator;
- приема само `SELECT_LOCAL_RECOVERY_RECORD` със strict валиден path;
- отказва preserve, subclass, malformed route, version/sequence mismatch и
  всеки forged source/access/secret/operation/filesystem claim;
- копира само exact locale/decisions/path metadata и не задържа original
  Stage 2.27 outcome.

Конструирането на schema-подобен object не създава authority. Бъдещият
privileged stage трябва отново да валидира целия transcript и да използва
отделна explicit mediation граница.

## 3. Path privacy и ограничения

Selected path остава недоверено sensitive metadata:

- не се нормализира, resolve-ва или hash-ва;
- не се показва, логва или persist-ва;
- е `repr=False` в outcome;
- prepared object и outcome отказват copy/deepcopy/pickle;
- preserve route го изхвърля и връща `selected_path=None`;
- positive request го предава byte-for-byte като Python text само за бъдещ
  stage.

Python `str` не може да даде доказуема memory zeroization. Path може да стане
stale или да сочи друг filesystem object след избора; той никога не се приема
като identity, authenticity, ownership или permissions evidence.

## 4. One-shot и concurrency semantics

Prepared object започва в `AWAITING_INSPECTION_DECISION`. Invalid decision type
fail-ва без consumption, за да може caller-ът да поправи programming error.
Първото exact enum решение atomically:

- създава един immutable bounded outcome;
- clear-ва path от prepared object;
- преминава terminal `COMPLETED`;
- отказва всеки replay и concurrent втори consumer.

Няма reset, retry, callback, executor или automatic transition.

## 5. Exact no-authority schema

И при positive request, и при preserve следните claims са exact `false`:

- source opened/content read/identity validated/access authorized/prepared;
- recovery secret received и review session prepared;
- operation authorized/performed;
- recovery-source filesystem access/mutation;
- network used и automatic transition.

Само positive request има
`future_secure_source_inspection_requested=true`, retained path metadata и
`contains_sensitive_path_metadata=true`. Preserve route има exact обратните
стойности и няма path.

## 6. Import и capability граница

Модулът import-ва само Python standard library и exact Stage 2.19, 2.21, 2.22
и 2.27 pure contracts. Няма GUI, storage, reconciliation, workflow, review,
candidate, publish, crypto, process, network или logging import.

Няма `open`, `read`, `stat`, `lstat`, `resolve`, `realpath`, directory listing,
dynamic execution, callback, executor, descriptor или caller-supplied object
capability.

## 7. Връзка с бъдещ secure source access

Stage 2.5 `_read_recovery_path` остава единственият reviewed POSIX secure-read
core. Бъдещият privileged stage трябва да използва неговите descriptor-relative
`O_NOFOLLOW`, owner/mode/link-count, canonical filename, inode и bounded
changed-source проверки. Тези проверки не се дублират или симулират тук.

Stage 2.29 не защитава от path replacement/TOCTOU, защото умишлено не отваря
source. Следващият access stage не може да се довери на path string или request
flag и не може да прескочи към Stage 2.8 reconciliation.

## 8. Задължителни тестове

Точно 30 test methods покриват:

- BG/EN positive request и preserve;
- exact Stage 2.27 type/schema/positive-route revalidation;
- forged path, route, sequence, format и authority отказ;
- path redaction, exact-text retention и discard-on-preserve;
- copy/deepcopy/pickle отказ;
- invalid-input non-consumption, replay и concurrent exactly-one success;
- exact public constants, enums, signatures и bounded fields;
- AST import/capability boundary;
- byte-exact critical GUI, selection, storage, reconciliation, paths и runtime
  dependency files.

Expected full installer gate е 1479 теста: `OK`, expected failures=3 само за
legacy MOK1, `skipped=0`. Няма visual gate, защото няма GUI промяна.

## 9. Installer и source-hygiene gate

Installer-ът трябва да:

- изисква exact clean Stage 2.28 commit/tree/tag;
- използва exact seven-path payload allowlist и base hashes/modes;
- проверява ignored root-level Python shadow sources;
- компилира exact tracked/non-ignored Python manifest, а не `compileall .`;
- използва `LC_ALL=C` за locale-stable manifests;
- изпълни 30 targeted теста, full regression и isolated rollback probe;
- създаде commit/tag само след всички PASS резултати.

Външният protected legacy quarantine се проверява read-only и не се променя.

## 10. Frozen project scope

Stage 2.29 променя точно седем project paths:

- `PROJECT_STATUS_BG.md`;
- `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`;
- `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`;
- `docs/SESSION_LOG_BG.md`;
- този contract;
- `mokosh_vault_recovery_source_inspection_request.py`;
- `tests/test_mokosh_vault_recovery_source_inspection_request.py`.

`mokosh_gui.py`, Stage 2.27, storage, reconciliation, crypto, launchers и всички
historical tests остават byte-exact.

## 11. Строго забранено

Stage 2.29 не:

- променя GUI или отваря picker;
- отваря, чете, parse-ва или identity-валидира source;
- разрешава source access или подготовка;
- приема password, recovery root/key, Vault session или keyring;
- извиква Stage 2.5, Stage 2.8, workflow, review, candidate или publish;
- променя user/recovery file;
- използва network, cloud, telemetry, logging или persistence;
- активира encryption, cleanup, Contacts или Sandbox;
- предоставя fallback или automatic recovery;
- твърди legal conformity, certification, independent audit или recovery
  success.

`SAFETY_MODE=True` остава задължително. Истински ценни recovery inputs остават
забранени.

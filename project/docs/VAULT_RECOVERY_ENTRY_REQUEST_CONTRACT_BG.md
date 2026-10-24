# MOKOSH — договор за неактивен recovery entry request

Статус: Stage 2.19 — bounded one-shot non-secret intent contract; няма GUI,
source preparation, review display или operation authority.

## 1. Цел

Stage 2.19 поставя отделна граница между бъдещо потребителско действие
„поискай recovery review“ и всяко по-късно source/API действие. Така бъдещ
main-GUI бутон не трябва директно да отваря файл, да чете Vault или да стартира
recovery workflow.

Този stage само записва едно exact locale-bound решение в паметта:

- `REQUEST_RECOVERY_REVIEW`; или
- `PRESERVE_AND_STOP`.

Нито едното решение не е разрешение за source или операция.

## 2. Public API

```python
prepare_recovery_entry_request(locale_id)
```

Допускат се само exact `bg-BG` и `en-GB`. Резултатът е fresh
`PreparedVaultRecoveryEntryRequest` с единствено действие:

```python
decide_once(decision)
```

Decision input е само exact `RecoveryEntryRequestDecision` enum. String,
boolean, друг enum или duck-typed value се отказва.

## 3. One-shot lifecycle

Prepared request има две състояния:

- `awaiting_decision`;
- `completed`.

Преходът се пази с process-local lock. При concurrent валидни опити точно един
връща outcome; останалият е replay отказ. Невалиден decision не консумира
request-а. След валиден decision няма reset, retry, copy, deepcopy или pickle.

## 4. Bounded outcome

`VaultRecoveryEntryRequestOutcome` съдържа само:

- exact locale;
- exact decision;
- completed state;
- взаимно изключващи се `review_requested`/`preserved_and_stopped`;
- fixed format/version/sequence и safety flags.

Няма password, recovery root/record, keyring, Vault/Recovery ID, path,
filename, workflow state, presentation, adapter, session, binding, callback,
executor или exception text.

## 5. Задължително false

Всеки outcome изисква `false` за:

- source access authorization;
- source selection/preparation;
- review session и main-GUI binding preparation;
- review display и normal-startup activation;
- operation authorization/performance;
- filesystem access, network и automatic transition.

Forged `true`, wrong type, inconsistent decision booleans, format, version или
sequence се отказват при dataclass validation.

## 6. Забранени зависимости и действия

Модулът не импортира filesystem, GUI, network, process, logging, recovery
source/storage/reconciliation/workflow/controller/bridge модули. Няма dynamic
execution, KDF, encryption/decryption, unlock, candidate, setup, publish,
retry, repair, cleanup или key deletion.

`mokosh_gui.py`, normal launcher, `crypto_core.py` и runtime requirements
остават byte-exact непроменени. `SAFETY_MODE=True` остава.

## 7. Задължителни тестове

- двата locale-а и двете exact решения;
- invalid locale/decision и non-consumption;
- one-shot replay и concurrent точно един outcome;
- copy/deepcopy/pickle отказ;
- outcome schema без sources, secrets или capabilities;
- forged authority/source/operation flags отказ;
- decision boolean, integer/bool, format и version validation;
- exact public signatures;
- static import/call boundary;
- byte-exact critical GUI/runtime файлове;
- full regression без skipped security тестове.

## 8. Непроменени ограничения

Stage 2.19 не добавя normal-startup recovery бутон, source picker, session,
binding или review display. Той не доказва recovery success, comprehension,
identity, usability, accessibility, platform certification, legal compliance
или independent audit.

Всяко бъдещо main-GUI wiring и всяко source access изискват отделен замразен
stage и fresh negative/security review.

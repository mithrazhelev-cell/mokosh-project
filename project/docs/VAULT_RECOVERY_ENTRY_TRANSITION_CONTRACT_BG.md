# MOKOSH — договор за non-secret recovery entry transition

Статус: Stage 2.21 — inactive one-shot complete-mediation boundary след exact
Stage 2.19 request outcome; няма source selection/preparation, GUI, review
session, filesystem или operation authority.

## 1. Цел

Stage 2.20 позволява на normal main GUI да създаде exact Stage 2.19 intent за
бъдещ recovery review. Този intent не трябва директно да се превръща в path,
credential, source object, review session или операция.

Stage 2.21 поставя отделен process-local transition gate. Той:

- приема само exact завършен `VaultRecoveryEntryRequestOutcome`;
- проверява повторно всички Stage 2.19 no-authority свойства;
- записва едно допълнително exact решение;
- връща само bounded non-secret outcome с всички capability flags false.

## 2. Public API

```python
prepare_recovery_entry_transition(entry_outcome)
```

Input-ът трябва да е exact `VaultRecoveryEntryRequestOutcome`, не subclass,
mapping или duck-typed object. Prepared object-ът предоставя само:

```python
decide_once(decision)
```

Decision input е exact `RecoveryEntryTransitionDecision`:

- `PRESERVE_AND_STOP`;
- `PROCEED_TO_FUTURE_SOURCE_SELECTION`.

Втората стойност означава само bounded intent за бъдещ отделен
source-selection boundary. Тя не избира, не отваря и не подготвя source.

## 3. Route mediation

Exact Stage 2.19 `REQUEST_RECOVERY_REVIEW` допуска и двете Stage 2.21 решения.
Exact Stage 2.19 `PRESERVE_AND_STOP` допуска само ново
`PRESERVE_AND_STOP`. Опит preserve route да продължи се отказва без consumption
на prepared object-а.

Така Stage 2.20 request не се превръща автоматично в source selection и
preserve решението не може да бъде отменено от по-късен слой.

## 4. One-shot lifecycle

Prepared transition има exact states:

- `AWAITING_TRANSITION_DECISION`;
- `COMPLETED`.

Process-local lock сериализира concurrent опити. Точно един валиден transition
може да завърши. Wrong type или wrong route не консумира fresh object-а.
След success няма reset, retry, copy, deepcopy или serialization.

Prepared object-ът не задържа original Stage 2.19 outcome. След strict
validation той пази само exact locale и exact entry decision.

## 5. Bounded outcome

`VaultRecoveryEntryTransitionOutcome` съдържа само:

- exact locale;
- exact Stage 2.19 entry decision;
- exact Stage 2.21 transition decision;
- completed state;
- mutually exclusive `future_source_selection_requested` и
  `preserved_and_stopped`;
- fixed format/version/sequences и safety flags.

Outcome-ът няма password, new password, recovery root/record, keyring,
Vault/Recovery ID, path, filename, storage, reconciliation result, workflow,
session, binding, callback, executor или exception text.

## 6. Задължително false

Всеки outcome изисква `false` за:

- source access authorization;
- source selection и preparation;
- review session и main-GUI binding preparation;
- review display;
- operation authorization/performance;
- filesystem access;
- network use;
- automatic transition.

`future_source_selection_requested=True` е само intent flag и не променя нито
едно от тези ограничения.

## 7. Забранени зависимости и действия

Stage 2.21 модулът не импортира директно filesystem, GUI, network, process,
logging, storage, reconciliation, workflow, controller, bridge, candidate,
publish или cleanup модул. Единствената MOKOSH source dependency е exact Stage
2.19 request contract и неговият exact locale enum.

Няма dynamic execution, KDF, encryption/decryption, source read, file picker,
unlock, candidate, setup, publish, retry, repair, cleanup или key deletion.

`mokosh_gui.py`, normal launcher, `crypto_core.py`, runtime requirements и
Stage 2.19 request module остават byte-exact. `SAFETY_MODE=True` остава.

## 8. Задължителни тестове

- двата locale-а и двата exact Stage 2.19 routes;
- proceed/preserve mapping и preserve-route downgrade отказ;
- invalid source/decision без consumption;
- strict повторна Stage 2.19 validation;
- one-shot replay и concurrent точно един success;
- copy/deepcopy/pickle отказ;
- bounded outcome без sources, secrets, paths или capabilities;
- forged authority/source/operation flags отказ;
- exact public signatures;
- static import/call boundary;
- byte-exact critical files и `SAFETY_MODE=True`;
- full regression без skipped security tests.

## 9. Непроменени ограничения

Stage 2.21 не добавя GUI wiring, source picker, Vault/recovery input, review
session, binding или display. Не извършва recovery и не доказва source
authenticity, user identity/comprehension, platform certification, independent
audit или legal compliance.

Всяко бъдещо source selection, secret intake, filesystem read или Stage 2.8
reconciliation invocation изисква отделен frozen stage, fresh threat review и
нови negative/fault/platform gates.

# MOKOSH — договор за main-GUI recovery entry transition widget/event

Статус: Stage 2.25 — отделно видимо one-shot действие върху exact Stage 2.21
non-secret transition contract; няма source selection/preparation, secret
intake, recovery review или operation authority.

## 1. Цел

Stage 2.20 позволява normal main GUI да запише exact Stage 2.19 заявка за
бъдещ recovery review. Stage 2.21 предоставя отделна process-local transition
граница, но до Stage 2.24 normal GUI не я извиква.

Stage 2.25 добавя второ ясно отделено действие. То остава заключено, докато
потребителят не завърши Stage 2.19 с `REQUEST_RECOVERY_REVIEW`. Първата заявка
само отключва втория бутон. Тя не подготвя Stage 2.21 и не отваря следващ
прозорец.

## 2. Видима normal-startup граница

Normal startup без prepared Stage 2.17 binding показва:

- съществуващия Stage 2.20 request banner/button;
- отделен Stage 2.25 banner за бъдещото no-source intent;
- отделен Stage 2.25 button, който започва disabled.

Stage 2.25 button се активира само след exact положителен Stage 2.19 outcome.
Stage 2.19 `PRESERVE_AND_STOP`, invalid/failing request или replay не го
активират. Conditional Stage 2.18 prepared-review session не показва нито
Stage 2.20, нито Stage 2.25 entry действията.

## 3. Explicit second action

Едва при отделно натискане на активирания Stage 2.25 button event-ът:

1. преминава от `ready` към `deciding` под process-local lock;
2. изчиства retained bounded Stage 2.19 outcome и изключва бутона;
3. извиква `prepare_recovery_entry_transition()` с exact outcome;
4. показва отделно exact Yes/No confirmation;
5. преобразува Yes само до
   `PROCEED_TO_FUTURE_SOURCE_SELECTION`, а No/close само до
   `PRESERVE_AND_STOP`;
6. извиква Stage 2.21 `decide_once()` точно веднъж;
7. показва bounded резултат без source, path, secret или exception text.

`PROCEED_TO_FUTURE_SOURCE_SELECTION` означава само intent за бъдещ отделен
stage. То не избира, не отваря и не подготвя recovery source.

Second confirmation и terminal result използват exact locale от retained
Stage 2.19 outcome. Междинна промяна на global GUI езика не може да промени
locale binding-а на вече записаната заявка.

## 4. Lifecycle и fail-closed поведение

Stage 2.25 event има exact states:

- `locked`;
- `ready`;
- `deciding`;
- `completed`;
- `failed`.

До `ready` programmatic call връща без действие. Exact positive Stage 2.19
outcome може да arm-не event-а само веднъж. При concurrent calls точно един
може да премине към `deciding`; останалите връщат без второ действие.

Missing/destroyed button, forged Stage 2.19 outcome, Stage 2.21 отказ или друг
regular Python error консумират event-а fail-closed и показват generic fixed
съобщение. `KeyboardInterrupt` и други process-level exceptions се пропускат
само след terminal consumption. Няма reset или retry.

## 5. Retention граница

Между двете отделни действия Stage 2.25 event задържа само exact bounded
`VaultRecoveryEntryRequestOutcome`. Той няма password, recovery root/record,
keyring, Vault/Recovery ID, path, filename, callback, executor или operation
capability.

При второто натискане outcome-ът се изчиства преди Stage 2.21 preparation.
Stage 2.21 го проверява изцяло отново, включително всички false safety flags,
format, version, sequence и route invariants. Process-local retention не е
persisted consent, digital signature, authentication или cross-restart token.

## 6. Import и dependency граница

Normal `mokosh_gui` import добавя само exact Stage 2.21 transition module към
вече разрешените Stage 2.19 request и Stage 2.22 locale leaf модули. Stage
2.21 е stdlib-only по transitive MOKOSH dependency closure и не зарежда
recovery storage, reconciliation, workflow, controller, bridge или review
window.

Няма dynamic import, plugin loader, caller-supplied callback или executor.
Stage 2.23 conditional heavy-recovery isolation остава.

## 7. Строго забранени действия

Stage 2.25:

- не избира, не отваря и не подготвя source, path, file или Vault;
- не приема password, recovery root/record, keyring или друг secret;
- не извиква Stage 2.8 reconciliation, Stage 2.9 workflow, Stage 2.16 session,
  Stage 2.17 binding или Stage 2.18 review;
- не извършва unlock, candidate, setup, publish, retry, rollback, repair,
  cleanup, key deletion, encryption или decryption;
- не предоставя filesystem access или operation authority;
- няма persistence, network, telemetry, logging, Guardian, update или
  licensing;
- няма automatic transition.

`SAFETY_MODE=True` остава. Legacy encryption, cleanup, Contacts и Sandbox
controls остават disabled. Legacy MOK1 decryption остава отделена recovery
compatibility функция и не получава MOKOSH v2 claims.

## 8. Локализация и visible Linux gate

Stage 2.25 добавя fixed Bulgarian/English banner, button, confirmation,
success, preserve и failure текстове. Няма runtime interpolation на path,
secret или exception text.

Отделният development launcher използва normal `mokosh_gui.main()` само със
synthetic human interaction. Потребителят не въвежда password и не избира
Vault. Наблюдават се:

- видими request и initially locked transition controls;
- първият Yes отключва само втория button;
- второто confirmation ясно отказва source/operation claim;
- резултатът казва, че е записано само бъдещо intent;
- не се отваря picker, Vault, review или recovery operation;
- двата използвани бутона остават one-shot и safety controls са видими.

Report-ът съдържа само fixed pass/fail/not-checked observations. Stage 2.26
version-2 schema отчита existing runtime-directory preparation като `true` и
ограничава false filesystem claims само до recovery-source access/mutation.
Това не е usability/accessibility audit или platform certification.

## 9. Задължителни automated тестове

- exact Bulgarian/English locked banner/button/confirmation/results;
- positive request arm и preserve-route non-arm;
- no Stage 2.21 preparation преди отделното второ натискане;
- Yes/No mapping към exact Stage 2.21 enums;
- disable/clear-before-prepare ordering;
- forged Stage 2.19 outcome revalidation;
- one-shot replay и concurrent точно един transition;
- missing/destroyed widget и preparation/decision errors fail-closed;
- generic error без exception text;
- process-level exception propagation след consumption;
- normal construction и conditional-review exclusion;
- language-switch update и retained entry-locale binding;
- bounded visual report и forged true-claim отказ;
- static import/call/dependency boundary;
- exact critical core hashes и `SAFETY_MODE=True`;
- full regression без skipped mandatory security tests.

## 10. Честни ограничения

Stage 2.25 не доказва recovery success, source authenticity, user identity,
comprehension, accessibility, Windows/macOS behavior, independent audit,
certification или legal compliance.

Следващ source-selection contract, secret intake, filesystem read, Stage 2.8
invocation, review-session preparation или operation authority изискват fresh
review, отделен frozen stage и нови negative/fault/platform gates.

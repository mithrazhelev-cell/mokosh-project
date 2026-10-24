# MOKOSH — договор за normal-startup recovery entry widget/event

Статус: Stage 2.20 — видим one-shot non-secret request в нормалния main GUI;
няма recovery source, review display, automatic transition или operation
authority.

## 1. Цел

Stage 2.20 свързва нормалния MOKOSH прозорец само с exact Stage 2.19 entry
request contract. Потребителят може да запише намерение за бъдещ recovery
review, без бутонът да отваря Vault, файл, keyring или recovery workflow.

Това е UI граница за намерение, а не начало на възстановяване.

## 2. Normal-startup widget

При обичайното `main()` стартиране се показват:

- fixed локализиран banner за no-source/no-operation границата;
- един бутон за заявка;
- confirmation с exact Yes/No решение.

Езикът се определя само от текущия allowlisted GUI език и се преобразува exact
до `bg-BG` или `en-GB`. Смяната на GUI езика обновява banner-а и бутона.

Условната Stage 2.18 prepared-review session не показва Stage 2.20 entry
widget. Двата режима не се смесват.

## 3. Exact request flow

След първото валидно натискане event-ът:

1. преминава от `ready` към `deciding` под process-local lock;
2. изключва бутона преди request preparation;
3. подготвя fresh exact Stage 2.19 request само от locale;
4. преобразува Yes само до `REQUEST_RECOVERY_REVIEW`, а No/close само до
   `PRESERVE_AND_STOP`;
5. извиква `decide_once` точно веднъж;
6. показва generic bounded резултат и приключва като `completed`.

Няма automatic transition след `REQUEST_RECOVERY_REVIEW`. Заявката не се пази
на диск и не отваря следващ UI слой.

## 4. Fail-closed lifecycle

Състоянията са exact:

- `ready`;
- `deciding`;
- `completed`;
- `failed`.

Replay или concurrent call връща без второ действие. Липсващ/повреден button,
Stage 2.19 error или друг regular Python error консумира event-а и показва
generic съобщение без exception text. `KeyboardInterrupt` и друг process-level
exception се пропускат след terminal consumption. Няма reset или retry.

## 5. Safety граница

Stage 2.20 не приема, съхранява или извиква:

- password, nickname, recovery root/record, keyring, Vault/Recovery ID;
- path, filename, source picker, source preparation или filesystem API;
- Stage 2.8 reconciliation, Stage 2.9 workflow, Stage 2.16 session или Stage
  2.17 binding;
- review display, unlock, candidate, setup, publish, cleanup или key deletion;
- callback, executor, plugin, dynamic import, network или telemetry.

Returned Stage 2.19 outcome изисква false за source, preparation, display,
normal recovery activation, operation, filesystem, network и automatic
transition flags. `SAFETY_MODE=True` остава.

## 6. Visible Linux gate

Отделният development launcher стартира exact normal `mokosh_gui.main()` в
`bg-BG` и `en-GB`. Потребителят не въвежда password и не избира Vault. Той
наблюдава само:

- banner и button visibility;
- ясно confirmation съобщение;
- ясно request-result съобщение;
- липса на file/Vault picker или recovery review;
- disabled one-shot button и видима safety-mode граница.

Report-ът съдържа само fixed pass/fail/not_checked стойности. Stage 2.26
version-2 schema отчита existing runtime-directory preparation като `true` и
ограничава false filesystem claims само до recovery-source access/mutation.
Human observation не е техническа проверка, usability/accessibility audit или
platform certification.

## 7. Задължителни automated тестове

- exact Bulgarian/English banner, button, confirmation и result;
- Yes/No mapping към exact Stage 2.19 enums;
- disable-before-prepare, replay и concurrent точно един request;
- missing/destroyed widget, Stage 2.19 error и unknown error fail-closed;
- interrupt propagation след consumption;
- normal startup показва entry без automatic request;
- conditional Stage 2.18 session не показва Stage 2.20 entry;
- language switch обновява exact texts;
- bounded visual report и forged false-claim отказ;
- static import/call boundary без source/operation API;
- byte-exact Stage 2.19 request, launcher, crypto core и requirements;
- full regression: 1268 tests, expected failures=3 само за legacy MOK1,
  skipped=0.

## 8. Непроменени ограничения

Stage 2.20 не доказва recovery success, source authenticity, user identity или
comprehension. Не е Windows/macOS evidence, independent audit, legal review
или production activation. Всяко source access, review-session preparation и
следващо свързване изискват отделен Stage 2.21 scope freeze и fresh negative
security review.

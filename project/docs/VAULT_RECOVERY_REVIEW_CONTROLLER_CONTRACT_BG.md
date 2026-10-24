# MOKOSH — договор за recovery review session controller

Статус: Stage 2.16 — реализиран изолиран application-service bridge към
съществуващите Stage 2.10–2.14 read-only review слоеве.

## 1. Цел

Stage 2.16 предоставя една контролирана граница, която бъдещият основен GUI
може да използва, без да импортира и сглобява самостоятелно presentation,
acknowledgement, localization и review-window lifecycle-а.

Controller-ът:

- приема един exact вече взет Stage 2.9 in-memory workflow state;
- приема един exact locale `bg-BG` или `en-GB`;
- подготвя fresh Stage 2.10 presentation и Stage 2.12 adapter;
- валидира Stage 2.13 localization и Stage 2.14 preparation без показване;
- по-късно приема само съществуващ Tk parent и показва Stage 2.14 window;
- връща само повторно валидиран bounded Stage 2.14 outcome.

Той не изпълнява recovery, не отключва Vault и не дава authority за следваща
операция.

## 2. Реализация и public API

Реализацията е в `mokosh_vault_recovery_review_controller.py`.

Единствената public module функция е:

```python
prepare_recovery_review_session(workflow_state, locale_id)
```

Тя връща `PreparedVaultRecoveryReviewSession`. Единственото display действие
върху подготвената session е:

```python
prepared.show_once(parent)
```

Public API няма password, recovery root, keyring, Vault path, filename,
callback, executor, operation, retry, repair, cleanup или network параметър.

Stage 2.17 добавя само bounded read-only `locale` property върху prepared
session-а. Тя връща exact Stage 2.13 enum и не излага presentation, adapter,
workflow state, source identifier или operation authority.

## 3. Exact входна граница

`workflow_state` трябва да бъде exact `VaultRecoveryWorkflowState` от Stage
2.9. Stage 2.10 го валидира повторно, включително:

- classification, decision, state и ordered gates;
- exact route mapping;
- read-only и no-authority flags;
- липса на candidate, unlock, setup, publish, retry, repair, cleanup, key
  deletion или user-file mutation authority.

Subclass, mapping, string, tuple или duck-typed object се отказва. Forged
state с добавена authority стойност се отказва преди GUI display.

`locale_id` приема само exact `bg-BG` или `en-GB` чрез Stage 2.13 allowlist.
Няма normalization, environment locale или silent fallback.

## 4. Подготовка без display

Preparation последователността е фиксирана:

1. Stage 2.10 създава presentation от exact Stage 2.9 state;
2. Stage 2.12 създава fresh one-shot UI adapter;
3. Stage 2.14 валидира exact presentation/adapter/locale binding;
4. controller-ът запазва само bounded presentation, fresh adapter, locale и
   expected presentation digest.

Оригиналният Stage 2.9 state не се задържа от controller session-а. Това
предотвратява задържане на неговите internal Recovery/Vault identifiers,
receipts, revisions и evidence digests в GUI bridge state.

Preparation не създава Tk widget, не стартира `mainloop` и не активира
`mokosh_gui.py`.

## 5. One-shot lifecycle

Lifecycle enum-ът има точно четири състояния:

- `prepared`;
- `displaying`;
- `completed`;
- `failed`.

Само `prepared` може да премине към `displaying`. Състоянието се сменя под
process-local lock преди Stage 2.14 display call, така че concurrent втори
опит се отказва преди втори прозорец.

След acknowledged или cancelled outcome session-ът е `completed`. След display,
source, interaction, mismatch или validation failure е `failed`. Keyboard
interrupt и друг process-level exception се пропускат към caller-а, но session
източниците се изчистват и session-ът остава consumed.

Няма blind retry. Нов опит изисква нова preparation и следователно ново
пълно Stage 2.9–2.14 валидиране.

Session object не може да се copy, deepcopy или serialize/pickle.

## 6. Outcome binding

Stage 2.14 outcome се реконструира чрез dataclass validation преди връщане.
Controller-ът допълнително изисква:

- exact `VaultRecoveryReviewWindowOutcome` type;
- exact prepared locale;
- constant-time equality на exact prepared presentation SHA-256;
- всички Stage 2.14 read-only/no-authority invariants;
- валиден Stage 2.12 receipt само при acknowledged decision;
- exact cancellation reason само при cancelled decision.

Wrong locale, wrong digest, subclass, mapping, arbitrary string, forged
authority или forged operation flag се отказва и session-ът се консумира като
`failed`.

След terminal outcome или failure controller-ът премахва internal reference-ите
към presentation и adapter. Bounded immutable outcome може да остане достъпен
само след успешен `completed` lifecycle.

## 7. Какво acknowledgement означава

`acknowledged` доказва само, че exact visible fixed confirmation sequence е
приета от Stage 2.12 през реалния Stage 2.14 прозорец.

То не доказва, че потребителят е разбрал текста, не е digital signature и не
разрешава:

- Vault unlock;
- recovery candidate или setup;
- publish, retry, repair или cleanup;
- key deletion или user-file mutation;
- network, update, Guardian или licensing действие.

`cancelled` не acknowledgement-ва Stage 2.12 adapter-а. Controller session-ът
въпреки това приключва и не може да бъде използван повторно.

## 8. Static trust boundary

Controller модулът няма import или direct call към:

- filesystem, path, process, network или logging API;
- `mokosh_gui.py`;
- Vault parse/storage, recovery record/root или reconciliation I/O;
- candidate, publish, retry, repair, cleanup или key deletion executor;
- Contacts, telemetry, Guardian, update или licensing код;
- dynamic import, `eval`, `exec` или plugin loading.

Допустими са само standard-library immutable validation/lifecycle primitives и
bounded Stage 2.9–2.14 types/functions.

## 9. Main GUI статус

Stage 2.16 не променя и не импортира `mokosh_gui.py`. `SAFETY_MODE` остава
exact `True`. Controller-ът е подготвена application-service граница, а не
активиран main-GUI recovery feature.

Бъдещо свързване към основния GUI изисква отделен замразен scope, tests и
visible review. То не може да добави истински Vault input или operation
authority чрез този controller.

## 10. Задължителни тестове

- preparation за четирите route-а и двата locale-а;
- exact source/locale type и forged-authority отказ;
- direct mismatched presentation/adapter отказ;
- acknowledged chain през Stage 2.10–2.14;
- exact Cancel, Escape и window-close outcomes;
- wrong locale/digest и forged authority outcome отказ;
- non-outcome и subclass отказ;
- success replay и post-failure retry отказ;
- display failure и KeyboardInterrupt consumption;
- concurrent attempts с точно един display;
- copy/deepcopy/pickle отказ;
- outcome schema без source identifiers, secrets, path или capability;
- static import/call boundary;
- доказателство, че `mokosh_gui.py` остава непроменен и fail-closed;
- пълен regression без skipped security tests.

## 11. Ограничения

Stage 2.16 не е cross-platform certification, usability audit, legal review,
recovery success evidence или production activation. Той доказва ограничената
application-service композиция при exact тестваните входове и среда.

Linux Stage 2.15 visible резултатът не се пренася автоматично към Windows или
macOS. Отделните platform и accessibility проверки остават задължителни преди
съответен публичен claim.

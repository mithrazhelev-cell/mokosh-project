# MOKOSH — договор за recovery locale leaf boundary

Статус: Stage 2.22 — pure stdlib-only leaf за exact recovery locale identity;
няма GUI, source selection/preparation, filesystem, crypto backend или
operation authority.

## 1. Причина

До Stage 2.21 `RecoveryLocalizationLocale` е дефиниран в големия Stage 2.13
localization модул. Затова import само на Stage 2.19 request или Stage 2.21
transition транзитивно зарежда presentation, adapter, reconciliation, workflow,
Vault storage и cryptography зависимости, въпреки че entry contract-ите не ги
използват.

Това не е извършвало recovery операция, но разширява import-time trust и
dependency boundary повече от необходимото.

## 2. Leaf contract

`mokosh_vault_recovery_locale.py` съдържа само exact enum:

- `BULGARIAN_BULGARIA = "bg-BG"`;
- `ENGLISH_UNITED_KINGDOM = "en-GB"`.

Модулът импортира само `__future__` и standard-library `enum`. Няма функции,
dataclass, parser, fallback, locale detection, filesystem или runtime catalog.

## 3. Съвместимост

Stage 2.13 localization модулът import-ва и re-export-ва същия exact enum
object. Съществуващите import-и през
`mokosh_vault_recovery_localization.RecoveryLocalizationLocale` продължават да
получават същия тип.

Stage 2.19 request и Stage 2.21 transition import-ват enum-а директно от leaf
модула. Техните public API, format/version, enum decisions, schemas, lifecycle
и no-authority semantics остават непроменени.

## 4. Доказуема import граница

В fresh Python process:

- leaf import зарежда само leaf MOKOSH модула;
- Stage 2.19 import зарежда само request + leaf;
- Stage 2.21 import зарежда само transition + request + leaf;
- и трите import-а работят при блокирани `cryptography`, `argon2`, `tkinter`,
  storage, reconciliation, workflow, controller и bridge dependencies.

Това е dependency isolation, не cryptographic validation или platform
certification.

## 5. Забранени действия

Stage 2.22:

- не избира и не подготвя recovery source;
- не приема password, recovery root/record, keyring, Vault ID, path или file;
- не създава review session, binding, picker, callback или executor;
- не извиква Stage 2.8 reconciliation, workflow, unlock, candidate, setup,
  publish, cleanup, encryption или decryption;
- няма filesystem, network, telemetry, Guardian, update, licensing или
  automatic transition;
- не предоставя operation authority.

`mokosh_gui.py`, launcher, `crypto_core.py` и runtime requirements остават
byte-exact. `SAFETY_MODE=True` остава.

## 6. Задължителни тестове

- exact два enum members, values, order, aliases и public export;
- exact type identity през leaf/localization/request/transition;
- непроменено Stage 2.19 и Stage 2.21 поведение;
- pickle identity round-trip;
- fresh-process exact import closure;
- blocked privileged/backend dependency import probe;
- AST import/call boundary;
- unchanged localization catalog cardinality;
- byte-exact critical runtime files и `SAFETY_MODE=True`;
- full regression без skipped security tests.

## 7. Непроменени ограничения

Stage 2.22 не свива целия transitive import graph на legacy main GUI, защото
той все още съдържа отделния Stage 2.17 conditional review seam и legacy login.
Това не трябва да се представя като цялостна GUI module isolation.

Следващо GUI wiring, source access, secret intake или operation invocation
изисква отделен fresh review и frozen stage.

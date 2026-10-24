# MOKOSH — договор за normal-main-GUI recovery import isolation

Статус: Stage 2.23 — conditional direct import boundary за съществуващия exact
Stage 2.17 bridge; няма нов GUI flow, source selection/preparation или operation
authority.

## 1. Причина

След Stage 2.22 pure entry request/transition contract-ите имат минимална
dependency граница. `mokosh_gui.py` обаче продължава да import-ва Stage 2.17
bridge на module level. Така обикновеният module import и normal startup
транзитивно зареждат review controller, review window, localization,
presentation, adapter, reconciliation, workflow и Vault storage модули, въпреки
че няма prepared review binding.

Това не е извършвало recovery или filesystem операция, но разширява
normal-startup code/dependency attack surface повече от необходимото.

## 2. Frozen boundary

Stage 2.23 премахва Stage 2.17 bridge от runtime module-level imports на
`mokosh_gui.py`. Един private no-argument helper използва обикновен explicit
Python `from ... import ...` само когато вече съществува explicit conditional
review path.

При normal `import mokosh_gui` и normal `main()` без binding:

- normal startup не зарежда Stage 2.17 bridge;
- не се зареждат controller, review window, recovery storage, reconciliation
  или workflow през bridge-а;
- Stage 2.20 entry request и pure locale leaf остават налични;
- не се създава review session, binding или display.

## 3. Conditional compatibility

Когато caller изрично подаде exact fresh
`PreparedMainGUIRecoveryReviewBinding`, private helper import-ва само:

- `PreparedMainGUIRecoveryReviewBinding`;
- `RecoveryMainGUIBridgeState`;
- `VaultRecoveryMainGUIBridgeError`.

Existing Stage 2.17 exact-type/state checks, Stage 2.18 one-shot event,
source-clearing, generic failure handling и bounded display outcome остават.
`TYPE_CHECKING` import-ът е само за static annotation и не се изпълнява runtime.

Няма `importlib`, `__import__`, plugin loader, string module name или caller
supplied import target.

## 4. Непроменен GUI

Stage 2.23 не променя:

- normal или conditional widget texts;
- button labels, commands, order или one-shot semantics;
- layout, geometry, colors или locale mapping;
- Stage 2.20 Yes/No request behavior;
- Stage 2.18 prepared-review behavior;
- launcher или normal `main()` call без аргументи.

Затова няма нов visual claim или platform certification. Existing automated
construction/event tests остават задължителни.

## 5. Забранени действия

Stage 2.23:

- не избира и не подготвя recovery source;
- не приема password, recovery root/record, keyring, Vault ID, path или file;
- не свързва Stage 2.21 transition към GUI;
- не подготвя review session или binding;
- не извиква Stage 2.8 reconciliation, unlock, candidate, setup, publish,
  cleanup, encryption или decryption;
- няма нов filesystem, network, telemetry, Guardian, update или licensing;
- не предоставя operation authority и няма automatic transition.

`SAFETY_MODE=True` остава. Legacy encryption, cleanup, Contacts и Sandbox
controls остават disabled.

## 6. Задължителни тестове

- fresh-process exact normal import closure;
- blocked bridge/controller/storage/workflow import probe;
- bridge absence след normal import;
- exact conditional bridge load и type identity;
- module-level, `TYPE_CHECKING` и private-helper AST boundaries;
- no dynamic/plugin import;
- default `main()` без binding;
- helper reachability само през explicit review paths;
- conditional non-`None` guard преди bridge load;
- exact seam signature/type check;
- byte-exact GUI text registries;
- `SAFETY_MODE=True`;
- no source/operation imports;
- byte-exact bridge, controller, entry contracts, launcher, crypto core и
  requirements;
- full regression без skipped security tests.

## 7. Непроменени ограничения

Stage 2.23 е import/dependency hardening, не usability review, recovery success,
crypto validation, independent audit, legal conclusion или certification.

Следващо transition wiring, source access, secret intake, filesystem read или
operation invocation изисква fresh review и отделен frozen stage.

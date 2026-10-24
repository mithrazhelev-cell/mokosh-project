# Stage 2.31 — recovery source inspection preparation-request contract

## Цел

Stage 2.31 е неактивен, process-local и строго ограничен договор. Той приема
само exact positive Stage 2.29 inspection-request outcome и записва едно от:

- `REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION`;
- `PRESERVE_AND_STOP`.

Това е заявка за бъдеща подготовка, а не самата подготовка и не
authorization/capability за source достъп.

## Строги входни условия

- входът е exact `VaultRecoverySourceInspectionRequestOutcome`, без subclass;
- Stage 2.19/2.21/2.27/2.29 route, schema, sequences, booleans, format и
  version се revalidate-ват;
- допуска се само positive Stage 2.29 request с exact retained path metadata;
- malformed, forged или preserve outcome отказва fail-closed.

## One-shot и чувствителни metadata

- `decide_once()` допуска точно един terminal consumer за конкретния prepared
  object, включително при concurrent attempts;
- невалиден decision не консумира fresh prepared object;
- positive preparation request запазва същия `str` path object без
  normalize/hash/resolve/stat/open;
- preserve outcome не съдържа path;
- prepared и outcome object-ите отказват copy, deepcopy и pickle; repr не
  показва path;
- caller-owned Stage 2.29 outcome може да бъде използван за създаване на друг
  prepared object: Stage 2.31 не твърди global source-outcome consumption;
- immutable Python `str` не може да бъде надеждно zeroized; договорът не
  твърди memory zeroization и caller-owned outcome може да продължи да държи
  path metadata.

## Забранени възможности

Модулът няма GUI, filesystem, Stage 2.5/2.8, storage, crypto, secret, callback,
descriptor, network, logging, process или mutation capability. Той не извършва
source open/read/stat/identity/authenticity/permission validation, не издава
filesystem capability, не подготвя review session, не разрешава операция и не
стартира automatic transition.

## Доказателства и граница на твърденията

Точно 33 automated tests покриват BG/EN routes, exact source revalidation,
forged claims, path privacy/identity, one-shot/replay/concurrency,
non-serialization, bounded schema, import/AST capability boundary, unchanged
critical hashes и fresh normal-GUI import isolation.

Този stage не е complete-mediation proof за бъдещия privileged secure-read
слой, independent audit, platform certification или legal conformity. Реалната
source identity/access mediation остава задължение на отделен frozen Stage 2.32.

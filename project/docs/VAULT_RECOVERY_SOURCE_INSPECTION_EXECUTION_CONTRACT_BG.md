# MOKOSH Stage 2.32 — secure recovery-source inspection execution

## Статус и цел

Този contract дефинира неактивна, process-local и one-shot граница за точно
един структурен secure read на локален Vault recovery record. Той приема само
fully revalidated exact positive Stage 2.31 outcome и използва съществуващия
Stage 2.5 POSIX secure-reader; не го дублира или отслабва.

Stage 2.32 не е recovery, rehearsal, unlock, consent за бъдеща операция или
доказателство за криптографска автентичност.

## Решения

- `PRESERVE_AND_STOP` — terminal stop, без import на storage слоя и без
  filesystem access;
- `AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION` — разрешава точно едно извикване на
  Stage 2.5 `_read_recovery_path` за конкретния prepared object.

Невалиден decision не потребява fresh object. След започнал filesystem access
success, ordinary exception и `BaseException` са terminal; replay се отказва.
One-shot свойството не е глобално потребление на caller-owned Stage 2.31
outcome, от който caller може да създаде нов prepared object.

## Complete mediation и secure-read свойства

Преди privileged import/read selected path се премахва от prepared object.
Storage модулът се зарежда условно само след exact positive решение.
Съществуващият Stage 2.5 reader осигурява:

- absolute canonical path без symlink components;
- canonical recovery filename и binding към parsed `recovery_id`;
- exact 0700 current-user parent directory;
- exact 0600 current-user regular file с link count 1;
- retained root-to-parent descriptor chain с component-by-component
  `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` traversal и identity revalidation;
- regular/type/owner/mode/link/size validation преди content-capable open;
- descriptor-relative file open с `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`;
- bounded descriptor read;
- device/inode/mode/owner/link/size и mutation проверки преди, по време и след
  read;
- затваряне на file и всички directory descriptors във `finally`, включително
  при `BaseException`;
- повторна проверка на цялата directory chain и файла непосредствено преди
  success.

Това е Linux/POSIX engineering claim. Няма Windows/macOS certification.

## Bounded outcome

При success outcome съдържа само:

- locale и exact execution decision;
- observed `recovery_id` и `vault_id`;
- observed source revision;
- observed source-Vault SHA-256 и record SHA-256;
- bounded encoded size;
- explicit structural-inspection flags.

Всички evidence полета са скрити от `repr`. Outcome няма path, filename,
descriptor, record, preamble/header bytes, nonce, ciphertext, recovery secret,
password, plaintext, keyring или callback. Prepared object и outcome отказват
copy, deepcopy и serialization.

## Honest security claims

- Recovery header и framing са само строго структурно валидирани. Без recovery
  secret ciphertext/tag не са криптографски автентикирани.
- `filesystem_mutation_performed=False` означава липса на заявено application
  write/chmod/unlink/rename/replace/fsync действие. POSIX read може да промени
  kernel/filesystem-managed `atime`; forensic no-metadata-change не се твърди.
- `O_NONBLOCK` затваря известния FIFO blocking клас, но не е latency или hard
  real-time гаранция.
- Python immutable `str`/`bytes`, временни frames и exception traceback data не
  могат да бъдат доказано zeroized; не се прави zeroization claim.
- Outcome не задържа path/content/descriptor, но process memory lifetime не е
  system-call или forensic non-retention proof.
- File identity е наблюдавана само за завършилата inspection. Всеки бъдещ
  достъп трябва отново да отвори и revalidate-ва целия source.
- Inspection authorization не е recovery, rehearsal, Stage 2.8 reconciliation,
  review-session preparation или operation authorization.

## Забранени способности

Stage 2.32 не приема recovery secret; не decrypt-ва; не извиква rehearsal,
Stage 2.8, workflow, candidate или publish; не отваря Vault; не променя source
или друг filesystem обект; не използва GUI, network, logging, telemetry,
Contacts, Guardian или software update; не активира normal application path.

## Evidence boundary

Точно 44 Stage 2.32 automated tests покриват exact source revalidation, BG/EN
inspect/preserve, conditional privileged import, preserve-without-access,
success/failure/replay/concurrency, terminal ordinary/`BaseException` failure,
path clear-before-read, non-retention/non-serialization, real 0700/0600 read,
owner/mode/symlink/hardlink/filename/malformed/change rejection, read-only
snapshot, unauthenticated-ciphertext semantics, bounded schema, critical hashes
fresh-process import isolation, ancestor replacement, FIFO race и коректното
structurally-observed identifier значение. Допълнителните Stage 2.5 reader
тестове покриват stable FIFO pre-open отказ, descriptor cleanup и липса на
заявени mutating calls.

Този contract и тестовете са engineering evidence. Те не са independent audit,
formal verification, platform certification, правно становище или декларация
за съответствие.

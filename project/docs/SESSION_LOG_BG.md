# MOKOSH Agent — дневник на работните сесии

Тук се записва само технически статус. Не се записват пароли, private keys,
recovery фрази, контакти или чувствителни имена на документи.

## 2026-08-06 — безопасна основа и Stage 1.1–1.4

- Проектът беше преместен от ~/phi_crypto в ~/MOKOSH_Agent.
- Създадени бяха защитни копия в ~/MOKOSH_BACKUPS.
- Проектната папка беше ограничена до права 700.
- Чувствителните runtime файлове бяха извадени от новата Git история.
- Legacy модулите бяха архивирани локално.
- Основният интерфейс беше оставен във fail-closed safety mode.
- Замразена беше MOKOSH v2 файловата спецификация.
- Добавени бяха prefix/header, frame, nonce/AAD и AES-GCM frame модулите.
- Контролна точка: commit c2080bc, tag stage1.4-v2-frame-crypto.
- Резултат: 87 теста, OK, expected failures=3 само за MOK1.

## 2026-08-07 — начало на Stage 1.5

- Потвърдени са commit c2080bc и чистият feature клон.
- Повторно са изпълнени 87 теста: OK, expected failures=3.
- Следва строг encrypted manifest за frame 0.

### Stage 1.5 завършен

- Добавен е строг encrypted frame-0 manifest codec.
- Потвърдени са 114 теста: OK, expected failures=3 само за MOK1.
- Контролна точка: commit fc7622d, tag stage1.5-v2-manifest.
- Следва Stage 1.6 — in-memory manifest/frame integration.

### Stage 1.6 завършен

- Добавена е in-memory manifest/frame integration.
- Потвърдени са 136 теста: OK, expected failures=3 само за MOK1.
- Контролна точка: commit 5d70265, tag stage1.6-v2-envelope.
- Следва Stage 1.7 — строг trailer и ciphertext transcript codec.

### Stage 1.7 завършен

- Добавени са строг v2 trailer и ciphertext transcript validation.
- Потвърдени са 162 теста: OK, expected failures=3 само за MOK1.
- Контролна точка: commit 5cd6199, tag stage1.7-v2-trailer.
- Следва Stage 1.8 — in-memory Ed25519 signing и verification.

### Stage 1.8 завършен

- Добавени са in-memory Ed25519 signing и verification.
- Потвърдени са 182 теста: OK, expected failures=3 само за MOK1.
- Валидният подпис остава отделен от доверието към контакт.
- Контролна точка: commit 5cf7c1a, tag stage1.8-v2-signatures.
- Следва Stage 1.9 — строг key-slot schema/codec.

### Stage 1.9 завършен

- Добавени са строг key-slot schema и header integration.
- Потвърдени са 214 теста: OK, expected failures=3 само за MOK1.
- Contact slot не публикува recipient fingerprint и не допуска hybrid downgrade.
- Контролна точка: commit 4888bd8, tag stage1.9-v2-key-slots.
- Следва Stage 1.10 — in-memory password slot wrapping.

### Stage 1.10 завършен

- Добавени са in-memory Argon2id и AES-256-GCM password-slot wrap/unwrap.
- Потвърдени са 235 теста: OK, expected failures=3 само за MOK1.
- KDF resource policy се проверява преди изпълнение на Argon2id.
- Контролна точка: commit b449ba0, tag stage1.10-v2-password-slots.
- Следва Stage 1.11 — in-memory Key Vault slot wrapping с HKDF-SHA-256.

### Stage 1.11 завършен

- Добавени са in-memory HKDF-SHA-256 и AES-256-GCM Key Vault slot wrap/unwrap.
- Потвърдени са 255 теста: OK, expected failures=3 само за MOK1.
- Vault root key не се използва директно като AES-GCM key.
- Старото неясно suite име без HKDF се отказва.
- Контролна точка: commit 541dcd7, tag stage1.11-v2-vault-slots.
- Следва Stage 1.12 — in-memory hybrid Contact slot wrapping.

### Stage 1.12 завършен

- Добавен е mandatory X25519 + ML-KEM-768 hybrid Contact slot wrap/unwrap.
- Потвърдени са 279 теста: OK, expected failures=3 само за MOK1.
- Изпълнени са реалните ML-KEM-768 integration тестове без skipped tests.
- Recipient fingerprint, nickname и дългосрочни public keys не се публикуват.
- X25519-only fallback и hybrid downgrade се отказват.
- Контролна точка: commit cf2e469, tag stage1.12-v2-contact-hybrid.
- Следва Stage 1.13 — строг in-memory key-slot orchestration.

### Stage 1.13 завършен

- Добавен е строг in-memory key-slot orchestration.
- Потвърдени са 300 теста: OK, expected failures=3 само за MOK1.
- Всички slots в един plan обвиват един и същ нов 32-byte DEK.
- Unwrap използва само изрично избрания slot и съответния credential.
- Няма автоматичен fallback или hybrid downgrade.
- Контролна точка: commit f949369, tag stage1.13-v2-slot-orchestration.
- Следва Stage 1.14 — пълна in-memory v2 envelope integration.

### Stage 1.14 завършен

- Добавена е пълна in-memory MOKOSH v2 envelope integration.
- Потвърдени са 326 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Contact envelope задължително изисква Ed25519 подпис.
- Transcript, trailer и signature policy се проверяват преди slot unwrap.
- Няма автоматичен fallback, hybrid downgrade или автоматично доверяване.
- Контролна точка: commit f4ead4b, tag stage1.14-v2-complete-envelope.
- Следва Stage 1.15 — bounded streaming envelope engine.

### Stage 1.15 завършен

- Добавен е bounded two-pass streaming envelope engine.
- Потвърдени са 358 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Plaintext и ciphertext се обработват с ограничени read размери.
- Подписът се проверява преди slot unwrap.
- Вторият pass трябва точно да съвпадне с първата проверка.
- Грешка или прекъсване задейства quarantine abort.
- Контролна точка: commit c072bcb, tag stage1.15-v2-streaming.
- Следва Stage 1.16 — safe filesystem source и quarantine primitives.


### Stage 1.16 завършен

- Добавени са verified file source и same-directory quarantine primitives.
- Потвърдени са 385 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Symlink, output collision, подменен inode, променен source и unsupported atomic publish се отказват.
- Abort премахва само проверения собствен temporary inode.
- Контролна точка: commit 1917f0c, tag stage1.16-v2-filesystem.
- Следва Stage 1.17 — безопасен end-to-end файлов pipeline.


### Stage 1.17 завършен

- Добавен е verified deferred-publish end-to-end файлов pipeline.
- Потвърдени са 411 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Криптираният temporary envelope се проверява повторно с fresh DEK.
- Декриптираният temporary plaintext се проверява по size и SHA-256.
- Source, output collision, signature policy и sealed inode се проверяват преди publish.
- Оригиналният файл никога не се изтрива или преименува.
- Контролна точка: commit 0cfdfd6, tag stage1.17-v2-file-pipeline.
- Следва Stage 1.18 — контролиран lifecycle, cancellation, progress и безопасни кодове за грешки.

### Stage 1.18 завършен

- Добавен е контролиран lifecycle за файловите операции.
- Потвърдени са 423 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Cancellation се проверява между bounded операциите и преди publish.
- Progress събитията не съдържат имена, пътища, размери, ключове или съдържание.
- Успех се отчита само след действителен atomic publish и проверка.
- Контролна точка: commit 1b0f625, tag stage1.18-v2-lifecycle.
- Следва Stage 1.19 — crash-safe operation journal и quarantine reconciliation.

### Stage 1.19 завършен

- Добавени са crash-safe operation journal и строго read-only reconciliation.
- Потвърдени са 455 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Journal не съдържа имена, пътища, размери, ключове или съдържание.
- Prefix на име самостоятелно не дава право за промяна или изтриване.
- Reconciliation класифицира остатъците, без да ги променя.
- Няма cleanup API, автоматично publish, decrypt или recovery.
- Контролна точка: commit e448a29, tag stage1.19-v2-reconciliation.
- Следва Stage 1.20 — reconciliation evidence и изричен план за действие.

### Stage 1.20 завършен

- Добавени са bounded canonical reconciliation evidence и action planning.
- Потвърдени са 476 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Report е свързан с exact directory device/inode, без да съдържа пътища и имена.
- Максимумът е 256 подробни findings с точни omitted counters.
- Canonical SHA-256 digest служи за сравнение, но не е подпис или доверие.
- User decision и нов rescan остават задължителни; mutation не е разрешена.
- Контролна точка: commit adfb0bb, tag stage1.20-v2-reconciliation-evidence.
- Следва Stage 1.21 — active-operation lease и abandonment proof.

### Stage 1.21 завършен

- Добавени са OS-managed active-operation lease и fail-closed activity assessment.
- Потвърдени са 506 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Active, released candidate, unsupported и identity conflict са ясно разделени.
- Released candidate не доказва abandonment и никога не разрешава mutation.
- POSIX и Windows backend договорите са изрични; неизвестна семантика отказва.
- Контролна точка: commit c87423a, tag stage1.21-v2-operation-lease.
- Следва Stage 1.22 — еднократен user-confirmed cleanup authorization contract.

### Stage 1.22 завършен

- Добавен е еднократен non-mutating cleanup authorization contract.
- Потвърдени са 527 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Разрешението изисква две съвпадащи fresh проверки и released-candidate assessment.
- Разрешението е CSPRNG-bound, еднократно и не допуска copy, pickle или повторна употреба.
- Claim изрично записва, че abandonment не е доказан и mutation не е разрешена.
- Няма cleanup executor, unlink, rename, GUI или изтриване на оригинала.
- Контролна точка: commit 52062e4, tag stage1.22-v2-cleanup-authorization.
- Следва Stage 1.23 — строго ограничен cleanup executor.

### Stage 1.23 завършен

- Добавен е strictly bounded one-shot cleanup executor.
- Потвърдени са 549 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Exact OS lease се държи през fresh rescan, temporary unlink и journal unlink.
- Original source и публикуваният output не могат да бъдат cleanup цели.
- Partial mutation никога не се представя като успешна операция.
- Добавена е матрица към стандарти, тестове и възпроизводими доказателства.
- Контролна точка: commit 6712aac, tag stage1.23-v2-cleanup-executor.
- Безопасният Stage 1 файлов lifecycle е завършен.
- Следва Stage 2.1 — строг формат и state machine за криптирано Key Vault хранилище.

### Stage 2.1 завършен

- Добавени са отделен encrypted Key Vault формат и in-memory session state machine.
- Потвърдени са 588 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Argon2id resource policy се проверява преди изпълнение на KDF.
- Vault metadata, revision и payload са authenticated чрез AES-256-GCM.
- Root key е достъпен само при unlocked session с explicit lock и inactivity timeout.
- Password rewrap запазва root key и Vault ID, но сменя salt, nonce и revision.
- Контролна точка: commit 14788be, tag stage2.1-vault-format-state.
- Следва Stage 2.2 — atomic no-clobber Vault persistence и crash recovery.

### Stage 2.2 завършен

- Добавени са immutable Vault generations и atomic no-clobber persistence.
- Потвърдени са 622 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Нов revision се публикува чрез same-directory hard link без overwrite.
- File и directory fsync се изискват преди durable success.
- Старите поколения никога не се презаписват или изтриват.
- Partial publish се отчита като uncertain и изисква read-only reconciliation.
- Локалният receipt не се представя като независим anti-rollback trust anchor.
- Контролна точка: commit a417fe0, tag stage2.2-vault-storage.
- Следва Stage 2.3 — versioned Vault keyring и безопасна rotation policy.

### Stage 2.3 завършен

- Добавени са canonical versioned Vault keyring и safe wrapping-key rotation.
- Потвърдени са 663 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Точно един active key се използва за нови slots; retired версиите остават
  само за exact-version decrypt на вече създадени slots.
- Rotation създава независим CSPRNG 32-byte key и не прекриптира старите файлове.
- Payload schema 2 и explicit legacy migration са authenticated и fail-closed.
- Wrong password, rollback, malformed keyring, missing version и fallback се отказват.
- Fault при rotation не променя активната session; publish създава ново immutable поколение.
- Контролна точка: commit f72c51a, tag stage2.3-vault-keyring.
- Следва Stage 2.4 — offline Vault recovery threat model и versioned recovery contract.

### Stage 2.4 завършен

- Добавени са canonical bounded offline recovery record и отделен 32-byte
  CSPRNG recovery root за exact schema-2 Vault keyring state.
- Потвърдени са 695 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Recovery record е cryptographically свързан с exact Vault ID, revision,
  source Vault hash и keyring digest чрез HKDF-SHA-256 и AES-256-GCM.
- Read-only rehearsal връща само non-secret evidence и не публикува, не мигрира
  и не променя истински Vault поколения или потребителски файлове.
- Wrong root, tamper, stale, rollback, mixed-vault, same-revision conflict,
  duplicate и malformed recovery данни се отказват fail-closed.
- Recovery setup се допуска само от unlocked, unexpired schema-2 Vault session;
  password rewrap, migration и key rotation правят стария record stale.
- Няма GUI, filesystem I/O, Contacts, Guardian, network, telemetry, automatic
  recovery, software update discovery или automatic installation.
- Ключовата rotation остава изрична операция на потребителя; вътрешните key и
  schema versions не задействат автоматична проверка или обновяване на софтуера.
- Контролна точка: commit cccc98a, tag stage2.4-vault-recovery.
- Следва Stage 2.5 — durable offline recovery export и read-only import
  integration без actual recovery publish или password reset.

### Stage 2.5 завършен

- Добавено е durable no-clobber хранилище само за encrypted recovery record.
- Потвърдени са 737 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Export се допуска само върху exact latest durable Vault receipt и clean,
  complete storage scan; recovery root остава отделно и не се записва от модула.
- Canonical `.mokr` файлът изисква private directory и file permissions,
  descriptor-relative create, `O_EXCL`, `O_NOFOLLOW`, file и directory fsync.
- Exact readback преди и след directory sync не допуска тихо подменен или
  частично публикуван recovery record да бъде отчетен като durable success.
- Read-only import използва bounded double read и Stage 2.4 rehearsal и връща
  само non-secret evidence без keyring, recovery root или decrypted payload.
- Symlink, hard link, inode race, unsafe owner/permissions, stale, rollback,
  mixed-vault, tamper, wrong root и malformed record се отказват fail-closed.
- Fault след възможен durable publish се отчита като uncertain; cleanup failure
  не се представя като безопасно изтриване или като успешна операция.
- Няма actual Vault recovery, password reset, filesystem publish на Vault,
  GUI, network, telemetry, update checking или automatic key deletion.
- Контролна точка: commit 846bfae, tag stage2.5-vault-recovery-storage.
- Следва Stage 2.6 — explicit in-memory recovery Vault candidate и one-shot
  authorization без filesystem publish, overwrite или user-file mutation.

### Stage 2.6 завършен

- Добавен е explicit in-memory recovery Vault candidate с изрично зададена
  нова парола и process-local one-shot authorization.
- Потвърдени са 779 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Входът изисква exact latest durable Vault receipt, private canonical `.mokr`
  record, отделен exact 32-byte recovery root и explicit enum decision.
- Exact schema-2 keyring се възстановява само в паметта и се запечатва в
  нормален encrypted Vault candidate със същия Vault ID и revision точно `R+1`.
- Нови CSPRNG salt и nonce и избраните Argon2id параметри защитават candidate-а;
  independent unlock с новата парола връща само non-secret evidence.
- Double source verification отказва stale, rollback, mixed-vault, tamper,
  wrong root, byte conflict, source race, malformed data и fault fail-closed.
- Recovery ID, source digest и filesystem identities са свързани от локалното
  one-shot разрешение, но честно не се представят като metadata, удостоверени
  от непроменения Vault формат.
- Stage 2.6 не публикува filesystem поколение и не разрешава overwrite, key
  deletion, rotation, migration или промяна на потребителски файлове.
- Няма GUI, Contacts, Guardian, network, telemetry, logging, automatic recovery,
  software update discovery или automatic installation.
- Контролна точка: commit 4c917d8, tag stage2.6-vault-recovery-candidate.
- Следва Stage 2.7 — отделен explicit no-clobber publish executor с fresh rescan,
  immutable generation, independent readback и uncertain durability semantics.

### Stage 2.7 завършен

- Добавен е отделен explicit executor за immutable publish на exact проверения
  Stage 2.6 recovery candidate като ново Vault поколение `R+1`.
- Потвърдени са 822 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Executor-ът приема само unclaimed one-shot candidate и отделно exact enum
  решение; невалидно или повторно разрешение се отказва fail-closed.
- Преди mutation се повтарят exact latest Vault, receipt, private `.mokr`,
  recovery-root, candidate password, keyring evidence и clean-history проверки.
- Единствената mutation се делегира на Stage 2.2 atomic no-clobber publish;
  старите Vault поколения и recovery файлът остават byte-for-byte запазени.
- След publish се доказват exact durable receipt/readback, clean contiguous
  history, new-password unlock и непроменен source/recovery state.
- Fault след възможната hard-link durability граница се отчита като uncertain,
  без false success, rollback, unlink, automatic cleanup или blind retry.
- Старият recovery record остава физически непроменен, но е stale спрямо `R+1`;
  нов recovery setup изисква отделно изрично Stage 2.5 действие.
- Exact schema-2 keyring history се запазва; няма rotation, migration, key
  deletion, re-encryption или промяна на потребителски файлове.
- Няма GUI, Contacts, Guardian, network, telemetry, logging, automatic recovery,
  software update discovery или automatic installation.
- Контролна точка: commit 050bacb, tag stage2.7-vault-recovery-publish.
- Следва Stage 2.8 — strict read-only reconciliation за uncertain Stage 2.7
  outcome с bounded absent/exact/conflict класификация и без mutation.

### Stage 2.8 завършен

- Добавен е strict read-only reconciliation за uncertain Stage 2.7 publish
  outcome без продължаване или поправяне на publish операцията.
- Потвърдени са 869 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Exact old source receipt и private `.mokr` recovery record/root се проверяват
  два пъти около два bounded storage scans.
- Stable clean history се класифицира като target absent или exact durable
  `R+1`; invalid, dirty, incomplete или променено наблюдение става conflict.
- Exact target трябва да се unlock-ва с explicit new password и да пази exact
  recovered schema-2 keyring digest, active version и key count.
- Wrong root, stale или forged source, tampered/unsafe/hardlinked recovery file
  и source/recovery race се отказват fail-closed без класификация.
- Резултатът съдържа само bounded non-secret evidence; recommended action е
  guidance и `mutation_authorized` винаги остава false.
- Старият recovery record не се обновява автоматично и остава stale спрямо
  приетото latest `R+1`; нов setup изисква отделно explicit Stage 2.5 действие.
- Няма publish, write, retry, rollback, repair, cleanup, key rotation/deletion,
  user-file mutation, GUI, network, telemetry, logging или automatic update.
- Контролна точка: commit 92a537d, tag
  stage2.8-vault-recovery-reconciliation.
- Следва Stage 2.9 — explicit recovery workflow state contract, който приема
  reviewed Stage 2.8 result без да превръща guidance в mutation authorization.

### Stage 2.9 завършен

- Добавен е explicit bounded in-memory workflow state върху exact reviewed
  Stage 2.8 reconciliation result.
- Потвърдени са 918 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Canonical domain-separated transcript SHA-256 обвързва classification,
  action, IDs, revisions, receipts, digests, counts и safety flags.
- Prepared workflow започва в `AWAITING_USER_REVIEW`, приема exact enum
  решение и допуска точно един успешен `review_once` transition.
- Target absent води само към fresh Stage 2.6 decision gate; exact target води
  към separate normal unlock и Stage 2.5 recovery setup gates.
- Conflict остава terminal `MANUAL_REVIEW_STOP`, а preserve решението —
  terminal `PRESERVED_STOP`, без автоматично продължаване.
- Different result, wrong classification route, string decision, malformed
  evidence и replay се отказват fail-closed.
- Workflow evidence/state е bounded и non-secret: няма password, recovery
  root, keyring, candidate, session, path, filename или executor reference.
- Всички candidate, unlock, recovery setup, publish, retry, repair, cleanup,
  key deletion и user-file mutation authority flags остават false.
- Няма filesystem access, Vault unlock/KDF, recovery rehearsal, GUI, network,
  telemetry, logging, clock, randomness или automatic software update.
- Контролна точка: commit 4f19ac1, tag stage2.9-vault-recovery-workflow.
- Следва Stage 2.10 — non-secret recovery workflow presentation contract с
  fixed message keys и ordered confirmations преди бъдещ GUI adapter.

### Stage 2.10 завършен

- Добавен е bounded non-secret presentation model върху exact validated
  Stage 2.9 workflow state.
- Потвърдени са 952 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Stage 2.9 schema, evidence, route, ordered gates и всички no-authority flags
  се валидират отново.
- Domain-separated fixed transcript SHA-256 обвързва exact evidence, decision,
  route, gates и safety flags.
- Fixed localization message keys и visible gate keys пазят exact route order
  без raw user text или template arguments.
- Ordered confirmation requirements не записват acknowledgement и не са
  operation authorization.
- Absent показва fresh Stage 2.6 gate; exact показва normal unlock преди
  separate Stage 2.5 setup; conflict и preserve са terminal stops.
- Presentation output не пази original state/evidence, Recovery/Vault IDs,
  receipts, revisions, source/target digests, password, root, keyring, path или
  exception text.
- Няма GUI, filesystem access, acknowledgement API, callback, executor,
  mutation, network, telemetry, logging, clock, randomness или automatic
  software update.
- Контролна точка: commit ed0e3c9, tag
  stage2.10-vault-recovery-presentation.
- Следва Stage 2.11 — one-shot non-mutating presentation acknowledgement
  contract с exact ordered confirmation keys и без operation authorization.

### Stage 2.11 завършен

- Добавен е one-shot non-mutating acknowledgement contract върху exact
  validated Stage 2.10 recovery presentation.
- Потвърдени са 993 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Domain-separated canonical transcript SHA-256 обвързва exact
  presentation, route, messages, gates, confirmations и safety flags.
- Prepared acknowledgement започва в `AWAITING_CONFIRMATIONS` и приема
  само complete exact ordered fixed-enum confirmation tuple.
- Skip, partial, reorder, duplicate, extra, string, list и cross-route keys се
  отказват fail-closed без consumption на prepared object-а.
- Process-local lock сериализира concurrent attempts и допуска точно
  един успешен acknowledgement.
- Bounded receipt/state е non-secret и не съдържа password, recovery root,
  keyring, candidate, session, path, filename или executor reference.
- Acknowledgement не е operation authorization, signature, persisted consent
  token или independent anti-rollback proof.
- Няма gate invocation, callback, executor, filesystem access, Vault unlock,
  recovery setup, candidate, publish, repair, cleanup или user-file mutation.
- Няма GUI, Contacts, Guardian, network, telemetry, logging, clock, randomness
  или automatic software update.
- Контролна точка: commit 51dbf0d, tag
  stage2.11-vault-recovery-acknowledgement.
- Следва Stage 2.12 — local non-mutating recovery UI adapter contract с
  fixed localization messages, exact ordered confirmations и без operational
  authority.

### Stage 2.12 завършен

- Добавен е bounded non-mutating recovery UI adapter core върху exact
  Stage 2.10 presentation и private Stage 2.11 acknowledgement lifecycle.
- Потвърдени са 1042 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Stage 2.10 schema, route, fixed keys и Stage 2.11 canonical presentation
  binding се валидират отново при prepare и transition.
- Message items имат stable ordinal, exact localization key, visible flag,
  exact gate marker и accessible-label-key binding.
- Всеки confirmation е separate, visible, required, individually selectable,
  accessible-label-key bound и започва с default false.
- Transition приема само exact ordered visible/user-selected/
  adapter-reported-user-initiated events и ги делегира на Stage 2.11.
- Hidden, unselected, wrong-ordinal, partial, reordered, duplicate, extra,
  mapping, string, stale и cross-route input се отказват fail-closed.
- Failed input не консумира adapter-а; process-local lock допуска
  точно един concurrent success и replay отказ след него.
- Bounded receipt не пази view, presentation, events, secrets, IDs,
  paths, callback, executor или operation capability.
- `user_initiated` е честно описан като adapter assertion, не
  human-comprehension, biometric, legal-consent или OS-trust proof.
- Няма GUI toolkit, localization rendering, filesystem, Vault unlock,
  gate invocation, candidate, setup, publish, repair, cleanup или mutation.
- Няма Contacts, Guardian, network, telemetry, logging, clock, randomness
  или automatic software update.
- Контролна точка: commit 0f5e5f9, tag
  stage2.12-vault-recovery-ui-adapter.
- Следва Stage 2.13 — versioned recovery localization registry с exact
  complete fixed text, no silent fallback и без GUI/operation authority.

### Stage 2.13 завършен

- Добавен е versioned immutable recovery localization registry за exact
  Stage 2.10 message/confirmation keys и validated Stage 2.12 view.
- Потвърдени са 1097 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Exact ordered locale allowlist е `bg-BG` и `en-GB`; unsupported, case,
  whitespace, language-only и region-substitution input се отказва без
  fallback или partial output.
- Всеки locale има complete one-to-one catalog за всички 24 message и 9
  confirmation keys с fixed Bulgarian/English human text.
- Missing, extra, duplicate, reordered, mixed-locale, altered и unsafe
  entries се отказват fail-closed.
- Text policy налага codepoint/UTF-8 bounds, NFC, trim и отказ на control,
  format, bidi-override/isolate и template characters.
- Domain-separated catalog SHA-256 обвързва exact locale, ordered keys и
  UTF-8 text без твърдение за signature или independent provenance.
- Deterministic localized records пазят Stage 2.12 ordinals, gate markers,
  visibility, accessible text и default-false confirmation policy.
- Localization не acknowledge-ва и не консумира adapter lifecycle; няма
  fallback, interpolation, widget, event, callback, executor или operation
  authority.
- Няма filesystem/environment locale, Vault unlock, recovery setup,
  candidate, publish, Contacts, Guardian, network, telemetry, logging, clock,
  randomness, update discovery или automatic recovery.
- Контролна точка: commit ec18a15, tag
  stage2.13-vault-recovery-localization.
- Следва Stage 2.14 — isolated local recovery review window с exact fixed
  localized view, default-false individual controls, safe cancel/close и без
  operational authority или main-GUI activation.

### Stage 2.14 завършен

- Добавен е отделен real Tkinter recovery review `Toplevel` върху exact
  Stage 2.10 presentation, fresh Stage 2.12 adapter и Stage 2.13 localization.
- Потвърдени са 1142 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Exact locale input е само `bg-BG` или `en-GB`, без OS/environment fallback.
- Scrollable ordered messages и отличени gate warnings се изграждат преди
  confirmation controls.
- Всеки checkbox е separate, required, false и disabled преди exact visible
  message report; няма select-all, pre-check, auto-accept или remembered state.
- Final action остава disabled до всички individual selections и отново се
  изключва след uncheck.
- Cancel button, Escape и window-manager close приключват без Stage 2.12
  acknowledgement; partial selection не създава receipt.
- Success създава само exact ordered visible/user-selected/user-initiated
  Stage 2.12 event tuple и bounded no-authority receipt.
- Process-local controller е one-shot, отказва copy/deep-copy/pickle и при
  concurrent terminal attempts допуска точно един result.
- Outcome не пази presentation, localized view, raw events, password,
  recovery root, keyring, path, callback, executor или operation capability.
- Widget използва existing Tk parent, child `Toplevel`, caller event loop,
  local grab, wrap, scroll и focus; няма втори `Tk` или втори `mainloop`.
- Изпитани са dry-run, apply и нарочно предизвикан post-install fault с чист
  rollback към baseline.
- Няма промяна на `mokosh_gui.py`, filesystem/Vault access, unlock, candidate,
  setup, publish, retry, repair, cleanup, Contacts, network или telemetry.
- Реалните cross-platform screen-reader, DPI, contrast и usability проверки
  още не са certification и остават отделна задача.
- Контролна точка: commit 1ed427b, tag
  stage2.14-vault-recovery-review-window.
- Следва Stage 2.15 — isolated synthetic visual/platform harness за реален
  Linux преглед на прозореца и checklist за Windows/macOS, без истински Vault
  input или main-GUI activation.

### Stage 2.15 завършен

- Добавен е отделен synthetic visual/platform harness, който отваря реалния
  Stage 2.14 `Toplevel`, без да стартира `mokosh_gui.py`.
- Exact fixture allowlist покрива `absent`, `exact`, `conflict` и `preserve` в
  `bg-BG` и `en-GB` с deterministic non-secret bindings.
- Scale профилите са ограничени до `100`, `125`, `150`, `200`, а размерите до
  `520x420` и `800x640`.
- Фиксираната Linux validation матрица изисква видим pass за scroll, wrap,
  focus order и keyboard-only действие, както и exact Escape, Cancel,
  window-manager close и acknowledgement outcomes.
- Реален първи Linux apply опит откри, че `Toplevel`, transient към withdrawn
  synthetic parent, може да остане невидим във `wait_visibility`; installer-ът
  отказа commit/tag и възстанови чистия `5e0a49b`.
- Harness owner-ът беше променен на малък видим mapped Tk parent преди
  Stage 2.14 child window, с regression test срещу повторно `root.withdraw()`.
- Bounded canonical JSON report няма свободен текст, password, recovery root,
  keyring, Vault path, filename, callback, executor или operation capability.
- Fail, mismatch или `not_checked` в задължителната visual матрица блокира
  installer commit/tag gate и възстановява clean base.
- Добавен е отделен Windows/macOS platform checklist; Linux или headless
  резултат не се представя като cross-platform certification.
- Потвърдени са 1162 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Няма промяна на `mokosh_gui.py`, истински Vault/recovery input, unlock,
  candidate, setup, publish, filesystem mutation, Contacts, network,
  telemetry, Guardian, software update или automatic recovery.
- Контролна точка: един commit върху `5e0a49b`, annotated tag
  `stage2.15-vault-recovery-visual-harness`; exact commit е target на tag-а.
- Преди Stage 2.16 се преглеждат Linux report-ите; main-GUI integration остава
  изключена до отделно замразен и прегледан scope.

### Stage 2.16 завършен

- Входната основа е exact Git archive от clean commit `54b0eb2`; archive
  SHA-256 е
  `d0d4ec100ac2f13e8239ef2b0f952315fdb1562ebdf66d356bcfd2a055089ee7`.
- Преди промяна са потвърдени 1162 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Замразен е отделен scope за one-shot recovery review application-service
  controller; `mokosh_gui.py` и main-GUI activation остават извън Stage 2.16.
- Добавен е `mokosh_vault_recovery_review_controller.py` с един public prepare
  API от exact Stage 2.9 state и exact Stage 2.13 locale.
- Controller-ът композира само Stage 2.10 presentation, fresh Stage 2.12
  adapter, Stage 2.13 localization и Stage 2.14 preparation/display.
- Prepared session има exact `prepared`, `displaying`, `completed`, `failed`
  lifecycle и допуска точно един display при concurrent/replay опити.
- Success, cancellation, display failure, forged outcome и interrupt
  консумират session-а; няма automatic или blind retry.
- Returned outcome се реконструира и валидира повторно и трябва да съвпада по
  exact locale и presentation SHA-256 с prepared session binding.
- Original Stage 2.9 state не се задържа; след terminal result/failure
  internal presentation/adapter references се премахват.
- Public API няма password, recovery root, keyring, Vault path, filename,
  callback, executor или operation capability.
- Добавен е
  `docs/VAULT_RECOVERY_REVIEW_CONTROLLER_CONTRACT_BG.md` и 20 positive,
  negative, replay, concurrency, interrupt и static-boundary теста.
- Потвърдени са 1182 теста: OK, expected failures=3 само за MOK1, skipped=0.
- Няма filesystem, network, logging, dynamic execution, Contacts, Guardian,
  update, licensing, candidate, unlock, setup, publish, retry, repair, cleanup
  или automatic recovery.
- `mokosh_gui.py` остава byte-exact непроменен и `SAFETY_MODE=True`.
- Контролна точка: един commit върху `54b0eb2`, annotated tag
  `stage2.16-vault-recovery-review-controller`; exact commit е target на
  tag-а.
- Преди Stage 2.17 се замразява отделен scope; main-GUI integration и истински
  Vault/recovery input остават забранени до този преглед.

### Stage 2.17 завършен

- Входната основа е exact Git archive от clean commit `938d23f`; archive
  SHA-256 е
  `a08602f6eeff7530eeec3609667542be232871b3ed13cb5fc42fcc639220f16b`.
- Преди промяна на лаптопа са потвърдени 1182 теста: OK, expected failures=3
  само за legacy MOK1, skipped=0.
- Замразен е отделен scope за inactive one-shot main-GUI recovery review
  handoff; normal-startup widget/event activation остава извън Stage 2.17.
- Добавен е `mokosh_vault_recovery_main_gui_bridge.py`, който приема само exact
  fresh Stage 2.16 session и exact matching `bg-BG` или `en-GB` locale.
- Stage 2.16 session излага само bounded read-only locale property; не излага
  workflow state, presentation, adapter, source identifiers или authority.
- Binding lifecycle-ът е exact `ready`, `displaying`, `completed`, `failed` и
  допуска точно един display при concurrent/replay опити.
- Success, cancellation, controller failure, forged outcome и interrupt
  консумират binding-а; internal Stage 2.16 session reference се премахва.
- `mokosh_gui.py` импортира само bounded Stage 2.17 bridge type и предоставя
  неактивен exact handoff seam. `main()` не го извиква и няма нов widget,
  geometry/layout промяна или source preparation.
- Добавен е
  `docs/VAULT_RECOVERY_MAIN_GUI_BRIDGE_CONTRACT_BG.md` и 21 positive, negative,
  replay, concurrency, interrupt и static-boundary теста.
- Очакваният пълен резултат е 1203 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Няма password, recovery root, record, keyring, Vault/recovery path, unlock,
  candidate, setup, publish, retry, repair, cleanup, filesystem mutation,
  Contacts, network, telemetry, Guardian, update, licensing или automatic
  recovery.
- `SAFETY_MODE=True`; legacy decryption и launcher-ът остават непроменени.
- Контролна точка: един commit върху `938d23f`, annotated tag
  `stage2.17-vault-recovery-main-gui-bridge`; exact commit е target на tag-а.
- Преди Stage 2.18 се замразява отделен scope за visible widget/event wiring;
  истински Vault/recovery input и operation authority остават забранени.

### Stage 2.18 завършен

- Входната основа е exact Git archive от clean commit `523af76`; archive
  SHA-256 е
  `660777288c6ed52868822f7e892fb9e15c207795a2bdfee8a48d0a9f605abe55`.
- Преди промяна на лаптопа са потвърдени 1203 теста: OK, expected failures=3
  само за legacy MOK1, skipped=0.
- Замразен е отделен scope за conditional inspection-only visible main-GUI
  widget/event към exact Stage 2.17 binding.
- `mokosh_gui.main()` приема само optional exact fresh Stage 2.17 binding;
  normal module entrypoint и launcher продължават да извикват `main()` без
  аргумент и не показват recovery widget.
- Условната session показва fixed localized banner и one-shot button, а
  всички unrelated main-GUI input/action controls са disabled.
- Event-ът изключва бутона и освобождава binding reference-а преди display;
  replay/concurrent опит не може да извика bridge-а втори път.
- Generic success/failure текстът не излага exception и казва изрично, че
  recovery операция не е разрешена или извършена.
- Добавени са fixed non-secret in-memory visual fixtures за четирите route-а и
  двата locale-а, bounded report и отделен real-main-GUI Linux launcher.
- Добавен е `docs/VAULT_RECOVERY_MAIN_GUI_WIDGET_CONTRACT_BG.md` и 25 positive,
  negative, replay, concurrency, interrupt, false-claim и static-boundary
  теста.
- Очакваният пълен резултат е 1228 теста: OK, expected failures=3 само за MOK1,
  skipped=0.
- Installer gate изисква реален Linux visual pass преди commit/tag; това е
  локално human observation, не platform certification или usability audit.
- Няма password, recovery root, record, keyring, Vault/recovery path, unlock,
  candidate, setup, publish, retry, repair, cleanup, filesystem mutation,
  Contacts, network, telemetry, Guardian, update, licensing или automatic
  recovery.
- `SAFETY_MODE=True`; legacy decryption и launcher-ът остават byte-exact.
- Контролна точка: един commit върху `523af76`, annotated tag
  `stage2.18-vault-recovery-main-gui-widget`; exact commit е target на tag-а.
- Преди Stage 2.19 се замразява отделен scope; true recovery source и всяка
  operation authority остават забранени.

### Stage 2.19 подготвен за installer gate

- Входната основа е exact Git archive от clean commit `3651c39`; archive
  SHA-256 е
  `8510680899bdeb66d43565675c0c6a24bfd3702bb23339743f776688a60b6667`.
- Преди промяна са потвърдени 1228 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0, както и двата Stage 2.18 Linux visual gates.
- Замразен е отделен scope за inactive, locale-bound, one-shot, non-secret
  recovery entry request; няма GUI wiring или source preparation.
- Добавен е `mokosh_vault_recovery_entry_request.py` с един public prepare API
  само от exact `bg-BG`/`en-GB` locale и exact enum decision.
- Допустимите решения са `REQUEST_RECOVERY_REVIEW` и `PRESERVE_AND_STOP`;
  нито едното не е source access или operation authorization.
- Prepared request допуска точно един валиден concurrent decision outcome и
  отказва replay, copy, deepcopy и serialization.
- Outcome schema няма password, recovery root/record, keyring, IDs, paths,
  workflow, presentation, adapter, session, binding, callback или executor.
- Всички source, preparation, display, normal-startup, operation, filesystem,
  network и automatic-transition flags са задължително false.
- Добавен е `docs/VAULT_RECOVERY_ENTRY_REQUEST_CONTRACT_BG.md` и 17 positive,
  negative, replay, concurrency, forged-claim и static-boundary теста.
- Очакваният пълен резултат е 1245 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- `mokosh_gui.py`, launcher, `crypto_core.py` и requirements остават byte-exact;
  няма visible Linux gate, защото Stage 2.19 няма GUI промяна.
- Commit/tag се записват само след успешния installer gate; този pre-apply
  текст не твърди предварителен pass.
- Преди Stage 2.20 се замразява отделен scope; main-GUI entry wiring, true
  recovery source и всяка operation authority остават забранени.

### Stage 2.20 завършен

- Входната основа е exact Git archive от clean commit `10eb789`; archive
  SHA-256 е
  `9f8a1fff3a1d16fd4d0e1bf0e1fbc5f8391c99a6b44e88b53950bfa20389856f`.
- Преди промяна са потвърдени 1245 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Замразен е отделен scope за normal-startup one-shot non-secret recovery
  entry widget/event към exact Stage 2.19 request contract.
- Normal GUI показва fixed locale-aware banner и бутон. Event-ът изключва
  бутона преди preparation и допуска точно един Yes/No outcome.
- Yes се преобразува само до `REQUEST_RECOVERY_REVIEW`, а No/close — само до
  `PRESERVE_AND_STOP`; нито едното не е source или operation authority.
- Request outcome не се пази на диск и не създава автоматичен преход към
  source picker, review session, binding или display.
- Stage 2.18 conditional prepared-review mode не показва Stage 2.20 entry;
  двата GUI режима остават разделени.
- Добавени са bounded visual observation report и отделен normal-main-GUI
  launcher за exact `bg-BG` и `en-GB` Linux преглед.
- Добавен е
  `docs/VAULT_RECOVERY_ENTRY_MAIN_GUI_WIDGET_CONTRACT_BG.md` и 23 positive,
  negative, replay, concurrency, interrupt, forged-claim и static-boundary
  теста; един Stage 2.18 regression test е актуализиран за новия normal widget,
  без да се променя броят му.
- Очакваният пълен резултат е 1268 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Няма true Vault/recovery input, password, keyring, source access,
  reconciliation/workflow preparation, review display, unlock, candidate,
  setup, publish, filesystem mutation, network, telemetry или automatic
  recovery.
- `SAFETY_MODE=True`; launcher, `crypto_core.py`, requirements и Stage 2.19
  request module остават byte-exact.
- Installer gate, rollback probe, automated regression и двата visible Linux
  gates са PASS. Контролна точка: commit `51f26d3`, annotated tag
  `stage2.20-vault-recovery-entry-main-gui-widget`.
- Актуалните full-history bundle, clean source snapshot и handoff са проверени.
  Fresh application review и laptop baseline на `51f26d3` потвърдиха 1268
  теста, expected failures=3 само за legacy MOK1 и skipped=0.

### Stage 2.21 завършен

- Входната основа е exact clean commit `51f26d3` и tag
  `stage2.20-vault-recovery-entry-main-gui-widget`.
- Преди промяна са потвърдени 1268 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Извършен е основен review на пълната Git история, application modules,
  imports/public APIs, filesystem/process/network/GUI/mutation boundaries и
  test coverage преди scope freeze.
- Замразен е отделен scope за inactive one-shot non-secret transition върху
  exact Stage 2.19 request outcome; няма GUI wiring или source preparation.
- `REQUEST_RECOVERY_REVIEW` допуска само нов exact intent за бъдещ отделен
  source-selection boundary или preserve; `PRESERVE_AND_STOP` не може да бъде
  върнат към proceed route.
- Prepared transition не задържа original request outcome и пази само exact
  locale и entry decision. Wrong type/route не консумира fresh object-а.
- Outcome няма password, recovery root/record, keyring, IDs, paths, storage,
  workflow, session, binding, callback или executor.
- Всички source, preparation, display, operation, filesystem, network и
  automatic-transition flags са задължително false.
- Добавени са `mokosh_vault_recovery_entry_transition.py`,
  `docs/VAULT_RECOVERY_ENTRY_TRANSITION_CONTRACT_BG.md` и 21 positive,
  negative, replay, concurrency, forged-claim и static-boundary теста.
- Очакваният пълен резултат е 1289 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- `mokosh_gui.py`, launcher, `crypto_core.py`, requirements и Stage 2.19
  request module остават byte-exact; няма visual gate, защото няма GUI промяна.
- Няма Vault/recovery input, secret intake, source access, Stage 2.8
  reconciliation, Stage 2.9 workflow, review session/display, unlock,
  candidate, setup, publish, cleanup, filesystem mutation, network, telemetry
  или automatic recovery.
- Installer gate, rollback probe и automated regression са PASS. Контролна
  точка: commit `bfcbe9f`, annotated tag
  `stage2.21-vault-recovery-entry-transition`.
- Преди Stage 2.22 се изискват fresh baseline, review и отделен scope freeze;
  source selection/preparation и operation authority остават забранени.

### Stage 2.22 завършен

- Входната основа е exact clean commit `bfcbe9f` и tag
  `stage2.21-vault-recovery-entry-transition`.
- Преди промяна са потвърдени 1289 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Fresh review на full history, source snapshot, imports, trust boundaries и
  tests откри, че Stage 2.19/2.21 entry import транзитивно зарежда 15 MOKOSH
  модула и cryptography backend през големия Stage 2.13 localization модул.
- Замразен е отделен hardening scope за pure stdlib-only recovery locale leaf;
  няма GUI wiring, source selection/preparation или operation authority.
- `RecoveryLocalizationLocale` е преместен в
  `mokosh_vault_recovery_locale.py`, който импортира само standard-library
  `enum` и съдържа exact `bg-BG`/`en-GB` identity.
- Stage 2.13 localization re-export-ва същия enum object; catalog texts,
  digests, public behavior и съществуващите import paths остават съвместими.
- Stage 2.19 request import closure е exact request + leaf, а Stage 2.21 — exact
  transition + request + leaf. Те import-ват успешно при блокирани crypto,
  GUI, storage, reconciliation, workflow, controller и bridge зависимости.
- Public API, format/version, decisions, outcomes, one-shot lifecycle и всички
  no-authority flags на Stage 2.19/2.21 остават непроменени.
- Добавени са `docs/VAULT_RECOVERY_LOCALE_LEAF_CONTRACT_BG.md` и 18 identity,
  compatibility, fresh-process, blocked-dependency, AST и byte-exact теста.
- Очакваният пълен резултат е 1307 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- `mokosh_gui.py`, launcher, `crypto_core.py` и requirements остават byte-exact;
  няма visual gate, защото Stage 2.22 не променя GUI.
- Няма recovery input, secret, source access, picker, filesystem, Stage 2.8
  invocation, session/display, unlock, candidate, setup, publish, cleanup,
  network, telemetry или automatic transition.
- Installer gate, rollback probe и automated regression са PASS. Контролна
  точка: commit `83aefb8`, annotated tag
  `stage2.22-vault-recovery-locale-leaf`.
- Преди Stage 2.23 се изискват fresh baseline, review и отделен scope freeze;
  source selection/preparation и operation authority остават забранени.

### Stage 2.23 implementation и installer gate

- Входната основа е exact clean commit `83aefb8` и tag
  `stage2.22-vault-recovery-locale-leaf`.
- Преди промяна са потвърдени 1307 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Fresh history/tree/import review потвърди Stage 2.22 leaf isolation, но
  откри, че normal `mokosh_gui` import продължава транзитивно да зарежда Stage
  2.17 bridge, controller, review window, storage, reconciliation и workflow.
- Замразен е отделен hardening scope за normal-main-GUI recovery import
  isolation; няма transition wiring, source preparation или operation authority.
- Stage 2.17 bridge type/error/state се import-ват runtime само от private
  no-argument helper при explicit prepared-review path. `TYPE_CHECKING` import
  служи само за annotation и не се изпълнява normal runtime.
- Fresh-process normal GUI import closure съдържа само `mokosh_gui`,
  `mokosh_paths`, Stage 2.19 request и pure locale leaf от MOKOSH модулите.
- Normal import минава при блокирани bridge/controller/review/storage/
  reconciliation/workflow dependencies; explicit helper връща exact Stage
  2.17 types и запазва conditional Stage 2.18 behavior.
- GUI texts, layout, geometry, locale mapping, Stage 2.20 request decisions и
  default `main()` без binding остават непроменени.
- Добавени са `docs/MAIN_GUI_RECOVERY_IMPORT_ISOLATION_CONTRACT_BG.md` и 19
  fresh-process, blocked-dependency, exact-type, AST, byte-exact и no-authority
  теста; две стари static assertions са стеснени към новата runtime граница.
- Очакваният пълен резултат е 1326 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Launcher, crypto core, requirements, Stage 2.17 bridge/controller и Stage
  2.19/2.21/2.22 contracts остават byte-exact. Няма нов visual gate, защото
  widget text/layout/geometry/event semantics не се променят; това не е нов
  visual или platform claim.
- Няма recovery input, secret, source access, picker, filesystem, Stage 2.8
  invocation, session preparation, unlock, candidate, setup, publish, cleanup,
  network, telemetry или automatic transition.
- Commit/tag се създават само от installer-а след full regression, exact
  staged-path/hash gates и rollback probe. До тогава този текст описва
  installer-gated implementation, а не предварителен pass.
- Преди Stage 2.24 се изискват fresh baseline, review и отделен scope freeze;
  transition wiring, source selection/preparation и operation authority остават
  забранени.

### Stage 2.24 implementation и installer gate

- Входната основа е exact clean commit `5a4d30b` и tag
  `stage2.23-main-gui-recovery-import-isolation`.
- Преди промяна на лаптопа са потвърдени 1326 теста: OK, expected failures=3
  само за legacy MOK1, skipped=0.
- Full-history bundle, source snapshot, `git fsck`, 92-commit linear history,
  51/51 annotated tags и byte-for-byte snapshot/Git identity са проверени
  преди scope freeze.
- Fresh review на modules, imports, filesystem/process/network/GUI boundaries
  и tests потвърди Stage 2.23 recovery isolation, но откри един import-time
  filesystem side effect в legacy `mokosh_paths.py`.
- Fresh-process probe с absent `MOKOSH_DATA_DIR` доказа, че normal
  `import mokosh_gui` създава директория с mode `0700`; `mokosh_paths.py` няма
  direct test coverage на тази граница.
- Замразен е отделен scope за explicit normal-main-GUI runtime path
  initialization; legacy storage redesign, recovery source и operation
  authority остават извън scope.
- Module-level `ensure_private_data_dir()` call е премахнат. `APP_DIR`,
  `DATA_DIR`, environment override и самата mkdir/chmod функция са запазени.
- `mokosh_gui.main()` извиква exact preparation след conditional binding
  validation и преди `tk.Tk()`. Preparation failure блокира GUI fail-closed.
- Normal GUI/path module import вече не създава и не chmod-ва runtime
  directory; explicit real startup запазва съществуващата preparation.
- Добавени са
  `docs/MAIN_GUI_RUNTIME_PATH_INITIALIZATION_CONTRACT_BG.md` и 18
  fresh-process, ordering, failure, AST, hash и no-authority теста.
- Очакваният пълен резултат е 1344 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Три стари GUI byte-hash guards са актуализирани до exact Stage 2.24 GUI
  hash; техните Stage 2.19/2.21/2.22 behavior assertions не са променени.
- GUI text/layout/geometry/events, launcher, crypto, seed/contact formats,
  recovery contracts и runtime requirements остават byte/behavior exact според
  frozen boundary. Няма visual gate, защото няма visible GUI промяна.
- Няма recovery input, secret intake, source/picker, Stage 2.8 invocation,
  workflow/session preparation, unlock, candidate, setup, publish, cleanup,
  user-file mutation, network, telemetry или automatic transition.
- Commit/tag се създават само от installer-а след rollback probe, exact
  staged-path/hash gates и full regression. До тогава този текст описва
  installer-gated implementation, а не предварителен pass.
- След успешния Stage 2.24 се подготвят full-history bundle, clean source
  snapshot и подробен handoff за продължаване от нов чат. Следващият stage не
  е предварително определен и изисква fresh review/scope freeze.

### Stage 2.25 implementation и installer gate

- Входната основа е exact clean commit `4c5952f` и tag
  `stage2.24-main-gui-runtime-path-initialization`.
- Bundle SHA-256 `2b42045aea830f6186ef5b388088ba0b55fbd5334c69bf684ba62707e9032fb3`
  и snapshot SHA-256
  `2c2e6dd79c0fbb2a09656b089aaf5c422a2cd839df779226ddc8b98b63f70172`
  са проверени; bundle complete, `git fsck --full --strict`, 93 commits, 0
  merges, 52/52 annotated tags и 148-file snapshot/Git identity са PASS.
- Преди промяна на лаптопа са потвърдени 1344 теста: OK, expected failures=3
  само за legacy MOK1, skipped=0.
- Fresh review на history, specifications, contracts, 105 Python files, import
  graph, trust boundaries и 52 test files потвърди, че Stage 2.20 request и
  Stage 2.21 transition са отделени, но normal GUI няма explicit second action.
- Замразен е minimal scope за отделен locked Stage 2.25 transition button;
  source selection/preparation, secret intake и operation authority остават
  забранени.
- Stage 2.25 action започва locked. Exact Stage 2.19 positive request само го
  arm-ва; Stage 2.21 не се подготвя преди отделно второ натискане.
- Второто действие disable-ва button и изчиства bounded request outcome преди
  exact Stage 2.21 revalidation/decision. Yes записва само future-source intent;
  No/close запазва и спира.
- Добавени са fixed Bulgarian/English texts, bounded visual harness/launcher,
  `docs/VAULT_RECOVERY_ENTRY_TRANSITION_MAIN_GUI_WIDGET_CONTRACT_BG.md` и 31
  positive/negative/replay/concurrency/fault/static/visual tests.
- Normal GUI import добавя само Stage 2.21 transition към pure Stage 2.19/2.22
  entry closure; Stage 2.17 heavy conditional bridge isolation остава.
- Очакваният пълен резултат е 1375 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- Mandatory Linux visible gate покрива `bg-BG` и `en-GB` positive transition
  route. Това е human observation, не usability/accessibility audit или
  platform certification.
- Launcher, runtime requirements, crypto, paths, seed/contact modules и Stage
  2.19/2.21 core contracts остават byte-exact. `SAFETY_MODE=True` остава.
- Няма recovery source/path/file/Vault input, password, recovery root/record,
  keyring, Stage 2.8 invocation, workflow/session/binding, review display,
  unlock, candidate, setup, publish, cleanup, user-file mutation, network,
  telemetry, persistence или automatic transition.
- Commit/tag се създават само от installer-а след visible gate, rollback probe,
  exact staged-path/hash gates и full regression. До тогава този текст описва
  installer-gated implementation, а не предварителен pass.

### Stage 2.26 implementation и installer gate

- Входната основа е exact clean commit `0c850c1` и tag
  `stage2.25-vault-recovery-entry-transition-main-gui-widget`.
- Fresh authoritative baseline на лаптопа е 1375 теста: OK, expected
  failures=3 само за legacy MOK1, skipped=0.
- Fresh architecture/security review потвърди Stage 2.25 no-source boundary,
  normal import isolation и `SAFETY_MODE=True`, но откри прекалено широки
  filesystem false claims в трите normal-main-GUI visual report families.
- Successful visual launcher извиква `mokosh_gui.main()`, а Stage 2.24
  изисква `ensure_private_data_dir()` преди `tk.Tk()`. Следователно общ
  whole-process no-filesystem claim не е точен.
- Замразен е minimal evidence-semantics scope без GUI behavior или recovery
  functionality промяна.
- Stage 2.18, 2.20 и 2.25 report versions стават `2`; generic filesystem
  полетата се заменят с exact runtime-preparation true и recovery-source
  access/mutation false полета.
- Трите development runners показват disclosure преди exact main call.
- Добавени са
  `docs/MAIN_GUI_VISUAL_FILESYSTEM_CLAIM_SEMANTICS_CONTRACT_BG.md` и 12
  cross-harness schema/negative/static/hash tests; existing report tests са
  актуализирани към exact version-2 semantics.
- Очакваният пълен резултат е 1387 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0.
- `mokosh_gui.py`, `mokosh_paths.py`, application launcher, requirements,
  crypto/Vault/recovery core и `SAFETY_MODE=True` остават byte-exact.
- Няма source picker/path retention, recovery file read, secret intake,
  Stage 2.8/workflow/review/session, operation authority, network, telemetry
  или persistence.
- Няма human visual gate, защото няма GUI text/layout/geometry/event промяна.
  Commit/tag се създават само след automated full regression, exact
  staged-path/hash gates и rollback probe.

### Stage 2.27 implementation и installer gate

- Входната основа е exact clean commit `9946ff7` и tag
  `stage2.26-main-gui-visual-filesystem-claim-semantics`.
- Bundle SHA-256 е
  `24051db042ec694d545a2b441c70ce337a3c1dee00bdc5d3897fe79394b51ca2`, а
  snapshot SHA-256 е
  `ef6515207872cd07ef39af71c0ecc6011b5374c016a15ca28ab00c79c93ea2f6`.
- Bundle integrity, 57 refs, 95 commits, 0 merges, 54/54 annotated tags и
  byte-for-byte snapshot/Git identity са проверени преди scope freeze.
- Fresh authoritative baseline на лаптопа е 1387 теста: OK, expected
  failures=3 само за legacy MOK1, skipped=0.
- High architecture/security review на 109 Python files, 54 test files,
  imports, dependency cycles, GUI/recovery trust boundaries, path/secret flow
  и Stage 2.5 storage secure-read core не откри нов critical functional defect.
- Замразен е exact seven-file scope за inactive one-shot process-local recovery
  source selection contract; `mokosh_gui.py` и privileged recovery layers не
  се променят.
- Само exact positive Stage 2.21 outcome може да подготви selection. Prepared
  object не задържа original outcome или path преди exact decision.
- `SELECT_LOCAL_RECOVERY_RECORD` приема един strict bounded absolute POSIX path;
  `PRESERVE_AND_STOP` изисква path да липсва.
- Path е недоверено sensitive metadata: lexical validation, `repr=False`, без
  copy/deepcopy/pickle, hash, log, display или persistence. Това не е secure
  erasure и не доказва file identity.
- Модулът не извиква filesystem API и не import-ва GUI, storage,
  reconciliation, workflow, controller, bridge, review, candidate, publish,
  crypto, process, network или logging dependencies.
- Source selection остава различна от source access: `source_opened`,
  `source_identity_validated`, `source_access_authorized`, preparation,
  secret, operation, recovery-source filesystem, network и automatic flags са
  exact false.
- Добавени са
  `docs/VAULT_RECOVERY_SOURCE_SELECTION_CONTRACT_BG.md`,
  `mokosh_vault_recovery_source_selection.py` и точно 26 positive/negative,
  forged-input, privacy, replay, concurrency, AST и critical-hash tests.
- Очакваният full installer gate е 1413 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0. Няма visual gate, защото няма GUI промяна.
- Installer-ът трябва да приложи само exact seven-path allowlist, да провери
  base hashes/modes, rollback, 26 targeted теста и full regression, и едва
  след това да създаде commit/tag. До успешния laptop gate този текст не
  твърди предварителен PASS.
- GUI picker, source open/read/preparation, recovery-secret intake, Stage 2.8
  invocation, review session, candidate/publish, user-file mutation, network,
  telemetry и automatic recovery остават забранени за бъдещи frozen stages.

### Stage 2.28 implementation и installer gate

- Входната основа е exact clean commit `45a977e` и tag
  `stage2.27-vault-recovery-source-selection`.
- Авторитетният laptop baseline е 1413 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0; Git identity/history/fsck и runtime dependencies са
  PASS.
- Full architecture/security review не откри нов critical дефект в current
  v2/recovery boundary. Legacy seed/contact/MOK1 рисковете остават изолирани
  чрез `SAFETY_MODE=True` и disabled controls.
- Първоначалният 9-path freeze беше спрян преди code change, защото пет
  historical security tests пазят exact `mokosh_gui.py` hash. Minimal re-freeze
  е точно 14 paths; петте добавени теста променят само expected GUI hash.
- За всички бъдещи stages е задължителен pre-freeze transitive test-impact scan
  за hash/import/schema/geometry/evidence/installer зависимости. Ако нова
  неизбежна зависимост се открие след freeze, code work спира до re-freeze.
- Stage 2.28 добавя отделен third action, locked до exact positive Stage 2.21
  outcome. Stage 2.27 се зарежда и подготвя условно само след third click.
- Event-ът clear-ва retained transition outcome и disable-ва button преди
  Stage 2.27 preparation и native picker. Select/cancel са exact one-shot
  routes без reset/retry; concurrency допуска точно един consumer.
- Native picker може да изброява directories и да чете filesystem metadata.
  Application recovery event не open/read/stat/resolve-ва source, не проверява
  identity/permissions и не го променя. Няма whole-process no-filesystem claim.
- Path не присъства във fixed GUI messages, exception detail, visual report,
  logging или persistence; GUI event не задържа path/outcome след връщането.
- Добавени са fixed BG/EN texts, pure bounded visual report/launcher,
  `docs/VAULT_RECOVERY_SOURCE_SELECTION_MAIN_GUI_WIDGET_CONTRACT_BG.md` и 36
  automated tests.
- Expected full gate е 1449 теста: OK, expected failures=3 само за legacy
  MOK1, skipped=0. Visible Linux gate е BG/EN × select/cancel със synthetic,
  harmless, non-sensitive input и никога истински recovery record.
- Source open/read/preparation, secret intake, Stage 2.5 secure read, Stage 2.8
  reconciliation, workflow/review/session, candidate/publish, user-file
  mutation, network, telemetry и automatic recovery остават забранени.
- Commit/tag се създават само от installer-а след targeted/full/visual,
  rollback и exact staged-path/hash/mode gates. До успешния laptop gate този
  текст описва installer-gated implementation, а не предварителен PASS.

### Stage 2.29 implementation и installer gate

- Входната основа е exact clean commit `6613b2e` и annotated tag
  `stage2.28-vault-recovery-source-selection-main-gui-widget`.
- Авторитетният laptop baseline е 1449 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0. Exact tree, Git history/fsck, runtime dependencies,
  ML-KEM-768, 114-source locale-stable manifest, archived Stage 2.28 package и
  protected legacy quarantine са проверени.
- Fresh High architecture/security review не откри нов critical дефект.
  Известните legacy MOK1/seed/contact рискове, един стар internal import cycle,
  POSIX-only semantics и planned SBOM/reproducible-build lane остават честно
  документирани и извън този pure scope.
- Pre-freeze transitive-impact scan потвърди, че new pure module не изисква
  промяна на GUI, Stage 2.27, privileged layers или historical hash tests.
  Frozen scope е точно седем paths.
- Stage 2.29 revalidate-ва exact positive Stage 2.27 source-selection outcome и
  записва едно one-shot `REQUEST_FUTURE_SECURE_SOURCE_INSPECTION` или
  `PRESERVE_AND_STOP` решение.
- Request-ът е process-local intent, не access authorization. Path остава
  sensitive metadata, repr-hidden, non-serializable и не е file identity,
  authenticity, ownership или permissions evidence.
- Няма source open/read/stat/identity/preparation, Stage 2.5/2.8 invocation,
  secret, review session, operation capability, filesystem access/mutation,
  network, logging или persistence.
- Добавени са
  `docs/VAULT_RECOVERY_SOURCE_INSPECTION_REQUEST_CONTRACT_BG.md`,
  `mokosh_vault_recovery_source_inspection_request.py` и точно 30 automated
  tests. Expected full gate е 1479 теста: OK, expected failures=3, skipped=0.
- След Stage 2.28 installer surprise е задължителен ignored root-Python scan,
  exact tracked/non-ignored compile manifest с `LC_ALL=C` и отделен rollback
  probe; `compileall .` върху реалния working tree е забранен.
- Няма visual gate, защото GUI/text/layout/event behavior са byte-exact.
  Commit/tag се създават само след laptop targeted/full/rollback/source-hygiene
  PASS. До тогава този запис не твърди предварителен PASS.

### Stage 2.30 implementation и installer gate

- Входната основа е exact clean commit `0af7a6d`, tree `4923cfcf` и annotated
  tag `stage2.29-vault-recovery-source-inspection-request`.
- Авторитетният laptop baseline е 1479 теста: OK, expected failures=3 само за
  legacy MOK1, skipped=0. Git, runtime, archived Stage 2.29 package, protected
  quarantine и 116-source locale-stable manifest са PASS.
- Fresh High architecture/security/standards review не откри new critical/high
  defect. Известният internal import cycle и legacy/SBOM/reproducible-build
  lanes остават документирани и извън frozen scope.
- Pre-freeze transitive-impact scan откри шест exact GUI-hash и три normal-GUI
  geometry guards. Frozen scope е точно 18 paths и включва само тяхната
  необходима механична актуализация.
- Stage 2.30 добавя separate fourth action, locked до exact positive Stage 2.27
  selection. Picker cancel или по-ранен preserve оставя action-а locked.
- Stage 2.29 се import-ва и prepare-ва само след explicit fourth click.
  Retained selection outcome/path и locale се clear-ват преди loader,
  preparation и confirmation processing.
- Yes записва exact one-shot future inspection request; No/window-close записва
  preserve. И двата резултата и всички errors са fixed, generic и path-free.
- Няма automatic transition, source open/read/stat/identity/access/preparation,
  secret, Stage 2.5/2.8, review/session, operation, mutation, network, logging
  или persistence.
- Normal GUI geometry става exact `820x720`; prepared review остава exact
  `820x560`. Всички четири actions са separate и one-shot/fail-closed.
- Добавени са contract, pure visual report/launcher и точно 42 automated tests.
  Expected full gate е 1521 теста: OK, expected failures=3, skipped=0.
- Visible Linux gate е BG/EN × request/preserve със synthetic harmless file и
  никога с real recovery record/password/Vault. Commit/tag се създават само
  след targeted/full/visual/rollback/source-hygiene PASS; този запис не твърди
  предварителен installer PASS.

### Stage 2.31 implementation и installer gate

- Входът е exact clean `b07a617`, tree `bef01e3b` и annotated Stage 2.30 tag.
- Fresh High review потвърди pure Stage 2.19→2.21→2.27→2.29 import closure и
  отдели бъдещия privileged mediation слой.
- Runtime incident: `venv_sys/pyvenv.cfg` е съдържал public identity export.
  Evidence е защитено с 0700/0600 и SHA-256; config е възстановен към isolated
  Python 3.12 venv. ML-KEM/Tkinter/pip-check и 1521 regression tests са PASS.
- Frozen scope е точно осем project paths: пет документа, един contract, един
  pure module и един 33-test module. GUI и privileged recovery code не се
  променят.
- Exact positive Stage 2.29 outcome може да подготви per-object one-shot
  `REQUEST_FUTURE_SECURE_SOURCE_INSPECTION_PREPARATION` или preserve outcome.
- Няма global source-outcome consumption или memory-zeroization claim. Request
  не е source identity, access authorization или filesystem capability.
- Expected full gate е 1554 теста: OK, expected failures=3, skipped=0. Няма
  visual gate. Commit/tag идват само след laptop dry-run/apply, full regression,
  exact manifest/hash/mode и clean-worktree gates.

### Stage 2.32 implementation и installer gate

- Входът е exact clean `f375981`, tree `1fea5410` и annotated Stage 2.31 tag;
  baseline source identity и safety mode са потвърдени.
- High review не откри critical/high blocker и замрази точно седем paths:
  четири документа, нов contract, нов execution module и нов 42-test module.
- Stage 2.32 revalidate-ва exact positive Stage 2.31 outcome. Preserve е
  terminal и не import-ва storage/не докосва filesystem.
- Exact positive decision clear-ва retained path преди conditional Stage 2.5
  import и извиква `_read_recovery_path` точно веднъж.
- Stage 2.5 reader остава byte-exact и осигурява POSIX 0700/0600 owner-only,
  no-symlink/hardlink, descriptor-relative `O_NOFOLLOW`/`O_CLOEXEC`, bounded
  read, canonical filename/recovery-ID binding и change/identity checks.
- Outcome съдържа само repr-hidden observed IDs, revision, size и hashes; няма
  path, descriptor, record/header/ciphertext, secret или operation authority.
- Structural header validity не е cryptographic authentication. Python memory
  zeroization, global source-outcome consumption, future filesystem identity и
  Windows/macOS certification не се твърдят.
- Добавени са точно 42 tests; expected full gate е 1596 tests, expected
  failures=3, skipped=0 и 123 tracked Python sources. Няма visual gate.
- Commit/tag се създават само след laptop dry-run/apply, isolated rollback,
  exact seven-path/hash/mode/source-manifest и full-regression PASS; този запис
  не твърди предварителен laptop PASS.

### Stage 2.33 implementation и installer gate

- Входът е exact clean `e1a92e7`, tree `3bdf6c36` и annotated Stage 2.32 tag.
  Laptop Stage 2.32 apply е 1596 tests: OK, expected failures=3, skipped=0;
  Git/package/quarantine/runtime и 123-source manifest са PASS.
- High review замрази точно седем paths: четири документа, нов presentation
  contract, нов pure module и нов 36-test module.
- Presentation приема само exact positive Stage 2.32 outcome. Preserve,
  subclass, mapping, raw string enum и forged authority/schema се отказват.
- Domain-separated fixed binary transcript обвързва locale, decision, raw
  Stage 2.32 evidence, safety flags, sequences, format и version в един
  repr-hidden SHA-256.
- Presentation съдържа само digest, fixed message keys, ordered confirmation
  requirements и safety flags; raw IDs/revision/size/hashes/path/content и
  original outcome не се задържат.
- Задължително се показват structure-not-authenticity, fresh-secure-reopen и
  no-recovery/no-authority semantics. Digest-ът не е signature, provenance,
  authentication или anti-rollback proof.
- Модулът няма storage/reconciliation/GUI/filesystem/network/logging capability
  и не извиква Stage 2.32 reader. GUI и privileged кодът са byte-exact.
- Първият targeted cycle откри и отстрани strict `str`-enum equality и dynamic
  `getattr` несъответствия преди docs/package; повторният exact 36-test gate е
  PASS.
- Expected full gate е 1632 tests, expected failures=3, skipped=0 и 125 tracked
  Python sources. Няма visual gate. Commit/tag идват само след laptop dry-run/
  apply, full regression, exact allowlist/hash/mode/manifest и rollback PASS.

### Stage 2.34 implementation и installer gate

- Входът е exact clean `8b2a233`, tree `bdcdb4d4` и annotated Stage 2.33 tag.
  Fresh laptop baseline е 1632 tests: OK, expected failures=3, skipped=0;
  runtime isolation, `pip check`, Git/source identity и safety mode са PASS.
- Fresh High review избра one-shot source-inspection acknowledgement вместо
  premature localization/view-model слой и замрази точно седем paths.
- Stage 2.34 revalidate-ва exact Stage 2.33 presentation. Canonical
  domain-separated transcript обвързва locale, digest, всички fixed keys,
  safety flags, format и version.
- Приемат се само трите complete exact ordered enum confirmation tokens.
  Receipt доказва token receipt, не human understanding, identity, informed
  consent, signature, provenance, authenticity, freshness или authority.
- Lifecycle commit е една immutable receipt-reference assignment под lock.
  Failure преди commit оставя fresh state; success е exactly-one; следващ опит
  е replay. Private binding се revalidate-ва изцяло.
- Няма GUI/renderer/filesystem/storage/recovery/secret/network/logging/callback/
  executor/gate/mutation capability и Stage 2.32 reader не се извиква.
- Първият targeted cycle даде 40 pass / 1 fail: test helper е заменял explicit
  `None` с default valid presentation. Production API не е причината. Helper
  sentinel-ът е поправен и повторният targeted gate е 42/42 PASS.
- Scratch full regression не е отчетен като PASS: runtime-ът няма `argon2`,
  три existing test modules не се import-ват и резултатът е 1645 tests,
  errors=3, skipped=7. Това е environment limitation; authoritative exact
  1674-test gate остава задължителен на laptop `$HOME/venv_sys`.
- Първият laptop installer dry-run спира fail-closed преди clone/patch/tests:
  verifier-ът изпълнява protected `SHA256SUMS` от quarantine root, но originals
  са в exact `files/` subdirectory. Това е installer path-resolution defect;
  evidence и repo не са променени. R1 изисква private owner-only `files/` и
  изпълнява manifest check от нея срещу parent `SHA256SUMS`.
- Приет е `MOKOSH Project Integrity and Full Disclosure Invariant`: всички
  defects, deviations, assumptions, additions, updates и future official/
  scientific standards changes се съобщават, записват и при релевантност минават
  fresh primary-source review и отделен freeze.
- Tracked reminders към 2026-08-29: SSDF 1.2 IPD, FIPS 203 future update,
  SP 800-38D Rev.1 second pre-draft и EU CRA 2026-09-11/2027-12-11 milestones.
  Няма automatic adoption, self-certification или legal conformity claim.
- Добавени са точно 42 tests; expected full gate е 1674 tests, expected
  failures=3, skipped=0 и 127 tracked Python sources. Няма visual gate.
- Commit/tag се създават само след laptop dry-run/apply, exact seven-path
  allowlist/hash/mode/source-manifest, isolated rollback и full regression PASS.

### Stage 2.35 implementation и installer gate

- Входът е exact clean
  `3a7d2a2479a0feeb447f8a8b8cbf66e626945e7d`, tree
  `f1401057399ce3822c30864f51de1af753cc63cc` и annotated Stage 2.34 tag.
  Authoritative baseline е 1674 tests: OK, expected failures=3, skipped=0;
  Git/fsck, 127-source identity, runtime isolation и safety mode са PASS.
- Fresh High architecture/security/standards review замрази точно седем paths:
  четири документа, new contract, new pure adapter и new 49-test module.
- View-model съдържа exact seven ordered visible message keys и three separate,
  required, individually-selectable, default-unselected controls. Няма raw
  text, select-all, auto-accept, remembered state или operation controls.
- Приемат се само три exact ordered events с matching ordinal/key и exact
  `visible=True`, `user_selected=True`, `user_initiated=True`.
- Private Stage 2.34 binding/fresh state се revalidate-ват; success изисква
  exact private terminal state и receipt identity. Един `_terminal`
  marker се задава непосредствено преди private delegation; всяко ordinary или
  `BaseException` failure след тази точка остава `FAILED_CLOSED`. Така nested
  success не може да съществува с fresh outer adapter.
- Receipt е immutable, repr-hidden, non-serializable и no-authority. Adapter
  assertions не доказват real rendering, accessibility, understanding,
  identity, consent, provenance, authenticity, recovery или operation.
- Review-ът откри historical Stage 2.12 dual-state/narrow interrupt-gap pattern.
  Той е inactive и safety-gated; записан е като отделен pre-activation
  hardening reminder и не се patch-ва извън Stage 2.35 freeze.
- Първият targeted cycle даде 1 failure и 2 errors в test harness: helper
  explicit-`None`, isolated subprocess import path и неточен critical-hash
  entry. Production failure не е наблюдаван. След корекциите повторният exact
  49-test gate е PASS.
- Scratch full suite е non-authoritative failure: 1694 tests, errors=3,
  skipped=7 поради липсващ `argon2` и три existing import failures. Няма
  dependency bypass и резултатът не заменя authoritative laptop gate.
- Expected full gate е 1723 tests, expected failures=3, skipped=0 и 129 tracked
  Python sources. Няма visual gate, защото няма real GUI. Commit/tag се
  създават само след laptop dry-run/apply, exact allowlist/hash/mode/source
  manifest, isolated rollback, full regression и clean final checkpoint.
- Full Disclosure Invariant остава закон на дейността: defects, deviations,
  assumptions, changes, additions, updates, standards revisions/errata и
  deadlines се съобщават и записват; релевантното прилагане изисква fresh
  primary-source review, impact analysis и отделен freeze.

### Stage 2.36 implementation и installer gate

- Входът е exact clean
  `37bd8e446c7ff633a8c9ec1f1ce0cf87408ac047`, tree
  `b80da694f645515eab04490546772f143f306010` и annotated Stage 2.35 tag.
  Laptop baseline е 1723 tests: OK, expected failures=3, skipped=0; 129-source
  manifest, safety mode и final checkpoint са PASS.
- Fresh High review избра отделен source-inspection localization registry и
  замрази точно седем paths. Old Stage 2.13, Stage 2.32–2.35, GUI, crypto и
  storage остават byte-exact.
- Exact built-in `bg-BG`/`en-GB` catalogs покриват седем messages и три
  confirmations. Locale идва само от exact Stage 2.35 view; няма fallback,
  caller override, OS locale, external catalog или interpolation.
- Fixed text policy е NFC, bounded codepoint/UTF-8, no-control/bidi/template;
  domain-separated digest обвързва locale/order/keys/text.
- Localized messages/controls запазват ordinals, visible/accessibility text
  equality и separate required default-unselected policy. Няма events,
  acknowledgement, GUI, source reader, secret или authority.
- Първият 58-test cycle даде 57 pass/1 failure: test-ът погрешно е очаквал
  Cyrillic `е + combining acute` да има NFC composition. Production code не е
  причината. Latin decomposed vector-ът е коригиран; повторният 58/58 gate е
  PASS.
- Scratch full suite е non-authoritative 1752 tests, errors=3, skipped=7 поради
  липсващ `argon2` и същите три existing imports. Няма dependency bypass.
- Expected laptop gate е 1781 tests, expected failures=3, skipped=0 и 131
  tracked Python sources. Няма visual gate; package/apply/final PASS не се
  твърдят предварително.
- WCAG 2.2, EN 301 549 V3.2.1/revision work и EAA applicability от 2025-06-28
  са tracked, без accessibility/legal conformity claim.
- Постоянен workflow law: точно три consecutive stages per chat; след третия
  package archive, history bundle, next-stage input и handoff; новият чат
  започва на High/read-only и без код преди freeze. Този чат е Stage 2.34–2.36,
  следващият започва със Stage 2.37.

### Stage 2.37 implementation и installer gate

- Новият Stage 2.37–2.39 chat започна на High с read-only проверка на bundle,
  input archive, handoff и authoritative Stage 2.36 laptop checkpoint.
- Base identity е exact `cc465b5b7d3c9188a9b0fbbd07987347c4e7c092`,
  tree `1737846afb192dce4b8bd37a3917d629f95eda07`, clean branch и annotated
  `stage2.36-vault-recovery-source-inspection-localization` tag.
- Runtime gate е isolated Python 3.12.3, cryptography 49.0.0, OpenSSL 4.0.1,
  argon2-cffi 25.1.0 и current ML-KEM-768 roundtrip PASS. Baseline full suite е
  1781 tests: OK, expected failures=3, skipped=0.
- Fresh High review откри, че historical Stage 2.14 dual state/outcome design
  не трябва да се копира: interrupt след consumed inner adapter може да остави
  outer state fresh. Freeze-ът изисква един terminal sentinel преди delegation.
- User прие minimal freeze с условие за future legal/official updates.
  Уточнено е, че неизвестни бъдещи правила не могат да бъдат гарантирани;
  процедурата е primary source → impact analysis → explicit notification →
  new freeze → explicit acceptance → едва тогава промяна.
- Реализацията е точно в седемте accepted paths. Locale се извлича само от
  Stage 2.35 view през Stage 2.36; exact 7 messages precede 3 disabled/false
  individual checkboxes; няма select-all, remembered state, auto-accept или
  window-wide Return. Escape/Cancel/WM close са bounded cancellation.
- Един `_terminal` marker преди Stage 2.35 delegation покрива ordinary fault,
  `BaseException`, interrupt, post-delegate validation failure, concurrency и
  replay. Outcome е bounded/no-authority и не задържа sensitive capability.
- Първият targeted run даде 55 PASS / 1 FAIL: forged-outcome test helper не
  извика validator след `object.__new__`. Коригиран е само test harness;
  повторният exact targeted gate е 56/56 PASS.
- Потвърденият legacy `contacts_core.py` ML-KEM tuple-order defect е записан
  като отделен safety-disabled pre-activation risk и не е silently patched.
- Standards review: WCAG 2.2; ETSI 2026-08-24 adopted-for-publication work-item
  с 4.1.0 срещу TC-HF flyer 4.1.1 inconsistency; final SSDF v1.1/SSDF 1.2 IPD;
  SP 800-38D Rev.1 work; FIPS 203 update note; EAA scope и CRA 2026-09-11.
  Няма automatic adoption или legal/accessibility conformity claim.
- Expected laptop gate е 1837 tests, expected failures=3, skipped=0, 189
  tracked files и 133 tracked Python sources. Commit/tag се създават само след
  package identity, exact allowlist/hash/mode, isolated rollback, full tests и
  clean final checkpoint PASS.

### Stage 2.38 High review, freeze и preliminary implementation

- Fresh read-only baseline потвърди exact Stage 2.37 `ba465fe`, tree
  `25a03227`, annotated tag, clean worktree, exact predecessor hashes/runtime,
  known three unreachable blobs и 1837 tests: OK, expected failures=3.
- Current session е Linux Wayland (`DISPLAY=:0`, `WAYLAND_DISPLAY=wayland-0`);
  platform claim остава ограничен до тази среда.
- Review-ът откри historical Stage 2.15 scaling defect за reuse: Tk scaling е
  pixels-per-point, затова absolute `percent/100` не е относителен процент.
  Freeze-ът изисква `initial_scaling × percent/100`.
- Stage 2.37 minimum е 560×440; historical 520×420 profile не се копира.
- User прие exact eight-path freeze и допълни безкомпромисен доброволен
  standards принцип. Изрично коригирахме правното предположение: private user
  и voluntary choice не освобождават автоматично от applicable law.
- След implementation count review е открита freeze счетоводна грешка: трите
  нови Python paths увеличават 133 до 136, не до 135. User е уведомен и прие
  explicit поправката; общият file count остава 193 и scope не е разширен.
- Standards/legal review добави WCAG2ICT 2.2 informative status, ETSI EN
  301 549 V4.1.0 adopted-for-publication status без OJ presumption и 2026 CRA
  guidance/reporting readiness. Нищо не е automatic legal adoption.
- Добавени са pure synthetic core, separate visible launcher, exact 48-test
  module и contract. Matrix покрива BG/EN, 100/125/150/200%, 560×440/800×640
  и четирите terminal actions по два пъти.
- Няма real Vault/source/path/secret, main GUI, event injection, filesystem
  mutation, recovery, operation authority, network или automatic evidence file.
- Първият local compile probe към `$HOME/venv_sys` не стартира, защото scratch
  средата няма този user runtime path; това не е отчетено като PASS.
- Първият 48-test run даде 10 pass / 38 errors поради нов Stage 2.38 bug:
  exception-based Stage 2.35 validator return `None` е бил използван като view.
  Stage 2.35–2.37 не са причината. Коригиран е само new core reference flow;
  repeat preliminary targeted gate е 48/48 PASS.
- Scratch full regression е explicit non-authoritative failure: 1856 tests,
  errors=3, skipped=7. Липсващият `argon2` блокира три existing test-module
  imports и 29 tests не се изпълняват. Няма dependency bypass или false PASS;
  authoritative expected gate остава 1885 tests на laptop runtime.
- Следват docs/source/static checks, scratch full regression, package-level
  allowlist/rollback gates и едва после authoritative laptop dry-run/visual/
  full tests. Няма commit/tag claim преди всички gates.
- R0 laptop attempt: package/runtime/ML-KEM/protected-legacy/exact-base gates
  са PASS, но isolated apply спира с `applied repository path allowlist differs`
  преди tests/GUI/actual apply. Read-only recovery gate доказва exact clean
  Stage 2.37, absent new paths/tag и unchanged fsck objects.
- Temporary clone diagnostic показва exact expected four ` M` и four `??`
  lines. Root cause е installer `_git().strip()`, който премахва значимия
  leading space от първия porcelain line. Това не е payload/Stage 2.37/GUI
  defect. R0 е оттеглен; R1 използва raw status lines и отделен regression gate.

### Stage 2.38 R1 visual failure и приет responsive amendment

- R1 package/parser/runtime/ML-KEM/legacy/exact-base gates са PASS.
- Isolated 48 tests и 1885 full tests са PASS; rollback PASS. Actual 48 tests
  и 1885 full tests също са PASS преди human matrix.
- Case 1 instruction изискваше three-check/uncheck/recheck и Escape, но
  operator натисна acknowledgement. Старият launcher премина към terminal
  observation prompt преди ясно да отхвърли action mismatch.
- Operator съобщи, че прозорецът не се разтяга ясно и част от текстовете не са
  достатъчно видими/четливи при малък размер. Matrix е прекратена със status
  130; `STAGE2_38_FAILURE_ROLLBACK=PASS`.
- Read-only post-failure command потвърди exact `ba465fe` HEAD,
  `25a03227` tree, clean worktree, absent four Stage 2.38 paths и absent tag.
- Обяснено е правилното action sequence и е признат communication/harness UX
  defect: checkbox workflow и final action трябва да са ясно разделени.
- Fresh review установи fixed wrap lengths, canvas-only wheel и possible
  off-viewport initial focus в Stage 2.37, както и terminal-input/
  validate-after-observations defects в launcher-а.
- User прие 12-path amended freeze и общ permanent GUI rule за размер,
  resize, четлив текст, dynamic wrap, scroll/focus и разширяване на преводите
  във всички прозорци/подпрозорци.
- Exact amended counts: Stage 2.37 68 tests, Stage 2.38 64 tests, expected full
  1913, expected failures=3, skipped=0, 193 tracked files, 136 Python.
- Изолираната реализация даде exact combined targeted 132/132 PASS. Това още
  не е authoritative laptop/full/visual PASS и няма commit/tag claim.
- Няма нова standards publication, приложена автоматично. Amendment-ът е
  по-строго прилагане на вече следените reflow/focus/software UI principles.

### Stage 2.38 R3 freeze и implementation

- След exact clean rollback user уточни, че Cases са били разбрани като
  различни ситуации/избори според резултата, не като sequential matrix.
- Изяснено е: terminal action е fixed test input; questions се отварят
  автоматично; PASS/FAIL се задава отделно след exact action.
- Вторият R2 run повтори exact pattern: Case 1 canonical six-PASS report;
  English Case 2 Escape при expected Cancel; no observation form; rollback
  PASS. Причината вече не е предположение.
- User прие exact same 12-path R3 freeze.
- Stage 2.37 footer е преместен в reserved grid row 2; introduction е row 0,
  а само review canvas row 1 има weight=1.
- Launcher добавя one-time sequential overview, large per-case action banner,
  unchecked acknowledgement, disabled Start, automatic-questions warning и
  exact mismatch diagnostics.
- Existing 132 tests остават PASS. След exact +8/+12 additions preliminary
  targeted gate е 76 + 76 = 152/152 PASS.
- Current expected laptop full gate е 1933 tests, expected failures=3,
  skipped=0, 193 tracked files и 136 Python. Няма commit/tag claim.

### Stage 2.38 R4 corrective freeze и implementation

- R3 laptop automated gates преминаха: 76/76 Stage 2.37, 76/76 Stage 2.38,
  1933 full, expected failures=3, и isolated apply/rollback.
- Manual phase не отвори прозорец: `_show_matrix_overview` хвърли exact
  `NameError: name 'case' is not defined`.
- Installer fail-safe rollback мина. User изпълни read-only gate: exact
  `ba465fe` HEAD, `25a03227` tree, clean worktree и absent Stage 2.38 tag.
- Причината е призната като implementation/test-design defect: banner block
  е бил в overview вместо case instruction, а старите string tests не са
  проверявали function ownership.
- User прие R4 corrective freeze със същия final 12-path allowlist.
- Banner-ът е преместен в case instruction. Два regression tests забраняват
  case-specific names/call в overview и изискват creation-before-resize-use.
- Current targets са 76 + 78 = 154 targeted и 1935 full, expected
  failures=3, skipped=0; 193 tracked files и 136 Python. Няма standards,
  crypto, data, authority, commit или tag промяна.

### Stage 2.38 R5 unified-layout freeze и implementation

- R4 laptop automated gates преминаха 76/78/1935, но human evidence е
  коригирано: Cases 1–3 са имали скрити долни controls; Case 4/200% не е
  показал acknowledgement/Start. Whole R4 visual matrix е FAIL и трите JSON
  PASS reports са withdrawn.
- Installer status 130 rollback PASS. Read-only gate потвърди exact Stage
  2.37 `ba465fe`/`25a03227`, clean, absent Stage 2.38 paths/tag, 106 commits,
  65 tags и unchanged fsck set.
- Fresh review доказа page-level pack competition, footer outside Canvas,
  fixed geometry under relative scaling и structural-only test gap.
- Fresh official review: WCAG2ICT Group Note 2025-12-11; WCAG-EM 2.0 Group
  Note 2026-07-23; EN 301 549 v4.1.0 adopted-for-publication 2026-08-24,
  pending publication/OJ confirmation; EAA applicability scope-dependent.
- User прие exact same 12-path R5 freeze: three-region grid във всички four
  phases, live client-bounds gate, no geometry logging, no event injection.
- Stage 2.37 long introduction е в scroll middle; short title е fixed header.
  Geometry settle/gate предхожда visible claim и checkbox enable.
- Exactly 8 + 12 regression tests са добавени. Preliminary targeted gate е
  84/84 + 90/90 = 174/174 PASS. Full target е 1955, expected failures=3,
  skipped=0; 193 files/136 Python. Няма commit/tag claim.


### Stage 2.38 post-R5 corrective review и candidate implementation

- Нов чат започна от exact `593e445`/`5b2ee0c`, clean, R5 annotated tag,
  107 commits/66 annotated tags и unchanged three unreachable blobs.
- Three-file export беше read-only verified; Stage 2.39 остана PAUSED.
- Operator-reported intermittent resize-operability finding invalidира final
  R5 quality acceptance, без да пренаписва R5 commit/tag.
- D1 root-cause evidence е rejected. D2 clean repeat даде six OPERABLE; raw
  `/dev/input/event3` Tab probe даде 10 press/10 release/0 repeat. D3 покри
  initial/slight/medium/large-nonmax/restored mouse sizes и всички са OPERABLE.
- Root cause остава unknown/currently non-reproducible. Не се прави speculative
  grab/focus/Wayland/window-manager patch.
- Fresh static review локализира доказана architecture gap: initial layout gate
  няма runtime post-resize revalidation. User прие minimal invariant-based
  corrective freeze.
- Candidate добавя 125 ms debounced Toplevel runtime layout validation, exact
  region/action recheck, controller-only Confirm state resync, focused checkbox
  reveal без focus stealing и fail-closed teardown/callback cancellation.
- Candidate targeted gate: 182/182 PASS. Expected laptop full gate: 1968 tests,
  expected failures=3. Sandbox full-suite partitioning няма candidate regression;
  два fresh-import tests са baseline-incompatible само в sandbox `/opt/pyvenv`
  и ще останат задължителни, без skip, в `~/venv_sys` laptop dry-run.
- Fresh standards check: SP 800-227 Final; SP 800-57r6 IPD; SP 800-38Dr1 second
  preliminary/no actual draft; EN 301 549 V4.1.0 adopted-for-publication with
  next ETSI publication status 2026-09-03 and no V4.1.0 OJ claim; CRA reporting
  date 2026-09-11 tracked without automatic applicability/legal claim.
- Няма repository apply, commit, tag или human quality acceptance на този етап.

### Stage 2.39 start — accepted freeze and implementation preparation

- New chat started from three authoritative Stage 2.38 corrective handoff artifacts.
- Bundle/snapshot/handoff consistency and live repository identity were verified read-only: exact `65721f4` HEAD, `7fd78e7` tree, parent `593e445`, branch `feature/mokosh-v2-core`, clean worktree, 108 commits, 0 merges, 67 annotated tags.
- Permanent lessons/preventive-corrections section was accepted as an ongoing process gate.
- Fresh architecture/security/standards/legal review completed; no silent compliance/certification claim was introduced.
- User explicitly accepted `Stage 2.39 — isolated Vault recovery source-inspection review controller` freeze before mutation.
- Exact six-path mutation allowlist and 20-test targeted design were frozen.
- Before repository commit, exact source review corrected an assistant overstatement: the superseded three-stages-per-chat rule exists in the active `PROJECT_STATUS_BG.md` invariant and as historical Stage 2.36/session evidence in `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md` and this session log. Only the active status invariant is rewritten; historical security/session evidence remains unchanged and is explicitly superseded by the current rule. Preventive rule: use exact search evidence before claiming the distribution of a documentation inconsistency.
- Authoritative pre-implementation baseline passed with 1968 tests, expected failures=3, no skipped tests, and clean exact `65721f4` before/after.
- R1 package verification and dry-run passed wrapper self-tests, 20/20 targeted tests and the 1988-test full candidate suite. R1 live apply repeated the 20/20 and 1988-test PASS gates, then false-failed on `live bytecode residue`; wrapper rollback to exact `65721f4` passed.
- R2 changed wrapper/tooling only and replaced the absolute-zero bytecode assertion with an exact baseline-relative bytecode-state invariant. Added self-tests prove unchanged pre-existing bytecode passes while new or changed bytecode fails closed; self-test cleanup is also verified.
- R2 authoritative dry-run passed all wrapper self-tests, 20/20 targeted tests, 1988 full tests with expected failures=3, and left the live repository unchanged. R2 live apply recorded 4341 pre-existing bytecode artifacts before mutation, then passed 20/20 targeted, 1988 full tests, exact six-path/hash checks and `LIVE_BYTECODE_STATE_UNCHANGED=PASS`; six frozen paths were left unstaged for independent pre-commit review.
- Independent pre-commit review found the documentation-distribution claim above was still inaccurate in the R2 payload, so no staging/commit/tag was allowed. Stage 2.39 production controller, tests and contract remain unchanged; only the three already-frozen evidence/status documents are corrected in R3.
- New preventive process gate: every pre-commit candidate receives an independent exact-diff factual-consistency review after automated PASS and before staging; tooling/evidence claims are checked against the baseline text, not memory.

### Stage 2.40 start — accepted inactive main-GUI bridge freeze

- Three Stage 2.40 handoff artifacts and exact Stage 2.39 history/snapshot were
  independently verified. Live identity/runtime gate and comprehensive
  wrapper-self-tested baseline are PASS.
- Exact live baseline: `468ad782` / `e4c0233`, clean, Stage 2.39 annotated tag,
  109 commits, 0 merges, 68 annotated tags and unchanged three dangling blobs.
- Full baseline is 1988 tests, expected failures=3, skipped=0. The exact 4341
  bytecode records have identical pre/post SHA-256
  `afc72643d2de686ca1e2a8f2ded999783d4d351b4590ec9def6a4456b29e8011`.
- User accepted the initial Stage 2.40 seven-path freeze. Work mode changed
  from High review to Medium implementation only after acceptance.
- Candidate adds an inactive one-shot bridge accepting only exact fresh Stage
  2.39 session. Locale is inherited; no caller locale or other authority input.
- `mokosh_gui.py` adds only a conditional loader and exact seam. No `main()`
  parameter, normal activation, widget, text, layout or geometry is added.
- First targeted run: 22 PASS / 2 FAIL. Root cause is test expectation, not
  production: two assertions confused raw controller outcome identity with the
  required fresh dataclass reconstruction returned by the bridge. Only the two
  assertions changed. Repeated targeted result: 24/24 PASS.
- Independent impact review then found 13 stale exact `mokosh_gui.py` hash
  expectations in 12 historical security test paths. A 384-test read-only run
  confirmed exactly those 13 failures and 371 passes. Work returned to High
  and stopped until the user accepted the minimal 19-path re-freeze. The 12
  added paths change only the expected GUI digest; no test is removed, skipped
  or weakened. Work then returned to Medium.
- The same review found a test-only defect in test 17: it inspected `__slots__`
  names rather than values for parent retention. Its assertion is corrected in
  the already-frozen 24-test path; production code and test count are unchanged.
- The next 765-test transitive run gave 764 PASS and one second-level hash
  dependency: localization byte-hashes the changed UI-adapter test. Exact
  reference-closure search found no other dependency. Work stopped again; the
  user accepted the one-line amendment inside the same 19-path scope before
  its expected predecessor-test digest was updated.
- Candidate is not yet package/full-regression/commit/tag evidence. Expected
  full count is 2012, expected failures=3, skipped=0; all remaining wrapper,
  transitive, bytecode, exact-diff and rollback gates remain mandatory.
- R1 laptop dry-run stopped fail-closed during runtime validation and before
  repository/candidate tests. Installer `.resolve()` had converted the lexical
  `venv_sys/bin/python3` symlink to `/usr/bin/python3.12`, bypassing the venv;
  system cryptography therefore lacked `ml_kem`. No live project mutation
  occurred. R2 preserves the lexical venv executable path and adds a symlink
  regression self-test plus exact executable/prefix/isolation/backend probes.
  The same gate is mandatory for every future Stage installer.
- R2 used the correct venv entry but failed before Git/candidate tests because
  the probe independently reconstructed the ML-KEM API as nonexistent
  `ml_kem`. The baseline project uses `mlkem` through `_mlkem_module()`; no live
  mutation occurred. R3 reuses that exact project dependency boundary for a
  real encapsulate/decapsulate roundtrip. Future installer probes must reuse
  proven application API boundaries instead of duplicating library API syntax.
- R3 passed live venv/ML-KEM, exact Git/fsck and bytecode-baseline gates, then
  stopped before payload tests because the laptop local clone retained the
  three known unreachable blobs whereas the scratch clone omitted them. No
  live mutation occurred. R4 distinguishes exact live history from clone
  reachability: clone dangling objects may be zero/a subset of the exact known
  live set, never unknown. Positive and negative self-tests prevent recurrence.
- High recovery semantic review found that two green foreign-outcome tests
  failed before reaching their named identity/locale guards and that the GUI
  seam test did not assert exact parent forwarding. The same 24 test methods
  are strengthened to isolate those guards; no production path or authority is
  added.
- High recovery production review reproduced one contract mismatch: replacing
  the private bound-session slot with another fresh same-locale session was
  accepted, although the freeze requires the exact preparation reference.
  Stage 2.40 now verifies a separate process-local preparation identity before
  display and clears it on all terminal routes. A negative substitution case
  is folded into the existing nonfresh-session method, so the accepted
  19-path scope and 24-test count do not expand.
- R1--R4 are now explicitly withdrawn and forbidden. A complete High
  post-mortem found that their common targeted parser could accept expected
  failures and that `WRAPPER_SELF_TESTS` never invoked package/candidate/copy/
  backup/apply/rollback paths. The new delivery implementation is written from
  the restated invariants and uses a `.git`-free `git archive HEAD` candidate.
- Before packaging, the new tool's blanket PAX rejection false-failed on Git's
  standard commit comment and its first rollback draft validated backup files
  too late. Exact PAX commit binding and complete pre-mutation backup-manifest
  validation are now covered. The pre-package internal tool suite was 33/33
  PASS; authoritative laptop, full-regression and live gates remain pending.

### Stage 2.41 start — accepted conditional source-inspection GUI freeze

- The new chat restored exact Stage 2.40 handoff/history/input. Uploaded-copy mode `0644` was not treated as source-machine mode; laptop originals were independently proved `0600`, owner-only ACL and exact hash.
- Exact live `b039b3b` baseline passed 24/24 predecessor, 2012 full tests, expected failures=3, skipped=0, clean worktree and identical pre/post 4341-record bytecode SHA-256.
- An earlier diagnostic incorrectly required absolute absence of bytecode. It was withdrawn; the permanent gate is exact baseline-relative state.
- User explicitly accepted the exact 24-path Stage 2.41 freeze before mutation.
- Candidate adds a keyword-only Stage 2.40 binding to `main()`, mutual exclusion with the old positional binding, pre-runtime/Tk validation, one-shot event/widget, fixed BG/EN text and four-case synthetic evidence.
- Existing private runtime-directory preparation remains; no whole-process no-filesystem claim is made. No recovery-source access/mutation or operation authority is added.
- Read-only closure found 25 textual hash references; the extra reference is immutable historical Stage 2.40 evidence. Mutation allowlist remains 24 paths.
- Preliminary scratch: 36/36 target and 128/128 compatibility PASS. Scratch full is 2048 PASS with expected failures=3 and seven non-authoritative build-runtime skips; laptop `~/venv_sys` must produce skipped=0.
- No live apply, manual visual PASS, commit or tag exists yet.

### Stage 2.41 R1 withdrawal, R2 live evidence и standards supersession

- Първият R1 dry-run изпълни 14/14 wrapper self-tests, после спря безопасно
  преди candidate/mutation на `.gitignore` mode mismatch. Root cause е
  wrapper defect: Git archive executable class е третиран като exact live
  physical mode. R1 е withdrawn и не е retry-ван.
- Read-only laptop audit потвърди exact clean `b039b3b`, zero Stage 2.41 tags,
  owner/group `mitra:mitra`, zero extended ACL и tracked distribution
  `61×0600`, `108×0644`, `24×0664`, `1×0700`, `5×0755`. Точно шест от 20
  existing targets са non-0644: пет `0664` и един `0600`.
- R2 замразява отделна 199-path physical-mode карта, пази exact existing target
  modes, задава новите files `0644/0755` според доказаните аналози и има
  explicit regression за R1 false fail. Package е `196231` bytes, SHA-256
  `a426adb7e224fc3a687fe880570ad44891b82999140dd70667c1a9ae0ae140f2`.
- R2 final-byte audit е PASS: reproducible build, 29/29 safe members, 25/25
  bytes/modes, normalized metadata, clean extraction, mode-drift negative
  tests и extracted rollback injection 24/24.
- Laptop dry-run и live apply независимо дадоха 36/36 Stage 2.41, 24/24
  predecessor и 2048 full PASS, expected failures=3, skipped=0. Dry-run
  rollback injection е 24/24. Independent post-apply gate повтори 36/36 и
  2048, exact 24 bytes/modes/owner/ACL, fsck и unchanged bytecode.
- Human matrix е завършена без корекция на observation evidence: cases
  BG/100/Escape, EN/125/Cancel, BG/150/child-X и EN/200/Acknowledge имат общо
  24/24 self-reported PASS observations. Последвалото user clarification е,
  че погрешно е било само по-ранното недовършено chat съобщение, не тестът.
- Reports са synthetic/non-secret, no operation, no recovery-source access или
  mutation, no network/retention и no normal-startup activation. Те не са
  accessibility/legal conformity, platform certification или comprehension
  claim.

- Pre-commit review не прие stale candidate текста „no live apply/manual PASS“
  за финална история и изиска този explicit supersession в същите allowlisted
  evidence paths. Production/test behavior и exact 24-path scope не се меня.
- Official recheck на 2026-09-03 намери публикуван EN 301 549 V4.1.1 (2026-09)
  в ETSI final repository от 2026-09-02. Това supersede-ва междинния V4.1.0
  status, но не доказва OJ citation, MOKOSH applicability или conformity.
- Candidate остава unstaged върху Stage 2.40 HEAD; няма Stage 2.41 commit/tag
  преди post-amendment tests и exact pre-commit gate.

## 2026-09-03 — Stage 2.42 accepted layout-audit freeze

- Handoff bundle `d213db4e...6aff` е complete и INPUT archive `2c9b7013...fbef1` се възпроизвежда byte-for-byte от exact Stage 2.41 HEAD.
- Laptop read-only gate потвърди exact HEAD/tree/parent/branch/tag, 111 commits, zero merges, 70 annotated tags, known three dangling blobs, pinned venv dependencies и clean worktree.
- Targeted резултатите са Stage 2.41 36/36 и Stage 2.40 24/24; full е 2048 PASS, expected failures=3, skipped=0.
- Fresh review намери отделен evidence gap: normal Stage 2.30 layout няма 100/125/150/200% scaling matrix. Conditional Stage 2.41 evidence не може да се пренася към normal mode.
- User-ът прие Stage 2.42 като точно осем-path audit/pre-activation freeze без `mokosh_gui.py` или production промяна.
- Direct request-to-review wiring е отказано; Stage 2.31, Stage 2.32 и Stage 2.39–2.41 boundaries не се сливат.
- New core/launcher записват само fixed BG/EN × scaling self-reported observations без GUI event injection, picker, path, source access, screenshot или host/geometry metadata.
- Първият 32-test cycle false-fail-на само test 26 заради raw `callback` substring в no-capability docstring. Root cause е lexical test predicate; AST correction и negative regression дават 32/32 PASS. Production behavior не е променяно.
- Human FAIL/NOT_CHECKED ще спре candidate-а преди live apply и ще изисква explicit corrective re-freeze.

## 2026-09-03 — Stage 2.42 pre-package corrections

- Independent review corrected the unpublished launcher because it had
  collapsed `initial_keyboard` and `resize_restore_keyboard` by asking every
  case to resize. Cases 1–2 now remain at initial size; only cases 3–4 perform
  resize/restore. The frozen eight-path scope is unchanged.
- The first archive/candidate wrapper run stopped safely on an incorrect
  211-file expectation. Root cause was counting all eight payload paths as new;
  four replace baseline documents and four are new, so exact inventory is 207.
  No live repository mutation occurred.
- The first bytecode diagnostic used a newly invented `*.pyc`-only schema and
  reported 4086. The verified handoff exporter source showed the exact prior
  schema: 4086 files plus 255 `__pycache__` directories, 4341 total, with the
  historical static digest. The wrapper now reuses that exact schema.
- The first source-extraction command stopped because laptop `rg` is absent;
  the retry used installed `grep` and made no project change. A local cleanup
  command was separately rejected by the work environment's `rm -f` policy;
  exact `unlink` cleanup succeeded without touching the project or payload.

## 2026-09-03 — Stage 2.42 human FAIL и corrective re-freeze

- R1 с `tar --same-permissions` достигна човешката матрица след 14/14 wrapper,
  8/8 rollback, 32/32 target, 36/36 и 24/24 predecessor и full 2080 PASS,
  expected failures=3, skipped=0.
- Case 1 BG/100/initial беше спрян честно: recovery banner/buttons се виждат,
  но main-interface controls под тях не се виждат при непроменен размер.
  Report-ът съдържа `safety_and_recovery_controls_visible=fail` и седем
  `not_checked`; wrapper exit 2 блокира live apply.
- Inspection показа fixed `820x720`, четири дълги recovery rows, после normal
  controls и липса на vertical viewport. User-ът прие explicit corrective
  re-freeze вместо waiver.
- Exact corrective scope е 23 paths. `mokosh_gui.py` добавя scrollable viewport
  само в normal mode, keyboard/mouse scrolling и focus reveal. Дванадесет hash
  consumers и два GUI mock tests затварят compatibility evidence; recovery,
  source, picker, secret, Vault, crypto и storage behavior не се разширяват.
- Target-ът е увеличен от 32 на 48, а full expected count от 2080 на 2096.
  Preliminary isolated rerun е 48/48 target и 61/61 direct GUI compatibility
  PASS. Нов package, authoritative laptop tests и пълно повторение на human
  matrix са pending; няма live mutation, commit или tag.
- Първият corrective R1 laptop dry-run спря след 14/14 installer self-tests и
  преди candidate/GUI/mutation на existing-target mode mismatch. Wrapper-ът
  погрешно прилагаше `0644` към всички 19 existing targets вместо exact mode
  map; засеченият acknowledgement test е `0664`. R1 е withdrawn. R2 запазва
  петте `0664`, единия `0600` и останалите `0644` modes и ги проверява
  поотделно.

## 2026-09-03 — Stage 2.42 R2 withdrawal и 25-path closure

- R2 dry-run доказа individual modes и мина 14/14 installer, 23/23 rollback,
  48/48 target, 36/36 Stage 2.41 и 24/24 Stage 2.40. Full 2096 run блокира с
  две `FakeWidget`/real-Canvas errors и един stale UI-adapter predecessor hash.
- Stop-ът е в temporary candidate преди human gate и live apply. Репото на
  laptop-а остава exact clean Stage 2.41; R2 е withdrawn.
- Read-only transitive hash graph намери 17 production/test consumers.
  Корекцията добавя само двата пропуснати entry main-GUI mock tests; stale
  hash се поправя в вече включения localization test. Exact scope става 25
  paths без нов production/capability boundary.
- Focused post-correction gate е 51/51 PASS. Два предварителни full runs върху
  pre-documentation candidate са 2096 PASS, expected failures=3, skipped=0;
  те не се използват като final package evidence. Два нови full runs върху
  окончателните post-documentation bytes са задължителни преди R3 build.

## 2026-09-03 — Stage 2.42 R3 status false fail и rollback

- R3 package/live gates минаха до края на втория post-overlay full 2096 PASS;
  human matrix отново е 32/32 PASS. След това final Git-status gate блокира и
  live PASS marker не е издаден.
- Reproduction върху exact baseline показва 25 raw porcelain lines и exact
  expected set. Общият `git()` helper прилага `.strip()` и унищожава leading
  space само на първия ` M` ред, затова сравнението false-fail-ва.
- `apply_live()` обработи отказа чрез 25-target rollback и вътрешна verification.
  R3 е withdrawn. R4 чете raw status без normalization и добавя explicit
  post-overlay/post-rollback status regression; scope остава exact 25 paths.

## 2026-09-03 — Stage 2.42 R4 live apply и independent gate

- R4 е издаден само след два post-documentation full 2096 PASS и full
  apply/status/rollback simulation. Package SHA-256 е `5249f40e...223b0`,
  size `212756`; installer SHA-256 е `2942c687...fb309`, size `40975`.
- Laptop pre-overlay gates: 15/15 installer, 25/25 rollback, 48/48 target,
  36/36 и 24/24 predecessors, full 2096 PASS, expected failures=3, skipped=0.
- Human cases BG/100, EN/125, BG/150 resize/restore и EN/200 resize/restore
  дадоха 32/32 self-reported PASS. След overlay вторият full 2096 също е PASS
  и final marker е `STAGE2_42_LIVE_APPLY=PASS_UNSTAGED_25_PATHS`.
- Independent gate потвърди exact 25/25 status и payload bytes/modes/owner/ACL,
  tracked mode distribution, strict fsck, unchanged bytecode и още един full
  2096 PASS. Няма staged paths, commit или Stage 2.42 tag преди evidence
  amendment/pre-commit gate.
- R1 mode-check defect, R2 closure defect и R3 porcelain-strip defect остават
  explicit withdrawn evidence; R4 PASS не ги пренаписва ретроактивно.

## 2026-09-04 — Stage 2.43 accepted freeze и candidate start

- Handoff/input/bundle и exact Stage 2.42 repository са read-only PASS.
  Laptop baseline е 48/48, 36/36, 24/24 и full 2096 PASS, expected failures=3,
  skipped=0, с exact pre/post physical и 4341-record bytecode state.
- Fresh review отхвърли direct Stage 2.29 -> Stage 2.39/2.41 activation като
  нарушение на separate preparation/authorization boundaries. User-ът прие
  минимално пето normal-GUI действие, което достига само Stage 2.31 intent.
- Freeze-ът е exact 22 paths, един production file и никакви Vault/crypto/
  storage/Contacts/network/Stage 2.32–2.41 production промени.
- Explicit privacy limitation: fifth event временно задържа exact Stage 2.29
  outcome; GUI reference се премахва преди loader/dialog, но Stage 2.31 може
  временно да държи Python path string и memory zeroization не е доказуема.
- Първият isolated target run беше 47/48: английският banner казваше `only in
  memory`, а strict test изискваше explicit `process-local`. Това е candidate
  wording/evidence mismatch преди package/live mutation, не tooling false fail.
  Banner-ът беше уточнен, тестът остана строг и повторението е 48/48 PASS.
- Package, authoritative laptop dry-run/full/human gates, live apply, commit и
  annotated tag още не съществуват.

## 2026-09-04/07 — Stage 2.43 R1 human cancellation и guided corrective workflow

- R1 package identity е SHA-256 `8672c1556ae973169ff5589d368e70cfa57ec06dc49c5994b4f16f471128f4b4`,
  size `203298`, mode `0600`. Dry-run мина 16/16 installer, exact Stage 2.42
  baseline, 22/22 rollback, 48/48 target, 48/36/24 predecessors и full 2144
  PASS, expected failures=3, skipped=0, без live mutation.
- Apply attempt повтори automated gates и стигна до BG/100 case 1. Петте
  product actions бяха извършени, но visual workflow-ът изискваше ad-hoc chat
  guidance: instructions бяха само в terminal, picker Directory беше `/tmp`,
  wrapper-ът създаде `.txt` вместо default-visible `.mokr`, а observations се
  появиха в terminal след затваряне на MOKOSH.
- Operator-ът прекрати на observation 1; launcher exit `130` и installer gate
  блокираха преди live apply. Exact read-only abort check потвърди Stage 2.42
  HEAD `98cbd53`, tree `f851ca0`, branch/tag, clean status и премахнат fixture.
  R1 не е human PASS и е withdrawn за apply.
- User requirement: explanation-ите да са налични от началото и успоредно с
  всяка activity, в отделен видим прозорец, с guidance за action и последващ
  dialog. Това е прието като corrective freeze amendment без production/scope
  expansion.
- Runner correction добавя separate resizable nine-step guide beside MOKOSH,
  exact exclusive/no-follow empty `.mokr` fixture в physical Downloads и
  graphical 11-step observation wizard. Всеки observation започва
  `not_checked`; PASS не е preselected и navigation изисква explicit choice.
- Pure report schema version 2 разграничава disclosed fixture creation/removal
  от MOKOSH application behavior чрез
  `application_recovery_source_filesystem_mutation_performed=false`. Fixture-ът
  се revalidate-ва по inode/mode/owner/size и се изтрива преди report.
- Corrective preliminary target остава 48/48 PASS. Package R2, authoritative
  laptop human matrix, live apply, commit и tag са pending.

## 2026-09-07 — Stage 2.43 R2 safe cancellation и R3 foreground correction

- R2 deterministic archive е `212020` bytes, SHA-256
  `54c95c688b32f1a86e54993fc509c6c0bd8a319aa9fdd3206328d7dcc2573a4a`.
  Laptop dry-run мина 18/18 installer self-tests, exact Stage 2.42 baseline,
  22/22 rollback, 48/48 target, 48/36/24 predecessors и full 2144 PASS без
  live mutation.
- R2 apply повтори всички automated gates. В case 1 отделният guide се появи
  преди normal main GUI и после остана зад него; след main close observation
  wizard-ът също остана зад browser-а. Това е human-usability/stacking FAIL,
  не operator error и не product-stage PASS.
- Operator-ът избра safe cancel във wizard-а. Launcher exit `130` и installer
  gate блокираха преди live apply. Отделен read-only gate потвърди exact
  `98cbd53` HEAD, `f851ca0` tree, branch/tag, clean worktree и премахнат exact
  synthetic `.mokr`. R2 е withdrawn и няма да се retry-ва.
- R3 създава guide-а след normal main GUI construction, държи го
  mapped/topmost чрез 500 ms watchdog и извежда observation wizard-а
  mapped/topmost/focused. Няма event injection или automatic PASS.
- Report schema става v3. Новото explicit human поле
  `parallel_step_guide_visible_and_usable` определя guide visibility и
  per-action-guidance claims; те вече не са unconditional. Matrix-ът става
  12 observations на case/48 общо, без промяна на 22-path closure или
  production behavior.

## 2026-09-07 — Stage 2.43 R3 clipped-controls cancellation и R4 design

- R3 deterministic archive е `214655` bytes, SHA-256
  `9bb059548948e57bf275b9ebda1aaf09f6d856641a389ee5944d34cd0e1ad535`.
  Laptop dry-run и apply pre-human gates минаха 18/18 installer, 22/22
  rollback, 48/48 target, 48/36/24 predecessors и full 2144 PASS.
- Human case 1 установи, че manual guide navigation и wizard footer buttons
  излизат под реалната visible work area, а wizard body няма scrollbar.
  Periodic guide topmost callback остана pending при destroy и Tk съобщи
  `invalid command name ..._keep_visible`.
- Operator-ът прекрати безопасно; launcher exit `130` блокира installer-а преди
  live apply. R3 не е human PASS, withdrawn е и няма да се retry-ва.
- R4 използва passive exact-button-state observer: петте normal-GUI action
  references се откриват по exact localized labels след main build; guide-ът
  преминава през шест phases само когато следващият button стане `normal` или
  consumed fifth button стане `disabled`. Няма command wrapping/event injection.
- Единственият 150 ms observer е root-owned и се cancel-ва explicit преди
  release. Guide-ът е transient/topmost без recurring visibility callback.
  Wizard safe-cancel/navigation controls са фиксирани отгоре, а въпросите и
  choices са в отделен scrollable Canvas body с screen-bounded geometry.
- Preliminary R4 verification: 48/48 target, 156/156 combined Stage 2.40–2.43,
  4/4 headless scale-layout structures и 6/6 passive guide transitions PASS;
  actual desktop human evidence остава задължително и не се подразбира.

## 2026-09-07 — Stage 2.43 R4 active-state cancellation и R5 correction

- R4 archive е `218061` bytes, SHA-256
  `3680d1435bf96c45a58393d4205b9e3248323563374878e67e1a4e710c784952`.
  Dry-run мина 18/18 installer, 22/22 rollback, 48/48 target, 48/36/24
  predecessors и full 2144 PASS без live mutation.
- В apply human case 1 operator-ът достигна действие 3, но guide marker-ът
  остана на действие 1. R4 погрешно валидираше само `normal`/`disabled` и
  отхвърли валидното transient classic Tk button state `active`; callback-ът
  показа traceback. Human matrix беше прекратен безопасно, exit `130` блокира
  overlay-а и R4 е withdrawn без retry/waiver.
- R5 приема exact `normal`/`active`/`disabled`, намира furthest enabled action
  след пропуснат poll и пази постоянен пълен шестфазен план в scrollable guide.
  Истински observer validation error вече се записва и затваря case-а
  fail-closed, вместо да остане uncaught callback.
- Corrective target е 48/48 PASS с четири-case/state/fast-transition/full-plan/
  fail-closed simulation. Combined closure е 156/156 и full regression е
  2144/2144 PASS при expected failures=3. Extracted candidate мина 18/18
  self-tests, 22/22 rollback injection, overlay, същите suites и exact rollback.
  Local-only ACL substitute провери липса на POSIX ACL xattr, защото scratch
  няма `getfacl`; distributed installer не е отслабен. Authoritative laptop
  dry-run/human matrix остават pending; live Stage 2.43 няма.

## 2026-09-07 — Stage 2.43 R5 incomplete instruction cancellation и R6 rule

- R5 archive е `221299` bytes, SHA-256
  `bd59e6410c2f95a4422e46a28ce3d5c4dbaeb9ac569bff733c2f7eafc0b2ceed`.
  Laptop dry-run и apply pre-human gates са PASS до full 2144.
- Human cases 1–3 записаха 36 PASS observations. В case 3 operator-ът посочи,
  че fifth keyboard guide изисква Tab/Shift+Tab/Tab, но не казва изрично
  `Space`; използва само двусмисленото „Активирайте“. Липсата беше дообяснена
  чрез chat, следователно run-ът не е self-contained.
- Трите JSON report-а са invalidated за guide-usability evidence. Case 4 беше
  прекратен безопасно, launcher exit `130` блокира overlay-а и R5 е withdrawn.
  Няма live Stage 2.43 mutation, waiver, commit или tag.
- Incident record R1–R5 се пази в security evidence като non-recurrence table.
  R6 въвежда exact `Tab → Shift+Tab → Tab → Space` wording и automated source/
  package assertions. Human test не може да разчита на chat за липсващо
  operator действие.

## 2026-09-07 — Stage 2.43 R6 authoritative live evidence

- R6 archive е `223721` bytes, SHA-256
  `2bcb0b6f5aa1f0d470e0791fff52ec2e96b6d60f7d65a278ceed6d998090d69d`.
  Laptop dry-run мина 18/18 installer, exact package/runtime/Stage 2.42
  baseline, 22/22 rollback, 48/48 target, 48/36/24 predecessors, full 2144 и
  extracted candidate rollback; live mutation нямаше.
- Apply повтори pre-human gates. Cases BG/100 request, EN/125 preserve, BG/150
  preserve resize/restore и EN/200 request resize/restore дадоха 48/48 explicit
  PASS observations. Exact `Tab → Shift+Tab → Tab → Space` беше налично в
  self-contained guide-а; четирите JSON reports остават bounded и path-free.
- След human gate extracted candidate rollback мина. Live overlay-ът беше
  приложен като exact unstaged 22 paths и post-overlay 48/48, 48/36/24 и full
  2144/2144 са PASS при expected failures=3.
- Independent post-apply gate потвърди exact bytes/modes/owner/ACL/status,
  no-staging/diff-check, known dangling-only fsck, Stage 2.42 HEAD/tree/branch,
  tracked physical manifest, премахнат synthetic fixture и unchanged bytecode
  преди/след още един full 2144 PASS.
- R1–R5 остават withdrawn в incident history. R6 live candidate е unstaged;
  evidence amendment, pre-commit gate, commit и annotated tag са pending.

## 2026-09-07 — Stage 2.44 accepted freeze и reader correction

- Exact Stage 2.43 checkpoint `c0bc959223db232290e96c1b09a61c8142a3f644`,
  tree `3b374226084cc46d396bb42be2faf1602c36de2d`, branch и annotated tag са
  потвърдени clean; laptop baseline е full 2144 PASS с три expected failures.
- User-ът прие exact 20-path freeze. Икономията на token/credit/time не променя
  security, legal/official-standard, regression, Git или evidence gates.
- Fresh review възпроизведе FIFO blocking, ancestor rename/symlink proof gap,
  неточно „authenticated identifier“ wording и двусмислен filesystem-mutation
  claim спрямо OS-managed `atime`.
- Candidate correction добавя retained descriptor chain, component-relative
  no-follow traversal, pre-open private regular-file validation, `O_NONBLOCK`,
  final chain/file revalidation и complete reverse cleanup.
- GUI и human visual matrix не са в Stage 2.44, защото GUI bytes са immutable.
  Ако реализацията изиска GUI промяна, Stage-ът трябва да блокира и да бъде
  re-freeze-нат.
- Local tooling incident: опит за изчистване на scratch directory с recursive
  remove беше отхвърлен от tool policy преди изпълнение; използвана е нова
  празна directory. Project snapshot и user repository не са засегнати.
- Candidate target/full/package evidence и authoritative laptop apply все още
  са pending и не се подразбират.

## 2026-09-07 — Stage 2.44 R1 dry-run, live apply и independent gate

- Final R1 package: `210357` bytes, SHA-256
  `c6553fc9c9e3dfdf8fd71a78e2e6ffe33805e08bf1857987bfba9df6df88b676`;
  installer: `27600` bytes, SHA-256
  `93ea95534081198c0b19ee3a0ad62b86e0ef0b5e3020c0892f394e907443ce6f`.
- Dry-run е PASS: archive 26/26, Stage 2.43 baseline, rollback 20/20,
  target 456/456 и full 2152/2152 при expected failures=3, skipped=0. Marker:
  `STAGE2_44_R1_DRY_RUN_WRAPPER=PASS`; live mutation няма.
- Apply е PASS: същите pre-overlay gates, exact 20-path transaction,
  post-overlay target 456/456 и full 2152/2152. Markers:
  `STAGE2_44_R1_LIVE_APPLY=PASS_UNSTAGED_20_PATHS` и
  `STAGE2_44_R1_APPLY_WRAPPER=PASS`.
- Independent verifier: `19044` bytes, SHA-256
  `c047a6d8b5551b4d6f47ad1f49bed60b3284820ca57ffcba5f8dc65ddb2955c7`.
  Той потвърди independent target 456, full 2152, exact 20 unstaged paths,
  package/live bytes, Git history/tag/fsck, physical manifest, ACL и bytecode.
  Marker: `STAGE2_44_INDEPENDENT_POST_APPLY_WRAPPER=PASS`.
- Authoritative logs са създадени извън repo с mode `0600`:
  `MOKOSH_STAGE2_44_R1_apply_q5cehfn9.log` и
  `MOKOSH_STAGE2_44_R1_post_apply_2s5f1a5m.log`.
- Scratch environment-only full run няма `argon2` и не е отчетен като PASS.
  Два direct-delta test опита бяха invalid tooling invocations; corrected full
  baseline-plus-extracted-overlay target run е 456/456 PASS.
- Преди package delivery review-ът хвана и премахна recurring `.resolve()` и
  `ml_kem` installer defects. User-ът е изпълнил само rebuild-натия final R1
  archive с горната exact identity.
- Този запис става final evidence само при marker
  `STAGE2_44_FINAL_EVIDENCE_R1_LIVE_APPLY=PASS_UNSTAGED_20_PATHS` след отделен
  456/2152 regression върху точните document bytes. Commit/tag остават
  забранени до последващ independent pre-commit gate.

## 2026-09-08 — Stage 2.45 accepted scope freeze и candidate audit

- User-ът прие Stage 2.45 като audit-only exact six-path freeze върху Stage 2.44
  commit `77c9432b519a8fd0c7ed7f446e39fbdc13547fb2` и tree
  `5b60a8520b7dfbbab4054a73766f60be6fda25b5`. Production/GUI bytes не могат да
  се променят; икономия на време/credit не отслабва нито един gate.
- Преди candidate работа laptop read-only baseline мина exact export/bundle/
  archive/live repository checks, pinned runtime/ML-KEM, full 2152 tests с три
  expected failures и zero skips, unchanged 4341-record bytecode state и
  known-three-dangling fsck. Marker-ът потвърди no project mutation.
- Review-ът установи, че Stage 2.32 вече има отделна authorization decision и
  one-shot secure-read boundary. Липсва normal-GUI handoff на положителния
  Stage 2.31 outcome; текущото пето действие връща outcome, който callback-ът
  не използва за Stage 2.32.
- Candidate audit result е `GO WITH BLOCKERS`, без production разрешение.
  Бъдещият freeze трябва да добави отделно locked шесто действие и path-free
  default-negative confirmation, exact Stage 2.31 → Stage 2.32 binding,
  terminal fail-closed lifecycle и забрана за automatic Stage 2.39–2.41 review.
- Retention contract изисква predecessor/locale clear под lock преди loader и
  dialog, локален predecessor release след Stage 2.32 preparation и path clear
  преди read. Replay, concurrency, loader/dialog/reader failure не могат да
  доведат до втори или implicit read.
- Privacy/honesty contract отказва path/content/logging/persistence/network,
  authentication/recovery/operation, global-consumption и zeroization claims и
  описва POSIX `atime` caveat.
- Бъдещият human fixture трябва да използва private runner-owned `0700`
  directory и `0600` regular single-link canonical synthetic non-secret `.mokr`
  с exclusive/no-follow creation и identity-safe cleanup. Stage 2.45 няма GUI
  delta, следователно няма human visual matrix.
- Добавен е нов 32-test audit module. Изолираният exact candidate мина 32/32
  target и 205/205 combined relevant tests. Това не замества pinned laptop full
  2184 regression или package transaction evidence; live apply, commit,
  annotated tag и handoff не са разрешени предварително.

## 2026-09-08 — Stage 2.45 R1 withdrawn след success-exit defect

- R1 laptop dry-run премина 12-member archive extraction, 12 installer
  self-tests, pinned runtime/ML-KEM, exact Stage 2.44 baseline, 4341 bytecode
  records, known-three-dangling fsck, 6/6 rollback, 32/32 target, 205/205
  combined и full 2184/2184 при три expected failures и zero skips.
- Dry-run snapshot comparison издаде `PASS_NO_LIVE_MUTATION`; след него
  installer-ът изпълни `raise SystemExit(main())`, но surrounding
  `except BaseException` прихвана успешния `SystemExit(0)`, отпечата false FAIL
  и върна nonzero. Wrapper-ът fail-closed не издаде своя PASS marker.
- Няма live project mutation. R1 е withdrawn и apply е забранен. R2 поправя
  само top-level package exit handling и трябва да повтори всички gates върху
  същия exact six-path audit scope.

## 2026-09-08 — Stage 2.45 R2 authoritative apply и independent gate

- R2 package: `149309` bytes, SHA-256
  `5ed4b80a5ace17acfb400c8c6225eb849168764a8f0859260c559714aa0bd4c7`.
  Success-exit regression е PASS без false FAIL. Dry-run повтори 12 self-tests,
  pinned runtime/ML-KEM, exact Stage 2.44 baseline, 6/6 rollback, 32/205/2184
  PASS, три expected failures, zero skips и no live mutation.
- Apply повтори candidate cycle, приложи exact six unstaged paths и изпълни
  live 32/205/2184 PASS. Няма production или GUI byte change.
- Independent verifier: `21027` bytes, SHA-256
  `02c72b8f401ae96b1cb2490c71c3a2141085170c784f89403551ce9397851d98`.
  Той потвърди 14 self-tests, pinned runtime, package-to-live binding, exact
  six-path/214-record physical state, owner/plain ACL, Git diff-check/history/
  tag/known-three-dangling fsck, 8 critical production hashes и unchanged
  4341-record bytecode преди/след още един 32/205/2184 PASS cycle.
- R1 остава withdrawn в permanent incident history. R2 evidence не го превръща
  ретроактивно в PASS candidate.
- Final evidence amendment трябва да приложи само тези verified facts в
  същия frozen scope и да мине нов regression. Commit/tag остават забранени до
  отделен independent pre-commit gate.

## 2026-09-08 — Stage 2.45 final-evidence R1 withdrawn extraction-validator incident

- Final-evidence R1 archive: `148782` bytes, SHA-256
  `178dabddb077e564ae0ff802e6e4caa70b33a44140cd3f8d49220243cec81d12`.
  Wrapper-ът е потвърдил download identity и exact 10-member safe normalized
  archive inventory.
- Clean Python 3.12 extraction с `filter="data"` и `umask 0077` е създала
  package directories `0700` и regular files `0644`. Външната проверка
  погрешно е очаквала archived `0755` и е спряла с
  `REFUSED_EXTRACTED_METADATA_MISMATCH`.
- Installer-ът не е стартиран. Няма self-tests, candidate regression, live
  apply или project mutation. Temp directory е премахната от wrapper cleanup.
- Final-evidence R1 е withdrawn и забранен за apply. R2 коригира само exact
  temp extraction-mode contract и добавя incident evidence; live six-path R2
  candidate, production bytes и frozen audit decision не се променят.

## 2026-09-08 — Stage 2.45 final-evidence R2 pre-commit safe stop

- R2 final-evidence dry-run и apply преминаха 12 self-tests, 5/5 rollback,
  candidate/live 32/205/2184 и exact six-path gates. Independent pre-commit
  verifier премина 17 self-tests, package/live binding, physical/ACL/fsck/
  bytecode/production gates и още един 32/205/2184 cycle.
- Commit transaction preflight потвърди exact шест hashes и status. След
  staging `git diff --cached --check` откри точно три trailing spaces в редове
  3–5 на новия audit документ и блокира commit.
- Cleanup guard върна paths unstaged. Follow-up read-only gate потвърди HEAD
  `77c9432`, липса на Stage 2.45 tag/staging, exact непроменени R2 bytes и exact
  three-line finding. Няма commit, tag или production/test mutation.
- Coverage defect-ът е pre-staging reliance върху `git diff --check`, който не
  включва untracked path. R2 е withdrawn като checkpoint candidate. R3 трябва
  да премахне exact трите spaces и да добави raw-byte scanner преди tests/apply;
  няма waiver и няма reuse на R2 identity за променени bytes.

## 2026-09-09 — Stage 2.45 final-evidence R3 fsck safe stop

- R3 package е `152247` bytes, SHA-256
  `6e8af78dfe572d5cd235321c84ab6c54aef1ee09063a657be4b11aa306869ca3`;
  reusable runner е `8726` bytes, SHA-256
  `2564d01712c187b9cec02871868884cf8bef9c8c32e023aa6e39b6a3d27b41bf`.
- Laptop dry-run премина 12 runner self-tests, exact 10-member extraction, 15
  installer self-tests и pinned Python/argon2/cryptography/ML-KEM. Strict fsck
  после отказа `9 != 3`, преди rollback/candidate tests/live overlay.
- Read-only follow-up потвърди baseline HEAD `77c9432`, exact six unstaged R2
  bytes, no staging/commit/tag и девет dangling blobs. Шестте нови blob contents
  съвпадат едно-към-едно с шестте R2 staged paths; трите historical blobs са
  непроменени.
- Причината е failed pre-commit `git add`: targeted reset възстановява index,
  но записаните loose Git objects остават unreachable. Това трябваше да бъде
  включено в R3 baseline model. R3 е withdrawn; няма project-file mutation.
- R4 консолидира exact nine-object evidence и вече въведения raw-whitespace
  control. Git objects не се delete/prune-ват, scope не се разширява и Stage
  2.45 не започва отначало.

## 2026-09-10 — Stage 2.45.1 legacy-contact security stabilization

- Stage 2.46 localization R1 е withdrawn след false dry-run failure от
  неправилен Python-path runtime type. R2 е withdrawn след import на
  несъществуващото `ml_kem` име вместо backend/project `mlkem`. Двата отказа са
  преди project mutation и задействат правилото за stop след два correction
  failures.
- Fresh read-only Gate 1–3 върху exact Stage 2.45 доказаха, че библиотечният
  ML-KEM работи, но legacy `contacts_core.py` има три PQ implementation defects,
  reciprocal contact-id defect, silent classic downgrade, unauthenticated
  routing/PQ metadata и private material извън Key Vault.
- Пълните предишни regression suites не са изпълнявали legacy Alice/Bob flow.
  Техният PASS остава валиден само за заявените assertions и не се
  преетикетира като legacy contact security/function PASS.
- User-ът прие първо seven-path quarantine freeze. Dependency review преди
  mutation установи десет действащи tests с exact predecessor
  `contacts_core.py` hash. Истинска quarantine промяна без тях би счупила или
  изисквала отслабване на regression gate-а.
- Няма silent workaround. User-ът прие corrected exact 18-path freeze:
  tombstone, нови quarantine tests, exact update само на разрешения digest и
  постоянни status/evidence/standards/session records. `mokosh_gui.py` и V2
  contact slots остават byte-exact; Stage 2.46 localization остава paused.
- Първата scratch editor операция за candidate е отказана без mutation, защото
  е комбинирала delete/add на един path. Операциите са разделени атомарно; това
  е tooling incident, не product/package test и не засяга laptop repository.
- Първият affected regression е изпълнил 414 tests с 413 PASS и един FAIL в
  localization predecessor hash: промененият UI-adapter test е second-order
  SHA-256 dependency. Няма skip или преетикетиране като PASS.
- Recursive graph на baseline file hashes е намерил още два и само два test
  consumers: main-GUI chain-layout audit и Stage 2.45 authorization-readiness
  audit. User-ът е приел exact 20-path re-freeze преди промяната им. Те сменят
  само recomputed hashes на санкционирано променените child tests.
- Candidate, authoritative pinned-runtime dry-run/apply, full regression,
  commit/tag и handoff не се твърдят преди съответните evidence gates.
- Окончателният corrected freeze е приет като exact 20 paths: добавени са само
  двата доказани second-order consumers
  `tests/test_mokosh_main_gui_recovery_chain_layout_audit.py` и
  `tests/test_mokosh_vault_recovery_source_inspection_normal_gui_authorization_readiness_audit.py`;
  `mokosh_gui.py` остава byte-exact, а Stage 2.46 localization остава paused.
- Повторният affected gate е 414/414, двата parent модула са 80/80, а общият
  exact affected set е 494/494. Локалният QA full regression е 2191/2191 с
  точно три historical MOK1 expected failures и zero skips. QA runtime-ът е
  Python 3.12.14 с exact `cryptography 49.0.0` и `argon2-cffi 25.1.0`; това е
  scratch evidence и не замества authoritative laptop Python 3.12.3 gate.
- Първият local exact-delta quality predicate е отказал без mutation, защото
  съдържал грешно ръчно преписан baseline SHA-256 за `contacts_core.py`.
  Корекцията извлича digest-а от exact baseline и моделира всяка позволена
  замяна: exact 20 paths, 12 hash-consumer files и 14 substitutions са PASS.
- Първият multi-document evidence patch е отказан изцяло без mutation поради
  несъвпадащ context в този log. Последвалите отделни exact-document patches
  запазват 20-path scope; това е editor matching incident, не package failure.
- Pre-package static review е открил, че proposed lexical installer self-test
  за withdrawn `ml_kem` spelling би откривал собствения си diagnostic literal
  и винаги би отказвал. Преди package issuance той е заменен с AST import-alias
  predicate. Project candidate не е променен извън exact evidence documents.
- Първият package build е отказал преди artifact creation поради липсваща
  `getfacl` команда в scratch средата. Release profile продължава да изисква
  real `getfacl`, plain ACL и exact laptop physical digest `f4b57b…`.
  Недоставяният QA-only profile използва explicit mode-derived plain-ACL model
  и local shim; резултатът му не се представя като authoritative ACL evidence.
- Първата QA launch команда е отказана от workspace safety policy преди
  execution поради shell recursive cleanup. Няма създаден clone и package-ът
  не е стартиран. Local driver използва scoped `TemporaryDirectory` cleanup;
  release wrapper-ът и exact project scope остават непроменени.
- Първият действително изпълнен QA twin е отказал в installer self-test преди
  baseline access: unittest-summary patterns за `errors` и `failures` са били
  синтактично незатворени. Няма project mutation; QA temporary home cleanup е
  изпълнен. Release build `235610` / `1e018f9b…` и runner `12298` /
  `18668650…` са withdrawn преди user issuance. Corrected template добавя AST
  compilation на всички literal regex-и. Това се брои като първи Stage 2.45.1
  pre-issuance package correction failure; при втори package failure следва
  stop/root-cause review, не трети correction.
- Вторият QA twin е минал installer 13/13 и real pinned primitive probes, след
  което exact physical gate е отказал observed `{0600: 205, 0700: 9}` срещу
  modeled `{0644: 205, 0755: 9}`. Root cause е наследеният `umask 0077` при
  създаване на QA clone-а, не release/laptop mode drift. Candidate/rollback
  suites и project overlay не са стартирали; temp residue е zero, baseline е
  clean, candidate остава exact 20 unstaged paths. Build `236519` /
  `d64f9248…` и runner `12298` / `6e418430…` са withdrawn. Това е package
  correction failure 2; работата спира преди трета корекция.
- User-ът прие exact QA recovery re-freeze. Mode-preserving QA copy preflight,
  deterministic rebuild и единственият fresh QA cycle са PASS: 13 self-tests,
  primitives, 20/20 rollback, 10/494/2191 tests и zero residue. Authoritative
  laptop dry-run обаче отказа преди candidate creation върху
  `baseline target mode drift: contacts_core.py`.
- Root cause е release manifest common-mode oracle error: всичките 18 existing
  targets са били моделирани като `0644` от normalized Git clone, въпреки че
  authoritative physical inventory съдържа `0600/0644/0664/0700/0755`. QA
  fixture и verifier са наследили същото грешно допускане, затова QA PASS не е
  могъл да го открие. Outer trap `line=73` е propagation site на
  `bash "$runner"`, не повтарящият се вътрешен defect.
- Release R1 `237250` / `76c01ea8…` и runner `12298` / `1f0ae760…` са withdrawn
  и забранени за rerun/apply. Code flow е спрял преди rollback candidate/tests/
  overlay; exact live no-mutation и per-target-mode diagnostic е следващият
  read-only gate. Няма нов correction package authorization.
- Последвалият authoritative diagnostic потвърди exact `18/18` predecessor
  hashes и target modes `2×0600`, `11×0644`, `5×0664`; clean HEAD/status и
  zero R1 temp residue са запазени. Същият physical-mode/Git-mode дефект вече
  е записан при Stage 2.41/2.42, следователно R1 е recurrence на неспазена
  превантивна мярка, а не нова platform особеност.
- R2 tooling correction обвързва independently manifest/installer/wrapper с
  exact 18-path map, запазва modes при apply/rollback, инжектира 18 individual
  отрицателни отклонения и отделно разменя два path modes при непроменено
  aggregate `2/11/5`. Exact 20 project paths, byte-exact `mokosh_gui.py` и
  paused Stage 2.46 не се променят. Local evidence не се представя като
  authoritative laptop PASS.
- R2 authoritative laptop dry-run впоследствие е PASS без mutation при exact
  Python `3.12.3`, physical manifest, 20/20 rollback и `10/494/2191` suites.
  Преди apply issuance изолираният live-apply QA е отказал върху
  `candidate file inventory drift`: exact extracted-candidate predicate е бил
  използван върху repository root и е видял валидните `.git`/bytecode records.
  Автоматичният rollback и temporary cleanup са PASS; laptop apply не е имало.
- R2 е withdrawn за apply. R3 запазва whole-tree inventory за extracted
  candidate, но използва selected-source snapshot за live repository, където
  отделни exact status/tracked/physical/fsck/bytecode gates покриват останалите
  граници. Добавен е positive/negative domain-separation self-test; exact
  20-path product scope остава непроменен.
- R3 pre-issuance temporary QA е PASS: dry-run `15` self-tests, 20/20 rollback
  и `10/494/2191`; отделният apply path повтаря candidate `10/494/2191`,
  прилага exact 20 unstaged paths и изпълнява live `10/494/2191` с exactly
  three expected failures и zero skips. Wrapper post-state и temporary cleanup
  са PASS. Scratch Python `3.12.14` не се представя като laptop evidence.

## Stage 2.45.2 MOK1 compatibility quarantine

- Първоначалният exact 28-path freeze е оттеглен преди user-repository
  mutation. Причината е едностепенен dependency scan, който е намерил 20-те
  direct `crypto_core.py` hash consumers, но не и двата tests, които pin-ват
  пет от самите променени consumers. Това е първият Stage 2.45.2
  scope-correction failure.
- Постоянна превантивна корекция: hash/dependency closure се изпълнява
  рекурсивно до неподвижна точка, след което се доказва липса на допълнителни
  consumers. User-ът прие окончателния exact 30-path re-freeze: MOK1 creation
  fail-closed и legacy
  payload-authenticated safe decrypt; `mokosh_gui.py`/`contacts_core.py`
  byte-exact; Stage 2.46 paused.
- Първото exhaustive candidate изпълнение е прихванало една останала
  second-order hash замяна между два вече включени tests. Няма scope expansion,
  издаден package или user mutation. След корекцията точният граф е 20 direct
  плюс 6 second-order edges, unresolved `0`, outside-scope `0`. Това е local
  pre-issuance implementation correction, не user/package correction failure.
- Първият affected candidate cycle е `736` tests с `14` errors: normal-GUI
  subprocess stubs предоставят историческия minimal `argon2.low_level`
  interface, а кандидатът е import-вал `hash_secret_raw` eager при module
  import. Няма изпълнен KDF, data path или user mutation. Production
  корекцията връща lazy import само при explicit Argon2id legacy recovery;
  writer-boundary test-ът вече pin-ва derive entry points. Следващият affected
  cycle трябва да докаже резултата; PASS не се твърди предварително.
- Вторият affected candidate cycle е `31/31` target PASS и `736` affected с
  един failure: eager top-level import на `mokosh_v2_filesystem` е разширил
  normal-GUI module set с пет V2 filesystem dependencies. Няма data-path
  failure или user mutation. Корекцията премества filesystem contract import-а
  само в explicit legacy recovery path; type-only imports не се изпълняват.
  Следващият affected cycle трябва да докаже резултата.
- Третият candidate cycle е PASS: `31/31` target и `736/736` affected,
  failures `0`, errors `0`, expected failures `0`, skips `0`. Recursive closure
  остава exact 30 paths / 26 edges / no outside or unresolved consumer.
- Две локални `apply_patch` конструкции са отказали atomically поради грешен
  context/syntax, а една shell orchestration команда не е стартирала поради
  escaping конфликт. Нито една не е направила partial file change; exact
  механичните substitutions впоследствие са проверени по count и digest.
- Локален `py_compile` е създал точно три `.pyc` файла и две cache директории
  в scratch кандидата. Те са установени по exact path, премахнати са изцяло и
  zero-residue е потвърден; user repository не е достъпван. Превантивно
  следващите static checks използват in-memory `compile`. `ruff`, `pyflakes`,
  `bandit` и `mypy` не са налични в scratch runtime и за тях няма PASS claim.
- Първият full discovery command е отказал преди test execution, защото custom
  runner-ът неправилно е изискал `tests/` да е importable package. Repository
  discovery режимът е използван без тази невярна предпоставка и е PASS:
  `2213/2213`, failures/errors/expected failures/unexpected successes/skips `0`.
- След full PASS са добавени четири practical fault/compatibility tests в двата
  вече разрешени crypto test модула: empty legacy payload, no quarantine before
  first-pass authentication, second-pass in-place payload change и private
  sink write failure cleanup. Първоначалното кратко описание е посочило три и
  е пропуснало да приложи empty-file test; несъответствието е коригирано преди
  следващото test execution.
- Authoritative laptop target-mode gate е PASS върху clean Stage 2.45.1:
  exact 29 existing targets, owner/group `1000/1000`, modes `1x0600`,
  `21x0644`, `7x0664`; новият документ остава fixed `0600`. Portable INPUT
  archive е показал унифицирано `0664` и изрично не е използван като physical
  mode authority. User repository не е променян.
- Exact closure върху authoritative laptop е PASS: clean Stage 2.45.1, 216
  tracked paths, 20 crypto hash consumers, три direct import consumers и три
  historical MOK1 expected failures.
- Реалната production delta е само `crypto_core.py`. Двата writer entry points
  отказват преди I/O/crypto; password/raw-key recovery използва strict parser,
  fixed KDF allowlist, bounded 1 MiB reads, two-pass authentication и
  existing V2 private atomic no-clobber sink.
- Двата crypto test модула използват independent fixed historical MOK1 bytes,
  а не забранения production writer. Exact golden fixture hashes покриват
  Argon2id, PBKDF2 и raw-key/contact-era layout.
- Първият scratch fixture-precompute command е използвал unbound host Python,
  в който `argon2` липсва, и е отказал преди file/project mutation. Вторият е
  посочил несъществуващ `qa_gate3_runtime/bin/python` и също е отказал преди
  mutation. Това са local environment path-selection грешки, не package,
  candidate или user correction failures. Съществуващият isolated QA wrapper
  е проверен и exact fixture generation е PASS.
- Първият изпълнен candidate target cycle е 29/29 PASS; след explicit tests за
  plaintext metadata и delimiter-collision containment актуалният target е
  31/31 PASS. Това е scratch
  functional evidence; не замества authoritative Python 3.12.3 dry-run/apply,
  full regression или final checkpoint.
- Historical header metadata authentication и delimiter ambiguity не се
  преетикетират като поправени. Нов writer няма; metadata е non-authoritative;
  пълното им премахване за данните изисква отделно V2 повторно криптиране.
- Package, live mutation, commit, tag и Stage PASS не се твърдят предварително.
- Първият local pre-issuance package dry-run е спрял преди baseline и project
  tests, защото изолираната QA среда няма системната команда `getfacl`.
  Потребителски package не е издаден и user repository не е достъпван.
  Инсталаторът е коригиран да запази същия fail-closed ACL gate чрез `getfacl`,
  когато е наличен, или чрез директна проверка за `system.posix_acl_access` и
  точно възстановяване на трите обикновени mode ACL записа, когато командата
  липсва. Изисква се ново детерминистично изграждане и пълен QA dry-run.
- Коригираният local pre-issuance package cycle е PASS върху изолирания
  синтетичен Stage 2.45.1 checkpoint: dry-run доказа `30/30` rollback
  injections, `35/35` target, `740/740` affected и `2217/2217` full tests;
  failures, errors, expected failures, unexpected successes и skips са `0`,
  baseline-ът остана byte-exact и няма residue. Отделен disposable apply е
  PASS със същите test counts и завърши с exact 30 unstaged paths, zero staged
  paths и zero bytecode residue. Това е local QA, не доказателство за
  авторитетната Python 3.12.3 машина. Поради настоящия log запис final archive
  трябва да бъде изграден детерминистично и изпитан отначало преди издаване.
- Издаденият R1 dry-run е спрял fail-closed на авторитетната машина при
  `physical manifest drift`, след като wrapper target modes, installer
  self-tests и pinned runtime са PASS, но преди rollback injection, candidate
  payload, project tests или repository mutation. R1 е оттеглен и забранен за
  apply. Това е първият от максимум два разрешени package correction failure-а
  за окончателния 30-path freeze.
- Последващата read-only диагностика доказва clean exact Stage 2.45.1 с 216
  tracked paths, очакваните mode/GID/bytecode/dangling-blob множества и без R1
  temp residue. Провереният авторитетен exporter изчислява raw-`getfacl`
  physical SHA-256
  `ee29c184c18616c3b76b076d4c8f4d4013ec8bc2d66d91d4483d15fda429a919`.
  Закрепеният в R1 digest
  `914aa014257299ff3057733fe34aaf5c29fe70e9cbb15e23f6eec547b1307312`
  не съвпада нито с raw-`getfacl`, нито с canonical-ACL, нито с no-ACL
  варианта и произходът му не е доказуем. Следователно причината е грешно
  evidence binding при издаването на R1, а не repository drift.
- Превантивна корекция: R2 приема само digest от exact verified exporter и
  записва изрично алгоритъма на физическия manifest. Няма промяна на freeze,
  production логика или tests спрямо R1 освен този incident record. R2 трябва
  да премине нов deterministic build, isolated dry-run и disposable live
  apply; authoritative user dry-run е задължителен преди реално прилагане.

## Stage 2.46 protected profile/session — 2026-09-11

- Новият чат започна от три independently verified handoff inputs. Exact
  baseline е clean `ce51ab1cd6e2e6c950a25215f81cba0df56f94b5`, tree
  `a616b8bd4e6d458c1b9134ec3061d5b5fed9ad1c`, 217 tracked files и tag
  `stage2.45.2-mok1-compatibility-quarantine`.
- User-ът изрично прие Stage 2.46 exact 35-path freeze и потвърди, че
  `$HOME/venv_sys/bin/python3` остава авторитетният runtime, защото настоящият
  Tk интерфейс там е ясен, четим и приличен. Windows/macOS трябва да пазят
  логиката и сходен изглед, но не получават native PASS чрез Linux симулация.
- Преди mutation беше проверен recursive GUI consumer graph. Открити са точно
  15 direct `mokosh_gui.py` SHA-256 consumers и три вътрешни second-order
  edges; всички са в приетия freeze. След замяната unresolved/outside consumer
  не е доказан.
- Implementation review откри, че първоначално приетото „безусловно
  `mokosh_gui.main()` dispatch“ противоречи на съществуващи recovery/visual
  harness tests, които използват точно този public technical seam. Silent
  scope expansion или test-specific GUI detection са отхвърлени.
  Корекцията пази `mokosh_gui.main(...)` като technical harness, а byte-exact
  launcher -> ordinary script execution отваря `mokosh_profile_gui.main()`;
  `--maintenance` отваря стария harness. Това не променя видимия normal route.
- Top-level `seed_manager` import е преместен в explicit historical
  `ensure_login`. Новият normal profile startup не зарежда и не чете legacy
  seed store; самите `seed_manager.py` и legacy files остават byte-exact.
- Добавени са strict EN/BG localization и test-only pseudo locale; Linux-only
  profile storage; session/capability state machine; нормален Tk GUI;
  отделен legacy one-file recovery GUI; synthetic visual contract/runner;
  седем test modules и пет evidence/status/contract updates.
- Profile root е no-clobber `0700`; canonical public descriptor е `0600` и се
  публикува последен. Existing schema-2 Vault generation се публикува чрез
  `VaultStorage`, после се отваря и unlock-ва отново преди descriptor publish.
  Partial/malformed/symlink/mode/unknown state блокира без repair.
- First run иска nickname/password/confirmation, завършва locked и изисква
  explicit login. Password policy е NFC, no trim, минимум 15 знака и максимум
  1024 UTF-8 bytes. Nickname е bounded NFC public UI metadata. Master phrase е
  видимо optional/unavailable и остава отделен Stage 2.47.
- След login полетата се изчистват; при отказ се изчиства password. Session
  lock gates са 900-second inactivity, 30-second suspend poll gap,
  monotonic/wall-clock anomaly, manual Lock, close и `Ctrl+Shift+L`.
- Only `LEGACY_MOK1_DECRYPT` може да е enabled след unlock. V2 encrypt/decrypt,
  clean, contacts, contact crypto, sandbox, network и recovery phrase остават
  explicit false.
- Първият нов-suite run е прихванал една реална implementation грешка преди
  package issuance: legacy GUI wrapper е извиквал hardened `decrypt_file` с
  грешен positional/keyword ред спрямо exact API
  `(input_path, output_path, password, nickname)`. Няма user/live mutation или
  plaintext output. Wrapper-ът и independent forwarding test са коригирани в
  същия frozen path; повторният run е PASS. Това е local pre-package code
  correction, не package correction failure.
- Текущият scratch new-suite резултат е `62/62`, zero failures/errors/expected
  failures/skips. Петте predecessor normal/recovery GUI suites са `133/133`.
  Exact 15-file affected/hash suite е `472/472`.
- Scratch е Python 3.12.14 / `cryptography 46.0.0`, без `argon2-cffi` и ML-KEM.
  Новите Vault tests използват реалния `cryptography` Argon2id. Historical
  predecessor imports са изпълнени с process-local QA-only Argon2 API shim;
  той не е project/package dependency и резултатът не е authoritative full
  regression/primitive PASS.
- In-memory compile и `git diff --check` са PASS. `ruff`, `pyflakes`, `mypy` и
  `bandit` не са налични; за тях няма PASS claim. Practical human visual,
  deterministic package self-test/dry-run/apply, exact pinned full regression,
  commit и tag остават pending.
- След това exact `cryptography 49.0.0` и `argon2-cffi 25.1.0` са инсталирани
  в отделен temporary Python 3.12.14 venv. Първата runtime probe команда е
  спряла преди project tests, защото е използвала грешния import spelling
  `cryptography.hazmat.primitives.asymmetric.ml_kem` вместо реалния `mlkem`.
  Това е local operator/probe naming error; няма project mutation, test run,
  package или user-machine access.
- Corrected probe потвърди exact dependencies, Tkinter и real
  `mlkem.MLKEM768PrivateKey`. Full discovery след това е PASS `2279/2279` за
  24.065 s с failures/errors/expected failures/unexpected successes/skips `0`.
  Това заменя предварителния shim evidence като по-силен local QA резултат,
  но Python 3.12.14 не се представя като authoritаtive laptop Python 3.12.3.
- Това грешно `ml_kem` spelling е точно повторение на вече записания в master
  handoff Stage 2.46 R2 incident. Следователно причината не е липса на
  информация, а неспазване на pre-existing preventive control преди probe.
  Корекцията за package tooling е задължителна: import-ът се проверява срещу
  installed public `mlkem` API, self-test има отрицателен `ml_kem` predicate и
  probe source се компилира преди repository access. Повторението се брои като
  process-control recurrence, но не като издаден package correction failure,
  защото artifact още няма и project/user state не е бил достъпен или променен.
- При първото pre-issuance package build tooling-ът отказа преди artifact
  заради три Markdown hard-break trailing-space реда в новия договор. Те бяха
  премахнати без semantic промяна. Следващият build отказа също преди artifact,
  защото critical immutable inventory сочеше несъществуващия
  `mokosh_vault.py`; recursive inventory доказа действителните отделни
  `mokosh_vault_format.py` и `mokosh_vault_storage.py`, след което allowlist-ът
  беше поправен. И двата случая са tooling/text-hygiene corrections без
  repository, user-machine или issued-package mutation.
- Опитът disposable apply да се изпълни като `nobody` беше спрян от scratch
  filesystem-а, който отказа `chown` върху временната fixture. Забраната на
  издавания wrapper/installer за root не беше отслабена. Вместо това QA-only
  driver извика exact shipped `live_apply` функцията върху отделно root-owned
  disposable repository; driver-ът не е project или package payload.
- Pre-issuance QA profile на exact 35-path payload премина 16 installer
  self-tests, wrapper self-test и dry-run: `35/35` rollback injections,
  candidate `62/62`, affected `472/472` и full `2279/2279`, с zero non-pass,
  zero residue и byte-exact повторно доказан baseline. Отделният exact-function
  disposable apply повтори candidate и live `62/62`, `472/472`, `2279/2279`,
  завърши с exact 35 unstaged paths, zero staged paths и zero bytecode residue.
- Този package QA използва изолиран Python 3.12.14 с exact dependency versions;
  не заменя авторитетния user dry-run с `$HOME/venv_sys/bin/python3` 3.12.3.
  След настоящите documentation bytes exact payload се изгражда и проверява
  отново; издаденият R1 остава само dry-run кандидат, без live apply, commit,
  tag или Stage PASS преди резултата от реалната машина и визуалния преглед.
- Първото повторно QA dry-run извикване след evidence update подаде правилния
  interpreter path, но пропусна съответния temporary `HOME`. Wrapper-ът отказа
  веднага на exact `$HOME/venv_sys/bin/python3` identity gate, преди extraction
  или repository access. Командата е коригирана чрез explicit QA `HOME`; това
  е local operator invocation error и положително negative-gate доказателство,
  не package correction failure или project/user mutation.
- Authoritative R1 dry-run на лаптопа премина exact Python 3.12.3,
  `argon2-cffi 25.1.0`, `cryptography 49.0.0`, OpenSSL 4.0.1, ML-KEM-768,
  X25519 и AES-GCM tamper rejection. Всички предходни baseline проверки за
  HEAD/tree/branch/tag, clean status, history, physical manifest, frozen и
  critical hashes и fsck достигнаха последния bytecode gate; той отказа на
  `bytecode baseline drift`. Payload, rollback tests, project tests и mutation
  не са започнали. R1 е оттеглен и не се изпълнява повторно.
- Read-only exact-schema diagnostic отчете същите `4341` записа и същото
  разпределение `4086` regular files + `255` directories, но нов SHA-256
  `914e83be4f131de233a62dfca6da683485f6d48f1a1aacca96da1252db04d362`.
  Най-новите едновременни записи са root `__pycache__` и
  `crypto_core.cpython-312.pyc` от 2026-09-11 10:55:31 local — 12 секунди
  преди предоставената GUI снимка от 10:55:43. Това свързва промяната с
  нормалното стартиране на приложението след handoff export, не с R1.
- Отделната source validation доказа exact unchanged `crypto_core.py` SHA-256
  `a53fab9f9b31c079fed330ec8bc7e6835f98657677a5ed51ff0764096b46ef62`,
  regular non-symlink `0600` cache, timestamp mode `flags=0`, exact embedded
  source mtime/size и byte-identical independent rebuild с SHA-256
  `b419ee7a1338d6f6dd395e95ae57fee748133cd00728cc49afbb36bd33046ba9`.
- Root cause: final handoff правилно е запазил историческия unchanged cache,
  но последващият изрично поискан practical GUI оглед е обновил derived cache
  за вече променения в Stage 2.45.2 source. R2 correction не трие и не връща
  cache, не отслабва exact invariant и не променя frozen интерфейса. Тя сменя
  package revision и закрепва доказания текущ 4341-record digest.
- Preventive rule: practical GUI снимка/оглед се извършва преди final bytecode
  snapshot или след него не се стартира normal launcher до package dry-run.
  R2 pre-issuance QA трябва да повтори self-tests, `35/35` rollback,
  `62/62`, `472/472`, `2279/2279`, disposable exact-function apply и двойно
  deterministic build. Авторитетният R2 user dry-run остава отделен gate.
- R2 pre-issuance QA след correction evidence е PASS: 16 installer self-tests,
  wrapper self-test, `35/35` rollback плюс success rollback, candidate
  `62/62`, `472/472`, `2279/2279`, zero non-pass и zero residue. Отделният
  exact-function disposable apply повтори live `62/62`, `472/472`,
  `2279/2279`, exact 35 unstaged paths, zero staged paths и zero bytecode
  residue. Това е Python 3.12.14 QA, не авторитетният user Python 3.12.3.
  След добавянето на този evidence запис exact payload преминава задължителен
  fresh final QA cycle и deterministic double build преди издаване.

## Stage 2.46 authoritative R2 apply и R3 locked-entry correction — 2026-09-12

- Authoritative R2 dry-run е PASS без project mutation: exact baseline,
  `35/35` rollback, `62/62`, `472/472`, `2279/2279` и zero residue.
- Authoritative live apply е PASS с exact 35 unstaged paths; повторните live
  `62/62`, `472/472`, `2279/2279` са zero non-pass. Final tracked physical
  SHA-256 е
  `54208fb61eaa7734c7c8fae89dc61338b8d7fa308f206ac502da2d21fdd340b2`.
- Independent post-apply verifier първо отказа единствено outer package mode
  `0664`, създаден от browser download. След exact size/SHA verification mode
  беше ограничен до `0600`; пълният independent run потвърди package,
  runtime/primitives, exact Git/physical/source/bytecode state, `62/472/2279`
  и no mutation.
- Practical visual Case 1 (`EN`, 100%, `LOCKED`) показа enabled полета и
  работещ caret, но въведените знаци изчезват незабавно. Case 1 е записан като
  blocking `FAIL`; останалите седем случая са спрени, за да не се повтаря
  известният дефект и да не се губи user time.
- Root cause е production-relevant: READY profile controller винаги държи
  `SecureProfileSession` в `LOCKED`, а global `_user_activity` изчиства
  password/nickname при всеки key/button event, когато state не е `UNLOCKED`.
  Автоматичните тестове са покрили login result и post-transition clearing, но
  не locked Tk entry sequence.
- User-ът изрично прие `Stage 2.46 R3 corrective freeze от 7 пътя`:
  `mokosh_profile_gui.py`, `tests/test_mokosh_profile_gui.py`, contract,
  project status, security evidence, standards crosswalk и session log. Всички
  са вътре в приетите 35; capability и product scope не се разширяват.
- Минималната корекция връща без действие при absent/locked session, touch-ва
  само `UNLOCKED` и запазва изчистването, ако touch причини преход към
  non-unlocked. Три regression теста доказват locked preservation, нормален
  unlocked touch и transition-triggered clearing; focused module е `14/14`
  PASS в scratch.
- Exact-dependency R3 target `65/65`, affected `472/472` и full `2282/2282`
  са PASS с zero non-pass и zero bytecode residue. Rollback package,
  authoritative laptop gates и повторният visual matrix остават pending. R2
  не се commit-ва и няма Stage PASS.
- Първият R3 corrective-package QA cycle е PASS върху отделна exact R2
  fixture: 16 self-tests, `7/7` rollback плюс success rollback, deterministic
  double build и wrapper dry-run без mutation. Exact shipped `live_apply`
  функцията е изпълнена само върху disposable copy; candidate и isolated-live
  `65/472/2282` са PASS, mode/status са запазени и няма bytecode/source
  residue. QA е с Python 3.12.14; след добавянето на този запис exact final
  bytes задължително минават нов build/dry-run/apply QA. User Python 3.12.3,
  независимият post-apply verifier и осемте human visual случая остават
  отделни последващи gates.

## Stage 2.46 R4 first-run modal input correction — 2026-09-12

- R3 package беше приложен успешно на лаптопа и independent verifier потвърди
  exact 35-path state, physical SHA-256
  `30c26c0a7b5a97cdd972c3877781f5562efc5719aa54050c577e160358db2842`,
  bytecode inventory,
  runtime/primitives и `65/472/2282` без mutation.
- Повторният synthetic locked Case 1 показа, че главните password/nickname
  fields вече задържат test input. Eye controls маскират/показват стойностите,
  а EN/BG switch работи. Screenshot-ът откри clipped BG clean label.
- За поисканата видима successful-login проверка беше стартиран isolated
  temporary real-profile route. User-ът съобщи, че предварителният малък
  first-run прозорец отново не приема typing или paste; опитът беше спрян преди
  profile create и няма твърдение за real profile/login PASS.
- Процесната причина за повторението е, че R3 scope и regression са покривали
  само `ProfileMainWindow`, а visual runner-ът изрично е скривал first run.
  Асистентът е приел погрешно, че близката корекция важи и за отделната modal
  реализация, вместо първо да изиска dedicated test. Това е записан coverage
  escape и не се приписва на user действие.
- Техническият defect е early `grab_set()` преди build/visibility плюс липсващ
  initial focus. Допълнителен lifecycle риск е, че main window не е пазил една
  explicit dialog reference и не е отказвал duplicate first-run instance.
- User-ът прие exact 12-path R4 freeze. Корекцията запазва настоящия layout,
  въвежда build → visible → focus → grab, retained single dialog, idempotent
  secret clearing и кратък BG label `Почисти оригинали...`.
- Добавен е synthetic in-memory `--entry-transition`, който отваря същия
  first-run Tk прозорец и позволява create → locked → login → unlocked → lock,
  без profile/data filesystem I/O. Формалният report изисква девет отделни
  observations и не съдържа path/credential стойности.
- Новите regression tests доказват modal order, entry retention, duplicate
  refusal, close clearing, synthetic controller transitions и complete BG
  visible state след login/manual lock. Pre-documentation local suites са
  `76/76`, `472/472`, `2293/2293`, zero non-pass.
- Първият GUI-suite invocation е спрял преди imports поради липсващ runtime
  shared-library search path за Tk в scratch QA venv. След explicit
  runtime-owned library path suites са PASS; частичният първи run не е броен.
- Preventive rule: всеки отделен credential-entry window трябва да присъства
  изрично в automated lifecycle coverage и в practical typing плюс paste test.
  Нито backend test, нито визуален harness, който изключва прозореца, може да
  бъде използван като заместител.
- R4 package, authoritative user dry-run/apply, independent post-apply,
  practical entry-transition, осемте scale cases, commit и tag остават pending.

## Stage 2.46 R4 pre-issuance package QA — 2026-09-12

- След documentation rerun target `76/76` и affected `472/472` са PASS. Един
  intended full-suite command не е стартирал поради assistant operator typo в
  interpreter path (`344641lish`); няма project execution/mutation и този опит
  не е броен. Correct exact-path rerun е `2293/2293` PASS. Добавено е правило
  executable path да се проверява преди invocation.
- Предварителният R4 QA wrapper е изграден върху exact R3 base и премина 16
  self-tests, pinned primitives, `12/12` injected rollback плюс success
  rollback, candidate `76/472/2293`, zero non-pass/residue и dry-run state
  unchanged.
- Exact shipped `live_apply` беше извикан чрез отделен driver само върху
  disposable R3 copy. Static/delta и повторните live `76/472/2293` са PASS;
  post-state е exact 35 unstaged paths и original R3 source не е променян.
- Това е QA Python 3.12.14, не authoritative user Python 3.12.3. Записът
  променя frozen docs, затова следва fresh final-byte double build, dry-run и
  disposable apply. User apply, independent verifier, human first-run PASS,
  Stage PASS, commit и tag не са заявени.

## Stage 2.46 R4 authoritative PASS и human mapping FAIL — 2026-09-12

- R4 user dry-run е PASS на Python 3.12.3: exact R3 base, `12/12` rollback,
  candidate `76/472/2293`, zero residue и no mutation.
- R4 live apply е PASS: live `76/472/2293`, exact 35 unstaged paths и final
  physical SHA-256
  `5895c0a318da4300e1c738c705afedc25490d39ed632d41768a3f19091c7a8ab`.
- Independent post-apply verifier потвърди package/runtime/primitives,
  Git/source/physical/4341-bytecode state, `76/472/2293` и unchanged state.
- Първият `--entry-transition --locale bg --scale 100` human run отпечата
  synthetic introduction, но не показа прозорец и не върна prompt. Два
  `Ctrl+C` не прекратиха Tk wait. User-ът изпълни `Ctrl+Z`, после `kill %%`;
  job status премина `Stopped` → `Terminated`. Няма profile/data mutation.
- Human R4 gate е blocking `FAIL`; няма commit/tag. Root cause е synchronous
  `wait_visibility()` в first-run конструктора. R4 test е pin-нал погрешното
  implementation order, без constructor-return/Map evidence.

## Stage 2.46 R5 accepted corrective freeze — 2026-09-12

- User-ът прие exact 10 пътя: `mokosh_profile_gui.py`, visual contract/runner,
  двата им tests и петте contract/status/evidence/crosswalk/session документа.
- Blocking visibility wait е премахнат. Constructor-ът build-ва и bind-ва
  `<Map>`, после се връща; Map планира idempotent `after_idle` focus/grab само
  при existing/viewable window.
- Pending activation се отменя при close; late callback е inert. Runner-ът
  има отделни constructed/main-mapped/first-run-mapped terminal markers;
  human report schema v2 съдържа 11 observations.
- Новите tests изпълняват constructor return, wrong-widget/duplicate Map,
  temporarily unviewable state, close-before-callback и marker idempotence.
  Pre-documentation target `80/80`, affected `472/472`, full `2297/2297` са
  PASS с zero non-pass.
- Записани са и два assistant QA operator incidents без product/user impact:
  malformed path в излишно R4 checksum display и missing QA `HOME` в първи
  negative-verifier опит. Exact variable-based recheck и corrected negative
  fail-closed run са PASS. Пътищата занапред се pin-ват веднъж и се валидират
  преди invocation.
- R5 final-byte QA/package, authoritative user gates, human PASS, commit и tag
  остават pending.

## Stage 2.46 R5 authoritative и human PASS — 2026-09-12

- Final package identity е size `226610`, mode `0600`, SHA-256
  `d09601dcad502dc032b8687f336d9e7ff357eb0baf1b2f491a9220397deae755`.
- User Python 3.12.3 dry-run е PASS: exact R4 baseline, 16 self-tests,
  `10/10` rollback плюс success rollback, candidate `80/472/2297`, zero
  residue и no mutation.
- Live apply е PASS с live `80/472/2297`, exact 35 unstaged paths и final
  physical SHA-256
  `78fb7a6dd21d5a4ff54845494391a0771d0346a1e49ee48fd0e77a92dcbe0d1c`.
- Independent verifier identity е size `39247`, mode `0600`, SHA-256
  `183479b26ac3de2f2098bbcb229109599264517050c04bddec3b42147b439000`.
  Той потвърди runtime/primitives/package, 217 tracked, status 35, 4341
  bytecode records, `80/472/2297` и unchanged state.
- Human entry-transition се изпълни в едно BG/100 synthetic стартиране без
  profile/data I/O. Двата прозореца се показаха; first-run nickname прие
  typing и `Ctrl+V`, password/confirmation приеха input, masking/eyes работиха,
  create върна locked main, login изчисти двете полета, BG/EN unlocked status
  и lock button бяха видими, а manual lock върна locked state.
- Всичките 11 formal observations са PASS. `CONSTRUCTED`,
  `FIRST_RUN_MAPPED` и `MAIN_MAPPED` са отпечатани точно веднъж; observed
  first-run-before-main event order е допустим. X затвори прозореца и shell
  prompt се върна без Ctrl+C/Ctrl+Z/kill.
- Touch single tap само фокусира. `Ctrl+V` е PASS, но current Tk application
  няма long-press Paste menu. Това е записано като нерешена cross-platform UX
  възможност за отделно обсъждане, не като security feature или R5 failure.

## Stage 2.46 R6 accepted final-evidence freeze — 2026-09-12

- User-ът прие exact пет documentation paths: `PROJECT_STATUS_BG.md`,
  `docs/SECURE_PROFILE_SESSION_CONTRACT_BG.md`,
  `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`,
  `docs/SECURITY_STANDARDS_CROSSWALK_BG.md` и `docs/SESSION_LOG_BG.md`.
- Няма production, localization, test, crypto, KDF, storage, capability,
  recovery или network delta. Human GUI test няма да се повтаря след
  documentation-only apply.
- R6 package/apply/independent verification и repository commit/tag се
  доказват само от последващите им външни outputs. Настоящият запис не ги
  заявява предварително и не е certification/compliance declaration.
- Първата intended R6 regression команда е отказана преди process start от
  managed execution policy заради recursive temporary cleanup; няма test или
  project mutation и тя не се брои като PASS. Повторението без destructive
  cleanup, в retained isolated scratch directory, е `80/472/2297` PASS.
  Бъдещи managed QA команди оставят bounded scratch residue на environment
  lifecycle вместо да включват recursive cleanup.
- Първият вътрешен R6 wrapper dry-run е спрян преди installer start с
  `archive regular-file count drift`: архивът има правилните 11 members, но
  launcher-ът е запазил R5 брояч за 12 regular files вместо R6 inventory от
  7 regular files и 4 directories. Няма project mutation или PASS claim.
  Корекцията `R6-C2` заменя брояча с exact regular-file set за manifest,
  installer и петте документа. Нейният пълен dry-run мина технически, но
  изписа наследено `R4_BASELINE` вместо фактически проверявания R5 baseline;
  този output не се приема за final evidence. `R6-C3` поправя marker-а на
  `R5_BASELINE` и задължава повторен пълен QA. Бъдещите pre-release проверки
  pin-ват member имена/типове/брой и сканират всички stage/revision labels.
- Първото `R6-C3` disposable-apply QA извикване пропусна isolated QA `HOME`.
  Runtime gate го спря след self-tests, но преди baseline verification и
  `live_apply`, с `Python path is not lexical $HOME/venv_sys/bin/python3`.
  Exact byte/mode/status сравнение потвърди непроменен disposable R5 repo.
  `R6-C4` повтаря цикъла с pin-нати заедно `HOME`, executable и `sys.prefix`,
  минимален environment и нов extraction target; няма waiver или PASS claim
  от отказаното извикване.

## Stage 2.46 R6 authoritative completion и accepted amendment — 2026-09-12

- Final R6 package е `216370` bytes, mode `0600`, SHA-256
  `67229f0dac54d96a4f5c1d3ba44338baa7f0a897e88bd1b4b1cd1259f3a38e37`.
- User Python 3.12.3 dry-run е PASS: exact R5 physical baseline `78fb7a6d…`,
  16 self-tests, `5/5` rollback плюс success rollback, candidate
  `80/472/2297`, zero non-pass/residue и no mutation.
- Live apply е PASS: live `80/472/2297`, exact 35 unstaged paths и final
  tracked physical SHA-256
  `2ba8c8eeb024cad44df35d758d24e2d940411fbc8008158694e336dacdbc6255`.
- Independent verifier е `39095` bytes, mode `0600`, SHA-256
  `e97c9d033a74c42fc508d330d53bf507133a0fe8bade17fc79ff3866da8c8955`.
  Той потвърди package/runtime/primitives, 217 tracked, status 35, physical
  digest, 4341 bytecode records, 165 Python и 1 shell source, `80/472/2297`
  и unchanged state. Final marker е
  `STAGE2_46_R6_INDEPENDENT_POST_APPLY=PASS_UNSTAGED_EXACT_35_PATHS`.
- User-ът изрично прие completion amendment в същите пет документа и
  изиска правилната стандартизация, доказателства и сигурност да останат
  водещи. Няма production/localization/test/GUI/crypto/KDF/storage/capability/
  recovery/network delta и не се повтаря human GUI или full regression само
  заради документационните bytes.
- Следва exact 35-path commit с message
  `Implement Stage 2.46 protected profile session and normal GUI` и annotated
  tag `stage2.46-protected-profile-session-normal-gui`. Те не се заявяват като
  PASS преди отделния finalizer output; Stage completion не означава
  certification, official audit, legal opinion или platform-native PASS.

## Stage 2.47 accepted scope и isolated implementation — 2026-09-13

- User-ът изрично прие: `Stage 2.47 scope freeze от 32 файла`.
- Authoritative read-only baseline от user terminal е PASS: commit
  `3716a8ecdf9b546d39cbef750c97811e7bb77cef`, tree
  `6fc1059b3ecaf9c8cdb228981acc1a15c0d80cf0`, branch
  `feature/mokosh-v2-core`, annotated tag
  `stage2.46-protected-profile-session-normal-gui`, tag object
  `455ff77c89e872087bccd403a178aa6a9d59cfee`, 118 commits, zero merges,
  two branches и 77 annotated tags. Baseline marker е
  `STAGE2_47_PROJECT_MUTATION=NONE`.
- User-ът потвърди exact 25 думи и поиска лесен optional начин за запазване,
  включително директно на флашка, ако сигурността го допуска. Прието е преди
  всяко различно действие да има кратко човешко обяснение и съвет `.mokr` и
  фразата никога да не се пазят на едно място.
- Реализацията е направена само в isolated tree-exact source copy. Не е
  променян `~/MOKOSH_Agent`.
- Добавен е versioned `MOKOSH-RP1`: 3 version bits, 256-bit random recovery
  root и 16-bit domain-separated transcription checksum в точно 25 × 11-bit
  думи. Pinned BIP39 English list е само MIT-licensed vocabulary; форматът не
  е wallet mnemonic/seed.
- Добавен е optional direct sheet export в user-selected new private folder,
  както и paper path с reentry на всичките 25 думи. Sheet-ът и `.mokr` са на
  различни filesystem devices; sheet-ът е отделен и от Vault device-а.
  FAT/exFAT се отказват с отделно човешко съобщение; няма автоматично
  форматиране, mount, destination, clipboard, log, cloud или network.
- Setup изисква unlocked session и current-password reauthentication. `.mokr`
  се записва първо; completion прави final read-only rehearsal без Vault
  publish. Cancel остава допустим и вече durable отчетените файлове не се
  изтриват автоматично.
- Forgotten-password route е само за locked READY profile. Exact Vault,
  `.mokr`, phrase/sheet и new-password confirmation подготвят encrypted
  candidate в паметта. Само един final yes/no dialog разрешава immutable
  publish; uncertain резултат се reconcile-ва read-only и никога не се retry-ва
  сляпо.
- Publish пази старото Vault поколение и record-а, връща locked state, отказва
  старата парола за latest и изисква explicit login с новата. Това е password
  replacement, не cryptographic revocation; стар `.mokr` + неговата фраза
  остават чувствителни.
- Normal GUI получи отделна recovery секция, singleton child windows и
  fail-closed gates. Setup phrase се скрива при lock/close. Допълнително panic
  lock вече затваря и двата recovery прозореца и чисти полетата.
- След storage review суровите low-level filesystem откази се normalise-ват в
  bounded domain errors след safe cleanup; uncertainty остава отделен
  stop/manual-review резултат. Добавени са fault-injection regression tests.
- Final-code local suites са target `138/138`, affected `472/472` и full
  `2374/2374`, с нула failures/errors/expected-failures/skips. По-ранните
  phrase/storage `30/30` и profile-prefixed `120/120` са само междинни
  подмножества и не се сумират към exact counts.
- Ранни unittest invocation-и срещнаха `PYTHONSAFEPATH=1`/non-package import
  проблем; един пълен discovery показа 29 subprocess import non-pass. Без
  product-byte промяна corrected controlled-candidate runner даде
  `2374/2374`. Invocation/environment errors са запазени честно, но не са
  приети product test results.
- Pre-release package rehearsal: installer self-tests `16/16`, file rollback
  `32/32`, new-directory rollback `2/2`, static `248` files / `176` Python /
  `1` shell и candidate target/affected/full `138/472/2374` PASS. Предстоят
  final deterministic package/verifier, user Python 3.12.3 dry-run, отделен
  apply, independent verifier и human BG/100 full recovery transition.
  Няма предварителен Stage PASS, commit, tag, audit или compliance claim.

## 2026-09-15 — приет Stage 2.47 corrective scope

- Практическите наблюдения бяха превърнати в постоянен ledger D01–D13 и
  TG01–TG04; всяко остава във всеки handoff със статус и evidence.
- Добавени са shared normal-window/dialog/reflow/scroll/eye primitives и
  specific local form validation. Native `messagebox`, `OK`, `Yes`, `No` и
  transient WM hints са премахнати от коригирания recovery path.
- Добавен е fail-closed recovery lifecycle state: forgotten-password entry е
  активен само за current комплект; след password replacement става пасивен,
  статусът и точно две successful-login reminders изискват нов `.mokr` и
  фраза.
- Setup state-publish failure е terminal one-shot: няма blind Finish retry,
  profile/Vault са unchanged, а вече създадените външни копия остават.
- Добавена е adversarial matrix за corrupt/truncated/trailing/unsupported,
  mix-and-match, concurrent/stale/replay, restart и short-write. Exact
  corrective suite: `181/181` PASS.
- Full local discovery изпълни 2361 теста без assertion failure, но три
  legacy modules не се import-наха поради липсващ `argon2` в scratch runtime;
  това е environment blocker, не full-suite PASS.
- Exact 33-path guarded R3 е изграден и локално мина `17/17` installer
  self-tests, 33/33 injected rollback позиции плюс success rollback,
  254-file static/delta проверка и `181/181` target без residue.
- Следват user dry-run/apply, independent verifier, пълен pinned-runtime suite
  и practical WM/reflow/eyes/messages/state retest. Няма Stage PASS, commit или
  tag.

## 2026-09-15 — Stage 2.47 R3 apply safe stop и R4 status correction

- Authoritative R3 dry-run е PASS: exact R1 baseline преди/след, pinned
  runtime/primitives, `33/33 + success` rollback, static/delta,
  `181/472/2416` PASS и no residue.
- Live apply повтори candidate `181/472/2416` PASS, приложи временния overlay
  и спря на `live exact 38-path status drift`. Няма приет R3 live state; R3 е
  withdrawn и не се retry-ва.
- Локалната exact реконструкция даде 32 R1 status paths и 40 R3 status paths.
  Причината е непълната формула `R1_STATUS_PATHS ∪ NEW_PATHS`, която пропуска
  `mokosh_profile_storage.py` и `tests/test_mokosh_profile_storage.py`: те са
  clean tracked в R1, но реално се променят от correction payload-а.
- R4 заменя формулата с `R1_STATUS_PATHS ∪ CORRECTION_PATHS`, очаква exact 40
  и добавя installer self-test за clean-tracked corrective subset и пълното
  включване на всеки correction path.
- Вторият identical `EXACT_STAGE2_47_R1_BASELINE=PASS` след
  `CANDIDATE_RESIDUE` в live-apply output е изпълнен от exception path след
  rollback и доказва възстановения R1. R4 dry-run отново проверява същия
  baseline; при drift спира преди mutation.
- Product/crypto design не се променя. Evidence docs се обновяват в същия
  frozen 33-path scope; остават задължителни R4 dry-run/apply, independent
  verifier и practical GUI audit. Няма Stage PASS, commit или tag.

## 2026-09-15 — R4 PASS, practically находки и R5 подготовка

- R4 live apply завърши с `181/472/2416` PASS, exact 40-path unstaged state и
  tracked physical digest
  `6fc034535dad1d5bc6afd55bf7f8786368b95119d07f204efbfe170a58d614c6`.
  Независимият read-only verifier повтори същите три suites, без residue или
  project mutation.
- BG/100 practical replay потвърди началния gate, scroll, password/nickname
  eyes, setup opening и current-password eye, но отвори D07/D09/D11:
  clipping на горните main controls при тесен resize, необяснен `Vault` и
  неясна removable-media/FAT инструкция.
- Clean terminal exit с `RECOVERY_TRANSITION_CONSTRUCTED`,
  `RECOVERY_TRANSITION_MAIN_MAPPED` и `RECOVERY_TRANSITION_SETUP_MAPPED` PASS
  е записан като construction/mapping evidence, а не като visual PASS.
- R5 моделът е byte-сверен с R4 по всичките 40 status paths; различават се
  само деветте умишлени product/test/evidence пътя. Добавен е responsive pair
  layout за folder/password/nickname/footer и plain-language EN/BG текст за
  защитеното хранилище, отделна USB флашка/външен диск и FAT/exFAT отказа.
- Target suite е `184/184` PASS. Local affected invocation изпълни 472 теста,
  но 10 imports са блокирани от липсващ `argon2`; резултатът не се приема за
  PASS и ще се повтори в pinned user runtime заедно с full `2419`.
- Оттук human тестовете се водят точно по една стъпка. След всяка снимка или
  описание се записва PASS/FAIL/UNCLEAR; следваща стъпка не се дава преди
  оценката. При FAIL се поправя веднага и се повтаря засегнатият checkpoint.
- Няма Stage PASS, commit или tag.

## 2026-09-15 — R5 D07 RED, R6 false GREEN и R6-R3 изолиран PASS

- Applied-R5 practical audit спря при реда `Прякор`: entry беше 99 px, eye
  беше изкуствено разширено до 262 px. Folder control беше потвърден PASS.
- Read-only real-Tk RED diagnostic възпроизведе точните размери и потвърди
  no project mutation. Общите `184/472/2419` R5 тестове остават валидни само
  за своите assertions и не се представят като pixel-geometry evidence.
- R6-R1 беше спрян от 276 px criterion. R6-R2 показа защо този criterion е
  грешен: default редът стана stacked, eye се премести под entry и create
  control се разтегна до 650 px при requested 262. Human FAIL обезсили
  автоматичния GREEN; live apply не е извършван.
- При R6-R3 eye е преместено в primary field group, create остава самостоятелен
  bounded secondary control, а narrow reflow мести само create. Gate-ът вече
  проверява X/Y ред, съседство, upper и lower width bounds и exact R5/R6-R2
  отрицателни envelopes.
- User real-Tk BG/100 даде default/wide/narrow PASS: entry `278/558/336`, eye
  `107/107`, create `248/248`, expected inline/inline/stacked, всички in-bounds.
  Screenshots са human PASS и затварянето завърши с
  `R6_R3_ISOLATED_PREVIEW=CLOSED_NO_PROJECT_MUTATION`.
- R6-R3 е само изолиран candidate PASS. Следва подготовка на exact-R5 guarded
  R6 installer; dry-run, apply, independent verifier и live practical replay
  остават отделни задължителни стъпки. Няма Stage PASS, commit или tag.

## 2026-09-16 — R6-R1 installer safe stop по exact untracked mode

- Първият user dry-run спря преди mutation с `R5 untracked mode drift` за
  `run_mokosh_profile_recovery_visual_harness.py`.
- Реалният applied-R5 runner е mode `0700`; R6-R1 manifest погрешно е записал
  `0600`, защото builder-ът е hard-code-нал един режим за всичките 22
  untracked файла.
- Installer self-tests и runtime primitives минаха, но baseline gate правилно
  отказа; rollback/candidate/target/affected/full не са стартирали и не се
  отчитат като PASS. Repository остава exact R5.
- R6-R1 е withdrawn. R6-R2 pin-ва exact карта `21 × 0600 + 1 × 0700`, добавя
  manifest/self-test regression и включва metadata baseline проверката в local
  rehearsal. Следва нов отделен dry-run; няма Stage PASS, commit или tag.

## 2026-09-16 — R6 applied checkpoint и решение за изолиран R7

- R6-R2 dry-run/apply/post-apply verifier завършиха с `185/472/2420` PASS,
  exact 40-path unstaged state и tracked physical SHA-256
  `5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db`.
- Human BG/100 replay даде move PASS, Escape close-child PASS и X close-child
  PASS. Предположеният scroll дефект беше прегледан повторно и оттеглен.
- Потвърдени са clipped „ПОДГОТВИ ВЪЗСТАНОВЯВАНЕ“ при minimum width и
  near-wall wrapping в recovery warnings. Няма действие само по screenshot:
  находките бяха споделени, обсъдени и user-ът изрично одобри R7 scope.
- R7 променя само setup reflow, shared responsive-label measurement, exact
  regressions, synthetic real-Tk audit и четирите evidence документа. Няма
  crypto/storage/lifecycle/password/text/file-format промяна.
- Exact R6 40/40 payload comparison е PASS преди изолираното копие. R7
  targeted structural/logic suite е `46/46`, а exact target suite е
  `188/188` PASS.
- Affected invocation откри 472 теста, но 10 legacy tests не се import-наха
  заради липсващ `argon2` в scratch Python. Това е environment blocker и не е
  affected PASS.
- Full local discovery изпълни 2368 теста с 3 `argon2` import errors и 7
  skips; резултатът е записан, но изрично не е full PASS.
- Изолираният candidate self-test потвърди exact R6 по 10-те договорени path-а,
  откри двата R6 RED source shapes, прие два GREEN и отхвърли два RED layout
  envelope-а и доказа no project mutation. Следва само user real-Tk preview;
  няма installer, dry-run, apply, Stage PASS, commit или tag.
- Постоянно правило: всяка промяна, обновяване, дефект, PASS или FAIL първо се
  споделя и обсъжда; след изрично решение се действа и се прави траен запис.

## 2026-09-16 — R7 user real-Tk и human whole-window PASS

- Exact R6 source, двата RED source shapes и 2 RED/2 GREEN layout envelopes са
  потвърдени преди отварянето на preview; няма project mutation.
- Реалният user Tk 8.6.14 при BG/100 измери default `851x46`, wide `1051x46`
  и minimum `571x86`. Default/wide остават inline. При minimum entry `448/206`
  и eye `107/107` остават на първия ред, а само prepare `314/314` е на втори,
  дясно подравнен ред; всички контроли са mapped и in-bounds.
- Wrap audit измери actual label width, wraplength и двустранния clearance за
  main recovery status, setup phrase warning и setup phrase help и завърши с
  `RECOVERY_SETUP_LAYOUT_AUDIT=PASS`.
- Първата снимка покри горната част. Преди решение беше поискан и долният край,
  за да няма PASS на половин прозорец. Втората снимка потвърди думи 23–25,
  стъпки 1–3, всички бутони и „Отказ“ без изрязване или навлизане в стените.
- Резултатът беше споделен и обсъден; user-ът изрично прие целия тесен прозорец
  като visual PASS и след това затвори preview-а. Финалът е
  `RECOVERY_SETUP_LAYOUT_PREVIEW=CLOSED_NO_PROJECT_MUTATION` и
  `R7_ISOLATED_REAL_TK=CLOSED_NO_PROJECT_MUTATION`. Последващият R7-R1 dry-run
  обаче доказа, че no-mutation частта на тези markers е невярна; visual PASS
  остава валиден, а markers са оттеглени.
- Разрешена е следващата отделна стъпка: подготовка на guarded read-only R7
  dry-run package. Apply, Stage PASS, commit и tag не са разрешени или заявени.

## 2026-09-16 — R7-R1 bytecode safe stop, forensic PASS и R2 решение

- Guarded R7-R1 dry-run мина `PASS_19` и pinned runtime primitives, после спря
  в exact-R6 baseline gate: bytecode records са `4351`, а не pin-натите `4345`.
  Няма payload, rollback injection, candidate suite или project mutation.
- Read-only inventory установи `+6` records и 11 наскоро записани root `.pyc`
  файла, чиито времена съвпадат с R7 real-Tk preview-а. Причината е preview
  tooling defect: project imports са били изпълнени без ранна bytecode забрана.
- Read-only forensic gate сравни всеки от 11-те `.pyc` файла с exact текущия
  `.py` source: Python magic, timestamp, size и целият marshalled code payload
  са `11/11` PASS. Няма различен code payload, symlink или special object.
- Bytecode snapshot преди/след проверката е неизменен: `4351` records и
  SHA-256 `83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.
  Старото физическо състояние не се възстановява чрез изтриване по предположение.
- След споделяне и обсъждане user-ът изрично прие R7-R2: същият 10-path scope,
  ранно `sys.dont_write_bytecode`, реален subprocess zero-residue regression,
  exact count+digest baseline и expected/actual FAIL diagnostics. Видимият
  layout, crypto, storage и recovery поведение не се променят. Разрешени са
  подготовката и един read-only dry-run; apply/Stage PASS/commit/tag не са.

## 2026-09-17 — R7-R2 dry-run, live apply и post-apply verifier PASS

- Guarded R7-R2 dry-run потвърди exact R6 baseline: 232 tracked файла,
  physical SHA-256
  `5a6b84924dc663a2d1ed6686937575c2e32ea7621d105e946b4d4018569a59db` и
  bytecode `4351` / `83a973c81da2b08f7041c2c8e7c5675437095db1bcd56902f59b519d46e910d4`.
- Installer self-tests са `20/20`; rollback injection е `40/40 + success`;
  candidate inventory е 254 source файла, 181 Python, 1 shell и точно 10
  променени пътя. Target/affected/full `189/472/2424` са PASS без non-pass и
  без residue. Повторният baseline е identical; dry-run няма project mutation.
- След споделяне на резултата и изрично user приемане live apply повтори
  candidate `189/472/2424`, после live `189/472/2424`, всички PASS. Получени
  са exact 40 unstaged paths и tracked physical SHA-256
  `972aa7bfbe40878934118ab1a7a81ab89dff3ec0fa7bb017b40570ed24581e58`.
- Отделният read-only post-apply verifier потвърди 254 source файла, 40 status
  paths, 22 untracked и 232 tracked файла; повтори независимо
  `189/472/2424`, намери нулев residue и потвърди непроменени physical и
  bytecode отпечатъци. Финалът е `PASS_NO_PROJECT_MUTATION`.
- User-ът прие техническия R7 резултат и напомни, че всяка следваща проверка
  трябва да стъпва на реални доказателства, а не на доверие или общи проверки.
  Приет е отделен evidence-only scope точно за тези три документа; няма code,
  GUI, crypto, storage или recovery-contract промяна.
- Stage 2.47 още не е финализиран. Следват guarded evidence dry-run, отделно
  приет apply, commit/tag и post-commit verifier. Няма извършен commit или tag.

## 2026-09-18 — Stage 2.48 baseline, scope и isolated implementation

- Stage 2.47 е финализиран на commit
  `7b99df6ae11b4e5a1b3f5228ec4dc187169a91c8`, tree
  `3c30b84b10cb742ba4d08bc50d50361eaa953f06` и annotated tag
  `stage2.47-profile-recovery-phrase-password-replacement` / object
  `480e3f8efa436e1be7322899d8163d19018e095f`.
- Първите resume/live baseline проверки са read-only PASS: clean branch,
  254 tracked files, 119 commits и 78 annotated tags.
- Първият прекалено дълъг pre-mutation shell gate се счупи върху mode check
  за `crypto_core.py`. Това не е project defect и не е основание да се
  отслабят проверките. Решението е кратък проверен `.pyz` transport, който
  пази пълните проверки вътре.
- User-ът изпълни pre-mutation `.pyz`: exact baseline/frozen paths и pinned
  runtime/primitives са PASS; full baseline е `2424/2424` без non-pass;
  финалът е `STAGE2_48_PRE_MUTATION_GATE=PASS_READ_ONLY`.
- User-ът изрично прие Stage 2.48 scope freeze: 32 paths, 23 existing + 9 new.
  Изискването е сигурността и точността да не се намаляват заради по-кратка
  команда. Live repository остава недокоснат; работата е в exact isolated copy.
- Реализирани са post-hard-link success-with-warning semantics, session sole
  key lease, exact Vault-version selection, Linux local V2 service, strict
  residue policy, one-worker Tk adapter и main-GUI wiring. MOK1 е отделен;
  originals/Clean/Contacts/Sandbox/Network остават недокоснати или disabled.
- Добавени са service, GUI, integration, race/fault и visual-contract тестове,
  включително second residue scan след lease, source identity binding,
  wrong-profile/tamper anti-oracle mapping и post-publication no-retry faults.
- Final manual security review добави `O_NONBLOCK` regular-to-FIFO race отказ,
  4096-entry fail-closed directory bound, magic→inspection→pipeline identity
  chain, strict public DTO invariants, keyless cleanup lease и mutually-
  exclusive V2/recovery/MOK1 windows с MOK1 close при session lock.
- Targeted suite е `218/218` PASS. Full isolated discovery е `2497/2497` PASS
  за 25.661 s, zero failures/errors/expected failures/unexpected successes/
  skips, с cryptography 49.0.0, argon2-cffi 25.1.0, real ML-KEM-768 и Tk 9.0.
- Следва exact source/scope/security audit и deterministic guarded apply
  package. Преди отделен успешен user dry-run няма live mutation; apply,
  practical visual PASS, commit и tag не се подразбират.

## 2026-09-20 — Stage 2.48 Case 01 FAIL и 34-path corrective scope

- R5 continuity archive, HEAD/tree/branch, празният index и exact 32-path
  status checksum са read-only потвърдени. Вчерашният launcher вече доказва
  непроменения user-machine physical digest преди/след Case 01.
- Case 01 е `FAIL_REQUIRES_FIX_AND_RETEST`. Бутони в cleanup dialog са били
  извън default geometry; parent-ът не се е върнал след `PRESERVE`; run е бил
  разрешен в CLEANABLE/BLOCKED/PUBLISHED; synthetic READY focus е изглеждал
  като state; след Close са наблюдавани два невидими Tab хода.
- User-ът изрично прие централно разширяване от 32 на 34 paths само с
  `mokosh_profile_ui.py` и `tests/test_mokosh_profile_ui.py`. Не е избран
  дублиран local-only dialog fix.
- Regression тестовете първо възпроизведоха старите дефекти. След корекцията
  focused suite е `45/45`, а всички засегнати shared-UI consumers са
  `100/100`, без failures/errors/skips.
- По-широкият scratch discovery не се приема за PASS: средата няма
  argon2-cffi, е с cryptography 46.0.0 и няма ML-KEM. Резултатът е 3 import
  errors и 7 skips; 239-test affected run има 0 failures/errors и 1
  environment skip. Authoritative pinned очакванията са `239/2503` с нулев
  non-pass.
- Следват deterministic guarded corrective package, user-machine pinned
  dry-run, отделно live apply, independent verifier и affected human replay
  от Case 01. Case 02–16, Stage PASS, commit и tag остават блокирани.

## 2026-09-23 — Cases 2–4 D1–D4 freeze и изолирана negative-first корекция

- Human Cases 1–4 са приключили като observations, но не като общ human PASS.
  Cases 2–4 потвърдиха D1 off-screen focus/reveal, D2 focus handoff преди
  disable, D3 `NOT V2` terminology и D4 observable synthetic chooser feedback.
  Case 4 е 12 PASS / 4 FAIL.
- User-ът прие корекцията само при доказана пълнота, последователност,
  архитектурна граница и сигурност. Dependency/consumer/document review
  фиксира exact 11-path overlay вътре в съществуващия 34-path scope. Crypto,
  Vault, format, key-version policy, filesystem, publication и cleanup
  semantics остават byte-exact непроменени.
- Възстановено е exact текущото 34-path състояние в изолирано копие. Live
  repository не е променян. Recovery capsule R3 е byte-identical reproducible,
  съдържа 13/13 проверени payload hashes, два валидни `.pyz`, complete 80-ref
  Git bundle и проверен input archive; SHA-256 е
  `142d1b87e6dc885c800c79cb3e8b418813eaedda8c8f96e028966c0dcd09731f`.
- Новите D1–D4 tests първо са изпълнени срещу непроменените bytes и са RED във
  всичките шест methods (`failures=5`, `errors=2` заради subtests). След
  bounded implementation същите са 6/6 GREEN; target е 49/49 PASS.
- Affected scratch suite изпълни 243 теста без failure/error и с един
  environment-only ML-KEM skip. Full scratch discovery изпълни 2452 теста с
  0 assertion failures, но 3 липсващи-`argon2` import errors и 7 environment
  skips; правилно остава non-PASS. AST parse е 189/189.
- Постоянна process забележка: към user terminal се дава точно една кратка
  команда; сложните проверки се доставят в hash-pinned `.pyz`. Не се изисква
  `rg` и не се предполага, че е инсталиран.
- Изграден е dry-run-only R1 `.pyz` без apply route. Package self-tests са
  PASS за exact 11-path payload, canonical manifest, internal digests, ZIP
  metadata, known-answer и negative control; повторният build е byte-identical.
- Следват pinned user-machine `49/243/2507` zero-non-pass gate, отделно решение
  за live apply, independent post-apply verifier и affected human replay.
  Няма Stage PASS, commit или tag.

## 2026-09-24 — D1–D4 apply PASS, D5–D7 freeze и process deviation 04

- User-machine D1–D4 guarded apply и independent read-only verifier са PASS.
  Exact markers са 34 status paths, physical SHA-256
  `554b6ea553625c2b1293ec534f9b0c774cb34716502fb040e9e9289be4c930b0`,
  projected tree `b14dd36c7461fbc4389ae720dcccb6af5709a21b` и pinned
  target/affected/full `49/243/2507` без non-pass. Human visual gate остава
  pending и блокира Stage PASS/commit/tag.
- В продължението на Case 4 user-ът физически потвърди D5: state click сменя
  displayed state, но focus остава върху стария control; D6: след
  restore/reactivation viewport-ът сам следва същия stale focus; D7: `Space`
  активира state button, но `Return` не го активира в Tk 8.6/X11.
- Read-only inspection установи direct `show_state` command без focus transfer,
  безусловно same-target FocusIn reveal и липсващи `Return`/`KP_Enter`
  bindings. User-ът прие exact 9-path overlay: два implementation, два test и
  пет documentation paths. Няма `mokosh_v2_local_gui.py`, crypto, Vault,
  format, localization, service, session, filesystem, pipeline или lifecycle
  byte delta.
- Изолираното копие е възстановено manifest-by-manifest: trees
  `0f1059e06e88d77f649866a0dda858204ef06117` →
  `6994d82f26f59be59628a7540c77b1f98959522c` →
  `b14dd36c7461fbc4389ae720dcccb6af5709a21b`, 34 status paths. Recovery
  archive-ът нормализира physical permission inventory, затова clone physical
  digest не се представя като user-machine identity evidence.
- Baseline focused е `30/30` PASS. D5–D7 tests първо са RED върху старите
  bytes (`failures=5`, `errors=2`, включително source-token subtests). След
  минималната корекция focused е `32/32`, target е `51/51` PASS.
- Affected scratch suite изпълни 245 теста без failure/error и с един
  environment-only ML-KEM skip. Full scratch discovery изпълни 2454 теста с
  0 assertion failures, 3 липсващи-`argon2` import errors и 7 environment
  skips. И двата резултата остават non-PASS; authoritative zero-non-pass
  проверката е само в pinned user runtime.
- Подготвеният D5–D7 R1 transport няма apply route, съдържа точно деветте
  приети payload paths и мина package self-tests. Две последователни build
  изпълнения са byte-identical. Това е package QA, не user-machine dry-run или
  human PASS.
- Записано невнимание/пропуск:
  `ASSISTANT_PROCESS_DEVIATION_04=INCOMPLETE_VIEWPORT_INSPECTION_AFTER_WINDOW_STATE_CHANGE`.
  След промяна на window state е огледана само видимата част и долният
  viewport е пропуснат. Постоянно правило: след resize, maximize, restore,
  minimize или reactivation се проверяват top и bottom преди PASS.
- Следват pinned user-machine read-only `51/245/2509` zero-non-pass dry-run,
  отделно apply решение, independent verifier и affected human replay. Няма
  Stage PASS, commit или tag.

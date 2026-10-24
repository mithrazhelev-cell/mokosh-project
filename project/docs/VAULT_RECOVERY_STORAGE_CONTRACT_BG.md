# MOKOSH — Durable Offline Recovery Export и Read-only Import Contract

Статус: Stage 2.5 — реализиран POSIX filesystem core без GUI и без actual
recovery publish.

Този договор интегрира Stage 2.4 recovery record с exact latest durable
Stage 2.2 Vault generation. Той записва само криптирания recovery record и
проверява неговото четене. Не записва recovery ключа.

## 1. Смисъл за потребителя

Stage 2.5 позволява на бъдещия service layer да:

1. докаже, че отключеният Vault е exact latest durable generation;
2. създаде Stage 2.4 recovery record и отделен recovery ключ;
3. запише само криптирания record в изрично избрана private директория;
4. прочете record-а обратно и направи read-only rehearsal срещу exact current
   Vault.

Recovery ключът остава отделна in-memory стойност. Няма функция за запис на
ключа, няма автоматично второ копие и няма „удобен“ общ package с record-а.

Потребителят трябва по-късно да постави record-а и recovery ключа върху
отделни offline носители. Ако нападател получи и двете, той може да отвори
record-а и да получи целия Vault keyring.

## 2. Trust boundary

Договорът изисква:

- некомпрометиран текущ процес и операционна система;
- current-user ownership;
- filesystem с надеждни POSIX `0700`, `0600`, `O_NOFOLLOW`, `O_EXCL`, file
  `fsync` и directory `fsync` semantics;
- private recovery директория, избрана изрично от caller-а;
- exact durable `VaultGenerationReceipt` от Stage 2.2;
- чист, complete и contiguous read-only Vault storage scan;
- unlocked и unexpired schema-2 `VaultSession`, чиито exact bytes съвпадат с
  latest receipt.

Ако носителят не може да докаже тези свойства, export-ът отказва. Няма тихо
понижаване към по-слаби permissions или недоказана durability.

## 3. Какво кодът не може да докаже

Filesystem device number, mount path или име на директория не доказват, че
носителят е физически отделен, изключен от мрежа или съхраняван на безопасно
място. Stage 2.5 отказва export вътре в самата Vault storage директория, но
физическата separation остава потребителска и бъдеща GUI responsibility.

POSIX core може да не работи върху FAT, exFAT или друга removable filesystem,
която не предоставя exact private modes и directory `fsync`. Това е изрично
ограничение, а не причина контролите да бъдат пропуснати. Бъдещи Windows и
macOS adapters трябва да имат отделни platform contracts и fault tests.

## 4. Threat model

Stage 2.5 отказва:

- forged, stale или non-latest Vault receipt;
- incomplete scan, revision gap, mixed Vault history, temporary или unknown
  object в Vault storage;
- session, която е locked, expired или не съвпада byte-for-byte с receipt-а;
- recovery setup за друг Vault, revision или source hash;
- wrong recovery key и authenticated record tamper;
- symlink в directory или file path;
- non-regular recovery target;
- hard-linked recovery file;
- owner, mode или link-count mismatch;
- existing target и target, създаден в race;
- inode/directory replacement преди или по време на операцията;
- truncated, trailing, oversized, malformed или non-canonical record;
- canonical filename, който не съвпада с authenticated Recovery ID;
- Vault или recovery file, променен по време на rehearsal;
- недостъпни `pread`, exclusive create или `fsync` semantics.

## 5. Canonical filename

Record filename е:

`mokosh-vault-recovery-<32 lowercase hex Recovery ID>.mokr`

Recovery ID е публичната 16-byte стойност от authenticated Stage 2.4 header.
Filename не съдържа recovery ключ, wrapping key, password, Vault path или име
на потребителя.

Extension `*.mokr` е private runtime artifact и е изключен от Git.

## 6. Exact latest durable доказателство

`_verified_latest_vault` приема само real `VaultStorage` и
`VaultGenerationReceipt`.

За всяко доказателство се изисква:

1. bounded `scan()` е complete;
2. report няма conflict;
3. има поне едно поколение;
4. последният exact receipt е подаденият receipt;
5. `verify_receipt()` връща exact encoded Vault bytes;
6. втори scan има същата generation tuple и същия latest receipt.

Unknown object, temporary, invalid generation, gap, mixed Vault ID, inode
change или digest mismatch прекратяват операцията.

Receipt е локално доказателство за exact durable state, но не е независим
anti-rollback anchor срещу пълен rollback на директорията и всички receipts.

## 7. Preparation contract

`prepare_recovery_export(storage, latest, session)`:

1. доказва exact latest durable Vault;
2. доказва unlocked, unexpired session със същите exact bytes;
3. извиква Stage 2.4 `create_recovery_record`;
4. проверява session-а отново;
5. доказва storage state отново;
6. изпълнява in-memory rehearsal на резултата;
7. връща Stage 2.4 `VaultRecoverySetup`.

На този етап няма path I/O. Ако Vault state се промени, setup не се връща.
Recovery root не се извежда от password и не се изпраща към storage API.

## 8. Export contract

`export_recovery_record(setup, storage, latest, directory)` приема вече
върнатия setup, така че caller-ът продължава да държи recovery ключа дори при
I/O fault или uncertain result.

Преди create операцията:

- latest durable Vault се доказва отново;
- setup metadata и encrypted record се сравняват;
- full in-memory rehearsal доказва recovery key и exact Vault binding;
- record size се проверява срещу Stage 2.4 maximum;
- directory path се отваря чрез exact descriptor и `O_NOFOLLOW`;
- directory трябва да е owner=current user и mode точно `0700`;
- directory inode не може да е Vault storage inode;
- target absence и directory durability се проверяват.

Final file се създава директно с descriptor-relative `O_CREAT | O_EXCL`, mode
`0600` и canonical filename. Никога не се overwrite-ва existing object.

След create:

1. mode и owner се проверяват;
2. exact record се записва чрез bounded writes;
3. file descriptor се `fsync`-ва;
4. size, inode, regular-file type и single-link state се проверяват;
5. exact bytes се четат чрез bounded `pread`;
6. record се parse-ва отново и exact read-back се сравнява;
7. latest durable Vault се доказва отново;
8. directory identity се доказва отново;
9. directory descriptor се `fsync`-ва;
10. final inode, private mode, single-link state, timestamps и size се
    сравняват с sealed file state;
11. exact record се чете повторно след directory `fsync` и descriptor/path
    state се сравнява отново;
12. latest durable Vault и directory identity се доказват още веднъж.

Едва тогава се връща non-secret `VaultRecoveryExportReceipt` с identities,
размери и SHA-256 digests. Receipt не съдържа path, filename или recovery key.

## 9. Crash и uncertain semantics

Portable direct exclusive create не прави incomplete file невидим по време на
write. Crash или power loss може да остави partial canonical file. Такъв файл:

- никога не е reported success;
- не се overwrite-ва при следващ опит;
- се отказва от strict import parser;
- изисква отделна бъдеща reconciliation/cleanup процедура или нова clean
  recovery директория.

Преди successful directory `fsync` кодът премахва само собствен exact inode,
ако path, descriptor, inode и single-link state още съвпадат. При foreign
hardlink или inode replacement файлът се запазва. Ако unlink е изпълнен, но
cleanup directory `fsync` се провали, on-disk състоянието е неизвестно. И в
двата случая се връща `RecoveryExportUncertainError` и се изисква manual
inspection.

След successful directory `fsync` файлът никога не се изтрива автоматично.
Всеки следващ fault, identity mismatch или Vault state change е uncertain и
изисква manual inspection. Caller-ът още държи recovery ключа в setup-а.

## 10. Read-only import contract

`rehearse_recovery_file(path, recovery_key, storage, latest)` не импортира
secrets в Vault и не създава ново поколение.

Операцията:

1. доказва exact latest durable Vault;
2. изисква canonical filename и отваря root-to-parent directory chain
   component по component с descriptor-relative `O_NOFOLLOW`;
3. задържа и revalidate-ва всеки directory descriptor, а final parent трябва
   да е current-user directory с mode точно `0700`;
4. изисква regular file, current owner, mode `0600`, link count `1` и bounded
   size преди content-capable open;
5. отваря file descriptor с `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK` и сравнява
   pre-open/path/opened identities;
6. чете exact bytes чрез bounded `pread`;
7. сравнява size, mode, link count, owner, mtime и ctime преди и след read;
8. parse-ва record-а и сравнява structurally observed Recovery ID с filename;
9. revalidate-ва файла и цялата root-to-parent chain преди success;
10. изпълнява Stage 2.4 rehearsal срещу exact current Vault;
11. чете същия file path втори път;
12. доказва отново exact latest durable Vault;
13. изисква еднакви directory/file identities, size, digest и exact bytes.

Успехът връща само non-secret `VaultRecoveryFileRehearsal`. Няма keyring,
wrapping keys, recovery key, password, plaintext, path или filename.

Read path не заявява mutating filesystem syscall. Обикновеният POSIX read може
да промени kernel/filesystem-managed `atime` според mount policy;
„read-only“ тук не е forensic no-metadata-change гаранция. `O_NONBLOCK`
предотвратява известното FIFO блокиране, но не е hard real-time гаранция.

## 11. Забранени действия

Stage 2.5 няма:

- запис, export, print или logging на recovery key;
- actual recovery publish или password reset;
- Vault generation publish, migration или wrapping-key rotation;
- automatic record selection, repair, overwrite или cleanup на uncertain
  final files;
- key deletion, destruction или file re-encryption;
- user-document read/write/delete;
- rename, replace или overwrite fallback;
- GUI, Contacts, Guardian, shards, licensing или telemetry;
- network, software update discovery, download или installation;
- твърдение, че path или device number доказват physical offline separation.

## 12. Задължителни тестове

- exact latest receipt preparation и successful export/import rehearsal;
- dirty, incomplete, forged и non-latest Vault history отказ;
- locked, expired, mismatched и changed-during-setup session отказ;
- private `0700` directory и `0600` single-link file;
- canonical filename и Recovery ID binding;
- existing target и create-race no-clobber отказ;
- symlink, hardlink, special-file, inode и directory replacement отказ;
- stable FIFO pre-open отказ, regular-to-FIFO race без блокиране и ancestor
  rename/symlink interleaving отказ;
- wrong key, tamper, truncation, oversize, stale, rollback и mixed-vault отказ;
- bounded double read и changed-during-read отказ;
- write, chmod, file fsync, directory fsync и read-back faults;
- owned-file cleanup само преди durable boundary;
- foreign hardlink и post-durability fault дават uncertain без deletion;
- source-level липса на network, GUI, logging, rename/replace и key export;
- доказателство, че rehearsal не променя Vault или recovery directory;
- доказателство за reverse-order descriptor cleanup и при `BaseException`, и
  за липса на заявени mutating filesystem calls в reader path.

Тези тестове са собствено възпроизводимо evidence за конкретния POSIX core.
Те не са независим одит, filesystem certification или доказателство срещу
компрометиран same-user account/OS.

## 13. Stage 2.6 integration boundary

Stage 2.6 използва същия strict `_read_recovery_path` contract два пъти около
in-memory candidate creation. Recovery file identity, size, digest и bytes,
както и exact latest durable Vault, трябва да съвпаднат преди и след.

Това reuse не променя Stage 2.5 export/import формата и не добавя write право.
Candidate-ът не се записва в recovery directory или Vault storage. Пълният
договор е в `docs/VAULT_RECOVERY_CANDIDATE_CONTRACT_BG.md`.

Stage 2.7 реализира отделния publish с нов explicit decision, fresh rescans и
Stage 2.2 no-clobber durability semantics. Executor-ът сам консумира exact
Stage 2.6 one-shot handoff; Stage 2.6 самостоятелно още не прави automatic
publish и не разрешава key deletion.

## 14. Stage 2.7 publish integration boundary

Stage 2.7 reuse-ва strict recovery reader преди и след единствения delegated
`VaultStorage.publish` call. Recovery file не се записва или изтрива. Преди
mutation той трябва да съвпадне exact със Stage 2.6 identities/digest/evidence;
след mutation трябва да остане byte/identity exact същият.

Vault publish използва непроменения Stage 2.2 contract. Final `R+1` е private,
single-link и no-clobber. `R` и цялата предишна history се пазят. Fault след
възможната publish граница е uncertain и не задейства rollback или cleanup.

След success `.mokr` е физически запазен, но stale спрямо latest `R+1`.
Stage 2.7 не създава автоматично нов record/root. Пълният договор е в
`docs/VAULT_RECOVERY_PUBLISH_CONTRACT_BG.md`.

## 15. Stage 2.8 reconciliation integration boundary

Stage 2.8 reuse-ва strict private recovery reader два пъти спрямо explicit old
source receipt `R`. Той не използва Stage 2.5 latest-only rehearsal helper,
защото при successful publish latest вече е `R+1` и record-ът умишлено е stale
спрямо latest, но exact валиден спрямо source `R`.

Два bounded Vault scans класифицират target absent, exact verified `R+1` или
conflict. Recovery file не се записва, премества или изтрива; incomplete scan,
temporary residue, hardlink, invalid target или changed observation не
задействат cleanup.

Stage 2.8 не създава нов recovery record/root. При exact target това остава
отделно explicit Stage 2.5 действие след normal unlock и user review. Пълният
договор е в `docs/VAULT_RECOVERY_RECONCILIATION_CONTRACT_BG.md`.

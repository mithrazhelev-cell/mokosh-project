# MOKOSH Key Vault — формат и state machine, версия 1

Статус: Stage 2.14, isolated local recovery review window върху замразените
Stage 2.1–2.13 договори.

Този формат е отделен от MOKOSH v2 файловия envelope. Vault контейнер никога
не се интерпретира като потребителски криптиран файл и обратно.

## 1. Граница на Stage 2.1

Stage 2.1 определя и реализира:

- bounded бинарен preamble;
- canonical authenticated JSON header;
- Argon2id password KDF с предварителна resource policy;
- AES-256-GCM криптиран payload;
- legacy 32-byte Vault root key при payload schema `1`;
- revision binding и външен anti-rollback anchor;
- password change чрез rewrap на същия root key;
- locked/unlocking/unlocked/locking/failed state machine;
- explicit lock и monotonic inactivity timeout;
- best-effort memory zeroization на управлявания `bytearray` буфер.

Stage 2.1 не чете и не записва пътища. Stage 2.2 добавя отделен POSIX storage
layer с atomic no-clobber persistence и read-only crash reconciliation върху
замразения криптографски формат.

Stage 2.3 добавя payload schema `2` с versioned wrapping-key keyring. Legacy
schema `1` остава четима само през legacy API и се преобразува единствено чрез
изрична authenticated migration операция.

Stage 2.4 добавя отделен versioned recovery record за exact schema-2 keyring и
read-only recovery rehearsal. Той не променя Vault container формата,
password unlock, key rotation или Stage 2.2 storage.

Stage 2.5 добавя private durable export само на encrypted recovery record и
strict read-only file rehearsal. Stage 2.6 може да създаде и провери encrypted
next-revision Vault candidate с explicit new password само в паметта. Stage 2.7
може при отделно explicit решение да го публикува чрез frozen Stage 2.2
immutable no-clobber contract. Stage 2.8 класифицира uncertain publish outcome
чрез double read-only verification без retry, rollback или cleanup.

Няма GUI, Contacts, network, telemetry, автоматично recovery или изтриване на
потребителски файлове.

## 2. Криптографски примитиви

- Password KDF: Argon2id.
- KDF output: точно 32 bytes.
- Payload AEAD: AES-256-GCM.
- Nonce: точно 12 случайни bytes, нови при всяко криптиране или rewrap.
- Salt: точно 16 случайни bytes, нови при всяко криптиране или rewrap.
- Vault root key: точно 32 CSPRNG bytes.
- Vault identifier: точно 16 CSPRNG bytes.

Паролата е UTF-8 текст от 1 до 1024 bytes. Тя не се записва в header, payload,
лог или session object.

## 3. Бинарен preamble

Всички цели числа са big-endian.

| Поле | Размер | Стойност |
|---|---:|---|
| magic | 8 bytes | `MOKVLT1\0` |
| major | uint8 | `1` |
| minor | uint8 | `0` |
| flags | uint16 | `0` |
| header_len | uint32 | `1..4096` |
| ciphertext_len | uint32 | `17..1048576` |

Общият размер трябва да бъде точно:

`preamble_len + header_len + ciphertext_len`

Truncation и trailing bytes се отказват. Неизвестна версия или flag се
отказва fail-closed.

## 4. Canonical authenticated header

Header е UTF-8 JSON object, кодиран с:

- ASCII-safe JSON;
- сортирани ключове;
- separators `,` и `:` без whitespace;
- забранени NaN, Infinity и други нестандартни constants;
- забранени duplicate keys;
- никакви missing или unknown полета.

Задължителните полета са:

- `format`: точно `MOKOSH_KEY_VAULT`;
- `version`: integer `1`, boolean не се приема;
- `vault_id`: canonical unpadded base64url на 16 bytes;
- `revision`: integer `1..2^63-1`;
- `created_utc`: strict `YYYY-MM-DDTHH:MM:SSZ`;
- `updated_utc`: същият формат и не по-ранен от `created_utc`;
- `payload_schema`: plain integer `1` за legacy root или `2` за keyring;
- `kdf`: exact Argon2id object;
- `aead`: exact AES-256-GCM object.

`kdf` съдържа точно:

- `algorithm`: `Argon2id`;
- `salt`: canonical unpadded base64url на 16 bytes;
- `time_cost`: plain integer;
- `memory_kib`: plain integer;
- `parallelism`: plain integer.

`aead` съдържа точно:

- `algorithm`: `AES-256-GCM`;
- `nonce`: canonical unpadded base64url на 12 bytes.

## 5. KDF format и local resource policy

Форматните граници са:

| Параметър | Минимум | Максимум |
|---|---:|---:|
| time_cost | 1 | 10 |
| memory_kib | 8192 | 1048576 |
| parallelism | 1 | 16 |

Default стойностите при създаване са `3`, `65536`, `4`.

Локалната policy по подразбиране допуска максимум `5`, `262144`, `8`.
Parser проверява header, форматните граници и local policy преди Argon2id.
Това не позволява на непроверен Vault да предизвика произволно скъп KDF.

## 6. Legacy authenticated payload — schema 1

След decrypt payload е exact canonical JSON object със следните полета:

- `format`: точно `MOKOSH_VAULT_PAYLOAD`;
- `version`: integer `1`;
- `vault_id`: същите 16 bytes като authenticated header;
- `revision`: същият revision като authenticated header;
- `vault_root_key`: canonical unpadded base64url на точно 32 bytes.

Missing, duplicate, unknown, non-canonical или несъвпадащи полета се отказват
като authentication failure. Payload не съдържа парола.

## 7. AEAD binding

Точният AES-GCM AAD е конкатенацията:

1. domain separator `MOKOSH\0KEY-VAULT\0AES-256-GCM\0`;
2. exact binary preamble;
3. exact canonical header bytes.

Така magic, версии, flags, размери, Vault ID, revision, timestamps, KDF
параметри, salt, AEAD algorithm и nonce са authenticated.

Wrong password, променен header, ciphertext или tag се отказват без root key.

## 8. Revision и anti-rollback

Нов Vault започва с revision `1`. Password rewrap:

- запазва exact Vault ID;
- запазва exact Vault root key;
- увеличава revision точно с едно;
- създава нов salt и nonce;
- не допуска връщане назад на `updated_utc`.

Самият файл не може да докаже, че по-старо валидно копие не е rollback.
Затова parser приема trusted `minimum_revision`, който се пази извън
контейнера от бъдещия storage layer. Revision под anchor-а се отказва преди
password KDF. Digest сам по себе си не е trust anchor.

## 9. Session state machine

Разрешените основни преходи са:

```text
locked -> unlocking -> unlocked
locked -> unlocking -> failed
failed -> locked
unlocked -> locking -> locked
unlocked -> failed          при monotonic clock anomaly
```

- `unlock` е разрешен само от `locked`.
- Authentication или parser failure преминава в `failed`.
- Нов опит изисква изрично `reset_failure`.
- Root key може да бъде поискан само в `unlocked`.
- `lock` нулира best-effort управлявания root-key буфер и преминава в
  `locked`; повторен `lock` е безопасен.
- Password change е разрешен само в активна unlocked session.
- Legacy root access е разрешен само за payload schema `1`.
- Keyring access и rotation са разрешени само за payload schema `2`.
- Няма автоматично schema migration при unlock, password change или publish.
- Session object забранява copy, deepcopy и pickle.
- `repr` не съдържа ключ, парола или ciphertext.

## 10. Inactivity timeout

Timeout използва monotonic clock, а не wall-clock timestamp.

- timeout трябва да бъде положително крайно число;
- проверява се преди root-key access и password change;
- изтичането извършва explicit lock;
- clock rollback или невалидна clock стойност отказва fail-closed;
- PID, wall-clock timestamp или възраст на файл не заместват тази проверка.

GUI event integration и OS suspend/resume policy остават за по-късен етап.

## 11. Memory limitation

Python и общите операционни системи не обещават доказуемо изтриване на всички
копия на секрет от RAM, registers, allocator, swap, crash dump или VM snapshot.
MOKOSH нулира best-effort собствения mutable root-key буфер при lock/failure,
не пази паролата и ограничава unlocked живота, но не твърди абсолютна memory
zeroization. По-късният platform review трябва да разгледа locked memory,
swap/dump policy и native secret containers поотделно за Linux, Windows и
macOS.

## 12. Задължителни отрицателни проверки

Тестовете покриват най-малко:

- wrong magic, version и flags;
- truncated и trailing data;
- invalid declared lengths;
- duplicate, missing, unknown и non-canonical JSON fields;
- boolean вместо integer;
- invalid UTC и backward timestamp;
- padded/non-canonical base64url;
- неизвестен KDF или AEAD;
- Argon2id resource policy преди KDF execution;
- wrong password и header/ciphertext tamper;
- revision rollback и exhaustion;
- invalid state transitions;
- timeout, clock rollback, copy и pickle;
- password rewrap със запазен root key и сменени salt/nonce.
- cross-schema API refusal и explicit legacy migration;
- canonical keyring, exact version selection и rotation invariants.

Преминаването на тези тестове е вътрешно възпроизводимо доказателство, не
сертификация и не независимо одобрение.

## 13. Stage 2.2 — immutable Vault storage

Stage 2.2 не променя криптографския Vault формат. Той добавя отделен storage
договор, който държи всеки revision в собствен immutable generation файл.

### 13.1 POSIX граница

Текущият backend изисква доказани POSIX операции:

- descriptor-relative `open`, `stat`, `mkdir`, `link` и `unlink`;
- `O_EXCL` и `O_NOFOLLOW` или еквивалентна отказваща семантика;
- hard-link publish без overwrite;
- file `fsync` и directory `fsync`;
- bounded descriptor read чрез `pread`.

Неподдържана или неясна семантика отказва fail-closed. Windows backend не се
симулира с по-слаби операции; той ще има отделна реализация и тестове преди
Windows release.

### 13.2 Private directory

Един storage directory съдържа поколения само на един Vault.

- directory mode е точно `0700`;
- directory owner е текущият потребител, когато платформата предоставя UID;
- symlink в path-а се отказва;
- при създаване parent не може да бъде group/world writable;
- directory се отваря с descriptor и identity `(device, inode)`;
- identity, типът, owner и mode се проверяват отново преди операции;
- directory creation е no-clobber и никога не приема съществуващ обект.

### 13.3 Immutable generation имена

Canonical generation име е:

`vault-rNNNNNNNNNNNNNNNNNNNN.mokv`

където `N` е точно 20-digit decimal revision. Filename revision трябва точно
да съвпада с authenticated Vault header revision.

Generation файл:

- е regular file;
- има mode точно `0600`;
- принадлежи на текущия потребител;
- след завършен publish има точно един hard link;
- съдържа точно един bounded Vault container с поддържан payload schema;
- никога не се презаписва, truncate-ва, rename-ва или replace-ва.

Revision `N+1` се добавя като нов inode. Revision `N` остава непроменен.

### 13.4 Publish transaction

Publish приема само активна unlocked `VaultSession`. Session timeout се
проверява преди запис и отново непосредствено преди създаване на final името.

Точната последователност е:

1. повторна проверка на directory identity и private policy;
2. bounded read-only scan на history;
3. проверка на exact durable previous receipt;
4. проверка за contiguous revisions и един Vault ID;
5. directory `fsync` preflight;
6. exclusive `0600` same-directory temporary inode;
7. bounded write, file `fsync` и exact readback;
8. повторен strict Vault parse и identity проверка;
9. atomic hard link от temporary към новото canonical generation име;
10. directory `fsync` след появата на final името;
11. доказване, че final и temporary са exact same inode с два links;
12. unlink само на exact temporary името;
13. втори directory `fsync`;
14. проверка на final inode, mode, link count, size, SHA-256 и Vault identity;
15. издаване на durable generation receipt.

Final generation име се създава само чрез no-clobber hard link. `rename` и
`replace` не участват в този договор.

### 13.5 Previous receipt

Durable receipt обвързва:

- exact directory device/inode;
- Vault ID;
- revision;
- SHA-256 на exact encoded Vault bytes;
- generation file device/inode и size;
- изрично durable състояние.

При update receipt трябва да съвпадне с последното read-only наблюдение и с
повторно отворения immutable generation файл. Новият revision трябва да бъде
точно `previous + 1`, със същия Vault ID.

Receipt е техническо доказателство за конкретното локално наблюдение. Той не
е цифров подпис и не е самостоятелен trust anchor срещу attacker, който може
да върне назад целия storage и всички локални state файлове.

### 13.6 Crash и partial publish

Преди hard-link publish безопасният abort може да премахне само temporary име,
ако exact inode ownership се потвърди от отворения descriptor.

След успешно създаване на final името всяка грешка се отчита като uncertain:

- final generation никога не се изтрива автоматично;
- старите поколения никога не се променят;
- linked temporary може да остане като второ име на същия inode;
- липса на последния directory `fsync` никога не се представя като success;
- следващото действие изисква нов read-only reconciliation.

Това различава логически валиден файл от доказано durable commit.

### 13.7 Read-only reconciliation

Scan е ограничен до максимум 512 подробни entries. Допълнителните entries се
броят точно като omitted, без да се трупат в паметта. Непълен scan никога не
разрешава publish.

Обектите се класифицират като:

- valid immutable generation;
- invalid generation;
- unlinked private temporary;
- linked private temporary;
- unknown или unsafe object.

Prefix на име не доказва ownership. Scan не извършва unlink, rename, replace,
publish, decrypt или recovery. Findings не съдържат basename или path, а само
несекретен hash token, classification и проверими inode факти.

Unknown, invalid, temporary или truncated evidence блокира следващ publish,
докато отделен бъдещ user-confirmed recovery/cleanup договор не реши случая.

### 13.8 Rollback граница

Immutable history открива gaps, mix-and-match и промени спрямо наличния latest
receipt. Тя не може сама да открие пълно връщане на цялата директория към стар
съгласуван snapshot.

Истинският trusted minimum revision трябва по-късно да се държи в независимо
защитен platform anchor. Storage receipt може да бъде подаден към такъв anchor
само след завършени file и directory durability проверки. Stage 2.2 не твърди,
че обикновен локален JSON, digest или filename е независим anti-rollback root.

### 13.9 Забранени действия

Stage 2.2 няма:

- in-place overwrite или truncate на поколение;
- automatic latest selection при конфликт;
- автоматично cleanup, recovery или rollback;
- root key, password или plaintext logging;
- GUI, Contacts, network или telemetry;
- изтриване на оригинални потребителски файлове.

## 14. Stage 2.3 — versioned Vault keyring

Stage 2.3 променя само authenticated payload договора и in-memory session
операциите. Stage 2.2 storage продължава да вижда opaque authenticated Vault
generations и не избира, ротира или изтрива ключове.

Договорът следва общите lifecycle принципи на NIST SP 800-57 Part 1 Rev. 5:
key identifier и state са authenticated metadata; новият ключ се генерира
независимо от стария; deactivated/retired key не прилага нова защита, но може
да обработва вече защитена информация, докато е необходим.

Нормативна препратка:
`https://doi.org/10.6028/NIST.SP.800-57pt1r5`

### 14.1 Payload schema evolution

Vault header `payload_schema` има две поддържани стойности:

- `1` — frozen Stage 2.1 legacy payload с един `vault_root_key`;
- `2` — Stage 2.3 keyring payload.

Неизвестна стойност се отказва преди password KDF. Legacy `unlock_vault` не
приема schema `2`, а `unlock_keyring_vault` не приема schema `1`. Това не е
format guessing: caller избира изрично точния API.

Schema `2` payload е canonical authenticated JSON object с точно:

- `format`: `MOKOSH_VAULT_PAYLOAD`;
- `version`: plain integer `2`;
- `vault_id`: exact authenticated header Vault ID;
- `revision`: exact authenticated header revision;
- `keyring`: exact keyring object от 14.2.

Missing, duplicate, unknown, non-canonical или cross-bound полета се отказват
като authentication failure след успешен AES-GCM decrypt.

### 14.2 Canonical keyring object

Keyring object съдържа точно:

- `format`: `MOKOSH_VAULT_KEYRING`;
- `version`: plain integer `1`;
- `purpose`: `MOKOSH_V2_KEY_VAULT_SLOT`;
- `algorithm`: `HKDF-SHA-256+AES-256-GCM`;
- `active_key_version`: positive uint32;
- `keys`: ordered array от 1 до 4096 exact key records.

Standalone canonical encoding е ограничено до 786432 bytes. Outer Vault
ciphertext продължава да спазва общата граница от 1048576 bytes.

Всеки key record съдържа точно:

- `key_version`: positive uint32 `1..2^32-1`, boolean е забранен;
- `state`: точно `active` или `retired`;
- `created_utc`: strict canonical UTC timestamp;
- `retired_utc`: strict UTC timestamp или `null`;
- `wrapping_key`: canonical unpadded base64url на точно 32 bytes.

Record object и keyring object отказват copy, deepcopy и pickle. Техният
`repr` не съдържа wrapping-key bytes. Самото canonical plaintext encoding е
секрет и се допуска само като краткоживееща in-memory стойност вътре в session
или непосредствено преди authenticated Vault sealing.

### 14.3 Structural invariants

Валиден keyring изпълнява едновременно:

- версиите са ordered и contiguous точно `1, 2, ..., N`;
- няма duplicate, gap, reorder или unknown record variant;
- `active_key_version` е точно `N`;
- record `N` е единственият `active` и има `retired_utc = null`;
- всички records преди `N` са `retired`;
- retirement timestamp на version `i` е точно creation timestamp на `i+1`;
- retirement не предхожда creation;
- wrapping-key material е уникален между всички версии;
- всички fixed format, purpose и algorithm полета съвпадат точно.

Нарушение отказва целия keyring. Няма repair, sorting, deduplication или
приемане на частично валидни records.

### 14.4 Rotation

Rotation е изрична операция върху unlocked schema `2` session:

1. проверява inactivity timeout и schema;
2. проверява отново текущата парола спрямо текущите authenticated Vault bytes;
3. валидира целия текущ keyring;
4. генерира нови независими 32 bytes от OS CSPRNG;
5. отказва невалидна дължина, тип или повторение на съществуващ key;
6. превръща досегашния active record в `retired`;
7. добавя точно version `N+1` като единствен active record;
8. запечатва schema `2` payload като Vault revision `R+1` с нов salt и nonce;
9. отключва и сравнява новия резултат преди session mutation;
10. оставя publish на Stage 2.2 като отделна atomic no-clobber операция.

Новият key не се извежда от стария. Rotation не прекриптира файлове, не
променя съществуващи slots и не изтрива retired records. Clock rollback,
version/resource exhaustion или грешна текуща парола оставят session bytes и
keyring непроменени.

### 14.5 Exact file-slot selection

Нов Key Vault slot се създава само с единствения active record и записва
неговия `vault_key_version` в authenticated slot metadata.

Decrypt приема exact positive uint32 от slot-а:

- version `V` избира само record `V` чрез директната contiguous позиция;
- active и retired record могат да отварят вече създаден slot;
- липсваща version отказва преди cryptographic unwrap;
- AES-GCM authentication failure с избраната version приключва операцията;
- не се опитва друга version и няма oldest/newest/nearest fallback.

Това запазва старите файлове четими след rotation, без да отслабва binding-а
между slot metadata и точния wrapping key.

### 14.6 Explicit legacy migration

Schema `1` никога не се преобразува автоматично. Единственият migration
договор:

1. strict parse с trusted `minimum_revision`;
2. authenticated legacy unlock с текущата парола;
3. exact legacy `vault_root_key` става key version `1`;
4. key creation timestamp се запазва от първоначалния Vault `created_utc`;
5. Vault ID и първоначалният creation timestamp се запазват;
6. Vault revision се увеличава точно с едно;
7. резултатът е schema `2` с нов salt и nonce и същата проверена парола.

Така съществуващите version-1 file slots остават отваряеми. Старото immutable
schema-1 generation не се променя или изтрива. Migration на schema `2`, wrong
password, revision rollback/exhaustion или backward timestamp се отказва.

### 14.7 Session и memory граница

Една `VaultSession` държи точно един secret вид според schema:

- mutable legacy root buffer за schema `1`; или
- mutable canonical keyring buffer за schema `2`.

Lock, timeout, clock anomaly и failure нулират best-effort управлявания secret
buffer. Keyring copy създава Python `bytes` objects за точната операция; затова
ограничението от раздел 11 остава в сила и Stage 2.3 не твърди доказуема
zeroization на всички interpreter/OS копия.

### 14.8 Забранени действия

Stage 2.3 няма:

- automatic migration, key search, fallback или silent downgrade;
- derivation на нов key от retired key;
- automatic file re-encryption;
- automatic retirement reversal, key deletion или destruction;
- GUI, Contacts, network, telemetry или secret logging;
- path I/O или промяна на потребителски файлове.

## 15. Stage 2.4 — offline Vault recovery contract

Stage 2.4 е отделен in-memory слой. Пълният normative threat model и binary
contract са в `docs/VAULT_RECOVERY_CONTRACT_BG.md`.

### 15.1 Recovery материал

Recovery setup създава:

- exact version-1 recovery record;
- независим 32-byte CSPRNG recovery root;
- независими 16-byte Recovery ID и 12-byte AES-GCM nonce.

Recovery root се превръща в exact 32-byte AEAD key чрез domain-separated
HKDF-SHA-256, обвързан с Vault ID и Recovery ID. Той не се извежда от password,
nickname, license, wrapping key или software version.

### 15.2 Exact state binding

Record-ът е authenticated към:

- exact Vault ID;
- exact source revision;
- SHA-256 на exact encoded source Vault generation;
- SHA-256 на exact canonical keyring;
- пълния canonical keyring с active и retired records.

Password rewrap, key rotation или migration създават ново Vault поколение и
правят стария recovery record stale. Няма fallback към по-стар record.

### 15.3 Strict format

Binary preamble използва magic `MOKREC1\0`, version `1.0`, flags `0`, header
до 4096 bytes и ciphertext до 851968 bytes. Header и encrypted payload са
strict canonical JSON без duplicate, missing или unknown полета.

AES-256-GCM AAD обхваща exact preamble и header. Payload повтаря exact Vault
binding metadata и съдържа keyring digest плюс Stage 2.3 keyring object.

### 15.4 Read-only rehearsal

Rehearsal приема един record, exact recovery root и exact current Vault bytes.
Тя отказва wrong root, tamper, stale, rollback, mixed-vault, same-revision
conflict, duplicate и malformed данни.

При успех се връща само non-secret evidence. Keyring и wrapping keys не се
връщат. Няма actual recovery publish, new password, storage mutation или
user-file operation.

### 15.5 Candidate sets

Структурната проверка приема bounded tuple от 1 до 32 records. Duplicate
record/ID, mixed Vault ID или смесени revisions/source hashes се отказват.
Distinct records за един exact Vault state са допустими.

### 15.6 Integration граница

Stage 2.4 не import-ва filesystem storage. Бъдещ export трябва отделно да
докаже latest durable Stage 2.2 receipt и чист read-only scan. Actual recovery,
password reset, atomic publish, export encoding и GUI са следващи отделни
етапи с нови fault тестове.

### 15.7 Забранени действия

Stage 2.4 няма:

- filesystem path I/O, publish, rename, replace, unlink или cleanup;
- automatic recovery, migration, rotation, key deletion или re-encryption;
- GUI, Contacts, Guardian, shards, network, telemetry или logging;
- software update discovery или automatic installation;
- dependency от licensing или server.

## 16. Stage 2.5 — durable recovery record storage integration

Пълният normative filesystem договор е в
`docs/VAULT_RECOVERY_STORAGE_CONTRACT_BG.md`.

### 16.1 Latest durable prerequisite

Recovery preparation, export и file rehearsal приемат само exact latest
durable Stage 2.2 receipt при clean, complete и contiguous storage scan.
Unlocked schema-2 session трябва byte-for-byte да съвпада с receipt-а.

### 16.2 Отделни материали

Stage 2.5 записва само encrypted Stage 2.4 recovery record. Recovery key остава
отделна in-memory стойност. Няма API за key file, общ package или автоматично
записване на двете стойности върху един носител.

### 16.3 Private no-clobber export

Изрично избраната recovery директория трябва да е owned от current user, mode
`0700`, без symlink и различна от Vault storage директорията. Canonical
`*.mokr` файл се създава descriptor-relative с `O_EXCL`, `O_NOFOLLOW` и mode
`0600`.

Success се връща само след bounded write, file `fsync`, exact read-back parse,
повторно latest-Vault доказателство, directory `fsync` и final inode/mode/link
проверка. Existing target никога не се overwrite-ва.

### 16.4 Read-only import rehearsal

Import приема един explicit canonical file path и recovery key. File трябва да
е regular, private, owned, single-link и bounded. Exact record се чете два пъти
около Stage 2.4 rehearsal и трябва да запази еднакви directory/file identities,
size, digest и bytes. Vault latest receipt също се доказва преди и след.

Резултатът съдържа само non-secret evidence. Няма actual recovery publish,
password reset или промяна на Vault generation.

### 16.5 Fault boundary

Преди durable directory sync се премахва само exact owned single-link file.
Foreign hardlink, cleanup uncertainty или всеки fault след durable boundary
запазват файла и връщат uncertain, без success.

Crash може да остави partial canonical file, защото portable exclusive create
не осигурява atomic visibility. Strict import го отказва, а следващ export не
го overwrite-ва. Няма automatic cleanup.

### 16.6 Platform и physical-media ограничение

POSIX core отказва filesystem без надеждни exact permissions и directory
`fsync`. Path, mount или device number не доказват физически отделен/offline
носител. Реалната separation остава изрична отговорност на потребителя и
бъдещия GUI workflow.

### 16.7 Забранени действия

Stage 2.5 няма:

- recovery-key file export, logging или network transfer;
- actual recovery publish, password reset, migration или rotation;
- rename, replace, overwrite fallback или automatic uncertain cleanup;
- GUI, Contacts, Guardian, licensing, telemetry или user-file mutation;
- software update discovery, download или automatic installation.

## 17. Stage 2.6 — in-memory recovery Vault candidate

Пълният normative договор е в
`docs/VAULT_RECOVERY_CANDIDATE_CONTRACT_BG.md`.

### 17.1 Exact recovery prerequisite

Candidate preparation приема само exact latest durable schema-2 Vault receipt
при clean complete history, strict private `.mokr` file и отделно предоставен
exact 32-byte recovery root. Stage 2.4 rehearsal трябва да съвпадне с exact
current Vault ID, revision и source SHA-256.

Stale, rollback, mixed-vault, same-revision byte conflict, wrong root, tamper,
hardlink, unsafe permissions или malformed input отказват fail-closed.

### 17.2 Explicit new password

Caller подава new password, exact enum decision и bounded Argon2id policy.
Няма old-password параметър, password guessing или fallback. Password и KDF
inputs се валидират преди recovery source access и преди Argon2id.

Stage 2.6 прилага само frozen 1..1024 UTF-8 byte format bound; не твърди
password-strength оценка или GUI confirmation policy.

### 17.3 Candidate invariants

Recovered canonical keyring се запечатва като нормален `MOKVLT1` schema-2
container:

- exact Vault ID и original `created_utc` се запазват;
- revision се увеличава точно с едно;
- exact active/retired key history се запазва без rotation или deletion;
- new password използва нови CSPRNG salt и nonce;
- `updated_utc` не се връща назад;
- candidate се unlock-ва и keyring digest се сравнява преди success.

Vault format не получава нови recovery fields и остава frozen.

### 17.4 Evidence и authorization

Non-secret evidence обвързва Recovery/Vault ID, source/target revision,
source/record/keyring/candidate SHA-256, KDF policy и recovery file identities.
Source-only facts не се представят като authenticated Vault header; те се
свързват от process-local authorization след exact double source verification.

Prepared candidate е one-shot, non-copyable и non-picklable. Claim се допуска
веднъж. Authorization изрично изисква бъдещ rescan и не разрешава filesystem
publish, key deletion или user-file mutation в Stage 2.6.

### 17.5 Забранени действия

Stage 2.6 няма:

- Vault generation create, publish, overwrite, rename или replace;
- automatic recovery, rotation, migration или key deletion;
- old-generation cleanup или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry или logging;
- software update discovery, download или automatic installation.

## 18. Stage 2.7 — immutable recovery-candidate publish

Пълният normative договор е в
`docs/VAULT_RECOVERY_PUBLISH_CONTRACT_BG.md`.

### 18.1 Separate explicit publish decision

Publish приема само unclaimed Stage 2.6 prepared candidate, exact source
receipt, същия private `.mokr` record/root, new password и exact enum decision.
Executor-ът сам консумира Stage 2.6 `claim_once`; preclaimed или повторен object
се отказва.

Invalid decision, password bounds, recovery-root length, object types, KDF
policy и evidence bounds се отказват преди claim, source access и Argon2id.

### 18.2 Fresh exact-source mediation

Source Vault и recovery file се проверяват два пъти преди mutation. Изискват се
clean complete contiguous history, exact latest receipt, exact Vault/source
digest, strict private single-link `.mokr`, stable identities и successful
Stage 2.4 rehearsal.

Candidate се unlock-ва отново с new password и трябва exact да съвпадне по
Vault ID, target revision `R+1`, KDF и keyring evidence. Candidate KDF трябва да
е разрешен от frozen default Stage 2.2 parser policy.

### 18.3 Единствена mutation и no-clobber

Stage 2.7 не извършва direct filesystem write. Единствената mutation е frozen
`VaultStorage.publish(session, previous=receipt)`, който създава private
immutable `R+1` чрез verified same-directory temporary, file/directory `fsync`
и atomic no-clobber hard link.

Старото `R`, всички предишни поколения и `.mokr` файлът не се overwrite-ват,
rename-ват или изтриват.

### 18.4 Post-publish и uncertain semantics

Преди success се проверяват exact receipt/readback на `R+1`, byte-preserved
`R`, exact history `old + R+1`, new-password unlock и непроменен recovery file.

Всеки fault след възможния hard-link publish се връща като uncertain. Няма
false success, rollback, unlink или automatic cleanup на target поколението.

### 18.5 Recovery freshness след успех

Старият recovery record физически остава, но е bound към `R` и става stale
спрямо latest `R+1`. Нов record/root се създава само чрез отделен explicit
Stage 2.5 setup след normal unlock с new password; никога автоматично.

### 18.6 Забранени действия

Stage 2.7 няма:

- overwrite, replace, rename или deletion на Vault generation;
- automatic retry, rollback, cleanup или new recovery setup;
- key rotation, migration, deletion или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry или logging;
- software update discovery, download или automatic installation.

## 19. Stage 2.8 — read-only recovery publish reconciliation

Пълният normative договор е в
`docs/VAULT_RECOVERY_RECONCILIATION_CONTRACT_BG.md`.

### 19.1 Surviving explicit inputs

Reconciliation приема exact old source receipt `R`, target revision точно
`R+1`, private `.mokr` record за `R`, отделния recovery root, new password,
exact `VaultStorage` и local KDF policy.

Stage 2.6 candidate/authorization не е вход: той е process-local, one-shot и
може да е изгубен след interruption. Observed target се доказва спрямо
surviving source/recovery/password invariants.

### 19.2 Double read-only mediation

Source receipt/bytes и recovery file/root rehearsal се проверяват два пъти.
Между тях се правят два bounded Vault scans с canonical order-independent
report signature.

Source receipt умишлено може да е nonlatest, когато `R+1` съществува. Той
трябва все още exact да съвпада с generation `R` и clean history.

### 19.3 Три bounded класификации

- `TARGET_ABSENT` — stable clean complete history завършва точно с `R`;
- `TARGET_EXACT_DURABLE` — stable clean history завършва с verified `R+1`,
  което се unlock-ва с new password и пази exact recovered keyring;
- `CONFLICT` — всяко друго bounded наблюдение, включително invalid target,
  temporary/unknown object, incomplete или changed scan.

Source/recovery verification failure прекратява без класификация. Untrusted
target receipt/digest не се връща при conflict.

### 19.4 Recommended action граница

Резултатът връща fixed non-secret action: new candidate при absent, review и
separate new recovery setup при exact, или stop при conflict. Action никога не
е mutation authorization.

### 19.5 Забранени действия

Stage 2.8 няма:

- publish, write, fsync, overwrite, replace или rename;
- automatic retry, rollback, unlink, cleanup или repair;
- candidate creation/reuse или new recovery setup;
- key rotation, migration, deletion или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry или logging;
- software update discovery, download или automatic installation.

## 20. Stage 2.9 — explicit recovery workflow state

Пълният normative договор е в
`docs/VAULT_RECOVERY_WORKFLOW_CONTRACT_BG.md`.

### 20.1 Exact reviewed-result binding

Workflow preparation приема само exact Stage 2.8 result. Проверяват се bounded
IDs, revisions, digests, receipts, counts, safety flags и exact
classification/action invariants.

Domain-separated fixed transcript SHA-256 обвързва целия result като
process-local mismatch evidence. Това не е digital signature, persisted token
или independent anti-rollback anchor.

### 20.2 One-shot explicit review

Prepared workflow започва само в `AWAITING_USER_REVIEW`, не пази original
result и допуска един successful `review_once`. Review-ът отново изисква exact
същия validated result и exact enum decision.

Different result, wrong classification route, string decision и replay се
отказват. Prepared object не може да бъде copy, deep-copy или pickle.

### 20.3 Bounded routes

- absent → `FRESH_CANDIDATE_DECISION_REQUIRED` и отделен fresh Stage 2.6 gate;
- exact → `NORMAL_UNLOCK_REQUIRED`, следван от отделен Stage 2.5 setup gate;
- conflict → terminal `MANUAL_REVIEW_STOP`;
- preserve → terminal `PRESERVED_STOP`.

Gate е ordered requirement, не operation authorization. Nonterminal route
изисква downstream reverification.

### 20.4 Non-secret no-authority state

Evidence/state съдържат само classification/action, IDs, revisions, digests,
complete/stable flags, explicit decision и fixed gates. Няма password,
recovery root, keyring, candidate, session, path или filename.

Всички candidate, unlock, recovery setup, publish, retry, repair, cleanup, key
deletion и user-file mutation authority flags са false.

### 20.5 Забранени действия

Stage 2.9 няма:

- filesystem access, Vault parse/unlock, KDF или recovery rehearsal;
- candidate creation, recovery setup, publish, retry, rollback или cleanup;
- automatic transition, key deletion или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry или logging;
- clock, randomness, update discovery, download или installation.

## 21. Stage 2.10 — recovery workflow presentation

Пълният normative договор е в
`docs/VAULT_RECOVERY_PRESENTATION_CONTRACT_BG.md`.

### 21.1 Exact Stage 2.9 state input

Presentation preparation приема само exact validated
`VaultRecoveryWorkflowState`. Stage 2.9 format/version, evidence, route, ordered
gates и всички read-only/no-authority flags се проверяват отново.

Няма password, recovery root, keyring, candidate, session, path, filename,
exception text, callback или executor input.

### 21.2 Fixed bounded view model

Output съдържа само classification, recorded decision, route state,
domain-separated state digest, fixed localization message keys, visible gate
keys, ordered confirmation requirements и fixed safety flags.

Presentation не пази original Stage 2.9 state или evidence. Message и
confirmation tuples са bounded, unique, exact-enum и exact ordered.

### 21.3 Route presentation

- absent показва downstream reverification и fresh Stage 2.6 decision gate;
- exact target показва normal unlock преди отделен Stage 2.5 setup decision и
  че старият recovery record остава stale;
- conflict показва terminal manual-review stop и no automatic repair;
- preserve показва terminal stop без gate и че проблемът не е решен.

Всеки route показва, че operation не е performed и не е authorized. Gate или
confirmation requirement никога не е operation authority.

### 21.4 Process-local binding limitation

Canonical fixed transcript SHA-256 обвързва exact Stage 2.9 evidence, decision,
route, gates и flags. Digest-ът открива mismatch, но не е signature, persisted
token, independent provenance или anti-rollback proof.

### 21.5 Забранени действия

Stage 2.10 няма:

- raw user-facing text, localization rendering или arbitrary template data;
- acknowledgement recording, callback, executor или mutation API;
- filesystem access, Vault unlock/KDF или recovery rehearsal;
- candidate creation, recovery setup, publish, retry, repair или cleanup;
- automatic transition, key deletion или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry, logging, clock или randomness;
- update discovery, download или installation.

## 22. Stage 2.11 — one-shot recovery presentation acknowledgement

Пълният normative договор е в
`docs/VAULT_RECOVERY_ACKNOWLEDGEMENT_CONTRACT_BG.md`.

### 22.1 Exact Stage 2.10 presentation input

Preparation приема само exact validated
`VaultRecoveryWorkflowPresentation`. Format/version, fixed message/gate/
confirmation tuples, route semantics и всички no-text/no-authority flags се
проверяват отново.

Canonical domain-separated transcript SHA-256 обвързва exact presentation.
Digest-ът е process-local mismatch evidence, не signature, persistent consent
token или anti-rollback anchor.

### 22.2 Exact ordered acknowledgement

Prepared object започва в `AWAITING_CONFIRMATIONS` и приема само exact bounded
tuple от `RecoveryPresentationConfirmationKey`, напълно еднакъв с ordered
requirements на presentation-а.

Skip, partial, reorder, duplicate, extra key, string, list и cross-route tuple
се отказват без automatic correction. Failed input не консумира object-а.

### 22.3 One-shot и concurrency

Един prepared object допуска точно един successful `acknowledge_once`.
Process-local lock гарантира един success при concurrent attempts; след него
всеки опит е replay отказ.

Няма cross-process state, persisted resume или restart authority. Prepared
object не може да бъде copy, deep-copy или pickle.

### 22.4 Bounded non-secret receipt

Receipt съдържа presentation digest, classification/decision/state, exact
confirmation tuple/count, sequence `1`, terminal/reverification semantics и
fixed safety flags.

Няма original presentation/state/evidence, Recovery/Vault IDs, revisions,
source/target digests, password, root, keyring, candidate, path, filename,
callback или executor reference.

Всички operation performed/authorized, gate invoked и automatic transition
flags са false. Acknowledgement никога не е candidate, unlock, setup, publish,
retry, repair, cleanup или user-file mutation authorization.

### 22.5 Забранени действия

Stage 2.11 няма:

- filesystem access, Vault unlock/KDF или recovery rehearsal;
- gate invocation, callback, executor или mutation API;
- candidate creation, recovery setup, publish, retry, repair или cleanup;
- automatic transition, key deletion или user-file mutation;
- GUI, Contacts, Guardian, network, telemetry, logging, clock или randomness;
- update discovery, download или installation.

## 23. Stage 2.12 — bounded non-mutating recovery UI adapter

Пълният normative договор е в
`docs/VAULT_RECOVERY_UI_ADAPTER_CONTRACT_BG.md`.

### 23.1 Exact presentation и acknowledgement binding

Public preparation приема само exact validated Stage 2.10
`VaultRecoveryWorkflowPresentation`. Stage 2.10 schema/route/safety validation
и Stage 2.11 canonical presentation binding се изпълняват отново.

Prepared adapter създава private Stage 2.11 acknowledgement lifecycle и
не приема external callback, executor или operation object.

### 23.2 Fixed ordered view

View съдържа само:

- presentation digest, classification, decision и route state;
- ordered `RecoveryUIMessageItem` със stable ordinal, exact message key,
  visible flag и accessible-label-key binding;
- ordered `RecoveryUIConfirmationControl` с exact key, visible/required/
  individually-selectable flags, accessible-label-key binding и
  `default_selected = false`;
- terminal/downstream semantics и fixed no-text/no-authority flags.

`auto_accept_available` и `operation_controls_included` са fixed false.

### 23.3 Exact visible interaction

One-shot transition приема exact tuple от
`RecoveryUIConfirmationEvent`. Всеки event трябва да има exact
ordinal/key и exact true flags за visible, user-selected и
adapter-reported user-initiated interaction.

Empty, list, mapping, string, partial, reorder, duplicate, extra, wrong
ordinal, hidden, unselected и cross-route input се отказват без
consumption. Successful key tuple се предава само на private Stage
2.11 `acknowledge_once`.

### 23.4 One-shot bounded receipt

Process-local lock допуска точно един success при concurrent
attempts. Copy, deep-copy и pickle на prepared adapter се отказват.

Receipt съдържа exact route, digest, confirmation tuple/count и fixed
visibility/order/Stage-2.11/no-authority flags. Той не пази view,
presentation, events, secrets, IDs, paths, callback или executor.

### 23.5 Честно UI ограничение

Stage 2.12 доказва structured adapter contract, не реален
widget. `user_initiated` е adapter assertion, не biometric/human-
comprehension proof.

Реалният GUI още трябва да докаже localization completeness,
keyboard/focus/screen-reader behavior, scaling, cancellation и widget
visibility на всяка платформа.

### 23.6 Забранени действия

Stage 2.12 няма:

- GUI toolkit, localization rendering или raw user-facing text;
- filesystem access, Vault unlock/KDF или recovery rehearsal;
- gate invocation, callback, executor или mutation API;
- candidate, recovery setup, publish, retry, repair или cleanup;
- automatic transition, key deletion или user-file mutation;
- Contacts, Guardian, network, telemetry, logging, clock или randomness;
- update discovery, download или installation.

## 24. Stage 2.13 — versioned recovery localization registry

Пълният normative договор е в
`docs/VAULT_RECOVERY_LOCALIZATION_CONTRACT_BG.md`.

### 24.1 Exact locale allowlist

Version 1 поддържа само exact plain-string locale IDs `bg-BG` и `en-GB`.
Няма case/whitespace normalization, language/region substitution или silent
fallback. Unsupported locale се отказва без partial output.

### 24.2 Complete fixed catalogs

Всеки immutable catalog съдържа exact ordered one-to-one translation за
всички 24 Stage 2.10 message keys и всички 9 confirmation keys.

Missing, extra, duplicate, reordered, mixed-locale, unsafe и altered text се
отказват. Fixed Bulgarian/English text няма runtime placeholder или
user-controlled interpolation.

### 24.3 Unicode и catalog binding

Text е bounded по code points и UTF-8 bytes, NFC-normalized, trimmed и без
control/format/bidi-override/template characters. Domain-separated catalog
SHA-256 обвързва exact locale, key order и UTF-8 text.

Digest-ът е integrity binding, не signature или independent provenance proof.

### 24.4 Deterministic localized records

Public localization приема exact validated Stage 2.12 view и exact locale.
Резултатът запазва presentation digest, route, ordinals, gate markers,
visibility и default-false confirmation policy и добавя само exact visible и
accessible fixed text.

Adapter state остава awaiting confirmations. Localization не acknowledge-ва,
не консумира lifecycle и не създава operation control.

### 24.5 Честно UI ограничение

Stage 2.13 не е real widget, usability/accessibility certification или proof,
че човек е прочел текста. Real GUI още трябва да докаже focus, keyboard,
screen-reader, scale, wrapping, scrolling, cancel/close и platform behavior.

### 24.6 Забранени действия

Stage 2.13 няма:

- GUI toolkit, widget, event loop или interaction input;
- external catalog, language pack, template или runtime formatter;
- filesystem/environment locale, network, telemetry, logging, clock или
  randomness;
- Vault unlock/KDF, recovery rehearsal, acknowledgement, candidate, setup,
  publish, retry, repair или cleanup;
- gate invocation, callback, executor, automatic transition, key deletion или
  user-file mutation;
- update discovery, download или installation.

## 25. Stage 2.14 — isolated local recovery review window

Пълният нормативен договор е в
`docs/VAULT_RECOVERY_REVIEW_WINDOW_CONTRACT_BG.md`.

### 25.1 Exact upstream binding

Stage 2.14 приема само exact Stage 2.10 presentation, fresh awaiting Stage
2.12 prepared adapter и exact locale ID `bg-BG` или `en-GB`.

Преди widget construction се проверяват presentation binding, adapter view,
Stage 2.13 catalog/localized route, ordinals, keys, gate markers, visibility и
required/individual/default-false confirmation policy. Consumed, altered,
mixed-route или unsupported source се отказва fail-closed.

### 25.2 Real isolated Tk window

Public display създава само child `tk.Toplevel` към caller-provided existing
Tk parent. Не създава втори `tk.Tk`, не стартира втори `mainloop` и не променя
`mokosh_gui.py`.

Scrollable ordered messages и bold gate warnings се създават преди отделните
confirmation checkboxes. Checkboxes са false и disabled до exact visible
message report. Няма group select, pre-check или remembered state.

### 25.3 Visible individual interaction

Final acknowledgement е disabled, докато всяка exact individual checkbox не
е true. Uncheck го изключва отново. Successful action създава само exact
ordered Stage 2.12 visible/user-selected/user-initiated event tuple.

Cancel button, Escape и window-manager close приключват без Stage 2.12
acknowledgement. Partial selection не създава receipt.

### 25.4 Bounded no-authority outcome

Success outcome съдържа само exact locale, presentation digest, decision и
validated Stage 2.12 receipt. Cancel outcome съдържа exact cancel reason и
никакъв receipt.

Outcome не пази presentation, localized view, raw events, password, recovery
root, keyring, path, filename, callback, executor или operation capability.
Operation/gate/automatic/group-select flags са fixed false.

### 25.5 Freshness и честно ограничение

Stage 2.14 не чете filesystem и не доказва current Vault/recovery state.
Nonterminal route продължава да изисква downstream fresh revalidation.

`user_initiated` остава local widget assertion, не proof за идентичност,
прочитане, разбиране, правно съгласие или uncompromised OS.

### 25.6 Забранени действия

Stage 2.14 няма:

- main-GUI activation, Vault unlock/KDF или recovery rehearsal;
- candidate, setup, publish, retry, rollback, repair или cleanup;
- filesystem access, key deletion или user-file mutation;
- callback, executor, gate invocation или automatic transition;
- Contacts, Sandbox operation, Guardian, network, telemetry или logging;
- OS-locale fallback, external language pack или runtime template;
- update discovery, download или installation;
- screenshot-control или cross-platform accessibility certification claim.

# MOKOSH v2 — формална файлова спецификация, проект 0.1

Статус: замразена основа за имплементация и тестове. Не е декларация за
независим криптографски одит.

## 1. Цели

MOKOSH v2 трябва да осигури:

- authenticated encryption на съдържание и служебен header;
- поточна работа с големи файлове;
- случайно генериран Data Encryption Key (`DEK`) за всеки файл;
- смяна на парола/получател чрез rewrap на DEK, без ново криптиране на файла;
- атомарни записи и отказ от неявно презаписване;
- точно разпознаваеми версии и алгоритми;
- отделни, явни classic и hybrid-PQ suites без тих downgrade;
- read-only съвместимост с MOK1.

Не се създават собствени криптографски примитиви. Използват се библиотечни
Argon2id, AES-256-GCM, HKDF-SHA-256, X25519, ML-KEM-768 и Ed25519.

## 2. Модел на заплахите

V2 защитава срещу прочит и незабелязана промяна на файл без необходимите
ключове. Форматът трябва да открива:

- грешна парола/ключ;
- променен header, key slot, frame или trailer;
- разместване, повторение, липса или добавяне на frame;
- съкратен или частично записан файл;
- неподдържана версия/suite;
- опасни размери и KDF параметри преди скъпа операция.

V2 самостоятелно не защитава компрометиран работещ компютър, keylogger, злонамерен
администратор, екранна снимка или вече декриптиран plaintext.

## 3. Съвместимост

- Ново криптиране винаги записва v2.
- MOK1 се разпознава отделно и се декриптира само през legacy reader.
- Няма автоматично преобразуване или презаписване на MOK1.
- Няма fallback от непознат/повреден v2 към MOK1.
- Миграцията създава нов v2 файл, проверява го и запазва MOK1 до отделно
  потвърдено почистване.

## 4. Външна структура

Всички цели числа са unsigned big-endian.

```text
PREAMBLE (20 bytes)
HEADER (header_len bytes, UTF-8 JSON)
FRAME 0 ... FRAME N
TRAILER
```

### 4.1 Preamble

| Поле | Размер | Стойност/значение |
|---|---:|---|
| magic | 8 | `MOKOSH2\0` |
| major | 1 | `2` |
| minor | 1 | `0` за тази спецификация |
| flags | 2 | неизвестен задължителен flag = отказ |
| header_len | 4 | максимум 65,536 bytes |
| chunk_size | 4 | 64 KiB–8 MiB; default 1 MiB |

Parser-ът валидира preamble и ограниченията преди JSON parsing, KDF или голяма
allocation.

### 4.2 Header

Header-ът е UTF-8 JSON без duplicate keys. Точните записани bytes, а не повторно
сериализиран обект, участват в payload authentication.

Задължителни полета:

```json
{
  "format": "MOKOSH",
  "version": 2,
  "file_id": "base64url-16-random-bytes",
  "content_aead": "AES-256-GCM-CHUNKED",
  "nonce_prefix": "base64url-8-random-bytes",
  "chunk_size": 1048576,
  "key_slots": [],
  "created_utc": "RFC3339",
  "writer": "MOKOSH Agent"
}
```

Човешки nickname, име на контакт, оригинално име, бележки и абсолютни пътища не
се записват в открития header. Те принадлежат на криптирания manifest във frame 0.

## 5. Ключове и key slots

Всеки файл получава независим случаен 32-byte DEK. Payload никога не се криптира
директно с password-derived key или дългосрочен private key.

### 5.1 Password slot

- Argon2id със случаен минимум 16-byte salt.
- Начален desktop профил: 64 MiB, `t=3`, `p=4`, 32-byte output, съгласно втория
  препоръчан профил на RFC 9106.
- Преди KDF се прилагат твърди minimum/maximum bounds.
- Полученият KEK wrap-ва DEK чрез AES-256-GCM.
- Nickname не е втори криптографски фактор и не се смесва скрито в паролата.
- KDF параметрите и slot идентификаторът са associated data на key wrap.

Stage 1.10 фиксира точната in-memory операция. Паролата е непразен Unicode text,
който се подава към Argon2id като точните му UTF-8 bytes, максимум 1024 bytes.
Криптографският слой не прави скрита Unicode нормализация. UI може по-късно да
налага ясна и тествана входна политика, но не може тихо да променя паролата.
Argon2id връща точно 32-byte KEK.

Преди Argon2id slot-ът се проверява и срещу локална execution policy. Началният
лимит е `time_cost <= 5`, `memory_kib <= 262144` (256 MiB) и
`parallelism <= 8`. Превишаване се отказва преди конструиране или стартиране на
KDF. По-висока изрично конфигурирана policy може да се използва само в твърдите
format граници.

Password-slot AAD е точно:

```text
b"MOKOSH2" || 0x00 || b"PASSWORD-SLOT-WRAP" || 0x00
|| canonical_json({
     file_id, type, suite, slot_id, salt,
     time_cost, memory_kib, parallelism, wrap_nonce
   })
```

`canonical_json` е UTF-8/ASCII JSON със сортирани ключове, без whitespace и с
unpadded canonical base64url за binary полетата. `file_id` е точно 16 bytes.
`wrapped_dek` умишлено не участва в AAD, защото е самият AES-GCM ciphertext и
tag. Slot ID, salt и nonce се генерират независимо с криптографски случаен
източник при всяко ново wrap-ване. Грешна парола, грешен `file_id` или промяна
на обвързано поле водят до един общ authentication failure, без DEK output.

### 5.2 Key Vault slot

Key Vault предоставя точно 32-byte root key след успешно отключване. Root key
никога не се използва директно като AES-GCM key. За всеки файл и slot се извежда
отделен 32-byte KEK чрез HKDF-SHA-256. Файловият DEK се пази само като
authenticated wrap. Смяна на master password rewrap-ва vault root key, а не
всички големи файлове.

HKDF е точно:

```text
IKM  = vault_root_key (32 bytes)
salt = file_id (16 bytes)
info = b"MOKOSH2" || 0x00 || b"KEY-VAULT-SLOT-KEK" || 0x00
       || canonical_json({
            file_id, slot_id, suite, type, vault_key_version
          })
L    = 32 bytes
Hash = SHA-256
```

AES-GCM AAD е точно:

```text
b"MOKOSH2" || 0x00 || b"KEY-VAULT-SLOT-WRAP" || 0x00
|| canonical_json({
     file_id, slot_id, suite, type, vault_key_version, wrap_nonce
   })
```

`canonical_json` използва същите строги правила като password slot: сортирани
ключове, без whitespace и canonical unpadded base64url. `wrapped_dek` не влиза
в AAD, защото е AES-GCM ciphertext и tag. `slot_id` и `wrap_nonce` са нови
криптографски случайни стойности при всяко wrap-ване. Грешен root key,
`file_id`, key version или променено slot поле водят до общ authentication
failure без DEK output. Изборът на правилния локален `vault_key_version` е
отделна бъдеща Vault policy; codec-ът не пробва автоматично неизвестни версии.

### 5.3 Contact hybrid slot

За hybrid suite са задължителни и двата компонента:

1. ephemeral X25519 sender key + X25519 public key на получателя;
2. ML-KEM-768 encapsulation към ML-KEM public key на получателя.

Sender приема точно 32-byte raw X25519 public key и 1184-byte raw ML-KEM-768
public key на една и съща потвърдена key version. За всеки slot се генерира нов
ephemeral X25519 private key, нов ML-KEM encapsulation, нов 16-byte `slot_id` и
нов 12-byte AES-GCM nonce.

KEK derivation е точно:

```text
IKM  = uint16_be(32) || x25519_shared_secret
       || uint16_be(32) || mlkem768_shared_secret
salt = file_id (16 bytes)
info = b"MOKOSH2" || 0x00 || b"CONTACT-HYBRID-SLOT-KEK" || 0x00
       || canonical_json({
            ephemeral_x25519_public_key, file_id, mlkem_ciphertext,
            recipient_key_version, slot_id, suite, type
          })
L    = 32 bytes
Hash = SHA-256
```

AES-GCM AAD е точно:

```text
b"MOKOSH2" || 0x00 || b"CONTACT-HYBRID-SLOT-WRAP" || 0x00
|| canonical_json({
     ephemeral_x25519_public_key, file_id, mlkem_ciphertext,
     recipient_key_version, slot_id, suite, type, wrap_nonce
   })
```

`canonical_json` е със сортирани ключове, без whitespace и с canonical unpadded
base64url. `wrapped_dek` не влиза в AAD, защото е AES-GCM ciphertext и tag.

Recipient приема точно един избран 32-byte raw X25519 private key и един избран
64-byte ML-KEM-768 private seed за декларираната key version. Codec-ът не търси
сам ключове, не променя trust и не приема ключове от различни версии.

Ако X25519 или ML-KEM компонент липсва, е с грешен размер, не може да бъде
обработен или води до различен shared secret, unwrap отказва без DEK output.
Променен KEM ciphertext се открива окончателно от HKDF binding и AES-GCM tag.
Текущият MOKOSH v2 contact profile не дефинира и не произвежда classic-only
slot; `X25519-ONLY` suite се отказва. Няма fallback или downgrade.

### 5.4 Точна публична key-slot схема

Всеки slot е JSON object с точен набор полета. Липсващо или неизвестно поле,
непознат `type`/`suite`, padded или non-canonical base64url и грешна binary
дължина се отказват. `slot_id` е нов случаен 16-byte идентификатор за конкретния
файл и не се използва повторно като постоянна самоличност.

Password slot има точно:

```json
{
  "type": "PASSWORD",
  "suite": "ARGON2ID-AES-256-GCM",
  "slot_id": "base64url(16 bytes)",
  "salt": "base64url(16 bytes)",
  "time_cost": 3,
  "memory_kib": 65536,
  "parallelism": 4,
  "wrap_nonce": "base64url(12 bytes)",
  "wrapped_dek": "base64url(48 bytes)"
}
```

При v2 parser bounds са: `time_cost` 2–10, `memory_kib` 65536–1048576 и
`parallelism` 1–16. Това са format граници, не автоматично разрешение за KDF;
бъдещият executor прави отделна resource проверка преди Argon2id.

Key Vault slot има точно:

```json
{
  "type": "KEY_VAULT",
  "suite": "KEY-VAULT-HKDF-SHA-256-AES-256-GCM",
  "slot_id": "base64url(16 bytes)",
  "vault_key_version": 1,
  "wrap_nonce": "base64url(12 bytes)",
  "wrapped_dek": "base64url(48 bytes)"
}
```

`vault_key_version` е положителен unsigned 32-bit integer.

Contact hybrid slot има точно:

```json
{
  "type": "CONTACT_HYBRID",
  "suite": "X25519-ML-KEM-768-HKDF-SHA-256-AES-256-GCM",
  "slot_id": "base64url(16 bytes)",
  "recipient_key_version": 1,
  "ephemeral_x25519_public_key": "base64url(32 bytes)",
  "mlkem_ciphertext": "base64url(1088 bytes)",
  "wrap_nonce": "base64url(12 bytes)",
  "wrapped_dek": "base64url(48 bytes)"
}
```

Contact slot не публикува nickname, име или recipient fingerprint. Получателят
пробва само собствените си локални ключове със съответните версии в рамките на
ограничения брой slots. Липсващ ML-KEM ciphertext или `X25519-ONLY` suite се
отказва, вместо да предизвика downgrade.

`wrapped_dek` е фиксиран на 48 bytes: 32-byte DEK ciphertext и 16-byte GCM tag.
В един header са позволени най-много 64 slots и всички `slot_id` трябва да са
уникални. Празен списък е допустим само като междинна структурна стойност;
бъдещият завършен file writer трябва да изисква поне един използваем slot.

### 5.5 Оркестрация на key slots

За всеки нов envelope се генерират точно един нов случаен 16-byte `file_id` и
един нов случаен 32-byte DEK. Всички избрани PASSWORD, KEY_VAULT и
CONTACT_HYBRID slots в този envelope обвиват независимо същия DEK и са
криптографски обвързани със същия `file_id`.

Оркестраторът изисква поне един slot, отказва повече от 64 slots и отказва
дублиран `slot_id`. След окончателното създаване builder-ът е еднократен и не
може да добавя или създава втори набор със същото вътрешно състояние.

При unwrap потребителят или по-високият policy слой избира точно един публичен
`slot_id` и предоставя credential от съответния вид:

- PASSWORD приема само password credential и приложимата локална KDF policy;
- KEY_VAULT приема само точния Vault root key;
- CONTACT_HYBRID приема едновременно X25519 private key и ML-KEM-768 private
  seed за декларираната recipient key version.

Несъвпадащ тип credential се отказва преди криптографски опит. Не се обхождат
други slots, authentication failure не задейства повторен опит с друг slot и
CONTACT_HYBRID никога не преминава към X25519-only режим. Успешно полученият
DEK трябва да бъде точно 32 bytes и е единственият ключ за payload frames на
този envelope.

## 6. Поточен payload

Frame структура:

| Поле | Размер |
|---|---:|
| index | 4 |
| plaintext_len | 4 |
| flags | 1 |
| ciphertext + GCM tag | `plaintext_len + 16` |

- Frame 0 е криптиран manifest.
- Данните започват от frame 1.
- Nonce = 8-byte случаен `nonce_prefix` + 4-byte frame index.
- Един DEK не може да използва повторно index/nonce.
- Frame index е unsigned 32-bit и целият диапазон `0`–`0xffffffff` е валиден.
- Trailer може да представи най-много `2^32 - 1` frames общо, включително
  manifest frame 0. Поради това writer-ът отказва input, който би изисквал
  `2^32` frames, въпреки че самият frame codec може да представи последния
  32-bit index.
- По-голям input се отказва предварително.
- AAD на всеки frame включва domain separator, SHA-256 на точните
  `PREAMBLE || HEADER`, index, plaintext_len и flags.
- Последният frame има задължителен FINAL flag.

Криптираният manifest съдържа оригиналното име, размер, content type по желание,
общ брой data frames и SHA-256 на plaintext за локална post-decrypt проверка.
Този hash не се публикува в открития header.

## 7. Trailer и подпис

Ciphertext transcript е точната последователност `PREAMBLE || HEADER || FRAMES`,
включително всички frame headers, ciphertext bytes и GCM tags, но без trailer.
Transcript digest е:

```text
SHA-256("MOKOSH2\\0CIPHERTEXT-TRANSCRIPT\\0" || transcript_bytes)
```

Trailer започва непосредствено след FINAL frame. Всички цели числа са unsigned
big-endian. Фиксираната част е 56 bytes:

| Поле | Размер | Стойност/значение |
|---|---:|---|
| magic | 8 | `MOKTRL2\\0` |
| major | 1 | `2` |
| minor | 1 | `0` |
| flags | 2 | за версия 2.0 трябва да е `0` |
| frame_count | 4 | общ брой frames, включително manifest frame 0 |
| transcript_sha256 | 32 | domain-separated digest на точния transcript |
| signature_algorithm | 1 | `0` = NONE, `1` = ED25519 |
| signer_key_version | 4 | `0` при NONE; положителна версия при ED25519 |
| fingerprint_len | 1 | `0` при NONE; `32` при ED25519 |
| signature_len | 2 | `0` при NONE; `64` при ED25519 |

След фиксираната част се записват точно `fingerprint_len` bytes и след тях точно
`signature_len` bytes. Няма trailing bytes или неявни полета.

Unsigned local trailer изисква едновременно algorithm `NONE`, key version `0`,
празен fingerprint и празен signature. Signed contact trailer изисква ED25519,
положителна key version, 32-byte fingerprint и 64-byte signature. Смесени или
частично попълнени състояния се отказват.

Ed25519 signer fingerprint е точно:

```text
SHA-256(b"MOKOSH2" || 0x00 || b"ED25519-PUBLIC-KEY" || 0x00
       || raw_32_byte_public_key)
```

Raw public key е точно 32-byte Ed25519 public key encoding. Друг algorithm,
друга дължина или недекларирана нормализация не са допустими.

Ed25519 signing input е domain separator
`MOKOSH2\\0TRAILER-SIGNATURE\\0`, следван от точната фиксирана trailer част с
декларирана 64-byte signature дължина и точния 32-byte fingerprint, но без
самите signature bytes.

Parser-ът сравнява `frame_count` и `transcript_sha256` с действително
сканираните frames. След това Ed25519 verifier-ът проверява, че подаденият
public key съвпада с fingerprint и че signature е валиден за точния signing
input. При contact mode липсващ или невалиден подпис води до Quarantine.

Успешната криптографска проверка не означава автоматично доверие. Тя доказва
само владение на съответния private key. Свързването на fingerprint и key
version с потвърден контакт е отделна trust policy и не се извършва от
signature codec-а.

### 7.1. Пълна in-memory envelope интеграция

Пълният Stage 1 envelope е точната последователност:

```text
PREAMBLE || HEADER || ENCRYPTED_MANIFEST_FRAME || ENCRYPTED_DATA_FRAMES || TRAILER
```

Writer-ът приема само окончателно създаден `EnvelopeKeyPlan`. Неговият единствен
32-byte DEK криптира manifest и всички data frames, а всеки публикуван key slot
в header-а обвива същия DEK за същия 16-byte `file_id`. За envelope се генерира
нов независим 8-byte `nonce_prefix`.

Режимът на trailer се избира изрично:

- `UNSIGNED_LOCAL` е разрешен само когато няма `CONTACT_HYBRID` slot;
- `ED25519_SIGNED` изисква точен Ed25519 private key и положителна uint32 key
  version;
- наличието на който и да е `CONTACT_HYBRID` slot задължително изисква
  `ED25519_SIGNED`; unsigned downgrade се отказва преди криптиране.

Reader-ът първо намира точната граница след FINAL frame, parse-ва целия trailer
без trailing bytes и сравнява frame count и transcript digest. След това
прилага предварително избрана verification policy:

- unsigned policy отказва подписан envelope и всеки contact envelope;
- Ed25519 policy отказва unsigned envelope и проверява точния supplied public
  key, fingerprint, key version и signature;
- няма режим „приеми каквото намериш“ и няма автоматично доверяване на signer.

Публичната структура и signature policy се проверяват преди password KDF,
Vault или contact secret операция. Едва след това reader-ът избира точно един
`slot_id`, използва само съответния credential и получава DEK без търсене или
fallback към друг slot. Manifest, всички GCM tags, FINAL, frame count,
plaintext size и plaintext SHA-256 трябва да бъдат валидни преди връщане на
plaintext към caller-а.

Този in-memory слой не чете и не записва файлове, не решава contact trust, не
достъпва реално Vault хранилище, recovery, мрежа, лицензиране, логове или GUI.

### 7.2. Bounded streaming envelope договор

Manifest frame 0 съдържа крайния plaintext размер и SHA-256, а signature policy
се проверява преди отваряне на secret slot. За да се запазят тези две правила
без зареждане на целия файл в RAM, streaming интеграцията е изрично двупроходна.

При криптиране:

1. първи plaintext source се прочита с bounded `read(size)` и създава
   `PlaintextStreamPlan` с точен размер, SHA-256, chunk size и data frame count;
2. независим втори source се криптира chunk по chunk;
3. вторият pass се сравнява с плана по точен размер, EOF и SHA-256;
4. различен, по-къс, по-дълъг или променен втори pass анулира quarantine sink;
5. trailer се записва и sink се commit-ва едва след пълното съвпадение.

При декриптиране:

1. първи ciphertext source се parse-ва последователно без slot unwrap;
2. prefix, frame sequence, FINAL, transcript digest, trailer и предварително
   избраната unsigned/Ed25519 policy се проверяват изцяло;
3. резултатът е непроменима `InspectedStreamEnvelope` контролна стойност;
4. само след нея се отваря един изрично избран slot;
5. независим втори source се декриптира към quarantine sink;
6. вторият prefix, transcript, frame count и trailer трябва да съвпаднат точно
   с първата проверка;
7. manifest size, data frame count и plaintext SHA-256 се проверяват преди
   commit на sink.

Source договорът разрешава само положителни bounded read размери и отказва
не-byte резултат или повече bytes от поисканите. Sink договорът има точно
`write`, `commit` и `abort`; частичните положителни записи се довършват, нулев
progress се отказва, а всяка грешка или прекъсване задейства `abort`.

Quarantine sink не може да публикува записаните bytes преди успешен `commit`.
Това е задължително особено при plaintext декриптиране. Stage 1.15 дефинира и
тества този транзакционен договор само с контролирани паметови потоци. Реалните
temporary files, metadata проверки, `fsync`, atomic rename и cleanup принадлежат
на отделен следващ файлов слой.

## 8. Безопасен файлов слой

Stage 1.16 въвежда само source и quarantine примитиви за локална regular-file
операция. Той още не избира потребителски пътища, не изтрива оригинал, не
активира GUI и не представлява завършен файлов pipeline.

### 8.1 Verified source

1. Последният компонент на source path не може да бъде symbolic link и трябва
   да е regular file.
2. Файлът се отваря с `O_NOFOLLOW`, `O_CLOEXEC`, `O_NONBLOCK` и binary mode,
   когато платформата ги предоставя. `O_NONBLOCK` не променя regular-file
   четенето, но позволява post-open type отказ без блокиране при
   regular-to-FIFO race.
3. Преди отваряне, непосредствено след отваряне и след операцията трябва да
   съвпадат device, inode, mode, size, mtime, ctime, uid и gid.
4. Всеки read е положителен и ограничен най-много до максималния v2 frame read.
   Не се допуска unbounded `read()`.
5. Изчезнал, заменен или променен source се отказва. Source примитивът никога
   не изтрива или преименува входа.

### 8.2 Same-directory quarantine sink

1. Крайното име трябва да липсва. Regular file, directory, link или друг
   съществуващ обект на това име се третира като collision.
2. Immediate parent трябва да е реална private директория, собственост на
   текущия потребител и без group/world write на POSIX.
3. Parent directory се отваря веднъж. Всички temporary операции се адресират
   спрямо нейния descriptor, за да не се доверяват повторно на променлив път.
4. Temporary regular file се създава изключително в същата директория с
   случаен непретенциозен basename, `O_EXCL`, `O_NOFOLLOW` и права `0600`.
5. Преди publish се проверяват отвореният descriptor, точният temporary inode,
   regular-file типът, mode `0600` и link count `1`.
6. След последния запис се извършва `fsync` на temporary file.
7. No-clobber publish използва атомарен hard link от проверения temporary inode
   към липсващото крайно име в същата отворена директория. Появило се крайно
   име се отказва, без overwrite. Не се използва check-then-rename fallback.
8. След publish parent directory се `fsync`-ва, когато платформата го поддържа,
   temporary името се премахва и директорията отново се синхронизира.
9. Ако filesystem или OS не осигурява relative directory operations и atomic
   no-clobber hard-link publish, операцията отказва затворено. Платформен adapter
   може да бъде добавен само със същите или по-силни доказани гаранции.
10. Abort изтрива само temporary path, който все още сочи към точно притежавания
    от транзакцията inode. При подмяна отказва да изтрие чуждия обект.

### 8.3 Stage 1.17 end-to-end файлов pipeline

Stage 1.17 свързва Stage 1.15 streaming двигателя и Stage 1.16 файловите
примитиви чрез задължителен deferred-publish договор.

При криптиране:

1. първи verified source pass създава plaintext size/SHA-256/frame plan;
2. втори verified pass трябва да отвори същия identity и да съвпадне с плана;
3. streaming `commit` само запечатва и `fsync`-ва private temporary inode;
4. крайното output име все още трябва да липсва;
5. записаният temporary envelope се прочита веднъж за public structure,
   transcript, trailer и signature-policy проверка;
6. независим втори temporary pass се декриптира до size/SHA-256 с вече
   притежавания fresh DEK, без публикуване или запис на plaintext;
7. manifest, transcript, trailer, encoded size и plaintext plan трябва да
   съвпадат точно с writer резултата;
8. sealed inode identity/metadata се проверяват отново и едва тогава се
   извършва atomic no-clobber publish.

При декриптиране:

1. първият verified ciphertext pass валидира публичната структура и изрично
   избраната signature policy преди slot unwrap;
2. втори pass трябва да отвори същия ciphertext identity, да отвори само
   избрания slot и да декриптира към private temporary inode;
3. streaming `commit` отново означава само seal, не publish;
4. temporary plaintext се прочита bounded и размерът, SHA-256 и frame plan се
   сравняват с автентичния manifest и decryption резултат;
5. sealed inode се проверява отново преди atomic no-clobber publish.

Всяка грешка преди действителния publish задейства abort, който премахва само
доказано притежавания temporary inode. Появил се краен файл не се заменя.
Source файловете никога не се изтриват или преименуват. Pipeline-ът приема
изрични input/output пътища и не взема GUI, trust, recovery или cleanup решения.

### 8.4 Stage 1.18 lifecycle, cancellation и безопасни резултати

Контролираният файлов вход използва строг еднопосочен lifecycle. Криптирането
преминава през `preflight`, `scan`, `encrypt`, `verify_output` и `publish`, а
декриптирането — през `preflight`, `verify_input`, `decrypt`, `verify_output`
и `publish`. Фаза не може да бъде пропусната, повторена или изпълнена извън
реда си.

Cancellation token се проверява преди и след всяко bounded read/write действие,
при границите на фазите и непосредствено преди atomic publish. Отказ преди
publish задейства quarantine abort. След успешния atomic publish по-късно
натиснатото „Отказ“ не може да превърне публикувания резултат във фалшива
грешка или да го изтрие.

Progress събитията съдържат само вида операция, фиксираната фаза, фиксираното
състояние и монотонен sequence номер. В тях няма имена, пътища, размери,
пароли, ключове, exception текст или потребителско съдържание. `complete` се
излъчва единствено след действителен publish и проверка на крайния inode.

Публичният operation wrapper връща или проверения pipeline result, или
стабилни несекретни error code, phase, retryable flag и localization key.
Оригиналният exception текст не се връща към UI. Observer грешка преди publish
е fail-closed; observer грешка след необратим publish не отменя успеха.

Stage 1.18 не активира GUI и не добавя изтриване, автоматичен output path,
network, telemetry, trust или recovery решение.

### 8.5 Stage 1.19 crash journal и read-only reconciliation

Всяка нова same-directory quarantine транзакция създава два private файла с
един и същ случаен 128-bit operation identifier:

```text
.mokosh-quarantine-<32 lowercase hex>
.mokosh-operation-<32 lowercase hex>.json
```

Journal-ът е canonical ASCII JSON, максимум 2048 bytes, mode `0600` и initial
link count `1`. Той съдържа само format/version, operation identifier,
temporary basename, parent device/inode, temporary device/inode, owner uid/gid,
mode и initial link count. Не съдържа source или output име/път, размер или hash
на съдържанието, ключ, credential, контакт, manifest или plaintext metadata.

Journal-ът се създава с exclusive no-follow операция, записва се bounded,
`fsync`-ва се и се свързва с exact temporary inode преди транзакцията да стане
достъпна за writer-а. Нормален commit или abort проверява exact journal inode и
metadata преди да премахне точно journal-а на тази транзакция. Подменен,
променен или hard-linked journal блокира publish/cleanup fail-closed.

Stage 1.19 reconciliation приема само изрично подадена private real directory и
прави стабилен read-only snapshot. Journal parser-ът отказва duplicate,
missing, unknown, noncanonical, oversized и неподдържани полета. Резултатите
различават поне:

- запис и temporary inode, които структурно съвпадат;
- липсващ temporary inode;
- identity/metadata mismatch;
- променен link count, включително crash window след publish link;
- invalid или unsafe journal;
- temporary име без валиден свързан journal.

Съвпадащият запис не доказва, че процесът е приключил или че pair-ът не е
създаден от процес със същите локални права. Затова всеки Stage 1.19 report и
finding има `mutation_permitted = false`. Няма API за unlink, rename, publish,
decrypt, recovery или автоматичен cleanup. Prefix, възраст или PID никога не са
самостоятелно доказателство за собственост или изоставена операция.

При crash преди journal се вижда unrecorded temporary; след изчезнал temporary
се вижда missing temporary; след publish link преди cleanup се вижда променен
link count. Нито едно от тези състояния не се поправя автоматично в Stage 1.19.

### 8.6 Stage 1.20 reconciliation evidence и план за действие

Stage 1.20 преобразува един стабилен Stage 1.19 snapshot в bounded canonical
evidence report. Report-ът е свързан с exact directory device/inode, но не
съдържа directory path, journal/temporary имена, output или source име,
content size/hash, ключ, credential, контакт, exception текст или plaintext
metadata.

Canonical report форматът е `MOKOSH-RECON-EVIDENCE`, version `1`, ASCII JSON с
максимум 131,072 bytes. Един report съдържа максимум 256 подробни findings.
Когато source snapshot има повече findings, report-ът отбелязва точните
`source`, `included` и `omitted` броя, `complete = false` и запазва пълни
classification counters. Пропуснатите записи никога не се представят като
проверени или безопасни.

Фиксираните несекретни classification стойности са:

- `inode_match`;
- `temporary_missing`;
- `identity_conflict`;
- `link_count_conflict`;
- `invalid_record`;
- `unsafe_record`;
- `unrecorded_temporary`.

Всеки подробен item съдържа само sequence, classification, optional canonical
operation identifier, фиксирана препоръчана следваща стъпка и задължителните
policy flags. `user_decision_required = true`, `rescan_required = true` и
`mutation_permitted = false` са неизменни. Само `inode_match` може да има
`identity_prerequisite_met = true`. Това означава единствено, че exact
journal/inode техническото предусловие е било изпълнено при snapshot-а; не
доказва изоставена операция и не разрешава cleanup.

Canonical bytes имат възпроизводим SHA-256 digest за сравнение и evidence
пакети. Digest-ът не е цифров подпис, не създава доверие и не заменя повторната
проверка. Decode отказва duplicate, missing, unknown, noncanonical, oversized,
неподдържани или policy-inconsistent полета.

Stage 1.20 няма filesystem write, unlink, rename, publish, decrypt, recovery,
cleanup, GUI, network, telemetry или trust API. Бъдещо действие трябва да
направи нов scan непосредствено преди изпълнение и да сравни отново exact
directory, journal и inode identity. Prefix, operation ID, report digest,
възраст или потребителско потвърждение поотделно никога не са достатъчно
разрешение за промяна.

### 8.7 Stage 1.21 active-operation lease и abandonment evidence

Активният writer държи OS-managed exclusive non-blocking lease върху exact
journal descriptor от създаването на journal-а до нормален commit, abort или
затваряне на процеса. Lease descriptor-ът е собственост на operation sink-а и
не се освобождава между отделните bounded фази. При process exit или crash
операционната система освобождава descriptor-а и свързания lease.

Поддържаните backend договори са изрични:

- POSIX използва `fcntl.flock` с `LOCK_EX | LOCK_NB`;
- Windows използва `msvcrt.locking` с `LK_NBLCK` върху точно един byte от
  offset zero;
- неизвестна платформа, липсващ API или неподдържана filesystem семантика
  отказва fail-closed като `lease_unsupported`.

Lease-ът координира само процеси, които спазват същия MOKOSH договор. Той не е
доказателство срещу процес със същите локални права и не удостоверява кой е
създал journal-а. Network/remote filesystem семантика не се приема по
подразбиране за еквивалентна на локалната; непотвърдената семантика е
unsupported.

Activity assessment различава точно четири несекретни състояния:

- `active` — exact pair е проверен и друг cooperating writer държи lease;
- `released_candidate` — exact pair е проверен и lease е придобит от probe-а;
- `lease_unsupported` — exact pair е проверен, но lease семантиката не е
  валидирана;
- `identity_conflict` — journal, temporary inode, directory или lease
  наблюдението не могат да бъдат свързани безопасно.

`released_candidate` означава само, че в момента на non-blocking probe-а не е
наблюдаван cooperating writer. То не доказва authenticity, crash,
abandonment, ownership или безопасност за cleanup. PID, timestamp, age,
basename prefix, operation ID и report digest също не доказват abandonment.

Преди връщане на assessment-а се проверяват отново exact directory,
journal и temporary device/inode identity. Когато probe-ът придобие lease,
повторната проверка се прави, докато probe descriptor-ът още държи lease.
Подмяна, hardlink/link-count промяна, невалиден journal, race или backend error
дават `identity_conflict`.

Всеки Stage 1.21 assessment запазва `user_decision_required = true`,
`rescan_required = true`, `abandonment_proven = false` и
`mutation_permitted = false`. Stage 1.21 няма unlink, rename, cleanup,
publish, decrypt, recovery, GUI, network, telemetry или автоматично действие.

### 8.8 Stage 1.22 еднократно cleanup authorization

Stage 1.22 подготвя само in-memory authorization contract. Той не изпълнява
cleanup и не променя filesystem. Подготовката приема единствено изрично
типизирано потребителско решение `authorize_cleanup`; `preserve`, boolean,
string или неясна стойност отказват fail-closed.

Reviewed evidence трябва да бъде canonical, complete и без omitted findings.
Точният operation ID трябва да присъства точно веднъж като `inode_match`, с
изпълнено identity prerequisite, задължителни user decision и rescan flags и
`mutation_permitted = false`.

Преди създаване на authorization се изпълнява следната read-only
последователност:

1. fresh reconciliation scan и canonical evidence build;
2. byte-for-byte сравнение с reviewed evidence, не само сравнение на digest;
3. exact activity assessment за избрания operation ID;
4. изискване за `released_candidate` с validated lease backend;
5. втори fresh reconciliation scan;
6. повторно byte-for-byte сравнение между reviewed, first fresh и second fresh;
7. създаване на случаен 128-bit authorization identifier едва след всички
   проверки.

`active`, `lease_unsupported`, `identity_conflict`, incomplete evidence,
duplicate operation, променен directory, journal, temporary inode или друг
finding отказват. Random source не се извиква преди успешното приключване на
всички технически проверки.

Authorization claim съдържа само format/version, случаен authorization ID,
operation ID, exact directory device/inode, canonical evidence SHA-256,
evidence sequence и lease backend. Не съдържа пътища, имена на файлове,
timestamp, PID, размери, ключове, credentials или съдържание.

Prepared authorization може да издаде точно един in-memory claim и отказва
copy, deepcopy и serialization. Claim-ът запазва
`executor_rescan_required = true`, `single_use_claim = true`,
`abandonment_proven = false` и `mutation_permitted = false`. Тези стойности
не доказват автентичност или abandonment. Бъдещият executor трябва да приеме
prepared authorization като еднократен процесен обект и непосредствено преди
всяко действие отново да провери exact directory, evidence, journal, temporary
inode и lease.

Stage 1.22 няма unlink, remove, rename, replace, publish, decrypt, recovery,
cleanup executor, persistent authorization codec, GUI, network или telemetry.

### Stage 1.23 — строго ограничен cleanup executor

Stage 1.23 приема само неизползван `PreparedCleanupAuthorization`. Първият
опит взема еднократния claim преди достъп до файловата система; неуспешният
опит не може да бъде повторен със същото разрешение.

Executor-ът:

1. отваря отново exact private directory и сравнява device/inode;
2. отваря canonical journal без следване на symlink;
3. придобива exact OS-managed exclusive lease и го държи до края;
4. изисква lease backend да съвпада с разрешението;
5. декодира canonical journal и проверява directory, operation и temporary
   inode binding;
6. прави нов bounded пълен reconciliation scan и изисква exact canonical
   evidence SHA-256 и sequence;
7. проверява directory, journal и temporary identity непосредствено преди
   mutation;
8. изисква успешен directory `fsync` preflight преди първото изтриване;
9. премахва първо само exact quarantine temporary и синхронизира directory;
10. проверява отново journal и directory;
11. премахва само exact journal, докато lease остава задържан, и отново
    синхронизира directory.

В модула има точно две unlink цели, и двете се извеждат канонично само от
валидирания operation ID. Caller не подава source, output, journal или
temporary име. Няма glob, recursive cleanup, rename, replace, publish,
decrypt, recovery, GUI, network или telemetry.

Ако temporary е премахнат, но journal не може да бъде премахнат или
синхронизиран, journal остава за нов reconciliation и резултатът изисква
rescan. Ако и двата записа са премахнати, но последният directory fsync е
неуспешен, резултатът е `pair_removed_final_sync_uncertain`, а не успех.
`completed` се връща само след двата unlink и последния успешен fsync.

Lease и authorization са защита срещу конкурентни cooperating MOKOSH процеси
и случайна повторна употреба. Те не са криптографска capability срещу
произволен код, работещ със същия компрометиран потребителски акаунт. Private
directory, операционната система и текущият account остават част от security
boundary; неизвестна filesystem или lock семантика отказва fail-closed.

## 9. Декриптиране и overwrite

- Plaintext се пише във временен файл с `0600`.
- Никакъв plaintext не се публикува преди валидни header, всички frame tags,
  FINAL marker, manifest consistency и signature policy.
- Съществуващ output никога не се презаписва без отделен, видим избор.
- Грешна парола, повреден файл и неподдържана версия имат различни вътрешни кодове,
  но UI не разкрива информация, полезна за password oracle.

## 10. Почистване на оригинала

Почистването е отделна операция след успешно криптиране. То изисква:

- завършен atomic v2 файл;
- пълна verify/decrypt-to-hash проверка;
- съвпадение с хеша и размера на оригинала;
- ясно избран точен оригинален път;
- потребителско потвърждение с обратим вариант „Премести в кошчето“.

Приложението не обещава сигурно физическо изтриване върху SSD, snapshot,
journaling или copy-on-write файлови системи.

## 11. Задължителни parser limits

- header: максимум 65,536 bytes;
- key slots: максимум 64;
- JSON nesting/string/collection limits;
- Argon2 memory/time/parallelism bounds;
- frame plaintext: максимум декларирания chunk size;
- signature: максимум 128 bytes за текущия suite;
- base64 fields: точни decoded размери;
- неизвестен задължителен flag/suite/version: отказ.

## 12. Задължителни тестове преди имплементация да се счита готова

- round-trip за празен, малък, голям и exact-boundary файл;
- wrong password/key и tamper на всеки структурен сегмент;
- duplicate/reordered/missing/extra frame;
- truncated preamble/header/frame/tag/trailer;
- oversized header, slot count, KDF параметри и frame length;
- nonce uniqueness и frame counter overflow;
- output collision и symlink/hardlink сценарии;
- прекъсване преди/след flush, fsync, verify и rename;
- input, променен по време на криптиране;
- MOK1 read-only compatibility;
- hybrid suite: success само с X25519 + ML-KEM;
- доказан отказ без тих downgrade;
- signature valid/invalid/unknown/rotated key;
- гаранция, че логовете не съдържат password, DEK, private key или чувствителен
  абсолютен път.

## 13. Нормативни технически източници

- RFC 9106 — Argon2: https://www.rfc-editor.org/rfc/rfc9106
- RFC 5869 — HKDF: https://www.rfc-editor.org/rfc/rfc5869
- NIST FIPS 203 — ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST SP 800-38D — AES-GCM: https://csrc.nist.gov/pubs/sp/800/38/d/final
- pyca/cryptography AEAD API: https://cryptography.io/en/latest/hazmat/primitives/aead/
- pyca/cryptography ML-KEM API: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/

Преди публично разпространение спецификацията и реализацията подлежат на
независим криптографски и приложен security review.

## 14. Stage 2.48 локален application profile

Stage 2.48 не променя MOKOSH2 wire format, алгоритъм, nonce, AAD, manifest,
frame или trailer. Той активира тесен Linux application profile:

- новото локално криптиране създава unsigned envelope с точно един
  `KEY_VAULT` slot от active key version на отключения профил;
- локалното декриптиране приема unsigned envelope с точно един
  `KEY_VAULT` slot и избира само exact записаната active или retired version;
- signed, password, Contact, multi-slot и непознати policy варианти се отказват
  от този GUI, макар core codec-ът да има по-широки отделно тествани primitives;
- decrypt detection е по exact `MOKOSH2\0` magic, не по extension;
- файл без MOKOSH2 magic никога не се подава автоматично към MOK1 reader;
- encrypt output изисква `.mok2`, explicit new destination и no-clobber;
- source и всички съществуващи файлове се запазват.

Преди пълен residue scan локалният application profile прави cancellation-
aware fail-closed bound check и приема най-много 4096 directory entries.
Над тази граница review е incomplete/`BLOCKED` и не започва file operation.

Atomic hard-link е publication boundary. След него cleanup, fsync, close,
observer или cancellation проблем се отчита като published success с bounded
warning и задължителен review, никога като retryable failure. Преди него fault
остава failure без final output. Exact GUI/service/session/residue договорът е
в `docs/V2_LOCAL_ENCRYPT_DECRYPT_GUI_CONTRACT_BG.md`.

# MOKOSH — Offline Vault Recovery Threat Model и Contract v1

Статус: Stage 2.4 — реализиран in-memory формат и read-only rehearsal.

Този договор е само за възстановимостта на exact MOKOSH Vault keyring. Той не
е software update, application Recovery Capsule, Guardian, Contacts backup,
лицензиране, telemetry или shard recovery.

## 1. Смисъл за потребителя

MOKOSH създава две отделни неща:

1. криптиран recovery record, съдържащ защитено копие на точния Vault keyring;
2. отделен случаен 32-byte recovery ключ, който отваря само този record.

Паролата за нормално отключване не е recovery ключ. Смяна на паролата не сменя
автоматично wrapping ключовете, но създава ново Vault поколение. Rotation на
wrapping key също е отделна, изрична операция на потребителя.

Recovery record и recovery ключът трябва по-късно да се изнасят върху отделни
offline носители. Ако нападател получи и двете, той може да получи целия
keyring и следователно да атакува файловете, защитени от него.

Stage 2.4 още няма export UI или реално публикуване на възстановен Vault. Той
реализира формата, проверките и безопасната проба само в паметта.

## 2. Защитавани активи

- всички active и retired 32-byte Vault wrapping keys;
- точният `active_key_version` и цялата key history;
- връзката към exact 16-byte Vault ID;
- връзката към exact Vault revision и exact encoded Vault SHA-256;
- целостта и автентичността на recovery metadata и keyring payload.

Recovery не съдържа потребителски документи, MOKOSH file envelopes, Contacts,
password, licensing data, telemetry, signing private keys или application
binary.

## 3. Threat model

Договорът отказва:

- wrong recovery key;
- променен preamble, header, ciphertext или GCM tag;
- truncated, trailing, oversized или endless-style bounded input;
- duplicate, missing, unknown или non-canonical JSON полета;
- неизвестен format, purpose, KDF, AEAD или version;
- recovery record за друг Vault ID;
- record от по-стар Vault revision (`stale`);
- текущ Vault, върнат под revision на record-а (`rollback`);
- същия Vault ID/revision с различни exact Vault bytes (`conflict`);
- duplicate recovery record или duplicate recovery ID в един candidate set;
- candidate set, който смесва Vault IDs, revisions или source hashes;
- malformed, duplicate или невалиден keyring вътре в authenticated payload;
- recovery root, който случайно повтаря съществуващ wrapping key;
- setup от locked, expired или legacy schema-1 session.

## 4. Извън гаранцията

Stage 2.4 не може да защити срещу:

- компрометирана операционна система по време на setup или rehearsal;
- memory dump, swap, crash dump, debugger или физически достъп до unlocked RAM;
- нападател, който притежава едновременно record-а и recovery ключа;
- загуба или физическо повреждане и на двете offline копия;
- пълно връщане назад на Vault, recovery record и всички външни anchors;
- слаб или злонамерен бъдещ export/GUI/storage integration;
- липсващи потребителски encrypted файлове — recovery не е document backup.

Python не обещава доказуемо изтриване на всички secret копия от RAM. Кодът
ограничава secret lifetime и не ги връща в rehearsal резултата, но не твърди
абсолютна zeroization.

## 5. Криптографски договор

- Recovery root: точно 32 случайни bytes от OS CSPRNG.
- Recovery ID: точно 16 случайни bytes.
- Nonce: точно 12 случайни bytes.
- KDF: HKDF-SHA-256 до exact 32-byte AEAD key.
- HKDF salt: `None`; domain-separated `info` свързва Vault ID и Recovery ID.
- AEAD: AES-256-GCM.
- Keyring state digest: SHA-256 на exact canonical encoded keyring.
- Source digest: SHA-256 на exact encoded Vault generation.

Точният HKDF `info` е:

`MOKOSH\0VAULT-RECOVERY\0HKDF-SHA-256\0 || vault_id || recovery_id`

Точният AES-GCM AAD е:

`MOKOSH\0VAULT-RECOVERY\0AES-256-GCM\0 || preamble || canonical_header`

Recovery root не се извежда от password, nickname, license, Vault wrapping key
или software version.

## 6. Binary preamble

Всички integers са big-endian.

| Поле | Размер | Стойност |
|---|---:|---|
| magic | 8 bytes | `MOKREC1\0` |
| major | uint8 | `1` |
| minor | uint8 | `0` |
| flags | uint16 | `0` |
| header_len | uint32 | `1..4096` |
| ciphertext_len | uint32 | `17..851968` |

Общата дължина е точно
`preamble_len + header_len + ciphertext_len`. Truncation и trailing bytes се
отказват преди cryptographic работа.

## 7. Canonical authenticated header

Header е strict canonical ASCII-safe JSON с точно:

- `format`: `MOKOSH_VAULT_RECOVERY`;
- `version`: plain integer `1`;
- `purpose`: `OFFLINE_VAULT_KEYRING_RECOVERY`;
- `recovery_id`: canonical unpadded base64url на 16 bytes;
- `vault_id`: canonical unpadded base64url на 16 bytes;
- `source_revision`: integer `1..2^63-1`;
- `source_vault_sha256`: canonical unpadded base64url на 32 bytes;
- `created_utc`: strict `YYYY-MM-DDTHH:MM:SSZ`;
- `kdf`: exact object с `algorithm = HKDF-SHA-256`;
- `aead`: exact object с `algorithm = AES-256-GCM` и 12-byte `nonce`.

Header metadata не съдържа keyring, recovery root или password. Целият header
е в AES-GCM AAD и промяната му се отказва при authentication.

## 8. Authenticated encrypted payload

След успешен decrypt payload е exact canonical JSON с точно:

- `format`: `MOKOSH_VAULT_RECOVERY_PAYLOAD`;
- `version`: plain integer `1`;
- `purpose`: exact recovery purpose;
- exact копия на `recovery_id`, `vault_id`, `source_revision` и
  `source_vault_sha256` от header-а;
- `keyring_sha256`: SHA-256 на canonical keyring bytes;
- `keyring`: exact Stage 2.3 canonical keyring object.

Payload metadata трябва да съвпадне с authenticated header. Keyring се
валидира отново за contiguous versions, един active key, exact retirement
timeline, unique key material, bounded record count и canonical encoding.

## 9. Setup contract

`create_recovery_record` приема само unlocked, unexpired `VaultSession` с
payload schema `2`.

Операцията:

1. проверява session state и timeout;
2. взема exact authenticated current Vault bytes и keyring;
3. доказва, че session не се е променила по време на setup;
4. генерира независими recovery root, recovery ID и nonce;
5. обвързва record-а с exact Vault ID, revision и source SHA-256;
6. криптира exact keyring и проверява собствения резултат чрез decrypt;
7. връща record и recovery root като отделни in-memory стойности.

Няма password параметър. Setup не ротира key, не променя session bytes и не
публикува Vault generation.

## 10. Candidate-set contract

Structural candidate-set проверката приема exact tuple от 1 до 32 records.

- byte-identical record или повторен Recovery ID се отказва като duplicate;
- различен Vault ID се отказва като mixed-vault;
- различен revision или source hash се отказва като mixed state;
- distinct records за един и същ exact Vault state са допустими.

Тази функция не чете директории и не избира автоматично носител.

## 11. Read-only rehearsal

`rehearse_recovery` изисква:

1. един strict recovery record;
2. exact 32-byte recovery root;
3. exact current encoded Vault bytes.

Преди decrypt тя сравнява Vault ID, revision и source hash. След decrypt
проверява payload binding, canonical keyring и keyring digest.

Успехът връща само non-secret evidence:

- Recovery ID;
- Vault ID;
- source revision и source Vault SHA-256;
- creation timestamp;
- keyring SHA-256;
- active key version и брой key records.

Rehearsal не връща keyring или wrapping keys, не приема нов password и няма
filesystem/storage API. Тя не променя Vault generations или user files.

## 12. Freshness правило

Recovery record е използваем само за exact Vault generation, от което е
създаден. След password rewrap, key rotation или migration Vault revision и
exact bytes се променят и предишният record става `stale`.

Това е съзнателна fail-closed политика. Бъдещият UI трябва ясно да поиска нов
recovery setup след успешно публикувана промяна. Той не може тихо да обнови
record-а, защото recovery root трябва да остане под контрола на потребителя.

Това вътрешно revision правило не е проверка за нова версия на приложението.
MOKOSH не прави network update discovery или automatic installation.

## 13. Storage и durability граница

Stage 2.4 е изцяло in-memory и умишлено не import-ва `mokosh_vault_storage`.
То може да докаже contract-а спрямо exact Vault bytes, но не доказва, че тези
bytes вече са последното durable поколение върху конкретен носител.

Бъдещ export integration трябва преди запис да изисква latest verified durable
Stage 2.2 receipt и чист read-only storage scan. При uncertain publish или
storage conflict recovery setup трябва да бъде блокиран.

Stage 2.5 реализира тази отделна POSIX integration граница в
`docs/VAULT_RECOVERY_STORAGE_CONTRACT_BG.md`, без да променя Stage 2.4 binary
format, HKDF/AEAD contract или freshness правила. Actual recovery publish и
password reset остават извън обхвата.

Stage 2.6 използва exact internal Stage 2.4 keyring decrypt само след successful
Stage 2.5 private file verification, за да създаде next-revision encrypted
Vault candidate в паметта. Пълният договор е в
`docs/VAULT_RECOVERY_CANDIDATE_CONTRACT_BG.md`. Recovery record format,
rehearsal result и freshness policy не се променят. Candidate preparation не
е filesystem publish и не връща keyring през public verifier.

Stage 2.7 използва същия record/root отново само за fresh verification на exact
Stage 2.6 handoff преди immutable publish. Пълният договор е в
`docs/VAULT_RECOVERY_PUBLISH_CONTRACT_BG.md`. След successful `R+1` publish
старият record остава byte-exact, но по това freshness правило е stale спрямо
новото latest поколение. Нов recovery setup остава отделно explicit действие.

Stage 2.8 използва стария record/root спрямо explicit source `R`, а не спрямо
latest, за strict read-only reconciliation на uncertain Stage 2.7 outcome.
Това позволява exact source rehearsal дори когато observed latest е `R+1`.
Observed target се приема само след new-password unlock и exact keyring digest
verification. Пълният договор е в
`docs/VAULT_RECOVERY_RECONCILIATION_CONTRACT_BG.md`.


## 14. Забранени действия

Stage 2.4 няма:

- actual recovery publish или password reset;
- автоматичен избор на latest record;
- автоматично repair, migration, rotation, key deletion или file re-encryption;
- filesystem path, open, rename, replace, unlink или cleanup;
- GUI, Contacts, Guardian, shards, network, telemetry или logging;
- software update discovery, download или installation;
- licensing dependency или външен server.

## 15. Задължителни тестове

- exact setup/rehearsal round-trip;
- wrong recovery root и authenticated tamper;
- strict preamble/header/payload bounds и canonical JSON;
- duplicate/missing/unknown fields и malformed keyring;
- unsupported version, purpose, HKDF и AEAD;
- stale след password rewrap и key rotation;
- rollback, mixed-vault и same-revision byte conflict;
- duplicate record/ID и mixed candidate set;
- locked, expired и legacy-session refusal;
- invalid CSPRNG output и encrypt fault без session mutation;
- source-level доказателство за липса на storage, network, logging, publish и
  deletion calls;
- резултат без password, recovery root, wrapping keys, keyring или plaintext.

Тези тестове са вътрешно възпроизводимо доказателство за contract-а. Те не са
независим одит или сертификация.

# Stage 2.45.2 — безопасно отваряне на стари MOK1 файлове

Дата на прегледа: 2026-09-10.

## Казано с обикновени думи

Старият MOK1 формат може правилно да заключва съдържанието на файла, но не
защитава всичко написано в неговото видимо заглавие. Освен това старият код
може да презаписва файл, да последва символна връзка и да зареди целия файл в
паметта.

Stage 2.45.2 прави две практически неща:

1. приложението повече не може да създава нови MOK1 файлове;
2. собственикът все още може да отвори стар MOK1 файл, но чрез ограничен и
   защитен път, който не презаписва съществуващи данни.

Това не включва новото V2 криптиране в главния GUI. `SAFETY_MODE=True` остава.

## Доказани проблеми преди промяната

Read-only диагностиката върху authoritative Stage 2.45.1 потвърди:

- видими `created`, `mode` и `nick` полета;
- JSON header, който не участва в AES-GCM authentication;
- игнориран `alg` и fallback на неизвестен KDF към PBKDF2;
- header без горна граница;
- презаписване на encryption и decryption output;
- следване на output symlink;
- output mode, зависим от caller `umask` (`0644` е възпроизведен);
- двусмислено старо `password|nickname` съединяване;
- whole-file reads в четирите стари entry points.

Това са отделни доказани свойства. Диагностичният PASS означава, че тестът ги
е възпроизвел; не означава, че старият код е бил сигурен.

## Новият fail-closed договор

### Създаване

`encrypt_file` и `encrypt_file_with_raw_key` винаги връщат типизиран
`MOK1EncryptionRetiredError`. Отказът е преди source/output access, KDF,
randomness или друга криптографска операция. Следователно не се създава нов
файл с историческите MOK1 ограничения.

### Съвместимо декриптиране

`decrypt_file` и `decrypt_file_with_raw_key` остават само за възстановяване на
съществуващи файлове. Те:

- приемат единствено regular, non-symlink source с непроменена identity;
- четат на блокове до 1 MiB, а не целия файл наведнъж;
- ограничават JSON header-а до 65 536 bytes;
- отказват duplicate keys, invalid UTF-8, non-object JSON, NaN/Infinity,
  неизвестни magic/version/algorithm/KDF и невалидни KDF параметри;
- изпълняват само историческите exact параметри:
  Argon2id `t=2, m=65536 KiB, p=4`, PBKDF2-HMAC-SHA256 `200000`, или exact
  `raw-key` entry point;
- удостоверяват целия ciphertext и tag в първи read-only pass;
- отварят същия source inode повторно и удостоверяват payload-а повторно;
- записват plaintext само в private `0600` quarantine;
- публикуват чрез atomic no-clobber hard link само след успешна authentication;
- отказват existing output, output symlink, unsafe parent или source drift;
- при грешка премахват собствените temp/journal записи и не публикуват
  plaintext.

Оригиналът не се изтрива или променя. Няма автоматична миграция.

## Ограничение, което не може да се поправи със задна дата

Историческият writer е извиквал AES-GCM с `associated_data=None`. Затова
старите `created`, `mode`, `nick`, `contact_id` и подобни header полета нямат
криптографски tag. Кодът не може честно да ги направи автентични, без да знае
паролата и да създаде нов формат.

Stage 2.45.2 не скрива това като „минал тест“. Тези полета са advisory и не
могат да определят output path, permissions, algorithm или trust решение.
Тестът умишлено доказва едновременно, че advisory tamper остава възможен за
старите bytes и че не може да управлява публикувания plaintext файл.

Старото `password|nickname` съединяване също е запазено единствено за
съвместимост. Премахването му би направило някои съществуващи файлове
нечетими. Понеже нов MOK1 writer няма, нови двусмислени credentials не могат
да бъдат създадени. Пълното премахване на тези две исторически ограничения
става чрез успешно декриптиране и отделно, изрично V2 повторно криптиране.

## Точен обхват

Окончателният freeze съдържа точно 30 paths:

- `crypto_core.py` — единствената production промяна;
- `tests/test_crypto_core.py` и `tests/test_crypto_core_negative.py` —
  практически compatibility, negative, filesystem и residue tests;
- exact 20 predecessor tests — само новия разрешен SHA-256 на
  `crypto_core.py`;
- два second-order audit tests — само пет нови SHA-256 стойности на променени
  predecessor tests; още една second-order стойност е в вече включен direct
  predecessor test;
- този документ и четирите постоянни status/evidence/crosswalk/session
  записа.

Първоначалният 28-path списък е оттеглен преди project mutation, защото
едностепенната dependency проверка е пропуснала двата second-order tests.
Окончателната проверка е рекурсивна до липса на нови hash consumers.
Точният резултат е 20 direct и 6 second-order edges, без consumer извън
30-файловия freeze.

`mokosh_gui.py`, `contacts_core.py`, requirements и всички V2 модули са
byte-exact. Stage 2.46 localization остава paused.

## Стандарти и граници на твърденията

- NIST SP 800-38D определя GCM като authenticated encryption with associated
  data. MOK1 payload authentication е съвместимо проверена, но header AAD не
  съществува и не се твърди.
- `cryptography` 49.0.0 документира, че associated data се удостоверява само
  когато еднаквите bytes участват при encrypt и decrypt, както и че invalid
  tag трябва да води до отказ.
- OWASP публикува Argon2id минимум `19 MiB, t=2, p=1`. Историческите параметри
  са по-високи от този минимум, но това не е benchmark, endorsement или
  compliance доказателство.
- Регламент (ЕС) 2024/2847 (CRA) има отделна applicability и distribution
  граница. Този engineering Stage не е conformity assessment, CE marking,
  certification, legal opinion или разрешение за пазарно разпространение.

Първични източници:

- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://cryptography.io/en/49.0.0/hazmat/primitives/aead/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://eur-lex.europa.eu/eli/reg/2024/2847/oj

## Следваща функционална граница

След окончателния Stage 2.45.2 checkpoint следва отделен малък Stage за
нормалното password-based V2 file service и практичното му свързване с GUI.
Това не е отложена поправка на MOK1: MOK1 creation вече е затворено, а
историческото четене е containment-only.

# MOKOSH — потребителска автономност, преносимост и official entitlement

Статус: прието бъдещо архитектурно и продуктово изискване. Не е реализирано в
текущия runtime, не е част от Stage 2.11 и не активира network или licensing
код.

## 1. Основен принцип

MOKOSH не превръща потребителя в зависим от ежедневна връзка, cloud account,
платежен оператор, конкретна машина или една операционна система.

Потребителят контролира:

- encrypted Vault, recovery material и собствените си файлове;
- кога да извърши update проверка;
- кога да смени или преинсталира машина;
- кои до три собствени устройства да използват official entitlement;
- произволна комбинация от поддържаните Windows, macOS и Linux версии.

Нито лиценз, нито server outage може да заключи decrypt, recovery или export.

## 2. Разделяне на четири независими области

MOKOSH поддържа отделни trust и data граници за:

1. open-source права върху публичния source;
2. official product identity, signing и trusted updates;
3. commercial entitlement за official builds и услуги;
4. потребителски Vault, recovery и plaintext данни.

Компрометиране, изтичане или прекратяване на една област не дава автоматичен
достъп до друга.

## 3. Open source и платен official продукт

Public source може да бъде четен, проверяван, копиран, променян и развиван
според бъдещия OSI-approved лиценз.

Платеният official MOKOSH предоставя проверима цялост:

- official signed installer за поддържана OS/architecture;
- exact release manifest, hashes, SBOM и provenance;
- trusted update channel;
- official security evidence и known limitations;
- entitlement за official operations на до три лични устройства;
- support и documented recovery/incident process.

Fork може да промени или премахне entitlement проверка, но тогава не е
official MOKOSH и няма official signing chain, branding или support promise.
Device ограничението не се представя като ограничение върху open-source
правата.

Точният open-source лиценз, commercial terms, contribution policy и trademark
policy се избират след dependency, business и legal review. Ако е нужен
dual-licensing модел, той се активира само ако copyright и dependency правата
го позволяват.

## 4. Точно правило за три устройства

Един personal official entitlement допуска най-много три едновременно активни
device certificates.

- устройствата могат да бъдат с еднакви или различни поддържани OS;
- download на installers не се брои като activation;
- преинсталация или смяна на OS изисква нов device key и controlled slot flow;
- четвърти active certificate се отказва от authoritative activation service;
- entitlement не отслабва криптографията и не създава различни Standard/Pro
  security версии;
- organizational и multi-seat условия са отделен бъдещ продукт contract.

„Стриктно“ означава exact server-side slot policy и fail-closed certificate
verification в непроменения official build. То не означава невъзможност
привилегирован attacker да промени open-source client; такъв client не е
official.

### 4.1. Бъдещо групово и организационно ползване

Ако personal продуктът получи положителна beta оценка и проектът има реален
капацитет за сигурна поддръжка, може да се предложи отделен multi-seat
official entitlement.

Предварителни примерни диапазони са:

- малка група — от 5 до 20 ползватели;
- разширена група — приблизително от 25 до 40 ползватели.

Това са ориентири, а не окончателни ценови или договорни граници. Преди
реализация диапазоните трябва да станат непрекъснати и недвусмислени,
включително за 21–24 ползватели. Тогава се определят и exact seat/device
правилата, цената, transfer, renewal и support условията.

Груповият план използва същия пълен official build и същата криптографска
защита. Той не създава по-слаб „business“ режим и не дава на group
administrator, MOKOSH service или платежния оператор достъп до:

- user Vault, passwords, keys или recovery material;
- файлове, Contacts или история на cryptographic operations;
- plaintext, remote decrypt, remote wipe или key escrow.

Seat management и cryptographic trust са отделни. Бъдещ group administrator
може да assign, release или reset-ва само anonymous signed seat/device
certificates в рамките на закупения брой. Всеки ползвател запазва независими
локални secrets; няма общ master decrypt key за организацията.

Revoked или изтекъл group seat може да спре само нови licensed operations след
обявения grace period. Decrypt, recovery и export на вече притежаваните данни
остават достъпни по същото правило като при personal entitlement.

## 5. Device activation key

Всяка official инсталация създава независима activation key pair само за
license proof-of-possession.

Activation private key:

- не е Vault key, wrapping key, file key, recovery root или Contact identity;
- никога не се изпраща към activation service;
- не се включва в support report, telemetry или source bundle;
- се пази в platform-protected или hardware-backed storage, когато това е
  надеждно налично;
- няма право да подписва release, update, recovery или user-file операция.

Activation public key може да бъде изпратен за подписване на device
certificate. Липсата на надежден protected storage на дадена платформа се
оценява изрично преди support; не се прикрива с общо твърдение за защита.

## 6. Минимална activation service

Избран е минимален server-side service само за:

- проверка на валиден commercial entitlement;
- броене на максимум три active device public keys;
- издаване, refresh, deactivation и revocation на подписани certificates;
- ограничен lost-device reset;
- anti-replay и abuse-resistance evidence.

Услугата не участва в:

- encrypt, decrypt, recovery, export или Integrity & Health Check;
- създаване или съхраняване на Vault/recovery ключове;
- Contact или user-file operations;
- remote command, code execution, configuration push или deletion;
- software update payload delivery.

License-signing private key е отделен от root, release, recovery, evidence и
platform-signing ключовете.

## 7. Минимални server данни

Activation service обработва само необходимото:

- случаен entitlement identifier;
- device activation public key и негов digest;
- slot index от 1 до 3;
- certificate serial/version и policy version;
- issued, refreshed, expires, deactivated или revoked status/time;
- минимална order връзка, необходима за entitlement и support;
- bounded anti-abuse и security audit records.

Услугата не получава:

- имена или съдържание на файлове;
- Vault ID, recovery ID, keyring или cryptographic user keys;
- Contacts, nickname, filesystem paths или clipboard;
- hostname, MAC address, disk serial или скрит hardware fingerprint;
- история на encrypt/decrypt operations;
- source code от локални промени.

Network доставчикът и hosting инфраструктурата неизбежно могат да обработят IP,
TLS и operational logs. Това се описва в Privacy Policy с purpose, retention,
access и deletion правила; не се нарича „никакви данни“.

## 8. Online и offline activation

Два user-controlled потока са допустими:

1. direct TLS activation от приложението след ясно потвърждение;
2. offline challenge/response файл, пренесен чрез друго online устройство до
   official portal и обратно.

И в двата случая service вижда само bounded activation request. Offline
challenge не премахва server authority; той само позволява криптографската
машина да остане без директна network връзка.

Няма background activation без предварително описана и избрана policy.

## 9. Certificate refresh и честота

За practically strict active-device policy official certificate може да има
bounded срок и refresh. Предварителната посока е:

- не повече от две или три license refresh проверки месечно;
- никакво hourly или daily задължително обаждане;
- видим local status и дата на следващата допустима проверка;
- signed offline grace period при временна липса на интернет;
- rate limiting и backoff без aggressive retry;
- exact периоди се замразяват едва след privacy, outage, clock и usability
  тестове.

Deactivated offline device може да запази стар certificate до неговото
изтичане. Незабавно remote revocation и продължителна offline работа не могат
да бъдат едновременно абсолютни. UI и commercial terms описват тази граница
честно.

## 10. Изтичане и server outage

Невалиден, изтекъл или непотвърден official entitlement никога не блокира:

- decrypt на съществуващи файлове;
- recovery rehearsal или recovery на потребителски данни;
- export на Vault, recovery material и public evidence;
- Integrity & Health Check;
- проверка на signatures, hashes и source evidence.

След изрично документиран grace period official build може да спре само нови
encrypt и нови Contact operations. Той не изтрива ключове, не поврежда Vault и
не променя user files.

При outage съществуващият signed certificate и grace policy се проверяват
локално. Няма silent fallback към unsigned entitlement.

## 11. Deactivation и прехвърляне

Нормална смяна на машина:

1. старото устройство създава signed slot-release request;
2. потребителят вижда точно кой anonymous slot освобождава;
3. service маркира slot-а като освободен;
4. новото устройство създава свой activation key;
5. service издава нов certificate след fresh max-three check.

License transfer не съдържа Vault, recovery root или user files. Данните се
пренасят отделно от потребителя чрез encrypted и verified MOKOSH формати.

## 12. Загубена или повредена машина

Загубата на устройство не трябва да заключва човека завинаги.

Предвижда се bounded reset с:

- проверка на commercial entitlement чрез Merchant of Record/order evidence;
- показване само на anonymous slots и activation dates;
- rate limit, cooldown и audit receipt;
- изрично предупреждение, че стар offline certificate може да остане валиден
  до expiry;
- без искане на Vault password, keys, recovery material или файлове.

Няма remote wipe, kill switch или опит да се изтрият данни от изгубената
машина.

## 13. Cross-platform portability

MOKOSH v2 formats, Vault и recovery contracts са platform-neutral на ниво
данни. Platform package и runtime са отделни.

При преминаване между Windows, macOS и Linux:

- изтегля се exact official installer за target OS/architecture;
- проверяват се platform signature, MOKOSH manifest и SHA-256;
- активира се нов или освободен device slot;
- encrypted Vault/recovery material се копира от потребителя;
- old machine не е необходима за decrypt, ако потребителят разполага с
  валидните си secrets/recovery material;
- няма automatic cloud sync или server-side data migration.

Compatibility matrix и migration rules се публикуват за всеки release.

## 14. Update и security-review cadence

Project maintainers извършват минимум две и целево до три контролирани
security/dependency/test проверки месечно през активната support фаза.

Това не означава две или три user-device връзки за update. Software update
discovery е отделно от license refresh:

- „Check for updates“ работи ръчно по подразбиране;
- optional automatic manifest fetch се активира само с informed opt-in;
- fetch-ва се public signed metadata без entitlement/device identifier;
- няма automatic download, install или activation;
- update metadata никога не съдържа remote command;
- изтекла metadata не блокира decrypt/recovery/export.

Security bulletin, release или „няма промяна“ се публикува само с честно
обозначен self-assessment/independent-review status.

## 15. User interface

Потребителят вижда отделно:

- official release и integrity status;
- entitlement period и offline grace;
- active slots 1–3 без скрито device profiling;
- next permitted license refresh;
- last user-requested update check;
- deactivation, transfer и lost-device reset действия;
- ясна граница между update, license и cryptographic data.

Никой screen не представя entitlement като ownership над user data.

## 16. Threat model и честни ограничения

Моделът отчита:

- copied activation files;
- replay, rollback и duplicated certificate;
- forged service response;
- clock rollback и snapshot restore;
- cloned software key при compromised OS;
- fourth-device activation;
- concurrent activation/deactivation race;
- lost device и malicious reset;
- service/database/key compromise;
- merchant outage и account recovery fraud;
- modified open-source client;
- offline revocation delay.

Нито software licensing, нито device certificate е защита срещу root/admin,
kernel compromise, physical capture или променен fork. Security claim се
ограничава до проверения official threat model.

## 17. Задължителни тестове

- exact maximum-three slot enforcement и fourth-device refusal;
- всяка комбинация от supported OS families;
- certificate signature, device-key binding и proof-of-possession;
- duplicate, replay, rollback, stale, forged и mixed-entitlement отказ;
- concurrent requests и crash/fault около slot transitions;
- normal deactivation, cross-OS replacement и lost-device reset;
- service outage, DNS/TLS failure, expired certificate и grace boundaries;
- clock rollback/snapshot limitations и user-visible warning;
- no Vault/user secret fields in request, response, logs или exceptions;
- decrypt/recovery/export винаги достъпни при license failure;
- no remote deletion, command execution, update installation или key access;
- open-source fork ясно различим от official signed build;
- privacy retention, access и deletion evidence;
- accessibility и localization на всички security/license съобщения.
- exact group seat limit, concurrent assignment и over-capacity refusal;
- group administrator няма достъп до user keys, Vault, files или Contacts;
- seat release, replacement и offboarding не повреждат и не заключват данни;
- personal и group certificates не могат да се смесват или преизползват;
- всички договорени seat ranges са непрекъснати и UI не оставя неясни
  диапазони.

## 18. Условие за реализация

Няма implementation преди:

- отделен licensing threat model;
- exact open-source/commercial/dependency legal review;
- contribution и trademark policy;
- data-protection impact assessment според реалния service design;
- protocol/schema contract и key-management ceremony;
- server outage и incident-response план;
- Windows, macOS и Linux protected-storage evaluation;
- full negative, concurrency, fault и privacy tests;
- beta usability review за transfer/reset/grace поведението;
- отделен group entitlement, administrator и offboarding threat model преди
  multi-seat beta;
- exact непрекъснати seat bands, per-user device policy, pricing и support
  capacity decision;
- ясно публикувани ограничения и support process.

Този документ не е лицензен текст, Privacy Policy или правен съвет. Той е
архитектурна граница, която бъдещите договори и implementation трябва да
спазят.

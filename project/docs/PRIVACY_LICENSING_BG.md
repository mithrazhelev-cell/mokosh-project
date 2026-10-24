# MOKOSH — поверително лицензиране и плащания

Статус: бъдещо изискване с окончателен избор преди публичната beta.

## Основен принцип

Самото приложение MOKOSH не създава задължителни потребителски акаунти и не
изгражда собствена база с платежни профили. То не съхранява:

- платежни карти и банкови данни;
- имена или съдържание на файлове;
- контакти, ключове и recovery информация;
- телеметрия за използването без изрично съгласие.

Merchant of Record неизбежно обработва необходимите за покупката платежни,
фактурни и контактни данни според закона и собствената си Privacy Policy.
MOKOSH получава само минималните order/licensing данни, необходими за издаване,
подновяване, refund, fraud/chargeback обработка и законова отчетност. Те не се
свързват с файлове, ключове, контакти или история на използването.

## Платежен оператор

Плащанията, задължителните платежни данни, данъците, фактурите,
възстановяването на суми и chargeback процедурите се обработват от
утвърден Merchant of Record.

Предварително предпочитан оператор: **Paddle**.

Причини за избора:

- утвърден Merchant of Record за software и digital products;
- subscriptions, локализиран checkout, фактури и customer portal;
- обработване на VAT/sales tax, refunds, fraud и chargebacks;
- ясна стандартна такса от 5% + 50¢ на транзакция към момента на оценката;
- възможност MOKOSH да запази собствен независим подписан offline лиценз;
- липса на необходимост платежният оператор да получава криптографски данни.

Резервен кандидат: **Lemon Squeezy**, особено ако неговото вградено software
licensing и по-лесното начално внедряване се окажат по-подходящи. Към момента на
оценката основната му такса е 5% + 50¢, но са възможни допълнителни такси за
international, PayPal, subscription и payout операции.

**FastSpring** остава кандидат при по-голям международен обем или необходимост
от по-специализирано обслужване на desktop software; цената му се договаря и
трябва да бъде получена като писмена оферта.

Окончателният избор се прави непосредствено преди публичната beta след:

- писмено потвърждение, че операторът приема легален desktop cryptography
  продукт с локално криптиране;
- проверка на държавите, валутите, tax-inclusive pricing, фактурите и refunds;
- privacy и security review на checkout, dashboard, API и webhooks;
- проверка на точните такси, reserve/hold условията и payout правилата;
- тест на покупка, отказ, chargeback, подновяване и смяна на оператор;
- правен преглед на действащите условия, restricted-products policy и DPA.

MOKOSH запазва възможност да смени оператора. Криптографските файлове,
декриптирането и recovery никога не зависят от продължаващата работа на Paddle
или друг платежен оператор.

Creator платформи от типа Buy Me a Coffee не са основен платежен канал
за професионалната версия на MOKOSH.

## Официален сайт и разделение на отговорностите

Официалният MOKOSH домейн предоставя:

- проверима информация за продукта и ограниченията му;
- downloads, release signatures и public fingerprints;
- документация, supported-platform matrix и security evidence;
- Privacy Policy, лицензни условия, refund и support информация;
- връзка към hosted checkout на избрания Merchant of Record.

Платежният оператор предоставя checkout, платежни методи, фактура/разписка,
данъци, subscription management, refund и chargeback обработка. Данни за карта
никога не преминават през MOKOSH приложението или собствения му сайт.

Покупката не създава задължителен MOKOSH cloud account. Ако операторът изисква
имейл за разписка, лиценз или законова комуникация, това се показва ясно преди
плащане. Адресът не се използва за marketing без отделно съгласие.

## Open-source модел и official commercial entitlement

Public source се предоставя според бъдещ exact OSI-approved лиценз. Това
позволява проверка, използване, развитие и разпространение според неговите
условия.

Платеният продукт е official signed distribution, trusted update/evidence
chain, tested installers и support entitlement. Commercial условията не се
представят като отнемане на вече дадени open-source права. Fork или modified
client не е official MOKOSH и не получава official signing keys, branding или
support promise.

Точният open-source лиценз, commercial terms и евентуален dual-licensing модел
се избират само след dependency, copyright, contribution, business и legal
review.

## Една пълна official версия

MOKOSH се предлага като **една цялостна версия**, а не като отслабена Standard
и пълна Pro версия. Всички клиенти получават еднакви:

- криптографски алгоритми и key-slot режими;
- Guardian, Integrity & Health Check и Recovery Capsule;
- локални и Contact функции;
- защити срещу downgrade и подмяна;
- езици, accessibility и подписани security updates.

Различават се само срокът, броят разрешени лични устройства и евентуалното ниво
на организационна поддръжка — никога качеството на криптографската защита.

Първоначално се предпочитат предплатени периоди:

- 30 дни;
- 12 месеца;
- без задължително автоматично подновяване;
- без MOKOSH потребителски профил;
- с подписан локално проверим лицензен файл или код.

Един personal official entitlement позволява до три едновременно активни
собствени устройства с произволна комбинация от поддържаните Windows, macOS и
Linux версии.

Избран е минимален activation service, който брои само три anonymous device
public keys и издава локално проверими signed certificates. Той не получава
файлове, Vault/recovery данни, cryptographic user keys, hostname, MAC address,
disk serial или скрит device fingerprint.

Нормална deactivation освобождава slot. Загубена машина използва bounded reset
с rate limit и audit receipt; няма remote wipe. Exact protocol, certificate
period и offline grace се определят след threat-model и cross-platform тестове.

Приложението предупреждава локално за изтичане на лиценза, например
30, 14, 7 и 1 ден предварително.

## Задължителни гаранции

- Изтекъл лиценз никога не блокира декриптирането на съществуващи файлове.
- Recovery, export и Integrity & Health Check остават достъпни.
- Няма дистанционно изтриване или блокиране на ключове.
- Проблем при платежния оператор не заключва данните.
- След разумен гратисен срок може да бъде ограничено само създаването на
  нови криптирани файлове и нови Contact операции.
- Няма по-слаба криптография или липсваща security функция заради вида лиценз.
- Лицензната проверка не получава файлови имена, ключове или контакти.
- Не се използва скрит device fingerprint.
- Избраната activation проверка използва само случаен entitlement identifier,
  device public key, slot/certificate status и минимална order връзка.
- License refresh не е hourly/daily; предварителната посока е най-много две или
  три проверки месечно с видим status и signed offline grace.
- Software update discovery е отделено от license refresh и не изпраща
  entitlement/device identifier.
- Частният ключ за подписване на лицензи не се включва в приложението.
- В приложението присъства само публичният ключ за проверка.
- Предвижда се безопасна работа при временно липсваща интернет връзка.
- Четвърти active official device certificate се отказва fail-closed.
- Modified fork може да премахне entitlement проверката, но не е official
  MOKOSH; ограничението не се представя като контрол над open-source кода.

Пълният архитектурен договор е в
`docs/USER_AUTONOMY_PORTABILITY_ENTITLEMENT_BG.md`.

## Предварителна ценова посока

Цените са за една и съща пълна версия и не са окончателни.

Предварителна рамка по етапи:

- затворено техническо тестване — безплатно за поканени тестери;
- публична beta — безплатна или ограничена начална година около £39–£49;
- стабилна версия — около £7.90 за 30 дни;
- стабилна версия — около £69 за 12 месеца;
- възможна начална цена около £49 за първата година.

Цената за 12 месеца е предпочитаната основна оферта. Месечният период осигурява
гъвкавост, без годишният клиент да плаща равностойността на дванадесет отделни
месеца.

Цените пред клиента се показват ясно като tax-inclusive, когато операторът и
местното законодателство го позволяват. Преди потвърждение checkout-ът показва
крайната сума, валутата, срока, renewal настройката и refund условията.

Няма отделен Pro продукт. Бъдещ multi-seat или organizational лиценз може да
използва същия пълен software build и да се различава само по броя места,
deployment правата, фактурирането и поддръжката.

Ако personal версията получи положителна beta оценка и има доказан капацитет
за поддръжка, предварителните примери за group plans са 5–20 и приблизително
25–40 ползватели. Това не са окончателни bands или цени; преди продажба
границите трябва да бъдат непрекъснати и ясни, включително за 21–24
ползватели.

Group plan управлява само anonymous seat/device certificates. Няма общ
organization decrypt key, server key escrow или administrator достъп до Vault,
пароли, recovery material, файлове, Contacts и cryptographic operation history.
Освобождаване или прекратяване на seat не блокира decrypt, recovery или export.

Окончателните цени се определят след beta тестовете, оценка на пазара,
комисионите, данъците и реалните разходи за поддръжка.

## Предстоящо уточняване

Преди реалното внедряване трябва да бъдат определени и тествани:

- избраният Merchant of Record;
- писменото му приемане на MOKOSH и действащите restricted-product условия;
- точният поток за покупка, подновяване, отказ и refund;
- форматът и подписът на лицензния файл;
- exact three-slot activation, refresh, deactivation и lost-device reset flow;
- exact group seat ranges, per-seat device policy, administrator permissions,
  offboarding и over-capacity flow;
- минималните service данни, retention, access и deletion правила;
- platform-protected activation key storage и fallback policy;
- cross-OS portability и compatibility matrix;
- разделянето на release-signing, evidence-signing и license-signing ключовете;
- offline и grace-period поведението;
- service outage, clock rollback, snapshot, clone и replay поведението;
- защита срещу подмяна без събиране на излишни лични данни;
- безопасна миграция към друг Merchant of Record;
- потребителските съобщения на всички поддържани езици;
- Privacy Policy, лицензионните условия и описанието на фактурите;
- аварийното поведение при прекратяване или смяна на платежния оператор.

## Източници за текущата предварителна оценка

- Paddle MoR и стандартна такса:
  <https://www.paddle.com/paddle-101>
- Paddle описание на Merchant of Record:
  <https://developer.paddle.com/get-started/how-paddle-works>
- Lemon Squeezy pricing и software license keys:
  <https://www.lemonsqueezy.com/pricing>
- Lemon Squeezy fee breakdown:
  <https://docs.lemonsqueezy.com/help/getting-started/fees>
- FastSpring Merchant of Record:
  <https://fastspring.com/merchant-of-record/>
- FastSpring pricing:
  <https://fastspring.com/pricing/>

Условията и цените се проверяват отново непосредствено преди внедряване и се
замразяват с дата и версия в съответния decision record.

Този модул не се активира преди отделен threat model, тестове и преглед
на правните и платежните условия.

## Stage 2.47 recovery privacy и licensing граница — 2026-09-13

Optional recovery не активира лицензиране, плащане, account service,
telemetry или network. Recovery root-ът и 25-те думи не се изпращат към
Merchant of Record, license server, email, cloud или друг външен получател.
Избраните локални пътища не се записват в `profile.json` и не се използват за
идентификация или аналитика.

MOKOSH не пази автоматично фразата. Ако ползвателят избере отделен файлов
носител, създаденият emergency sheet е plain ASCII secret с private Linux
права, не криптиран blob. Това е изричен usability избор за offline recovery;
потребителят трябва да държи носителя отделно от `.mokr`. Хартиеният вариант
не създава phrase файл. Снимка, email и cloud sync не се препоръчват.

GUI изчиства current/new password и manually entered phrase полетата и скрива
показаната setup фраза при lock/close. Python/Tk не дава доказуема пълна
memory zeroisation, а компрометирана ОС, screenshot/camera, root/admin и
физическа кражба са извън тази privacy гаранция.

Stage 2.47 vendорва само английския BIP-0039 wordlist като речник. Exact
provenance, upstream commit, SHA-256 и MIT notice са в
`third_party/bip39/PROVENANCE_BG.md`, `english.txt` и `LICENSE`. MOKOSH-RP1 не
е BIP39 wallet functionality. Съществуващите proprietary/commercial licensing
решения на MOKOSH не се променят от разрешения upstream MIT речник; окончателен
release все пак изисква обичайния legal/license review.

### Коригиращо privacy допълнение — 2026-09-15

Новият `recovery-state/state.json` е локална публична lifecycle бележка и не
съдържа думи, пароли, recovery/Vault keys, Vault bytes или външни пътища.
Тя е bounded и private-permission файл, но не се представя като криптографски
secret. GUI изчиства всички въведени recovery думи и двете нови пароли при
всеки локален или core отказ, маскира ги отново и пази само не-secret избраните
пътища. Няма нов dependency, network, telemetry или licensing delta.

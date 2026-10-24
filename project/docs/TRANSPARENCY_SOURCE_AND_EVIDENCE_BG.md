# MOKOSH — прозрачност, изходен код и доказателства

Статус: избран е controlled official open-source модел като бъдещо продуктово
изискване след стабилизиране на core, application service layer и GUI adapter.
Това не е част от Stage 2.11 и не активира нова runtime функция.

## 1. Цел

MOKOSH трябва да може да бъде разбран и проверяван не само от програмисти, а и
от обикновен потребител. Бъдещият интерфейс включва отделен read-only прозорец
„Прозрачност и архитектура“, който представя приложението модул по модул с
кратко и ясно обяснение.

Прозорецът не е заместител на публикувания exact source, build инструкции,
тестове, подписани release artifacts, SBOM или независим security review. Той
е достъпен образователен слой върху тези доказателства.

## 2. Какво показва прозорецът

За всеки включен модул се показват поне:

- стабилно име и версия;
- кратко предназначение на разбираем език;
- към коя функционална област принадлежи;
- допустими входове и изходи;
- кои други модули извиква;
- trust boundary и security assumptions;
- дали чете или променя filesystem;
- дали използва network, clock, randomness, subprocess или GUI;
- дали може да вижда password, private key, recovery material или plaintext;
- какви mutation операции може да поиска или изпълни;
- криптографски алгоритми и versioned formats;
- приложими стандарти и проектни договори;
- точните test modules и последния потвърден test result;
- SHA-256 или друг release binding към exact публикувания source;
- известни ограничения и неизпълнени бъдещи зависимости.

Информацията се представя в предвидим ред и с отделни раздели:

1. общ преглед;
2. карта на модулите и връзките;
3. data flow и trust boundaries;
4. permissions и mutations;
5. алгоритми и формати;
6. тестове и evidence;
7. dependencies, SBOM и лицензи;
8. known limitations и security review status.

## 3. Източник на истината

GUI описанията не се пишат ръчно независимо от кода. Преди реализация се
определя versioned machine-readable module registry, от който се създават:

- bounded GUI presentation;
- human-readable документация;
- release evidence index;
- automated consistency tests.

Registry записът се свързва с exact release identifier, source commit,
manifest digest и module digest. Несъвпадащ, липсващ или неподдържан запис се
показва като непроверен, а не се заменя с общо успокоително съобщение.

## 4. Пълен source и кратко обяснение

Краткото GUI описание не трябва да скрива действителния код. Exact release
source се предоставя публично в отделен проверим source archive или repository
tag с:

- подписан release manifest;
- source commit и tag;
- SHA-256 на source archive;
- dependency lock и SBOM;
- build инструкции;
- test и evidence инструкции;
- ясно посочен лиценз;
- списък на известните ограничения.

Прозорецът предоставя module-by-module read-only достъп до пълния exact source
от локалния проверен source bundle и кратко обяснение към всеки модул. Той не
парсва или изпълнява показвания код. Показването на source не дава runtime
authority и не зарежда модулите динамично.

## 5. Избран модел: controlled official open source

MOKOSH избира истински open-source модел с публично проверим exact source и
строго контролиран official project.

Open-source лицензът позволява на получателите да:

- четат и независимо да проверяват кода;
- копират source според лицензионните условия;
- правят собствени промени и forks;
- разпространяват допустими derived versions според лиценза.

Тези права не дават право за промяна на official MOKOSH repository, branch,
release, website, signing key или update channel. Публичният write access е
забранен. Външни специалисти могат да подават issues, design proposals,
security reports и reviewable patches/pull requests, но нищо не се приема
автоматично.

Само изрично определени maintainers могат да приемат промяна след:

1. provenance и license проверка;
2. architectural и security review;
3. всички приложими positive, negative, fault и compatibility tests;
4. clean protected-branch merge;
5. подписан release manifest и official build process.

Official branches се защитават от direct public push, deletion и force-push.
Преди merge се изискват status checks, review и resolution на откритите
въпроси. Exact policy се version-ва преди публичния repository launch.

## 6. Official и modified builds

Official MOKOSH е само release, който едновременно има:

- разрешен product name и branding;
- commit/tag в official repository;
- валиден official release-manifest signature;
- exact component hashes и supported dependency lock;
- публикуван build/evidence record;
- непроменена trusted-update signer chain.

Fork или modified build може да съществува по силата на open-source лиценза,
но не се представя като official MOKOSH. Лицензът и отделна trademark policy
могат да изискват ясно означение, различно име/version и забрана за използване
на official logo, signing keys или misleading update channel.

Official Integrity & Health Check не изтрива modified build или данни. Той
само отказва да го представи като official verified release и не смесва негови
компоненти с official update.

## 7. Копиране, развитие и отговорност

Няма надежден технически начин публикуван source да бъде едновременно
open source и некопируем. Разрешеното от избрания лиценз копиране, review,
forking и development не се представя като кражба.

Проектът отговаря за:

- ясен copyright и license notice;
- точни attribution и redistribution условия;
- разграничаване на official от modified builds;
- защита на signing private keys и търговски марки;
- protected official branches и минимален maintainer access;
- ясно приемане или отказ на external contribution без automatic merge;
- липса на подвеждащи твърдения за одит или сертификация;
- публикуване на security contact и vulnerability process.

Чуждо действие в нарушение на лиценза не може да бъде предотвратено само чрез
GUI забрана за маркиране или бутон „Копирай“. При реален публичен release
точният OSI-approved лиценз, copyright notices, contribution policy и
trademark policy се преглеждат от квалифициран специалист.

Предпочитаната посока е copyleft лиценз, който при разпространение на modified
version запазва достъпа до corresponding source и изисква промените да бъдат
ясно означени. GPLv3 и EUPL-1.2 са кандидати за отделен compatibility,
dependency, business и legal review; лиценз не се избира само по име.

Open-source MOKOSH може да предлага платени official signed builds, удобен
installer, update assurance и support. Трябва честно да се приеме, че лицензът
може да позволява други лица да разпространяват свои допустими builds.

## 8. Защо banking apps понякога блокират screenshot

Те защитават показани account данни, пароли, balances или payment операции, а
не програмния си код.

- Android предоставя `FLAG_SECURE`, който иска от системата прозорецът да не
  присъства в screenshots или non-secure displays.
- Windows предоставя `SetWindowDisplayAffinity` и
  `WDA_EXCLUDEFROMCAPTURE` за top-level window, но Microsoft изрично посочва,
  че това не е DRM и няма абсолютна гаранция.
- Apple платформите предоставят capture-state сигнали, чрез които приложението
  може да скрие или redact-не чувствителни полета по време на screen sharing,
  recording или remote control.
- Linux desktop поведението зависи от compositor, X11/Wayland, desktop portal
  и capture tool; няма единна cross-platform гаранция, че приложението може да
  забрани всяка снимка.

Нито един software флаг не спира външна камера, привилегирован или
компрометиран OS, modified client, virtual machine capture или човек с достъп
до публикувания source archive.

## 9. Решение за MOKOSH

Screen-capture защита се оценява отделно за чувствителните operational
прозорци, например password entry, private-key reveal или recovery material.
Тя е:

- platform-specific;
- best-effort и честно описана;
- изключена от security claims, които изискват абсолютна гаранция;
- придружена от redaction/minimal-display дизайн;
- тествана отделно на всяка поддържана OS версия;
- без скрит monitoring, telemetry или запис на screenshots.

Прозорецът „Прозрачност и архитектура“ не съдържа secrets и по подразбиране не
изисква screenshot blocking. Прозрачността, accessibility и независимият
review имат по-голяма стойност от неефективна забрана за копиране.

Този transparency прозорец е строго read-only: няма editor, save/apply patch,
code execution, dynamic import, plugin loading или contribution submission към
runtime. Public source и hashes могат да се маркират и копират за audit,
accessibility и проверка.

## 10. Забранено съдържание в transparency view

Прозорецът никога не показва:

- реални passwords, private keys или recovery roots;
- plaintext или потребителски файлове;
- реални contacts, paths, filenames или clipboard content;
- runtime exception text с чувствителни стойности;
- device fingerprint, license secret или signing private key;
- непроверен online content, реклама или telemetry identifiers.

Всички примери са fixed, synthetic и ясно означени.

## 11. Accessibility и usability

Забраната за text selection не се приема като security control. Тя може да
пречи на screen readers, keyboard navigation, цитиране на hashes и независим
review.

Затова бъдещият adapter трябва:

- да е read-only спрямо проекта и runtime state;
- да позволява keyboard navigation и screen-reader labels;
- да позволява копиране на public source, hashes, version IDs, license и
  evidence references;
- да не позволява editing, code execution, dynamic imports или mutation;
- да има fixed bounded content и safe search/filter;
- да работи offline.

## 12. Какво е доказателство и какво не е

Полезни reproducible доказателства са:

- source-to-release manifest binding;
- signed artifacts и public fingerprints;
- reproducible или контролирани build records;
- dependency lock и SBOM;
- positive, negative, fault и interoperability tests;
- static analysis и dependency review;
- documented threat model и security boundaries;
- public known limitations;
- independent findings и remediation records, когато съществуват.

GUI текст, зелен знак или голям брой собствени тестове сами по себе си не са
независим одит, сертификация или доказателство срещу compromised runtime.

## 13. Release условия

Transparency функцията не влиза в production преди:

1. стабилен application service layer и GUI adapter;
2. versioned module-registry contract;
3. exact release/source/manifest binding;
4. bounded presentation без runtime secrets;
5. accessibility и localization review;
6. tests за missing, forged, stale и mixed-version registry data;
7. no-network, no-execution и no-mutation static checks;
8. отделно решение за лиценз и публично разпространение;
9. security review на platform-specific capture protections;
10. ясно публикувани limitations;
11. protected official branches и documented maintainer/contribution policy;
12. signed official releases и trademark separation от modified builds.

## 14. Официални технически ориентири

- Open Source Initiative — Open Source Definition:
  <https://opensource.org/osd>
- GitHub — protected branches:
  <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches>
- GNU — GPLv3:
  <https://www.gnu.org/licenses/gpl-3.0.html>
- Android — screenshot detection и `FLAG_SECURE`:
  <https://developer.android.com/about/versions/14/features/screenshot-detection>
- Microsoft — `SetWindowDisplayAffinity`:
  <https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity>
- Apple — защита на sensitive content при screen sharing/capture:
  <https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing>
- XDG Desktop Portal — Screenshot:
  <https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Screenshot.html>
- XDG Desktop Portal — ScreenCast:
  <https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html>

Тези източници са технически ориентири, а не правен съвет или обещание за
еднакво поведение на всички OS версии.

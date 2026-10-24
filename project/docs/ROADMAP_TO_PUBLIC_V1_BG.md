# MOKOSH Agent — ориентировъчен roadmap до публична v1

Статус: работен план, последна актуализация 2026-09-18.

Този документ е прогноза, а не обещание за дата, цена, сертификация или
приемане от конкретна държава или платежен оператор. Сигурността и коректното
поведение имат предимство пред календарния срок.

## Основен принцип

MOKOSH трябва да бъде полезен и безопасен за клиента по проверим начин. Това
защитава и проекта: намалява скритите рискове, подвеждащите твърдения,
повредените данни, неясните плащания и зависимостта от външни сървъри.

- Данните, ключовете и recovery материалите остават под контрола на клиента.
- Няма задължителен cloud account за криптографските функции.
- Проблем с лиценз или платежен оператор не заключва декриптирането и export-а.
- Няма скрита телеметрия или изпращане на диагностични данни.
- Няма твърдение „одитирано“, ако няма действителен независим одит.
- Публичната версия се активира само след изпълнени release gates.

## Реалистична времева рамка

При приблизително 5–7 активни часа на работен ден:

- затворена beta: ориентировъчно 4–6 месеца;
- подготвена платена публична v1: ориентировъчно 6–9 месеца.

При приблизително 2–3 часа дневно:

- ориентировъчно 9–14 месеца до публична v1.

Срокът се удължава при криптографски redesign, cross-platform дефекти,
неуспешна code-signing регистрация, payment onboarding, правни ограничения или
сериозни findings от beta/security review.

## Технически работни области

### 1. Завършване на безопасния файлов lifecycle

Ориентир: 4–7 работни дни след Stage 1.21.

- non-mutating authorization contract;
- еднократен executor с fresh rescan и exact inode проверки;
- crash/fault тестове около всяка permitted mutation;
- никакво изтриване на оригинала в този lifecycle.

### 2. Key Vault, профил и recovery

Ориентир: 20–35 работни дни.

- реално криптирано Vault хранилище;
- отключване, lock timeout и безопасно затваряне;
- password change чрез rewrap;
- recovery setup и пробно възстановяване;
- signed Recovery Capsule и Guardian contracts;
- versioned migrations с rollback и отрицателни тестове.

### 3. Contacts и trust workflow

Ориентир: 12–20 работни дни.

- contact packages и fingerprint verification;
- X25519 + ML-KEM-768 без downgrade;
- Ed25519 signature verification, отделено от trust;
- key rotation, revoke и version history;
- QR/import/export без автоматично доверяване.

### 4. Application service layer и GUI

Ориентир: 20–35 работни дни.

- една контролирана API граница към криптографския core;
- Local, Contacts и Sandbox workflow;
- cancellation, progress и безопасни error messages;
- достъпност, малки екрани и keyboard navigation;
- отделен read-only прозорец „Прозрачност и архитектура“ върху versioned
  module registry с full public source view, без secrets, editor, code
  execution или mutation;
- оригиналите не се премахват без отделна verified операция.

### 5. Езици

Ориентир: 10–20 работни дни плюс последваща човешка проверка.

Поддържани езици:

- български;
- английски;
- руски;
- немски;
- френски;
- испански;
- италиански;
- бразилски португалски;
- опростен китайски.

Приложението не използва runtime online translator. Текстовете са статични
locale ресурси и работят offline. Българският и английският са контролни
източници. Machine translation може да се използва само като чернова;
security, recovery, payment и legal текстовете изискват терминологичен review.

Възможен локален workflow: self-hosted Weblate и LibreTranslate.

- https://docs.weblate.org/en/latest/
- https://docs.weblate.org/en/latest/admin/machine.html

### 6. Windows, macOS и Linux distribution

Ориентир: 15–25 работни дни плюс времето за identity verification.

- reproducible или контролирани builds;
- подписан manifest и SHA-256 за всеки artifact;
- Windows installer и Authenticode/Artifact Signing;
- macOS signing и notarization;
- Linux packages и repository/package signatures;
- exact source commit/archive, license, SBOM и build instructions, свързани с
  подписания release manifest;
- protected official branches, documented contribution policy и trusted
  signing chain, които отделят official MOKOSH от forks/modified builds;
- clean-install, upgrade, rollback и uninstall тестове;
- отделни реални машини/VM за поддържаните версии.

Официални ориентири:

- Apple Developer Program: 99 USD годишно;
- Microsoft Artifact Signing: приблизително 10 USD месечно според публикувания
  Microsoft ориентир за non-Store distribution.

- https://developer.apple.com/support/compare-memberships/
- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation

### 7. Integrity, Guardian и updates

Ориентир: 15–25 работни дни.

- подписан Integrity & Health Check;
- signed update manifest и rollback protection;
- минимум две и целево до три maintainer security/dependency/test проверки
  месечно без задължителна user-device update връзка;
- manual-by-default update discovery и отделен opt-in automatic manifest fetch;
- Recovery Capsule без скрито дистанционно управление;
- shard-based recovery само след отделен threat model;
- локална диагностика и доброволен support report;
- никакво автоматично изпращане към скрит адрес.

### 8. Лицензиране и плащане

Ориентир: 8–15 работни дни плюс onboarding на оператора.

- лицензът е отделен от ключовете и encrypted data;
- signed local entitlement с offline grace period;
- максимум три active anonymous device certificates в произволна комбинация
  от поддържаните Windows, macOS и Linux версии;
- бъдещи group plans само след успешна personal beta и доказан support
  capacity; примерни диапазони 5–20 и приблизително 25–40 ползватели;
- преди multi-seat продажба — непрекъснати exact seat bands, включително ясно
  правило за 21–24, и отделен administrator/offboarding threat model;
- group seat management без общ decrypt key и без administrator/service достъп
  до user Vault, recovery, файлове или Contacts;
- minimal activation service само за issue/refresh/deactivate/reset на slots,
  без Vault, recovery, Contact, filename или hidden fingerprint данни;
- cross-OS replacement, lost-device reset и service-outage contract;
- expiry предупреждения без заключване на decrypt/recovery/export;
- без задължителен MOKOSH потребителски профил;
- hosted checkout при Merchant of Record;
- ясни refund, renewal и cancellation правила.

Предварителен основен кандидат: Paddle. Резервни кандидати: Lemon Squeezy и
FastSpring. Окончателният избор се прави 3–5 седмици преди платената beta след
проверка на държавите, KYC, payout, fees и условията за криптографски софтуер.

Публикуваният Paddle pay-as-you-go ориентир е 5% + 0.50 USD на транзакция.
Merchant of Record обработва необходимите платежни и данъчни данни; MOKOSH не
получава card data, файлове, ключове или recovery информация.

- https://www.paddle.com/resources/b2b-payments
- https://docs.lemonsqueezy.com/help/payments/merchant-of-record

### 9. Домейн, сайт и downloads

Ориентир: 8–15 работни дни; част може да върви успоредно с beta.

- проверка на име, domain и trademark conflict;
- domain registrar с DNSSEC;
- статичен многоезичен сайт;
- download страници с version, signature и SHA-256;
- security, privacy, licensing, refund и support страници;
- release notes и known limitations;
- `support@domain` без публикуване на лични вътрешни адреси.

Предварителен вариант: Cloudflare Registrar и Cloudflare Pages. Registrar
обявява at-cost domain регистрация и подновяване; началният статичен сайт може
да използва безплатен план.

- https://developers.cloudflare.com/registrar/
- https://developers.cloudflare.com/pages/

Ориентировъчен domain разход: около 10–25 GBP годишно според TLD и наличност.

### 10. Beta и release evidence

Ориентир: 20–40 календарни дни.

- clean machines и supported OS matrix;
- negative, corruption, race, power-loss и fault-injection тестове;
- malware/installer false-positive проверка;
- reproducible evidence bundles;
- преглед дали module-by-module transparency view съвпада с exact release
  source, permissions, tests и known limitations;
- цел поне три отделни външни професионални review преминавания — архитектура,
  криптография и release/packaging — според наличния бюджет;
- всяко собствено тестване е означено честно като self-assessment;
- findings се поправят или се публикуват като known limitations.

## Минимален начален бюджет

Ориентир за първата година, без платен професионален одит, адвокат и платени
човешки преводачи:

- domain: приблизително 10–25 GBP годишно;
- статичен hosting: възможно 0 GBP в началото;
- Windows signing: приблизително 10 USD месечно, когато започнат release-и;
- Apple Developer Program: 99 USD годишно;
- Merchant of Record: предимно transaction fees при реални продажби.

Практически минимален ориентир: около 100–250 GBP за първата година, ако
платените услуги се активират едва непосредствено преди beta.

Не са включени business registration, trademark, счетоводство, юридическа
консултация, независим security audit или допълнителна инфраструктура.

## Release gates

Публична платена v1 не се публикува, докато едновременно не са изпълнени:

1. няма known plaintext-loss или key-loss дефект;
2. всички задължителни тестове минават без skipped security tests;
3. release artifacts са подписани за съответната платформа;
4. update и recovery механизмите са fail-closed;
5. деветте езика имат всички задължителни security/payments текстове;
6. сайтът публикува hashes, signatures, limitations и support процес;
7. payment flow не получава ключове, файлове или recovery данни;
8. Privacy Policy, license terms и refund условията са налични;
9. beta findings са прегледани и класифицирани;
10. няма твърдение за независим одит без действително доказателство.
11. exact OSI-approved open-source лиценз, contribution policy и trademark
    policy са публикувани след dependency, business и legal review;
12. публичният transparency/evidence index е свързан с exact release и не
    съдържа secrets, executable content или mutation authority.
13. official branches са protected, public direct push е забранен и само
    authorized maintainers могат да приемат проверени промени.

## Международна приложимост

Целта е техническа съвместимост и ясна документация за широк международен
пазар. Не се обещава законна продажба във всяка държава без изключение.
Реалната наличност зависи от export/sanctions правила, местни потребителски
закони, поддържаните от платежния оператор държави и приложимите business и
tax задължения.

## Stage 2.48 progress note — local V2 vertical slice

Изолираният Stage 2.48 кандидат реализира първия тесен vertical slice от
област 4: един Linux local file, session-bound active/retired Vault key,
MOKOSH2 encrypt/decrypt, progress/cancel, no-overwrite и exact residue review.
Това намалява неизвестността около service/GUI boundary, но не завършва
„Application service layer and GUI“ като roadmap област.

След Stage 2.48 отделно остават:

- practical EN/BG visual matrix и accessibility review;
- clean-original authorization като собствен high-risk stage;
- batch/folder UX и bounded resource policy;
- Contacts/trust/signature workflows;
- Sandbox import/export;
- Windows/macOS native filesystem, packaging и signing;
- transparency/help/evidence windows;
- distribution, beta, external reviews и всички release gates по-горе.

Local V2 кандидатът не променя сроковете в обещание и не разрешава публична
употреба с единствени ценни копия. Package dry-run, explicit apply,
post-apply verification, human visual evidence, commit/tag и следващите
release gates остават отделни решения.

Case 01 от physical human matrix откри видими action controls извън default
geometry, невъзстановен parent след `PRESERVE`, два невидими Tab stop-а и
разрешен повторен run в `CLEANABLE`, `BLOCKED` и `PUBLISHED`. Резултатът е
`FAIL_REQUIRES_FIX_AND_RETEST`, не частичен PASS. Приетият corrective scope е
точно 34 paths; correction package, pinned regression, independent verifier и
affected human replay от Case 01 остават задължителни преди Case 02–16.

Cases 2–4 впоследствие потвърдиха още четири bounded GUI/harness дефекта:
off-screen focus без viewport follow, disabled focused action без handoff,
`NOT_V2` вместо human label `NOT V2` и silent synthetic chooser controls.
Приетият D1–D4 overlay е точно 11 от frozen 34 paths и не променя crypto,
Vault, MOKOSH2 format, filesystem/pipeline/lifecycle policy или roadmap scope.
Корекцията е подготвена negative-first само в изолирано копие. Pinned
read-only dry-run, отделно apply решение, independent verifier и affected
human replay остават release-blocking; Case 4 е 12 PASS / 4 FAIL, не human
PASS. Това не съкращава или прескача нито един следващ roadmap gate.

D1–D4 live overlay и read-only verifier впоследствие са технически PASS, но
продълженият Case 4 откри D5–D7: stale keyboard focus след state click,
reactivation auto-scroll към същия stale target и липсваща `Return` активация
при работещ `Space`. Приет е exact 9-path corrective overlay само за shared
focus/scroll helper-а, synthetic runner-а, техните тестове и петте evidence
документа. Това не разширява product scope и не променя crypto, Vault,
MOKOSH2, filesystem, publication или cleanup policy.

Нов roadmap gate за този checkpoint: след всяка промяна на window state се
оглеждат и двата края на scroll viewport-а; D5–D7 negative-first regression,
pinned read-only dry-run и affected human replay трябва да са PASS преди
Stage 2.48 да продължи. Текущите isolated резултати са `32/32` focused и
`51/51` target PASS. Affected scratch е 245 теста без failure/error, но с един
environment-only ML-KEM skip; full scratch е 2454 теста с 0 assertion failures,
3 липсващи-`argon2` import errors и 7 environment skips. Те са non-PASS;
D5–D7 R1 transport self-tests и byte-identical rebuild са PASS, но pinned
user-machine execution и human gate остават pending. Transport-ът няма apply
route и не разрешава live mutation. Няма commit, tag или Stage PASS.

# MOKOSH — Trusted Update, Integrity и Recovery Architecture

Статус: задължително бъдещо архитектурно изискване. Не е активирано в
текущия runtime и не разрешава автоматична промяна на приложението.

## Основен принцип

MOKOSH следва модела:

1. защити;
2. открий;
3. докажи;
4. възстанови;
5. провери повторно.

Приложението не се доверява на име, местоположение, версия, timestamp,
сървър, AI отговор или отделен hash без валидна криптографска връзка към
одобрен root of trust.

Самопроверката може да бъде автоматична. Самопромяната не е автоматична.

## Историческа и техническа основа

Архитектурата използва утвърдени принципи:

- принципът на Керкхофс: защитата зависи от тайните ключове, а не от
  скриването на алгоритъма или кода;
- подписан manifest и hash chain, използвани от защитени package системи;
- TUF модели за offline root, разделени роли, threshold signatures,
  rollback, freeze и mix-and-match защита;
- NIST SP 800-193 модел Protect, Detect, Recover;
- SLSA и in-toto provenance за връзката source, build и release;
- reproducible builds за независимо сравняване на source и binary;
- transparency log като незадължително допълнително публично доказателство.

Подписът доказва кой ключ е одобрил artifact-а. Той самостоятелно не
доказва, че build системата, source кодът или подписващият ключ не са били
компрометирани.

## Threat model

Системата трябва да отчита поне:

- случайно повреждане или частично записване;
- злонамерена промяна на модул;
- подмяна на manifest или Recovery Capsule;
- rollback към известна уязвима версия;
- freeze върху остаряла update информация;
- mix-and-match на компоненти от различни releases;
- компрометиран download сайт или mirror;
- компрометиран отделен signing ключ;
- компрометирана build среда;
- подмяна между проверка и активиране;
- symlink, hardlink, inode и path race атаки;
- прекъсване на ток или crash по време на recovery;
- злонамерен или грешен AI patch;
- пълен административен контрол над локалната операционна система.

## Root of trust и ключови роли

MOKOSH използва разделени роли:

- Root — определя допустимите ключове и тяхната ротация;
- Release — подписва официалните release manifests;
- Recovery — подписва Recovery Capsule и recovery policy;
- Emergency/Revoke — разрешава отмяна на компрометиран ключ;
- Platform — Windows, macOS и Linux package signing, отделно от вътрешния
  MOKOSH подпис.

Root private keys никога не присъстват в приложението, source архива,
build машината или AI диагностичния пакет.

Предпочитаната бъдеща root политика е 2-of-3 независими подписи. Това може
да бъде реализирано като два валидни подписа от три отделни ключа, без
необходимост от сложна threshold cryptography.

Ключовете се пазят на отделни offline носители и физически места.
Процедурите за създаване, backup, rotation, revocation и загуба се
документират и тестват.

## Подписан release manifest

Всеки release има canonical подписан manifest, който съдържа:

- product и release identifier;
- semantic и monotonic security version;
- целева операционна система и архитектура;
- точен hash и размер на всеки компонент;
- тип и предназначение на компонента;
- минимална допустима версия;
- списък на забранените уязвими версии;
- dependency lock и SBOM digest;
- build provenance digest;
- recovery compatibility;
- signer role и key version;
- policy version;
- допустими migration правила.

Hash без валиден manifest signature не е доказателство за автентичност.

Компоненти от различни release identifiers не могат да бъдат смесвани.

## Anti-rollback и offline поведение

MOKOSH помни най-високата потвърдена security version.

По-стара версия се отказва, освен при отделен подписан emergency recovery
процес с ясно предупреждение и доказана съвместимост.

Изтекла online update metadata спира само приемането на нов update. Тя не:

- блокира локалното декриптиране;
- заключва потребителски данни;
- деактивира вече проверена версия;
- изтрива или променя файлове.

Offline Recovery Capsule има отделна политика и не става неизползваема
единствено поради липса на интернет.

## Доброволна update проверка и maintainers cadence

През активната support фаза project maintainers извършват минимум две и целево
до три контролирани security, dependency и test проверки месечно.

Това не създава задължителна network честота за user device:

- „Check for updates“ е ръчно действие по подразбиране;
- automatic manifest fetch е отделна opt-in настройка;
- изтегля се само public signed metadata без entitlement/device identifier;
- няма automatic download, install, migration или activation;
- няма remote command, kill switch или configuration push;
- липсваща или изтекла metadata не блокира decrypt, recovery или export.

License certificate refresh е отделен bounded protocol и не може да доставя
software update. Неговата честота, privacy и offline grace граници са в
`docs/USER_AUTONOMY_PORTABILITY_ENTITLEMENT_BG.md`.

## Source, build и release provenance

Вграденият source самостоятелно не доказва произхода на изпълнявания код.

Преди публична v1 се изискват:

- заключени версии и hashes на dependencies;
- документирана build среда;
- SBOM за всяка платформа;
- подписано build provenance;
- reproducible build, доколкото платформата позволява;
- независимо повторно изграждане и сравнение;
- проверка на Python runtime, native libraries и package metadata;
- архивирани test results и release evidence.

При невъзпроизводим platform artifact причините и ограниченията се
документират честно.

## Локален Integrity & Health Check

Локалната проверка работи без интернет и проверява:

- release manifest и подписите;
- hashes, размери и identity на модулите;
- разрешената версия и anti-rollback състоянието;
- зависимости и platform runtime;
- права за достъп и опасни filesystem свойства;
- Guardian и Recovery Capsule;
- последната контролирана recovery операция;
- задължителните безопасни тестове.

Резултатите са:

- HEALTHY;
- DEGRADED;
- REPAIR_AVAILABLE;
- ENVIRONMENT_UNTRUSTED;
- RECOVERY_REQUIRED;
- UNSUPPORTED.

При неяснота системата отказва fail-closed и не показва подвеждащо
„всичко е наред“.

## Recovery Capsule и A/B recovery

Проверена версия не се променя на място.

Recovery използва:

1. текуща активна позиция;
2. отделна staging или резервна позиция;
3. quarantine за временните резултати;
4. пълна проверка преди превключване;
5. atomic activation;
6. post-activation health check;
7. контролиран rollback само към разрешена версия.

Recovery средата трябва да бъде по-малка и по-проста от основното
приложение и да не зависи от потенциално повредения runtime.

Оригиналните потребителски данни и криптографски ключове не са част от
application recovery package.

## Resilient recovery shards

Shard recovery използва erasure coding или threshold reconstruction, а не
непроверимо „фрактално“ копиране.

Всеки shard съдържа:

- release identifier;
- shard index и coding parameters;
- hash;
- връзка към подписания manifest;
- достатъчна информация за проверка, но не signing private key.

Нито един shard не се изпълнява директно. Първо се възстановява целият
artifact, после се проверява manifest, signature, hash и policy.

Повреден, чужд или смесен shard се отказва.

## AI-assisted diagnostics

AI е недоверен консултант, а не част от root of trust.

Само след изрично решение на потребителя може да бъде създаден ограничен
диагностичен export с:

- публичен или изрично избран source код;
- release manifest;
- hashes и безопасни test results;
- несекретни error codes;
- предварително премахнати лични данни.

Не се предоставят:

- Vault или потребителски документи;
- пароли, DEK, KEK, private keys или recovery secrets;
- контакти;
- чувствителни пътища и имена;
- live контрол върху приложението;
- право за изпълнение или запис върху машината.

AI резултатът може да бъде само анализ, предложение, patch и тестове.

AI patch:

- влиза в quarantine;
- няма подпис и доверие по подразбиране;
- минава schema, static, unit, negative и fault-injection тестове;
- показва exact diff;
- изисква човешко одобрение;
- става официален само след MOKOSH release signing процедура.

AI никога няма достъп до release private keys и не може да подпише,
активира или разпространи официална поправка.

## Известяване и поверителност

Критичният проблем първо се показва локално.

Изпращането към MOKOSH Support е доброволно и показва предварително точния
диагностичен payload.

Няма:

- скрита телеметрия;
- скрити имейл адреси в клиента;
- тайно дистанционно управление;
- автоматично изпращане на код или данни;
- remote kill switch.

Официалният support endpoint може да препраща потвърден критичен сигнал
към защитени имейл или push канали на поддръжката, без да разкрива
вътрешните получатели в приложението.

## Ограничение при компрометирана операционна система

Проверка, извършена изцяло от компрометирана ОС, не може да бъде абсолютен
източник на доверие.

При съмнение за административен или kernel compromise MOKOSH показва
ENVIRONMENT_UNTRUSTED и насочва към:

- външна подписана Recovery Capsule;
- clean boot recovery среда;
- проверка от друга доверена машина;
- чиста преинсталация при необходимост.

TPM, Secure Boot и platform keystore могат да бъдат допълнителни сигнали,
но не заменят MOKOSH manifest, signatures и external recovery.

## Задължителни тестове

Преди активиране се покриват:

- променен или липсващ модул;
- променен manifest или signature;
- rollback, freeze и mix-and-match;
- компрометиран или отменен ключ;
- грешна платформа и архитектура;
- подмяна след проверка;
- crash и power-loss във всяка recovery фаза;
- повредена или непълна Recovery Capsule;
- недостатъчни, чужди или смесени shards;
- злонамерен AI patch;
- повредена A/B позиция;
- неуспешен post-activation health check;
- offline работа;
- отказ на update/recovery без загуба на потребителски данни.

Security тест не се пропуска тихо.

## Публични доказателства

За публична версия се публикуват според възможностите:

- release manifest и signatures;
- SHA-256 hashes;
- SBOM;
- build provenance;
- reproducibility резултати;
- security test summary;
- известни ограничения;
- key fingerprints и rotation history;
- по желание transparency-log inclusion proof.

Това са проверими технически доказателства, но не се представят като
държавна сертификация или независим одит, ако такива реално няма.

## Условие за реализация

Механизмът не се активира преди:

- отделен threat model;
- key-management ceremony;
- recovery и incident-response процедура;
- cross-platform отрицателни и fault-injection тестове;
- външен професионален review според риска и бюджета;
- ясни потребителски текстове на всички поддържани езици.

## Основни референции

- NIST SP 800-193 Platform Firmware Resiliency Guidelines
- The Update Framework specification
- Uptane deployment guidance
- SLSA specification
- in-toto supply-chain integrity framework
- Reproducible Builds project
- Sigstore/Rekor transparency model
- Debian apt-secure chain of trust

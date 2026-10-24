# MOKOSH Agent — бъдещи незадължителни възможности

Този документ съдържа идеи за бъдеща оценка. Те не са одобрени за
реализация и не променят текущия архитектурен план.

## Незадължителен хардуерен криптографски ключ

Статус: идея за бъдещо проучване.

Възможност за използване на USB устройство със защитен криптографски чип,
в който частният ключ се създава и остава неизвлекаем.

Основни правила:

- функцията е изключена по подразбиране;
- не е необходима за нормалната работа на MOKOSH;
- активира се само по изричен избор на потребителя;
- не трябва да бъде обикновен key файл върху USB памет;
- може да работи като бъдещ hardware-token key slot;
- възможни режими са „парола и устройство“ или допълнителен резервен slot;
- преди активиране се изисква резервен ключ или recovery механизъм;
- загубата на единственото устройство не трябва да остава необяснен риск;
- компрометиран компютър все още може да прочете вече отворен plaintext;
- интерфейсът трябва ясно да обяснява ползите, ограниченията и риска;
- ако бъде реализирана, функцията трябва да присъства на всички поддържани езици.

Възможността ще бъде оценена едва след стабилизиране на:

- MOKOSH v2 core;
- Ed25519 подписите;
- key slots;
- recovery механизма;
- streaming и atomic file pipeline;
- основния интерфейс и неговия security review.

Добавянето ѝ изисква отделен threat model, хардуерна съвместимост, тестове
при загубено или повредено устройство и независим security review.

## Прозрачност, архитектура и source evidence

Статус: избран е controlled official open-source модел като бъдещо продуктово
изискване; не е част от текущия Stage 2.11.

След стабилизиране на core, application service layer и GUI adapter се планира
отделен read-only прозорец „Прозрачност и архитектура“. Той представя MOKOSH
модул по модул с предназначение, входове/изходи, trust boundaries, permissions,
алгоритми, тестове, evidence и known limitations.

Прозорецът не изпълнява показвания код, не зарежда модули динамично и не вижда
passwords, private keys, recovery material, plaintext или потребителски paths.
Той е образователен слой и не замества public exact source archive/repository
tag, подписан manifest, SBOM, build инструкции или независим review.

Получателите могат да четат, проверяват, копират и създават forks според
бъдещия OSI-approved лиценз, но нямат write access до official MOKOSH.
Външните идеи, findings и patches са предложения; само определени maintainers
могат да ги приемат след review, tests и protected-branch policy. Official
releases се различават чрез trusted signing chain, exact manifest, branding и
trademark policy.

Прозорецът позволява копиране на public source, hashes и evidence за независима
проверка, но няма editor, apply patch, code execution, dynamic import или
runtime contribution API. Platform-specific capture protection се оценява
отделно само за чувствителни operational прозорци и остава best-effort.

Пълният договор е в `docs/TRANSPARENCY_SOURCE_AND_EVIDENCE_BG.md`.

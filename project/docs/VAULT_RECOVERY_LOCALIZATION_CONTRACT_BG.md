# MOKOSH — Recovery Localization Registry Contract v1

Статус: Stage 2.13 — реализиран versioned, bounded и fail-closed
localization registry за exact Stage 2.10 message/confirmation keys и
детерминистично локализиране на validated Stage 2.12 view.

Този модул съдържа фиксиран български и английски потребителски текст. Той
не създава прозорец, не приема натискане, не потвърждава workflow и не
изпълнява recovery операция.

## 1. Смисъл за потребителя

Stage 2.10 определя какво трябва да бъде съобщено чрез fixed keys. Stage
2.12 определя видимия ред на messages и confirmation controls, но до този
етап не съдържа човешки текст.

Stage 2.13 добавя проверимата езикова граница:

- всеки message key има точно един български и един английски текст;
- всеки confirmation key има точно един български и един английски текст;
- липсващ или непознат език се отказва, без скрита замяна;
- текстът е фиксиран в кода, ограничен по размер и без template input;
- route, gate order и confirmation semantics не могат да се променят от
  превода.

## 2. Scope и trust граница

Единственият render input е exact validated
`VaultRecoveryUIAdapterView` от Stage 2.12 и exact plain-string locale ID.

Модулът приема само:

- `bg-BG`;
- `en-GB`.

Той не приема external catalog, translation file, mapping, template,
placeholder, user text, callback, widget, executor или operation object.

## 3. Public API

Public функциите са точно:

- `supported_recovery_locale_ids()`;
- `get_recovery_localization_catalog(locale_id)`;
- `localize_recovery_ui_adapter_view(view, locale_id)`.

Няма public register, extend, merge, fallback, interpolate, format, widget,
acknowledge, unlock, setup, candidate, publish или dispatch функция.

## 4. Exact locale allowlist

Версия 1 има exact ordered allowlist `("bg-BG", "en-GB")`.

Locale ID трябва да е exact plain `str`. Case normalization, whitespace
trim, language-only downgrade, region substitution и OS-locale fallback не
се извършват.

Например `bg`, `en`, `en-US`, `BG-bg`, `bg-BG ` и `ru-RU` се отказват.
Отказът не връща частично локализиран view.

## 5. Versioned immutable registry

`RECOVERY_LOCALIZATION_REGISTRY` е immutable tuple в allowlist order.
Всеки `VaultRecoveryLocalizationCatalog` съдържа:

- exact locale enum;
- format `MOKOSH_VAULT_RECOVERY_LOCALIZATION`;
- version `1`;
- domain-separated catalog SHA-256;
- exact ordered tuple за всички message translations;
- exact ordered tuple за всички confirmation translations;
- fixed completeness/no-fallback/no-interpolation flags.

Catalog dataclasses са frozen и slots-based. Няма mutable global mapping.

## 6. Пълно one-to-one покритие

Всеки каталог трябва да съдържа точно:

- всички 24 `RecoveryPresentationMessageKey` стойности;
- всички 9 `RecoveryPresentationConfirmationKey` стойности.

Order-ът е enum-definition order и е част от version 1. Missing, extra,
duplicate, reordered, wrong-enum и mixed-locale entries се отказват.

Safe-looking, но различен текст също се отказва. Това предотвратява runtime
подмяна на смисъла чрез direct construction на catalog object.

## 7. Fixed reviewed text

Текстовете са literals в модула. Няма:

- `%`, `{name}` или друг runtime placeholder contract;
- user-controlled interpolation;
- route-dependent free text;
- exception, path, filename, ID, digest или secret insertion;
- online translation или downloadable language pack.

`fixed_reviewed_text = true` означава, че текстът е фиксиран и прегледан като
част от този source/test contract. Това не е независима лингвистична,
юридическа или accessibility сертификация.

## 8. Unicode и resource policy

Всеки text е:

- exact built-in `str`;
- от 1 до 240 Unicode code points;
- до 768 UTF-8 bytes;
- NFC-normalized;
- без leading/trailing whitespace;
- без `{` и `}` template markers;
- без Unicode category `C` characters;
- без bidi embedding, override, isolate, pop и boundary controls.

Това отказва NUL, newline, tab, bidi override и невидими format controls.
Политиката е предназначена за текущите български/английски каталози; нова
писмена система изисква отделен review и нова версия на policy-то.

## 9. Catalog digest

Catalog SHA-256 е върху domain-separated length-prefixed transcript от:

- exact locale ID;
- entry kind;
- exact ordered key;
- exact UTF-8 text.

Digest-ът открива смяна на locale, key order или text. Той не е digital
signature, release signature, independent provenance proof или защита при
компрометиран interpreter.

## 10. Exact Stage 2.12 source validation

Преди localization се изисква exact `VaultRecoveryUIAdapterView` и се
изпълнява отново пълната Stage 2.12 validation:

- format/version и presentation digest;
- classification, decision и route state;
- exact ordered messages и gate markers;
- exact ordered confirmation controls;
- stable ordinals, visibility и default-false policy;
- terminal/downstream semantics;
- всички no-auto-accept/no-authority flags.

Malformed, hidden, partial, reordered или forged source view се отказва.

## 11. Localized message records

Всеки `RecoveryLocalizedMessageItem` съдържа само:

- stable ordinal;
- exact locale enum;
- exact message key;
- exact fixed visible text;
- exact identical accessible text;
- gate marker;
- `visible = true`.

Message key order и gate order трябва да съвпадат с exact Stage 2.12 route.

## 12. Localized confirmation records

Всеки `RecoveryLocalizedConfirmationControl` съдържа:

- stable ordinal;
- exact locale enum;
- exact confirmation key;
- exact fixed visible/accessible text;
- `visible = true`;
- `required = true`;
- `individually_selectable = true`;
- `default_selected = false`.

Това е display record, не checkbox/widget и не selection event.

## 13. Localized view

`VaultRecoveryLocalizedUIAdapterView` съдържа:

- Stage 2.12 presentation digest;
- selected locale и catalog digest;
- classification, decision, route и adapter state;
- exact localized messages и confirmations;
- terminal/downstream flags;
- fixed validation, completeness, no-fallback и no-authority flags.

Adapter state остава `AWAITING_USER_CONFIRMATIONS`. Localization не
потвърждава, не консумира и не променя Stage 2.12 lifecycle.

## 14. Fail-closed без fallback

Unsupported locale, malformed registry, missing translation, unsafe text,
changed catalog digest или source-view contradiction водят до explicit error.

Не се допуска:

- fallback към English;
- fallback към първия catalog;
- смесване на български и английски entries;
- показване на raw key вместо липсващ text;
- partial result;
- auto-correction на locale ID или text.

## 15. Locale isolation и determinism

Един source view и един locale дават равен deterministic localized view.

`bg-BG` и `en-GB` запазват еднакви key/ordinal/gate/route semantics, но имат
различни catalog digests и human text. Един locale не може да вземе entry от
другия.

Модулът не използва clock, randomness, environment locale или OS settings.

## 16. Accessibility граница

Всеки record носи exact accessible text, равен на видимия text. Това
предотвратява скрита различна формулировка между display и screen-reader
input на contract ниво.

Stage 2.13 още не доказва:

- screen-reader произношение;
- keyboard navigation и focus order;
- contrast, font, scale, wrapping или scrolling;
- пълна видимост в реален прозорец;
- качество на превода за всеки бъдещ потребител.

Тези свойства изискват реален widget и platform tests.

## 17. No-operation граница

Localized view изрично има false за:

- `fallback_used`;
- `dynamic_interpolation_used`;
- `operation_controls_included`;
- `operation_performed`;
- `operation_authorized`;
- `secrets_retained`.

Той не съдържа event, acknowledgement receipt, callback, executor или
operational capability.

## 18. Freshness и lifecycle limitation

Stage 2.13 не чете filesystem и не доказва, че Vault/recovery state не се е
променил след Stage 2.8–2.12.

Nonterminal route запазва `downstream_reverification_required = true`.
След restart се изисква fresh recovery chain; localized record не е persisted
resume или authorization token.

## 19. Direct-construction limitation

Direct-constructed localized view с валиден-looking digest не доказва, че
реален прозорец е бил видим или че човек е прочел текста.

Catalog digest не доказва release provenance самостоятелно. Public release
трябва отделно да подпише source/build/release manifest и exact artifacts.

## 20. Забранени действия

Stage 2.13 няма:

- Tkinter/GUI widget, window, event loop или screenshot control;
- external translation file, plugin, template или runtime formatter;
- filesystem read/write/scan, environment locale или platform preference;
- Vault parse/unlock, password KDF или recovery rehearsal;
- acknowledgement, candidate, setup, publish, retry, repair или cleanup;
- gate invocation, callback, executor или mutation API;
- automatic transition, key deletion или user-file mutation;
- Contacts, Guardian, network, telemetry, logging, clock или randomness;
- update discovery, download, installation или server dependency.

## 21. Задължителни тестове

- exact allowlist и отказ на unsupported/case/whitespace/region variants;
- complete one-to-one coverage за всеки message/confirmation key;
- отказ на missing, extra, duplicate, reorder, mixed locale и altered text;
- stable domain-separated catalog digests;
- NFC, codepoint/UTF-8 bounds и control/bidi/template отказ;
- exact localization на absent/exact/conflict/preserve във всеки locale;
- locale isolation и deterministic repeated result;
- exact text, accessible-text equality, ordinals и gate order;
- visible/required/individual/default-false confirmation policy;
- malformed/hidden/forged Stage 2.12 source отказ;
- missing/reordered/mixed/altered localized output отказ;
- fallback/interpolation/operation/authority flags fixed false;
- source view остава byte-for-field непроменен;
- static липса на filesystem, GUI, network, mutation, logging, clock,
  randomness и dynamic-execution calls;
- public API без template, callback или executor arguments.

Тестовете са собствено reproducible evidence, не независим security,
linguistic, usability или accessibility audit.

## 22. Условие за реален recovery review window

Преди свързване към `mokosh_gui.py` трябва отделно да има:

- real Tkinter widget adapter, който приема само localized records;
- всички messages видими преди confirmations;
- no pre-check и no group-accept behavior;
- keyboard, focus, screen-reader, scaling, wrap и scroll tests;
- cancel/close без acknowledgement или operation;
- explicit supported-locale selector без OS fallback;
- fresh Stage 2.12/2.13 view при всяко отваряне;
- Linux, Windows и macOS platform tests;
- отделна operational граница с fresh source revalidation.

## 23. Честно ограничение

Stage 2.13 доказва, че exact recovery meanings имат пълен, фиксиран,
ограничен и детерминистичен български/английски текст.

Той не доказва как текстът изглежда на екран, кой го е прочел и не разрешава
или извършва нито една recovery операция.

## 24. Реализирана Stage 2.14 display граница

Stage 2.14 консумира exact Stage 2.13 localized view чрез отделен child
Tkinter `Toplevel` по
`docs/VAULT_RECOVERY_REVIEW_WINDOW_CONTRACT_BG.md`.

Той добавя code-level evidence за:

- explicit exact locale input без OS fallback;
- ordered message labels и отделно styled gate warnings;
- scroll/wrap/focus и Escape/Return/window-close wiring;
- individual default-false checkboxes без select-all;
- final action само след every selection;
- cancel/close без acknowledgement;
- success само към exact Stage 2.12 no-authority receipt.

Stage 2.13 registry остава непроменен и е единственият източник на recovery
meaning. Stage 2.14 fixed window chrome не променя и не интерполира catalog
text.

Реалните Linux/Windows/macOS, screen-reader, DPI, contrast и usability tests
още не са изпълнени. Stage 2.14 не е включен в `mokosh_gui.py` и не разрешава
или извършва recovery операция.

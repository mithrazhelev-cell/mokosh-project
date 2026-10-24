# MOKOSH Stage 2.36 — source-inspection localization contract

## Статус и цел

Stage 2.36 добавя pure, versioned, fixed Bulgarian/English localization
registry за exact Stage 2.35 source-inspection UI adapter view. Registry-то
свързва всяко от седемте message и трите confirmation enum keys с един
ограничен, прегледан project text.

Това е localization data/validation boundary, не GUI, renderer, accessibility
сертификат, доказателство за съгласие, acknowledgement или recovery операция.

## Exact source boundary

`localize_recovery_source_inspection_ui_adapter_view(view)` приема само exact
`VaultRecoverySourceInspectionUIAdapterView`. Stage 2.35 validator-ът се
изпълнява изцяло: digest/locale/state, седемте visible messages, трите separate
required/default-unselected controls и всички no-authority flags.

Subclass, mapping, sequence, malformed view, hidden/reordered message,
preselected control, select-all claim или forged authority се отказват.
Localization не приема prepared adapter, events или receipt и не извиква
Stage 2.35 acknowledgement lifecycle.

## Locale binding и allowlist

Поддържаните locale IDs са exact ordered tuple `("bg-BG", "en-GB")`. Public
catalog lookup приема само exact plain `str`; няма trim, case normalization,
language-only downgrade, region substitution или OS locale fallback.

Localization функцията няма caller-supplied locale argument. Тя избира само
exact locale enum, вече обвързан в revalidated Stage 2.35 view. Така caller не
може да преведе BG-bound presentation с EN catalog или обратно.

## Fixed catalogs

Всеки immutable catalog съдържа точно:

- седем message translations в Stage 2.33 enum-definition order;
- три confirmation translations в Stage 2.33 enum-definition order;
- exact locale enum;
- domain-separated catalog SHA-256;
- format/version;
- explicit complete/fixed/no-fallback/no-interpolation/no-external flags.

Missing, extra, duplicate, reordered, mixed-locale или altered entry се
отказва. Registry-то е built-in immutable tuple; няма external catalog,
register, extend, merge, plugin, download или runtime update API.

## Fixed reviewed meanings

BG и EN текстовете изрично запазват:

- inspection completed;
- header structurally validated;
- structural validity is not cryptographic authenticity;
- no recovery secret received;
- fresh secure reopen and inspection required before future use;
- no recovery performed;
- no operation authorized.

Confirmation текстовете отделно изискват acknowledgement на
structure-not-authenticity, fresh secure reopen и no-recovery/no-operation.

`fixed_reviewed_text=True` означава review в този source/test contract. Това не
е независима лингвистична, legal, cognitive или accessibility оценка.

## Unicode и resource policy

Всеки text е exact built-in `str`:

- от 1 до 240 Unicode code points;
- до 768 UTF-8 bytes;
- NFC-normalized;
- без leading/trailing whitespace;
- без Unicode category `C` characters;
- без bidi embedding/override/isolate/pop controls;
- без `{`, `}`, `%` или `$` template/interpolation markers.

Няма dynamic formatting, placeholder, path, ID, digest, exception или
user-controlled insertion. Unsupported text води до explicit failure, не до
partial localization или raw-key display.

## Catalog digest

SHA-256 е върху нов domain-separated canonical transcript с exact locale,
entry kind/count, ordered enum key и UTF-8 text, всички length-prefixed.
Comparison използва `hmac.compare_digest`.

Digest-ът открива несъответствие в process-local catalog. Той не е signature,
release provenance, authenticity, anti-rollback или legal evidence.

## Localized records

Всеки localized message съдържа stable ordinal, exact locale/key, fixed visible
text, identical accessible text и `visible=True`.

Всеки localized confirmation control съдържа stable ordinal, exact locale/key,
fixed visible/accessible text и exact:

- `visible=True`;
- `required=True`;
- `individually_selectable=True`;
- `default_selected=False`;
- `select_all_available=False`.

Localized view съдържа само repr-hidden presentation/catalog digests, locale,
`AWAITING_USER_CONFIRMATIONS`, exact localized tuples и honest safety flags.
Source view не се задържа и остава byte-for-field непроменен.

## Honest accessibility и consent boundary

Visible и accessible text equality е contract-level data property. То не
доказва actual rendering, screen-reader output, pronunciation, focus order,
keyboard use, contrast, scaling, wrapping, scrolling, completeness on screen,
human understanding, identity или informed consent.

Тези свойства изискват бъдещ real widget, platform/accessibility tests и
отделен freeze. Localized view не е resume token или authority record.

## No-operation и privacy boundary

Localized view няма selection events, acknowledgement receipt, callback,
executor, gate, source path/content, Recovery/Vault IDs, revision, hashes,
secret или password. Всички operation/authority/filesystem/network/logging/GUI
flags са exact false.

Catalog и localized view са frozen/slotted, repr-hidden за digests и отказват
copy, deepcopy и serialization. Fixed public text не е secret, но process-local
nonserialization предотвратява използването на localized view като persisted
workflow state. Python/OS memory zeroization не се твърди.

## Capability и import boundary

Модулът import-ва само standard-library hashing/encoding/Unicode/dataclass
primitives, locale leaf, Stage 2.33 enums и Stage 2.35 pure adapter.

Няма old Stage 2.13 renderer, Tkinter/GUI, filesystem, storage,
reconciliation, workflow, source reader, crypto, process, network, logging,
clock, randomness, dynamic execution, `getattr` или mutation capability.
Stage 2.32 reader не се извиква.

## Standards и честно значение

WCAG 2.2 е engineering reference за бъдещ real UI. EN 301 549 V3.2.1 и
текущата ETSI revision work item се следят. Directive (EU) 2019/882/EAA се
прилага от 2025-06-28 за продукти и услуги в приложимия обхват.

Stage 2.36 не е web UI и не доказва WCAG/EN/EAA conformity. Реалната
приложимост, harmonised-standard status, национално транспониране и conformity
assessment изискват отделен qualified legal/accessibility review. Draft или
work item не се приема автоматично като final standard.

## Project workflow invariant

Един работен чат обхваща точно три последователни stage-а. След третия са
задължителни package archive, history bundle, next-stage input и handoff;
следващият чат започва на High с read-only baseline/fresh review и без код
преди нов приет freeze.

Текущият чат обхваща Stage 2.34–2.36. След Stage 2.36 handoff-ът е за Stage
2.37. Правилото е project-history control срещу context drift и пропуснати
артефакти; то не заменя Git/evidence verification.

## Test evidence

Точно 58 targeted tests покриват locale allowlist/binding, complete catalogs,
fixed text meanings, independent digests, exact public API, BG/EN localization,
determinism, source immutability, unsupported locale, registry/catalog/schema
tampering, missing/extra/duplicate/reorder/mixed entries, Unicode codepoint/
UTF-8/NFC/control/bidi/template policy, exact Stage 2.35 revalidation,
localized schemas/text/order/booleans, privacy, honest claims,
copy/serialization, repr redaction, AST/import isolation, no reader и critical
unchanged hashes.

Първият targeted cycle е 57 pass / 1 fail: negative test е използвал Cyrillic
`е` плюс combining acute с погрешната предпоставка, че NFC задължително го
композира. Production validator не е причината. Vector-ът е заменен с Latin
`e` плюс combining acute и повторният exact gate е 58/58 PASS.

Scratch full-suite опитът е non-authoritative failure: 1752 tests, errors=3,
skipped=7 поради липсващ `argon2` и същите три existing import failures. Няма
dependency bypass или false PASS claim.

Expected authoritative laptop gate е 1781 tests: OK, expected failures=3 само
за legacy MOK1, skipped=0, плюс 131 tracked Python sources. Няма visual gate,
защото Stage 2.36 не създава real GUI.

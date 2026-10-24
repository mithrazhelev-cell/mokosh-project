# MOKOSH — матрица към стандарти, тестове и доказателства

Статус: жив документ за инженерна проследимост. Последна проверка: 2026-08-30.

## Цел и честно значение

Този документ свързва архитектурните изисквания на MOKOSH с признати
стандарти, нормативни източници, собствени тестове и бъдещи външни проверки.
Целта е разработката отсега да произвежда доказателства, които могат да бъдат
повторени и прегледани професионално.

Собствен тест по официален стандарт означава „тествано от проекта спрямо
посоченото изискване“. Той не означава FIPS validation, Common Criteria
certificate, ISO certification, държавно одобрение или независим audit.
Такова твърдение се прави само след реална процедура от оправомощена външна
страна и само за точно оценената версия и конфигурация.

## Статуси в матрицата

- `implemented` — има код и автоматични тестове;
- `partial` — има част от контрола, но липсва пълно доказателство;
- `planned` — изискването е прието, но реализацията предстои;
- `external-only` — проектът може да се подготви, но не може сам да издаде
  официалния резултат.

## Криптографски примитиви

| Област | Нормативна основа | MOKOSH контрол | Доказателство | Статус |
|---|---|---|---|---|
| AES-256-GCM | NIST SP 800-38D и следващата му окончателна ревизия | 256-bit DEK/KEK, уникален 96-bit nonce, exact AAD, tag отказ | known-answer, round-trip, nonce/AAD/tamper/negative tests; backend inventory | implemented, revision-watch |
| ML-KEM-768 | NIST FIPS 203 | exact key/ciphertext sizes, mandatory hybrid contact path, no downgrade | реален encapsulate/decapsulate, malformed/tamper/downgrade tests; бъдещи ACVP vectors | implemented, errata-watch |
| Ed25519/EdDSA | NIST FIPS 186-5 и RFC 8032 | domain-separated exact transcript, fingerprint/key-version binding, trust отделно от signature validity | known-answer и negative transcript/key tests | implemented |
| X25519 | RFC 7748 | exact raw key sizes, ephemeral exchange, mandatory hybrid composition | known-answer, invalid key/material и hybrid-binding tests | implemented |
| HKDF-SHA-256 | RFC 5869 | domain-separated `salt`/`info`, exact 32-byte output | RFC known-answer и context-separation tests | implemented |
| Argon2id | RFC 9106 | bounded memory/time/parallelism, random salt, exact 32-byte KEK | RFC vectors, wrong-password, bounds и resource-policy tests | implemented |
| SHA-256 | NIST FIPS 180-4 | plaintext/transcript/evidence digests с различни domain/context правила | known-answer, canonical encoding и tamper tests | implemented |
| CSPRNG | OS и validated cryptography backend | random DEK, nonce, salt, slot/operation/authorization identifiers; fail on invalid source | length/type/failure/fault tests; future platform entropy evidence | implemented/partial |

MOKOSH не създава собствени реализации на AES, Ed25519, X25519 или ML-KEM.
Използва поддържана криптографска библиотека и трябва да фиксира, инвентаризира
и проверява точната библиотека и backend във всеки release. Валидиран примитив
в библиотека не прави автоматично цялото приложение валидиран криптографски
модул.

## Формат, протокол и key management

| Контрол | Изискване и доказателство | Статус |
|---|---|---|
| Canonical v2 parser | exact magic/version/flags, bounded lengths, duplicate-key отказ, deterministic encodings, truncation/extra-data tests | implemented |
| AEAD binding | header digest, exact frame header, frame index и deterministic nonce са в AAD; mutation tests за всяко поле | implemented |
| Frame sequence | contiguous uint32 sequence, exact FINAL, overflow/missing/duplicate/reorder отказ | implemented |
| Manifest | frame 0 е encrypted; exact size/frame count/plaintext SHA-256/content metadata; strict limits | implemented |
| Trailer/transcript | exact ciphertext transcript count и digest; signature policy преди unwrap | implemented |
| Password slot | Argon2id → KEK → AES-GCM DEK wrap; nickname не участва в KDF | implemented |
| Vault slot | per-file HKDF-SHA-256; versioned root key никога не е direct AES key; exact uint32 version selection без fallback | implemented |
| Contact slot | X25519 + ML-KEM-768 са едновременно задължителни; no classical-only fallback | implemented |
| Trust policy | валиден signature не означава автоматично trusted contact | implemented core; UI planned |
| Wrapping-key rotation | NIST SP 800-57 Part 1 Rev. 5: authenticated identifier/state metadata, независимо re-keying, retired process-only употреба; canonical contiguous keyring и negative tests | implemented |
| Offline Vault recovery record | independent CSPRNG recovery root; HKDF-SHA-256 + AES-256-GCM; exact Vault ID/revision/source hash/keyring digest binding; stale/rollback/mixed/duplicate отказ; read-only rehearsal | implemented core; UI planned |
| Durable recovery record storage | exact latest durable receipt + clean scan; private descriptor-relative `O_EXCL` export; file/directory fsync; exact read-back; read-only double import; uncertain без false success | implemented POSIX core; platform adapters/UI planned |
| In-memory recovery Vault candidate | exact latest Vault + private `.mokr` + separate root; explicit new password; schema-2 keyring preservation; exact next revision; fresh salt/nonce; password verification; double source rescan; one-shot non-mutating authorization | implemented core; UI planned |
| Immutable recovery publish | separate enum decision; executor-owned one-shot claim; fresh double source/recovery mediation; Stage 2.2 no-clobber `R+1`; exact post-readback/history; uncertain без rollback/deletion | implemented POSIX core; platform adapters/UI planned |
| Recovery publish reconciliation | explicit old source receipt + expected `R+1`; private record/root and new-password re-verification; double bounded scan; absent/exact/conflict classification; no retry/rollback/cleanup | implemented read-only POSIX core; platform adapters/UI planned |
| Recovery workflow state | strict reviewed-result validation and transcript digest; one-shot exact enum review; absent/exact/conflict/preserve routes; ordered gates with all authority flags false | implemented non-mutating core; UI planned |
| Recovery workflow presentation | exact Stage 2.9 state revalidation; fixed bounded localization keys; visible ordered gates and confirmations; state digest; no raw text/callback/executor/authority | implemented non-mutating core; consumed through Stage 2.14 review seam |
| Recovery presentation acknowledgement | exact Stage 2.10 revalidation and transcript binding; complete ordered fixed-enum confirmations; one-shot/concurrent replay control; bounded no-authority receipt | implemented non-mutating core; consumed by Stage 2.12 adapter |
| Recovery UI adapter | exact Stage 2.10/2.11 binding; stable visible fixed-key items; separate required default-false controls; exact visible ordered events; no auto-accept/operation controls | implemented non-mutating adapter core; consumed by Stage 2.14 widget and conditional Stage 2.18 inspection-only main-GUI event; true source/operation integration remains prohibited |
| Recovery entry request | exact locale-bound one-shot enum intent; no source/secret/path/session/binding; all source, display and operation authority flags false | implemented bounded normal-main-GUI intent; source access remains prohibited |
| Recovery entry transition | strict Stage 2.19 outcome revalidation; second exact one-shot intent; preserve route cannot proceed; no retained source outcome/path/secret/capability; all authority flags false | implemented inactive non-mutating boundary; source selection/preparation remains prohibited |
| Recovery source selection | strict positive Stage 2.21 revalidation; one caller-supplied absolute POSIX path or preserve; bounded UTF-8/control policy; path redaction/no serialization; no open/identity/access/secret/operation authority | implemented inactive process-local selection contract; GUI picker and secure source access remain prohibited |
| Recovery source inspection request | strict positive Stage 2.27 revalidation; separate one-shot request or preserve; path redaction/discard; every source/access/secret/operation flag false | implemented inactive process-local intent; secure source access remains prohibited |
| Recovery locale leaf | exact `bg-BG`/`en-GB` enum identity in stdlib-only leaf; Stage 2.13 compatible re-export; Stage 2.19/2.21 fresh-process import closure excludes crypto/storage/workflow dependencies | implemented dependency-isolation boundary; no GUI/source/operation authority |
| Normal-main-GUI recovery import isolation | normal GUI import excludes Stage 2.17 bridge/controller/storage/workflow; exact bridge types load only for explicit conditional prepared-review path; text/layout/event semantics unchanged | implemented attack-surface reduction; no transition/source/session preparation/operation authority |
| Recovery localization registry | exact `bg-BG`/`en-GB` allowlist; complete immutable 24-message/9-confirmation catalogs; bounded NFC/control/bidi policy; domain-separated digest; no fallback/interpolation/authority | implemented deterministic non-mutating localization core; consumed by Stage 2.14 widget |
| Isolated recovery review window | exact Stage 2.10–2.13 revalidation; child `Toplevel`; messages before individual default-false controls; no select-all; cancel/Escape/close without acknowledgement; exact Stage 2.12 event delegation; no operation authority | implemented isolated Tkinter seam; main-GUI and cross-platform accessibility tests planned |
| Пълен key lifecycle | backup, compromise/revocation, recovery, cryptoperiod policy и доказуемо destruction | partial/planned |

За key lifecycle се използват като ръководство NIST SP 800-57 Part 1 Rev. 5
и приложимите изисквания на избраната платформа. Stage 2.3 реализира versioned
local wrapping-key rotation и exact historical selection. Stage 2.4 реализира
само in-memory offline recovery record и read-only rehearsal за exact keyring
state. Той още не реализира actual recovery publish, compromise/revocation,
cryptoperiod или destruction процедури. Stage 2.5 добавя private durable export
само на encrypted record и read-only file rehearsal. Recovery key storage,
physical-media proof и GUI остават planned. Stage 2.7 реализира explicit actual
Vault recovery publish за проверения POSIX core, но не automatic recovery.
Това не означава, че MOKOSH е оценен по SP 800-57.

Stage 2.6 добавя explicit new-password Vault candidate само в паметта. Той
запазва exact keyring history, увеличава revision точно с едно и проверява
candidate-а чрез authenticated unlock. Process-local one-shot authorization
обвързва non-secret source и candidate evidence след double source verification,
но не е digital signature или independent anti-rollback anchor.

Stage 2.7 добавя separate explicit publish decision, fresh complete mediation
на Vault/recovery sources и frozen Stage 2.2 immutable no-clobber publish.
Success изисква exact post-publish receipt/readback, запазено source поколение,
непроменен `.mokr` и clean history. Fault след publish boundary е uncertain без
rollback или deletion. Automatic recovery, key deletion и user-file mutation
остават забранени. Това е приложен lifecycle control, не SP 800-57 evaluation
или независима anti-rollback защита.

Stage 2.8 добавя strict read-only uncertain-outcome reconciliation без
process-local candidate dependency. Exact source/recovery prerequisites се
проверяват два пъти; absent/exact/conflict result е bounded и non-secret.
Recommended action не е mutation authorization. Няма blind retry, rollback,
cleanup, key deletion или automatic new recovery setup. Това не добавя
independent anti-rollback anchor или filesystem certification.

Stage 2.9 добавя process-local one-shot workflow state върху exact reviewed
Stage 2.8 result. Canonical transcript digest открива mismatch, но не е digital
signature. Absent/exact routes само изброяват следващите отделни gates;
conflict/preserve са terminal stop. Нито route, нито gate разрешават candidate,
unlock, recovery setup, publish, retry, cleanup, key deletion или user-file
mutation. Това е complete-mediation control за бъдещ adapter, не GUI и не
automatic recovery.

Stage 2.10 добавя bounded presentation model върху exact validated Stage 2.9
state. Fixed message/gate/confirmation keys пазят route semantics и изрично
показват no-operation/no-authority границата без raw user text. Presentation
digest е process-local binding, не signature или persisted trust token. Няма
acknowledgement recording, callback, executor, mutation API или GUI. Това е
least-authority view-model control, не usability certification или automatic
recovery.

Stage 2.11 добавя process-local one-shot acknowledgement върху exact Stage
2.10 presentation. Само complete ordered fixed-enum confirmation tuple може да
създаде bounded receipt; skip, partial, reorder, duplicate, extra и cross-route
keys се отказват. Lock сериализира concurrent attempts до точно един success,
но не е cross-process или persisted proof. Receipt не invoke-ва gate и всички
operation/authorization/automatic-transition flags са false. Това е
complete-mediation control за бъдещ adapter, не GUI, legal consent или
automatic recovery.

Stage 2.12 добавя bounded UI adapter seam без GUI toolkit. Exact
message и gate keys са stable ordered visible items; всеки confirmation
е separate required individually-selectable control с default false. Hidden,
automatic, partial, reordered и cross-route events се отказват преди
exact Stage 2.11 delegation. Receipt не е operation capability. Това е
least-authority/complete-mediation adapter contract, не доказателство за
human comprehension, accessibility certification, real GUI или automatic
recovery.

Stage 2.14 добавя първия real Tkinter seam, без да активира recovery в
основния GUI. Exact localized messages се създават преди confirmation
checkboxes; controls са disabled до visible-message report и false по
подразбиране; final action изисква every individual selection. Cancel, Escape
и close не consume-ват Stage 2.12 adapter. Success създава само bounded
no-authority receipt. Това е least-authority/complete-mediation widget seam,
не доказателство за human comprehension, legal consent, independent audit или
cross-platform accessibility certification.

Stage 2.5 POSIX contract следва fail-closed, least-privilege, no-clobber,
complete-mediation и crash-consistency принципи. Успех се отчита само след
exact read-back и file/directory durability. Unsupported permissions или fsync
semantics се отказват; няма portability downgrade.


## Secure software lifecycle и supply chain

Основната организационна матрица следва NIST SP 800-218 SSDF 1.1. Проектът
поддържа следните evidence families:

| Evidence ID family | Съдържание | SSDF посока | Статус |
|---|---|---|---|
| `REQ-*` | threat model, security requirements, misuse cases | Prepare / Protect | partial |
| `DES-*` | versioned format и архитектурни решения | Prepare / Produce | implemented/partial |
| `TST-KAT-*` | known-answer и interoperability vectors | Produce / Respond | partial |
| `TST-NEG-*` | tamper, malformed, boundary, downgrade и oracle отказ | Produce | implemented/expanding |
| `TST-FAULT-*` | crash, power-loss, I/O, lock, fsync и cancellation injection | Produce / Respond | implemented/expanding |
| `BLD-*` | pinned dependencies, SBOM, reproducible build и provenance | Protect / Produce | planned |
| `REL-*` | signed manifest, artifact hashes, platform signatures, release notes | Protect / Produce | planned |
| `VUL-*` | intake, triage, remediation, disclosure и supported lifetime | Respond | planned |

Към release evidence се планират още SLSA provenance, in-toto attestations,
reproducible-build сравнения и TUF-подобни root/targets/snapshot/timestamp роли
за обновяване. Това са архитектурни цели, не текущи сертификати.

## Файлова система, lifecycle и Stage 1.23

Stage 1.23 не валидира криптографски алгоритъм. Той покрива приложни security
properties, които трябва да имат собствена traceability:

| Evidence ID | Property | Задължителни тестове |
|---|---|---|
| `FS-CLEAN-001` | само exact canonical quarantine temporary е първа unlink цел | source inspection и tracked unlink order |
| `FS-CLEAN-002` | journal се премахва само след temporary и durable directory sync | fault injection след всеки boundary |
| `FS-CLEAN-003` | exact journal lease се държи през двете действия | active/unsupported/backend mismatch/concurrency tests |
| `FS-CLEAN-004` | authorization се консумира при първия опит | success/refusal/reuse tests |
| `FS-CLEAN-005` | fresh canonical evidence трябва точно да съвпадне | changed directory/journal/temp/evidence tests |
| `FS-CLEAN-006` | symlink, hardlink, inode replacement и TOCTOU отказват | adversarial filesystem tests |
| `FS-CLEAN-007` | original и published output не са адресируеми от API | schema/source/static-scope tests |
| `FS-CLEAN-008` | partial mutation никога не се отчита като success | post-unlink fsync/unlink/final-sync fault tests |

Тези проверки следват принципите fail closed, least privilege, complete
mediation, no-clobber, bounded processing и crash consistency. Portable
`unlink-by-name` няма атомична „изтрий само ако inode е X“ операция; затова
private directory и uncompromised same-user account са изрична trust boundary.
При неизвестни lock/fsync/filesystem semantics операцията отказва.

## Подготовка за официални и независими проверки

### NIST CAVP / ACVP

Безплатната ACVTS Demo среда може да се използва за подготовка и проверка на
поддържани алгоритми. Само Production ACVTS чрез акредитирана лаборатория
създава официални CAVP validation certificates. Преди такъв етап MOKOSH трябва
да пази exact implementation/backend/version, vector request/response,
build hash и environment manifest.

### FIPS 140-3 / CMVP

FIPS 140-3 е оценка на определена криптографска module boundary и operational
environment чрез оторизиран процес. Unit тестове и използване на стандартни
алгоритми не дават FIPS 140-3 статус. Ако пазарът го изисква, по-реалистичният
път за малък проект е употреба на подходящ вече валидиран модул в точно
допустимата му конфигурация и отделна проверка на integration boundary.

### Common Criteria

Common Criteria CC:2022 / ISO/IEC 15408 и CEM / ISO/IEC 18045 могат да
помогнат за структуриран Security Target, threat assumptions, SFR/SAR и
evaluation evidence. Самостоятелното им използване е подготовка, не Common
Criteria certificate. Сертификатът важи само за точно оценен продукт,
версия и конфигурация.

### Европейски Cyber Resilience Act

Регламент (EU) 2024/2847 се следи като продуктов регулаторен gate за
предлагане в ЕС: secure-by-design, vulnerability handling, документация,
support period, conformity и reporting задължения. Точната класификация,
срокове и conformity route се преглеждат с компетентен специалист преди
публична beta/продажба. Тази матрица подпомага техническото evidence, но не е
правно становище или декларация за съответствие.

## Правила за възпроизводимо собствено доказателство

За всяко release-кандидат изпълнение се пазят без лични данни:

1. immutable source commit и annotated tag;
2. exact OS, architecture, Python, dependency и crypto-backend versions;
3. signed dependency lock и SBOM;
4. test plan с requirement/evidence IDs;
5. machine-readable test results, vector origins и zero-skipped security gate;
6. fault/adversarial environment и точните injected failures;
7. coverage и static-analysis резултати с известните ограничения;
8. artifact SHA-256, signatures и build provenance;
9. reviewer identity/role и ясно разграничение self-review / independent review;
10. открити дефекти, remediation и повторните резултати.

Пароли, private keys, recovery материали, контакти, имена и съдържание на
потребителски файлове не влизат в evidence bundle.

## Release gates

- няма skipped задължителен security test;
- няма unresolved critical/high defect в release scope;
- всички normative алгоритъм vectors за поддържания backend минават;
- negative и fault tests минават на Windows, macOS и Linux;
- SBOM, source, build, test и artifact identity са взаимно свързани;
- ограниченията и trust boundaries са публикувани;
- няма certification/audit/conformity твърдение без съответния документ;
- законовият преглед се повтаря непосредствено преди пазара, защото
  изискванията и сроковете могат да се променят.

## Първични източници

- NIST FIPS 203, ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 186-5, Digital Signatures: https://csrc.nist.gov/pubs/fips/186-5/final
- NIST FIPS 180-4, Secure Hash: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
- NIST SP 800-38D, GCM: https://csrc.nist.gov/pubs/sp/800/38/d/final
- NIST SP 800-57 Part 1: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST SP 800-218 SSDF 1.1: https://csrc.nist.gov/pubs/sp/800/218/final
- NIST CAVP/ACVTS: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- NIST CMVP: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- RFC 5869, HKDF: https://www.rfc-editor.org/rfc/rfc5869
- RFC 7748, X25519: https://www.rfc-editor.org/rfc/rfc7748
- RFC 8032, Ed25519: https://www.rfc-editor.org/rfc/rfc8032
- RFC 9106, Argon2: https://www.rfc-editor.org/rfc/rfc9106
- Common Criteria Portal, CC:2022/CEM:2022: https://www.commoncriteriaportal.org/
- Regulation (EU) 2024/2847, Cyber Resilience Act:
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- UK ICO, Data protection by design and by default:
  https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/guide-to-accountability-and-governance/data-protection-by-design-and-by-default/
- OWASP Thick Client Application Security Verification Standard:
  https://owasp.org/TCASVS/

Точната версия на всеки източник се фиксира в release evidence. Draft или
предстояща ревизия се следи, но не се представя като окончателен стандарт.

## Stage 2.20 bounded GUI-entry mapping

Stage 2.20 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.5 / PW.7:** отделен frozen contract, allowlisted locale/decision
  inputs, negative tests и fail-closed event lifecycle;
- **SSDF RV.1:** възпроизводим full regression gate, exact artifact hashes,
  clean Git base, staged-path allowlist и rollback probe;
- **least authority / user intent:** visible request се отделя от source
  selection, review preparation и operation execution; няма automatic
  transition;
- **privacy by data minimisation:** request и visual report нямат password,
  path, Vault/recovery identifier, callback, free notes или telemetry;
- **honest claims:** Linux human observation се маркира само като visual
  evidence и изрично не е platform certification, audit или legal compliance.

Това mapping не добавя cryptographic validation и не променя FIPS/RFC
algorithm claims. То не е conformity assessment. Реалният source-access слой,
cross-platform evidence, accessibility/usability review и independent
security/legal gates остават бъдещи отделни requirements.

## Stage 2.21 bounded entry-transition mapping

Stage 2.21 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.5 / PW.7:** frozen no-capability contract, strict exact-type and
  route validation, negative tests и fail-closed one-shot lifecycle;
- **SSDF RV.1:** full regression gate, exact source/critical hashes,
  staged-path allowlist и rollback probe преди commit/tag;
- **complete mediation:** Stage 2.20 request не прескача директно към source,
  reconciliation, review session или operation; изисква отделно exact решение;
- **fail-safe defaults:** preserve route не може да бъде върнат към proceed,
  invalid input не създава partial result и всички authority flags са false;
- **least authority / data minimisation:** prepared object пази само locale и
  enum intent; outcome няма path, secret, source object, callback или executor;
- **honest claims:** proceed означава само future source-selection intent, не
  source authorization, recovery success, audit или conformity.

Това mapping не активира source selection или filesystem access и не добавя
cryptographic validation. Реалният source/secret intake и Stage 2.8 invocation
изискват отделен frozen threat model и implementation stage.

## Stage 2.22 recovery locale leaf mapping

Stage 2.22 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** минимализирана dependency и trust boundary за
  non-secret entry contract-ите;
- **SSDF PW.7:** exact type identity, compatibility, negative import и AST
  тестове върху frozen stdlib-only leaf;
- **SSDF RV.1:** full regression, exact critical hashes, staged-path allowlist
  и rollback probe преди commit/tag;
- **least privilege / attack-surface reduction:** Stage 2.19/2.21 import не
  зарежда crypto, storage, reconciliation, workflow, controller или GUI;
- **honest claims:** доказателството е само dependency isolation и не се
  представя като crypto validation, audit, source authorization или recovery.

Това mapping не променя localized текст, GUI behavior, recovery format,
filesystem semantics или operation authority. Source selection/preparation и
всяка реална recovery стъпка остават за отделен frozen stage.

## Stage 2.23 normal-main-GUI import-isolation mapping

Stage 2.23 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** normal-startup dependency minimisation и отделен
  conditional integration boundary;
- **SSDF PW.7:** fresh-process/blocked-dependency, exact-type, static import и
  full regression tests;
- **SSDF RV.1:** exact base/critical hashes, staged-path allowlist, rollback
  probe и zero-skipped gate;
- **least privilege / attack-surface reduction:** bridge/controller/storage/
  workflow code не се зарежда без explicit prepared-review path;
- **complete mediation:** conditional path продължава да изисква exact Stage
  2.17 binding и ready state преди display;
- **honest claims:** няма твърдение за visual change, recovery success,
  platform certification, audit или conformity.

Това mapping не добавя source selection, secret intake, filesystem access,
session preparation, Stage 2.8 invocation или operation authority. Следващо
wiring изисква отделен frozen threat review.

## Stage 2.24 explicit runtime-path initialization mapping

Stage 2.24 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** import-time side effect е преместен към explicit
  application-startup boundary с минимална dependency промяна;
- **SSDF PW.7:** fresh-process absent/existing directory probes, explicit
  function, ordering, failure и static reachability tests;
- **SSDF RV.1:** exact base/critical hashes, staged-path allowlist, rollback
  probe и zero-skipped full-regression gate;
- **least surprise / explicit mediation:** module inspection и import не
  променят runtime directory; real `main()` startup явно извършва съществуващата
  preparation;
- **fail-safe defaults:** invalid conditional binding се отказва преди
  preparation, а preparation failure блокира Tk root;
- **least change:** `APP_DIR`, `DATA_DIR`, environment override,
  mkdir/chmod function, GUI behavior и legacy formats остават непроменени;
- **honest claims:** доказателството е само за exact import/startup boundary,
  не за filesystem certification, legacy storage approval, audit или
  conformity.

Това mapping не добавя recovery source selection, secret intake, Stage 2.8
invocation, session preparation, cryptographic operation или operation
authority. Legacy seed/contact redesign и file-pipeline/lifecycle import cycle
остават отделни future scopes.

## Stage 2.25 main-GUI entry-transition mapping

Stage 2.25 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** отделна reviewed integration граница между existing
  Stage 2.20 request и Stage 2.21 transition contract;
- **SSDF PW.7:** positive/negative, forged-input, one-shot, concurrency,
  fault, visible, static import/call и full-regression tests;
- **SSDF RV.1:** exact base/critical hashes, staged-path allowlist, rollback
  probe, visible Linux gate и zero-skipped full regression преди commit/tag;
- **complete mediation:** Stage 2.21 preparation се достига само след exact
  positive Stage 2.19 outcome и отделно второ user action;
- **fail-safe defaults:** second action започва locked, preserve route не го
  arm-ва, а error/replay/concurrency paths не предоставят повторно действие;
- **least privilege:** GUI задържа само bounded non-secret Stage 2.19 outcome и
  не import-ва source/storage/reconciliation/workflow/publish modules;
- **honest claims:** future-source intent не се представя като source access,
  recovery authorization, operation, audit или conformity.

Това mapping не добавя source selection/preparation, secret intake,
filesystem read, Stage 2.8 invocation, session/binding preparation или
operation authority. Всяка такава граница изисква отделен frozen threat review.

## Stage 2.26 visual filesystem-claim semantics mapping

Stage 2.26 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** security evidence schema използва точни boundary names
  вместо двусмислен whole-process filesystem claim;
- **SSDF PW.7:** exact schema/default/validator/JSON, negative-forgery,
  disclosure-order, import и byte-hash tests;
- **SSDF RV.1:** fresh baseline, full regression, exact critical hashes,
  staged-path allowlist и rollback probe преди commit/tag;
- **honest claims:** existing runtime-directory preparation се отчита като
  извършена, докато само recovery-source filesystem access/mutation се
  отчитат като неизвършени;
- **least change:** GUI, paths implementation, crypto/Vault/recovery core и
  runtime dependency identity остават byte-exact;
- **traceability/versioning:** трите засегнати report families използват
  version `2`, без retroactive rewrite или automatic schema downgrade.

Това mapping не доказва липса на всички OS/Python/Tk filesystem system calls и
не е filesystem certification, platform certification, audit или conformity
assessment. Не добавя source selection, path retention, secret intake,
filesystem authority или recovery operation.

## Stage 2.27 recovery source-selection mapping

Stage 2.27 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** frozen отделна trust boundary между no-path Stage 2.21
  intent и бъдещия privileged source-access слой;
- **SSDF PW.7:** exact-type/schema/route, lexical path, Unicode, forged-claim,
  replay, concurrency, serialization и static capability negative tests;
- **SSDF RV.1:** fresh full-history/tree review, authoritative baseline, exact
  critical hashes, seven-path allowlist, rollback probe и zero-skipped full
  regression преди commit/tag;
- **complete mediation:** само exact positive Stage 2.21 outcome може да
  подготви selection; preserve и malformed outcomes не могат да преминат;
- **fail-safe defaults:** invalid input не консумира fresh object, но първият
  валиден decision е terminal и не предоставя retry/reset;
- **least privilege:** selection module няма GUI, filesystem, storage,
  reconciliation, workflow, secret, callback, executor или network capability;
- **privacy/data minimisation:** path е process-local sensitive metadata,
  скрит от repr и отказва copy/deepcopy/pickle; няма hash, log, display или
  persistence;
- **honest claims:** `source_selected` не означава existence, identity,
  authenticity, access authorization, recovery success или legal consent.

Това е technical design evidence, съвместимо като подход с NIST SSDF и с
privacy-by-design/data-minimisation посоката на актуалното ICO ръководство.
Не е UK GDPR/CRA conformity assessment или правно становище. OWASP TCASVS се
използва само като развиващ се desktop-security ориентир, не като certification.
GUI picker, secure open/read, recovery-secret intake, Stage 2.8 invocation и
review-session preparation остават бъдещи отделни frozen scopes.

## Stage 2.28 main-GUI source-selection mapping

Stage 2.28 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** отделна reviewed GUI mediation граница и conditional
  import на pure Stage 2.27 само при explicit third action;
- **SSDF PW.7:** positive/negative, forged-input, state/order, privacy, fault,
  replay, concurrency, fresh-process import, static capability и visual tests;
- **SSDF RV.1:** exact base, corrected 14-path allowlist, critical hashes,
  rollback probe, visual Linux matrix и zero-skipped full regression;
- **complete mediation:** exact Stage 2.19 request и exact Stage 2.21 transition
  предхождат отделното third action и Stage 2.27 revalidation;
- **fail-safe defaults:** source action започва locked; cancel, failure,
  interruption и replay не възстановяват authority;
- **least privilege:** application event записва само bounded path metadata и
  няма source open/read/identity/preparation, secret или operation capability;
- **privacy/data minimisation:** path не влиза в fixed messages, exceptions,
  reports, logs или persistence и не се задържа от GUI event-а;
- **honest claims:** native picker metadata access и runtime-directory
  preparation са explicit; няма whole-process no-filesystem claim;
- **change control:** pre-freeze transitive test-impact scan обхваща historical
  hash, import, schema, geometry, evidence и installer dependencies.

Това mapping е техническо design/test evidence и не е UK GDPR/CRA conformity
assessment, правно становище, independent audit, system-call proof или
platform certification. Secure source open/read, recovery-secret intake,
Stage 2.8 invocation и review-session preparation остават забранени.

## Stage 2.29 recovery source inspection-request mapping

Stage 2.29 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** отделна pure trust boundary между selected path и
  бъдещ privileged secure-read слой;
- **SSDF PW.7:** exact-type/schema/route, forged-claim, privacy, replay,
  concurrency, AST capability и full-regression tests;
- **SSDF RV.1:** exact baseline/tree/tag, seven-path allowlist, critical hashes,
  ignored-shadow scan, locale-stable source manifest и rollback gate;
- **complete mediation:** само fully revalidated positive Stage 2.27 outcome
  може да подготви request; preserve или malformed source отказват;
- **fail-safe defaults:** first exact decision е terminal, а request flag не е
  access authorization или automatic transition;
- **least privilege:** модулът няма filesystem, GUI, storage, crypto, workflow,
  review, process, network, callback или executor capability;
- **privacy/data minimisation:** path е process-local, repr-hidden,
  non-serializable и се discard-ва при preserve;
- **honest claims:** path/request не доказват existence, identity,
  authenticity, permissions, secure read или recovery success.

Нормативна SSDF основа остава финалната NIST SP 800-218 v1.1; SP 800-218 Rev.1
v1.2 е Initial Public Draft и се следи, без да се представя като final.
FIPS 203 се следи за публикуваната NIST future-update/errata бележка, а
SP 800-38D Rev.1 остава revision-watch без публикуван actual draft към
2026-08-25. EU CRA, ICO privacy-by-design и OWASP TCASVS са release/legal или
engineering ориентира, не self-certification.

Това mapping не добавя secure source access, secret intake, Stage 2.8,
review/session, operation authority, platform certification, audit или legal
conformity.

## Stage 2.30 main-GUI inspection-request mapping

Stage 2.30 добавя engineering evidence за следните ограничени свойства:

- **SSDF PW.4 / PW.5:** отделна reviewed GUI mediation граница между positive
  source selection и бъдещ privileged secure-read stage;
- **SSDF PW.7:** exact state/order/type/schema, forged-input, privacy, fault,
  replay, concurrency, import-isolation, static-capability и visual tests;
- **SSDF RV.1:** exact base/tree/tag, 18-path allowlist, historical hash и
  geometry guards, rollback probe, visible Linux matrix и full regression;
- **complete mediation:** fourth action се отключва само от fully revalidated
  exact positive Stage 2.27 outcome и изисква отделно explicit решение;
- **fail-safe defaults:** cancel, preserve, malformed input, fault,
  interruption и replay не предоставят access или automatic transition;
- **least privilege:** GUI event може само да подготви Stage 2.29 request и
  няма source open/read/stat/identity, secret, review или operation capability;
- **privacy/data minimisation:** retained selection outcome/path се clear-ва
  преди contract loading, preparation и dialog; fixed messages/reports са
  path-free;
- **honest claims:** request не е access authorization, source identity,
  authenticity, permission, recovery proof или consent.

Нормативната основа остава NIST SP 800-218 v1.1; NIST draft/errata watches,
EU CRA, ICO privacy-by-design и OWASP TCASVS са проследявани ориентири, не
self-certification. Това mapping не е правно становище, audit, platform или
legal conformity assessment и не добавя secure source access.

## Stage 2.31 inspection preparation-request mapping

- **SSDF PW.4 / PW.5:** отделна pure boundary преди бъдещия privileged source
  inspection-preparation слой;
- **SSDF PW.7:** exact-type/schema/route, forged-claim, privacy, replay,
  concurrency, import-isolation, AST capability и full-regression tests;
- **SSDF RV.1:** exact base/tree/tag, eight-path allowlist, critical hashes,
  source manifest, dry-run и rollback gates;
- **fail-safe defaults:** само exact positive Stage 2.29 outcome се приема;
  preserve, malformed input, fault и replay не предоставят authority;
- **least privilege:** резултатът е intent metadata без source open/read/stat,
  filesystem capability, secret, review/session или operation authority;
- **privacy/data minimisation:** path е repr-hidden и non-serializable, а при
  preserve се discard-ва;
- **honest claims:** one-shot е per prepared object; няма claim за global
  consumption, memory zeroization или complete privileged mediation.

SSDF v1.1 остава final baseline. SSDF Rev.1 v1.2 IPD, FIPS 203 errata watch,
SP 800-38D Rev.1 preliminary planning, CRA/ICO/NCSC и OWASP TCASVS са следени
ориентири, не self-certification или правно заключение.

## Stage 2.32 secure source-inspection execution mapping

- **SSDF PW.4 / PW.5:** отделна reviewed privileged mediation boundary,
  използваща вече тествания Stage 2.5 secure reader без дублиране;
- **SSDF PW.7:** exact input/schema, lazy-import, privacy, replay, concurrency,
  terminal fault, real POSIX adversarial и full-regression tests;
- **SSDF RV.1:** exact base/tree/tag, seven-path allowlist, payload hashes,
  source manifest, isolated dry-run/rollback и pre-commit full gate;
- **complete mediation:** exact positive Stage 2.31 outcome и отделно exact
  positive Stage 2.32 decision предхождат единствения secure read;
- **fail-safe defaults:** preserve няма storage import/access; path се clear-ва
  преди access, а ordinary/`BaseException` failure е terminal;
- **least privilege:** success връща само bounded observed IDs, revision, size
  и hashes, без path/content/descriptor, secret или downstream authority;
- **privacy/data minimisation:** evidence е repr-hidden и non-serializable;
  prepared/outcome objects не задържат source bytes;
- **honest claims:** structural header validation не е cryptographic
  authentication; няма Python zeroization, global consumption, future-identity,
  recovery-success или cross-platform claim.

Mapping-ът е engineering evidence по финалната SSDF v1.1 baseline. Следените
draft/errata, CRA/ICO/NCSC и OWASP ориентири не са self-certification, audit,
правно становище или formal conformity conclusion.

## Stage 2.33 source-inspection presentation mapping

- **SSDF PW.4 / PW.5:** отделна pure presentation boundary след privileged
  inspection и преди бъдещ UI/acknowledgement слой;
- **SSDF PW.7:** exact source/schema, forged enum/string/boolean, deterministic
  digest, privacy, static capability, import-isolation и regression tests;
- **SSDF RV.1:** exact base/tree/tag, seven-path allowlist, payload hashes,
  source manifest, dry-run и isolated rollback gates;
- **complete mediation:** само fully revalidated exact positive Stage 2.32
  outcome може да създаде presentation; preserve не се преобразува;
- **fail-safe defaults:** presentation предоставя fixed warnings и няма
  fallback, raw text, callback, secret, reader или downstream authority;
- **least privilege:** raw IDs/revision/size/hashes/path/source content се
  редуцират до един domain-separated repr-hidden digest;
- **privacy/data minimisation:** original outcome не се задържа; exact enums и
  bounded tuples не приемат extensible payload;
- **honest claims:** digest не е signature/provenance/authentication/
  anti-rollback proof, structural validity не е ciphertext authenticity и
  fresh secure reopen остава задължителен.

Това е technical design/test evidence по final SSDF v1.1 baseline, не
self-certification, independent audit, platform certification или правно
заключение.

## Stage 2.34 source-inspection acknowledgement mapping

- **SSDF PW.4 / PW.5:** отделна pure acknowledgement boundary след exact
  presentation и преди бъдещ UI/localization слой;
- **SSDF PW.7:** exact source/binding/confirmation/receipt types, malformed и
  forged input, transcript, privacy, exception, replay, concurrency, static
  capability, import-isolation и full-regression tests;
- **SSDF RV.1:** exact base/tree/tag, seven-path allowlist, critical hashes,
  source manifest, dry-run и isolated rollback gates;
- **complete mediation:** същата fully revalidated Stage 2.33 presentation и
  complete exact ordered token tuple са задължителни при success;
- **fail-safe defaults:** failed input не commit-ва receipt; след един success
  replay се отказва преди input validation;
- **least privilege:** няма GUI, renderer, source reader, filesystem, secret,
  recovery, callback, executor, gate или operation authority;
- **privacy/data minimisation:** original presentation/raw evidence не се
  задържат; deterministic digest е repr-hidden process-local correlation
  handle и не се persist-ва/log-ва/изпраща;
- **honest claims:** exact tokens не доказват human understanding, identity,
  informed consent, signature, provenance, authenticity или source freshness.

`MOKOSH Project Integrity and Full Disclosure Invariant` изисква всички
defects, deviations, additions и standards updates да бъдат съобщавани и
проследявани. Към 2026-08-29 watch ledger включва:

- final NIST SP 800-218 v1.1 baseline и SP 800-218 Rev.1 / SSDF 1.2 IPD;
- FIPS 203 planning note за future update/revision;
- SP 800-38D Rev.1 second preliminary/pre-draft work от 2026-06-01;
- EU CRA Article 14 от 2026-09-11 и обща приложимост от 2027-12-11 за продукти
  в обхвата;
- GDPR Article 25 privacy-by-design/default при приложим processing scope;
- OWASP transaction-authorization/TCASVS като engineering guidance.

Watch item не се прилага механично: при релевантност се прави fresh primary-
source review, impact analysis и отделен freeze. Mapping-ът не е
self-certification, conformity assessment, independent audit или правно
становище.

## Stage 2.35 source-inspection UI adapter mapping

- **SSDF PW.4 / PW.5:** отделен pure key-only view/interaction boundary след
  Stage 2.33/2.34 и преди какъвто и да е real renderer;
- **SSDF PW.7:** exact source/private binding, strict item/control/event/view/
  receipt schemas, malformed/forged/partial/reorder tests, replay, concurrency,
  fault/interrupt injection, privacy, AST/import isolation и regression hashes;
- **SSDF RV.1:** exact Stage 2.34 base/tree/tag, seven-path allowlist, package
  hashes/modes, source manifest, dry-run, rollback и final checkpoint gates;
- **complete mediation:** exact presentation, view binding и трите ordered
  visible/selected/user-initiated events се revalidate-ват преди delegation,
  а success изисква exact private terminal state и receipt identity;
- **fail-safe defaults:** pre-boundary invalid input не consume-ва state; един
  terminal marker преди private delegation прави всеки post-boundary failure
  `FAILED_CLOSED` и предотвратява fresh outer state след consumed inner state;
- **least privilege:** няма renderer, GUI toolkit, source reader, filesystem,
  secret, recovery, Stage 2.8, callback, executor, gate или operation authority;
- **privacy/data minimisation:** fixed enum keys и repr-hidden binding digest;
  няма raw text, source evidence, path, identifiers или retained presentation;
- **honest claims:** adapter-reported visibility/selection/user-initiation не
  доказват actual rendering, accessibility, comprehension, identity или legal
  consent; receipt не е signature/provenance/authenticity/authority proof.

Historical Stage 2.12 dual-state/interrupt-gap pattern е `planned hardening`
преди activation, не silent Stage 2.35 scope expansion. Нужни са отделен High
review/freeze и real-GUI regression evidence.

Standards watch остава задължителен: final SSDF v1.1 е current baseline;
SSDF 1.2 IPD, FIPS 203 future update и SP 800-38D Rev.1 pre-draft са tracked,
но не final-adopted; EU CRA/GDPR се оценяват според реалния product/processing
scope. Всяка релевантна revision/erratum/deadline минава primary-source review,
impact analysis и new freeze. Това не е certification, conformity assessment,
independent audit или правно становище.

## Stage 2.36 source-inspection localization mapping

- **SSDF PW.4 / PW.5:** отделен fixed localization boundary след pure Stage
  2.35 view и преди бъдещ renderer;
- **SSDF PW.7:** exact locale/catalog/source/output schemas, independent
  transcript digests, Unicode/NFC/bidi/template negative tests, privacy,
  static capability/import isolation и critical regression hashes;
- **SSDF RV.1:** exact Stage 2.35 base/tree/tag, seven-path allowlist,
  payload/hash/mode/tree/source manifest, dry-run и rollback gates;
- **complete mediation:** целият Stage 2.35 view и неговият bound locale се
  revalidate-ват; няма caller locale override;
- **fail-safe defaults:** unsupported locale, missing/reordered/mixed/altered
  catalog или source contradiction отказват без fallback/partial/raw-key view;
- **least privilege:** fixed strings и digests, без GUI, external catalog,
  filesystem, source reader, secret, event, acknowledgement или authority;
- **privacy/data minimisation:** source view/raw evidence/IDs/path не се
  задържат; localized view е nonserializable и digests са repr-hidden;
- **honest claims:** visible/accessibility text equality не доказва rendering,
  screen-reader behavior, understanding, identity, consent или conformity.

Accessibility traceability използва WCAG 2.2 като engineering reference и
следи EN 301 549 V3.2.1 плюс текущата ETSI revision работа. Directive (EU)
2019/882/EAA се оценява за продукти/услуги в реалния приложим scope; мерките се
прилагат от 2025-06-28. Pure Stage 2.36 не е WCAG/EN/EAA assessment и няма
self-certification или правно заключение.

Conversation lifecycle control е exact three consecutive stages per chat,
последвани от package archive, history bundle, next input и handoff. Новият
chat започва на High/read-only. Това е process traceability control, не SSDF
certification.

## Stage 2.37 source-inspection review-window mapping

- **SSDF PW.4 / PW.5:** отделен local review boundary след fixed Stage 2.36
  localization и преди бъдещ application-service/main-GUI activation;
- **SSDF PW.7:** exact presentation/adapter/localized/chrome/outcome schemas,
  malformed/forged/replay/concurrency/fault/BaseException/privacy/AST/Tk tests;
- **SSDF RV.1:** exact Stage 2.36 commit/tree/tag, seven-path allowlist,
  critical hashes, source manifest, isolated rollback и full-regression gates;
- **complete mediation:** exact Stage 2.33 presentation, fresh Stage 2.35
  adapter, Stage 2.36 bound locale, seven visible ordinals и three individual
  exact confirmations се revalidate-ват преди delegation;
- **fail-safe defaults:** controls започват disabled/false; final е disabled
  до three selections; един terminal sentinel преди private delegation прави
  всеки post-boundary failure `FAILED_CLOSED`;
- **least privilege:** един child `Toplevel`, без second root/mainloop,
  filesystem/source reader, secret, crypto, recovery, network, callback,
  executor, gate, main-GUI activation или operation authority;
- **privacy/data minimisation:** bounded repr-hidden digest/receipt и enums;
  няма path, source material, identifiers, password или extensible payload;
- **honest claims:** process-local visible/selected events не доказват
  physical rendering, accessibility, comprehension, identity, consent или
  legal conformity; structural validity не е cryptographic authenticity.

Accessibility watch използва WCAG 2.2 като engineering reference. ETSI work
item за revision на EN 301 549 V3.2.1 показва adopted-for-publication на
2026-08-24 и version 4.1.0, докато TC HF flyer посочва 4.1.1. Това изрично
numbering/status отклонение остава watch item до authoritative published text
и OJ/harmonisation review; не се прави automatic baseline replacement.

Final SSDF v1.1 остава baseline; SSDF 1.2 е IPD. SP 800-38D Rev.1 preliminary
work, FIPS 203 future-update note, EAA scope и CRA reporting readiness от
2026-09-11 се следят. Всяко релевантно update/erratum/deadline изисква primary
source, impact analysis, explicit notification, new freeze и acceptance.
Mapping-ът не е certification, independent audit или правно становище.

## Stage 2.38 source-inspection visual-harness mapping

- **SSDF PW.4 / PW.5:** pure fixed synthetic core е отделен от visible Linux
  launcher и от real application/main-GUI activation;
- **SSDF PW.7:** exact matrix/schema/type/binding/action/privacy/AST/JSON tests,
  relative-scale invariant и bounded map-timeout failure;
- **SSDF RV.1:** exact Stage 2.37 commit/tree/tag, eight-path allowlist,
  predecessor hashes, 48 targeted tests, full regression, isolated rollback и
  human visual gate;
- **complete mediation:** всеки case revalidate-ва exact Stage 2.33
  presentation и Stage 2.35 adapter; report приема само matching Stage 2.37
  outcome и frozen required terminal action;
- **fail-safe defaults:** invisible/timeout child, mismatch, malformed result,
  `fail` или `not_checked` дават nonzero status; няма fallback success;
- **least privilege:** core няма GUI/filesystem/network/process/source/secret/
  recovery capability; launcher няма real input, main GUI или automatic event
  injection;
- **privacy/data minimisation:** deterministic non-secret fixtures и bounded
  canonical JSON без path, host/environment dump, notes или retained source;
- **honest claims:** manual evidence е self-reported и не доказва screen reader,
  accessibility API, contrast, user preferences, comprehension, identity,
  consent, platform certification или legal conformity.

Accessibility engineering checks trace-ват WCAG 2.2 non-web interpretation
чрез informative/non-normative WCAG2ICT 2.2 и relevant EN 301 549 V4.1.0
non-web software keyboard/focus/user-preference/name-role-value clauses.
Текущият ETSI status е adopted-for-publication от 2026-08-24; OJ/
harmonisation и презумпция за съответствие не се твърдят без отделна official
verification.

Правният status ledger има четири категории: applicable mandatory law,
voluntarily adopted standard, reasoned non-applicability и qualified legal/
conformity assessment required. Private user и explicit user choice не са
автоматично изключение. CRA може да обхваща consumer software на EU market;
EAA се решава по exact product/service scope. CRA reporting readiness от
2026-09-11 остава project-level watch item.

Final SSDF v1.1 остава baseline; SSDF 1.2 е IPD. FIPS 203 future update и SP
800-38D Rev.1 work не се auto-adopt-ват. Всяка future revision/erratum/legal
change изисква primary-source review, impact analysis, disclosure, new freeze
и acceptance.

## Stage 2.38 responsive-UI amendment mapping

- **SSDF PW.4/PW.5:** responsive behavior се дефинира преди downstream GUI
  integration: minimum usable size, resize, reflow, locale expansion, scroll
  reachability и visible focus са строителни инварианти;
- **SSDF PW.7/RV.1:** 76 Stage 2.37 и 76 Stage 2.38 tests проверяват static
  boundaries, ordering и fail-fast behavior; human matrix остава отделна и
  задължителна;
- **complete mediation:** exact terminal action се проверява непосредствено
  след real child outcome и преди manual observations/report;
- **fail-safe defaults:** observation choices започват unset, submit е
  disabled до шест explicit selections, mismatch/FAIL/not-checked/cancel е
  nonzero;
- **least privilege:** wheel/key bindings са window-local, няма `bind_all`,
  stdin control channel, event injection, source/Vault input или operation
  capability;
- **privacy/data minimisation:** responsive amendment не добавя полета,
  arbitrary notes, environment/path/source/secret данни;
- **honest claims:** minimum-size/reflow/focus PASS на една Wayland среда не е
  Windows/macOS, screen-reader, WCAG/EN/EAA или legal conformity proof.

WCAG 2.2 reflow и focus-not-obscured guidance и WCAG2ICT/EN 301 549 software
mapping се използват като engineering references. Няма установена нова
official/scientific/legal publication спрямо предходния Stage 2.38 review;
amendment-ът променя строгостта на вътрешното прилагане, не status-а на
стандарт. Бъдещ език изисква собствен visible locale-expansion gate.

### R3 human-factors traceability

- repeated operator misunderstanding се третира като design evidence, а не
  автоматично като user fault;
- sequential cases, prescribed action и later PASS/FAIL phase се разделят
  семантично и визуално;
- unchecked acknowledgement и disabled Start са fail-safe comprehension
  prompt, но не доказват actual human understanding или informed consent;
- exact expected/observed diagnostics подобряват RV.1 evidence без разширяване
  на privacy payload;
- reserved footer grid подкрепя reflow/focus/reachability engineering, но
  изисква повторен human visible gate и не е conformity proof.

### R4 implementation-integrity traceability

- fail-safe rollback при pre-GUI `NameError` запази authoritative Stage 2.37;
- function-ownership и definition-before-use regression gates подкрепят
  software verification и reviewability, без да заместват visual test;
- повторяемият defect е записан честно като implementation/test-design
  finding, не е приписан на operator;
- няма ново установено official/scientific/legal standards изменение;
  WCAG 2.2, WCAG2ICT и EN 301 549 остават engineering references, без claim
  за сертифициране, правно съответствие или platform-wide conformity.

### R5 live-layout и updated-guidance traceability

- **complete mediation/fail-safe:** mapped header/middle/footer и required
  actions се проверяват преди visible/user/report claim;
- **RV.1:** pure bounds tests допълват structural tests; corrected human
  evidence invalidates трите R4 JSON PASS reports;
- **privacy:** geometry се оценява process-local; dimensions, coordinates,
  screen/host metadata не се логват или сериализират;
- **WCAG2ICT:** W3C Group Note 2025-12-11 е новият informative Level A/AA
  non-web software interpretation reference;
- **WCAG-EM 2.0:** W3C Group Note 2026-07-23 се приема като informative
  evaluation-method reference за scope/sample/evaluate/report discipline;
- **EN 301 549:** v4.1.0 е adopted for publication на 2026-08-24, но остава
  pending authoritative publication/OJ harmonisation verification;
- **EAA:** Directive (EU) 2019/882 е in force и measures apply от 2025-06-28
  за enumerated scope; MOKOSH classification остава release/product/service
  dependent и изисква qualified assessment;
- никой от тези редове не е certification, legal opinion или automatic
  conformance claim.


### Post-R5 corrective standards/status review — 2026-08-31

- **WCAG 2.2 / WCAG2ICT engineering traceability:** runtime resize mediation,
  preserved keyboard focus и focused-control reveal са engineering checks за
  reflow/keyboard/focus robustness. Те не са accessibility conformity proof.
- **EN 301 549 V4.1.0:** official ETSI work programme показва `Final deliverable
  adopted for publication` на 2026-08-24 и next status Publication 2026-09-03;
  наличният 4.1.0 download е approval-vote artifact. Не се твърди вече
  published/harmonised/OJ-cited V4.1.0. V3.2.1 остава current OJ-cited item в
  проверения ETSI harmonised listing.
- **NIST SP 800-227:** Final от 2025-09-18 и вече е explicit KEM
  implementation/use reference за бъдещи ML-KEM/contact decisions. Този GUI
  corrective не променя KEM код или crypto baseline.
- **NIST SP 800-57 Part 1 Rev.6:** Initial Public Draft от 2025-12-05; Rev.5
  остава final baseline до отделен review на бъдещ final revision.
- **NIST SP 800-38D Rev.1:** към 2026-06-01 е second preliminary/pre-draft
  workflow и NIST изрично няма actual draft document; няма automatic adoption.
- **EU CRA:** Commission guidance потвърждава reporting obligations за
  manufacturers от 2026-09-11 за actively exploited vulnerabilities/severe
  incidents при products with digital elements. Exact MOKOSH applicability,
  manufacturer role и release obligations изискват отделна qualified legal
  assessment; този ред не е legal opinion.

Нито една от тези актуализации не дава certification/conformity claim и не
разширява Stage 2.38 corrective scope.

## Stage 2.41 standards/legal traceability note (2026-09-02)

- NIST SP 800-218 SSDF 1.1 remains the final engineering reference. SP 800-218 Rev.1/SSDF 1.2 is tracked as draft and is not silently promoted.
- WCAG2ICT 2.2 (W3C Group Note, 2025-12-11) informs keyboard, reachability, text/layout and scaling observations for native Tk. It is informative and cannot establish conformity by itself.
- EN 301 549 V4.1.0 publication status is time-sensitive around 2026-09-03. Stage 2.41 makes no publication, OJ harmonisation or conformity claim; official status must be rechecked before final handoff packaging.
- CRA reporting obligations are tracked for 2026-09-11 and principal obligations for 2027-12-11. Applicability depends on product market/commercial/manufacturer role; no automatic applicability, CE readiness or legal opinion is inferred.
- Primary references: `https://csrc.nist.gov/pubs/sp/800/218/final`, `https://csrc.nist.gov/pubs/sp/800/218/r1/ipd`, `https://www.w3.org/TR/wcag2ict-22/`, `https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act`, `https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng`.
- The Stage 2.41 report states no accessibility/legal/platform certification and separates existing runtime-directory mutation from absent recovery-source access/mutation.

## Stage 2.41 standards-status supersession — 2026-09-03

- Този раздел supersede-ва само time-sensitive EN 301 549 status реда от
  2026-09-02; историческият запис остава непроменен.
- Официалният ETSI deliver repository публикува **EN 301 549 V4.1.1
  (2026-09)** на 2026-09-02 като final publication (`04.01.01_60`), със
  заглавие „Accessibility requirements for ICT products and services“.
  Change history казва, че целият документ е revised to become a harmonised
  standard for Directive (EU) 2019/882 и Directive (EU) 2016/2102.
- Primary ETSI evidence:
  `https://www.etsi.org/deliver/etsi_en/301500_301599/301549/04.01.01_60/`
  и
  `https://www.etsi.org/deliver/etsi_en/301500_301599/301549/04.01.01_60/en_301549v040101p.pdf`.
- Публикуването на Harmonised European Standard от ETSI не се третира като
  доказателство, че V4.1.1 вече е cited в Official Journal или че автоматично
  дава presumption of conformity за конкретен MOKOSH product/service. Този
  Stage не твърди OJ citation, applicability, conformity, CE readiness или
  legal opinion; това изисква отделна актуална qualified assessment преди
  разпространение.
- NIST официалната страница все още определя SP 800-218 Rev.1 / SSDF 1.2 като
  Initial Public Draft (2025-12-17; comment period closed), затова SSDF 1.1
  остава final engineering baseline. WCAG2ICT 2.2 остава W3C Group Note и
  informative non-web guidance, а не самостоятелен conformity стандарт.
- Stage 2.41 human keyboard/scaling/modal/readability evidence остава bounded
  engineering evidence. Пълна gap/applicability оценка спрямо целия нов
  V4.1.1 не е извършена и не се подразбира; тя е отделен pre-distribution gate.

## Stage 2.42 standards/legal traceability note — 2026-09-03

- Stage 2.42 добавя bounded normal-main-GUI layout/keyboard audit evidence, а не production UI или recovery capability.
- Fixed 100–200% scaling, keyboard reachability, visible focus, meaningful order, no-trap, clipping/readability и resize/restore observations са engineering mappings към релевантни non-web accessibility concerns.
- WCAG2ICT 2.2 остава W3C Group Note и explicit informative guidance; audit report-ът задължително отказва accessibility-conformance claim.
- EN 301 549 V4.1.1 (2026-09) остава публикуваният current ETSI text при freeze-а. Publication не доказва Official Journal citation, exact MOKOSH applicability или presumption of conformity.
- NIST SP 800-218 SSDF 1.1 остава final engineering baseline; Rev.1/SSDF 1.2 остава Initial Public Draft и не се прилага като silent final baseline.
- CRA Article 14 reporting date 2026-09-11 е активен project-level readiness reminder. Stage 2.42 local audit не определя manufacturer/product/market scope и не е legal opinion.
- Direct Stage 2.29 -> Stage 2.41 wiring е отхвърлено по complete-mediation принцип: intent, privileged source read и display activation остават отделни gates.

### Stage 2.42 corrective layout traceability — 2026-09-03

- BG/100% initial human FAIL доказва конкретен reflow/reachability gap в
  normal GUI; той не се преобразува в conformity PASS и нулира оставащите
  непроверени observations за този run.
- Adaptive vertical viewport, keyboard scrolling и automatic focused-control
  reveal са bounded engineering mitigations за reflow, keyboard access,
  visible focus и no-trap concerns. Те не доказват WCAG/WCAG2ICT или EN
  301 549 conformity.
- Четири-case 100–200% human matrix се рестартира след корекцията. Нито
  isolated automated PASS, нито един Linux laptop run представлява assistive-
  technology coverage, platform certification, legal opinion или EAA/CRA
  applicability determination.
- R1/R2 installer и test-closure отказите не променят standards mapping или
  capability boundary. Те са engineering-process evidence и блокират R3 до
  exact 25-path closure и пълна повторна регресия; не се третират като waiver.
- R3 post-apply status-parser false fail също не променя standards mapping или
  GUI capability. Transactional rollback и отказът от PASS marker са
  fail-closed engineering evidence; R4 е wrapper/evidence correction в същия
  exact 25-path scope.

### Stage 2.42 final bounded evidence note

- R4 human matrix 32/32 и independent post-apply integrity/regression gate са
  PASS за наблюдавания Linux/Tk setup при 100/125/150/200% scaling.
- Evidence подкрепя само конкретните keyboard, focus, reflow, visibility,
  clipping и resize engineering checks. То не установява пълно WCAG2ICT/EN
  301 549 съответствие, assistive-technology coverage, EAA/CRA applicability,
  legal compliance, certification или presumption of conformity.
- R1–R3 withdrawals остават част от traceability record и не са заличени от
  финалния R4 PASS.

## Stage 2.43 preparation-request transition — 2026-09-04

- NIST SP 800-218 SSDF 1.1 остава final secure-development baseline. Rev.1 /
  SSDF 1.2 остава Initial Public Draft и не се прилага като тих final standard.
- Complete-mediation mapping запазва отделни Stage 2.29 intent, Stage 2.31
  preparation intent, Stage 2.32 privileged one-read authorization и Stage
  2.39–2.41 review граници. Stage 2.43 не прескача или слива тези authority
  слоеве.
- Data-minimisation mapping: exact path се задържа само process-local за
  bounded transition, не се показва, log-ва, hash-ва, serialize-ва, persist-ва
  или изпраща. Python `str` zeroization не се твърди.
- WCAG2ICT 2.2 остава informative W3C Group Note. Fifth-action keyboard focus,
  reachability, text reflow/readability и 100–200% human observations са
  bounded engineering evidence, не WCAG2ICT/EN 301 549 conformity.
- ETSI EN 301 549 V4.1.1 (2026-09) е current published text при freeze-а;
  publication не доказва Official Journal citation, MOKOSH applicability или
  presumption of conformity.
- CRA reporting date 2026-09-11 и principal date 2027-12-11 остават отделен
  pre-distribution readiness/legal gate. Stage 2.43 local candidate не е
  placing-on-market решение и не твърди CRA/EAA/GDPR/CE compliance.
- R1 automated PASS не supersede-ва cancelled human evidence. SSDF verification
  и fail-safe-default mapping изискват R1 да остане withdrawn за apply, след
  като instruction/picker/terminal-question workflow-ът се оказа непригоден за
  самостоятелно изпълнение; independent gate доказва no live mutation.
- Corrective guide/wizard е usability и reviewability control: separate visible
  per-action instructions, explicit `.mokr` fixture navigation и default
  `not_checked` observations намаляват operator ambiguity, без automatic event
  injection или PASS. Това подпомага WCAG2ICT keyboard/understandability
  evaluation, но не доказва WCAG2ICT/EN 301 549 conformity.
- Test fixture creation/removal е explicit runner filesystem mutation. Report
  v2 не използва двусмисления whole-flow mutation claim, а точното
  `application_recovery_source_filesystem_mutation_performed=false`, заедно с
  true fixture-mutation disclosure и cleanup-before-report fields.
- R2 human stacking failure supersede-ва неговите automated PASS резултати за
  release/apply purposes. Guide и wizard не останаха reliably foreground;
  safe cancel/exit `130` и exact no-live-mutation gate са fail-safe-default
  evidence. R2 е withdrawn без waiver.
- R3 report v3 прави guide visibility/per-action guidance зависими от explicit
  human observation, вместо unconditional claims. Mapped/topmost watchdog-ът
  е harness-only usability control без event injection, automatic invocation
  или automatic PASS. Matrix-ът е 12 observations на case/48 общо; това
  подобрява reviewability, но не създава WCAG2ICT/EN 301 549 conformity claim.
- R3 clipped-controls и pending-callback human failure също supersede-ва
  automated PASS за apply purposes. R4 премахва recurring Toplevel watchdog-а,
  използва cancelable root-owned passive button-state observation и държи
  wizard controls извън scrollable body. Това следва fail-safe defaults и
  usability/reviewability целите, без да се представя като accessibility или
  platform conformity.
- R4 human `active`-state failure supersede-ва неговия dry-run PASS. Valid
  transient UI state е било отхвърлено, guide marker-ът е изостанал и uncaught
  callback error е направил guidance-а ненадежден; safe cancellation и exit
  `130` отново блокират live mutation. R5 приема exact classic Tk state set,
  синхронизира до furthest enabled action, показва постоянен пълен план и
  превръща observer validation error в контролиран fail-closed case failure.
  Това подобрява SSDF verification/fail-safe traceability, без conformity claim.
- R5 cases 1–3 JSON PASS records са invalidated, защото exact keyboard action
  `Space` липсваше от guide-а и беше обяснено извън harness-а чрез chat. Това
  нарушава self-contained/reproducible human evidence, независимо че самото
  действие е било извършено. Safe cancellation на case 4 и exit `130` запазват
  fail-safe default. R6 instruction-completeness gate изисква exact control,
  key, order и expected effect; това е SSDF verification evidence, не
  accessibility или legal conformity claim.
- R6 authoritative matrix 48/48 и independent post-apply integrity/regression
  gate са PASS за наблюдавания Linux/Tk desktop при 100/125/150/200% scaling.
  Това подкрепя само bounded keyboard, focus, reflow, guide clarity,
  one-shot/explicit-action и fail-safe engineering controls. То не установява
  assistive-technology coverage, WCAG2ICT/EN 301 549 conformity, CRA/EAA/GDPR
  applicability/compliance, CE marking, certification или legal opinion.
- R1–R5 withdrawals и причините им остават постоянна traceability history;
  R6 PASS не ги заличава и не ги преобразува ретроактивно в успешни evidence
  runs. Live R6 остава unstaged върху Stage 2.42 HEAD до evidence amendment и
  pre-commit verification.

## Stage 2.44 reader-hardening mapping

- NIST SP 800-218 SSDF 1.1 verification и fail-safe-default практиките се
  подкрепят от pre-open type/permission bounds, component-by-component
  no-follow traversal, post-open identity проверки и deterministic adversarial
  regression cases. Това е project evidence, не NIST certification.
- Data-minimization и security-by-design целите се подкрепят от one-shot
  bounded structural read, path/content non-retention в outcome и липса на
  recovery secret, network и нова persistence capability.
- Честното разграничение между structurally observed identifier и последваща
  AEAD authentication предотвратява недоказана security claim.
- POSIX `atime` caveat и ограниченията за kernel/current-account/filesystem
  trust са explicit. Няма hard real-time, universal filesystem, WCAG2ICT,
  EN 301 549, CRA/EAA/GDPR applicability/compliance, CE или legal claim.
- Current standards reconnaissance не замества pre-distribution qualified
  legal review; Stage 2.44 не е placing-on-market решение.

## Stage 2.44 authoritative verification status

- R1 dry-run, transactional apply и independent post-apply gate дават три
  отделни full 2152-test cycles върху candidate/live/final-observed code bytes;
  всеки е PASS с точно три документирани legacy expected failures и zero skips.
- 20/20 rollback injection, exact package/live hash binding, strict fsck,
  physical owner/mode/plain-ACL manifest и unchanged bytecode подкрепят SSDF
  verification, integrity и fail-safe-default traceability. Това не е NIST
  endorsement или certification.
- Adversarial reader tests покриват FIFO, special-file precheck, ancestor
  rename/symlink, parse-time replacement, terminal one-shot failure и complete
  descriptor cleanup. `O_NONBLOCK` е bounded engineering control, не real-time
  или availability guarantee за всяка filesystem/kernel среда.
- GUI bytes не са променени; липсата на human visual matrix не създава
  accessibility claim и не отслабва предишните bounded GUI evidence records.
- Fresh legal-source extraction остана непълна за част от EUR-Lex/националните
  страници поради access/extraction ограничения. Pre-distribution qualified
  CRA/EAA/GDPR/национална applicability проверка остава open gate без waiver.

## Stage 2.45 authorization-readiness/privacy audit mapping

- **NIST SSDF / explicit mediation:** отделното шесто user action и отделният
  default-negative confirmation запазват границата между Stage 2.31 intent и
  Stage 2.32 one-secure-read authorization. Exact input revalidation, one-shot
  terminal state, replay/concurrency refusal и generic failure подкрепят
  fail-safe-default/complete-mediation engineering; това не е NIST endorsement.
- **privacy by design/default:** predecessor/path references са time-bounded и
  се clear-ват преди loader/dialog/read; fixed path-free UI и липсата на
  logging, telemetry, persistence, network и свободен текст минимизират
  disclosure. Python memory zeroization и global consumption не се твърдят.
- **honest security claims:** structural validation не е cryptographic
  authentication, recovery proof или operation authorization. POSIX `atime`
  може да бъде filesystem-managed side effect и observed identity важи само за
  конкретния read; няма forensic no-change или future-identity claim.
- **privilege separation:** Stage 2.32 success не активира Stage 2.39–2.41 и не
  дава recovery/write authority. Всеки следващ слой изисква отделен action,
  confirmation, frozen scope и evidence.
- **verification:** Stage 2.45 планира 32 static audit tests, 173 relevant
  predecessors, full 2184 regression, rollback/integrity/ACL/fsck/bytecode и
  independent gate. GUI bytes са immutable, затова human matrix не принадлежи
  на този audit-only Stage; бъдещ GUI Stage трябва да има собствена матрица и
  identity-safe `0700`/`0600` synthetic fixture.
- Към 2026-09-08 NIST SP 800-218 SSDF 1.1 остава final; SP 800-218 Rev. 1 /
  SSDF 1.2 е Initial Public Draft от 2025-12-17. WCAG2ICT 2.2 е informative
  W3C Group Note от 2025-12-11. ETSI EN 301 549 V4.1.1 е публикуван през
  2026-09, но publication сам по себе си не доказва OJ citation/presumption.
- CRA reporting readiness за manufacturer в приложим scope започва 2026-09-11
  с 24-hour early warning и 72-hour full notification; main obligations са от
  2027-12-11. Commission guidance от 2026-07-27 е non-binding. Exact MOKOSH
  applicability остава qualified pre-distribution legal gate.
- Mapping-ът не е accessibility evaluation, WCAG/EN conformity, CRA/EAA/GDPR
  compliance, CE marking, certification, independent audit или legal opinion.

### Stage 2.45 authoritative verification status

- R2 dry-run, live transaction и independent post-apply verifier дават три
  отделни 2184-test cycles при exactly three documented legacy expected
  failures и zero skips. 6/6 rollback injection, package-to-live binding,
  exact Git/physical/ACL/fsck/bytecode gates подкрепят SSDF verification и
  fail-safe-default traceability; не представляват NIST certification.
- Exact 8 critical production hashes и непромененият `mokosh_gui.py` доказват
  границата на audit-only delta. Липсата на human GUI matrix е следствие от
  no-GUI-change scope, не accessibility/conformity waiver.
- `GO WITH BLOCKERS` разрешава единствено бъдещо scope предложение. То не
  активира Stage 2.32 read, Stage 2.39–2.41 review, recovery/operation или
  distribution и не отменя qualified legal/applicability gates.
- Final-evidence R1 външният extraction validator е отказал безопасно преди
  installer execution, защото е объркал archived directory mode `0755` с
  private extracted mode `0700` под `filter="data"`/`umask 0077`. Withdrawal,
  no-mutation record и R2 exact extracted-mode correction поддържат SSDF
  fail-safe/traceability целите; инцидентът не е certification или product PASS.
- Final-evidence R2 pre-commit gate е отказал три trailing-space реда в
  untracked audit документа едва след staging. Targeted unstage и липсата на
  commit/tag запазват fail-safe state; R3 direct raw-byte scanner затваря
  coverage gap-а на pre-staging `git diff --check`. Това е repository-quality
  и SSDF traceability control, не нов compliance или security claim.
- Failed staging е оставил шест unreachable Git blobs, така че R3 strict
  historical-three fsck allowlist е отказал безопасно преди overlay. R4 pin-ва
  exact nine-object type/OID/size/content-hash evidence, без prune или broad
  acceptance. Това разширява tooling traceability, не product authority,
  certification или frozen production scope.

## Stage 2.45.1 legacy-contact containment mapping — 2026-09-10

- **FIPS 203 / NIST SP 800-227:** реалният pinned backend доказва правилен
  ML-KEM-768 KEM contract; legacy swapped result binding, wrong constructor и
  truncated unwrap се отказват чрез quarantine, не чрез classic downgrade.
  FIPS 203 остава final с official future-correction planning note; exact
  errata-watch е open. SP 800-227 е final KEM implementation/use reference.
- **NIST SP 800-38D:** GCM поддържа authenticated additional data, но legacy
  contact header-ът не е AAD-bound. Практическият Gate 3 приема PQ-field strip
  и contact-id rewrite без integrity error. Quarantine предотвратява употреба;
  бъдещият V2 application path трябва да докаже exact header/transcript AAD.
- **NIST SP 800-218 SSDF:** read-only discovery, explicit incident record,
  fail-safe containment, exact allowlist, non-weakened regression hashes и
  subsequent remediation blockers подкрепят identify/respond/remediate
  engineering. Това не е NIST endorsement или SSDF conformity assessment.
- **privacy by design/default:** quarantine import-ът няма path, filesystem,
  contact, identity или private-key access. Реални `contacts.json` данни не се
  четат, променят, мигрират или изтриват. Съществуването/съдържанието им не се
  предполага и остава отделен consent-bound privacy gate.
- **CRA current-date watch:** European Commission посочва reporting obligations
  от 2026-09-11 и main obligations от 2027-12-11. Повечето default-category
  products могат да използват manufacturer self-assessment, но exact MOKOSH
  product category и conformity route не са определени тук. Няма legal opinion,
  CE/compliance claim или waiver на qualified pre-distribution review.
- **honest evidence:** diagnostic PASS, quarantine PASS и function PASS са
  различни твърдения. Disabled/quarantined contact functionality остава
  unavailable; работеща функция може да се заяви само след real-backend
  two-party, negative/fault и practical GUI evidence.
- **SSDF evidence provenance / non-recurrence:** Stage 2.45.1 R1 е повторил
  вече известния Stage 2.41/2.42 defect — Git `100644` е използван като
  заместител на недоказан physical POSIX mode. Authoritative diagnostic
  установява exact `2×0600`, `11×0644`, `5×0664` за 18 existing targets.
  Корекцията изисква три независими exact-map bindings, individual negative
  injections и mode-preserving rollback; aggregate counts сами по себе си не
  са достатъчно evidence. Това е engineering control, не SSDF certification.
- **verification-domain separation:** R2 dry-run PASS не доказва live apply
  path. Pre-issuance apply QA откри, че whole-tree predicate за clean extracted
  candidate е неприложим към repository root с `.git` и baseline bytecode.
  R3 използва различни predicates за тези trust boundaries и запазва отделни
  Git/status/physical/fsck/bytecode controls. Това е defect containment и
  regression evidence, не application security или standards conformity PASS.

Първични current-date източници:

- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/sp/800/227/final
- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment

## Stage 2.45.2 MOK1 compatibility mapping — 2026-09-10

- **evidence dependency closure:** окончателният exact 30-path freeze е получен
  чрез recursive hash-consumer closure до липса на нови consumers. Оттегленият
  28-path резултат е бил едностепенен и е пропуснал два second-order audit
  tests; това е коригирано преди user-repository mutation. Финалният граф има
  20 direct и 6 second-order edges, без consumer извън freeze-а.
- **NIST SP 800-38D / `cryptography` 49.0.0:** AES-GCM удостоверява
  ciphertext и само подадените associated-data bytes. Historical MOK1 е
  създаден с `AAD=None`; затова payload tag-ът може да бъде проверен, но JSON
  metadata не може да стане authenticated със задна дата. Новият writer е
  fail-closed, а compatibility decrypt прави two-pass full-payload tag
  verification преди atomic publication.
- **algorithm/KDF agility safety:** exact allowlist отказва missing/unknown
  `alg`/`kdf`, duplicate JSON keys и attacker-selected KDF costs. Няма
  downgrade или unknown-to-PBKDF2 fallback. Historical Argon2id и PBKDF2
  параметрите са compatibility constants, не динамична header policy.
- **OWASP password guidance:** MOK1 Argon2id `m=65536 KiB, t=2, p=4` е над
  публикувания минимум `m=19456 KiB, t=2, p=1`, но няма benchmark или
  password-storage/compliance claim. Legacy `password|nickname` ambiguity е
  документирана и не може да се създава наново, защото writer-ът е затворен.
- **fail-safe filesystem boundary:** verified regular-file source, bounded
  reads, private `0600` quarantine, source revalidation и atomic no-clobber
  publish предотвратяват silent overwrite/symlink release. Това е конкретно
  tested engineering behavior, не обща platform-security гаранция.
- **privacy by design/default:** нов plaintext MOK1 metadata не се създава.
  Съществуващите видими полета са untrusted и не управляват output path/mode
  или trust. Няма logging, telemetry, network, data deletion или automatic
  migration в този Stage.
- **CRA / distribution boundary:** Регламент (ЕС) 2024/2847 се прилага според
  product, market и commercial-activity фактите; Article 14 е приложим от
  2026-09-11, а общото прилагане е от 2027-12-11. Exact MOKOSH applicability и
  conformity route изискват отделна pre-distribution правна и продуктова
  класификация. Този запис не е legal opinion, CE marking, certification или
  compliance declaration.

Първични current-date източници:

- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://cryptography.io/en/49.0.0/hazmat/primitives/aead/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://eur-lex.europa.eu/eli/reg/2024/2847/oj

## Stage 2.46 protected profile/session mapping — 2026-09-12

Това е engineering traceability, не conformity assessment. MOKOSH profile
password отключва локален encrypted Key Vault; той не е remote CSP/verifier и
не се заявява NIST Authentication Assurance Level.

| Източник/принцип | Stage 2.46 контрол | Доказателство | Ограничение |
|---|---|---|---|
| NIST SP 800-63B-4 §3.1.1 | минимум 15 знака, Unicode/NFC, space, без произволни composition rules или periodic-change prompt | password policy tests и strict first-run validation | 63B-4 е за digital identity/remote authentication; използва се информативно, без AAL claim; breach blocklist още няма offline/privacy-preserving дизайн |
| NIST SP 800-63B-4 session guidance | explicit login intent, locked credential-entry preservation, 15-minute inactivity, manual/close/panic lock | injected monotonic/wall/suspend/session tests, R3 GUI event-routing regressions и practical visual gate | няма overall reauthentication timer, MFA, phishing-resistant authenticator или AAL3 claim |
| NIST SP 800-38D | existing AES-GCM Key Vault удостоверява header-bound ciphertext | schema-2 create, publish, reopen и fresh unlock tests | няма FIPS/CMVP validation claim; GCM revision/errata се следят отделно |
| OWASP Password Storage Cheat Sheet | existing Argon2id memory-hard KDF, bounded policy и authenticated storage | Key Vault vectors/tests плюс Stage 2.46 integration | параметрите не се представят като универсално оптимални без target-device benchmark |
| NIST SP 800-218 SSDF | exact baseline/scope, code-reviewable contract, negative tests, deterministic package, rollback и evidence gates | 35-path freeze, recursive consumer closure, package plan и session log | собствените gates не са independent audit или certification |
| Fail-safe defaults / least functionality | всички unfinished actions и network са explicit `false`; само legacy one-file recovery се разрешава след unlock | complete capability-registry tests | V2 local/contact/sandbox operations остават неизползваеми до отделни stages |
| Filesystem race/no-clobber controls | descriptor-relative open, type/owner/mode checks, immutable Vault generation, descriptor-last hard-link publish | symlink/mode/partial/tamper/collision/failure tests | Stage 2.46 backend е Linux-only; Windows/macOS изискват native backends и tests |
| Privacy by design/default | public nickname е отделен от KDF; няма telemetry/network; legacy records са lstat-only и untouched | static import/network checks и byte-exact legacy fixtures | nickname е умишлено plaintext UI metadata, не тайна |
| Secure recovery honesty | GUI казва, че optional master phrase още не е configured | EN/BG localization tests | забравена profile password не може да се възстанови до отделния Stage 2.47 |

Проверени първични източници към 2026-09-11:

- https://pages.nist.gov/800-63-4/sp800-63b.html
- https://csrc.nist.gov/pubs/sp/800/218/final
- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

NIST SP 800-63B-4 изрично различава centrally verified passwords от local
activation secrets. Поради това сходните Stage 2.46 choices (15 знака, NFC,
Unicode, inactivity) са консервативни design references, а не доказателство,
че локалният MOKOSH профил „съответства“ на remote identity standard.

Human Case 1 на 2026-09-12 отказа R2 въпреки пълния automated PASS, защото
locked Tk activity routing изчистваше входа при всеки клавиш. Exact 7-path R3
correction разделя credential entry в `LOCKED` от inactivity touch в
`UNLOCKED` и добавя regression tests. Това е конкретна secure-usability
корекция и evidence за human-in-the-loop gate, не нов conformity claim.

R3 package QA допълнително доказва exact-R2 baseline binding, седемпозиционен
transaction rollback, deterministic build, dry-run без mutation и disposable
apply с `65/472/2282` regression. Тези engineering controls подкрепят SSDF
PW.7/RV.1 traceability, но local QA не е independent assessment, certification
или доказателство за Windows/macOS native поведение.

## Stage 2.46 R4 corrective mapping — 2026-09-12

Това е engineering traceability update, не conformity assessment.

| Принцип | R4 контрол | Доказателство | Ограничение |
|---|---|---|---|
| Secure usability / explicit user intent | first-run credential fields трябва реално да приемат typing/paste преди explicit create; login остава отделно explicit действие | modal lifecycle tests и задължителен human entry-transition route | synthetic visual state не доказва real profile storage; backend integration остава отделен |
| Fail-safe defaults | дефектният first-run път не създава автоматично профил и не отключва capability | `ABSENT` остава locked; synthetic route няма filesystem/crypto/network операция | practical PASS предстои след authoritative apply |
| NIST SSDF PW.7 / RV.1 | escaped path е записан, root cause е свързан с липсващо test coverage и е добавен regression/visual gate | exact 12-path freeze, target/affected/full suites, бъдещ rollback и independent verifier | собствените тестове не са независим audit или certification |
| Credential minimization | modal close изчиства nickname/password/confirmation; successful login изчиства главните две полета | idempotent close test и complete visible-state login/lock test | Python/Tk не предоставя доказуема zeroisation на immutable string copies |
| Cross-platform honesty | lifecycle следва portable Tk primitives: visibility, focus и local grab | static/runtime-order tests и Linux practical visual gate | Windows/macOS native focus, signing и packaging изискват бъдещи реални tests |
| Accessible/readable localization | по-краткият `Почисти оригинали...` се побира по-добре в симетричната BG action grid | exact localization assertion и повторна EN/BG scale matrix | action остава disabled и семантиката му ще се freeze-не в отделен clean-original stage |

R4 не променя NIST/OWASP cryptographic mapping, Argon2id/AES-GCM параметри,
profile format, Linux filesystem guarantees, capability registry или legal
claims. Local `76/472/2293` automated PASS е предварително доказателство;
authoritative package и human visual gates остават задължителни.

R4 pre-issuance package assurance е PASS върху QA Python 3.12.14: exact R3
baseline, 16 installer self-tests, `12/12` rollback, candidate и disposable
live `76/472/2293`, zero non-pass/residue и exact 35 unstaged paths. Това е
engineering evidence за transaction/integrity/regression controls, не
сертификация, официален одит, platform-native validation или user-machine
acceptance. Final documented bytes, Python 3.12.3 apply и practical modal
typing/paste резултат остават отделни gates.

## Stage 2.46 R5 non-blocking liveness mapping — 2026-09-12

R4 cryptographic/source/package/independent evidence остава валидно, но human
GUI gate е `FAIL`: synchronous Tk `wait_visibility()` блокира преди actual
window mapping. Следователно automated regression PASS не се използва като
заместител на operational availability или secure-usability evidence.

| Принцип | R5 контрол | Доказателство | Ограничение |
|---|---|---|---|
| Availability / non-blocking UI | first-run constructor не чака visibility и се връща след Map bind | executable constructor regression и забрана на wait/update/mainloop calls | actual Linux/Windows/macOS window-manager mapping остава human/native gate |
| Event-driven lifecycle | focus и local grab се планират след реален `<Map>` чрез една idempotent idle callback | duplicate Map, unviewable retry opportunity и activation-order tests | Tk focus policy може да се различава по platform/window manager |
| Fail-safe teardown | close отменя pending callback, чисти credential variables и прави late callback inert | close-before-callback regression | Python string zeroisation не се заявява |
| Observable verification | constructed/main-mapped/first-run-mapped са отделни non-secret markers | runner observer idempotence и report schema v2 | marker доказва lifecycle event, не че човекът може да въведе текст |
| NIST SSDF PW.7 / RV.1 | human failure отменя release gate и води до root-cause regression преди нов опит | exact 10-path freeze, `80/472/2297`, evidence/session trace | internal engineering evidence не е certification или independent audit |

R5 не променя Argon2id, AES-GCM, profile/storage formats, permissions model,
capability registry, recovery policy, network posture или legal claims.

## Stage 2.46 R6 evidence closure mapping — 2026-09-12

Това е documentation-only engineering traceability update, не conformity
assessment или нов security control.

| Принцип | Наблюдаван R5 резултат | R6 доказателствена граница | Оставащо ограничение |
|---|---|---|---|
| Availability / fail-safe lifecycle | Linux BG/100 first-run и main прозорците се map-наха; constructor/process не блокираха | трите markers са unique, 11/11 human observations и `80/472/2297` са записани | Windows/macOS native window-manager behavior не е тествано |
| Explicit user intent | create, отделен login и manual lock бяха видимо отделни действия | synthetic controller няма profile/file/network I/O; screenshots подкрепят self-reported flow | human evidence не е independently witnessed audit |
| Credential minimization | modal fields се изчистиха след create; main fields се изчистиха след login; lock ги остави празни | automated regressions плюс visible screenshots | Python immutable-string zeroisation не се заявява |
| Secure usability | keyboard typing, `Ctrl+V`, masking/eye controls и BG/EN switch работят | exact tested capabilities се разграничават от непроверени touch gestures | long-press/right-click Paste menu не е реализирано; future separate cross-platform scope |
| NIST SSDF PW.7 / RV.1 traceability | R4 human FAIL доведе до source-localized R5 fix и liveness regressions преди повторен human PASS | exact R5 package, rollback, independent verifier и physical state са записани | internal process не е certification или third-party assessment |
| Change control / least functionality | R6 докосва само пет evidence документа | production/localization/tests остават byte-exact спрямо R5 | commit/tag се доказват само от бъдещия repository finalization output |

R6 не променя приложимостта или ограниченията на NIST SP 800-63B-4,
SP 800-218, SP 800-38D, OWASP guidance или Регламент (ЕС) 2024/2847. Няма
FIPS/CMVP, AAL, CE, official-audit, legal-opinion или release-readiness claim.

## Stage 2.46 authoritative completion mapping — 2026-09-12

| Принцип | Авторитетно доказателство | Остатъчна граница |
|---|---|---|
| Change integrity | exact R6 package SHA-256, `5/5` rollback, physical SHA-256 и independent package/live binding | доказва конкретния build/state, не обща сертификация |
| Verification independence | отделен `39095`-byte verifier повтори Git/source/runtime и `80/472/2297`, после доказа unchanged state | вътрешна engineering независимост, не third-party audit |
| Least functionality | completion amendment променя само същите пет документа; production/localization/tests са byte-exact | disabled capabilities остават за отделни stages |
| Secure usability | R5 human 11/11 PASS остава относимо без фиктивно повторение след docs-only change | touch-native context menu и Windows/macOS native behavior не са доказани |
| Traceability | реалните package, verifier, physical digest и final markers са записани преди repository finalization | commit/tag се приемат само от външния finalizer output |

User-ът прие exact five-document completion amendment. Тя не променя
съпоставянето към NIST SP 800-63B-4, SP 800-218, SP 800-38D, OWASP guidance
или Регламент (ЕС) 2024/2847 и не създава FIPS/CMVP, AAL, CE, official-audit,
legal-opinion, platform-native или release-readiness claim.

## Stage 2.47 recovery crosswalk — 2026-09-13

Това е engineering съпоставка, не декларация за съответствие. NIST SP
800-63B-4 е насочен към remote digital identity/CSP системи, докато MOKOSH
Stage 2.47 е локален еднопотребителски Vault. Неговите правила се използват
само като risk/usability ориентир, не като доказателство за AAL.

| Източник / принцип | Stage 2.47 решение | Доказателство | Разлика или остатъчен риск |
|---|---|---|---|
| NIST SP 800-63B-4 §4.2 saved recovery codes: случаен, достатъчно силен и offline пазен recovery secret | random 256-bit root, 25-word human form, paper или отделен local device | phrase vectors/bit coverage, storage separation и e2e tests | MOKOSH фразата не е NIST saved code и няма CSP/account notification |
| NIST SP 800-63B-4 §4.2: invalidate използвания saved recovery code | след recovery `.mokr` става stale за latest workflow, но старите bytes се пазят | old-record-stale и preserved-history tests | **явна gap:** няма cryptographic revocation; стар `.mokr` + фраза остават чувствителни |
| NIST SP 800-63B-4 §5: session control и reauthentication | setup само в unlocked session плюс current-password reauth; publish връща locked | session/capability/GUI/integration tests | няма AAL или network-auth claim |
| OWASP Forgot Password: CSPRNG, достатъчна дължина, secure storage, промяна само след валиден secret | random 256-bit root, exact `.mokr`+phrase verification, read-only preview | core orchestration и negative-source tests | offline local workflow; няма email/SMS side channel или server throttling |
| OWASP Forgot Password: нова парола два пъти и normal login след reset | exact confirmation; след publish няма auto-login | GUI и integration old/new password tests | existing old recovery copies не се revoke-ват |
| NIST SP 800-218 SSDF PW/RV: минимален scope, review, provenance, tests и отстраняване на root cause | exact 32 paths, pinned vocabulary/provenance, fault injection, full-disclosure log | scope/status/evidence + automated suites | вътрешен процес, не third-party assessment |
| BIP-0039 vocabulary/license | exact 2 048-word English list и MIT notice се vendорват | SHA-256/structure/license tests and provenance | използва се само речникът; 25-word MOKOSH-RP1 не е BIP39 mnemonic/seed |
| Linux least privilege / no-clobber / durable local write | exact 0700/0600, uid/type/nlink, no symlink, O_EXCL, fsync и double read | filesystem and injected-failure tests | root/compromised OS/physical media са извън защитата; FAT/exFAT са отказани |
| Data minimization | няма cloud, network, log, clipboard или app-stored phrase | import/static tests and bounded objects | plain-text sheet разкрива думите при достъп до носителя |

Проверени първични източници:

- NIST SP 800-63B-4, §§4–5: <https://pages.nist.gov/800-63-4/sp800-63b.html>
- NIST SP 800-218 SSDF 1.1: <https://csrc.nist.gov/pubs/sp/800/218/final>
- OWASP Forgot Password Cheat Sheet:
  <https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html>
- pinned BIP-0039 source:
  <https://github.com/bitcoin/bips/tree/bfc142f2b580a314c846dbce3c15c659c2b1d32d/bip-0039>
- NIST FIPS 203 current publication/errata page, относимо само към отделния
  existing ML-KEM boundary, не към recovery phrase:
  <https://csrc.nist.gov/pubs/fips/203/final>

FIPS 203 има NIST planning note от 2025-11-17 за бъдеща корекция/ревизия.
Stage 2.47 не променя ML-KEM implementation-а и не заявява FIPS validation.
Регламент (ЕС) 2024/2847, CE, продуктова cybersecurity conformity и правните
задължения остават отделна квалифицирана оценка.

## Stage 2.47 corrective crosswalk — 2026-09-15

| Принцип | Коригиращо решение | Постоянен gate |
|---|---|---|
| NIST SP 800-218 PW.7/RV.1 — root cause и регресия | откритите practical GUI дефекти се връщат към код, тест и повторна проверка преди нов stage | ledger D01–D13/TG01–TG04; няма „за после“ |
| OWASP Forgot Password — ясен и безопасен reset | current recovery state gate, exact local password mismatch, общ anti-oracle source mismatch, explicit publish, normal login след reset | positive/negative/state/restart tests плюс human transition |
| NIST SP 800-63B-4 recovery ориентир | използваният комплект става operationally stale, entry е пасивен и се искат нови външни копия | persistent status и първите две successful-login reminders |
| CWE-252/CWE-367/CWE-362 класове | write progress, descriptor checks, atomic replace, CAS counter, one-shot uncertain handling | short-write, race/conflict, replay и unchanged-snapshot tests |
| WCAG 2.2 usability ориентир | keyboard focus, visible labels, reflow/scroll, resize и action-specific controls | автоматични contracts плюс human EN/BG scale gate; няма WCAG conformance claim |

Официалните източници и ограниченията в предходната таблица остават
приложими. Корекцията не разширява crypto primitive или compliance scope.

## Stage 2.48 local V2 crosswalk — 2026-09-18

| Източник / принцип | Stage 2.48 решение | Проверимо доказателство | Разлика или остатъчен риск |
|---|---|---|---|
| NIST SP 800-38D authenticated encryption | използва съществуващия AES-256-GCM MOKOSH2 frame/slot core без промяна на primitive или wire format | pre-existing vector/tamper/frame suites плюс local round-trip | няма FIPS validation или independent cryptographic review |
| NIST SP 800-218 SSDF PW.4/PW.7/RV.1 | exact 32-path freeze, narrow service boundary, negative/race/fault tests и запис на limitations | baseline, scope, targeted и full regression gates | self-assessment, не third-party audit |
| CWE-367 TOCTOU | magic/public/pipeline source identity chain; residue има втори scan след sole session lease и fresh cleanup rescan | source replacement при всяка граница и scan/start race tests | код със същия компрометиран OS account остава извън доверената граница |
| CWE-59 / least-privilege filesystem | regular/no-symlink/no-clobber, `O_NONBLOCK` FIFO-race отказ, private quarantine, exact inode и directory-relative operations | FIFO, symlink, hardlink, collision, permission и replacement tests | Linux-only; други filesystem/OS семантики са отказани, не емулирани |
| CWE-362 concurrency | key/keyless sole session lease, един GUI worker и mutually-exclusive V2/recovery/MOK1 windows; lock/panic/timeout cancel преди Vault close | busy, lock-drain, sensitive-window, close-drain и integration tests | външен hostile process не се превръща в cooperating lease owner |
| CWE-252 / irreversible operation honesty | final hard-link разделя pre-publish failure от post-publish success-with-warning; след link няма retryable failure | unlink/stat/fsync/close/observer fault matrix | durable state може да изисква човешки технически review |
| Data minimization / privacy by default | generic suggested names, stable codes, без path/exception/key в result, log, network или telemetry | repr/static/localization tests | OS file chooser и filesystem естествено виждат избраните локални пътища |
| CWE-400 resource control | cancellation-aware pre-scan допуска максимум 4096 directory entries преди legacy reconciliation list | oversized-directory refusal и cancellation tests | same-account race след pre-scan е извън cooperating-process модела |
| WCAG 2.2 usability ориентир | EN/BG, keyboard focus, reflow, scroll, 100–200% synthetic matrix, visible cancel/warnings | main/local visual contracts и GUI structure tests | няма WCAG conformance claim; human matrix остава отделен gate |

Local profile приема само unsigned envelope с един Vault slot. Това е
application policy, не нов cryptographic standard. Signed/Contact/password
вариантите не се downgrade-ват, а се отказват. MOK1 е отделен historical
reader и никога не е fallback след MOKOSH2 отказ.

Stage 2.48 не променя ML-KEM, Argon2id, HKDF, AES-GCM или Ed25519 primitive
implementation и не заявява certification, CRA conformity, legal opinion или
native Windows/macOS security equivalence.

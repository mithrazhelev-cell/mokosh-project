# MOKOSH Stage 2.45.1 — fail-closed карантина на legacy contact подсистемата

Дата на решението: 2026-09-10

## Статус и граница

Този документ определя незабавна техническа карантина. Той не поправя и не
разрешава legacy contact криптографията. `contacts_core.py` е tombstone, който
отказва още при import, преди path resolution, filesystem достъп, прочит или
запис на `contacts.json`, зареждане на private key или cryptographic backend.

Нормалният `mokosh_gui.py` остава byte-exact със `SAFETY_MODE=True`. Съществуващият
V2 contact-slot core също остава byte-exact. Няма migration, delete, rewrite или
inspection на реални потребителски contact данни в този Stage.

Това е containment, не доказателство за завършена contact функция, production
готовност, interoperability, compliance, certification или independent audit.

## Практически установени факти

### Gate 1 — static capability и test-reachability inventory

- exact Stage 2.45 checkpoint е clean: commit
  `6c5d14a18f2184d247a700154add1a02d39d3358`, tree
  `ec608c8a54db90e068fff7b36f8b6d01d6f0271f`;
- активните runtime bindings в `contacts_core.py` са късните дублирани
  definitions, а не по-ранните skeleton definitions;
- няма exact `tests/test_contacts_core.py` и legacy contact функциите не са
  били практически покрити от пълната regression suite;
- това е evidence-gap факт, а не твърдение, че всяка непосочена функция е
  дефектна.

### Gate 2 — isolated primitive/runtime execution

- pinned `cryptography 49.0.0` изпълнява реален ML-KEM-768
  encapsulate/decapsulate с shared secret `32`, ciphertext `1088`, public key
  `1184` и private seed `64` bytes;
- legacy wrapper разменя `(shared_secret, ciphertext)` и записва `32` bytes
  като `pq_ciphertext`, вместо задължителните `1088`;
- legacy unwrap извиква несъществуващото
  `MLKEM768PrivateKey.from_private_bytes`, вместо наличното `from_seed_bytes`;
- след този отказ source-ът има отделен незавършен израз
  `ciphertext = base64.b`;
- isolated synthetic X25519/KEK/AES-GCM helper round-trip е успешен. Това не
  поправя contact protocol-а и не компенсира останалите дефекти.

### Gate 3 — synthetic Alice/Bob end-to-end execution

- нормалният reciprocal model криптира с recipient id `bob`, но Bob пази
  публичния ключ на sender-а под id `alice`; decrypt отказва с
  `Contact 'bob' not found`;
- legacy encryption отпечатва PQ success въпреки невалидния `32`-byte stored
  KEM ciphertext;
- PQ unwrap отказът се поглъща без warning и decrypt приема classic fallback
  само след изкуствено погрешно identity mapping;
- премахване на трите PQ header полета не причинява integrity отказ и classic
  decrypt продължава;
- промяна на `contact_id` от `bob` на `alice` не причинява integrity отказ и
  позволява decrypt при съответния public-key lookup;
- действителните legacy identity generators записват Base64-кодирани private
  X25519 key bytes и ML-KEM private seed в `contacts.json`. Mode `0600` е
  полезна filesystem граница, но не е Key Vault encryption;
- всички Gate 3 данни са синтетични, в runner-owned временна `0700` директория,
  изтрита преди final marker. Repository-то остава exact Stage 2.45.

## Защо предишните зелени тестове не доказват тази функция

Пълната suite е доказвала проверяваните V2/recovery/GUI свойства и byte-exact
изоляцията на legacy файла. Тя не е изпълнявала legacy Alice/Bob contact flow.
Следователно `2184 tests OK` не е било и не може да бъде честно тълкувано като
contact-crypto PASS. Stage 2.45.1 добавя тази разлика като постоянен invariant:

- test-run PASS означава само, че заявените assertions са изпълнени;
- function PASS изисква реалният production path да е изпълнен с positive,
  negative, tamper, boundary и failure evidence;
- disabled или quarantined функция се отчита като unavailable/blocked, никога
  като работеща;
- mock не може да замени задължителен реален cryptographic-backend или
  filesystem integration gate.

## Техническо решение

1. Legacy source остава проследим в Git history и Stage 2.45 bundle.
2. Текущият `contacts_core.py` съдържа само quarantine identifier, typed error и
   unconditional raise.
3. Tombstone-ът няма runtime import и не предлага старите callable имена.
4. Normal GUI и V2 contact-slot core остават byte-exact.
5. Десет predecessor regression tests запазват exact SHA-256 gate, но приемат
   само новия предварително изчислен tombstone digest. Другите digest-и и
   assertions не се променят.
6. Новите тестове изпълняват fresh isolated subprocess import и доказват
   nonzero refusal, exact typed marker и нулева data-directory промяна.

## Exact frozen path scope

Stage 2.45.1 има точно 20 допустими paths:

1. `contacts_core.py`
2. `tests/test_contacts_core_quarantine.py`
3. `tests/test_stage0_safety.py`
4. `tests/test_mokosh_main_gui_runtime_path_initialization.py`
5. `tests/test_mokosh_vault_recovery_entry_transition_main_gui_widget.py`
6. `tests/test_mokosh_vault_recovery_source_inspection_acknowledgement.py`
7. `tests/test_mokosh_vault_recovery_source_inspection_execution.py`
8. `tests/test_mokosh_vault_recovery_source_inspection_localization.py`
9. `tests/test_mokosh_vault_recovery_source_inspection_preparation_request_main_gui_widget.py`
10. `tests/test_mokosh_vault_recovery_source_inspection_presentation.py`
11. `tests/test_mokosh_vault_recovery_source_inspection_request_main_gui_widget.py`
12. `tests/test_mokosh_vault_recovery_source_inspection_ui_adapter.py`
13. `tests/test_mokosh_vault_recovery_source_selection_main_gui_widget.py`
14. `docs/LEGACY_CONTACT_CRYPTO_QUARANTINE_BG.md`
15. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
16. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
17. `docs/SESSION_LOG_BG.md`
18. `PROJECT_STATUS_BG.md`
19. `tests/test_mokosh_main_gui_recovery_chain_layout_audit.py`
20. `tests/test_mokosh_vault_recovery_source_inspection_normal_gui_authorization_readiness_audit.py`

## Непосредствени release blockers

Localization остава paused. След quarantine checkpoint-а последователните
малки corrective Stage-ове трябва практически да завършат преди contact
активиране или public release:

1. privacy-preserving inventory и изрично решение за legacy data
   recovery/migration, без implicit read/delete/rewrite;
2. V2 application-service contact workflow с mandatory X25519 + ML-KEM-768,
   authenticated identity/algorithm metadata и без classical-only downgrade;
3. Key Vault lifecycle за private contact keys, rotation/revocation и
   zero-secret evidence;
4. реален pinned-backend two-party interoperability harness с отделни
   Alice/Bob stores, malformed/tamper/wrong-key/replay/overwrite/fault tests;
5. normal-GUI integration и human practical matrix само след backend gates;
6. pre-distribution threat-model, dependency, platform, privacy и qualified
   legal/applicability review.

Нито един blocker няма waiver. Разделянето на малки Stage-ове е контрол на
риска, не отлагане или отслабване.

## Standards и правна честност

- NIST FIPS 203 е final baseline за ML-KEM и има official planning note от
  2025-11-17 за future correction; exact errata остава revision-watch.
- NIST SP 800-227 е final от 2025-09-18 и е explicit KEM implementation/use
  reference.
- NIST SP 800-38D остава final GCM reference с обявена revision работа.
- CRA reporting obligations започват на 2026-09-11, а main obligations — на
  2027-12-11. Exact MOKOSH scope/category/manufacturer/conformity route не се
  предполага и изисква qualified pre-distribution determination.
- Това mapping не е legal opinion, CRA/GDPR conformity, CE marking, FIPS/CMVP
  validation, NIST endorsement, certification или independent security audit.

Първични източници:

- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/sp/800/227/final
- https://csrc.nist.gov/pubs/sp/800/38/d/final
- https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://digital-strategy.ec.europa.eu/en/policies/cra-conformity-assessment

## Incident traceability

- Stage 2.46 R1 dry-run wrapper е дал false failure, защото е подал Python path
  с неправилен runtime type към installer validation. Independent diagnostic е
  потвърдил exact Stage 2.45 и no mutation. R1 е withdrawn.
- Stage 2.46 R2 dry-run е импортирал несъществуващото `ml_kem` име вместо
  доказаното project/backend име `mlkem`. Independent diagnostic е потвърдил
  ML-KEM boundary и no mutation. R2 е withdrawn.
- След два correction-package failure-а localization implementation е спряна
  съгласно правилото, а работата е върната към read-only security review.
- Първият scratch patch за Stage 2.45.1 е отказан преди mutation, защото една
  editor операция е съдържала едновременно delete и add за същия path.
  Атомарно разделяне е коригирало tooling механиката; това не е package/product
  PASS или failure и не е засегнало laptop repository.
- Първият affected candidate regression е изпълнил 414 tests с един честен
  FAIL: променен test файл е бил second-order SHA-256 dependency на друг test.
  Пълният baseline-hash graph е намерил точно два допълнителни test consumers.
  User-ът е приел corrected dependency-closed 20-path re-freeze преди тяхната
  промяна; няма skip, waiver или отслабване на assertion.
- Първият local exact-delta quality predicate е отказал преди package build,
  защото ръчно въведеният expected baseline digest за `contacts_core.py` е бил
  грешен. Candidate bytes не са били променени. Коригираният audit извлича
  digest-а директно от authoritative baseline и доказва exact 20-path status,
  точно 12 hash-consumer файла и 14 предварително моделирани substitutions.
- Първият опит за добавяне на този evidence record е отказан изцяло преди
  mutation поради несъвпадащ patch context в `SESSION_LOG_BG.md`. Записите са
  приложени поотделно към exact разрешените документи; scope не е разширен.
- Pre-package review е хванал installer-template self-test, който е търсел
  forbidden import spelling като raw текст, но същият spelling е присъствал в
  собствения му diagnostic literal. Няма издаден package. Predicate-ът е сменен
  с AST проверка на действителните import aliases и negative forbidden alias.
- Първият package build е спрял преди artifact creation, защото scratch
  средата няма `getfacl`. Release ACL gate-ът и exact laptop physical digest не
  са отслабени. Недоставяният QA profile използва explicit plain-mode ACL model
  и local shim само за control-flow testing; това не е authoritative ACL PASS.
- Първият local QA launch command е отказан преди execution от workspace
  safety policy заради shell recursive cleanup. Няма clone или package run.
  QA harness-ът използва `TemporaryDirectory` lifecycle; release runner bytes
  и project scope не са променени.
- Първият изпълнен pre-issuance QA package е отказал в installer self-tests:
  два unittest-summary regex литерала са имали незатворена character group.
  Baseline gate и project mutation не са започвали; temporary home е изчистен.
  Build-ът `235610` bytes / `1e018f9b…` и runner-ът `12298` bytes /
  `18668650…` са withdrawn и не се издават. Корекцията затваря patterns и
  добавя AST gate, който компилира всички literal regex-и преди baseline read.
  Това е първи Stage 2.45.1 pre-issuance package correction failure; втори
  correction failure задейства stop без трети опит.
- Коригираният QA twin е минал 13 self-tests и реалните Argon2id, ML-KEM-768,
  X25519 и AES-GCM probes, но е отказал на baseline physical-mode gate. QA
  driver-ът е създал fresh clone след наследен `umask 0077`, което е превърнало
  modeled `0644/0755` clone modes в observed `0600/0700`. Installer-ът правилно
  е отказал; rollback/candidate suites/project mutation не са започвали и
  temporary residue е zero. Build `236519` / `d64f9248…` и runner `12298` /
  `6e418430…` са withdrawn. Това е correction failure 2 и package работата е
  спряна; не се допуска трети опит без ново explicit recovery решение.
- След explicit recovery re-freeze QA copy-equivalence и единственият разрешен
  fresh QA package cycle са PASS, но authoritative laptop R1 dry-run е отказал
  след self-tests/runtime probes върху `baseline target mode drift:
  contacts_core.py`. Издаденият manifest погрешно задава `0644` за всичките 18
  existing targets. Тази стойност е била извлечена от Git clone, който не може
  да запази физическата разлика `0600/0644/0664`; QA baseline и gate са имали
  един и същ грешен oracle. Wrapper `line=73` е само редът `bash "$runner"`, на
  който вътрешният nonzero exit се е разпространил, не root-cause line.
- R1 archive `237250` / `76c01ea8…` и runner `12298` / `1f0ae760…` са withdrawn
  и не трябва да се стартират повторно. Failure-ът е преди rollback candidate,
  tests или overlay; independent live no-mutation/mode diagnostic остава
  задължителен преди каквото и да е ново correction решение.

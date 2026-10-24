# MOKOSH Stage 2.34 — source-inspection acknowledgement contract

## Статус и цел

Stage 2.34 добавя pure, bounded, process-local и one-shot acknowledgement върху
една exact Stage 2.33 source-inspection presentation. Acknowledgement означава
единствено, че API е получило пълния exact ordered tuple от трите frozen
confirmation enum tokens за същата revalidated presentation.

Stage-ът не доказва човешко прочитане/разбиране, user identity, informed
consent, digital signature, source provenance, cryptographic authenticity,
freshness, recovery или operation authority.

## Exact source boundary

Public функцията
`prepare_recovery_source_inspection_acknowledgement(presentation)` приема само
exact `VaultRecoverySourceInspectionPresentation`. Subclass, mapping, string,
друг dataclass или malformed/forged Stage 2.33 schema се отказват.

Stage 2.33 validator-ът се изпълнява изцяло. Това доказва schema consistency,
не provenance на object-а: Python caller може директно да конструира иначе
валидна presentation с произволен 32-byte evidence digest. Поради това Stage
2.34 не превръща digest-а в authentication или trusted origin claim.

## Canonical presentation binding

Prepared acknowledgement не задържа original presentation. То пази само:

- repr-hidden presentation SHA-256;
- exact locale;
- fixed ordered confirmation tuple.

SHA-256 се изчислява върху нов domain-separated canonical binary transcript,
който обвързва:

- locale;
- Stage 2.33 inspection-evidence digest;
- седемте exact ordered message enum keys;
- трите exact ordered confirmation enum keys;
- всички 32 Stage 2.33 safety/honest-claim flags;
- Stage 2.33 format и version.

Transcript-ът използва fixed-width big-endian encoding и length-prefixed ASCII
enum/format values. Digest comparison използва `hmac.compare_digest`, но
digest-ът не е secret MAC, signature, consent record, persisted trust token,
provenance proof или anti-rollback anchor.

## Confirmation semantics

`acknowledge_once(presentation, confirmations)` приема само exact tuple:

1. structure is not authenticity;
2. fresh secure reopen is required;
3. no recovery or operation was performed/authorized.

Tuple-ът трябва да е с дължина точно три, с exact enum types, без duplicate,
missing, extra, raw-string, list или reordered values. Future UI слой трябва
отделно да докаже visibility, individual selection и explicit user action.
Stage 2.34 core не прави тези human-interface claims.

## One-shot, failure и concurrency

Prepared object използва process-local lock. Единственото committed lifecycle
състояние е immutable receipt reference:

- преди success receipt е `None` и state е `AWAITING_CONFIRMATIONS`;
- след един success receipt е зададен и state е `ACKNOWLEDGED`;
- след success всеки опит отказва като replay преди input validation;
- malformed confirmation, source mismatch, ordinary `Exception` или
  `BaseException` преди final assignment не consume-ва object-а;
- interruption след final assignment оставя object-а fail-closed consumed.

Този модел избягва drift между отделни `_receipt` и `_acknowledged` mutable
полета. Exactly-one важи за конкретния prepared object, не е global user/
presentation consumption guarantee.

## Receipt и privacy

Receipt е frozen/slotted, repr-hidden за presentation digest и отказва copy,
deepcopy и serialization. Съдържа само digest, locale, exact confirmations,
fixed count/sequence/state и explicit safety/honest-claim booleans.

Не съдържа original presentation/outcome, Recovery/Vault ID, revision, size,
raw source/record hashes, path, filename, descriptor, source bytes,
ciphertext, secret, password, callback, executor, gate или operation input.

Deterministic digest може да служи като process-local correlation handle.
Затова не се log-ва, serialize-ва, persist-ва или изпраща и не се представя
като anonymous/pseudonymous legal conclusion. Python/OS memory zeroization не
се твърди.

## Capability boundary

Stage 2.34 няма GUI, localization renderer, filesystem, storage, reconciliation,
Vault access, recovery secret, crypto authentication, process, network,
logging, clock, randomness, callback, executor или mutation capability.

Fresh import транзитивно зарежда pure Stage 2.33/2.32 schema chain, но не
зарежда Stage 2.5 storage reader, main GUI или localization renderer. Stage
2.32 secure reader не се извиква.

## Project integrity и standards watch

Действа `MOKOSH Project Integrity and Full Disclosure Invariant`: всяка
открита грешка, deviation, assumption, risk, addition, update или standards
change се съобщава и се записва с rationale/evidence/tests. Няма silent scope,
fallback, claim или security weakening.

Към 2026-08-29 tracked reminders са:

- NIST SP 800-218 v1.1 остава final SSDF baseline;
- SP 800-218 Rev.1 / SSDF 1.2 е Initial Public Draft от 2025-12-17 и не се
  третира като final;
- FIPS 203 има NIST planning note от 2025-11-17 за issue, предвиден за future
  update/revision;
- SP 800-38D Rev.1 е second preliminary/pre-draft work от 2026-06-01, не final;
- EU CRA Article 14 започва да се прилага от 2026-09-11 за продукти в обхвата,
  а общата приложимост е от 2027-12-11;
- GDPR Article 25 privacy-by-design/default се оценява, когато обработването и
  ролята на продукта попадат в приложимия обхват.

Преди криптографска, release или legal decision тези записи се проверяват
отново от първичните NIST/EUR-Lex източници. Те не са self-certification,
independent audit или правно становище.

## Test evidence

Точно 42 targeted tests покриват BG/EN, exact Stage 2.33 revalidation, direct
digest-construction honest claim, complete transcript, mismatch, exact ordered
confirmations, failed-attempt non-consumption, replay, concurrency,
`Exception`/`BaseException`, single receipt state commit, private binding
revalidation, strict receipt schema/booleans, privacy, no-authority claims,
copy/serialization, AST/import isolation, no Stage 2.32 reader и critical
unchanged hashes.

Първият targeted cycle е 40 pass / 1 fail поради test-helper sentinel defect:
explicit `None` е било заменяно с default valid presentation. Production API
не е причината. Helper-ът е поправен и повторният 42-test gate е PASS.

Pre-package scratch full-suite опитът не е authoritative PASS: scratch runtime
няма `argon2`, поради което три existing test modules не могат да се import-нат
и резултатът е 1645 tests, errors=3, skipped=7. Това е environment limitation,
не product regression, и не заменя задължителния exact 1674-test gate чрез
изолирания `$HOME/venv_sys` на основния Linux лаптоп.

Първият laptop installer dry-run спира fail-closed преди temporary clone/
patch/tests: protected-legacy verifier-ът изпълнява `sha256sum -c` от quarantine
root, а четирите originals са в exact поддиректория `files/`. Това е installer
path-resolution defect, не missing/corrupt evidence или product defect. Repo не
е променено. R1 verifier-ът изисква exact private `files/` directory и изпълнява
manifest проверката от нея срещу parent `SHA256SUMS`.

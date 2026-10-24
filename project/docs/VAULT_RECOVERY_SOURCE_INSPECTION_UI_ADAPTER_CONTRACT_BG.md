# MOKOSH Stage 2.35 — source-inspection UI adapter contract

## Статус и цел

Stage 2.35 добавя pure, bounded и process-local UI adapter core върху една
exact Stage 2.33 source-inspection presentation и private Stage 2.34
acknowledgement. Това е view-model и interaction contract, а не истински GUI,
localization renderer, consent mechanism или recovery operation.

Целта е бъдещ отделен renderer да получи exact fixed-key view и да подаде само
три отделни, видими, изрично избрани и user-initiated confirmation events.
Adapter assertion не доказва физическо показване, accessibility conformance,
човешко разбиране, identity или informed consent.

## Exact source и private binding

`prepare_recovery_source_inspection_ui_adapter(presentation)` приема само exact
`VaultRecoverySourceInspectionPresentation`. Stage 2.33 schema и Stage 2.34
canonical binding се revalidate-ват изцяло. Subclass, mapping, raw string,
malformed/forged schema или authority claim се отказват.

Prepared adapter създава private Stage 2.34 acknowledgement за същия exact:

- repr-hidden presentation SHA-256;
- locale;
- седем ordered message keys;
- три ordered confirmation keys.

Private acknowledgement type, binding, required confirmations и fresh state се
проверяват в constructor-а. Друг digest, locale, tuple или вече консумиран
private object се отказва. Stage 2.35 не приема caller-supplied callback,
executor, gate или operation capability.

## Fixed key-only view

View-ът съдържа точно седем ordered message items със stable ordinals 1–7 и
точно три отделни confirmation controls със stable ordinals 1–3. Всички keys
са exact Stage 2.33 enum members; няма raw/rendered text или fallback key.

Всеки message item е `visible=True` и има bound accessibility-label key.
Всеки confirmation control е:

- visible и required;
- individually selectable;
- default unselected;
- без select-all;
- с bound accessibility-label key.

View-ът забранява auto-accept, remembered selection и operation controls.
Тези стойности са contract assertions на adapter-а. Само бъдещ real GUI и
отделна human/platform проверка могат да дадат evidence за действително
rendering, focus/order, screen-reader behavior или usability.

## Exact interaction tuple

`acknowledge_visible_once(presentation, events)` приема само tuple с точно три
`RecoverySourceInspectionUIConfirmationEvent` обекта. За всеки ordinal и key
трябва да съвпадат с frozen control-а, а следните exact bool стойности трябва да
са `True`:

- `visible`;
- `user_selected`;
- `user_initiated`.

List, empty/partial/extra tuple, duplicate, reorder, raw-string lookalike,
hidden, unselected или non-user-initiated event се отказва преди delegation.
Няма select-all, implicit acceptance или remembered state.

## Fail-closed lifecycle и interrupt boundary

Prepared adapter използва един lock и точно един `_terminal` marker:

- `None` означава `AWAITING_USER_CONFIRMATIONS`;
- private terminal-failure sentinel означава `FAILED_CLOSED`;
- exact immutable receipt означава `ACKNOWLEDGED`.

Source/view/event validation се извършва преди terminal boundary. Malformed
input или mismatch преди boundary не consume-ва adapter-а и коректен следващ
опит е разрешен.

Непосредствено преди private Stage 2.34 delegation marker-ът атомарно става
terminal failure. След тази точка ordinary failure, unexpected exception или
`BaseException` оставя adapter-а `FAILED_CLOSED`. Това затваря прозореца, при
който private acknowledgement може да е консумирано, а outer adapter да
изглежда fresh. Само след валиден private receipt, exact private terminal
state/receipt identity и валиден outer receipt marker-ът се заменя с
`ACKNOWLEDGED` receipt.

Concurrency допуска точно една terminal delegation. След success или
post-boundary failure всеки нов опит е replay преди input validation. Невалиден
вътрешно подменен terminal marker не се интерпретира като success, а причинява
format error.

## Receipt, privacy и честни твърдения

Receipt е frozen/slotted, repr-hidden за digest и отказва copy, deepcopy и
serialization. То съдържа само locale, binding digest, exact confirmation
tuple/count/sequence/state и bounded safety booleans.

Receipt доказва единствено, че adapter core е revalidate-нал собствените си
view/event assertions и exact private Stage 2.34 receipt. То не доказва:

- actual GUI rendering или accessibility conformance;
- human understanding, user identity или informed consent;
- digital signature, provenance, authenticity или freshness;
- recovery secret, rehearsal, recovery или Stage 2.8 use;
- review session, authorization, gate invocation или operation;
- filesystem, network, logging или GUI activity.

Original presentation/outcome, raw IDs, revision, size, source/record hashes,
path, source bytes, secret, password и renderer state не се задържат. Digest-ът
е process-local mismatch binding, не trust token, и не се persist-ва, log-ва
или изпраща. Memory zeroization не се твърди.

## Capability boundary

Stage 2.35 не import-ва GUI toolkit, localization renderer, storage,
reconciliation, workflow, crypto, filesystem, process, network, logging, time
или randomness dependencies. Няма source reader, callback, executor, mutation
API, Stage 2.8 invocation или recovery authority. Existing Stage 2.32–2.34,
GUI, storage и crypto кодът остават byte-exact.

## Historical pre-activation hardening reminder

Fresh review откри отделен historical Stage 2.12 lifecycle pattern с две
състояния (`_receipt`/`_acknowledged`) и narrow interrupt gap след nested
acknowledgement success, преди outer commit. Stage 2.12 е inactive,
safety-gated и няма operation authority, поради което Stage 2.35 не го променя.

Преди бъдещо активиране на Stage 2.12/2.14/2.18 path е задължителен отделен
High review и freeze за single-terminal-marker hardening, interrupt/fault
tests и regression на real GUI seam. Това е tracked risk reminder, не claim за
текущ exploitable recovery capability и не е разрешение за silent patch.

## Project integrity и standards watch

Действа `MOKOSH Project Integrity and Full Disclosure Invariant`: всяка грешка,
deviation, assumption, risk, промяна, добавка, update, standards revision,
erratum или нормативен срок се съобщава и записва. Няма silent fallback, scope
change, claim weakening или автоматично приемане на draft като final.

Към 2026-08-29 watch ledger остава: final NIST SP 800-218 v1.1; SP 800-218
Rev.1/SSDF 1.2 IPD; FIPS 203 future-update note; SP 800-38D Rev.1 second
pre-draft; EU CRA Article 14 от 2026-09-11 и обща приложимост от 2027-12-11 при
приложим product scope; GDPR Article 25 при приложим processing scope. Всяка
релевантна промяна изисква fresh primary-source review, impact analysis и нов
freeze. Няма self-certification, independent audit или legal conformity claim.

## Test evidence

Точно 49 targeted tests покриват BG/EN view, exact source/private binding,
седемте messages, трите default-unselected controls, strict view/event/receipt
schemas, partial/reorder/duplicate/extra/lookalike/hidden/unselected events,
retryable pre-boundary failures, equivalent presentation, terminal private
failure, ordinary/`BaseException` paths, interrupt след private success,
exactly-one concurrency, single marker, replay precedence, privacy,
copy/serialization, repr redaction, AST/import isolation и critical unchanged
hashes.

Първият targeted cycle е `Ran 49` с 1 failure и 2 errors. И трите са test
harness defects: helper default е поглъщал explicit `None`; fresh subprocess с
`-I` не е получил explicit repo import path; един critical-hash entry е бил с
неточно filename/hash. Production module failure не е наблюдаван. Harness-ът е
поправен, exact predecessor hashes са взети от проверения Stage 2.34 tree и
повторният targeted gate е 49/49 PASS.

Последващият scratch full-suite опит е non-authoritative failure: 1694 tests,
errors=3, skipped=7, защото scratch runtime няма `argon2` и три existing test
modules не могат да се import-нат. Не е използван dependency bypass и това не
заменя laptop gate.

Expected authoritative laptop full gate е 1723 tests: OK, expected failures=3
само за legacy MOK1, skipped=0, плюс 129 tracked Python sources. Това остава
очакване до installer dry-run/apply на основния Linux лаптоп; scratch targeted
PASS не се представя като laptop/full/package PASS.

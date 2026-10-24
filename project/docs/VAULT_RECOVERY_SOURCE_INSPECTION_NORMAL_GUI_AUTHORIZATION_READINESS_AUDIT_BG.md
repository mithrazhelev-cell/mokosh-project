# MOKOSH — Stage 2.45 normal-GUI source-inspection authorization readiness/privacy audit

Статус: **GO WITH BLOCKERS — audit-only, без production разрешение**
Дата на freeze: 2026-09-08
Авторитетен baseline commit: `77c9432b519a8fd0c7ed7f446e39fbdc13547fb2`
Авторитетен baseline tree: `5b60a8520b7dfbbab4054a73766f60be6fda25b5`

## 1. Цел и граница

Stage 2.45 проверява готовността за бъдещо, отделно свързване на exact positive
Stage 2.31 normal-GUI outcome към вече съществуващата Stage 2.32 one-secure-read
граница. Този Stage не реализира и не активира свързването.

Одитният резултат `GO WITH BLOCKERS` означава само, че съществува архитектурно
допустим път към бъдещ freeze. Той **не** означава GO за production промяна,
source access, secure read, review activation, recovery operation, release или
commit/tag. Всеки blocker в раздел 11 е задължителен вход към нов, изрично приет
scope freeze; липса или отслабване на blocker означава `NO-GO`.

## 2. Exact Stage 2.45 scope

Freeze-ът съдържа точно шест paths:

1. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_NORMAL_GUI_AUTHORIZATION_READINESS_AUDIT_BG.md` — нов;
2. `tests/test_mokosh_vault_recovery_source_inspection_normal_gui_authorization_readiness_audit.py` — нов;
3. `PROJECT_STATUS_BG.md` — допълнение;
4. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md` — допълнение;
5. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md` — допълнение;
6. `docs/SESSION_LOG_BG.md` — допълнение.

`mokosh_gui.py`, всички production модули, locale strings, launchers, crypto,
Vault, storage, Contacts и network paths остават byte-exact спрямо baseline.

## 3. Проверено текущо състояние

- Stage 2.43 normal GUI има пет отделни действия. Петото извиква pure Stage 2.31
  preparation-request contract и връща outcome към Tk callback.
- Върнатият Stage 2.31 outcome не се предава към Stage 2.32. Normal GUI няма
  Stage 2.32 import/call и не отваря/чете recovery source.
- Stage 2.32 вече изисква exact positive Stage 2.31 outcome и отделно
  `RecoverySourceInspectionExecutionDecision.AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION`.
  При positive decision той прави точно един conditional secure structural read.
- Stage 2.32 изчиства retained path преди reader call; success outcome не пази
  path, descriptor, record bytes, header bytes, nonce или ciphertext.
- Stage 2.39–2.41 review chain е отделна граница и не се активира автоматично.

Следователно липсващата част е normal-GUI handoff и неговата отделна човешка
медиация, а не нов privileged reader или нов authorization primitive.

## 4. Задължителна бъдеща mediation последователност

Бъдещ Stage може да предложи само следната логическа последователност:

1. петото действие завършва с exact positive Stage 2.31 outcome;
2. normal GUI показва ново, отделно **шесто действие**, започващо locked;
3. само exact positive Stage 2.31 outcome може да arm-не шестото действие;
4. клик/keyboard activation на шестото действие отваря отделно path-free
   confirmation, което ясно казва, че ще бъде извършен един structural read;
5. default/cancel/close/negative route е `PRESERVE_AND_STOP` и не чете source;
6. само explicit positive confirmation избира exact Stage 2.32
   `AUTHORIZE_ONE_SECURE_SOURCE_INSPECTION` decision;
7. Stage 2.32 изпълнява at most one secure read и става terminal;
8. result се представя само като bounded structural evidence и **не** активира
   Stage 2.39, Stage 2.40 или Stage 2.41.

Забранени са direct Stage 2.29 → Stage 2.32 route, повторно използване на стар
Stage 2.31 outcome, implicit/default-positive authorization, auto-click,
timer-driven authorization и authorization в същото действие/диалог като
Stage 2.31 preparation request.

## 5. Бъдещ one-shot lifecycle и fail-closed правила

Бъдещият GUI event трябва да има проверим lifecycle:

`LOCKED → READY → DECIDING → COMPLETED` при terminal success/preserve и
`LOCKED/READY/DECIDING → FAILED` при нарушение или грешка.

- Само `READY` може да започне decision; concurrent/replayed activation връща
  no result и не отваря втори dialog/read.
- Exact Stage 2.31 reference и bound locale се clear-ват под lock **преди**
  conditional Stage 2.32 loader и преди confirmation dialog.
- Локалната predecessor reference се освобождава веднага след създаване на
  Stage 2.32 prepared execution; няма повторно задържане в widget/controller.
- Stage 2.32 може да държи path само докато е awaiting decision; path се clear-ва
  преди preserve/result или преди reader call, както изисква текущият contract.
- Ordinary exception води до generic localized path-free error и terminal
  `FAILED`; `BaseException` маркира terminal failure и се propagate-ва.
- Partial UI failure, loader failure, invalid/forged outcome, lost widget,
  invalid locale, replay и concurrency никога не downgrade-ват към read.
- Няма retry върху същия prepared object и няма global-consumption claim за
  caller-owned immutable outcome. Python memory zeroization не се твърди.

## 6. Privacy и disclosure contract

Confirmation и result текстовете трябва да са fixed/localized и да не включват
path, filename, directory, username, hostname, recovery/vault identifier,
hash, size, exception detail, secret, nonce или ciphertext.

Не се допуска logging, telemetry, clipboard, screenshot, network, persistence
или analytics на path/outcome/decision. Не се въвежда свободен текст. Outcome
към следващ bounded слой не носи path или source bytes.

UI трябва изрично да разграничава:

- structural parsing/validation от cryptographic authentication;
- inspection evidence от recovery proof или operation authorization;
- process-local one-shot behavior от global consumption;
- reference clearing от доказана memory zeroization.

Stage 2.32 read не заявява application-requested filesystem mutation. На POSIX
четенето все пак може да промени filesystem-managed `atime` според mount,
filesystem и kernel policy; Stage 2.45 не твърди forensic no-change гаранция.
Observed file identity е валидна само за завършения read и не дава future
identity guarantee.

## 7. Забрани за automatic review и authority escalation

Stage 2.32 result не може автоматично да:

- подготви или покаже Stage 2.39 review session;
- създаде Stage 2.40 main-GUI binding;
- активира Stage 2.41 conditional review widget/window;
- поиска recovery secret, decrypt, authenticate, reconcile или recover;
- разреши write, replace, rename, unlink, chmod, publish или друга операция.

Такова действие изисква отделен бъдещ user action, отделен confirmation и нов
приет frozen scope. Нито audit `GO WITH BLOCKERS`, нито structural success са
authorization token за следващ слой.

## 8. Safe synthetic human-test fixture за бъдещ implementation Stage

Stage 2.45 няма GUI промяна и затова няма human visual matrix. Бъдещият Stage,
който променя normal GUI, трябва да има собствен self-contained human matrix и
безопасен synthetic fixture със следните exact минимални свойства:

- fixture е изцяло synthetic, non-secret и не е копие на реален recovery record;
- създава се в runner-owned нов private directory с mode `0700`, например под
  physical `~/Downloads`, а не директно в обичайния shared-mode Downloads;
- record е regular file, current-user-owned, single-link, mode `0600`, bounded,
  с canonical `mokosh-vault-recovery-<32 lowercase hex>.mokr` filename;
- bytes образуват structurally valid record, но не съдържат recovery secret и
  не се представят като cryptographically authenticated или recoverable;
- creation е exclusive/no-follow; всеки component, owner, mode, type, link
  count, identity и size се validate-ва преди употреба;
- cleanup изтрива само runner-owned exact inode след повторна identity проверка,
  после премахва само празната runner-owned directory; при несигурност отказва
  чуждо изтриване и докладва fail-closed;
- cleanup се изпълнява при success, failure, cancel, interrupt и `BaseException`
  преди report; report е path-free и отличава fixture mutation от MOKOSH
  application behavior;
- инструкциите посочват exact control/key/order/effect и не зависят от chat;
  observation започва `not_checked`, PASS не е предварително избран.

## 9. Stage 2.45 verification closure

- нов audit test module: точно `32/32` methods;
- relevant predecessors: Stage 2.31 `33/33`, Stage 2.32 `44/44`, Stage 2.43 GUI
  boundary `48/48`, storage `48/48`; combined target `205/205`;
- final full regression target: `2184/2184`, точно три документирани legacy
  expected failures и `0` skips в pinned laptop runtime;
- exact six-path allowlist, no staged files, rollback injection, owner/modes,
  plain ACL, Git diff-check/fsck и unchanged bytecode са задължителни;
- поне един independent post-apply/pre-commit gate е задължителен преди commit;
- Stage 2.45 не изисква human visual matrix, защото production/GUI bytes са
  immutable. Ако GUI byte се промени, Stage 2.45 е `NO-GO` и се re-freeze-ва.

## 10. Standards и legal-status граница

Mapping-ът използва NIST SP 800-218 SSDF 1.1 като final project guidance.
SP 800-218 Rev. 1 / SSDF 1.2 е Initial Public Draft от 2025-12-17 и не се
представя като final standard. WCAG2ICT 2.2 е W3C Group Note от 2025-12-11 и е
informative. ETSI EN 301 549 V4.1.1 е публикуван през 2026-09; самото издание
не доказва citation в Official Journal или presumption of conformity.

CRA reporting readiness за manufacturer в приложим scope започва 2026-09-11
(24-hour early warning и 72-hour full notification), а основните obligations —
2027-12-11. Commission implementation guidance от 2026-07-27 е non-binding.
Exact MOKOSH manufacturer/product/service/distribution/market scope изисква
qualified pre-distribution legal review.

Този одит не е NIST endorsement, accessibility evaluation, WCAG/EN conformity,
CRA/EAA/GDPR compliance, CE marking, platform certification, independent
security audit, formal verification или правно становище.

## 11. Blockers преди бъдещ production freeze

1. Exact sixth-action BG/EN UX, path-free confirmation и default-negative route.
2. Отделен locked/ready/deciding/completed/failed event с доказана one-shot,
   replay и concurrency семантика.
3. Exact Stage 2.31 → Stage 2.32 binding и reference-clearing order без direct
   Stage 2.29 route или top-level privileged import.
4. Generic path-free error policy и bounded result disclosure, включително
   structural-not-authenticated и POSIX `atime` caveat.
5. Доказано отсъствие на automatic Stage 2.39–2.41 activation и operation
   authority; следващите layers остават отделен freeze.
6. Self-contained safe synthetic fixture/cleanup и нов human GUI matrix за
   реалните BG/EN, keyboard, scale/reflow, cancel/preserve/authorize/failure
   routes върху целевата платформа.
7. Exact automated regression/rollback/integrity closure и independent gate.
8. Fresh official-source/legal applicability review преди distribution.

До отделното приемане и доказване на всички осем blockers production bridge-ът
остава забранен. Няма silent waiver, silent fallback или scope expansion.

## 12. Authoritative Stage 2.45 R2 evidence

- R2 deterministic package е `149309` bytes, SHA-256
  `5ed4b80a5ace17acfb400c8c6225eb849168764a8f0859260c559714aa0bd4c7`.
- Dry-run и transactional apply изпълниха отделни candidate/live 32/205/2184
  PASS cycles при точно три expected failures и zero skips. Rollback injection
  е 6/6; live delta е exact six unstaged paths.
- Independent read-only verifier (`21027` bytes; SHA-256
  `02c72b8f401ae96b1cb2490c71c3a2141085170c784f89403551ce9397851d98`)
  потвърди package/live bytes, Git status/history/tag/fsck, 214 physical paths,
  modes/owner/plain ACL, 8 critical production hashes, unchanged 4341-record
  bytecode и трети 32/205/2184 PASS cycle.
- R1 success-exit defect е withdrawn и остава документиран; той не е използван
  за apply. R2 е authoritative live candidate.
- Final audit decision остава **GO WITH BLOCKERS — audit-only, без production
  разрешение**. Това evidence не изпълнява осемте blockers и не разрешава
  бъдещия bridge, source read или review activation.

## 13. Final-evidence extraction-validator traceability

- Final-evidence R1 (`148782` bytes; SHA-256
  `178dabddb077e564ae0ff802e6e4caa70b33a44140cd3f8d49220243cec81d12`)
  е withdrawn след safe pre-installer false rejection.
- Exact archive identity и 10 safe normalized members са потвърдени. Python
  `filter="data"` под private `umask 0077` е извлякъл directory entries като
  `0700`, но външният validator погрешно е изискал archived `0755` и е отказал
  с `REFUSED_EXTRACTED_METADATA_MISMATCH`.
- Installer execution, tests и live overlay не са започнали; repository state
  е непроменен. R2 коригира само extraction-mode validation и запазва всички
  path/type/owner/size/hash проверки и exact six-path audit-only граница.
- Инцидентът не променя одитното решение: **GO WITH BLOCKERS** остава в сила и
  не разрешава production bridge, source read, review activation, commit или
  tag преди останалите задължителни gates.

## 14. Final-evidence R2 pre-commit whitespace-gate incident

- R2 dry-run/apply и independent pre-commit regression са действителни PASS
  върху exact R2 bytes, но не разрешават commit при неуспешен repository
  quality gate.
- След staging `git diff --cached --check` е открил точно три trailing-space
  реда — 3, 4 и 5 в този нов untracked преди staging audit документ. Предишният
  `git diff --check` не е обхванал untracked файла.
- Failure guard е върнал exact шестте пътя unstaged. Commit и tag не са
  създадени; production/test bytes и repository HEAD са непроменени.
- Final-evidence R2 остава historical evidence, но е withdrawn като checkpoint
  candidate. R3 премахва exact трите trailing spaces и изисква директен
  byte-level trailing-whitespace scan върху всички шест allowlisted файла,
  включително untracked, преди candidate/live authorization.

## 15. Final-evidence R3 Git-object traceability

- R3 package/runner/self-test/runtime gates са PASS, но strict fsck е отказал
  преди candidate или live overlay, защото baseline allowlist-ът е останал на
  трите historical dangling blobs.
- Failed R2 pre-commit staging е записал шест допълнителни unreachable blobs.
  Read-only classification потвърждава exact content SHA-256 match към шестте
  R2 staged paths; index cleanup не изтрива object-store records.
- R3 е withdrawn. R4 трябва да запази и валидира exact деветте type/OID/size/
  SHA-256 records, включително exact six-path classification, без `git prune`,
  неизвестен-object fallback или broad fsck acceptance.
- Worktree остава exact six-path R2 state без commit/tag/staging. Одитното
  решение остава **GO WITH BLOCKERS** и няма production permission.

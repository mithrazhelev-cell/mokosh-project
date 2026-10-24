# MOKOSH Agent — Stage 2.39 Vault recovery source-inspection review controller contract

## Статус

Този договор замразява Stage 2.39 като изолиран application-service controller
над вече доказаните Stage 2.32–2.38 read-only слоеве. Той не разширява recovery
authority и не прави accessibility, security, legal или standards certification
claim.

## Единствен публичен preparation вход

`prepare_recovery_source_inspection_review_session(execution_outcome)` приема
само exact `VaultRecoverySourceInspectionExecutionOutcome` от Stage 2.32.
Caller-controlled locale няма. Locale остава bound в Stage 2.32 evidence и се
пренася през Stage 2.33 presentation, Stage 2.35 adapter и Stage 2.36
localization.

## Композиция

Stage 2.39 композира само:

1. Stage 2.33 `prepare_recovery_source_inspection_presentation`;
2. Stage 2.35 `prepare_recovery_source_inspection_ui_adapter`;
3. Stage 2.37 `prepare_recovery_source_inspection_review_window` за exact
   binding validation;
4. Stage 2.37/2.38 `show_recovery_source_inspection_review_window` при
   `show_once(parent)`.

Stage 2.38 corrective runtime resize/layout protections остават част от този
existing display path; Stage 2.39 не ги дублира и не ги променя.

## One-shot lifecycle

`PREPARED -> DISPLAYING -> COMPLETED | FAILED`.

State transition към `DISPLAYING` е atomic под process-local lock преди GUI
delegation. След започнал display всяко Exception/BaseException/interrupt или
post-display validation fault е terminal. Няма replay/retry на consumed session.

## Retention boundary

Prepared session не задържа оригиналния Stage 2.32 execution outcome, recovery
ID, vault ID, source revision/hash/size, path, source descriptor/content,
password, secret, callback, executor или operation capability. Тя държи само
Stage 2.33 presentation, fresh Stage 2.35 adapter и bounded expected locale/
presentation digest, необходими до `show_once`.

При `COMPLETED` или `FAILED` presentation и adapter references се изчистват.

## Outcome revalidation

Stage 2.37/2.38 result се приема само ако е exact
`VaultRecoverySourceInspectionReviewWindowOutcome`. Controller-ът reconstruct-ва
чрез dataclass validation и проверява exact bound locale и presentation SHA-256
с constant-time digest comparison. Ако има acknowledgement receipt, неговите
locale и digest също трябва да съвпадат. Forged authority flags, malformed
receipt, subclass/non-outcome или mismatch дават fail-closed terminal error.

## Забранени възможности

Stage 2.39 няма filesystem/source reader, Vault read/write, crypto, recovery
execution, Stage 2.8 call, network, logging, dynamic import, main-GUI wiring,
Contacts, callback/executor или operation/recovery authority.

Няма промяна на Stage 2.32–2.38 production modules.

## Evidence gate

Frozen targeted module съдържа точно 20 tests за source validation/retention,
outcome binding, one-shot lifecycle/concurrency и static trust boundaries.
След тях остават задължителни приложимите Stage 2.32–2.38 regressions и full
repository suite. Existing expected failures не се преименуват на Stage 2.39
defects.

## Process correction

Superseded правилото „точно три stage-а на чат“ вече не е действащо. Текущото
постоянно правило е: след всеки успешно приложен и затворен Stage се започва
нов чат. Историческите immutable contracts не се пренаписват; active evidence
документите се коригират с explicit supersession note.

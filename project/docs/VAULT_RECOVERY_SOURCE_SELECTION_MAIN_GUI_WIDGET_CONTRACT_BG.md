# MOKOSH — договор за main-GUI recovery source selection

Статус: Stage 2.28 — отделно заключено one-shot GUI действие за native picker
и pure Stage 2.27 path-metadata selection; няма source open/read/identity,
secret intake, preparation, recovery session или operation authority.

## 1. Цел и последователност

Normal main GUI показва три отделни recovery действия:

1. Stage 2.20 записва exact Stage 2.19 recovery-review request;
2. Stage 2.25 записва exact Stage 2.21 future-source-selection intent;
3. Stage 2.28 отваря native picker и предава избрания path на Stage 2.27.

Третото действие започва disabled. Само exact positive Stage 2.21 outcome
може да го активира. Първите две положителни решения не отварят picker и няма
automatic transition.

## 2. Exact arming граница

`_RecoverySourceSelectionGUIEvent.arm_once()`:

- приема само exact `VaultRecoveryEntryTransitionOutcome`;
- извиква exact Stage 2.21 schema validator;
- изисква `PROCEED_TO_FUTURE_SOURCE_SELECTION` и
  `future_source_selection_requested=true`;
- отказва preserve, wrong type, forged schema/format/authority и replay;
- активира button само след успешна пълна revalidation;
- binding-ва exact `bg-BG`/`en-GB` locale от outcome, а не от по-късната
  global GUI language стойност.

Преди arming event-ът няма transition outcome или bound locale. При widget
configuration failure не задържа authority и преминава terminal `failed`.

## 3. Отделно трето user action

Само отделно натискане на третия button:

- atomically преминава `ready → selecting`;
- изчиства retained Stage 2.21 outcome от event-а;
- disable-ва button;
- зарежда условно pure Stage 2.27 contract;
- revalidate-ва Stage 2.21 outcome чрез
  `prepare_recovery_source_selection()`;
- едва тогава извиква `filedialog.askopenfilename()`.

Stage 2.27 не се import-ва при normal module import и не се подготвя при
първото или второто действие. Lock допуска точно един concurrent consumer.
Няма reset, retry или reuse след selection, cancel, failure или interruption.

## 4. Picker и path semantics

Picker-ът използва `.mokr` filter и secondary `All files` route. Filter-ът е
само native-UI hint и не доказва extension, format, existence, identity,
ownership, permissions, authenticity или usability.

- empty picker result означава exact Stage 2.27 `PRESERVE_AND_STOP`;
- non-empty result се предава непроменен на exact Stage 2.27
  `SELECT_LOCAL_RECOVERY_RECORD`;
- Stage 2.27 извършва единствено frozen lexical POSIX/UTF-8 validation;
- GUI event-ът не запазва outcome или selected path след връщането към caller;
- path не присъства в fixed GUI messages, exception text, visual report, log
  или persistence.

Python/Tk и OS могат временно да държат path string; това не е доказуема memory
zeroization. Native picker може да изброява directories и да чете filesystem
metadata.

## 5. Честна filesystem граница

Stage 2.28 не прави whole-process no-filesystem-access claim. Normal GUI
извършва existing runtime-directory preparation, а native picker може да
достъпва filesystem metadata.

Точните ограничени твърдения са:

- application recovery selection code не извиква `open`, `read`, `stat`,
  `lstat`, `resolve` или `realpath` върху selected source;
- source content не се чете;
- source identity/permissions не се валидират;
- source access/preparation не се разрешава;
- selected source не се променя;
- няма recovery operation.

Stage 2.5 `_read_recovery_path` остава единственият reviewed secure-read core и
не се извиква от Stage 2.28.

## 6. Error и interruption semantics

Stage 2.27 error, invalid picker result, loader/picker/widget exception и
неочакван ordinary exception:

- водят до terminal `failed`;
- не възстановяват transition outcome;
- не позволяват втори picker;
- показват само fixed localized generic error;
- не показват selected path или exception detail.

`BaseException` след consumption също маркира event-а `failed`, изчиства
retained authority и се propagate-ва. Това не предоставя retry/reset.

## 7. Import и capability граница

Normal import closure остава Stage 2.19 + Stage 2.21 + Stage 2.22 leaf. Pure
Stage 2.27 се зарежда чрез exact conditional helper само на третото действие.

Няма top-level или event capability към storage, reconciliation, workflow,
controller, bridge, review, candidate, publish, VaultStorage, crypto, process,
network, telemetry или logging.

## 8. Visual evidence

Bounded visual report покрива exact `bg-BG`/`en-GB` и `select`/`cancel` routes.
Той не съдържа path, filename, secret, callback, executor или free-text notes.

Report-ът задължително отчита:

- native picker invoked = true;
- picker filesystem metadata access possible = true;
- runtime-directory preparation = true;
- whole-process no-filesystem-access claimed = false;
- application source open/read = false;
- source identity/access/preparation, secret, operation, network и automatic
  transition = false;
- source selection/path metadata = true само за synthetic `select` route;
- preserve-and-stop = true само за `cancel` route.

Visual report е human observation, не system-call trace, usability/
accessibility audit, platform certification или доказателство за recovery.

## 9. Frozen project scope

Stage 2.28 променя точно 14 project paths:

- `mokosh_gui.py`;
- този contract;
- visual report core и launcher;
- един нов 36-test module;
- четири status/evidence документа;
- пет historical critical-GUI-hash test files.

Петте historical теста променят само expected `mokosh_gui.py` SHA-256. Техните
behavior/security assertions не се отслабват и не се skip-ват.

## 10. Задължителен бъдещ pre-freeze impact scan

Преди всеки следващ scope freeze се изпълнява transitive test-impact scan за:

- byte/hash guards;
- exact import closures;
- schema/version assertions;
- GUI geometry/text registries;
- visual/evidence semantics;
- installer allowlist и rollback assumptions.

Всички неизбежно засегнати test/docs paths се включват преди одобрението на
freeze. Ако зависимост се открие след freeze, кодът спира и се изисква minimal
re-freeze. Това предотвратява скрито отслабване на тестове и късно масово
пренаписване.

## 11. Строго забранено

Stage 2.28 не:

- отваря, чете, parse-ва или identity-валидира recovery source;
- извиква Stage 2.5 secure read или Stage 2.8 reconciliation;
- приема password, recovery secret/root/key, Vault session или keyring;
- създава review session, candidate, publish, unlock или operation authority;
- променя user/recovery files;
- използва network, cloud, telemetry, logging или persistence;
- активира encryption, cleanup, Contacts или Sandbox;
- предоставя algorithm/software fallback или automatic recovery;
- твърди legal conformity, certification, independent audit или recovery
  success.

`SAFETY_MODE=True` остава задължително.

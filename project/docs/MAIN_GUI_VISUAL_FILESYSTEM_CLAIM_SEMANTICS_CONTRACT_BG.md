# MOKOSH — договор за filesystem claim semantics във visual reports

Статус: Stage 2.26 — корекция на точността на bounded evidence за Stage 2.18,
Stage 2.20 и Stage 2.25 normal-main-GUI visual harnesses; няма GUI behavior,
recovery source, secret, filesystem authority или operation промяна.

## 1. Review finding

Трите report schema версии `1` съдържат общо поле
`filesystem_mutation_performed=false`, а Stage 2.25 съдържа и
`filesystem_access_performed=false`. Тези имена са прекалено широки.

Всеки успешен exact launcher извиква `mokosh_gui.main()`. След Stage 2.24
`main()` explicit извиква `ensure_private_data_dir()` преди `tk.Tk()`. То
изпълнява съществуващите `mkdir(..., exist_ok=True)` и `chmod(0700)` runtime
preparation действия. Следователно report-ът може честно да откаже recovery
source access/mutation, но не и да твърди обща липса на filesystem действие за
целия normal-startup process.

Това е evidence-semantics несъответствие. Не е доказателство за recovery-source
достъп, secret exposure, user-file mutation или криптографски дефект.

## 2. Frozen correction

Stage 2.26 променя само report/launcher/test/documentation границата:

- Stage 2.18, 2.20 и 2.25 report versions стават `2`;
- двусмислените `filesystem_access_performed` и
  `filesystem_mutation_performed` се премахват от тези report schemas;
- всеки успешен report изисква
  `runtime_directory_preparation_performed=true`;
- всеки report изисква
  `recovery_source_filesystem_access_performed=false`;
- всеки report изисква
  `recovery_source_filesystem_mutation_performed=false`;
- launcher-ите показват disclosure преди `mokosh_gui.main()`.

`runtime_directory_preparation_performed=true` означава само, че exact
existing Stage 2.24 preparation boundary е завършила. То не твърди, че
директорията непременно е била новосъздадена или че permission bits са се
променили спрямо предишното им състояние.

Recovery-source отрицателните полета се отнасят само до MOKOSH recovery source
selection/read/write. Те не твърдят, че Python, Tk, OS или други normal-startup
компоненти не са извършили никакъв filesystem metadata access.

## 3. Versioning и исторически evidence

Историческите version-1 JSON reports и annotated tags не се променят и не се
презаписват. Stage 2.26 документира, че техните generic filesystem имена са
неподходящи за whole-process claim. Новите reports използват version `2`.

Format identifiers остават същите, защото report семейството е същото;
`version` е задължителната schema discriminator. Няма backward parser или
automatic downgrade. Непозната/стара версия трябва да се интерпретира според
собствения ѝ договор, а не като version-2 claim.

## 4. Непроменени trust boundaries

Stage 2.26:

- не променя `mokosh_gui.py`, `mokosh_paths.py` или launcher-а на приложението;
- не избира, не задържа, не отваря и не валидира recovery source/path/file;
- не приема password, recovery root/record, keyring или Vault data;
- не извиква storage, reconciliation, workflow, controller, bridge, review,
  candidate или publish операции;
- не добавя filesystem, network, process, logging, callback, executor или
  dynamic-import capability към report core модулите;
- не променя `SAFETY_MODE=True`, legacy controls или MOK1 compatibility;
- не предоставя legal consent, operation authority или platform
  certification.

## 5. Задължителни тестове

- exact version `2` за трите засегнати report families;
- exact нови field names/defaults и липса на generic старите fields;
- validator отказ при forged `runtime_directory_preparation_performed=false`;
- validator отказ при forged recovery-source access/mutation `true`;
- canonical JSON съдържа само точните version-2 filesystem claims;
- disclosures са преди exact `mokosh_gui.main()` call;
- report core modules остават без direct filesystem/network/process/logging
  imports;
- `mokosh_gui.py`, `mokosh_paths.py`, runtime requirements, launcher и
  crypto/recovery core остават byte-exact;
- full regression без skipped mandatory security tests.

## 6. Честни ограничения

Stage 2.26 не наблюдава system calls и не доказва whole-process filesystem
absence. То поправя schema semantics чрез exact known application call graph и
static/runtime tests. Не е filesystem certification, independent audit,
platform certification или legal conclusion.

Source selection, path retention, recovery file read, secret intake, Stage 2.8
invocation, session preparation и operation authority остават бъдещи отделни
review scopes.

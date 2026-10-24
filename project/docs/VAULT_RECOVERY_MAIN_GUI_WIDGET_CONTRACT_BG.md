# MOKOSH — договор за условен main-GUI recovery review widget/event

Статус: Stage 2.18 — реализирано отделно, inspection-only видимо свързване към
exact Stage 2.17 binding; normal startup остава неактивен.

## 1. Цел

Stage 2.18 добавя най-малката видима Tkinter граница в главния MOKOSH GUI за
вече подготвен Stage 2.17 read-only binding. Целта е да се провери реалното
widget/event свързване, без да се добавя recovery source или операция.

Видимата граница съдържа:

- ясно inspection-only съобщение;
- един локализиран бутон за exact `bg-BG` или `en-GB`;
- one-shot event, който изключва бутона преди display;
- generic success/failure съобщение без exception или чувствителен текст.

## 2. Условно активиране

`mokosh_gui.main()` приема един optional параметър:

```python
main(prepared_recovery_review_binding=None)
```

Само exact fresh `PreparedMainGUIRecoveryReviewBinding` е допустим. `None`
означава normal startup и запазва стария прозорец без recovery widget.

`run_mokosh_gui.sh` и module entrypoint-ът продължават да извикват `main()` без
аргумент. Няма command-line option, environment switch, auto-discovery,
stored binding или automatic startup.

## 3. Inspection-only main-GUI session

Когато exact binding е подаден от отделен доверен in-memory caller:

- GUI езикът се избира exact по binding locale;
- показват се фиксиран banner и един бутон;
- language, Vault picker, password, nickname, login, encrypt, decrypt, cleanup,
  Contacts и Sandbox controls се изключват за тази условна session;
- няма достъп до потребителски файл, credential или runtime recovery source;
- след приключване приложението трябва да се стартира нормално отново за
  legacy decryption или друга разрешена функция.

Това условно изключване не променя normal startup и не блокира legacy
decryption в обичайното приложение.

## 4. Event lifecycle

Вътрешният GUI event има exact състояния:

- `ready`;
- `displaying`;
- `completed`;
- `failed`.

Преходът от `ready` се пази с process-local lock. Binding reference-ът се
премахва от event object-а и бутонът се изключва преди извикване на Stage 2.17
seam-а. Replay или concurrent event не може да извика bridge-а втори път.

Acknowledgement и cancellation са `completed`. Bridge error или друг regular
Python error е generic visible failure и `failed`. `KeyboardInterrupt` и друг
process-level exception се пропускат, но event-ът остава consumed. Няма retry.

## 5. Outcome и честно потребителско съобщение

Stage 2.17 връща само exact Stage 2.14 bounded outcome. След успешен terminal
review главният GUI казва изрично, че:

- не е разрешена recovery операция;
- не е извършена recovery операция.

Текстът не твърди recovery success, comprehension, signature, identity,
certification или последваща operation authority.

## 6. Забранени входове и действия

Main-GUI runtime кодът не импортира и не приема:

- password, recovery root, record, keyring, Vault/recovery path или filename;
- Stage 2.8 reconciliation source или Stage 2.9 workflow source;
- unlock, candidate, setup, publish, retry, repair, cleanup или key deletion;
- callback, executor, plugin, dynamic import, `eval` или `exec`;
- network, telemetry, Guardian, update, licensing или payment capability.

Stage 2.18 recovery-review action не чете и не променя recovery source или
user file. Normal `mokosh_gui.main(binding)` все пак изпълнява съществуващата
runtime-directory preparation граница. Stage 2.26 version-2 report schema
описва това отделно и не прави общ whole-process no-filesystem claim.
Съществуващите legacy GUI функции остават в кода, но са недостъпни в условната
inspection-only session.

## 7. Synthetic visual harness

`mokosh_vault_recovery_main_gui_visual_harness.py` създава само четири fixed,
non-secret, in-memory Stage 2.9 states и ги прекарва през exact Stage 2.16 и
Stage 2.17 preparation. Той няма GUI, filesystem, network, process или logging
API.

`run_main_gui_recovery_review_visual_harness.py` е отделният development
launcher. Той:

- приема само allowlisted route и locale;
- подава exact synthetic binding към условния `mokosh_gui.main(binding)`;
- изисква потребителят да натисне бутона точно веднъж;
- записва само bounded `pass`/`fail`/`not_checked` наблюдения;
- изкарва canonical JSON без paths, names, secrets или arbitrary notes.

Linux visual pass е локално human observation за тестваната конфигурация. Не е
usability/accessibility audit, platform certification или доказателство за
Windows/macOS.

## 8. Bounded evidence flags

Report-ът фиксира като `true` само:

- synthetic non-secret fixture;
- exact Stage 2.17 binding;
- conditional main-GUI activation.
- existing runtime-directory preparation, след Stage 2.26 schema version 2.

Той изисква `false` за:

- normal-startup activation;
- true Vault input;
- operation performed/authorized;
- recovery-source filesystem access/mutation;
- network use;
- platform certification claim.

Forged true стойност се отказва при dataclass validation и JSON encoding.
Историческото generic version-1 filesystem поле е заменено, а не
reinterpretирано като whole-process доказателство.

## 9. Задължителни автоматизирани тестове

- exact banner/button за `bg-BG` и `en-GB`;
- exact fresh binding и nonfresh/invalid отказ преди widget;
- disable-before-display и binding-reference clearing;
- acknowledged/cancelled bounded outcome;
- replay и concurrent точно един bridge call;
- bridge/unknown error generic failure без exception text;
- interrupt propagation след consumption;
- exact synthetic четири route-а и два locale-а;
- invalid route/locale отказ;
- canonical bounded report и mismatch отказ;
- false authority/certification claim отказ;
- schema без secrets, paths, callbacks или capabilities;
- normal entrypoint `main()` без аргумент;
- static main-GUI import boundary и `SAFETY_MODE=True`;
- byte-exact launcher, `crypto_core.py` и runtime requirements;
- full regression: 1228 tests, expected failures=3 само за legacy MOK1,
  skipped=0.

## 10. Mandatory visible gate

Преди commit/tag installer-ът трябва да изпълни реалния synthetic launcher на
Linux и да получи само `pass` за:

- banner и button visibility;
- unrelated controls disabled;
- review window opened in front;
- button remained disabled след terminal review.

`fail`, `not_checked`, cancellation на harness-а или липса на completed exact
outcome блокира stage-а и задейства rollback.

## 11. Непроменени ограничения

`SAFETY_MODE=True` остава. Няма true recovery source, normal-startup recovery
button, recovery success, operation authority или автоматична следваща стъпка.
Windows/macOS observation, accessibility/usability review, independent audit,
legal review и production activation остават отделни бъдещи gates.

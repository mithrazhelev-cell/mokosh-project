# MOKOSH — Synthetic Recovery Review Visual/Platform Harness v1

Статус: Stage 2.15 — отделен development/test harness върху реалния Stage 2.14
Tkinter `Toplevel`, само с фиксирани synthetic non-secret fixtures.

## 1. Цел и граница

Harness-ът позволява видим локален преглед на четирите route-а `absent`,
`exact`, `conflict` и `preserve` в точните locale-и `bg-BG` и `en-GB`.
Той не се извиква от `mokosh_gui.py` и не е production recovery интерфейс.

Няма вход за Vault, password, recovery root/record, keyring, candidate,
filesystem path, callback, executor или operation capability. Fixture-ите са
детерминистични, фиксирани и не четат environment, home директория или runtime
данни.

## 2. Стартиране

Единичен видим Linux преглед:

```bash
python3 run_recovery_review_visual_harness.py \
  --route absent --locale bg-BG --scale 100 --window-profile small
```

Пълната route/locale матрица се отваря последователно с `--matrix`. Допустимите
scale стойности са само `100`, `125`, `150` и `200`, а размерите са:

- `small` — точният минимален допустим размер `520x420`;
- `standard` — `800x640`.

Фиксираната Linux validation матрица се стартира с:

```bash
python3 run_recovery_review_visual_harness.py --validation-matrix
```

Тя покрива осемте route/locale комбинации, четирите scale стойности, двата
размера и предписани Escape, Cancel, window-manager close и acknowledgement
маршрути. Всеки предписан terminal action трябва да съвпадне и четирите
наблюдения за всеки случай трябва да са `pass`; иначе командата завършва с
failure и не може да служи като Linux visual gate.

Launcher-ът създава малък видим synthetic test owner, map-ва го преди child
window, задава избрания Tk scale и отваря реалния Stage 2.14
`show_recovery_review_window`. Видимият owner е задължителен, защото при някои
Linux window manager-и `Toplevel`, transient към withdrawn parent, остава
невидим и блокира във `wait_visibility`. Launcher-ът не импортира и не стартира
основния MOKOSH GUI.

## 3. Задължителен видим преглед

За всеки избран случай човекът проверява:

1. достигане на всеки message и confirmation чрез scroll;
2. wrap без видимо отрязване или застъпване;
3. логичен и видим focus order;
4. keyboard-only работа.

Terminal prompt приема само `y`, `n` или `s` и преобразува отговора във fixed
enum `pass`, `fail` или `not_checked`. Няма поле за свободен текст.

Escape, Cancel, window-manager close и успешно acknowledgement се записват
само чрез exact Stage 2.14 outcome. Един run не доказва останалите close
маршрути; те се изпитват в отделни runs.

## 4. Bounded report

Всеки приключил run отпечатва един canonical JSON report с:

- route, locale, scale и fixed window profile;
- Stage 2.14 decision и exact cancel reason, ако има;
- четирите fixed observations;
- non-secret presentation digest;
- изрични false flags за main GUI, true Vault input, operation, authority,
  filesystem mutation, network, secrets и platform certification.

Report-ът няма notes, user text, password, keyring, Vault/recovery path,
filename, callback, executor или capability. Той не се записва автоматично.

## 5. Fail-closed правила

- Route, locale, scale и profile извън allowlist се отказват.
- Stage 2.14 outcome с друг locale или digest се отказва.
- Forge-нат authority, mutation, network, secret или certification flag се
  отказва.
- `not_checked` никога не се преобразува в `pass`.
- Display/Tk грешка връща само фиксиран safe failure и не създава report.
- Harness-ът не може да unlock-ва, setup-ва, publish-ва, retry-ва, repair-ва,
  cleanup-ва или да стартира automatic recovery.

## 6. Какво доказва и какво не доказва

Unit/static тестовете доказват bounded fixture/report contract-а, exact
route/locale matrix, no-authority flags и отделянето от main GUI.

Видимият Linux run е човешко наблюдение за конкретната среда. Той не е
accessibility certification, независим одит, доказателство за разбиране или
Windows/macOS резултат. Преди public GUI claim остава задължителен отделният
platform checklist.

# MOKOSH — Recovery Review Platform Observation Checklist

Статус: Stage 2.15 — checklist за бъдещи реални наблюдения. Непопълнен checklist
не е pass и не разрешава public GUI claim.

## Матрица

За всяка поддържана версия на Linux, Windows и macOS се проверяват четирите
route-а `absent`, `exact`, `conflict`, `preserve` в `bg-BG` и `en-GB`.

Минимални профили за всеки route/locale:

- scale `100`, размер `520x420`;
- scale `125`, размер `520x420`;
- scale `150`, размер `800x640`;
- scale `200`, размер `800x640`.

## Видими проверки

- [ ] Всички messages се виждат в точния ред преди confirmations.
- [ ] Gate предупрежденията се различават видимо, без да изглеждат като
  разрешена операция.
- [ ] Всеки текст се wrap-ва без clipping, overlap или хоризонтално скриване.
- [ ] Последният message и последният confirmation са достижими със scroll.
- [ ] Всеки checkbox започва false; няма select-all или remembered state.
- [ ] Final action е disabled до всички отделни selections и пак се disabled-ва
  след uncheck.
- [ ] Focus indicator е видим; Tab/Shift+Tab редът е логичен.
- [ ] Space превключва само focused checkbox.
- [ ] Return не потвърждава преди всички selections.
- [ ] Escape приключва с exact `escape_key` cancel reason.
- [ ] Cancel button приключва с exact `cancel_button` reason.
- [ ] Window-manager close приключва с exact `window_close` reason.
- [ ] Keyboard-only acknowledgement работи без mouse.
- [ ] Mouse wheel и platform scroll gesture работят очаквано.
- [ ] Theme и contrast не скриват normal/gate/disabled/focus states.
- [ ] Няма off-screen или недостижим dialog при multi-monitor конфигурация.
- [ ] Screen reader обявява заглавие, messages, отделни confirmation labels,
  state и buttons в смислен ред.

## Данни за наблюдението

Записват се извън приложението само:

- OS и точна версия;
- desktop environment/window manager или Windows/macOS build;
- Python, Tcl/Tk версия, theme, monitor resolution и scale;
- MOKOSH commit/tag;
- exact harness route/locale/scale/profile;
- pass/fail/not-checked за всяка проверка;
- отделен минимален bug report при fail, без истински Vault данни.

Не се записват password, recovery key/root/record, keyring, Vault path,
filename, контакт или потребителски документ.

## Общ GUI строителен инвариант от Stage 2.38 нататък

Historical Stage 2.15 матрицата по-горе остава evidence за тогавашния
520×420 harness и не се пренаписва. За всеки нов или изменен прозорец/
подпрозорец от Stage 2.38 нататък преди commit са задължителни:

- изрично договорени initial и minimum usable размери;
- изрично resize поведение по двете оси; maximize не се предполага, защото е
  window-manager dependent;
- пълна използваемост при minimum size без потребителят да е длъжен да
  увеличава прозореца;
- dynamic wrap/reflow от текущата видима ширина, без fixed ширина по-голяма
  от viewport-а;
- достатъчно четливи букви, spacing и contrast, без clipping, truncation,
  overlap или хоризонтално скрит основен текст;
- вертикално scroll reachability на всички messages, controls и actions;
- FocusIn автоматично показва целия focused control; Tab/Shift+Tab/Space/
  Escape и приложимите PageUp/PageDown/Home/End остават предвидими;
- long-label/locale-expansion gate за всеки поддържан език; преводът не може
  да бъде съкратен само за да се побере;
- инструкции, error dialogs, confirmation dialogs и harness-only помощни
  прозорци следват същите resize/wrap/scroll/focus правила;
- 100/125/150/200% scale и най-малко small/standard профили в synthetic
  visual gate, преди platform claim;
- unit/static tests не заменят човешкото visible наблюдение.

От R5 общият инвариант има измерим runtime минимум:

- fixed header, middle viewport и fixed footer са три неприпокриващи се
  mapped области вътре в client area;
- всички required footer controls са изцяло видими при initial geometry,
  без resize/maximize и без scroll;
- само middle viewport се scroll-ва и има минимум 80 pixels usable height;
- live geometry failure спира преди visible/control/report claim;
- actual screen size, coordinates и widget dimensions не се записват;
- titlebar maximize остава window-manager dependent; usable minimum profile
  никога не зависи от неговата наличност.

Поправка, открита по време на строежа, е нормална част от engineering
процеса, но се документира и минава impact review/freeze acceptance; не се
прилага тихо. Нов език или превод изисква собствено visible locale-expansion
покритие, а не предположение от BG/EN резултата.

## Последователни harness cases и разбираемост

- Case number означава поредна задължителна тестова стъпка, освен ако
  contract-ът изрично не дефинира branch.
- Предварително зададеното terminal action е test input, не потребителска
  оценка PASS/FAIL.
- PASS/FAIL се събира само в ясно отделена observation phase след action.
- Преди изпълнение operator потвърждава exact action с unchecked-by-default
  acknowledgement; Start остава disabled дотогава.
- Error evidence посочва case, expected и observed action без path, secret,
  user identity или environment dump.
- Повторяемо неправилно разбиране от целевия operator е instruction-design
  finding и не се отхвърля автоматично като „потребителска грешка“.

## Условие за platform claim

Platform claim е забранен, докато няма реален pass на цялата договорена
матрица за съответната поддържана OS версия и няма прегледани unresolved
failures. Linux резултат не се пренася към Windows/macOS и headless/unit тест
не замества видимото и screen-reader наблюдение.

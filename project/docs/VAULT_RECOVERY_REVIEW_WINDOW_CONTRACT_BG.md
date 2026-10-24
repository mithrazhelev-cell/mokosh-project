# MOKOSH — договор за изолиран локален Vault recovery review window

Статус: Stage 2.14 — реализиран real Tkinter `Toplevel` и process-local
controller върху замразените Stage 2.10–2.13 договори.

Това е прозорец само за четене и изрично потвърждаване на видяното. Той не е
recovery operation, не отключва Vault, не създава candidate и не публикува
поколение.

## 1. Цел

Stage 2.14 добавя най-малкия реален widget слой, който:

- приема exact `VaultRecoveryWorkflowPresentation`;
- приема exact fresh `PreparedVaultRecoveryUIAdapter`;
- изисква exact locale ID `bg-BG` или `en-GB`;
- създава exact Stage 2.13 localized view;
- показва ordered messages и отделно отличени gate warnings;
- показва required confirmation checkboxes, всички false по подразбиране;
- разрешава final acknowledgement само след всяка отделна отметка;
- при success предава само exact Stage 2.12 event tuple;
- при cancel, Escape или window close не acknowledgement-ва adapter-а.

## 2. Модул и public API

Реализацията е в `mokosh_vault_recovery_review_window.py`.

Public входовете са:

- `prepare_recovery_review_window(presentation, adapter, locale_id)`;
- `show_recovery_review_window(parent, presentation, adapter, locale_id)`.

Public API няма password, recovery root, keyring, path, filename, callback,
executor или operation argument.

`show_recovery_review_window` изисква съществуващ Tk parent. Той създава само
един child `tk.Toplevel`, не създава втори `tk.Tk` и не стартира втори
`mainloop`.

## 3. Exact source mediation

Преди widget construction controller-ът проверява отново:

1. exact Stage 2.10 presentation type, schema, route и safety flags;
2. exact Stage 2.12 prepared adapter type и awaiting state;
3. Stage 2.12 view schema и exact presentation binding;
4. exact supported locale без normalization или fallback;
5. exact Stage 2.13 localized view schema, catalog digest и ordered route;
6. one-to-one equality между adapter и localized ordinals, keys, gate markers,
   visibility, required/individual/default-false policy;
7. exact locale equality между fixed window chrome и localized view.

Already-acknowledged adapter, чужда presentation, tampered view, unsupported
locale, reordered item или authoritative flag се отказват преди прозорец.

## 4. Locale граница

Version 1 поддържа само exact plain strings:

- `bg-BG`;
- `en-GB`.

Изборът е explicit аргумент от calling UI. Не се чете OS locale, environment,
timezone, hostname или platform preference. Няма `bg`, `en`, region
substitution, case normalization или silent fallback.

Stage 2.14 има малък immutable registry само за fixed window chrome: title,
introduction, confirmation heading, confirm button и cancel button. Recovery
meaning остава единствено в Stage 2.13 catalogs.

## 5. Process-local controller

`PreparedVaultRecoveryReviewWindow` има точно три състояния:

- `awaiting_visible_review`;
- `acknowledged`;
- `cancelled`.

Началното състояние има:

- `messages_visible = false`;
- confirmation selection tuple само от `false`;
- `confirm_enabled = false`;
- няма outcome и няма Stage 2.12 receipt.

Controller-ът отказва copy, deep-copy и pickle. Process-local lock допуска само
един terminal result при concurrent acknowledge/cancel attempts.

Това не е cross-process token, digital signature или persistent consent.

## 6. Ordered visible messages

Widget-ът създава всички message labels в exact Stage 2.13 order преди да
създаде confirmation controls.

След като `Toplevel` е visible, controller-ът приема точно веднъж complete
ordered tuple от message ordinals. Едва след това checkboxes преминават от
disabled към normal state.

Empty, list, partial, reordered, duplicate или repeated visibility report се
отказва.

Gate messages използват отделен namespaced bold Tk style. Стилът не променя
или допълва exact localized meaning.

## 7. Confirmation политика

Всеки Stage 2.13 confirmation става отделен `ttk.Checkbutton` със:

- exact localized text;
- exact ordinal и confirmation key;
- `BooleanVar(value=False)`;
- `takefocus=True`;
- disabled state до visible message report;
- individual toggle command.

Няма select-all, group accept, pre-check, remembered selection, hidden
confirmation или automatic accept.

Final button започва disabled. Той става normal само когато всички exact
individual selections са `true`. Uncheck го връща незабавно в disabled state.

## 8. Successful acknowledgement

При final action controller-ът отново валидира complete upstream binding и
създава един exact ordered tuple от `RecoveryUIConfirmationEvent`:

- exact ordinal;
- exact confirmation key;
- `visible = true`;
- `user_selected = true`;
- `user_initiated = true`.

Tuple-ът се предава само на private prepared Stage 2.12 adapter. Полученият
`VaultRecoveryUIAdapterReceipt` отново се валидира.

Stage 2.14 outcome пази само locale, presentation digest, bounded decision и
Stage 2.12 receipt. Не пази presentation, localized view, raw events, password,
root, keyring, path или operation object.

Receipt и outcome имат fixed false за operation, authorization, gate,
auto-accept, group-select и secrets.

## 9. Cancel, Escape и close

Трите cancel routes са отделни exact enums:

- cancel button;
- Escape key;
- window-manager close.

Всеки route приключва с `cancelled` outcome без Stage 2.12 acknowledgement.
Partial checkbox state не се превръща в receipt. Prepared Stage 2.12 adapter
остава unacknowledged и не е consumed.

След cancel или success controller-ът отказва всяко следващо interaction.
Повторно отваряне изисква fresh presentation, fresh Stage 2.12 adapter и fresh
Stage 2.13 localization.

## 10. Tk ownership и modal поведение

Window-ът:

- е `Toplevel` на caller-provided existing parent;
- е transient към parent;
- използва local `grab_set` само докато е отворен;
- освобождава grab преди destroy;
- използва caller event loop чрез `wait_window`;
- не използва `bind_all`;
- не стартира background thread или worker.

Display/Tcl failure приключва fail-closed и не създава acknowledgement.

## 11. Scroll, wrap, focus и keyboard

Реалният layout използва:

- scrollable `Canvas` и vertical `ttk.Scrollbar`;
- inner frame и recalculated scroll region;
- bounded wrap lengths за introduction и messages;
- stable message-before-confirmation order;
- initial focus върху първия confirmation след visibility;
- focusable checkboxes и scroll canvas;
- Escape за cancel;
- Return за final action само когато controller-ът вече го допуска.

Mouse-wheel binding е само върху локалния Canvas. Няма global binding.

Тези свойства са code/test evidence, не independent accessibility
certification. Реални screen-reader, contrast, DPI и platform observations
остават задължителни.

## 12. No-operation граница

Stage 2.14 не импортира и не приема capability за:

- Vault storage, parse, unlock, KDF или keyring access;
- recovery root, record read, rehearsal или candidate creation;
- recovery setup, publish, retry, repair или cleanup;
- unlink, overwrite, rename, replace или user-file mutation;
- callback, executor, gate invocation или automatic transition;
- network, telemetry, logging, clock, randomness или update discovery.

Window-ът не може да изпълни действие зад confirmation button-а. Той може само
да създаде no-authority acknowledgement receipt.

## 13. Freshness

Stage 2.14 не чете filesystem и не доказва, че Stage 2.8 observation е още
current. Nonterminal route запазва
`downstream_reverification_required = true`.

Acknowledgement не е candidate/unlock/setup/publish authorization. Всеки
бъдещ operational stage трябва да направи fresh source revalidation и отделно
explicit решение.

След restart няма persisted review, checkbox state, receipt resume или
cross-process authority.

## 14. Direct-call limitation

Controller method може да бъде извикан от същия Python process. Затова
`user_initiated` остава bounded widget assertion, а не доказателство за:

- идентичност на човека;
- прочитане или разбиране;
- свободно правно съгласие;
- физическо присъствие;
- uncompromised desktop, interpreter или OS.

Screenshot blocking не е security boundary и не е част от Stage 2.14.

## 15. Забранени действия

Stage 2.14 няма:

- main-GUI activation или промяна на `mokosh_gui.py`;
- Vault unlock, recovery rehearsal, candidate, setup или publish;
- filesystem read/write/scan или user-file mutation;
- Contacts, Sandbox operation, Guardian, shards или entitlement integration;
- network, server, telemetry, logging, update discovery/download/install;
- locale auto-detection, external translation file или plugin;
- select-all, auto-accept, remembered checkbox state или hidden confirmation;
- screenshot-prevention claim или accessibility certification;
- automatic recovery, retry, rollback, repair, cleanup или key deletion.

## 16. Задължителни тестове

- exact preparation за absent/exact/conflict/preserve във всеки locale;
- exact locale allowlist и no-fallback отказ;
- wrong presentation/adapter, cross-route, consumed и tampered source отказ;
- all confirmation values false и final disabled по подразбиране;
- message visibility exact-once и in-order преди checkbox interaction;
- individual selection, wrong ordinal/key/type и pre-visibility отказ;
- final enable само при all true и disable след uncheck;
- partial acknowledge без adapter consumption;
- successful exact Stage 2.12 receipt за всички routes/locales;
- cancel button, Escape и close без acknowledgement;
- cancel след partial selection без receipt;
- one-shot/replay/copy/deep-copy/pickle отказ;
- concurrent terminal attempts с точно един result;
- outcome без view, events, secrets, path или operation object;
- forged authority/auto/group/gate flags отказ;
- static real `Toplevel`, Canvas, Scrollbar, labels, checkboxes и buttons;
- static no `Tk`, no second `mainloop`, no filesystem/network/logging/dynamic
  execution;
- explicit close/Escape/Return, focus, wrap, scroll и local-grab wiring;
- public API без password/root/path/callback/executor/operation arguments.

## 17. Platform validation, която още остава

Преди main-GUI integration и public claim трябва да има реални platform tests
върху поддържаните версии на:

- Linux desktop environments;
- Windows;
- macOS.

Те трябва да проверят screen reader, high DPI, font scaling, keyboard-only
navigation, long-text clipping, theme/contrast, window-manager close,
multi-monitor behavior и actual visible scroll reachability.

Headless unit/static tests не заменят тези наблюдения.

## 18. Честно заключение

Stage 2.14 доказва ограничен реален Tkinter review seam и fail-closed
interaction state върху exact Stage 2.10–2.13 data.

Той не доказва, че човек е разбрал текста, не е production GUI integration,
не е independent audit и не разрешава или извършва recovery операция.

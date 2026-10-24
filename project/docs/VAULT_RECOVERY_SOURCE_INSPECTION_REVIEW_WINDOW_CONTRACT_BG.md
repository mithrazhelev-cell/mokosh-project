# Stage 2.37 — договор за локален преглед на проверката на източника

Дата на freeze: 2026-08-29  
Ниво: High  
Статус: installer-gated; няма main-GUI activation или conformity claim

## 1. Цел и вход

Stage 2.37 създава един изолиран process-local Tkinter child window за exact
Stage 2.33 presentation, fresh exact Stage 2.35 prepared adapter и exact Stage
2.36 localized view. Locale се извлича единствено от напълно валидирания
adapter view; API няма locale argument, fallback, OS-locale избор, външен
catalog или динамична интерполация.

Това е review boundary. То не е source reader, recovery session, consent
proof, accessibility certificate, legal assessment или operation dispatcher.

## 2. Exact видим и интерактивен договор

- използва се съществуващ Tk parent и точно един `tk.Toplevel`;
- не се създава втори `Tk`, не се стартира втори `mainloop` и не се активира
  `mokosh_gui.py`;
- седемте localized messages се създават в exact Stage 2.36 order;
- трите confirmations са отделни checkboxes, disabled и false при създаване;
- controls стават interactive едва след логическото visible-order събитие;
- няма select-all, precheck, remembered selection или auto-accept;
- final button е disabled, докато и трите controls не са true, и отново се
  disabled-ва при uncheck;
- няма window-wide Return binding; acknowledgement е само чрез explicit final
  button action;
- Cancel button, Escape и window-manager close завършват без acknowledgement.

Tk/process-local assertion за visibility или selection не доказва физическо
изобразяване, screen-reader поведение, accessibility conformance, човешко
разбиране, самоличност, информирано съгласие или правна валидност.

## 3. Atomic lifecycle и fail-closed граница

Prepared controller използва точно един `_terminal` marker под lock. Преди
делегиране към Stage 2.35 се записва private fail-closed sentinel. След тази
граница всяко ordinary exception, unexpected exception, `BaseException` или
interrupt оставя outer controller terminal `FAILED_CLOSED`, освен ако exact
success не замени sentinel-а с един immutable outcome.

Това предотвратява consumed inner adapter да съществува заедно с outer
controller, който изглежда fresh. Concurrency допуска точно един terminal
резултат. Replay, duplicate visibility, post-terminal selection и duplicate
cancel/acknowledgement се отказват.

Invalid interaction преди границата е retryable и не consume-ва adapter-а.
Cancel не consume-ва private Stage 2.35 adapter. Следователно direct caller,
който още държи adapter reference, може изрично да подготви нов window; Stage
2.37 не твърди global consumption или application-session ownership.

## 4. Bounded outcome и забранени capabilities

Outcome съдържа само bound locale, repr-hidden 32-byte correlation digest,
decision/cancel reason, exact Stage 2.35 receipt при acknowledgement, bounded
counts и честни no-authority flags. Той е frozen, slots-based, non-copyable и
non-serializable.

Не се задържат path, source bytes/material, source identifiers, secret,
password, callback, executor, reader, operation capability или main-GUI
reference. Няма filesystem access/mutation, crypto, storage, network,
telemetry, logging, recovery, Stage 2.8 invocation или operation authorization.

## 5. Freeze и evidence gate

Променят се точно седем paths:

1. `mokosh_vault_recovery_source_inspection_review_window.py`
2. `tests/test_mokosh_vault_recovery_source_inspection_review_window.py`
3. `docs/VAULT_RECOVERY_SOURCE_INSPECTION_REVIEW_WINDOW_CONTRACT_BG.md`
4. `PROJECT_STATUS_BG.md`
5. `docs/SECURITY_EVIDENCE_AND_TESTING_BG.md`
6. `docs/SECURITY_STANDARDS_CROSSWALK_BG.md`
7. `docs/SESSION_LOG_BG.md`

Targeted gate е точно 56 tests. Authoritative laptop full gate е точно 1837
tests, `OK (expected failures=3)`, skipped=0; 189 tracked files и 133 tracked
Python sources. Изискват се exact Stage 2.36 identity, critical predecessor
hashes, exact allowlist/hash/mode, compile, source hygiene, full regression,
isolated dry-run/rollback, clean worktree и final checkpoint преди commit/tag.

Proposed annotated tag:
`stage2.37-vault-recovery-source-inspection-review-window`.

Stage 2.38 е отделен synthetic Linux visual/platform harness и не се включва
тук. Няма човешки visual, Windows/macOS или accessibility conformity claim.

## 6. Изрични non-goals и известен отделен риск

Не се променят Stage 2.32–2.36 modules, launchers, main GUI, crypto, Vault,
storage, Contacts, licensing, Guardian, update или network code. Historical
Stage 2.12/2.14 lifecycle patterns не се patch-ват в този freeze.

Потвърденият legacy defect в `contacts_core.py`, където current ML-KEM
`encapsulate()` резултатите са разменени, остава отделен pre-activation
hardening риск. Contacts са safety-disabled; Stage 2.37 не го прикрива и не го
поправя извън приетия scope.

## 7. Официални стандарти и бъдещи обновявания

Към 2026-08-30 engineering baseline/watch ledger е:

- WCAG 2.2 остава W3C Recommendation и reference, не desktop conformity proof;
- WCAG2ICT 2.2 е W3C Group Note от 2025-12-11 и дава informative,
  non-normative guidance за Level A/AA към non-web software;
- WCAG-EM 2.0 е W3C Group Note от 2026-07-23 и се използва като informative
  evaluation-method reference, не като certification;
- ETSI work item показва adopted-for-publication на 2026-08-24 и latest
  version 4.1.0 за ревизията на EN 301 549 V3.2.1; ETSI TC HF flyer посочва
  4.1.1. Номерът/status inconsistency се следи и не се решава чрез автоматична
  смяна на baseline преди authoritative publication/OJ harmonisation review;
- final NIST SSDF v1.1 остава baseline; SP 800-218 Rev.1/SSDF 1.2 е Initial
  Public Draft, не final автоматично приет standard;
- NIST SP 800-38D Rev.1 second preliminary draft work и FIPS 203 future-update
  planning note са watch items;
- Directive (EU) 2019/882/EAA се оценява само при реално приложим product/
  service scope; CRA reporting readiness за 2026-09-11 е project-level item.

Нито текущият код, нито тестовете дават legal/accessibility certification.
Бъдещо официално/научно изменение минава: primary-source review → impact
analysis → изрично уведомяване → нов minimal freeze → изрично приемане → едва
тогава промяна. Неизвестни бъдещи изисквания не се обещават предварително и
нищо не се прилага автоматично.

## 8. Stage 2.38 responsive-UI amendment

Stage 2.38 visual gate установи реален usability defect на текущата
Linux/Wayland среда: при малък прозорец част от съдържанието не беше ясно
достижимо, преоразмеряването не беше очевидно/надеждно и първоначалният фокус
можеше да отиде към confirmation извън видимата област. Успешният rollback
остави Stage 2.37 checkpoint-а непроменен. След отделен fresh review
потребителят прие изричен amended freeze; historical Stage 2.37 commit/tag не
се пренаписват.

Stage 2.38 checkpoint изменя този UI слой със следните задължителни
инварианти:

- `560×440` остава minimum usable profile, а не изискване потребителят да
  увеличи прозореца;
- resize по двете оси е изрично разрешен, но usable content не зависи от
  maximize или от window-manager-specific controls;
- message, introduction и confirmation текстовете пренасят динамично спрямо
  текущата видима ширина, с bounded 240–960 wrap length;
- дългите BG/EN и бъдещи локализирани текстове са вертикално достижими без
  horizontal scrolling, clipping или overlap;
- mouse wheel се прихваща само в child window boundary; няма `bind_all`;
- reading canvas поддържа PageUp/PageDown/Home/End;
- initial focus е върху canvas-а при scroll position 0, а FocusIn върху
  confirmation довежда целия контрол във viewport-а;
- transient ownership, modal grab, explicit acknowledgement, default-false,
  re-disable, Escape/Cancel/WM-close и fail-closed lifecycle се запазват.

След R3 footer-grid amendment targeted module gate се увеличава от historical
56, през R2 68, до точно 76 tests.
Промяната не добавя path/source/secret/capability, filesystem, network,
operation authority или cryptographic behavior.

R3 заменя pack-order competition между expanding review canvas и долния
action footer с three-row grid. Последващият R4 human gate доказа, че това е
само structural improvement: без live mapped-geometry verification grid
наличието не доказва видим footer при fixed geometry и 125–200% scaling.

## 9. Stage 2.38 R5 live-layout amendment

R4 manual run стигна до Cases 1–3, но operator впоследствие коригира
self-reported PASS: долни контроли са били скрити и недостижими чрез scroll.
Case 4/200% instruction не показа acknowledgement/Start дори при resize.
Matrix завърши status 130, rollback PASS, а отделен read-only gate потвърди
exact clean Stage 2.37 без Stage 2.38 tag/files. Трите R4 JSON PASS отчета са
withdrawn като визуално доказателство.

R5 използва short localized title в fixed row 0, единствен scrollable review
row 1 и fixed Cancel/Confirm row 2. Дългият introduction е преместен в
scroll content. След mapping се изчаква bounded geometry settle; exact
header/canvas/footer/Cancel/Confirm bounds и minimum 80-pixel middle viewport
се проверяват преди `mark_messages_visible_once` и преди controls enable.
Hidden, unmapped, zero-size, out-of-client или overlapping region затваря
fail-closed без visible claim.

Exact R5 targeted gate е 84 tests. Geometry measurements са process-local и
не се логват, сериализират или добавят към outcome/report. Няма промяна в
presentation, adapter, acknowledgement, crypto, data, authority или lifecycle
contract.

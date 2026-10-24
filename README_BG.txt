MOKOSH — НЕЗАВЪРШЕНО ПРИЛОЖЕНИЕ, ПРЕДВАРИТЕЛЕН АНАЛИЗ
Това е точно копие за сверяване и съвети. Няма release, сертификация или независим продуктов security audit.
Stage2.47 е приет вътрешно; Stage2.48 NOT_ACCEPTED; D005 OPEN.

project/:263 точни файла, непроменени тестове и пет фиксирани зависимости.
Шестте R3 файла са отделни входове за статичен анализ, без overlay или изпълнение.
Нормалният LocalV2Service в наличния код изрично допуска само Linux. Windows/macOS продуктовото приемане изисква отделно задание и native/физически проверки.

Първи действителен GitHub run40087175055/attempt1, commit838bd591...: общ FAILURE.
Linux2509 уникални PASS/0FAIL/ERROR/SKIP; macOSARM64 само ограничен compile/runtime probe.
Windows е спрял преди компилация/runtime при началната проверка на временното копие; точният файл/stat поле не е записан.
Security: завършени320baseline+7R3 pattern сигнала, не327 доказани дефекта. Cloud dependency audit е COMPLETE: един distinct advisory за cryptography49, NOT_FIXED. Старият локален DNS/INCOMPLETE запис остава исторически.

CI кандидатът добавя отделна РЪЧНА задача MOKOSH Windows stat diagnosis only.
Основният workflow/матрица са непроменени. Read-only contents, pinned actions/locks, частни временни копия и artifact allowlist остават.
Новата задача наблюдава метаданни и спира преди product compile/probe/worker. Няма автоматични поправки, update, merge, release или push/PR trigger.
Публикуването/пускането на кандидата се обсъждат отделно. Реален нов Windows run още няма.

Диагностичният журнал е ограничен до16/32/16 записа, общо64×4096 bytes. Няма файлово съдържание или environment dump. ctime и другите guards не са отслабени; отказаните artifact байтове остават блокирани.
Пълнота се установява от финалния receipt И точния изходен код за същите run/job/attempt/commit. Exit2 или липсващи данни = INCOMPLETE. Audit exit1 = първоначален FAIL или NON_REPRODUCED, не compatibility PASS. PENDING_FINAL_RECEIPT не е крайна пълнота.

Локално:33 съществуващи CI guards,20 целеви и17 независими проверки PASS;3 смислени fault/positive двойки доказани. Нормалният контролер премина2509 в квалифицирана Linux/Python3.12.14 среда с точните пет pin-а.
Първият опит без наличната Tk loader настройка е FAIL и е запазен. Няма exactDell/nativeWindows/macOS/физическо приемане от тези резултати.
ANALYSIS_STATUS.json е текущото разграничение; LOCAL_VALIDATION.json/history/draft_workflows пазят старите подготовителни състояния.
Git пази executable bit, не пълните POSIX права/owner/ACL. Windows POSIXbits NOT_VERIFIED.

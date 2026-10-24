MOKOSH — НЕЗАВЪРШЕНО ПРИЛОЖЕНИЕ, ПРЕДВАРИТЕЛЕН АНАЛИЗ
Няма release, сертификация, продуктов security audit или приемане за готовност.
Stage2.47 е приет вътрешно; Stage2.48 NOT_ACCEPTED; D005 OPEN.
263 product файла,6 отделни R3 inputs и петте dependency pins остават непроменени.
Нормалният LocalV2Service изрично допуска Linux. Windows/macOS продуктовата
поддръжка изисква отделен файлов договор и native/физически приемания.

ИЗПЪЛНЕНИЯ, КОИТО ОСТАВАТ ИСТОРИЯ
40087175055/attempt1/838bd591...: общ FAILURE. Linux2509uniquePASS/0FAIL/ERROR/SKIP,
189compile; macOSARM64 само limited portability probe. Windows отказва при
началната copy проверка; точното старо име/поле не е записано.
Cloud security320baseline+7R3 сигнала не са327 доказани дефекта. Един distinct
cryptography49 advisory CVE-2026-69247/GHSA-g6cj-pr64-35w5 остава NOT_FIXED.

40096716338/attempt1/8f62fa6: FAILURE в BOOTSTRAP_BEFORE иFINAL. Измерена грешка
в нашия CI reader: Windows/CPython3.12.3 lstatctime=birthtime, fstatctime=ChangeTime.
Вход mokosh_vault_recovery_source_selection.py,17741bytes,
SHA256856143153b21cc6c3ff81e908cbf875c0433492a79a023ee2ab3e4b793024600.
Само crossAPIctime е различен; path/path иfd/fd са стабилни, bytes/hash точни.
Пълният263before/after guard не завършва. Appvenv/pip/copy/compile/probe/worker
не са достигнати; старият отказанpip report не е възпроизведен и е OPEN.
BOOTSTRAPreceipt+raw1 са налични. STAGEreceipt+runner success има, raw0 не е
отпечатан; изводът за0 и строгият evidence пропуск са запазени отделно.

ЛОКАЛНО ПОДГОТВЕНАТА CI ПОПРАВКА
Потребителят одобри подготовката в отделно копие. Path/path7fields inclctime
иsamefd/fd7fields inclctime се сравняват отделно. CrossAPIidentity/regular/link/
size/mode/mtime, boundedread, length/SHA/count/canonical, finalsource/copy и
cleanup остават. Задължителният postpath е при още отворен descriptor.
Няма tolerance/retry/sleep в reader, Python upgrade или продуктова поправка.
Windows pathctime не е ChangeTime baseline преди отварянето. FD наблюдението
започва при първия проверенfstat; няма универсално обещание за минали събития,
ACL/owner или Windows backend за ключове/профили.
Новите diagnostic записи разграничават actual lstat_guard_after от по-късния
lstat_failure_probe, observation_contract LIKE_API_GUARD_PAIRS_V2. Старите raw
записи са непроменени. Неуспешен guardstat остава INCOMPLETE дори при успешен
по-късен probe. Бюджет16/32/16 записа, общо64×4096bytes; без content/envdump.
Стар baseline0eccbc1832459c98e19142d2907cba3786c2185a/treebcefce72... е равен на
публикуван8f62fa6. Само доказаните false-refusal очаквания са подравнени към
одобрения договор; privacy/sink/phase отрицателните цели остават с истинска
FD промяна. Старите тестове/код/FAIL са запазени.

СЛЕДВАЩ WINDOWS КОНТРОЛ — САМО ПОДГОТВЕН
Двата стари workflows са byte-exact. Новият MOKOSH Windows stat reader
verification only е manual-only, Windows2022/x64/Python3.12.3, pinned actions,
read-only contents. Bootstrap, owned non-secret native fixtures, ограничен
compile/runtime portability probe и allowlisted reports; без fullmatrix/GUI.
Реалните kernel метаданни трябва да докажат стабилната разлика и истинската
ctime-only промяна. Невъзпроизведено условие = nonzero/UNEXERCISED, не PASS.
Wrapper записва действителния числов childexit и запазва отказите. Timeout,
collection/write/flush/cleanup грешка не може да се представи за wrapperPASS.
Marker, действителният wrapperexit и run/job/attempt/commit се четат заедно.
Преди публикуване и новrun се представят точният кандидат и резултатите.
Локалните резултати са в ANALYSIS_STATUS.json; няма nativeWindows/macOS,
exactDell/физическо или продуктово security приемане от Linux лабораторията.
LOCAL_VALIDATION/history/draft_workflows пазят по-старата подготовка. Git пази
executable bit, не всички POSIX права/owner/ACL; WindowsPOSIXbits NOT_VERIFIED.
Всички продуктови дефекти остават по отделните си доказателства и gates.

ЛОКАЛНИ ПРОВЕРКИ НА ГОТОВИЯ КАНДИДАТ
89 интегрирани CI контроли PASS:44controller+26diagnostic+19verification,
включително33 дословно запазени стари проверки. Независими29+17,8reader fault/
positive двойки,32workflow/wrapper контроли и1exit-projection двойка PASS.
Full2509uniquePASS/0FAIL/ERROR/SKIP,92модула/189compile,30.603s controller,
qualifiedlocalLinux/Python3.12.14/същите5pins/наличнатаprivateTkloader среда.
Развойните fixture грешки и първоначалните reviewFAIL са запазени, не са
броени за успешни контратестове. NativeWindows и физическият обхват предстоят.

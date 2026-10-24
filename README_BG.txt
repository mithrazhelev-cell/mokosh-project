MOKOSH — НЕЗАВЪРШЕНО ПРИЛОЖЕНИЕ, ПРЕДВАРИТЕЛЕН АНАЛИЗ
Това е отделно точно копие за сверяване и съвети, не готов продукт или release.
project/:263 точни файла, тестовете и зависимостите не са променяни.
Локално:2509 уникални PASS,0FAIL/ERROR/SKIP;33CIguards PASS, Python3.12.14,
headless. Това не приема физическия GUI, точната Dell среда или Windows/macOS.
Bandit:320baseline и7LOW в отделни R3файлове; това не са доказани дефекти.
Последният локален pip-audit е INCOMPLETE заради PyPI DNS. Предишният
cryptography49 advisory CVE-2026-69247 остава NOT_FIXED; няма blindupgrade.
Workflow е само за ръчно пускане, с read-only права, изолирани временни копия,
точни metadata/content guards и без автоматични поправки, merge или release.
R3файловете са само за отделен статичен анализ; не се прилагат върху project/.
Git пази executable bit, не пълни POSIX права. WindowsPOSIXbits NOT_VERIFIED.
D005 OPEN; Stage2.48 NOT_ACCEPTED; Dell проектът не е променян.
При открит дефект се пазят logs/FAIL и се следва O048 преди отделна поправка.
Актуални ограничения/доказателства:LOCAL_VALIDATION.json иANALYSIS_STATUS.json.
Историческите HOLD/no-account записи в history/ са superseded, не текущ статус.

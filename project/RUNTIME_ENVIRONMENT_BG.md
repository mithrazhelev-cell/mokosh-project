# MOKOSH Agent — проверена runtime среда

Дата на проверката: 2026-08-26

## Активно ядро

- Python: `3.12.3`
- Python executable: `/home/mitra/venv_sys/bin/python3`
- `cryptography`: `49.0.0`
- `argon2-cffi`: `25.1.0`
- криптографски backend: `OpenSSL 4.0.1 9 Jun 2026`
- ML-KEM import: наличен
- `MLKEM768PrivateKey`: наличен
- Tkinter: `8.6`, наличен от system Python standard-library integration
- `include-system-site-packages = false`
- user site: изключен
- `/usr/lib/python3/dist-packages`: не присъства в `sys.path`
- `pip check`: `No broken requirements found.`

`venv_sys` остава избраната среда за интерфейса и приложението. Изолацията не
премахва Tkinter или проектните crypto зависимости; тя премахва само неописани
глобални Python пакети. На 2026-08-26 повреден `pyvenv.cfg`, съдържащ public
identity export, беше запазен като защитено evidence и възстановен към exact
Python 3.12 virtual-environment конфигурация. Не бяха открити private keys.

`numpy`, `psutil` и `watchdog` не са необходими за текущото fail-closed ядро.
Те принадлежаха на архивирани експериментални модули и няма да бъдат включвани
като runtime зависимости, докато нов модул не докаже необходимостта им.

## Правила

1. Приложението се стартира само с Python от избраната виртуална среда.
2. Стартерът прекратява работа, ако средата липсва.
3. Не се прави тихо преминаване към друга Python инсталация.
4. ML-KEM се счита за наличен само след import, проверка на backend и известен
   тестов вектор/round-trip тест.
5. Обновяване на зависимост се прави в отделен Git commit след целия тестов
   комплект и тест за обратна съвместимост.
6. Публичен пакет няма да зависи от глобален `~/venv_sys`; преди packaging ще
   има възпроизводима project-local среда и проверен lock файл.

## Системни зависимости

Tkinter е системна Python библиотека в използваната Linux инсталация. Тя не се
инсталира чрез `pip` и трябва да бъде проверявана отделно от health check.

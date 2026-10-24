# MOKOSH Stage 2.47 — договор за съхранение на recovery фразата

Статус: част от приетия 32-файлов изолиран кандидат. Този документ описва
само Linux/POSIX storage границата и не е твърдение за сертификация,
непробиваемост или native Windows/macOS поддръжка.

Дата: 2026-09-13

## 1. Решението за удобство и сигурност

Потребителят не е длъжен да помни 25-те думи. След изричен избор има два
допустими начина:

| Начин | Какво прави MOKOSH | Задължителна проверка |
|---|---|---|
| отделен носител | записва четим, номериран лист в нова private папка | exact read-back и отделен filesystem device |
| хартия | не създава файл с фразата | повторно въвеждане на всичките 25 думи |

Приложението не предлага да пази фразата вътре в профила. Това би поставило
Vault-а и аварийния му ключ на едно място и би превърнало удобството в обща
точка на компрометиране.

## 2. Трите места

- Profile Vault: основното криптирано профилно хранилище.
- Recovery record: криптираният `.mokr` файл; може да е на Vault device-а,
  но никога вътре в profile root-а.
- Phrase backup: хартия или отделен файлов device; при файловия вариант
  device-ът трябва да е различен и от Vault, и от `.mokr` record-а.

„Друга папка“ на същия device не е достатъчна. Разделянето се проверява чрез
точната `st_dev` самоличност на вече отворените директории/файлове. Това
различава файлови системи, не обещава физически различна машина или защита
срещу storage/virtualization, които представят подвеждащи device identities.

## 3. Имена и формати

MOKOSH създава ново child име и отказва съществуващо:

```text
mokosh-recovery-record-<32 lowercase hex>/
└── mokosh-vault-recovery-<32 lowercase hex>.mokr

mokosh-recovery-phrase-<32 lowercase hex>/
└── mokosh-recovery-phrase-<32 lowercase hex>.txt
```

`<32 lowercase hex>` е 16-byte non-secret recovery identifier, не фразата.

Листът е canonical ASCII:

```text
MOKOSH-RP1
recovery-id=<32 lowercase hex>
secret=KEEP-SEPARATE-FROM-MOKR
words=25
01=<word>
...
25=<word>
END
```

Файлът с фразата е **plain text secret**, а не втори криптиран контейнер.
Това го прави използваем без още една парола, но означава, че всеки с достъп
до носителя може да прочете думите. Отделното физическо пазене от `.mokr` е
основната защита. `.mokr` остава криптиран и не съдържа четимата фраза.

## 4. Exact Linux filesystem правила

- родителската папка се избира изрично от ползвателя;
- path-ът трябва да е абсолютен след нормализация и без symlink компонент;
- родителят и създадените обекти трябва да принадлежат на текущия uid;
- новата child папка е точно `0700`;
- новият phrase файл е regular file точно `0600`, с `st_nlink == 1`;
- отварянето използва налични `O_DIRECTORY`, `O_CLOEXEC`, `O_NOFOLLOW`,
  `O_EXCL` и bounded non-blocking read правила;
- няма overwrite, rename върху съществуващ target или автоматичен destination;
- identity се сравнява преди, по време и след операцията чрез descriptor,
  device и inode;
- записът е bounded, `fsync`-нат, прочетен обратно, parsed и сравнен точно;
- parent directory се `fsync`-ва преди отчетен durable success;
- при import съдържанието се чете два пъти и source identity трябва да остане
  непроменена;
- файл над 4 096 bytes, нек canonical формат, грешни права, owner, type,
  hardlink или trailing bytes се отказва.

Правата `0700/0600` не криптират носителя и не защитават срещу root/admin или
физическо четене на незашифрован диск.

## 5. Флашки и неподходящи файлови системи

Директен запис на флашка е позволен само когато тя е отделен filesystem
device, собствеността и exact private mode могат да се проверят и durable
операциите са налични. Linux FAT/MSDOS (`0x4D44`) и exFAT (`0x2011BAB0`) се
отказват изрично: техният permission модел не може надеждно да изпълни този
договор.

Практическият удобен вариант е отделен Linux filesystem носител, например
подходящо подготвен ext4 volume с папка, притежавана от текущия ползвател.
Форматирането на носител изтрива данни и **не** се извършва от MOKOSH. Ако
ползвателят не желае отделен подходящ носител, хартиеният вариант остава
допустим. MOKOSH не mount-ва, не unmount-ва и не eject-ва устройство.

## 6. Отказ, rollback и несигурен резултат

Отказ от file chooser не прави нищо. При доказано неуспешна операция MOKOSH
може да премахне само exact нов обект, който сам е създал и чиято identity е
непроменена. Нова папка се премахва само ако е exact и празна. Чужд,
съществуващ, променен, hard-linked или non-empty обект никога не се чисти.

Ако write/fsync/read-back/cleanup резултатът не може да бъде доказан, изходът
е `UNCERTAIN`. GUI казва да не се опитва сляпо повторно и да се прегледа точно
избраната папка. Няма автоматичен retry, overwrite или предположение, че
файлът не съществува.

Затваряне след вече отчетен durable export оставя файла. Това е умишлено:
изтриването на recovery material без отделна authorization и exact ownership
доказателство би било по-опасно. Незавършените отделни файлове не трябва да
се приемат за готов комплект.

## 7. Поверителност

Забранени са:

- clipboard copy/paste feature за показаната фраза;
- автоматичен запис в home/profile/application directory;
- log, telemetry, crash-report или network изпращане на думи/root;
- cloud/email/photo препоръка;
- сериализиране или secret-bearing `repr` на parsed sheet object-а.

GUI полетата се изчистват при приключване, отказ, грешка и затваряне. Видимата
setup фраза се скрива незабавно при manual, panic, inactivity или anomaly
lock. Това е best effort в Python/Tk и не е гаранция за memory zeroisation.

## 8. Тестова и platform граница

Unit/integration проверките симулират no-clobber, symlink, hardlink, mode,
owner, same-device, FAT/exFAT, write/fsync/read race, safe rollback, uncertain
cleanup, double-read tamper и canonical parsing. Synthetic visual harness-ът
не записва реални файлове и използва само измислени данни.

Преди приемане са нужни pinned Python 3.12.3 Linux dry-run/apply, exact
32-path verification, full regression, independent post-apply verifier и
реален human тест с подходящи removable devices. Няма fallback към по-слаби
права на FAT/exFAT и няма Windows/macOS claim.

## 9. Коригиращо правило за state publish — 2026-09-15

След final rehearsal се публикува само публичната bounded lifecycle бележка.
Ако нейният write/fsync/replace/read-back не бъде доказан, setup-ът се затваря
като terminal failure и „Завърши“ не може да се повтори върху същия план.
Vault и паролата остават byte-exact; вече създадените външни копия остават,
но не се приемат за активен комплект. Това поведение има short-write и
one-shot regression тест и не въвежда автоматично изтриване или retry.

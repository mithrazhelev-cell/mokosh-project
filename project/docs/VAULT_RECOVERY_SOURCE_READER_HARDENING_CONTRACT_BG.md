# MOKOSH Stage 2.44 — hardening на recovery-source reader

## Статус и ограничен обхват

Stage 2.44 поправя единствено read boundary в
`mokosh_vault_recovery_storage.py`. Няма нов GUI action, recovery операция,
Vault mutation, cryptographic primitive, формат, network capability или
Contacts промяна. Съществуващите one-shot и preserve-and-stop договори остават
непроменени.

## Причини за промяната

Предишният reader имаше три недоказани свойства:

1. regular-file проверката беше след content-capable `open`, така че стабилен
   FIFO с валидно име и permissions можеше да блокира процеса;
2. предварително `realpath` сравнение и проверка само на непосредствения parent
   не задържаха descriptor за всеки ancestor и не доказваха пълната pathname
   identity при rename/symlink interleaving;
3. думата „authenticated“ за filename identifier беше неточна преди
   предоставяне на recovery secret и AEAD проверка.

POSIX read може да промени kernel/filesystem-managed access metadata според
mount policy. Следователно `filesystem_mutation_performed=False` означава, че
MOKOSH не заявява write/chmod/unlink/rename/replace/fsync или друга mutating
операция. Полето не е forensic гаранция за непроменен `atime`.

## Задължителен reader алгоритъм

За exact absolute canonical source path reader-ът:

1. валидира canonical `.mokr` filename;
2. отваря root и всеки directory component последователно с descriptor-relative
   `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`;
3. задържа цялата descriptor верига до края на операцията;
4. сравнява pre-open, opened и current device/inode за всеки component;
5. изисква final parent да е current-user directory с mode точно `0700`;
6. прави no-follow stat и изисква regular current-user file, mode точно `0600`,
   link count `1` и bounded nonzero size **преди** content-capable open;
7. отваря файла descriptor-relative с `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`;
8. проверява отново regular-file type, owner, mode, link count, size и
   path/opened identity;
9. чете само bounded bytes чрез `pread` и отказва truncation или trailing data;
10. сравнява device/inode/mode/owner/link/size/mtime/ctime преди и след read;
11. parse-ва само структурно framing/header и сравнява filename с
    **structurally observed** `recovery_id`;
12. проверява отново файла и всеки retained directory component непосредствено
    преди success;
13. затваря file descriptor и цялата directory chain в reverse order при
    success, ordinary exception и `BaseException`.

`O_NONBLOCK` не е latency или real-time гаранция. Той предотвратява известния
FIFO blocking клас при race; type и identity проверките остават задължителни и
всяко special-file или replacement състояние се отказва.

## Security boundary

Контролите предполагат некомпрометирани kernel, процес и current-user account и
filesystem с надеждни Linux/POSIX descriptor semantics. Те не доказват защита
срещу kernel compromise, universal filesystem behavior, физически offline
носител или бъдеща непроменяемост на pathname след приключилата проверка.

Структурната inspection не приема recovery secret и не удостоверява
ciphertext/tag. Криптографска автентикация съществува едва в отделния rehearsal
след правилен recovery secret.

## Verification

Задължителните regression случаи включват stable FIFO преди open, deterministic
regular-to-FIFO race с `O_NONBLOCK`, ancestor rename/symlink interleaving,
replacement по време на structural parse, descriptor cleanup при
`BaseException`, липса на заявени mutating filesystem calls, structurally
observed identifier wording и terminal one-shot failure behavior.

Това е възпроизводимо engineering evidence за конкретната поддържана POSIX
среда. Не е formal verification, независим одит, platform certification,
правно становище или декларация за съответствие.

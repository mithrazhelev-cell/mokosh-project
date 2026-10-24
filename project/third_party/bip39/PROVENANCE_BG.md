# Произход на английския речник за MOKOSH-RP1

Файлът `english.txt` е точно копие на английския списък от BIP-0039.

- официално хранилище: `https://github.com/bitcoin/bips`
- фиксиран commit: `bfc142f2b580a314c846dbce3c15c659c2b1d32d`
- изходен път: `bip-0039/english.txt`
- SHA-256: `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
- размер: 13 116 bytes, 2 048 ASCII думи
- лиценз на BIP-0039: MIT

MOKOSH използва списъка единствено като проверен речник от 2 048 думи.
MOKOSH-RP1 не е BIP39 мнемоника, wallet seed или BIP32 вход. Не се използват
BIP39 PBKDF2, passphrase, seed generation или позволените BIP39 дължини.
MOKOSH-RP1 съдържа точно 25 думи, за да не може да бъде объркан с валидна
BIP39 фраза.

Пълният текст на MIT лиценза е в съседния файл `LICENSE`.

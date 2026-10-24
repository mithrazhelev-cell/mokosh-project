import os
import getpass
import json
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from mokosh_paths import DATA_DIR

CONFIG_DIR = str(DATA_DIR)
SEED_STORE_PATH = os.path.join(CONFIG_DIR, "seed_store.enc")
SEED_META_PATH = os.path.join(CONFIG_DIR, "seed_meta.json")


def derive_key_from_password(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    pad = 16 - len(data) % 16
    data = data + bytes([pad] * pad)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(data) + enc.finalize()

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    iv, data = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    result = dec.update(data) + dec.finalize()
    pad = result[-1]
    if pad < 1 or pad > 16:
        raise ValueError("Invalid PKCS7 padding")
    if result[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid PKCS7 padding")
    return result[:-pad]

def init_seed():
    if os.path.exists(SEED_STORE_PATH):
        print("Seed вече е инициализиран.")
        return

    os.makedirs(CONFIG_DIR, exist_ok=True)

    pwd1 = getpass.getpass("Въведи мастер парола: ")
    pwd2 = getpass.getpass("Повтори паролата: ")

    if pwd1 != pwd2:
        print("Паролите не съвпадат. Прекратявам.")
        return

    nickname = input("Въведи никнейм: ").strip()

    seed_internal = os.urandom(32)
    salt = os.urandom(16)
    iterations = 200_000

    key = derive_key_from_password(pwd1, salt, iterations)
    enc = aes_encrypt(seed_internal, key)

    with open(SEED_STORE_PATH, "wb") as f:
        f.write(enc)

    meta = {
        "salt": base64.b64encode(salt).decode(),
        "iterations": iterations,
        "nickname": nickname
    }
    with open(SEED_META_PATH, "w") as f:
        json.dump(meta, f)

    print("Seed инициализиран и запазен криптирано.")

def _ensure_nickname_in_meta():
    if not os.path.exists(SEED_META_PATH):
        return
    with open(SEED_META_PATH, "r") as f:
        meta = json.load(f)
    if "nickname" not in meta:
        nick = input("Нямаш зададен никнейм. Въведи никнейм за този профил: ").strip()
        meta["nickname"] = nick
        with open(SEED_META_PATH, "w") as f:
            json.dump(meta, f)
        print("Никнеймът е запазен.")


def _load_seed_core(password: str, nickname: str):
    if not os.path.exists(SEED_STORE_PATH) or not os.path.exists(SEED_META_PATH):
        print("Seed не е инициализиран. Пусни init_seed() първо.")
        return None

    _ensure_nickname_in_meta()

    with open(SEED_META_PATH, "r") as f:
        meta = json.load(f)
    salt = base64.b64decode(meta["salt"])
    iterations = meta["iterations"]
    expected_nick = meta.get("nickname", "")

    if nickname != expected_nick:
        print("Грешен никнейм.")
        return None

    key = derive_key_from_password(password, salt, iterations)

    with open(SEED_STORE_PATH, "rb") as f:
        enc = f.read()

    try:
        seed_internal = aes_decrypt(enc, key)
    except Exception:
        print("Грешна парола или повреден seed_store.enc.")
        return None

    return seed_internal



def load_seed():
    """
    CLI вариант: пита за парола + никнейм през терминал.
    Винаги прави реална проверка.
    """
    pwd = getpass.getpass("Въведи мастер парола: ")
    nick = input("Въведи никнейм: ").strip()
    seed_internal = _load_seed_core(pwd, nick)
    if seed_internal is not None:
        print("Seed успешно зареден.")
    return seed_internal


def load_seed_with_creds(password: str, nickname: str) -> bool:
    """
    GUI вариант: подава му се парола + никнейм от прозорец.
    Винаги прави реална проверка и декриптиране.
    Връща True при успех, False при грешка.
    """
    seed_internal = _load_seed_core(password, nickname)
    return seed_internal is not None


def get_phi_seed():
    """
    Връща phi SEED (base64), ако seed е зареден успешно.
    Винаги изисква реално въвеждане/проверка (чрез load_seed()).
    """
    seed_internal = load_seed()
    if seed_internal is None:
        return None
    return base64.urlsafe_b64encode(seed_internal).decode()


def change_password_cli():
    """
    Смяна на паролата през терминала.
    """

    seed_internal = load_seed()
    if seed_internal is None:
        print("Неуспешно зареждане на seed. Прекратявам.")
        return

    new1 = getpass.getpass("Нова мастер парола: ")
    new2 = getpass.getpass("Повтори новата парола: ")

    if new1 != new2:
        print("Новите пароли не съвпадат. Прекратявам.")
        return

    with open(SEED_META_PATH, "r") as f:
        meta = json.load(f)

    nickname = meta.get("nickname", "")
    salt = os.urandom(16)
    iterations = 200_000

    key = derive_key_from_password(new1, salt, iterations)
    enc = aes_encrypt(seed_internal, key)

    with open(SEED_STORE_PATH, "wb") as f:
        f.write(enc)

    meta["salt"] = base64.b64encode(salt).decode()
    meta["iterations"] = iterations

    with open(SEED_META_PATH, "w") as f:
        json.dump(meta, f)

    print("Мастер паролата е сменена успешно.")

def change_password_gui(new_password: str, old_password: str, nickname: str) -> bool:
    """
    Смяна на паролата от GUI.
    Винаги прави реална проверка със старата парола и никнейм.
    """
    seed_internal = _load_seed_core(old_password, nickname)
    if seed_internal is None:
        return False


    if not os.path.exists(SEED_META_PATH):
        return False

    with open(SEED_META_PATH, "r") as f:
        meta = json.load(f)

    salt = os.urandom(16)
    iterations = 200_000

    key = derive_key_from_password(new_password, salt, iterations)
    enc = aes_encrypt(seed_internal, key)

    with open(SEED_STORE_PATH, "wb") as f:
        f.write(enc)

    meta["salt"] = base64.b64encode(salt).decode()
    meta["iterations"] = iterations

    with open(SEED_META_PATH, "w") as f:
        json.dump(meta, f)

    return True

if __name__ == "__main__":
    print("1) init_seed (инициализиране)")
    print("2) load_seed (зареждане и показване)")
    print("3) change_password (смяна на паролата)")
    choice = input("Избери (1/2/3): ").strip()
    if choice == "1":
        init_seed()
    elif choice == "2":
        s = get_phi_seed()
        if s is not None:
            print("phi SEED:", s)
    elif choice == "3":
        change_password_cli()
    else:
        print("Невалиден избор.")

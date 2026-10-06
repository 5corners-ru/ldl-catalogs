"""Подпись ленты готовых справочников 5 УГЛОВ.

Модуль fivecorners.loadeddirectorylist принимает ленту, только если index.json.sig — подпись
ed25519 точных байтов index.json ключом из tools/public-keys.txt, а каждый файл справочника
совпадает с sha256 из оглавления.

    python tools/sign.py            проставить sha256 файлов в index.json и подписать его
    python tools/sign.py --check    проверить подпись и суммы (без закрытого ключа; так же гоняет CI)

Закрытый ключ — base64 32-байтового seed: переменная LDL_CATALOG_SIGNING_KEY или файл
--key-file (по умолчанию ~/.ldl-catalogs/signing.key). Хранится в BearPass, в репозиторий
не попадает никогда.

Нужен pynacl: pip install pynacl
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.json"
SIGNATURE = ROOT / "index.json.sig"
PUBLIC_KEYS = ROOT / "tools" / "public-keys.txt"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_signing_key(key_file: str) -> SigningKey:
    raw = os.environ.get("LDL_CATALOG_SIGNING_KEY") or Path(key_file).expanduser().read_text().strip()
    return SigningKey(base64.b64decode(raw, validate=True))


def public_keys() -> list:
    return [line.strip() for line in PUBLIC_KEYS.read_text().splitlines() if line.strip() and not line.startswith("#")]


def sign(key_file: str) -> None:
    key = load_signing_key(key_file)
    own = base64.b64encode(bytes(key.verify_key)).decode()
    if own not in public_keys():
        sys.exit(f"ключ не из tools/public-keys.txt (его открытая часть {own}) — модуль такой подписи не поверит")

    index = json.loads(INDEX.read_text(encoding="utf-8"))
    for entry in index["catalogs"]:
        entry["sha256"] = sha256(ROOT / entry["file"])
    body = (json.dumps(index, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    INDEX.write_bytes(body)
    SIGNATURE.write_text(base64.b64encode(key.sign(body).signature).decode() + "\n")
    print(f"подписано: {len(index['catalogs'])} справочник(ов)")


def check() -> int:
    body = INDEX.read_bytes()
    signature = base64.b64decode(SIGNATURE.read_text().strip(), validate=True)
    for key in public_keys():
        try:
            VerifyKey(base64.b64decode(key)).verify(body, signature)
            break
        except BadSignatureError:
            continue
    else:
        print("ПОДПИСЬ НЕ СХОДИТСЯ: index.json правили после подписи — запустите tools/sign.py")
        return 1

    bad = [e["file"] for e in json.loads(body)["catalogs"] if e.get("sha256") != sha256(ROOT / e["file"])]
    if bad:
        print("СУММЫ НЕ СХОДЯТСЯ: " + ", ".join(bad) + " — запустите tools/sign.py")
        return 1
    print("подпись и суммы в порядке")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--key-file", default="~/.ldl-catalogs/signing.key")
    args = parser.parse_args()
    sys.exit(check() if args.check else sign(args.key_file))

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import pathlib
from datetime import datetime


BASE_DIR = pathlib.Path(__file__).resolve().parent
CREDENTIALS_PATH = BASE_DIR / "app_credentials.json"
PBKDF2_ITERS = 200_000


def _hash_password(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS)
    return digest.hex()


def _create_credentials_interactive() -> dict:
    print("\n=== Configuracao inicial de acesso ===")
    username = input("Defina username [admin]: ").strip() or "admin"

    while True:
        pwd1 = getpass.getpass("Defina password: ").strip()
        pwd2 = getpass.getpass("Confirme password: ").strip()
        if not pwd1:
            print("Password nao pode ser vazia.")
            continue
        if pwd1 != pwd2:
            print("Passwords diferentes. Tente novamente.")
            continue
        break

    salt = os.urandom(16)
    password_hash = _hash_password(pwd1, salt)
    return {
        "username": username,
        "salt_hex": salt.hex(),
        "password_hash": password_hash,
        "iterations": PBKDF2_ITERS,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }


def _ensure_credentials() -> dict:
    if CREDENTIALS_PATH.exists():
        return json.loads(CREDENTIALS_PATH.read_text(encoding="utf-8"))

    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    creds = _create_credentials_interactive()
    CREDENTIALS_PATH.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    print(f"Credenciais guardadas em: {CREDENTIALS_PATH}")
    return creds


def authenticate_or_exit(max_attempts: int = 3) -> bool:
    creds = _ensure_credentials()
    username_expected = str(creds.get("username", "admin"))
    salt_hex = str(creds.get("salt_hex", ""))
    expected_hash = str(creds.get("password_hash", ""))
    iterations = int(creds.get("iterations", PBKDF2_ITERS))

    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        print("Erro: ficheiro de credenciais invalido (salt).")
        return False

    for _ in range(max_attempts):
        print("\n=== Autenticacao da aplicacao ===")
        user = input("Username: ").strip()
        pwd = getpass.getpass("Password: ").strip()

        digest = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, iterations).hex()
        if user == username_expected and hmac.compare_digest(digest, expected_hash):
            print("Autenticacao concluida com sucesso.")
            return True
        print("Credenciais invalidas.")

    print("Acesso bloqueado: numero maximo de tentativas excedido.")
    return False


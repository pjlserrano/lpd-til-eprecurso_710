import base64
import json
import pathlib
import uuid

from dataclasses import dataclass, asdict
from datetime import datetime
from getpass import getpass
from typing import Optional

try:
    import pyotp
except ImportError:  # pragma: no cover
    pyotp = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:  # pragma: no cover
    rsa = None  # type: ignore


BASE_DIR = pathlib.Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "keys"
PRIVATE_KEY_PATH = KEY_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "public_key.pem"
DATA_PATH = BASE_DIR / "data.json"
SECRET_PATH = BASE_DIR / "2fa_secret.txt"


@dataclass
class Record:
    id: str
    url_enc: str
    user_enc: str
    password_enc: str
    created_at: str
    updated_at: str


def _ensure_dependencies() -> None:
    if pyotp is None:
        raise RuntimeError(
            "Dependencia em falta: instale 'pyotp' (pip install pyotp) para usar o password manager."
        )
    if rsa is None:
        raise RuntimeError(
            "Dependencia em falta: instale 'cryptography' (pip install cryptography) para usar o password manager."
        )


def _ensure_dirs() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    BASE_DIR.mkdir(parents=True, exist_ok=True)


def _generate_keypair() -> None:
    # Gera um par de chaves RSA e grava em PEM
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_bytes(public_bytes)


def _load_private_key():
    data = PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def _load_public_key():
    data = PUBLIC_KEY_PATH.read_bytes()
    return serialization.load_pem_public_key(data)


def _load_or_create_keys() -> None:
    _ensure_dirs()
    if not PRIVATE_KEY_PATH.exists() or not PUBLIC_KEY_PATH.exists():
        _generate_keypair()


def _load_or_create_2fa_secret() -> str:
    # Gera e guarda um segredo para 2FA se ainda não existir
    if not SECRET_PATH.exists():
        secret = pyotp.random_base32()
        SECRET_PATH.write_text(secret, encoding="utf-8")
        print("\n=== Configuracao inicial de 2FA ===")
        print("Guarde este codigo em uma app de autenticacao como Google Authenticator ou Authy:")
        print(f"  {secret}\n")
        uri = pyotp.TOTP(secret).provisioning_uri(
            name="LPD_PasswordManager", issuer_name="LPD"
        )
        print("Opcional: utilize este URI para adicionar a conta no seu autenticador:")
        print(f"  {uri}\n")
        print(
            "Depois de configurado, utilize o codigo TOTP para aceder ao gestor de passwords.\n"
        )
        return secret

    return SECRET_PATH.read_text(encoding="utf-8").strip()


def _prompt_2fa(secret: str) -> bool:
    for attempt in range(3):
        token = input("Codigo 2FA (TOTP): ").strip()
        if pyotp.TOTP(secret).verify(token, valid_window=1):
            return True
        print("Codigo invalido. Tente novamente.")
    return False


def _encrypt_password(password: str) -> str:
    public_key = _load_public_key()
    ciphertext = public_key.encrypt(
        password.encode("utf-8"),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def _decrypt_password(password_enc: str) -> str:
    private_key = _load_private_key()
    ciphertext = base64.b64decode(password_enc)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return plaintext.decode("utf-8")


def _encrypt_text(value: str) -> str:
    return _encrypt_password(value)


def _decrypt_text(value_enc: str) -> str:
    return _decrypt_password(value_enc)


def _load_records() -> list[Record]:
    if not DATA_PATH.exists():
        return []
    try:
        raw = json.loads(DATA_PATH.read_text(encoding="utf-8") or "[]")
        records: list[Record] = []
        for r in raw:
            # Compatibilidade com formato antigo (url/user em texto simples).
            if "url_enc" not in r and "url" in r:
                r["url_enc"] = _encrypt_text(r.get("url", ""))
            if "user_enc" not in r and "user" in r:
                r["user_enc"] = _encrypt_text(r.get("user", ""))
            r.pop("url", None)
            r.pop("user", None)
            records.append(Record(**r))
        return records
    except Exception:
        return []


def _save_records(records: list[Record]) -> None:
    DATA_PATH.write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")


def _select_record(records: list[Record]) -> Optional[Record]:
    if not records:
        print("Nenhum registo encontrado.")
        return None

    print("\nRegistos disponiveis:")
    for r in records:
        url = _decrypt_text(r.url_enc)
        user = _decrypt_text(r.user_enc)
        print(f"  {r.id} -> {url} ({user})")

    selected = input("ID do registo: ").strip()
    for r in records:
        if r.id == selected:
            return r
    print("ID nao encontrado.")
    return None


def _create_record(records: list[Record]) -> None:
    url = input("URL: ").strip()
    user = input("User: ").strip()
    password = getpass("Password: ").strip()

    rec = Record(
        id=str(uuid.uuid4()),
        url_enc=_encrypt_text(url),
        user_enc=_encrypt_text(user),
        password_enc=_encrypt_password(password),
        created_at=datetime.utcnow().isoformat() + "Z",
        updated_at=datetime.utcnow().isoformat() + "Z",
    )
    records.append(rec)
    _save_records(records)
    print("Registo criado com sucesso.")


def _view_record(records: list[Record]) -> None:
    rec = _select_record(records)
    if not rec:
        return
    url = _decrypt_text(rec.url_enc)
    user = _decrypt_text(rec.user_enc)
    password = _decrypt_password(rec.password_enc)
    print("\n--- Registo ---")
    print(f"URL: {url}")
    print(f"User: {user}")
    print(f"Password: {password}")
    print(f"Criado: {rec.created_at}")
    print(f"Atualizado: {rec.updated_at}")


def _update_record(records: list[Record]) -> None:
    rec = _select_record(records)
    if not rec:
        return

    current_url = _decrypt_text(rec.url_enc)
    current_user = _decrypt_text(rec.user_enc)
    print("(deixe vazio para manter valor atual)")
    url = input(f"URL [{current_url}]: ").strip() or current_url
    user = input(f"User [{current_user}]: ").strip() or current_user
    password = getpass("Password (nova / Enter para manter): ").strip()
    if password:
        rec.password_enc = _encrypt_password(password)

    rec.url_enc = _encrypt_text(url)
    rec.user_enc = _encrypt_text(user)
    rec.updated_at = datetime.utcnow().isoformat() + "Z"
    _save_records(records)
    print("Registo atualizado.")


def _delete_record(records: list[Record]) -> None:
    rec = _select_record(records)
    if not rec:
        return
    rec_url = _decrypt_text(rec.url_enc)
    confirm = input(f"Tem a certeza que deseja apagar '{rec_url}'? (s/N): ").strip().lower()
    if confirm != "s":
        print("Operacao cancelada.")
        return
    records.remove(rec)
    _save_records(records)
    print("Registo apagado.")


def run_password_manager() -> None:
    try:
        _ensure_dependencies()
        _ensure_dirs()
        _load_or_create_keys()
        secret = _load_or_create_2fa_secret()
    except RuntimeError as exc:
        print(f"Erro: {exc}")
        return

    print("\n=== Password Manager (2FA requerido) ===")
    if not _prompt_2fa(secret):
        print("Acesso negado: 2FA invalido.")
        return

    records = _load_records()
    while True:
        print("\n1) Listar registos")
        print("2) Criar registo")
        print("3) Consultar registo")
        print("4) Atualizar registo")
        print("5) Apagar registo")
        print("0) Voltar")
        choice = input("Opcao: ").strip()

        if choice == "1":
            if not records:
                print("Nenhum registo guardado.")
            else:
                for r in records:
                    url = _decrypt_text(r.url_enc)
                    user = _decrypt_text(r.user_enc)
                    print(f"  {r.id} -> {url} ({user})")

        elif choice == "2":
            _create_record(records)

        elif choice == "3":
            _view_record(records)

        elif choice == "4":
            _update_record(records)

        elif choice == "5":
            _delete_record(records)

        elif choice == "0":
            break

        else:
            print("Opcao invalida.")

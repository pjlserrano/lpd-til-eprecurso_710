#!/usr/bin/env python3
#
# Módulo: server.py - Servidor de mensagens seguras multiutilizador
#

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

HOST = "0.0.0.0"
PORT = 9000
PROTOCOL_VERSION = "LPDMSG/2"
BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = BASE_DIR / "server_private_key.pem"
PUBLIC_KEY_PATH = BASE_DIR / "server_public_key.pem"
ARCHIVE_PATH = BASE_DIR / "messages_store.enc"
BACKUP_PATH = BASE_DIR / "messages_backup.enc"


@dataclass
class ClientSession:
    sock: socket.socket
    addr: tuple[str, int]
    user: str
    cipher: Fernet


clients: list[ClientSession] = []
clients_lock = threading.Lock()
archive_lock = threading.Lock()


def _send_line(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\n").encode("utf-8"))


def _recv_line(sock: socket.socket) -> str | None:
    data = b""
    while b"\n" not in data:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
        if len(data) > 1024 * 1024:
            return None
    return data.split(b"\n", 1)[0].decode("utf-8", errors="ignore").strip()


def _ensure_keys() -> tuple[object, object]:
    if not PRIVATE_KEY_PATH.exists() or not PUBLIC_KEY_PATH.exists():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        PUBLIC_KEY_PATH.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    private_key = serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    return private_key, public_key


def _encrypt_archive_entry(public_key: object, plaintext: str) -> str:
    session_key = Fernet.generate_key()
    token = Fernet(session_key).encrypt(plaintext.encode("utf-8")).decode("utf-8")
    enc_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    row = {"k": base64.b64encode(enc_key).decode("utf-8"), "m": token}
    return json.dumps(row, ensure_ascii=True)


def _decrypt_archive_entry(private_key: object, line: str) -> str | None:
    try:
        row = json.loads(line)
        enc_key = base64.b64decode(row["k"])
        token = row["m"].encode("utf-8")
        session_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return Fernet(session_key).decrypt(token).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _load_archive_rows(private_key: object) -> list[dict]:
    if not ARCHIVE_PATH.exists():
        return []
    rows: list[dict] = []
    with archive_lock:
        with ARCHIVE_PATH.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                plaintext = _decrypt_archive_entry(private_key, line)
                if plaintext is None:
                    continue
                try:
                    row = json.loads(plaintext)
                    if isinstance(row, dict):
                        rows.append(row)
                except Exception:
                    continue
    return rows


def _save_archive_rows(public_key: object, rows: list[dict]) -> None:
    with archive_lock:
        with ARCHIVE_PATH.open("w", encoding="utf-8") as f:
            for row in rows:
                plaintext = json.dumps(row, ensure_ascii=False)
                encrypted_line = _encrypt_archive_entry(public_key, plaintext)
                f.write(encrypted_line + "\n")


def _archive_message(public_key: object, sender: str, message: str, participants: list[str]) -> None:
    row = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sender": sender,
        "participants": sorted(set(participants)),
        "message": message,
    }
    with archive_lock:
        with ARCHIVE_PATH.open("a", encoding="utf-8") as f:
            f.write(_encrypt_archive_entry(public_key, json.dumps(row, ensure_ascii=False)) + "\n")


def _send_payload(session: ClientSession, payload: dict) -> None:
    token = session.cipher.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("utf-8")
    _send_line(session.sock, token)


def _broadcast_payload(payload: dict, exclude: socket.socket | None = None) -> None:
    with clients_lock:
        sessions = list(clients)
    for session in sessions:
        if exclude is not None and session.sock is exclude:
            continue
        try:
            _send_payload(session, payload)
        except Exception:
            continue


def _remove_client(sock: socket.socket) -> None:
    with clients_lock:
        for session in list(clients):
            if session.sock is sock:
                clients.remove(session)
                break


def _find_by_user(rows: list[dict], username: str) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        participants = row.get("participants", [])
        sender = str(row.get("sender", ""))
        if username == sender or username in participants:
            out.append(row)
    return out


def _derive_backup_key(passphrase: str) -> bytes:
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _export_backup(private_key: object) -> None:
    passphrase = input("Passphrase para cifrar backup: ").strip()
    if not passphrase:
        print("Passphrase vazia. Operacao cancelada.")
        return

    rows = _load_archive_rows(private_key)
    blob = json.dumps(rows, ensure_ascii=False, indent=2).encode("utf-8")
    token = Fernet(_derive_backup_key(passphrase)).encrypt(blob)
    BACKUP_PATH.write_bytes(token)
    print(f"Backup cifrado criado: {BACKUP_PATH}")


def _view_backup() -> None:
    if not BACKUP_PATH.exists():
        print("Backup nao encontrado.")
        return
    passphrase = input("Passphrase do backup: ").strip()
    if not passphrase:
        print("Passphrase vazia.")
        return
    try:
        blob = Fernet(_derive_backup_key(passphrase)).decrypt(BACKUP_PATH.read_bytes())
        rows = json.loads(blob.decode("utf-8", errors="ignore"))
    except Exception:
        print("Credenciais invalidas ou backup corrompido.")
        return

    print("\n=== Conteudo do Backup (decifrado) ===")
    for i, row in enumerate(rows, 1):
        print(
            f"{i}. {row.get('timestamp','-')} | {row.get('sender','-')} | "
            f"{row.get('message','')} | participants={row.get('participants',[])}"
        )


def _show_archived_messages(private_key: object) -> None:
    rows = _load_archive_rows(private_key)
    if not rows:
        print("Sem mensagens arquivadas.")
        return
    print("\n=== Mensagens Arquivadas (chave privada) ===")
    for i, row in enumerate(rows, 1):
        print(
            f"{i}. {row.get('timestamp','-')} | {row.get('sender','-')} | "
            f"{row.get('message','')} | participants={row.get('participants',[])}"
        )


def _handle_archive_command(
    session: ClientSession, cmd: str, private_key: object, public_key: object
) -> None:
    rows = _load_archive_rows(private_key)
    mine = _find_by_user(rows, session.user)

    if cmd == "/archive list":
        _send_payload(session, {"type": "archive_list", "count": len(mine), "items": mine})
        return

    if cmd == "/archive download":
        _send_payload(session, {"type": "archive_download", "count": len(mine), "items": mine})
        return

    if cmd == "/archive delete":
        mine_ids = {r.get("id") for r in mine}
        kept = [r for r in rows if r.get("id") not in mine_ids]
        _save_archive_rows(public_key, kept)
        _send_payload(
            session,
            {"type": "archive_delete_result", "deleted": len(rows) - len(kept), "remaining": len(kept)},
        )
        return

    _send_payload(
        session,
        {
            "type": "info",
            "text": "Comandos: /archive list | /archive download | /archive delete | /quit",
        },
    )


def _handle_client(conn: socket.socket, addr: tuple[str, int], private_key: object, public_key: object) -> None:
    user = f"{addr[0]}:{addr[1]}"
    try:
        conn.settimeout(120)
        _send_line(conn, f"PROTO:{PROTOCOL_VERSION}")
        conn.sendall(PUBLIC_KEY_PATH.read_bytes())

        proto_line = _recv_line(conn)
        if not proto_line or proto_line != f"PROTO:{PROTOCOL_VERSION}":
            _send_line(conn, "ERROR:CLIENT_SERVER_PROTOCOL_MISMATCH")
            conn.close()
            return

        key_line = _recv_line(conn)
        if not key_line or not key_line.startswith("KEY:"):
            _send_line(conn, "ERROR:INVALID_KEY_FRAME")
            conn.close()
            return

        try:
            enc_session_key = base64.b64decode(key_line[4:])
            session_key = private_key.decrypt(
                enc_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            _send_line(conn, "ERROR:KEY_DECRYPT_FAILED")
            conn.close()
            return
        cipher = Fernet(session_key)

        user_line = _recv_line(conn)
        if user_line:
            try:
                decoded = cipher.decrypt(user_line.encode("utf-8")).decode("utf-8", errors="ignore")
                if decoded.startswith("USER:"):
                    user = decoded.split(":", 1)[1].strip() or user
            except Exception:
                pass

        session = ClientSession(sock=conn, addr=addr, user=user, cipher=cipher)
        with clients_lock:
            clients.append(session)

        print(f"[+] Cliente ligado: {user} ({addr[0]}:{addr[1]})")
        with clients_lock:
            participants = [c.user for c in clients]
        _archive_message(public_key, "SYSTEM", f"{user} entrou no chat", participants)
        _broadcast_payload({"type": "chat", "text": f"[SYSTEM] {user} entrou no chat"})

        while True:
            line = _recv_line(conn)
            if not line:
                break
            try:
                plaintext = cipher.decrypt(line.encode("utf-8")).decode("utf-8", errors="ignore").strip()
            except Exception:
                continue

            if plaintext.lower() in {"/quit", "exit"}:
                break

            if plaintext.startswith("/archive"):
                _handle_archive_command(session, plaintext.lower(), private_key, public_key)
                continue

            with clients_lock:
                participants = [c.user for c in clients]
            _archive_message(public_key, user, plaintext, participants)
            _broadcast_payload({"type": "chat", "text": f"[{user}] {plaintext}"})

    except Exception as exc:
        print(f"[!] Erro ao processar cliente {addr}: {exc}")
    finally:
        _remove_client(conn)
        try:
            conn.close()
        except Exception:
            pass
        print(f"[-] Cliente desligado: {user}")
        with clients_lock:
            participants = [c.user for c in clients]
        _archive_message(public_key, "SYSTEM", f"{user} saiu do chat", participants + [user])
        _broadcast_payload({"type": "chat", "text": f"[SYSTEM] {user} saiu do chat"})


def run_server() -> None:
    private_key, public_key = _ensure_keys()

    while True:
        print("\n=== Servidor de Mensagens Seguras ===")
        print("1) Iniciar servidor multiutilizador")
        print("2) Consultar mensagens arquivadas (chave privada)")
        print("3) Exportar backup cifrado (todas as mensagens)")
        print("4) Visualizar backup cifrado (com passphrase)")
        print("0) Voltar")
        choice = input("Opcao: ").strip()

        if choice == "2":
            _show_archived_messages(private_key)
            continue
        if choice == "3":
            _export_backup(private_key)
            continue
        if choice == "4":
            _view_backup()
            continue
        if choice == "0":
            return
        if choice != "1":
            print("Opcao invalida.")
            continue

        print(f"[+] Servidor a escutar em {HOST}:{PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(20)
            while True:
                try:
                    conn, addr = server.accept()
                    thread = threading.Thread(
                        target=_handle_client,
                        args=(conn, addr, private_key, public_key),
                        daemon=True,
                    )
                    thread.start()
                except KeyboardInterrupt:
                    print("\n[!] Servidor interrompido pelo utilizador.")
                    return

import base64
import json
import socket
import threading
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = Path(__file__).resolve().parent
DOWNLOADS_DIR = BASE_DIR / "downloads"
PROTOCOL_VERSION = "LPDMSG/2"


def _recv_until_public_key(sock: socket.socket) -> bytes:
    marker = b"-----END PUBLIC KEY-----\n"
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 1024 * 1024:
            break
    end = data.find(marker)
    if end == -1:
        raise RuntimeError("Nao foi possivel receber a chave publica do servidor.")
    return data[: end + len(marker)]


def _recv_protocol_line(sock: socket.socket) -> str:
    line = _recv_line(sock)
    if not line:
        raise RuntimeError("Servidor nao respondeu com versao de protocolo.")
    return line


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


def _save_download(username: str, items: list[dict]) -> Path:
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = DOWNLOADS_DIR / f"archive_{username}_{stamp}.json"
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _handle_payload(payload: dict, username: str) -> None:
    ptype = payload.get("type")
    if ptype == "chat":
        print(f"\n{payload.get('text', '')}")
        return
    if ptype == "info":
        print(f"\n[INFO] {payload.get('text', '')}")
        return
    if ptype == "archive_list":
        items = payload.get("items", [])
        print(f"\n[ARQUIVO] Mensagens em que participou: {len(items)}")
        for i, row in enumerate(items[:20], 1):
            print(
                f"  {i}. {row.get('timestamp','-')} | {row.get('sender','-')} | "
                f"{row.get('message','')}"
            )
        if len(items) > 20:
            print(f"  ... ({len(items) - 20} adicionais)")
        return
    if ptype == "archive_download":
        items = payload.get("items", [])
        path = _save_download(username, items)
        print(f"\n[DOWNLOAD] {len(items)} mensagens guardadas em: {path}")
        return
    if ptype == "archive_delete_result":
        print(
            f"\n[ARQUIVO] Removidas: {payload.get('deleted', 0)} | "
            f"Restantes no servidor: {payload.get('remaining', 0)}"
        )
        return
    print(f"\n[SERVER] {payload}")


def _reader_loop(sock: socket.socket, cipher: Fernet, username: str) -> None:
    while True:
        line = _recv_line(sock)
        if line is None:
            print("\n[INFO] Ligacao encerrada pelo servidor.")
            break
        try:
            plaintext = cipher.decrypt(line.encode("utf-8")).decode("utf-8", errors="ignore")
            payload = json.loads(plaintext)
            if isinstance(payload, dict):
                _handle_payload(payload, username)
            else:
                print(f"\n{plaintext}")
        except Exception:
            continue


def run_client() -> None:
    host = input("Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = int(input("Server port [9000]: ").strip() or "9000")
    username = input("Username: ").strip() or "anon"

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            proto_line = _recv_protocol_line(sock)
            if proto_line != f"PROTO:{PROTOCOL_VERSION}":
                print(
                    "Erro: protocolo incompativel entre cliente e servidor. "
                    "Atualize ambos para a mesma versao."
                )
                return
            _send_line(sock, f"PROTO:{PROTOCOL_VERSION}")

            public_pem = _recv_until_public_key(sock)
            public_key = serialization.load_pem_public_key(public_pem)

            session_key = Fernet.generate_key()
            cipher = Fernet(session_key)
            enc_session_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            _send_line(sock, "KEY:" + base64.b64encode(enc_session_key).decode("utf-8"))
            _send_line(sock, cipher.encrypt(f"USER:{username}".encode("utf-8")).decode("utf-8"))

            thread = threading.Thread(target=_reader_loop, args=(sock, cipher, username), daemon=True)
            thread.start()

            print("Ligado ao servidor.")
            print("Comandos: /archive list | /archive download | /archive delete | /quit")
            while True:
                msg = input("> ").strip()
                if not msg:
                    continue
                token = cipher.encrypt(msg.encode("utf-8")).decode("utf-8")
                _send_line(sock, token)
                if msg.lower() in {"/quit", "exit"}:
                    break
    except ConnectionRefusedError:
        print("Erro: ligacao recusada. Confirme se o servidor (opcao 5) esta ativo e a porta esta correta.")
    except TimeoutError:
        print("Erro: timeout na ligacao ao servidor. Verifique IP/porta e firewall.")
    except Exception as exc:
        print(f"Erro no cliente: {exc}")

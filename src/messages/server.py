import json
import pathlib
import socket
import threading
from datetime import datetime

from cryptography.fernet import Fernet

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
KEY_FILE = BASE_DIR / "messages" / "chat.key"
STORE_FILE = BASE_DIR / "messages" / "messages_store.enc"


def load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key


def append_message(cipher: Fernet, sender: str, text: str) -> None:
    payload = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "sender": sender,
        "text": text,
    }
    token = cipher.encrypt(json.dumps(payload).encode("utf-8"))
    with STORE_FILE.open("ab") as f:
        f.write(token + b"\n")


def handle_client(conn: socket.socket, addr: tuple[str, int], cipher: Fernet) -> None:
    with conn:
        conn.sendall(b"Nome: ")
        name = conn.recv(1024).decode("utf-8", errors="ignore").strip() or "anon"
        print(f"[+] Cliente ligado: {name} ({addr[0]}:{addr[1]})")
        conn.sendall(b"Mensagem (exit para sair): ")
        while True:
            data = conn.recv(4096)
            if not data:
                break
            text = data.decode("utf-8", errors="ignore").strip()
            if text.lower() == "exit":
                break
            print(f"[MSG] {name}@{addr[0]}:{addr[1]} -> {text}")
            append_message(cipher, name, text)
            conn.sendall(b"OK guardado\n")
        print(f"[-] Cliente desligado: {name} ({addr[0]}:{addr[1]})")


def run_server() -> None:
    host = input("Bind host [0.0.0.0]: ").strip() or "0.0.0.0"
    port = int(input("Bind port [5050]: ").strip() or "5050")

    cipher = Fernet(load_or_create_key())
    print(f"Servidor ativo em {host}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(8)

        while True:
            conn, addr = server.accept()
            th = threading.Thread(target=handle_client, args=(conn, addr, cipher), daemon=True)
            th.start()

import socket


def run_client() -> None:
    host = input("Server IP [127.0.0.1]: ").strip() or "127.0.0.1"
    port = int(input("Server port [5050]: ").strip() or "5050")

    with socket.create_connection((host, port), timeout=10) as sock:
        print(sock.recv(1024).decode("utf-8", errors="ignore"), end="")
        sock.sendall((input().strip() + "\n").encode("utf-8"))

        print(sock.recv(1024).decode("utf-8", errors="ignore"), end="")
        while True:
            msg = input().strip()
            sock.sendall((msg + "\n").encode("utf-8"))
            if msg.lower() == "exit":
                break
            print(sock.recv(1024).decode("utf-8", errors="ignore"), end="")

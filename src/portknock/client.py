import socket
import time


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def send_knock_sequence(
    target_ip: str,
    ports: list[int],
    protocol: str = "tcp",
    timeout: float = 0.5,
    inter_knock_delay: float = 0.4,
) -> None:
    for port in ports:
        if protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b"knock", (target_ip, port))
            finally:
                sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect_ex((target_ip, port))
            finally:
                sock.close()

        print(f"Knock enviado para {target_ip}:{port}/{protocol.upper()}")
        time.sleep(max(inter_knock_delay, 0.0))


def run_port_knocking_client() -> None:
    print("[LAB] Port Knocking Client - usar apenas em laboratorio autorizado.")
    target = input("Target IP: ").strip()
    sequence_csv = input("Sequencia de portas CSV [7000,8000,9000]: ").strip() or "7000,8000,9000"
    protocol = (input("Protocolo dos knocks [tcp]: ").strip() or "tcp").lower()
    wait_after = float(input("Aguardar apos knocks (s) [2]: ").strip() or "2")
    ssh_port = int(input("Porta SSH para validar [22]: ").strip() or "22")

    ports = [int(p.strip()) for p in sequence_csv.split(",") if p.strip().isdigit()]
    if not target or not ports:
        print("Erro: target e sequencia de portas sao obrigatorios.")
        return
    if protocol not in {"tcp", "udp"}:
        print("Erro: protocolo invalido. Utilize 'tcp' ou 'udp'.")
        return

    print(f"\nA enviar knock sequence para {target}: {ports} ({protocol.upper()})")
    send_knock_sequence(target_ip=target, ports=ports, protocol=protocol)

    print(f"A aguardar {wait_after:.1f}s para regra da firewall abrir SSH...")
    time.sleep(max(wait_after, 0.0))

    if _is_port_open(target, ssh_port, timeout=1.5):
        print(f"[OK] Porta SSH {ssh_port} acessivel apos knocking.")
        print(f"Teste de login: ssh utilizador@{target} -p {ssh_port}")
    else:
        print(f"[INFO] Porta SSH {ssh_port} ainda fechada/filtrada.")
        print("Verifique sequencia, tempo entre knocks e regras iptables/ipchains no servidor.")


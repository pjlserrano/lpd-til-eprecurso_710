import socket
import statistics
import time

def tcp_load_test(
    target_ip: str,
    target_port: int,
    duration: int,
    cps: int = 50,
    timeout: float = 1.5,
) -> dict[str, float]:
    attempts = 0
    ok = 0
    errors = 0
    latencies_ms: list[float] = []

    end_time = time.time() + duration
    delay = 1 / max(cps, 1)

    while time.time() < end_time:
        start = time.perf_counter()
        attempts += 1
        try:
            with socket.create_connection((target_ip, target_port), timeout=timeout):
                ok += 1
                elapsed_ms = (time.perf_counter() - start) * 1000
                latencies_ms.append(elapsed_ms)
        except OSError:
            errors += 1
        time.sleep(delay)

    total_time = max(duration, 1)
    avg_ms = statistics.fmean(latencies_ms) if latencies_ms else 0.0
    p95_ms = 0.0
    if latencies_ms:
        sorted_lat = sorted(latencies_ms)
        idx = max(0, min(len(sorted_lat) - 1, int(0.95 * (len(sorted_lat) - 1))))
        p95_ms = sorted_lat[idx]

    return {
        "attempts": float(attempts),
        "ok": float(ok),
        "errors": float(errors),
        "rps": attempts / total_time,
        "success_rate": (ok / attempts * 100.0) if attempts else 0.0,
        "avg_ms": avg_ms,
        "p95_ms": p95_ms,
    }


def run_syn_flood() -> None:
    print("[LAB] Teste de carga TCP (ligacoes legitimas) - usar apenas em laboratorio.")
    ip = input("Target IP: ").strip()
    port = int(input("Target port: ").strip() or "80")
    duration = int(input("Duracao (s) [10]: ").strip() or "10")
    cps = int(input("Ligacoes por segundo [50]: ").strip() or "50")
    timeout = float(input("Timeout por ligacao (s) [1.5]: ").strip() or "1.5")

    summary = tcp_load_test(ip, port, duration, cps=cps, timeout=timeout)
    print("\nResumo do teste:")
    print(f"Tentativas: {int(summary['attempts'])}")
    print(f"Ligacoes com sucesso: {int(summary['ok'])}")
    print(f"Falhas: {int(summary['errors'])}")
    print(f"Taxa media: {summary['rps']:.2f} tentativas/s")
    print(f"Taxa de sucesso: {summary['success_rate']:.1f}%")
    print(f"Latencia media: {summary['avg_ms']:.2f} ms")
    print(f"Latencia p95: {summary['p95_ms']:.2f} ms")

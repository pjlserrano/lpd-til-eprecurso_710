import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def scan_host(host: str, ports: list[int]) -> list[int]:
    return [port for port in ports if scan_port(host, port)]


def quick_scan_subnet(subnet: str, ports: list[int], max_hosts: int = 32) -> dict[str, list[int]]:
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = [str(ip) for ip in net.hosts()][:max_hosts]
    results: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(scan_host, host, ports): host for host in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                open_ports = fut.result()
            except OSError:
                open_ports = []
            if open_ports:
                results[host] = open_ports

    return dict(sorted(results.items()))

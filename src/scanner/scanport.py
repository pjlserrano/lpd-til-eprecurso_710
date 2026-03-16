#!/usr/bin/env python3
#
# MESI - Mestrado em Engenharia de Segurança da Informação 
# Linguagem de Programação Dinâmica - LPD - Projeto Python
# Aluno: Paulo Serrano - 710
#
# Módulo: scanport.py - Solicita um endereço IP ou subrede e faz scan das portas disponviveis.
# Exibe o resultao na tela
# Criado em 27/02/2026
# Historio de modificacoes:
# 

import socket
import ipaddress


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]

def scan_port(ip: str, port: int, timeout: float = 0.5) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), int(port)))
        sock.close()
        return "Aberta" if result == 0 else "Fechada"
    except socket.timeout:
        return "Sem resposta(pode estar bloqueada)"
    except socket.error:
        return "Erro"


def scan_host(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    open_ports = []
    for port in ports:
        status = scan_port(ip, port, timeout=timeout)
        print(f"{ip}:{port} -> {status}")
        if status == "Aberta":
            open_ports.append(port)
    return open_ports


def quick_scan_subnet(
    subnet: str,
    ports: list[int],
    max_hosts: int = 32,
    timeout: float = 0.5,
) -> dict[str, list[int]]:
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"Subrede inválida: {subnet}")
        return {}

    ports_to_scan = ports if ports else COMMON_PORTS
    results: dict[str, list[int]] = {}

    for index, ip in enumerate(network.hosts()):
        if index >= max_hosts:
            break
        results[str(ip)] = scan_host(str(ip), ports_to_scan, timeout=timeout)

    return results

def run():
    print("\n[ Scanner de Portos de Rede ]\n")
    target = input("Introduza um IP ou subrede (ex: 192.168.152.10 ou 192.168.152.0/24): ")

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print("Formato de IP ou subrede inválido.")
        return

    print(f"\nInício do scan em: {network}\n")

    for ip in network.hosts():
        print(f"\n--- Scan em {ip} ---")
        ports = scan_host(str(ip), COMMON_PORTS)

        if ports:
            print(f"[+] {ip} -> Portos abertos encontrados: {ports}")
        else:
            print(f"[-] {ip} -> Nenhuma porta aberta detectada")

    print("\nScan concluído.\n")

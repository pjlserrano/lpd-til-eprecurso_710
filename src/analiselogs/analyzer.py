#!/usr/bin/env python3
#
# MESI - Mestrado em Engenharia de Segurança da Informação 
# Linguagem de Programação Dinâmica - LPD - Projeto Python
# Aluno: Paulo Serrano - 710
#
# Módulo: analyzer.py - Analisa arquivo de log fornecido pelo professor ufw.log.
#
# Exibe o resultao na tela
# Criado em 25/02/2026
# Historio de modificacoes:
#
import re
import os
import geoip2.database
import geoip2.errors

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# Caminhos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UFW_LOG = os.path.join(BASE_DIR, "ufw.log")
AUTH_LOG = os.path.join(BASE_DIR, "auth.log")
GEOIP_DB = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

# Regex UFW
UFW_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+).*'
    r'SRC=(?P<src>\S+).*'
    r'DST=(?P<dst>\S+)'
    r'(?:.*SPT=(?P<spt>\d+))?'
    r'(?:.*DPT=(?P<dpt>\d+))?'
)

# Regex auth.log (SSH)
AUTH_PATTERN = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s[\d:]+).*'
    r'(Failed|Accepted).*from\s+(?P<src>\S+)'
)

# Reader global
reader = None
results = []

import csv

def export_csv(results, filename="security_events.csv"):
    if not results:
        return

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"[+] CSV gerado: {filename}")

def generate_pdf(results, filename="security_report.pdf"):
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    y = height - 50
    c.setFont("Helvetica", 10)

    c.drawString(50, y, "Relatório de Segurança")
    y -= 30

    for r in results:
        line = (
            f"{r['timestamp']} | "
            f"{r['src_ip']} ({r['country']}) → "
            f"{r['dst_ip']} | Porta {r['dpt']} | {r['log']}"
        )

        c.drawString(50, y, line)
        y -= 15

        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 50

    c.save()
    print(f"[+] PDF gerado: {filename}")

def get_country(ip):
    try:
        response = reader.country(ip)
        return response.country.name
    except geoip2.errors.AddressNotFoundError:
        return "Privado/Desconhecido"
    except Exception:
        return "Desconhecido"


def analyze_ufw():
    print("\n[ Análise de Logs UFW ]\n")

    if not os.path.exists(UFW_LOG):
        print("ufw.log não encontrado.")
        return

    with open(UFW_LOG, "r") as file:
        for line in file:
            match = UFW_PATTERN.search(line)
            if match:
                timestamp = match.group("timestamp")
                src_ip = match.group("src")
                dst_ip = match.group("dst")
                dpt = match.group("dpt") or "N/A"
                country = get_country(src_ip)

                print(f"Timestamp : {timestamp}")
                print(f"Origem    : {src_ip} ({country})")
                print(f"Destino   : {dst_ip}")
                print(f"Porta Dst : {dpt}")
                print("-" * 40)

                results.append({
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "country": country,
                    "dst_ip": dst_ip,
                    "dpt": dpt,
                    "log": "Firewall"
                })

def analyze_auth():
    print("\n[ Análise de Logs AUTH (SSH) ]\n")

    if not os.path.exists(AUTH_LOG):
        print("auth.log não encontrado.")
        return

    with open(AUTH_LOG, "r") as file:
        for line in file:
            match = AUTH_PATTERN.search(line)
            if match:
                timestamp = match.group("timestamp")
                src_ip = match.group("src")
                country = get_country(src_ip)

                status = "Sucesso" if "Accepted" in line else "Falha"

                print(f"Timestamp : {timestamp}")
                print(f"Origem    : {src_ip} ({country})")
                print(f"Resultado : {status}")
                print("-" * 40)

                results.append({
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "country": country,
                    "dst_ip": "N/A",
                    "dpt": "N/A",
                    "log": f"Acesso SSH ({status})"
                })

def run():
    global reader
    reader = geoip2.database.Reader(GEOIP_DB)

    analyze_ufw()
    analyze_auth()
    export_csv(results)
    generate_pdf(results)
    reader.close()


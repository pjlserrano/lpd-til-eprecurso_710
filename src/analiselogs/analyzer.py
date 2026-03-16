#!/usr/bin/env python3
#
# MESI - Mestrado em Engenharia de Seguranca da Informacao
# Linguagem de Programacao Dinamica - LPD - Projeto Python
# Modulo: analyzer.py
#

from __future__ import annotations

import csv
import ipaddress
import pathlib
import re
import sqlite3
import subprocess
import shutil
from collections import Counter
from datetime import datetime

try:
    import geoip2.database
except Exception:  # pragma: no cover
    geoip2 = None

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover
    A4 = None
    canvas = None

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception:  # pragma: no cover
    plt = None


BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "security_events.csv"
PDF_PATH = BASE_DIR / "security_report.pdf"
DB_PATH = BASE_DIR / "analiselogs" / "events.db"
CHART_PATH = BASE_DIR / "analiselogs" / "security_chart.png"

MMDB_CANDIDATES = [
    BASE_DIR / "analiselogs" / "GeoLite2-City-2025.mmdb",
    BASE_DIR / "analiselogs" / "GeoLite2-City.mmdb",
    BASE_DIR / "GeoLite2-City-2025.mmdb",
    BASE_DIR / "GeoLite2-City.mmdb",
    BASE_DIR / "GeoLite2-Country.mmdb",
    BASE_DIR / "analiselogs" / "GeoLite2-Country.mmdb",
]

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).*?\[UFW\s+(?P<action>\w+)\].*?"
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)"
    r"(?:\s+SPT=(?P<spt>\d+))?(?:\s+DPT=(?P<dpt>\d+))?"
)
AUTH_FAIL_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).*?"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)"
)
AUTH_OK_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).*?"
    r"Accepted \S+ for (?P<user>\S+) from (?P<src>\S+)"
)
HTTP_ACCESS_RE = re.compile(
    r'^(?P<src>\S+) \S+ \S+ \[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3})'
)
HTTP_ACCESS_SEARCH_RE = re.compile(
    r'(?P<src>\S+) \S+ \S+ \[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" (?P<status>\d{3})'
)
SYSLOG_RFC5424_RE = re.compile(
    r"^<\d+>\d+\s+(?P<ts>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<msg>.*)$"
)
SYSLOG_RFC3164_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+\S+\s+(?P<msg>.*)$"
)


def _build_geoip_reader():
    if geoip2 is None:
        return None, "-"
    for candidate in MMDB_CANDIDATES:
        if candidate.exists():
            try:
                return geoip2.database.Reader(str(candidate)), str(candidate)
            except Exception:
                continue
    return None, "-"


GEOIP_READER, GEOIP_DB_USED = _build_geoip_reader()
COUNTRY_CACHE: dict[str, str] = {}


def country_from_ip(ip: str) -> str:
    if ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip]

    value = "Unknown"
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Tudo o que nao e IP global publico nao deve ser geolocalizado em pais.
        if not ip_obj.is_global:
            value = "Private/Reserved"
        elif GEOIP_READER is None:
            value = "GeoIP-DB-Missing"
        else:
            try:
                # DB City ou Country: tentar city() e fallback para country().
                try:
                    resp_city = GEOIP_READER.city(ip)
                    value = resp_city.country.name or "GeoIP-No-Country"
                except Exception:
                    resp_country = GEOIP_READER.country(ip)
                    value = resp_country.country.name or "GeoIP-No-Country"
            except Exception:
                value = "GeoIP-No-Match"
    except Exception:
        value = "Unknown"

    COUNTRY_CACHE[ip] = value
    return value


def pick_existing_log(primary: pathlib.Path | None, fallbacks: list[str]) -> pathlib.Path | None:
    if primary and primary.exists():
        return primary
    for candidate in fallbacks:
        p = pathlib.Path(candidate).expanduser()
        if p.exists():
            return p
    return None


def read_journal_auth_lines(max_lines: int = 5000) -> list[str]:
    if shutil.which("journalctl") is None:
        return []

    commands = [
        ["journalctl", "--no-pager", "-o", "short-unix", "-u", "ssh", "-n", str(max_lines)],
        ["journalctl", "--no-pager", "-o", "short-unix", "-u", "sshd", "-n", str(max_lines)],
        ["journalctl", "--no-pager", "-o", "short-unix", "-t", "sshd", "-n", str(max_lines)],
    ]

    for cmd in commands:
        try:
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        except Exception:
            continue

        lines = []
        for line in out.splitlines():
            m = re.match(r"^\d+\.\d+\s+\S+\s+(.+)$", line)
            lines.append(m.group(1) if m else line)
        if lines:
            return lines
    return []


def parse_ufw_line(line: str, year: int) -> dict | None:
    m = LINE_RE.search(line)
    if not m:
        return None

    raw = m.groupdict()
    ts = datetime.strptime(f"{year} {raw['month']} {raw['day']} {raw['time']}", "%Y %b %d %H:%M:%S")
    return {
        "timestamp": ts.isoformat(sep=" "),
        "service": "ufw",
        "action": raw["action"],
        "src": raw["src"],
        "dst": raw["dst"],
        "proto": raw["proto"],
        "spt": int(raw["spt"] or 0),
        "dpt": int(raw["dpt"] or 0),
        "country": country_from_ip(raw["src"]),
        "status": 0,
    }


def parse_auth_fail_line(line: str, year: int) -> dict | None:
    m = AUTH_FAIL_RE.search(line)
    if not m:
        return None
    raw = m.groupdict()
    ts = datetime.strptime(f"{year} {raw['month']} {raw['day']} {raw['time']}", "%Y %b %d %H:%M:%S")
    return {
        "timestamp": ts.isoformat(sep=" "),
        "service": "ssh",
        "action": "AUTH_FAIL",
        "src": raw["src"],
        "dst": "localhost",
        "proto": "SSH",
        "spt": 0,
        "dpt": 22,
        "country": country_from_ip(raw["src"]),
        "status": 0,
    }


def parse_auth_ok_line(line: str, year: int) -> dict | None:
    m = AUTH_OK_RE.search(line)
    if not m:
        return None
    raw = m.groupdict()
    ts = datetime.strptime(f"{year} {raw['month']} {raw['day']} {raw['time']}", "%Y %b %d %H:%M:%S")
    return {
        "timestamp": ts.isoformat(sep=" "),
        "service": "ssh",
        "action": "AUTH_OK",
        "src": raw["src"],
        "dst": "localhost",
        "proto": "SSH",
        "spt": 0,
        "dpt": 22,
        "country": country_from_ip(raw["src"]),
        "status": 0,
    }


def parse_http_access_line(line: str) -> dict | None:
    m = HTTP_ACCESS_RE.search(line)
    if not m:
        return None
    raw = m.groupdict()
    ts = datetime.strptime(raw["ts"], "%d/%b/%Y:%H:%M:%S %z")
    status = int(raw["status"])
    return {
        "timestamp": ts.isoformat(sep=" "),
        "service": "http",
        "action": "HTTP_ACCESS",
        "src": raw["src"],
        "dst": "localhost",
        "proto": "HTTP",
        "spt": 0,
        "dpt": 80,
        "country": country_from_ip(raw["src"]),
        "status": status,
    }


def parse_syslog_line(line: str, year: int) -> list[dict]:
    line = line.strip()
    if not line:
        return []

    timestamp: datetime | None = None
    message = line

    m5424 = SYSLOG_RFC5424_RE.match(line)
    if m5424:
        raw = m5424.groupdict()
        message = raw["msg"]
        try:
            ts_raw = raw["ts"].replace("Z", "+00:00")
            timestamp = datetime.fromisoformat(ts_raw)
        except Exception:
            timestamp = None
    else:
        m3164 = SYSLOG_RFC3164_RE.match(line)
        if m3164:
            raw = m3164.groupdict()
            message = raw["msg"]
            try:
                timestamp = datetime.strptime(
                    f"{year} {raw['month']} {raw['day']} {raw['time']}",
                    "%Y %b %d %H:%M:%S",
                )
            except Exception:
                timestamp = None

    events: list[dict] = []

    ufw_match = re.search(
        r"\[UFW\s+(?P<action>\w+)\].*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)"
        r"(?:\s+SPT=(?P<spt>\d+))?(?:\s+DPT=(?P<dpt>\d+))?",
        message,
    )
    if ufw_match:
        raw = ufw_match.groupdict()
        ts = timestamp or datetime.now()
        events.append(
            {
                "timestamp": ts.isoformat(sep=" "),
                "service": "ufw",
                "action": raw["action"],
                "src": raw["src"],
                "dst": raw["dst"],
                "proto": raw["proto"],
                "spt": int(raw["spt"] or 0),
                "dpt": int(raw["dpt"] or 0),
                "country": country_from_ip(raw["src"]),
                "status": 0,
            }
        )

    fail = re.search(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+)", message)
    if fail:
        src = fail.group("src")
        ts = timestamp or datetime.now()
        events.append(
            {
                "timestamp": ts.isoformat(sep=" "),
                "service": "ssh",
                "action": "AUTH_FAIL",
                "src": src,
                "dst": "localhost",
                "proto": "SSH",
                "spt": 0,
                "dpt": 22,
                "country": country_from_ip(src),
                "status": 0,
            }
        )

    ok = re.search(r"Accepted \S+ for (?P<user>\S+) from (?P<src>\S+)", message)
    if ok:
        src = ok.group("src")
        ts = timestamp or datetime.now()
        events.append(
            {
                "timestamp": ts.isoformat(sep=" "),
                "service": "ssh",
                "action": "AUTH_OK",
                "src": src,
                "dst": "localhost",
                "proto": "SSH",
                "spt": 0,
                "dpt": 22,
                "country": country_from_ip(src),
                "status": 0,
            }
        )

    http_m = HTTP_ACCESS_SEARCH_RE.search(message)
    if http_m:
        raw = http_m.groupdict()
        ts = datetime.strptime(raw["ts"], "%d/%b/%Y:%H:%M:%S %z")
        events.append(
            {
                "timestamp": ts.isoformat(sep=" "),
                "service": "http",
                "action": "HTTP_ACCESS",
                "src": raw["src"],
                "dst": "localhost",
                "proto": "HTTP",
                "spt": 0,
                "dpt": 80,
                "country": country_from_ip(raw["src"]),
                "status": int(raw["status"]),
            }
        )

    return events


def write_csv(events: list[dict], path: pathlib.Path = CSV_PATH) -> None:
    fields = [
        "timestamp",
        "service",
        "action",
        "src",
        "country",
        "dst",
        "proto",
        "spt",
        "dpt",
        "status",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)


def write_sqlite(events: list[dict], db_path: pathlib.Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP TABLE IF EXISTS events")
        conn.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                service TEXT,
                action TEXT,
                src TEXT,
                country TEXT,
                dst TEXT,
                proto TEXT,
                spt INTEGER,
                dpt INTEGER,
                status INTEGER
            )
            """
        )
        conn.executemany(
            "INSERT INTO events(timestamp, service, action, src, country, dst, proto, spt, dpt, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    e["timestamp"],
                    e["service"],
                    e["action"],
                    e["src"],
                    e["country"],
                    e["dst"],
                    e["proto"],
                    e["spt"],
                    e["dpt"],
                    e.get("status", 0),
                )
                for e in events
            ],
        )
        conn.commit()
    finally:
        conn.close()


def build_chart(summary: dict, chart_path: pathlib.Path = CHART_PATH) -> str:
    if plt is None:
        return "-"

    countries = summary.get("top_countries", [])[:7]
    services = summary.get("service_counts", [])[:7]
    if not countries and not services:
        return "-"

    labels_c = [str(k) for k, _ in countries]
    values_c = [int(v) for _, v in countries]
    labels_s = [str(k) for k, _ in services]
    values_s = [int(v) for _, v in services]

    plt.close("all")
    fig, axes = plt.subplots(2, 1, figsize=(8.2, 6.2))
    fig.suptitle("Resumo Visual de Eventos de Seguranca", fontsize=12)

    ax1 = axes[0]
    if labels_c:
        ax1.bar(labels_c, values_c)
        ax1.set_title("Top paises de origem")
        ax1.set_ylabel("Eventos")
        ax1.tick_params(axis="x", rotation=30)
    else:
        ax1.text(0.5, 0.5, "Sem dados de paises", ha="center", va="center")
        ax1.set_axis_off()

    ax2 = axes[1]
    if labels_s:
        ax2.pie(values_s, labels=labels_s, autopct="%1.1f%%", startangle=110)
        ax2.set_title("Distribuicao por servico")
    else:
        ax2.text(0.5, 0.5, "Sem dados de servicos", ha="center", va="center")
        ax2.set_axis_off()

    fig.tight_layout(rect=[0, 0.02, 1, 0.95])
    chart_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(chart_path, dpi=160)
    plt.close(fig)
    return str(chart_path)


def write_pdf(summary: dict, pdf_path: pathlib.Path = PDF_PATH) -> None:
    if canvas is None or A4 is None:
        return

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    c.setTitle("Security Report")
    y = 800

    lines = [
        "Relatorio de Seguranca - UFW/SSH/HTTP",
        f"Gerado em: {datetime.now().isoformat(timespec='seconds')}",
        f"Total de eventos: {summary['total_events']}",
        f"Log UFW: {summary.get('ufw_log_used', '-')}",
        f"Log SSH: {summary.get('auth_log_used', '-')}",
        f"Log HTTP: {summary.get('http_log_used', '-')}",
        f"Log SYSLOG: {summary.get('syslog_log_used', '-')}",
        "",
        "Top IPs origem:",
    ]

    lines.extend([f"- {ip}: {count}" for ip, count in summary["top_sources"]])
    lines.append("")
    lines.append("Top portos destino:")
    lines.extend([f"- {port}: {count}" for port, count in summary["top_dpt"]])
    lines.append("")
    lines.append("Top paises de origem:")
    lines.extend([f"- {country}: {count}" for country, count in summary["top_countries"]])
    lines.append("")
    lines.append("Eventos por servico:")
    lines.extend([f"- {svc}: {count}" for svc, count in summary["service_counts"]])
    lines.append("")
    lines.append(f"Tentativas invalidas (auth.log/syslog): {summary['invalid_attempts']}")
    lines.append("Top origens de tentativas invalidas:")
    lines.extend([f"- {ip}: {count}" for ip, count in summary["top_auth_fail_sources"]])

    for line in lines:
        c.drawString(50, y, line)
        y -= 18
        if y < 50:
            c.showPage()
            y = 800

    chart_path = summary.get("chart_path", "-")
    if chart_path and chart_path != "-":
        chart_file = pathlib.Path(chart_path)
        if chart_file.exists():
            c.showPage()
            c.setFont("Helvetica", 12)
            c.drawString(50, 800, "Grafico de eventos (gerado com matplotlib)")
            c.drawImage(str(chart_file), 45, 250, width=500, height=500, preserveAspectRatio=True, mask="auto")

    c.save()


def run_analysis(
    log_path: str,
    year: int | None = None,
    auth_log_path: str | None = None,
    http_log_path: str | None = None,
    syslog_log_path: str | None = None,
) -> dict:
    year = year or datetime.now().year
    path = pathlib.Path(log_path)
    if path.is_dir():
        path = path / "ufw.log"
    if not path.exists():
        raise FileNotFoundError(f"Log nao encontrado: {path}")

    events: list[dict] = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, 1):
            parsed = parse_ufw_line(line, year)
            if parsed:
                events.append(parsed)
            if idx % 500 == 0:
                print(f"Processadas {idx} linhas de UFW...")

    auth_primary = pathlib.Path(auth_log_path).expanduser() if auth_log_path else path.parent / "auth.log"
    http_primary = pathlib.Path(http_log_path).expanduser() if http_log_path else path.parent / "access.log"

    auth_path = pick_existing_log(auth_primary, ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog"])
    http_path = pick_existing_log(
        http_primary,
        ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/httpd/access_log"],
    )
    syslog_primary = pathlib.Path(syslog_log_path).expanduser() if syslog_log_path else None
    syslog_path = pick_existing_log(syslog_primary, ["/var/log/syslog", "/var/log/messages"])

    invalid_attempts = 0
    ssh_success = 0
    http_accesses = 0

    auth_source = str(auth_path) if auth_path else "-"

    if auth_path:
        with auth_path.open("r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                failed = parse_auth_fail_line(line, year)
                if failed:
                    events.append(failed)
                    invalid_attempts += 1

                ok = parse_auth_ok_line(line, year)
                if ok:
                    events.append(ok)
                    ssh_success += 1

                if idx % 500 == 0:
                    print(f"Processadas {idx} linhas de AUTH/SSH...")
    else:
        journal_lines = read_journal_auth_lines()
        if journal_lines:
            auth_source = "journalctl:ssh/sshd"
            for idx, line in enumerate(journal_lines, 1):
                failed = parse_auth_fail_line(line, year)
                if failed:
                    events.append(failed)
                    invalid_attempts += 1

                ok = parse_auth_ok_line(line, year)
                if ok:
                    events.append(ok)
                    ssh_success += 1

                if idx % 500 == 0:
                    print(f"Processadas {idx} linhas de JOURNAL SSH...")

    if http_path:
        with http_path.open("r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                parsed = parse_http_access_line(line)
                if parsed:
                    events.append(parsed)
                    http_accesses += 1
                if idx % 500 == 0:
                    print(f"Processadas {idx} linhas de HTTP...")

    if syslog_path:
        same_as_ufw = syslog_path.resolve() == path.resolve()
        same_as_auth = bool(auth_path and syslog_path.resolve() == auth_path.resolve())
        same_as_http = bool(http_path and syslog_path.resolve() == http_path.resolve())
        if same_as_ufw or same_as_auth or same_as_http:
            print("Aviso: syslog coincide com outro log selecionado; parsing duplicado ignorado.")
            syslog_path = None

    if syslog_path:
        with syslog_path.open("r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                parsed_events = parse_syslog_line(line, year)
                for event in parsed_events:
                    events.append(event)
                    if event["service"] == "ssh" and event["action"] == "AUTH_FAIL":
                        invalid_attempts += 1
                    elif event["service"] == "ssh" and event["action"] == "AUTH_OK":
                        ssh_success += 1
                    elif event["service"] == "http" and event["action"] == "HTTP_ACCESS":
                        http_accesses += 1
                if idx % 500 == 0:
                    print(f"Processadas {idx} linhas de SYSLOG...")

    top_sources = Counter(e["src"] for e in events).most_common(10)
    top_dpt = Counter(e["dpt"] for e in events if e["dpt"] > 0).most_common(10)
    top_countries = Counter(e["country"] for e in events).most_common(10)
    service_counts = Counter(e["service"] for e in events).most_common(10)
    top_auth_fail_sources = Counter(e["src"] for e in events if e["action"] == "AUTH_FAIL").most_common(10)

    recent_invalid_attempts = [
        {"timestamp": e["timestamp"], "src": e["src"], "country": e["country"]}
        for e in events
        if e["action"] == "AUTH_FAIL"
    ][-10:]
    recent_http_accesses = [
        {"timestamp": e["timestamp"], "src": e["src"], "country": e["country"], "status": e.get("status", 0)}
        for e in events
        if e["action"] == "HTTP_ACCESS"
    ][-10:]

    summary = {
        "total_events": len(events),
        "invalid_attempts": invalid_attempts,
        "ssh_success": ssh_success,
        "http_accesses": http_accesses,
        "top_sources": top_sources,
        "top_dpt": top_dpt,
        "top_countries": top_countries,
        "service_counts": service_counts,
        "top_auth_fail_sources": top_auth_fail_sources,
        "recent_invalid_attempts": recent_invalid_attempts,
        "recent_http_accesses": recent_http_accesses,
        "ufw_log_used": str(path),
        "auth_log_used": auth_source,
        "http_log_used": str(http_path) if http_path else "-",
        "syslog_log_used": str(syslog_path) if syslog_path else "-",
        "geoip_db_used": GEOIP_DB_USED,
        "csv_path": str(CSV_PATH),
        "pdf_path": str(PDF_PATH),
        "db_path": str(DB_PATH),
    }

    summary["chart_path"] = build_chart(summary, CHART_PATH)
    write_csv(events, CSV_PATH)
    write_sqlite(events, DB_PATH)
    write_pdf(summary, PDF_PATH)
    return summary


if __name__ == "__main__":
    default_log = BASE_DIR / "analiselogs" / "ufw.log"
    try:
        result = run_analysis(str(default_log))
        print(result)
    finally:
        if GEOIP_READER is not None:
            GEOIP_READER.close()

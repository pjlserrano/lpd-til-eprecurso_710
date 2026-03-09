import csv
import pathlib
import re
import sqlite3
from collections import Counter
from datetime import datetime
from urllib.request import urlopen

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CSV_PATH = BASE_DIR / "security_events.csv"
PDF_PATH = BASE_DIR / "security_report.pdf"
DB_PATH = BASE_DIR / "analiselogs" / "events.db"

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d).*?\[UFW\s+(?P<action>\w+)\].*?"
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:\s+SPT=(?P<spt>\d+))?(?:\s+DPT=(?P<dpt>\d+))?"
)

COUNTRY_CACHE: dict[str, str] = {}


def country_from_ip(ip: str) -> str:
    if ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip]
    try:
        with urlopen(f"http://ip-api.com/line/{ip}?fields=country", timeout=2) as r:
            value = r.read().decode("utf-8", errors="ignore").strip() or "Unknown"
    except Exception:
        value = "Unknown"
    COUNTRY_CACHE[ip] = value
    return value


def parse_line(line: str, year: int) -> dict | None:
    m = LINE_RE.search(line)
    if not m:
        return None

    raw = m.groupdict()
    ts = datetime.strptime(f"{year} {raw['month']} {raw['day']} {raw['time']}", "%Y %b %d %H:%M:%S")
    return {
        "timestamp": ts.isoformat(sep=" "),
        "action": raw["action"],
        "src": raw["src"],
        "dst": raw["dst"],
        "proto": raw["proto"],
        "spt": int(raw["spt"] or 0),
        "dpt": int(raw["dpt"] or 0),
        "country": country_from_ip(raw["src"]),
    }


def write_csv(events: list[dict], path: pathlib.Path = CSV_PATH) -> None:
    fields = ["timestamp", "action", "src", "country", "dst", "proto", "spt", "dpt"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(events)


def write_sqlite(events: list[dict], db_path: pathlib.Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                src TEXT,
                country TEXT,
                dst TEXT,
                proto TEXT,
                spt INTEGER,
                dpt INTEGER
            )
            """
        )
        conn.execute("DELETE FROM events")
        conn.executemany(
            "INSERT INTO events(timestamp, action, src, country, dst, proto, spt, dpt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    e["timestamp"],
                    e["action"],
                    e["src"],
                    e["country"],
                    e["dst"],
                    e["proto"],
                    e["spt"],
                    e["dpt"],
                )
                for e in events
            ],
        )
        conn.commit()
    finally:
        conn.close()


def write_pdf(summary: dict, pdf_path: pathlib.Path = PDF_PATH) -> None:
    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    c.setTitle("Security Report")
    y = 800

    lines = [
        "Relatorio de Seguranca - UFW",
        f"Gerado em: {datetime.now().isoformat(timespec='seconds')}",
        f"Total de eventos: {summary['total_events']}",
        "",
        "Top IPs origem:",
    ]

    lines.extend([f"- {ip}: {count}" for ip, count in summary["top_sources"]])
    lines.append("")
    lines.append("Top portos destino:")
    lines.extend([f"- {port}: {count}" for port, count in summary["top_dpt"]])

    for line in lines:
        c.drawString(50, y, line)
        y -= 18
        if y < 50:
            c.showPage()
            y = 800

    c.save()


def run_analysis(log_path: str, year: int | None = None) -> dict:
    year = year or datetime.now().year
    path = pathlib.Path(log_path)
    events: list[dict] = []

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_line(line, year)
            if parsed:
                events.append(parsed)

    top_sources = Counter(e["src"] for e in events).most_common(10)
    top_dpt = Counter(e["dpt"] for e in events if e["dpt"] > 0).most_common(10)

    summary = {
        "total_events": len(events),
        "top_sources": top_sources,
        "top_dpt": top_dpt,
        "csv_path": str(CSV_PATH),
        "pdf_path": str(PDF_PATH),
        "db_path": str(DB_PATH),
    }

    write_csv(events, CSV_PATH)
    write_sqlite(events, DB_PATH)
    write_pdf(summary, PDF_PATH)
    return summary


if __name__ == "__main__":
    default_log = BASE_DIR.parent / "ufw.log"
    result = run_analysis(str(default_log))
    print(result)

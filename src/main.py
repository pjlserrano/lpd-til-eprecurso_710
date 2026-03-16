import pathlib

from analiselogs.analyzer import run_analysis
from auth import authenticate_or_exit
from portknock import run_port_knocking_client
from scanner.scanport import quick_scan_subnet
from scanner.webcheck import run_web_check
from synflood.tcpflood import run_syn_flood
from udpflood.udpflood import run_udp_flood

BASE_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / "analiselogs" / "ufw.log"


def print_menu() -> None:
    print("\n=== MESI - LPD EPOCA RECURSO - APLICACAO DE FERRAMENTAS DE SEGURANCA ===")
    print("1) Port scan rapido (rede 192.168.152.0/24)")
    print("2) Analisar logs UFW + SSH + HTTP (CSV/PDF/SQLite)")
    print("3) UDP flood (laboratorio)")
    print("4) Teste de carga TCP (HTTP/SMTP, laboratorio)")
    print("5) Iniciar servidor de mensagens seguras")
    print("6) Iniciar cliente de mensagens seguras")
    print("7) Verificar vulnerabilidades de URL")
    print("8) Gestor de passwords (2FA + encriptacao)")
    print("9) Port knocking client (abrir SSH em laboratorio)")
    print("0) Sair")


def main() -> None:
    if not authenticate_or_exit():
        return

    while True:
        print_menu()
        choice = input("Opcao: ").strip()

        if choice == "1":
            subnet = input("Subnet [192.168.152.0/24]: ").strip() or "192.168.152.0/24"
            ports = input("Portos CSV [22,80,443,8080]: ").strip() or "22,80,443,8080"
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            results = quick_scan_subnet(subnet=subnet, ports=port_list)
            for host, open_ports in results.items():
                if open_ports:
                    print(f"{host} -> {open_ports}")

        elif choice == "2":
            raw_log_path = input(f"Log path [{DEFAULT_LOG}]: ").strip()
            if not raw_log_path or raw_log_path.lower() == "auto":
                log_path = str(DEFAULT_LOG)
            elif raw_log_path.lstrip(": ").isdigit():
                print("Aviso: valor numerico detetado no Log path; a usar caminho default.")
                log_path = str(DEFAULT_LOG)
            else:
                log_path = raw_log_path
            auth_log_path = input("Auth log path [auto]: ").strip() or None
            http_log_path = input("HTTP access log path [auto]: ").strip() or None
            syslog_log_path = input("Syslog server path [auto/none]: ").strip() or None
            path = pathlib.Path(log_path)

            if path.is_dir():
                path = path / "ufw.log"

            if not path.exists():
                print(f"Erro: ficheiro nao encontrado -> {path}")
                continue

            summary = run_analysis(
                str(path),
                auth_log_path=auth_log_path,
                http_log_path=http_log_path,
                syslog_log_path=syslog_log_path,
            )
            print(f"Eventos processados: {summary.get('total_events', 0)}")
            print(f"Tentativas invalidas (auth.log): {summary.get('invalid_attempts', 0)}")
            print(f"Acessos SSH validos (auth.log): {summary.get('ssh_success', 0)}")
            print(f"Acessos HTTP (access.log): {summary.get('http_accesses', 0)}")
            print(f"Top paises de origem: {summary.get('top_countries', [])[:5]}")
            print(f"UFW usado: {summary.get('ufw_log_used', '-')}")
            print(f"SSH/Auth usado: {summary.get('auth_log_used', '-')}")
            print(f"HTTP usado: {summary.get('http_log_used', '-')}")
            print(f"SYSLOG usado: {summary.get('syslog_log_used', '-')}")
            print(f"CSV: {summary.get('csv_path', '-')}")
            print(f"PDF: {summary.get('pdf_path', '-')}")
            print(f"DB: {summary.get('db_path', '-')}")
            print(f"Grafico: {summary.get('chart_path', '-')}")

            print("\nUltimas tentativas invalidas SSH (timestamp, origem, pais):")
            recent_invalid = summary.get("recent_invalid_attempts", [])
            if recent_invalid:
                for item in recent_invalid:
                    print(f"- {item['timestamp']} | {item['src']} | {item['country']}")
            else:
                print("- Sem registos")

            print("\nUltimos acessos HTTP (timestamp, origem, pais, status):")
            recent_http = summary.get("recent_http_accesses", [])
            if recent_http:
                for item in recent_http:
                    print(f"- {item['timestamp']} | {item['src']} | {item['country']} | {item['status']}")
            else:
                print("- Sem registos")

        elif choice == "3":
            run_udp_flood()

        elif choice == "4":
            run_syn_flood()

        elif choice == "5":
            # Import local para evitar side effects de arranque no import global.
            from messages.server import run_server
            run_server()

        elif choice == "6":
            # Import local para evitar side effects de arranque no import global.
            from messages.client import run_client
            run_client()

        elif choice == "7":
            run_web_check()

        elif choice == "8":
            # Import local para evitar side effects e dependencias opcionais.
            from password_manager import run_password_manager

            run_password_manager()

        elif choice == "9":
            run_port_knocking_client()

        elif choice == "0":
            print("A terminar.")
            break

        else:
            print("Opcao invalida.")


if __name__ == "__main__":
    main()

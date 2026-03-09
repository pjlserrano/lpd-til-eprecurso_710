import pathlib

#from analiselogs.analyzer import run_analysis
from messages.client import run_client
from messages.server import run_server
from scanner.scanport import quick_scan_subnet
from scanner.webcheck import run_web_check
from synflood.tcpflood import run_syn_flood
from udpflood.udpflood import run_udp_flood
from scanner.scanport import quick_scan_subnet

BASE_DIR = pathlib.Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR.parent / "ufw.log"


def print_menu() -> None:
    print("\n=== MESI - LPD EPOCA RECURSO - APLICAÇÃO DE FERRAMENTAS DE SEGURANÇA ===")
    print("1) Port scan rapido (rede 192.168.30.0/24)")
    print("2) Analisar ufw.log + CSV + PDF + SQLite")
    print("3) UDP flood (laboratorio)")
    print("4) SYN flood (laboratorio)")
    print("5) Iniciar servidor de mensagens seguras")
    print("6) Iniciar cliente de mensagens seguras")
    print("7) Verificar vulnerabilidades de URL")
    print("0) Sair")


def main() -> None:
    while True:
        print_menu()
        choice = input("Opcao: ").strip()

        if choice == "1":
            subnet = input("Subnet [192.168.30.0/24]: ").strip() or "192.168.30.0/24"
            ports = input("Portos CSV [22,80,443,8080]: ").strip() or "22,80,443,8080"
            port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            results = quick_scan_subnet(subnet=subnet, ports=port_list)
            for host, open_ports in results.items():
                if open_ports:
                    print(f"{host} -> {open_ports}")

        elif choice == "2":
            log_path = input(f"Log path [{DEFAULT_LOG}]: ").strip() or str(DEFAULT_LOG)
            summary = run_analysis(log_path)
            print(f"Eventos processados: {summary['total_events']}")
            print(f"CSV: {summary['csv_path']}")
            print(f"PDF: {summary['pdf_path']}")
            print(f"DB: {summary['db_path']}")

        elif choice == "3":
            run_udp_flood()

        elif choice == "4":
            run_syn_flood()

        elif choice == "5":
            run_server()

        elif choice == "6":
            run_client()

        elif choice == "7":
            run_web_check()

        elif choice == "0":
            print("A terminar.")
            break

        else:
            print("Opcao invalida.")


if __name__ == "__main__":
    main()

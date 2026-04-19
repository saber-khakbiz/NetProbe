import os
import sys
from core.colors import Colors
from core.validators import clear_screen
from modules import discovery, dns_tools, scanner, web_tools, whois_tools

if os.name == 'nt':
    os.system('')


def main():
    menu = {
        '1':  ('ARP Discovery (Layer 2)',           discovery.module_l2_arp),
        '2':  ('ICMP Ping (Layer 3)',               discovery.module_l3_ping),
        '3':  ('Traceroute (Layer 3)',              discovery.module_traceroute),
        '4':  ('TCP Handshake (Layer 4)',           discovery.module_tcp_test),
        '5':  ('DNS Whitelist Scanner (From File)', dns_tools.module_dns_whitelist_scanner),
        '6':  ('SSL Certificate Checker',           web_tools.module_ssl_checker),
        '7':  ('DNS Record Lookup',                 dns_tools.module_dns_lookup),
        '8':  ('Port Range Scanner',                scanner.module_port_scanner),
        '9':  ('HTTP Probe',                        web_tools.module_http_probe),
        '10': ('Latency Statistics',                discovery.module_latency_stats),
        '11': ('Reverse DNS Lookup',                dns_tools.module_reverse_dns),
        '12': ('Full Site Accessibility Check',     web_tools.module_full_access_check),
        '13': ('WHOIS Lookup',                      whois_tools.module_whois_lookup), 
        '0':  ('Exit',                              sys.exit),
    }

    while True:
        print(f"\n{Colors.HEADER}{Colors.BOLD}--- Network Tool v4.2 ---{Colors.RESET}")
        for k in sorted(menu.keys(), key=lambda x: int(x)):
            c = Colors.RED if k == '0' else Colors.CYAN
            print(f"{c}[{k:>2}] {Colors.RESET}{menu[k][0]}")

        choice = input(f"\n{Colors.BOLD}Select: {Colors.RESET}").strip()
        if choice in menu:
            try:
                menu[choice][1]()
            except KeyboardInterrupt:
                print("\nStopped.")
            if choice != '0':
                input("\nPress Enter...")
            clear_screen()
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    clear_screen()
    main()
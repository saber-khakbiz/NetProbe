from core.colors import Colors
from core.validators import print_header, clean_domain, validate_ip_or_host
from core.network_utils import resolve, tcp_probe, is_dns_poisoned
from core.config import path_data
import platform
import subprocess
import socket
import os



def module_dns_whitelist_scanner():
    print_header("Advanced Whitelist Scanner (DNS + TCP Validation)")
    file_path = path_data()
    if not os.path.exists(file_path):
        print(f"{Colors.RED}[-] Error: '{file_path}' not found.{Colors.RESET}")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Colors.RED}[-] Read error: {e}{Colors.RESET}")
        return

    if not domains:
        print(f"{Colors.YELLOW}[!] File is empty.{Colors.RESET}")
        return

    print(f"{Colors.BLUE}[*] Testing {len(domains)} domains (DNS + TCP on Port 443)...{Colors.RESET}")
    print(f"{Colors.BLUE}[*] TCP handshakes may take a few seconds per blocked domain.{Colors.RESET}\n")
    print(f"{Colors.BOLD}{'Domain':<25} {'IP Address':<16} {'Status'}{Colors.RESET}")
    print("-" * 75)

    for domain in domains:
        d = clean_domain(domain)
        try:
            ip = resolve(d)
            if is_dns_poisoned(ip):
                status = f"{Colors.RED}Blocked (DNS Poisoned){Colors.RESET}"
            else:
                result = tcp_probe(ip, 443)
                if result == 0:
                    status = f"{Colors.GREEN}Fully Accessible (DNS+TCP OK){Colors.RESET}"
                else:
                    status = f"{Colors.YELLOW}Blocked (IP/SNI Filtered) [err={result}]{Colors.RESET}"
            print(f"{d[:24]:<25} {ip:<16} {status}")
        except socket.gaierror:
            print(f"{d[:24]:<25} {'N/A':<16} {Colors.RED}Unreachable (No DNS){Colors.RESET}")
        except Exception:
            print(f"{d[:24]:<25} {'ERROR':<16} {Colors.RED}Test Failed{Colors.RESET}")



def module_dns_lookup():
    print_header("DNS Record Lookup")
    raw = input(f"{Colors.YELLOW}Enter Domain: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    domain     = clean_domain(target)
    is_windows = platform.system().lower() == "windows"
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            if is_windows:
                result = subprocess.run(
                    ["nslookup", "-type=" + rtype, domain],
                    capture_output=True, text=True, errors='ignore', timeout=5
                )
                answers = [
                    l.strip() for l in result.stdout.splitlines()
                    if l.strip()
                    and not l.startswith("Server")
                    and not l.startswith("Address")
                    and ">" not in l
                ]
            else:
                result = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True, errors='ignore', timeout=5
                )
                answers = [l.strip() for l in result.stdout.splitlines() if l.strip()]

            if answers:
                print(f"\n{Colors.BOLD}{Colors.CYAN}[{rtype}]{Colors.RESET}")
                for ans in answers:
                    print(f"  {Colors.GREEN}{ans}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[{rtype}] No records found.{Colors.RESET}")

        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[{rtype}] Query timed out.{Colors.RESET}")
        except FileNotFoundError:
            print(f"{Colors.RED}[-] Required tool (dig / nslookup) not found.{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.RED}[{rtype}] Error: {e}{Colors.RESET}")



def module_reverse_dns():
    print_header("Reverse DNS Lookup")
    raw = input(f"{Colors.YELLOW}Enter IP Address: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    try:
        socket.inet_aton(target)
    except socket.error:
        print(f"{Colors.RED}[-] Invalid IP address format.{Colors.RESET}")
        return

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(target)
        print(f"\n{Colors.BOLD}IP:{Colors.RESET}        {target}")
        print(f"{Colors.BOLD}Hostname:{Colors.RESET}  {Colors.GREEN}{hostname}{Colors.RESET}")
        if aliases:
            print(f"{Colors.BOLD}Aliases:{Colors.RESET}   {', '.join(aliases)}")
        if addresses:
            print(f"{Colors.BOLD}Addresses:{Colors.RESET} {', '.join(addresses)}")
    except socket.herror:
        print(f"{Colors.RED}[-] No PTR record found for {target}.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")

import socket
import ssl
import time
import os
import sys
import re
import ipaddress
import subprocess
import platform
import threading
import http.client
import urllib.parse
import datetime

if os.name == 'nt':
    os.system('')

POISONED_PREFIXES = ("10.", "127.", "0.0.0.", "169.254.", "192.168.", "172.16.")
DEFAULT_TIMEOUT   = 3.0
PORT_SCAN_THREADS = 100


class Colors:
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    RED    = '\033[91m'
    RESET  = '\033[0m'
    BOLD   = '\033[1m'


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title):
    print(f"\n{Colors.CYAN}{Colors.BOLD}=== {title} ==={Colors.RESET}")


def validate_port(port_str, default=443):
    # Validates if the provided string is a valid network port (1-65535)
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
        return port
    except (ValueError, TypeError):
        print(f"{Colors.YELLOW}[!] Invalid port format. Using default: {default}{Colors.RESET}")
        return default

def validate_ip_or_host(target):
    # Validates if the input is a valid IP address or a valid hostname
    if not target or not isinstance(target, str):
        return None
        
    target = target.strip()
    if not target:
        return None

    # 1. Check if it is a valid IPv4 or IPv6 address
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass # Not a valid IP, move on to hostname validation

    # 2. Check if it is a valid hostname using regular expressions
    # This regex matches standard domains (e.g., example.com) and localhost
    hostname_regex = re.compile(
        r'^(?=.{1,253}$)'                                  # Overall length check (max 253 chars)
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+'            # Domain labels (max 63 chars per label)
        r'[A-Za-z]{2,63}$'                                 # Top-Level Domain (TLD)
        r'|^localhost$'                                    # Allow localhost
    )
    
    if hostname_regex.match(target):
        return target
        
    print(f"{Colors.RED}[-] Invalid input: Must be a valid IP address or Hostname.{Colors.RESET}")
    return None

def clean_domain(raw):
    # Extracts the core domain name from a URL safely
    try:
        # Basic removal of protocols and paths
        cleaned = raw.replace("https://", "").replace("http://", "").split('/')[0].strip()
        # Return only if it passes the hostname validation
        if validate_ip_or_host(cleaned):
            return cleaned
        return None
    except Exception:
        return None


def resolve(target):
    return socket.gethostbyname(target)


def run_os_command(command_list):
    process = None
    try:
        process = subprocess.Popen(
            command_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors='ignore'
        )
        for line in process.stdout:
            print(f"{Colors.RESET}{line.strip()}")
        process.wait()
    except KeyboardInterrupt:
        if process:
            process.terminate()
            process.wait()
        print(f"\n{Colors.YELLOW}[!] Interrupted.{Colors.RESET}")
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Command not found: {command_list[0]}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Execution failed: {e}{Colors.RESET}")


def is_dns_poisoned(ip):
    for prefix in POISONED_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def tcp_probe(ip, port, timeout=DEFAULT_TIMEOUT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port))


def module_l2_arp():
    print_header("Layer 2 ARP Discovery")
    raw = input(f"{Colors.YELLOW}Enter Local IP (e.g., 192.168.1.1): {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    ping_param = '-n' if platform.system().lower() == 'windows' else '-c'
    subprocess.run(
        ['ping', ping_param, '3', target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        arp_result = subprocess.run(
            ['arp', '-a'],
            capture_output=True,
            text=True,
            errors='ignore'
        )
        found = False
        for line in arp_result.stdout.splitlines():
            if target in line:
                print(f"{Colors.GREEN}[+] MAC Found: {line.strip()}{Colors.RESET}")
                found = True
                break
        if not found:
            print(f"{Colors.RED}[-] Not in ARP cache.{Colors.RESET}")
    except FileNotFoundError:
        print(f"{Colors.RED}[-] arp command not available on this system.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")


def module_l3_ping():
    print_header("Layer 3 ICMP Ping")
    raw = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return
    ping_param = '-n' if platform.system().lower() == 'windows' else '-c'
    run_os_command(['ping', ping_param, '4', target])


def module_traceroute():
    print_header("Routing Path (Traceroute)")
    raw = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return
    cmd = ['tracert', '-d', target] if platform.system().lower() == 'windows' else ['traceroute', '-n', target]
    run_os_command(cmd)


def module_dns_whitelist_scanner():
    print_header("Advanced Whitelist Scanner (DNS + TCP Validation)")
    file_path = "sites.txt"

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


def module_tcp_test():
    print_header("TCP Handshake Test")
    raw_target = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw_target)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    raw_port = input(f"{Colors.YELLOW}Port (default 443): {Colors.RESET}").strip() or "443"
    port = validate_port(raw_port)

    try:
        ip = resolve(target)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            start = time.time()
            result = sock.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000
            if result == 0:
                print(f"{Colors.GREEN}[+] SUCCESS! {ip}:{port} reachable (RTT: {elapsed:.2f}ms){Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] FAILED. {ip}:{port} unreachable (error code: {result}){Colors.RESET}")
    except socket.gaierror:
        print(f"{Colors.RED}[-] DNS resolution failed for: {target}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")


def module_ssl_checker():
    print_header("SSL Certificate Checker")
    raw = input(f"{Colors.YELLOW}Enter Hostname (e.g., google.com): {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    raw_port = input(f"{Colors.YELLOW}Port (default 443): {Colors.RESET}").strip() or "443"
    port = validate_port(raw_port)

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=DEFAULT_TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                cert   = tls_sock.getpeercert()
                cipher = tls_sock.cipher()

        subject  = dict(x[0] for x in cert.get("subject", []))
        issuer   = dict(x[0] for x in cert.get("issuer", []))
        san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        fmt        = "%b %d %H:%M:%S %Y %Z"
        not_after  = datetime.datetime.strptime(cert.get("notAfter",  ""), fmt)
        not_before = datetime.datetime.strptime(cert.get("notBefore", ""), fmt)
        days_left  = (not_after - datetime.datetime.utcnow()).days

        expiry_color = Colors.GREEN if days_left > 30 else (Colors.YELLOW if days_left > 0 else Colors.RED)

        print(f"\n{Colors.BOLD}Subject:{Colors.RESET}     {subject.get('commonName', 'N/A')}")
        print(f"{Colors.BOLD}Issuer:{Colors.RESET}      {issuer.get('organizationName', 'N/A')} / {issuer.get('commonName', 'N/A')}")
        print(f"{Colors.BOLD}Valid From:{Colors.RESET}  {not_before.strftime('%Y-%m-%d')}")
        print(f"{Colors.BOLD}Expires:{Colors.RESET}     {not_after.strftime('%Y-%m-%d')}  {expiry_color}({days_left} days left){Colors.RESET}")
        print(f"{Colors.BOLD}Protocol:{Colors.RESET}    {cipher[1]}")
        print(f"{Colors.BOLD}Cipher:{Colors.RESET}      {cipher[0]}")
        if san_list:
            shown = ', '.join(san_list[:6])
            extra = " ..." if len(san_list) > 6 else ""
            print(f"{Colors.BOLD}SAN ({len(san_list)}):{Colors.RESET}    {shown}{extra}")

    except ssl.SSLCertVerificationError as e:
        print(f"{Colors.RED}[-] Certificate verification failed: {e}{Colors.RESET}")
    except ssl.SSLError as e:
        print(f"{Colors.RED}[-] SSL error: {e}{Colors.RESET}")
    except socket.gaierror:
        print(f"{Colors.RED}[-] DNS resolution failed for: {target}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")


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


def module_port_scanner():
    print_header("Port Range Scanner")
    raw = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    raw_start  = input(f"{Colors.YELLOW}Start Port (default 1): {Colors.RESET}").strip()    or "1"
    raw_end    = input(f"{Colors.YELLOW}End Port   (default 1024): {Colors.RESET}").strip() or "1024"
    start_port = validate_port(raw_start, default=1)
    end_port   = validate_port(raw_end,   default=1024)

    if start_port > end_port:
        start_port, end_port = end_port, start_port

    try:
        ip = resolve(target)
    except socket.gaierror:
        print(f"{Colors.RED}[-] DNS resolution failed for: {target}{Colors.RESET}")
        return

    total      = end_port - start_port + 1
    open_ports = []
    lock       = threading.Lock()
    semaphore  = threading.Semaphore(PORT_SCAN_THREADS)
    scanned    = [0]

    print(f"{Colors.BLUE}[*] Scanning {ip} ports {start_port}-{end_port} ({total} total, {PORT_SCAN_THREADS} threads)...{Colors.RESET}\n")

    def scan_port(port):
        with semaphore:
            result = tcp_probe(ip, port, timeout=1.0)
            with lock:
                scanned[0] += 1
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                    open_ports.append((port, service))
                    print(f"\r  {Colors.GREEN}[OPEN]  {port:<6} {service}{Colors.RESET}")
                progress = int((scanned[0] / total) * 40)
                bar = f"[{'#' * progress}{'.' * (40 - progress)}] {scanned[0]}/{total}"
                print(f"\r  {Colors.BLUE}{bar}{Colors.RESET}", end='', flush=True)

    threads = []
    try:
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(port,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted.{Colors.RESET}")

    print(f"\n\n{Colors.BOLD}Scan complete. {len(open_ports)} open port(s) found.{Colors.RESET}")
    if open_ports:
        print(f"\n{Colors.BOLD}{'Port':<8} {'Service'}{Colors.RESET}")
        print("-" * 30)
        for port, service in sorted(open_ports):
            print(f"{Colors.GREEN}{port:<8} {service}{Colors.RESET}")


def module_http_probe():
    print_header("HTTP Probe")
    raw = input(f"{Colors.YELLOW}Enter URL (e.g., https://example.com): {Colors.RESET}").strip()
    if not raw:
        print(f"{Colors.RED}[-] No URL provided.{Colors.RESET}")
        return

    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw

    MAX_REDIRECTS = 10
    url = raw

    print(f"\n{Colors.BOLD}{'#':<4} {'Status':<10} {'URL / Location'}{Colors.RESET}")
    print("-" * 75)

    for hop in range(MAX_REDIRECTS + 1):
        try:
            parsed = urllib.parse.urlparse(url)
            scheme = parsed.scheme
            host   = parsed.netloc or parsed.path
            path   = parsed.path if parsed.netloc else "/"
            if parsed.query:
                path += "?" + parsed.query

            if scheme == "https":
                conn = http.client.HTTPSConnection(host, timeout=DEFAULT_TIMEOUT)
            else:
                conn = http.client.HTTPConnection(host, timeout=DEFAULT_TIMEOUT)

            start = time.time()
            conn.request("GET", path or "/", headers={
                "User-Agent": "NetworkTool/4.0",
                "Host":       host,
                "Connection": "close"
            })
            resp     = conn.getresponse()
            elapsed  = (time.time() - start) * 1000
            status   = resp.status
            reason   = resp.reason
            location = resp.getheader("Location", "")
            server   = resp.getheader("Server",   "")
            ctype    = resp.getheader("Content-Type", "")
            conn.close()

            sc = Colors.GREEN if 200 <= status < 300 else (Colors.YELLOW if 300 <= status < 400 else Colors.RED)
            print(f"{hop:<4} {sc}{status} {reason:<8}{Colors.RESET} {location or url}")

            if status in (301, 302, 303, 307, 308) and location:
                url = location if location.startswith("http") else f"{scheme}://{host}{location}"
                continue

            print(f"\n{Colors.BOLD}Final URL:{Colors.RESET}     {url}")
            print(f"{Colors.BOLD}RTT:{Colors.RESET}           {elapsed:.2f} ms")
            print(f"{Colors.BOLD}Server:{Colors.RESET}        {server or 'N/A'}")
            print(f"{Colors.BOLD}Content-Type:{Colors.RESET}  {ctype or 'N/A'}")
            break

        except ssl.SSLError as e:
            print(f"{Colors.RED}[-] SSL error: {e}{Colors.RESET}")
            break
        except socket.gaierror:
            print(f"{Colors.RED}[-] DNS resolution failed.{Colors.RESET}")
            break
        except Exception as e:
            print(f"{Colors.RED}[-] Connection error: {e}{Colors.RESET}")
            break
    else:
        print(f"{Colors.RED}[-] Too many redirects (>{MAX_REDIRECTS}).{Colors.RESET}")


def module_latency_stats():
    print_header("Latency Statistics")
    raw = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return

    raw_count = input(f"{Colors.YELLOW}Probe count (default 10): {Colors.RESET}").strip() or "10"
    try:
        count = max(1, min(100, int(raw_count)))
    except ValueError:
        count = 10

    raw_port = input(f"{Colors.YELLOW}Port (default 443): {Colors.RESET}").strip() or "443"
    port = validate_port(raw_port)

    try:
        ip = resolve(target)
    except socket.gaierror:
        print(f"{Colors.RED}[-] DNS resolution failed for: {target}{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Probing {ip}:{port} x{count}...{Colors.RESET}\n")
    print(f"{Colors.BOLD}{'#':<5} {'RTT (ms)':<12} {'Bar'}{Colors.RESET}")
    print("-" * 50)

    rtts = []
    sent = 0

    try:
        for i in range(1, count + 1):
            sent += 1
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(DEFAULT_TIMEOUT)
                    t0     = time.time()
                    result = sock.connect_ex((ip, port))
                    rtt    = (time.time() - t0) * 1000

                if result == 0:
                    rtts.append(rtt)
                    bar = Colors.GREEN + "|" * min(int(rtt / 5), 30) + Colors.RESET
                    print(f"{i:<5} {rtt:<12.2f} {bar}")
                else:
                    print(f"{i:<5} {'---':<12} {Colors.RED}unreachable{Colors.RESET}")

            except socket.timeout:
                print(f"{i:<5} {'---':<12} {Colors.RED}timeout{Colors.RESET}")
            except Exception:
                print(f"{i:<5} {'---':<12} {Colors.RED}error{Colors.RESET}")

            time.sleep(0.2)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted.{Colors.RESET}")

    received = len(rtts)
    lost     = sent - received
    loss_pct = (lost / sent * 100) if sent > 0 else 0.0

    print(f"\n{Colors.BOLD}--- Statistics for {target} ---{Colors.RESET}")
    print(f"Sent: {sent}  Received: {received}  Lost: {lost} ({loss_pct:.1f}% loss)")

    if rtts:
        avg    = sum(rtts) / len(rtts)
        jitter = (sum((r - avg) ** 2 for r in rtts) / len(rtts)) ** 0.5
        print(f"RTT  min: {min(rtts):.2f} ms  avg: {avg:.2f} ms  max: {max(rtts):.2f} ms  jitter: {jitter:.2f} ms")


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


def main():
    menu = {
        '1':  ('ARP Discovery (Layer 2)',           module_l2_arp),
        '2':  ('ICMP Ping (Layer 3)',               module_l3_ping),
        '3':  ('Traceroute (Layer 3)',              module_traceroute),
        '4':  ('TCP Handshake (Layer 4)',           module_tcp_test),
        '5':  ('DNS Whitelist Scanner (From File)', module_dns_whitelist_scanner),
        '6':  ('SSL Certificate Checker',           module_ssl_checker),
        '7':  ('DNS Record Lookup',                 module_dns_lookup),
        '8':  ('Port Range Scanner',                module_port_scanner),
        '9':  ('HTTP Probe',                        module_http_probe),
        '10': ('Latency Statistics',                module_latency_stats),
        '11': ('Reverse DNS Lookup',                module_reverse_dns),
        '0':  ('Exit',                              sys.exit),
    }

    while True:
        print(f"\n{Colors.HEADER}{Colors.BOLD}--- Network Tool v4.0 ---{Colors.RESET}")
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
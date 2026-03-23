import socket
from core.validators import validate_ip_or_host, validate_port, print_header
from core.colors import Colors
from core.network_utils import resolve, tcp_probe
import threading
from core.config import PORT_SCAN_THREADS 



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

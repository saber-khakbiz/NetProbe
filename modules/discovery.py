import socket
import time
import subprocess
import platform
from core.validators import print_header,validate_ip_or_host, validate_port
from core.network_utils import run_os_command, resolve
from core.config import DEFAULT_TIMEOUT
from core.colors import Colors


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

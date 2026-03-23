
from core.config import POISONED_PREFIXES, DEFAULT_TIMEOUT
from core.colors import Colors
import socket
import subprocess


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

def load_targets_from_file(file_path):
    # Reads targets from a text file and returns a clean list
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith('#'):
                    targets.append(cleaned)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    return targets
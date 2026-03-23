
import os
import re
import ipaddress
from core.colors import Colors


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
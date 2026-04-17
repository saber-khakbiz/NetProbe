import socket
import re
from core.colors import Colors
from core.validators import print_header, clean_domain, validate_ip_or_host


def whois_query(domain, server="whois.iana.org", port=43):
    """
    Send a WHOIS query to the specified server and return the response.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect((server, port))
            sock.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            return response.decode("utf-8", errors="ignore")
    except Exception as e:
        return None


def get_whois_server(domain):
    """
    Query IANA to find the appropriate WHOIS server for the TLD.
    """
    tld = domain.split(".")[-1]
    response = whois_query(tld, "whois.iana.org")
    if not response:
        return None

    # Look for "refer:" line in IANA response (most common)
    match = re.search(r"refer:\s*(\S+)", response, re.IGNORECASE)
    if match:
        return match.group(1)

    # Fallback for some ccTLDs that use "whois:" line
    match = re.search(r"whois:\s*(\S+)", response, re.IGNORECASE)
    if match:
        return match.group(1)

    # Fallback to a hardcoded list for common TLDs
    tld_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "biz": "whois.neulevel.biz",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
    }
    if tld.lower() in tld_servers:
        return tld_servers[tld.lower()]

    return None


def parse_whois_response(raw):
    """
    Extract key fields from WHOIS response (basic parsing).
    """
    fields = {}
    patterns = {
        "Domain Name": r"Domain Name:\s*(.+)",
        "Registrar": r"Registrar:\s*(.+)",
        "Creation Date": r"Creation Date:\s*(.+)",
        "Expiration Date": r"(?:Registry Expiry Date|Expiration Date|Expiry Date):\s*(.+)",
        "Updated Date": r"Updated Date:\s*(.+)",
        "Name Servers": r"Name Server:\s*(.+)",
        "Status": r"Domain Status:\s*(.+)",
        "Registrant": r"Registrant\s*(?:Name|Organization):\s*(.+)",
        "Admin": r"Admin\s*(?:Name|Organization):\s*(.+)",
        "Tech": r"Tech\s*(?:Name|Organization):\s*(.+)",
    }

    # Extract single-line fields
    for field, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            if field in ["Name Servers", "Status"]:
                fields[field] = list(set(matches))  # unique entries
            else:
                fields[field] = matches[0].strip()

    return fields


def module_whois_lookup():
    print_header("WHOIS Lookup")
    raw = input(f"{Colors.YELLOW}Enter Domain: {Colors.RESET}").strip()
    if not raw:
        print(f"{Colors.RED}[-] No domain provided.{Colors.RESET}")
        return

    domain = clean_domain(raw)
    if not domain:
        print(f"{Colors.RED}[-] Invalid domain format.{Colors.RESET}")
        return

    print(f"\n{Colors.BLUE}[*] Querying WHOIS for {domain}...{Colors.RESET}\n")

    # Step 1: Find WHOIS server for this TLD
    whois_server = get_whois_server(domain)
    if not whois_server:
        print(f"{Colors.RED}[-] Could not determine WHOIS server for TLD.{Colors.RESET}")
        return

    print(f"{Colors.CYAN}[+] WHOIS Server: {whois_server}{Colors.RESET}")

    # Step 2: Query the actual WHOIS server
    raw_response = whois_query(domain, whois_server)
    if not raw_response:
        print(f"{Colors.RED}[-] WHOIS query failed or timed out.{Colors.RESET}")
        return

    # Step 3: Parse and display
    fields = parse_whois_response(raw_response)

    if not fields:
        print(f"{Colors.YELLOW}[!] No structured data could be parsed. Showing raw output snippet:{Colors.RESET}")
        # Show first 500 chars of raw response
        print(raw_response[:500])
        return

    print(f"{Colors.BOLD}--- WHOIS Information ---{Colors.RESET}")
    for key, value in fields.items():
        if isinstance(value, list):
            print(f"{Colors.BOLD}{key}:{Colors.RESET}")
            for item in value:
                print(f"  {Colors.GREEN}{item}{Colors.RESET}")
        else:
            print(f"{Colors.BOLD}{key}:{Colors.RESET} {Colors.GREEN}{value}{Colors.RESET}")

    # Optionally show registrar abuse contact etc.
    if "Registrar" in fields:
        print(f"\n{Colors.YELLOW}[*] For full details, visit registrar's WHOIS page or use 'whois {domain}' on Linux.{Colors.RESET}")
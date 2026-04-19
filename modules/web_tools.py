from core.colors import Colors
from core.validators import print_header, validate_ip_or_host, validate_port
from core.config import DEFAULT_TIMEOUT
import http.client
import urllib.parse
import socket
import ssl
import time
import datetime


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
        
        
def module_full_access_check():
    """
    Comprehensive site accessibility check v2:
      - DNS resolution (poisoning detection)
      - Scan common web ports (80,443,8080,8443,3000,5000,8000)
      - HTTP/HTTPS request on each open port
    """
    print_header("Full Site Accessibility Check v2")
    raw = input(f"{Colors.YELLOW}Enter domain or URL: {Colors.RESET}").strip()
    if not raw:
        print(f"{Colors.RED}[-] No input provided.{Colors.RESET}")
        return

    from core.validators import clean_domain
    domain = clean_domain(raw)
    if not domain:
        print(f"{Colors.RED}[-] Could not extract a valid domain.{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}Target:{Colors.RESET} {domain}\n")
    print(f"{Colors.BLUE}[*] Step 1: DNS Resolution{Colors.RESET}")

    from core.network_utils import resolve, is_dns_poisoned, tcp_probe
    try:
        ip = resolve(domain)
        if is_dns_poisoned(ip):
            print(f"{Colors.RED}    [!!] DNS Poisoned → IP: {ip}{Colors.RESET}")
            print(f"{Colors.RED}    [!!] Site likely blocked or redirected.{Colors.RESET}")
            return
        else:
            print(f"{Colors.GREEN}    [+] DNS OK → {ip}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}    [-] DNS resolution failed: {e}{Colors.RESET}")
        return

    # --- Step 2: Scan common web ports ---
    common_web_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888]
    print(f"\n{Colors.BLUE}[*] Step 2: Scanning common web ports{Colors.RESET}")
    open_ports = []
    for port in common_web_ports:
        if tcp_probe(ip, port, timeout=1.5) == 0:
            open_ports.append(port)
            print(f"{Colors.GREEN}    [+] Port {port} open{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}    [!] Port {port} closed/filtered{Colors.RESET}")

    if not open_ports:
        print(f"{Colors.RED}[✗] No web ports open. Site unreachable via HTTP/HTTPS.{Colors.RESET}")
        return

    # --- Step 3: HTTP/HTTPS probe on each open port ---
    print(f"\n{Colors.BLUE}[*] Step 3: Probing HTTP/HTTPS on open ports{Colors.RESET}")
    import http.client
    import ssl
    from core.config import DEFAULT_TIMEOUT

    def http_check(scheme, port, host):
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port=port, timeout=DEFAULT_TIMEOUT)
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=DEFAULT_TIMEOUT)
            conn.request("GET", "/", headers={"User-Agent": "NetworkTool/4.0", "Host": host})
            resp = conn.getresponse()
            status = resp.status
            reason = resp.reason
            server = resp.getheader("Server", "")
            location = resp.getheader("Location", "")
            conn.close()
            return status, reason, server, location
        except Exception as e:
            return None, str(e), None, None

    any_success = False
    for port in open_ports:
        print(f"\n{Colors.CYAN}  --- Testing port {port} ---{Colors.RESET}")
        # Determine likely scheme: assume HTTPS for 443,8443; HTTP for others (but try both if ambiguous)
        schemes_to_try = []
        if port in (443, 8443):
            schemes_to_try = ["https"]
        elif port == 80:
            schemes_to_try = ["http"]
        else:
            schemes_to_try = ["http", "https"]  # try both

        for scheme in schemes_to_try:
            print(f"    Trying {scheme.upper()}...")
            status, reason, server, location = http_check(scheme, port, domain)
            if isinstance(status, int):
                color = Colors.GREEN if 200 <= status < 400 else Colors.YELLOW
                print(f"{color}      Response: {status} {reason}{Colors.RESET}")
                if location:
                    print(f"{color}      Redirect: {location}{Colors.RESET}")
                if server:
                    print(f"      Server: {server}")
                any_success = True
                break  # Stop trying other scheme for this port
            else:
                print(f"{Colors.RED}      Failed: {reason}{Colors.RESET}")

    print(f"\n{Colors.BOLD}--- Summary ---{Colors.RESET}")
    if any_success:
        print(f"{Colors.GREEN}[✓] Site appears accessible on at least one web port.{Colors.RESET}")
    else:
        print(f"{Colors.RED}[✗] No HTTP/HTTPS service responded correctly.{Colors.RESET}")
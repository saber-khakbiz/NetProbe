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
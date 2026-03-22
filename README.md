# NetProbe

A portable, modular CLI network diagnostic toolkit for layer-by-layer troubleshooting — from ARP to SSL.

Built with Python's standard library only. No external dependencies required.

---

## Features

| # | Module | Layer | Description |
|---|--------|-------|-------------|
| 1 | ARP Discovery | L2 | Resolve MAC address from a local IP via ARP cache |
| 2 | ICMP Ping | L3 | Standard ping with 4 packets |
| 3 | Traceroute | L3 | Hop-by-hop path to target |
| 4 | TCP Handshake | L4 | Single-port reachability test with RTT |
| 5 | DNS Whitelist Scanner | L4/L7 | Batch DNS + TCP validation from a domain list file |
| 6 | SSL Certificate Checker | L7 | Expiry date, issuer, cipher suite, SAN list |
| 7 | DNS Record Lookup | L7 | Query A, AAAA, MX, NS, TXT, CNAME, SOA records |
| 8 | Port Range Scanner | L4 | Multi-threaded TCP scan across a port range |
| 9 | HTTP Probe | L7 | GET request with redirect chain, RTT, headers |
| 10 | Latency Statistics | L4 | min / max / avg / jitter / packet loss over N probes |
| 11 | Reverse DNS Lookup | L3/L7 | IP → PTR record + aliases |

---

## Requirements

- Python 3.7+
- No third-party packages

**System tools used (must be available in PATH):**

| Tool | Platform | Used by |
|------|----------|---------|
| `ping` | Windows / Linux / macOS | ICMP Ping, ARP Discovery |
| `tracert` | Windows | Traceroute |
| `traceroute` | Linux / macOS | Traceroute |
| `arp` | All | ARP Discovery |
| `nslookup` | Windows | DNS Record Lookup |
| `dig` | Linux / macOS | DNS Record Lookup |

---

## Installation

```bash
git clone https://github.com/your-username/netprobe.git
cd netprobe
python network_tool.py
```

No `pip install` needed.

---

## Usage

### Interactive menu

```
--- Network Tool v4.0 ---
[ 1] ARP Discovery (Layer 2)
[ 2] ICMP Ping (Layer 3)
[ 3] Traceroute (Layer 3)
[ 4] TCP Handshake (Layer 4)
[ 5] DNS Whitelist Scanner (From File)
[ 6] SSL Certificate Checker
[ 7] DNS Record Lookup
[ 8] Port Range Scanner
[ 9] HTTP Probe
[10] Latency Statistics
[11] Reverse DNS Lookup
[ 0] Exit

Select:
```

### DNS Whitelist Scanner

Create a `sites.txt` file in the same directory, one domain per line:

```
google.com
github.com
https://example.com
```

Run the tool and select option `5`. Each domain is tested with DNS resolution followed by a TCP handshake on port 443.

---

## Module Details

### SSL Certificate Checker
Connects via TLS and reads the peer certificate. Displays:
- Common Name and issuer
- Validity window and days remaining (color-coded: green > 30d, yellow ≤ 30d, red = expired)
- Negotiated protocol and cipher suite
- Subject Alternative Names (SAN)

### Port Range Scanner
Spawns up to 100 concurrent threads. Displays a live progress bar and reports open ports with their resolved service names.

### Latency Statistics
Performs N TCP probes (default 10, max 100) to a given host:port. Reports min, max, avg, jitter (standard deviation), and packet loss percentage.

### HTTP Probe
Follows redirect chains (up to 10 hops). Reports each hop's status code, the final resolved URL, RTT, `Server` header, and `Content-Type`.

---

## DNS Poisoning Detection

The whitelist scanner checks resolved IPs against known private/loopback ranges that indicate DNS hijacking:

```
10.x.x.x     RFC 1918 private
127.x.x.x    Loopback
169.254.x.x  Link-local
172.16.x.x   RFC 1918 private
192.168.x.x  RFC 1918 private
0.0.0.x      Unspecified
```

---

## Platform Support

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| ARP Discovery | ✓ | ✓ | ✓ |
| ICMP Ping | ✓ | ✓ | ✓ |
| Traceroute | ✓ (`tracert`) | ✓ | ✓ |
| DNS Scanner | ✓ | ✓ | ✓ |
| TCP / SSL / HTTP | ✓ | ✓ | ✓ |
| DNS Record Lookup | ✓ (`nslookup`) | ✓ (`dig`) | ✓ (`dig`) |
| Port Scanner | ✓ | ✓ | ✓ |
| ANSI colors | ✓ * | ✓ | ✓ |

\* Requires Windows Terminal or a terminal that supports ANSI escape codes (e.g. Windows 10+, VS Code terminal).

---

## License

MIT

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
    print_header("Layer 3 ICMP Ping (Enhanced with Continuous Mode)")
    raw = input(f"{Colors.YELLOW}Enter Target: {Colors.RESET}")
    target = validate_ip_or_host(raw)
    if not target:
        print(f"{Colors.RED}[-] No target provided.{Colors.RESET}")
        return
    
    # Options
    print(f"\n{Colors.CYAN}Options:{Colors.RESET}")
    print(f"{Colors.CYAN}  Enter '0' for continuous ping (Ctrl+C to stop){Colors.RESET}")
    count_str = input(f"{Colors.YELLOW}Number of pings (default 4): {Colors.RESET}").strip() or "4"
    
    try:
        count_input = int(count_str)
        continuous_mode = (count_input == 0)
        count = float('inf') if continuous_mode else max(1, min(1000, count_input))
    except ValueError:
        count = 4
        continuous_mode = False
    
    timeout_str = input(f"{Colors.YELLOW}Timeout per ping in seconds (default 2): {Colors.RESET}").strip() or "2"
    try:
        timeout = max(1, min(10, int(timeout_str)))
    except ValueError:
        timeout = 2
    
    # Interval between pings for continuous mode
    interval = 1.0
    if continuous_mode:
        interval_str = input(f"{Colors.YELLOW}Interval between pings in seconds (default 1): {Colors.RESET}").strip() or "1"
        try:
            interval = max(0.2, min(5.0, float(interval_str)))
        except ValueError:
            interval = 1.0
    
    if continuous_mode:
        print(f"\n{Colors.BLUE}[*] Continuous ping to {target} (Press Ctrl+C to stop){Colors.RESET}")
        print(f"{Colors.BLUE}[*] Interval: {interval}s, Timeout: {timeout}s{Colors.RESET}\n")
    else:
        print(f"\n{Colors.BLUE}[*] Pinging {target} with {int(count)} packets (timeout={timeout}s)...{Colors.RESET}\n")
    
    # Detect OS for ping command
    is_windows = platform.system().lower() == "windows"
    
    if is_windows:
        cmd = ['ping', '-t' if continuous_mode else '-n', str(int(count)) if not continuous_mode else '', '-w', str(timeout * 1000), target]
        if continuous_mode:
            cmd.remove('')  # Remove empty string
    else:
        if continuous_mode:
            # Linux continuous ping
            cmd = ['ping', '-i', str(interval), '-W', str(timeout), target]
        else:
            cmd = ['ping', '-c', str(int(count)), '-W', str(timeout), target]
    
    # Run ping with real-time output parsing
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors='ignore',
            bufsize=1
        )
        
        stats = {
            'sent': 0,
            'received': 0,
            'lost': 0,
            'times': [],
            'ttl_values': [],
            'errors': [],
            'start_time': time.time()
        }
        
        ip_address = None
        seq_num = 0
        
        print(f"{Colors.BOLD}{'Seq':<6} {'IP':<16} {'TTL':<6} {'Time':<10} {'Status':<12} {'Loss %':<8}{Colors.RESET}")
        print("-" * 75)
        
        def print_realtime_stats(stats, seq_num):
            """Print real-time statistics line"""
            if stats['sent'] > 0:
                loss_rate = (stats['lost'] / stats['sent']) * 100
                if loss_rate == 0:
                    loss_color = Colors.GREEN
                elif loss_rate < 10:
                    loss_color = Colors.CYAN
                elif loss_rate < 25:
                    loss_color = Colors.YELLOW
                else:
                    loss_color = Colors.RED
                
                if stats['times']:
                    avg_time = sum(stats['times'][-10:]) / min(10, len(stats['times']))
                    return f"{loss_color}{loss_rate:.1f}%{Colors.RESET} (avg: {avg_time:.1f}ms)"
            return ""
        
        try:
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                # Extract IP address from first line
                if not ip_address:
                    import re
                    ip_match = re.search(r'\[?(\d+\.\d+\.\d+\.\d+)\]?', line)
                    if ip_match:
                        ip_address = ip_match.group(1)
                
                # Windows ping output parsing
                if is_windows:
                    # Reply from IP: bytes=32 time=XXms TTL=XX
                    if "Reply from" in line:
                        seq_num += 1
                        stats['sent'] += 1
                        
                        ip_match = re.search(r'Reply from (\d+\.\d+\.\d+\.\d+)', line)
                        time_match = re.search(r'time[=<](\d+)ms', line)
                        ttl_match = re.search(r'TTL=(\d+)', line)
                        
                        current_ip = ip_match.group(1) if ip_match else ip_address or "N/A"
                        time_val = int(time_match.group(1)) if time_match else None
                        ttl_val = int(ttl_match.group(1)) if ttl_match else None
                        
                        if time_val is not None:
                            stats['received'] += 1
                            stats['times'].append(time_val)
                            if ttl_val:
                                stats['ttl_values'].append(ttl_val)
                            
                            # Color coding based on response time
                            if time_val < 50:
                                color = Colors.GREEN
                                status = "Excellent"
                            elif time_val < 100:
                                color = Colors.CYAN
                                status = "Good"
                            elif time_val < 200:
                                color = Colors.YELLOW
                                status = "Fair"
                            else:
                                color = Colors.RED
                                status = "Slow"
                            
                            time_display = f"{time_val}ms"
                            ttl_display = str(ttl_val) if ttl_val else "N/A"
                            
                            realtime_stats = print_realtime_stats(stats, seq_num)
                            print(f"{color}{seq_num:<6} {current_ip:<16} {ttl_display:<6} {time_display:<10} {status:<12}{Colors.RESET} {realtime_stats}")
                        else:
                            stats['lost'] += 1
                            realtime_stats = print_realtime_stats(stats, seq_num)
                            print(f"{Colors.RED}{seq_num:<6} {'N/A':<16} {'N/A':<6} {'---':<10} {'No Response':<12}{Colors.RESET} {realtime_stats}")
                    
                    # Request timed out
                    elif "Request timed out" in line:
                        seq_num += 1
                        stats['sent'] += 1
                        stats['lost'] += 1
                        realtime_stats = print_realtime_stats(stats, seq_num)
                        print(f"{Colors.YELLOW}{seq_num:<6} {'N/A':<16} {'N/A':<6} {'---':<10} {'Timeout':<12}{Colors.RESET} {realtime_stats}")
                    
                    # Destination unreachable
                    elif "Destination host unreachable" in line or "Destination net unreachable" in line:
                        seq_num += 1
                        stats['sent'] += 1
                        stats['lost'] += 1
                        stats['errors'].append("Unreachable")
                        realtime_stats = print_realtime_stats(stats, seq_num)
                        print(f"{Colors.RED}{seq_num:<6} {'N/A':<16} {'N/A':<6} {'---':<10} {'Unreachable':<12}{Colors.RESET} {realtime_stats}")
                
                # Linux/Mac ping output parsing
                else:
                    # 64 bytes from IP: icmp_seq=1 ttl=XX time=XX.X ms
                    if "bytes from" in line and "icmp_seq" in line:
                        seq_match = re.search(r'icmp_seq=(\d+)', line)
                        if seq_match:
                            seq_num = int(seq_match.group(1))
                        else:
                            seq_num += 1
                        
                        stats['sent'] = max(stats['sent'], seq_num)
                        
                        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                        time_match = re.search(r'time[=<](\d+\.?\d*)\s*ms', line)
                        ttl_match = re.search(r'ttl=(\d+)', line)
                        
                        current_ip = ip_match.group(1) if ip_match else ip_address or "N/A"
                        time_val = float(time_match.group(1)) if time_match else None
                        ttl_val = int(ttl_match.group(1)) if ttl_match else None
                        
                        if time_val is not None:
                            stats['received'] += 1
                            stats['times'].append(time_val)
                            if ttl_val:
                                stats['ttl_values'].append(ttl_val)
                            
                            # Color coding based on response time
                            if time_val < 50:
                                color = Colors.GREEN
                                status = "Excellent"
                            elif time_val < 100:
                                color = Colors.CYAN
                                status = "Good"
                            elif time_val < 200:
                                color = Colors.YELLOW
                                status = "Fair"
                            else:
                                color = Colors.RED
                                status = "Slow"
                            
                            time_display = f"{time_val:.1f}ms"
                            ttl_display = str(ttl_val) if ttl_val else "N/A"
                            
                            realtime_stats = print_realtime_stats(stats, seq_num)
                            print(f"{color}{seq_num:<6} {current_ip:<16} {ttl_display:<6} {time_display:<10} {status:<12}{Colors.RESET} {realtime_stats}")
                        else:
                            stats['lost'] += 1
                            realtime_stats = print_realtime_stats(stats, seq_num)
                            print(f"{Colors.RED}{seq_num:<6} {'N/A':<16} {'N/A':<6} {'---':<10} {'No Response':<12}{Colors.RESET} {realtime_stats}")
                    
                    # Timeout (Linux shows nothing for timeout, but some versions show this)
                    elif "no answer yet" in line.lower():
                        pass  # Handled by missing sequence
                    
                    # Unreachable
                    elif "Destination Host Unreachable" in line or "Destination Net Unreachable" in line:
                        seq_num += 1
                        stats['sent'] += 1
                        stats['lost'] += 1
                        stats['errors'].append("Unreachable")
                        realtime_stats = print_realtime_stats(stats, seq_num)
                        print(f"{Colors.RED}{seq_num:<6} {'N/A':<16} {'N/A':<6} {'---':<10} {'Unreachable':<12}{Colors.RESET} {realtime_stats}")
                
                # Stop if we've reached the requested count (non-continuous mode)
                if not continuous_mode and stats['sent'] >= count:
                    process.terminate()
                    break
                    
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Ping interrupted by user.{Colors.RESET}")
            process.terminate()
        
        process.wait()
        
        # Calculate final statistics
        if stats['sent'] == 0:
            stats['sent'] = seq_num
        
        stats['lost'] = stats['sent'] - stats['received']
        
        # Print final statistics
        elapsed_time = time.time() - stats['start_time']
        
        print(f"\n{Colors.BOLD}{'='*75}{Colors.RESET}")
        print(f"{Colors.BOLD}Ping Statistics for {target}:{Colors.RESET}")
        print("-" * 75)
        
        if ip_address:
            print(f"{Colors.BOLD}Resolved IP:{Colors.RESET} {ip_address}")
        
        print(f"{Colors.BOLD}Duration:{Colors.RESET} {elapsed_time:.1f} seconds")
        
        # Packet statistics with color
        sent = stats['sent']
        received = stats['received']
        lost = stats['lost']
        loss_rate = (lost / sent * 100) if sent > 0 else 0
        
        if loss_rate == 0:
            loss_color = Colors.GREEN
            loss_status = "Perfect"
        elif loss_rate < 10:
            loss_color = Colors.CYAN
            loss_status = "Good"
        elif loss_rate < 25:
            loss_color = Colors.YELLOW
            loss_status = "Fair"
        elif loss_rate < 50:
            loss_color = Colors.RED
            loss_status = "Poor"
        else:
            loss_color = Colors.RED
            loss_status = "Critical"
        
        print(f"{Colors.BOLD}Packets:{Colors.RESET} Sent = {sent}, Received = {Colors.GREEN}{received}{Colors.RESET}, Lost = {Colors.RED}{lost}{Colors.RESET}")
        print(f"{Colors.BOLD}Loss Rate:{Colors.RESET} {loss_color}{loss_rate:.1f}% ({loss_status}){Colors.RESET}")
        
        # Round trip time statistics
        if stats['times']:
            min_time = min(stats['times'])
            max_time = max(stats['times'])
            avg_time = sum(stats['times']) / len(stats['times'])
            
            # Color for RTT
            if avg_time < 50:
                rtt_color = Colors.GREEN
            elif avg_time < 100:
                rtt_color = Colors.CYAN
            elif avg_time < 200:
                rtt_color = Colors.YELLOW
            else:
                rtt_color = Colors.RED
            
            print(f"\n{Colors.BOLD}Round Trip Time (RTT):{Colors.RESET}")
            print(f"  Min: {Colors.GREEN}{min_time:.1f}ms{Colors.RESET}")
            print(f"  Avg: {rtt_color}{avg_time:.1f}ms{Colors.RESET}")
            print(f"  Max: {Colors.RED}{max_time:.1f}ms{Colors.RESET}")
            
            # Jitter calculation
            if len(stats['times']) > 1:
                import math
                variance = sum((t - avg_time) ** 2 for t in stats['times']) / len(stats['times'])
                jitter = math.sqrt(variance)
                
                if jitter < 10:
                    jitter_color = Colors.GREEN
                elif jitter < 30:
                    jitter_color = Colors.YELLOW
                else:
                    jitter_color = Colors.RED
                
                print(f"  Jitter: {jitter_color}{jitter:.2f}ms{Colors.RESET}")
            
            # Show last 10 pings average
            if len(stats['times']) >= 10:
                last_10_avg = sum(stats['times'][-10:]) / 10
                first_10_avg = sum(stats['times'][:10]) / 10 if len(stats['times']) >= 10 else avg_time
                
                if last_10_avg < first_10_avg * 0.9:
                    trend = f"{Colors.GREEN}↓ Improving{Colors.RESET}"
                elif last_10_avg > first_10_avg * 1.1:
                    trend = f"{Colors.RED}↑ Degrading{Colors.RESET}"
                else:
                    trend = f"{Colors.CYAN}→ Stable{Colors.RESET}"
                
                print(f"  Last 10 Avg: {last_10_avg:.1f}ms {trend}")
        
        # TTL statistics (helps identify OS)
        if stats['ttl_values']:
            avg_ttl = sum(stats['ttl_values']) / len(stats['ttl_values'])
            print(f"\n{Colors.BOLD}Average TTL:{Colors.RESET} {avg_ttl:.0f}")
            
            # Guess OS based on TTL
            if 60 <= avg_ttl <= 64:
                os_guess = "Linux/Unix"
            elif 120 <= avg_ttl <= 128:
                os_guess = "Windows"
            elif 250 <= avg_ttl <= 255:
                os_guess = "Solaris/Cisco"
            else:
                os_guess = "Unknown"
            
            print(f"{Colors.BOLD}OS Guess:{Colors.RESET} {Colors.CYAN}{os_guess}{Colors.RESET}")
        
        # Overall status
        print(f"\n{Colors.BOLD}{'─'*75}{Colors.RESET}")
        
        if continuous_mode:
            print(f"{Colors.CYAN}📊 Continuous ping session ended.{Colors.RESET}")
            print(f"{Colors.CYAN}   Total pings: {sent} over {elapsed_time:.1f}s{Colors.RESET}")
        
        if loss_rate == 0 and avg_time < 100:
            print(f"{Colors.GREEN}✅ Target is fully reachable with excellent performance.{Colors.RESET}")
        elif loss_rate < 10:
            print(f"{Colors.CYAN}✓ Target is reachable with good performance.{Colors.RESET}")
        elif loss_rate < 50:
            print(f"{Colors.YELLOW}⚠ Target has connectivity issues (high packet loss).{Colors.RESET}")
        elif loss_rate == 100:
            if "Unreachable" in str(stats['errors']):
                print(f"{Colors.RED}❌ Target is unreachable (Network/Host down).{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}⚠ Target is not responding to ICMP (firewall may be blocking ping).{Colors.RESET}")
                print(f"{Colors.CYAN}💡 Try TCP Handshake test (Option 4) to check real connectivity.{Colors.RESET}")
        else:
            print(f"{Colors.RED}❌ Target has severe connectivity problems.{Colors.RESET}")
        
        print(f"{Colors.BOLD}{'─'*75}{Colors.RESET}")
    
    except KeyboardInterrupt:
        if process:
            process.terminate()
            process.wait()
        print(f"\n{Colors.YELLOW}[!] Ping interrupted by user.{Colors.RESET}")
    except FileNotFoundError:
        print(f"{Colors.RED}[-] Ping command not found on this system.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error during ping: {e}{Colors.RESET}")

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

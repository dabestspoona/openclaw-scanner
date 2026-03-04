#!/usr/bin/env python3
"""
OpenClaw Network Scanner
Detects rogue OpenClaw instances on the network by scanning for:
- TCP ports: 18789 (WebSocket Gateway), 18793 (Canvas/A2UI), 9090 (Service mode)
- UDP port: 5353 (mDNS broadcasts)
"""

import socket
import struct
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import sys
import time

# OpenClaw ports to scan
OPENCLAW_TCP_PORTS = [18789, 18793, 9090]
OPENCLAW_MDNS_PORT = 5353
TIMEOUT = 2  # seconds

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def scan_tcp_port(host, port, timeout=TIMEOUT):
    """
    Scan a single TCP port on a host
    Returns tuple: (is_open, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            # Port is open, try to grab banner
            banner = None
            try:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
            sock.close()
            return (True, banner)

        sock.close()
        return (False, None)
    except socket.error:
        return (False, None)

def scan_host(host, ports=OPENCLAW_TCP_PORTS):
    """
    Scan a single host for OpenClaw ports
    Returns list of open ports with details
    """
    open_ports = []
    for port in ports:
        is_open, banner = scan_tcp_port(host, port)
        if is_open:
            port_info = {
                'port': port,
                'banner': banner,
                'service': get_openclaw_service_name(port)
            }
            open_ports.append(port_info)

    return host, open_ports

def get_openclaw_service_name(port):
    """Return the OpenClaw service name for a given port"""
    service_map = {
        18789: "WebSocket Gateway",
        18793: "Canvas/A2UI Host",
        9090: "Service Mode"
    }
    return service_map.get(port, "Unknown")

def scan_network(network, max_workers=50):
    """
    Scan an entire network range for OpenClaw instances
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"{Colors.RED}Error: Invalid network address: {e}{Colors.RESET}")
        return []

    hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
    total_hosts = len(hosts)

    print(f"{Colors.BLUE}[*] Scanning {total_hosts} hosts in {network}...{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Looking for OpenClaw ports: {OPENCLAW_TCP_PORTS}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] Timeout: {TIMEOUT}s per port{Colors.RESET}\n")

    detected_instances = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(scan_host, str(host)): str(host) for host in hosts}

        for future in as_completed(future_to_host):
            scanned += 1
            host, open_ports = future.result()

            if open_ports:
                detected_instances.append((host, open_ports))
                print(f"{Colors.RED}{Colors.BOLD}[!] OpenClaw DETECTED on {host}:{Colors.RESET}")
                for port_info in open_ports:
                    print(f"    {Colors.YELLOW}Port {port_info['port']}/tcp OPEN - {port_info['service']}{Colors.RESET}")
                    if port_info['banner']:
                        banner_preview = port_info['banner'][:100].replace('\n', ' ')
                        print(f"        Banner: {banner_preview}")
                print()

            # Progress indicator
            if scanned % 10 == 0 or scanned == total_hosts:
                print(f"{Colors.BLUE}[*] Progress: {scanned}/{total_hosts} hosts scanned{Colors.RESET}", end='\r')

    print()  # New line after progress
    return detected_instances

def listen_mdns(duration=10):
    """
    Listen for mDNS broadcasts on port 5353 to discover OpenClaw instances
    """
    print(f"{Colors.BLUE}[*] Listening for mDNS broadcasts on port {OPENCLAW_MDNS_PORT} for {duration} seconds...{Colors.RESET}\n")

    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind to mDNS port
        sock.bind(('', OPENCLAW_MDNS_PORT))

        # Join mDNS multicast group
        mreq = struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(duration)

        discovered = set()
        start_time = time.time()

        while time.time() - start_time < duration:
            try:
                data, addr = sock.recvfrom(1024)
                if 'openclaw' in data.decode('utf-8', errors='ignore').lower():
                    if addr[0] not in discovered:
                        discovered.add(addr[0])
                        print(f"{Colors.RED}{Colors.BOLD}[!] OpenClaw mDNS broadcast detected from {addr[0]}{Colors.RESET}")
            except socket.timeout:
                break
            except Exception as e:
                continue

        sock.close()

        if not discovered:
            print(f"{Colors.GREEN}[+] No OpenClaw mDNS broadcasts detected{Colors.RESET}\n")

        return list(discovered)

    except PermissionError:
        print(f"{Colors.YELLOW}[!] Warning: Need root/admin privileges to listen on port {OPENCLAW_MDNS_PORT}{Colors.RESET}")
        print(f"{Colors.YELLOW}    Run with sudo/administrator to enable mDNS detection{Colors.RESET}\n")
        return []
    except Exception as e:
        print(f"{Colors.YELLOW}[!] mDNS listening error: {e}{Colors.RESET}\n")
        return []

def print_summary(tcp_instances, mdns_hosts):
    """Print summary of scan results"""
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}SCAN SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}\n")

    if tcp_instances or mdns_hosts:
        print(f"{Colors.RED}{Colors.BOLD}[!] ALERT: Rogue OpenClaw instances detected!{Colors.RESET}\n")

        if tcp_instances:
            print(f"{Colors.YELLOW}TCP Port Scan Results:{Colors.RESET}")
            for host, ports in tcp_instances:
                port_list = [str(p['port']) for p in ports]
                print(f"  • {host} - Ports: {', '.join(port_list)}")
            print()

        if mdns_hosts:
            print(f"{Colors.YELLOW}mDNS Discovery Results:{Colors.RESET}")
            for host in mdns_hosts:
                print(f"  • {host}")
            print()

        print(f"{Colors.RED}Total rogue instances found: {len(set([h for h, _ in tcp_instances] + mdns_hosts))}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}[+] No OpenClaw instances detected on the network{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}\n")

def main():
    parser = argparse.ArgumentParser(
        description='OpenClaw Network Scanner - Detect rogue OpenClaw instances',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single host
  python openclaw_scanner.py -t 192.168.1.100

  # Scan a network range
  python openclaw_scanner.py -t 192.168.1.0/24

  # Scan multiple targets
  python openclaw_scanner.py -t 192.168.1.0/24 -t 10.0.0.50

  # Listen for mDNS only
  python openclaw_scanner.py --mdns-only

  # Full scan with mDNS (requires root/sudo)
  sudo python openclaw_scanner.py -t 192.168.1.0/24 --mdns
        """
    )

    parser.add_argument('-t', '--target', action='append', dest='targets',
                        help='Target IP address or network (CIDR notation). Can be specified multiple times.')
    parser.add_argument('--mdns', action='store_true',
                        help='Also listen for mDNS broadcasts (requires root/admin)')
    parser.add_argument('--mdns-only', action='store_true',
                        help='Only listen for mDNS broadcasts, skip port scanning')
    parser.add_argument('--mdns-duration', type=int, default=10,
                        help='Duration to listen for mDNS in seconds (default: 10)')
    parser.add_argument('--timeout', type=int, default=2,
                        help='Timeout per port in seconds (default: 2)')
    parser.add_argument('--threads', type=int, default=50,
                        help='Number of concurrent threads (default: 50)')

    args = parser.parse_args()

    if not args.targets and not args.mdns_only:
        parser.print_help()
        sys.exit(1)

    global TIMEOUT
    TIMEOUT = args.timeout

    print(f"\n{Colors.BOLD}{Colors.BLUE}OpenClaw Network Scanner{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")

    tcp_instances = []
    mdns_hosts = []

    # mDNS-only mode
    if args.mdns_only:
        mdns_hosts = listen_mdns(args.mdns_duration)
    else:
        # TCP port scanning
        for target in args.targets:
            instances = scan_network(target, max_workers=args.threads)
            tcp_instances.extend(instances)

        # Optional mDNS listening
        if args.mdns:
            mdns_hosts = listen_mdns(args.mdns_duration)

    # Print summary
    print_summary(tcp_instances, mdns_hosts)

if __name__ == '__main__':
    main()

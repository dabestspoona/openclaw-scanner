# OpenClaw Network Scanner

A Python-based network security tool to detect rogue OpenClaw instances on your network.

## Features

- **TCP Port Scanning**: Scans for OpenClaw services on ports 18789, 18793, and 9090
- **Service Identification**: Identifies specific OpenClaw services (WebSocket Gateway, Canvas/A2UI, Service Mode)
- **Banner Grabbing**: Captures service banners for verification
- **mDNS Discovery**: Listens for OpenClaw mDNS broadcasts on UDP port 5353
- **Network Range Scanning**: Supports CIDR notation for scanning entire subnets
- **Concurrent Scanning**: Multi-threaded for fast network sweeps
- **Color-coded Output**: Easy-to-read results with status indicators

## Requirements

- Python 3.6+
- No external dependencies (uses standard library only)

## Usage

### Basic Scanning

Scan a single host:
```bash
python openclaw_scanner.py -t 192.168.1.100
```

Scan a network range:
```bash
python openclaw_scanner.py -t 192.168.1.0/24
```

Scan multiple targets:
```bash
python openclaw_scanner.py -t 192.168.1.0/24 -t 10.0.0.0/24 -t 172.16.5.50
```

### mDNS Discovery

Listen for mDNS broadcasts only (requires root/sudo):
```bash
sudo python openclaw_scanner.py --mdns-only
```

Combine port scanning with mDNS detection:
```bash
sudo python openclaw_scanner.py -t 192.168.1.0/24 --mdns
```

### Advanced Options

```bash
# Adjust timeout per port (default: 2 seconds)
python openclaw_scanner.py -t 192.168.1.0/24 --timeout 5

# Increase concurrent threads (default: 50)
python openclaw_scanner.py -t 192.168.1.0/24 --threads 100

# Listen for mDNS for 30 seconds
sudo python openclaw_scanner.py --mdns-only --mdns-duration 30
```

### Help

```bash
python openclaw_scanner.py --help
```

## OpenClaw Ports

The scanner detects the following OpenClaw ports:

- **18789 (TCP)**: WebSocket Gateway - Primary port for AI agent and client connections
- **18793 (TCP)**: Canvas/A2UI Host - Browser-based functionality
- **9090 (TCP)**: Service Mode - Docker deployments
- **5353 (UDP)**: mDNS - Local network discovery broadcasts

## Output

The scanner provides:
- Real-time detection alerts for discovered instances
- Port-specific service identification
- Service banners (when available)
- Comprehensive summary report
- Color-coded status indicators (requires terminal with ANSI color support)

## Permissions

- Standard TCP port scanning works without special privileges
- mDNS listening (UDP 5353) requires root/administrator privileges:
  - Linux/macOS: Use `sudo`
  - Windows: Run as Administrator

## Example Output

```
OpenClaw Network Scanner
============================================================

[*] Scanning 254 hosts in 192.168.1.0/24...
[*] Looking for OpenClaw ports: [18789, 18793, 9090]
[*] Timeout: 2s per port

[!] OpenClaw DETECTED on 192.168.1.105:
    Port 18789/tcp OPEN - WebSocket Gateway
    Port 18793/tcp OPEN - Canvas/A2UI Host

[*] Progress: 254/254 hosts scanned

============================================================
SCAN SUMMARY - 2026-02-24 10:30:00
============================================================

[!] ALERT: Rogue OpenClaw instances detected!

TCP Port Scan Results:
  • 192.168.1.105 - Ports: 18789, 18793

Total rogue instances found: 1

============================================================
```

## Security Considerations

- Use this tool only on networks you own or have authorization to scan
- Unauthorized network scanning may violate laws and policies
- Consider rate limiting when scanning large networks
- Some firewalls may detect and block scanning activity

## License

This tool is provided for authorized security assessment and network administration purposes only.

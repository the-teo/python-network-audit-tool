import socket
from typing import List, Dict, Optional

# Minimal mapping of common TCP ports to likely services
COMMON_PORT_SERVICES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "rpcbind",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTPS",
    514: "syslog",
    587: "SMTP-submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt",
}


def grab_banner(ip: str, port: int, timeout: float = 1.0, recv_size: int = 1024) -> Optional[str]:
    """Attempt to grab a TCP banner from a service.

    Returns the raw banner as a decoded string, or None on failure.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Some services send banners immediately; try to read first
            try:
                data = s.recv(recv_size)
                if data:
                    try:
                        return data.decode(errors="replace").strip()
                    except Exception:
                        return repr(data)
            except socket.timeout:
                # No banner received immediately; fallthrough
                pass

            # Try small protocol-specific probes for common services
            probe = None
            if port in (80, 8080, 443):
                probe = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode()
            elif port == 22:
                # SSH typically sends banner; if not, wait briefly
                pass
            elif port == 25:
                # SMTP will send banner; if not, ask for it
                probe = b"EHLO example.com\r\n"

            if probe:
                try:
                    s.sendall(probe)
                    data = s.recv(recv_size)
                    if data:
                        return data.decode(errors="replace").strip()
                except Exception:
                    return None

    except Exception:
        return None

    return None


def detect_services(ip: str, open_ports: List[int], timeout: float = 1.0) -> Dict[int, Dict[str, Optional[str]]]:
    """Given an IP and a list of open ports, return detected service info.

    Returns a dict keyed by port with values like:
      {"service": <likely service name>, "banner": <banner or None>}
    """
    results: Dict[int, Dict[str, Optional[str]]] = {}
    for port in sorted(open_ports):
        service = COMMON_PORT_SERVICES.get(port, "unknown")
        banner = grab_banner(ip, port, timeout=timeout)
        results[port] = {"service": service, "banner": banner}

    return results


if __name__ == "__main__":
    # Minimal manual test when run directly
    target = "127.0.0.1"
    sample_ports = [22, 80, 443, 8080]
    print(detect_services(target, sample_ports))

import argparse
from typing import List

from scanner.port_scanner import scan_ports
from scanner.service_detector import detect_services
from scanner.report import generate_text_report, generate_json_report, save_report
import os


def parse_ports(port_str: str) -> List[int]:
    """Parse a port specification like "22,80,8000-8010" into a list of ints."""
    ports = set()
    if not port_str:
        return []
    parts = port_str.split(",")
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a_i = int(a)
                b_i = int(b)
                if a_i > b_i:
                    a_i, b_i = b_i, a_i
                for v in range(a_i, b_i + 1):
                    ports.add(v)
            except ValueError:
                continue
        else:
            try:
                ports.add(int(p))
            except ValueError:
                continue

    return sorted(p for p in ports if 0 < p < 65536)


def default_ports() -> List[int]:
    # Top ~100 TCP ports (simple approach: 1-100)
    return list(range(1, 101))


def main():
    parser = argparse.ArgumentParser(description="Simple network audit scanner")
    parser.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    parser.add_argument(
        "--ports",
        "-p",
        help="Comma-separated ports and ranges, e.g. 22,80,8000-8010. If omitted, uses common ports.",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--output", "-o", help="Path to save report file")
    parser.add_argument(
        "--format",
        choices=("txt", "json"),
        default=None,
        help="Report format when saving. If omitted, inferred from output filename extension or defaults to txt.",
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports) if args.ports else default_ports()
    print(f"Scanning {args.target} on {len(ports)} ports (timeout={args.timeout}s)")
    open_ports = scan_ports(args.target, ports, timeout=args.timeout)
    services = detect_services(args.target, open_ports, timeout=args.timeout)
    # Decide output format
    out_format = args.format
    if out_format is None and args.output:
        _, ext = os.path.splitext(args.output)
        if ext.lower() == ".json":
            out_format = "json"
        else:
            out_format = "txt"

    # Generate and print text report to stdout
    text_report = generate_text_report(args.target, open_ports, services)
    print(text_report)

    if args.output:
        if out_format == "json":
            content = generate_json_report(args.target, open_ports, services)
        else:
            content = text_report
        save_report(args.output, content)
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()

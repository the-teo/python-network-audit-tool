from typing import Dict, List
import json


def generate_text_report(target: str, open_ports: List[int], services: Dict[int, Dict]) -> str:
    """Generate a plain-text report for scan results.

    Args:
        target: target IP or hostname
        open_ports: list of open ports
        services: mapping from port -> {"service": name, "banner": banner}

    Returns:
        A multi-line string report.
    """
    lines = []
    lines.append(f"Scan report for {target}")
    lines.append("=" * (len(lines[0])))
    lines.append("")

    if not open_ports:
        lines.append("No open TCP ports detected (in requested set).")
        return "\n".join(lines)

    lines.append("Open ports:")
    for port in sorted(open_ports):
        info = services.get(port, {})
        svc = info.get("service", "unknown")
        banner = info.get("banner")
        lines.append(f" - {port}/tcp: {svc}")
        if banner:
            # Keep banner to a reasonable size
            excerpt = banner.replace("\r", "\\r").replace("\n", "\\n")
            if len(excerpt) > 400:
                excerpt = excerpt[:400] + "..."
            lines.append(f"     banner: {excerpt}")

    return "\n".join(lines)


def save_report(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def generate_json_report(target: str, open_ports: List[int], services: Dict[int, Dict]) -> str:
    """Return a JSON string representing the scan results."""
    payload = {
        "target": target,
        "open_ports": sorted(open_ports),
        "services": {
            str(port): {"service": info.get("service"), "banner": info.get("banner")}
            for port, info in services.items()
        },
    }
    return json.dumps(payload, indent=2)

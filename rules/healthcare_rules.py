import ipaddress
from typing import Optional, Dict, Any

# Helper
def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not addr.is_private
    except Exception:
        return False

def _mk(alert_type: str, severity: str, msg: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    d = {"alert_type": alert_type, "severity": severity, "msg": msg}
    if extra:
        d.update(extra)
    return d

# -------------------------
# Core healthcare rules
# -------------------------

def rule_device_to_internet(row, ctx) -> Optional[Dict[str, Any]]:
    """Medical device should not directly talk to public internet."""
    src = row["src_ip"]
    dst = row["dst_ip"]
    if src in ctx["device_ips"] and is_public_ip(dst):
        return _mk(
            "DEVICE_TO_INTERNET",
            "high",
            "Medical device communicating with public internet",
            {"risk": "Possible malware/C2 or data exfiltration"},
        )
    return None

def rule_unsafe_protocols(row, ctx) -> Optional[Dict[str, Any]]:
    """Telnet/FTP/SMB usage is usually unacceptable for medical devices."""
    src = row["src_ip"]
    dport = int(row.get("dst_port", 0) or 0)
    UNSAFE = {21, 23, 445}
    if src in ctx["device_ips"] and dport in UNSAFE:
        return _mk(
            "UNSAFE_PROTOCOL",
            "high",
            "Unsafe legacy protocol used by medical device",
            {"dst_port": dport},
        )
    return None

def rule_unexpected_port(row, ctx) -> Optional[Dict[str, Any]]:
    """Device uses a port not in allowlist."""
    src = row["src_ip"]
    dst = row["dst_ip"]
    dport = int(row.get("dst_port", 0) or 0)

    involved = (src in ctx["device_ips"]) or (dst in ctx["device_ips"])
    if not involved:
        return None

    if dport and dport not in ctx["allowed_ports"]:
        return _mk(
            "UNEXPECTED_PORT",
            "medium",
            "Traffic to destination port not in allowlist",
            {"dst_port": dport},
        )
    return None

def rule_unexpected_endpoint(row, ctx) -> Optional[Dict[str, Any]]:
    """Device talks to an endpoint not in allowlist."""
    src = row["src_ip"]
    dst = row["dst_ip"]

    if src in ctx["device_ips"] and dst not in ctx["allowed_endpoints"]:
        return _mk(
            "UNEXPECTED_ENDPOINT",
            "high",
            "Known device sent traffic to non-allowlisted endpoint",
            {"device": src, "dst": dst},
        )
    return None

def rule_port_scan_fanout(row, ctx) -> Optional[Dict[str, Any]]:
    """High fanout/port fanout from a device is scan-like behavior."""
    src = row["src_ip"]
    if src not in ctx["device_ips"]:
        return None

    uniq_ports = int(row.get("unique_dst_port_count", 0) or 0)
    uniq_dsts = int(row.get("unique_dst_count", 0) or 0)

    if uniq_ports >= ctx.get("scan_port_threshold", 15) or uniq_dsts >= ctx.get("scan_dst_threshold", 15):
        return _mk(
            "POSSIBLE_SCAN_FANOUT",
            "high",
            "Device shows high destination/port fanout within window",
            {"unique_dst_count": uniq_dsts, "unique_dst_port_count": uniq_ports},
        )
    return None

def rule_large_transfer(row, ctx) -> Optional[Dict[str, Any]]:
    """Large egress from device can indicate exfiltration or misconfig."""
    src = row["src_ip"]
    if src not in ctx["device_ips"]:
        return None

    byte_count = int(row.get("byte_count", 0) or 0)
    threshold = int(ctx.get("exfil_bytes_threshold", 2_000_000))
    if byte_count >= threshold:
        return _mk(
            "DATA_EXFILTRATION_SUSPECTED",
            "high",
            "Unusually large data transfer from medical device",
            {"bytes": byte_count, "threshold": threshold},
        )
    return None

def rule_icmp_ping(row, ctx):
    src = row["src_ip"]
    dst = row["dst_ip"]
    proto = row.get("proto", "")

    involved = (src in ctx["device_ips"]) or (dst in ctx["device_ips"])
    if involved and proto == "ICMP":
        return _mk(
            "PING_DETECTED",
            "low",
            "ICMP (ping) traffic involving monitored device",
            {
                "note": "Ping can be normal for monitoring, but repeated bursts may indicate scanning."
            }
        )
    return None

# Export a ruleset (Snort-like)
HEALTHCARE_RULESET = [
    rule_icmp_ping,
    rule_device_to_internet,
    rule_unsafe_protocols,
    rule_unexpected_endpoint,
    rule_unexpected_port,
    rule_port_scan_fanout,
    rule_large_transfer,
]

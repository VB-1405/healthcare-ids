import argparse
import json
import os
import time
import signal
from collections import defaultdict, deque
from datetime import datetime

# Optional: real capture using scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

RUNNING = True


def ts():
    return datetime.now().strftime("%m/%d/%Y, %I:%M:%S %p")


def log(msg, log_path=None):
    line = f"[IDS] {msg}"
    print(line, flush=True)
    if log_path:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def safe_write_alert(alerts_path, alert_obj):
    os.makedirs(os.path.dirname(alerts_path) or ".", exist_ok=True)
    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert_obj) + "\n")


def parse_rules_yaml_simple(rules_path):
    """
    Minimal YAML parser for our simple format.
    Expected shape:
    rules:
      - id: ...
        enabled: true
        type: PING_SCAN
        ...
    """
    rules = []
    if not os.path.exists(rules_path):
        return rules
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            lines = [ln.rstrip("\n") for ln in f.readlines()]
    except Exception:
        return rules

    cur = None
    in_rules = False
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if s == "rules:":
            in_rules = True
            continue
        if not in_rules:
            continue

        if s.startswith("- "):
            if cur:
                rules.append(cur)
            cur = {}
            # handle "- id: something"
            rest = s[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                cur[k.strip()] = v.strip().strip('"').strip("'")
            continue

        if cur is None:
            continue

        if ":" in s:
            k, v = s.split(":", 1)
            k = k.strip()
            v = v.strip()
            # basic typing
            if v.lower() in ("true", "false"):
                cur[k] = (v.lower() == "true")
            else:
                try:
                    if "." in v:
                        cur[k] = float(v)
                    else:
                        cur[k] = int(v)
                except Exception:
                    cur[k] = v.strip('"').strip("'")

    if cur:
        rules.append(cur)

    # only enabled
    return [r for r in rules if r.get("enabled", True) is True]


class Cooldown:
    def __init__(self):
        self.last = {}

    def ok(self, key, cooldown_sec):
        now = time.time()
        last = self.last.get(key, 0)
        if now - last >= cooldown_sec:
            self.last[key] = now
            return True
        return False


def build_alert(severity, atype, flow, details):
    return {
        "time": ts(),
        "severity": severity,
        "type": atype,
        "flow": flow,
        "details": details
    }


def handle_sigterm(signum, frame):
    global RUNNING
    RUNNING = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--iface", default="wlan0")
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--ping-threshold", type=int, default=5)
    parser.add_argument("--cooldown", type=int, default=60)
    parser.add_argument("--emulate", action="store_true", help="Generate synthetic events for UI testing")
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)

    cfg = load_json(args.config)
    rules = parse_rules_yaml_simple(args.rules)

    log(f"Starting capture on interface='{args.iface}', window={args.window}s", args.log)
    log(f"Alerts file: {args.alerts}", args.log)
    log(f"YAML rules: {args.rules} (loaded {len(rules)} rules)", args.log)

    # Apply rule overrides if present, else defaults from args for ping
    ping_rule = None
    port_sweep_rule = None
    for r in rules:
        if r.get("type") == "PING_SCAN":
            ping_rule = r
        if r.get("type") == "PORT_SWEEP":
            port_sweep_rule = r

    ping_threshold = int(ping_rule.get("ping_threshold", args.ping_threshold)) if ping_rule else args.ping_threshold
    ping_window = int(ping_rule.get("window_sec", args.window)) if ping_rule else args.window
    ping_cd = int(ping_rule.get("cooldown_sec", args.cooldown)) if ping_rule else args.cooldown
    ping_sev = (ping_rule.get("severity", "low") if ping_rule else "low")

    ps_threshold = int(port_sweep_rule.get("unique_dst_port_threshold", 25)) if port_sweep_rule else 25
    ps_window = int(port_sweep_rule.get("window_sec", args.window)) if port_sweep_rule else args.window
    ps_cd = int(port_sweep_rule.get("cooldown_sec", args.cooldown)) if port_sweep_rule else args.cooldown
    ps_sev = (port_sweep_rule.get("severity", "high") if port_sweep_rule else "high")

    # Sliding windows
    icmp_by_src = defaultdict(lambda: deque())          # src -> timestamps
    ports_by_pair = defaultdict(lambda: defaultdict(lambda: deque()))  # src->dst->deque((t, dport))

    cd = Cooldown()

    def prune_deque(dq, window_sec):
        cutoff = time.time() - window_sec
        while dq and dq[0] < cutoff:
            dq.popleft()

    def prune_ports(dq, window_sec):
        cutoff = time.time() - window_sec
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def process_event(src, dst, proto, sport, dport, is_icmp=False):
        now = time.time()

        # --- PING_SCAN ---
        if is_icmp:
            dq = icmp_by_src[src]
            dq.append(now)
            prune_deque(dq, ping_window)

            if len(dq) >= ping_threshold:
                key = f"PING_SCAN:{src}->{dst}"
                if cd.ok(key, ping_cd):
                    flow = f"{src}:0 -> {dst}:0 (ICMP)"
                    alert = build_alert(
                        ping_sev,
                        "PING_SCAN",
                        flow,
                        {"msg": "ICMP ping scan detected", "count_in_window": len(dq), "window_sec": ping_window}
                    )
                    safe_write_alert(args.alerts, alert)
                    log(f"ALERT PING_SCAN src={src} dst={dst} count={len(dq)} window={ping_window}", args.log)

        # --- PORT_SWEEP ---
        if dport is not None and proto in ("TCP", "UDP"):
            dq2 = ports_by_pair[src][dst]
            dq2.append((now, int(dport)))
            prune_ports(dq2, ps_window)

            uniq = len(set([x[1] for x in dq2]))
            if uniq >= ps_threshold:
                key = f"PORT_SWEEP:{src}->{dst}"
                if cd.ok(key, ps_cd):
                    flow = f"{src} -> {dst} (SCAN)"
                    alert = build_alert(
                        ps_sev,
                        "PORT_SWEEP_SUSPECTED",
                        flow,
                        {"msg": "Possible port sweep (many destination ports in one window)",
                         "pkt_total": len(dq2),
                         "unique_dst_port_count": uniq}
                    )
                    safe_write_alert(args.alerts, alert)
                    log(f"ALERT PORT_SWEEP src={src} dst={dst} uniq_ports={uniq} window={ps_window}", args.log)

    if args.emulate:
        # Generate a clean ping scan example like your goal
        log("Emulation enabled: generating synthetic ICMP pings + port hits", args.log)
        src = "192.168.7.65"
        dst = "192.168.7.16"
        for _ in range(ping_threshold + 1):
            if not RUNNING:
                break
            process_event(src, dst, "ICMP", None, None, is_icmp=True)
            time.sleep(0.2)
        while RUNNING:
            time.sleep(1)
        log("Stopped.", args.log)
        return

    if not SCAPY_OK:
        log("ERROR: scapy not available. Install scapy or run with --emulate for UI testing.", args.log)
        return

    def on_packet(pkt):
        if not RUNNING:
            return

        try:
            if IP not in pkt:
                return

            src = pkt[IP].src
            dst = pkt[IP].dst

            # ICMP
            if ICMP in pkt:
                process_event(src, dst, "ICMP", None, None, is_icmp=True)
                return

            # TCP/UDP
            if TCP in pkt:
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                process_event(src, dst, "TCP", sport, dport, is_icmp=False)
                return

            if UDP in pkt:
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
                process_event(src, dst, "UDP", sport, dport, is_icmp=False)
                return

        except Exception:
            return

    # sniff loop
    while RUNNING:
        try:
            sniff(iface=args.iface, prn=on_packet, store=False, timeout=2)
        except Exception as e:
            log(f"Capture error: {e}", args.log)
            time.sleep(1)

    log("Signal received, stopping...", args.log)
    log("Stopped.", args.log)


if __name__ == "__main__":
    main()

import time
import json
import socket
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple, List

from scapy.all import sniff, IP, TCP, UDP, ICMP

import yaml
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from joblib import dump, load

from scapy.all import sniff, IP, TCP, UDP  # noqa: F401

from rules.healthcare_rules import HEALTHCARE_RULESET


# ----------------------------
# Alerting
# ----------------------------

@dataclass
class Alert:
    ts: float
    severity: str
    alert_type: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: str
    details: Dict[str, Any]


class AlertSink:
    def __init__(self, print_enabled: bool, jsonl_path: Optional[str], syslog_cfg: Dict[str, Any]):
        self.print_enabled = print_enabled
        self.jsonl_path = jsonl_path
        self.syslog_cfg = syslog_cfg or {}
        self._lock = threading.Lock()

    def emit(self, alert: Alert):
        payload = asdict(alert)

        if self.print_enabled:
            print(json.dumps(payload, indent=2))

        if self.jsonl_path:
            with self._lock:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload) + "\n")

        if self.syslog_cfg.get("enabled", False):
            self._send_syslog(payload)

    def _send_syslog(self, payload: Dict[str, Any]):
        host = self.syslog_cfg.get("host", "127.0.0.1")
        port = int(self.syslog_cfg.get("port", 514))
        msg = json.dumps(payload)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode("utf-8"), (host, port))
        except Exception as e:
            if self.print_enabled:
                print(f"[syslog error] {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass


# ----------------------------
# Feature extraction (windowed flows)
# ----------------------------

class FlowWindowAggregator:
    """
    Aggregates packet observations into fixed-time windows per (src_ip, dst_ip, proto, src_port, dst_port).
    Produces features suitable for anomaly detection + rule checks.
    """
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.window_start = time.time()
        self.counts = defaultdict(int)
        self.bytes_ = defaultdict(int)
        self.unique_dsts = defaultdict(set)
        self.unique_dst_ports = defaultdict(set)
        self.tcp_syn = defaultdict(int)
        self.tcp_rst = defaultdict(int)

    def _key(self, src_ip: str, dst_ip: str, proto: str, src_port: int, dst_port: int) -> Tuple[str, str, str, int, int]:
        return (src_ip, dst_ip, proto, int(src_port), int(dst_port))

    def observe(self, pkt):
        if IP not in pkt:
            return

        src = pkt[IP].src
        dst = pkt[IP].dst

        proto = "OTHER"
        sport = 0
        dport = 0

        if TCP in pkt:
            proto = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            # SYN = 0x02, RST = 0x04
            if flags & 0x02:
                self.tcp_syn[(src,)] += 1
            if flags & 0x04:
                self.tcp_rst[(src,)] += 1

        elif UDP in pkt:
            proto = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        
        elif ICMP in pkt:
            proto = "ICMP"
            sport = 0
            dport = 0

        k = self._key(src, dst, proto, sport, dport)
        self.counts[k] += 1
        self.bytes_[k] += len(pkt)

        self.unique_dsts[src].add(dst)
        self.unique_dst_ports[src].add(dport)

    def ready(self) -> bool:
        return (time.time() - self.window_start) >= self.window_seconds

    def flush(self) -> pd.DataFrame:
        now = time.time()
        rows = []

        for (src, dst, proto, sport, dport), c in list(self.counts.items()):
            b = self.bytes_[(src, dst, proto, sport, dport)]
            rows.append({
                "window_start": self.window_start,
                "window_end": now,
                "src_ip": src,
                "dst_ip": dst,
                "proto": proto,
                "src_port": int(sport),
                "dst_port": int(dport),
                "pkt_count": int(c),
                "byte_count": int(b),
                "avg_pkt_size": float(b / c) if c else 0.0,

                # src fanout / scanning-ish signals
                "unique_dst_count": int(len(self.unique_dsts.get(src, set()))),
                "unique_dst_port_count": int(len(self.unique_dst_ports.get(src, set()))),

                # tcp flag signals per src
                "tcp_syn_count_src": int(self.tcp_syn.get((src,), 0)),
                "tcp_rst_count_src": int(self.tcp_rst.get((src,), 0)),
            })

        # reset window
        self.window_start = time.time()
        self.counts.clear()
        self.bytes_.clear()
        self.unique_dsts.clear()
        self.unique_dst_ports.clear()
        self.tcp_syn.clear()
        self.tcp_rst.clear()

        return pd.DataFrame(rows)


# ----------------------------
# Rule engine (Snort-like ruleset loop)
# ----------------------------

class RuleEngine:
    def __init__(self, device_ips: List[str], allowed_ports: List[int], allowed_endpoints: List[str],
                 scan_port_threshold: int = 15, scan_dst_threshold: int = 15, exfil_bytes_threshold: int = 2_000_000):
        self.device_ips = set(device_ips)
        self.allowed_ports = set(int(p) for p in allowed_ports)
        self.allowed_endpoints = set(allowed_endpoints)

        self.ctx = {
            "device_ips": self.device_ips,
            "allowed_ports": self.allowed_ports,
            "allowed_endpoints": self.allowed_endpoints,
            "scan_port_threshold": int(scan_port_threshold),
            "scan_dst_threshold": int(scan_dst_threshold),
            "exfil_bytes_threshold": int(exfil_bytes_threshold),
        }

    def evaluate_row(self, row: pd.Series) -> Optional[Alert]:
        # Run each rule like a Snort ruleset; first match returns alert.
        for rule in HEALTHCARE_RULESET:
            spec = rule(row, self.ctx)
            if not spec:
                continue

            src = row["src_ip"]
            dst = row["dst_ip"]
            return Alert(
                ts=time.time(),
                severity=spec.get("severity", "medium"),
                alert_type=spec.get("alert_type", "RULE_MATCH"),
                src_ip=src,
                dst_ip=dst,
                src_port=int(row.get("src_port", 0)) if row.get("src_port", None) is not None else None,
                dst_port=int(row.get("dst_port", 0)) if row.get("dst_port", None) is not None else None,
                proto=str(row.get("proto", "OTHER")),
                details={
                    "msg": spec.get("msg", ""),
                    **{k: v for k, v in spec.items() if k not in {"severity", "alert_type", "msg"}}
                }
            )

        return None


# ----------------------------
# ML model wrapper (Isolation Forest)
# ----------------------------

class AnomalyModel:
    def __init__(self, path: str, contamination: float):
        self.path = path
        self.contamination = contamination
        self.model: Optional[IsolationForest] = None

    def load_if_exists(self) -> bool:
        try:
            self.model = load(self.path)
            return True
        except Exception:
            return False

    def train(self, df: pd.DataFrame):
        X = self._to_features(df)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=float(self.contamination),
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        dump(self.model, self.path)

    def score(self, df: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model not trained/loaded.")
        X = self._to_features(df)
        preds = self.model.predict(X)  # -1 anomaly, 1 normal
        scores = self.model.decision_function(X)
        return np.column_stack([preds, scores])

    @staticmethod
    def _to_features(df: pd.DataFrame) -> np.ndarray:
        cols = [
            "pkt_count", "byte_count", "avg_pkt_size",
            "unique_dst_count", "unique_dst_port_count",
            "tcp_syn_count_src", "tcp_rst_count_src",
            "dst_port",
        ]
        return df[cols].fillna(0.0).astype(float).to_numpy()


# ----------------------------
# Main IDS runtime
# ----------------------------

def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_ids(config_path: str = "config.yaml"):
    cfg = load_config(config_path)

    iface = cfg.get("interface", None)

    model_cfg = cfg.get("model", {})
    window_seconds = int(model_cfg.get("window_seconds", 30))
    min_train_windows = int(model_cfg.get("min_train_windows", 200))
    model_path = model_cfg.get("path", "./ids_isoforest.joblib")
    contamination = float(model_cfg.get("contamination", 0.02))

    devices = cfg.get("devices", [])
    device_ips = [d["ip"] for d in devices]

    rules = RuleEngine(
        device_ips=device_ips,
        allowed_ports=cfg.get("allowed_ports", []),
        allowed_endpoints=cfg.get("allowed_endpoints", []),
        scan_port_threshold=int(cfg.get("scan_port_threshold", 15)),
        scan_dst_threshold=int(cfg.get("scan_dst_threshold", 15)),
        exfil_bytes_threshold=int(cfg.get("exfil_bytes_threshold", 2_000_000)),
    )

    alerts_cfg = cfg.get("alerts", {})
    sink = AlertSink(
        print_enabled=bool(alerts_cfg.get("print", True)),
        jsonl_path=alerts_cfg.get("jsonl_path", None),
        syslog_cfg=alerts_cfg.get("syslog", {}),
    )

    aggregator = FlowWindowAggregator(window_seconds=window_seconds)

    model = AnomalyModel(path=model_path, contamination=contamination)
    has_model = model.load_if_exists()

    train_buffer = deque(maxlen=max(min_train_windows, 1000))

    def on_packet(pkt):
        aggregator.observe(pkt)

    print(f"[IDS] Starting capture on interface={iface!r}, window={window_seconds}s, model_loaded={has_model}")
    print("[IDS] NOTE: Run with appropriate privileges for packet capture.")

    while True:
        sniff(iface=iface, prn=on_packet, store=False, timeout=1)

        if aggregator.ready():
            df = aggregator.flush()
            if df.empty:
                continue

            # Rule-based alerts
            for _, row in df.iterrows():
                a = rules.evaluate_row(row)
                if a:
                    sink.emit(a)

            # ML training / scoring (optional)
            if model.model is None:
                train_buffer.append(df)
                if sum(len(x) for x in train_buffer) >= min_train_windows:
                    train_df = pd.concat(list(train_buffer), ignore_index=True)
                    train_df = train_df[
                        (train_df["src_ip"].isin(device_ips)) | (train_df["dst_ip"].isin(device_ips))
                    ]
                    if len(train_df) >= min_train_windows:
                        print(f"[IDS] Training model on {len(train_df)} rows...")
                        model.train(train_df)
                        print(f"[IDS] Model saved to {model_path}")
                continue

            scored = model.score(df)
            preds = scored[:, 0]
            scores = scored[:, 1]

            for i, (_, row) in enumerate(df.iterrows()):
                if int(preds[i]) == -1:
                    sink.emit(Alert(
                        ts=time.time(),
                        severity="medium",
                        alert_type="ANOMALY_DETECTED",
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        src_port=int(row.get("src_port", 0)),
                        dst_port=int(row.get("dst_port", 0)),
                        proto=str(row["proto"]),
                        details={
                            "msg": "Anomalous traffic pattern in window",
                            "model_score": float(scores[i]),
                            "features": {
                                "pkt_count": int(row["pkt_count"]),
                                "byte_count": int(row["byte_count"]),
                                "avg_pkt_size": float(row["avg_pkt_size"]),
                                "unique_dst_count": int(row["unique_dst_count"]),
                                "unique_dst_port_count": int(row["unique_dst_port_count"]),
                                "tcp_syn_count_src": int(row["tcp_syn_count_src"]),
                                "tcp_rst_count_src": int(row["tcp_rst_count_src"]),
                                "dst_port": int(row["dst_port"]),
                            }
                        },
                    ))


if __name__ == "__main__":
    run_ids("config.yaml")

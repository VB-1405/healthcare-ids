from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

@dataclass
class YamlRule:
    name: str
    severity: str
    when: Dict[str, Any]
    msg: str

class YamlRuleEngine:
    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.rules: List[YamlRule] = []
        self.load()

    def load(self) -> None:
        if not self.rules_path.exists():
            self.rules = []
            return
        data = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        raw_rules = data.get("rules", []) or []
        parsed = []
        for r in raw_rules:
            try:
                parsed.append(
                    YamlRule(
                        name=str(r["name"]),
                        severity=str(r.get("severity", "low")),
                        when=dict(r.get("when", {}) or {}),
                        msg=str(r.get("msg", "")),
                    )
                )
            except Exception:
                continue
        self.rules = parsed

    def evaluate(self, obs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        obs is your per-flow/per-window observation dict, like:
        {
          "proto": "TCP",
          "src_ip": "...",
          "dst_ip": "...",
          "src_port": 123,
          "dst_port": 2575,
          "pkt_count": 42,
          "byte_count": 10000,
          "unique_dst_count": 3,
          "unique_dst_port_count": 10,
          "payload_sample": "...."  (optional)
        }
        Returns list of alert dicts.
        """
        alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            if self._match(rule.when, obs):
                alerts.append(
                    {
                        "alert_type": rule.name,
                        "severity": rule.severity,
                        "details": {"msg": rule.msg, "rule": rule.name, "when": rule.when},
                    }
                )
        return alerts

    def _match(self, cond: Dict[str, Any], obs: Dict[str, Any]) -> bool:
        # --- protocol / ports ---
        proto = obs.get("proto")
        if "proto" in cond and str(cond["proto"]).upper() != str(proto).upper():
            return False

        dst_port = obs.get("dst_port")
        src_port = obs.get("src_port")

        if "dst_port" in cond and int(cond["dst_port"]) != int(dst_port or -1):
            return False
        if "src_port" in cond and int(cond["src_port"]) != int(src_port or -1):
            return False
        if "dst_port_in" in cond and int(dst_port or -1) not in [int(x) for x in cond["dst_port_in"]]:
            return False
        if "dst_port_not_in" in cond and int(dst_port or -1) in [int(x) for x in cond["dst_port_not_in"]]:
            return False

        # --- IP allow/deny patterns ---
        if "src_ip" in cond and str(cond["src_ip"]) != str(obs.get("src_ip")):
            return False
        if "dst_ip" in cond and str(cond["dst_ip"]) != str(obs.get("dst_ip")):
            return False

        # --- thresholds ---
        def gte(field: str, key: str) -> bool:
            if key not in cond:
                return True
            return float(obs.get(field, 0)) >= float(cond[key])

        if not gte("pkt_count", "pkt_count_gte"):
            return False
        if not gte("byte_count", "byte_count_gte"):
            return False
        if not gte("unique_dst_count", "unique_dst_count_gte"):
            return False
        if not gte("unique_dst_port_count", "unique_dst_port_count_gte"):
            return False

        # --- payload substring (optional) ---
        if "payload_contains" in cond:
            payload = obs.get("payload_sample") or ""
            if str(cond["payload_contains"]) not in payload:
                return False

        return True

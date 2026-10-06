import os
import glob
import yaml
from typing import List, Dict, Any, Optional

try:
    import sigma
    from sigma.collection import SigmaCollection
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


class SigmaEngine:
    """Sigma Rule Detection Engine supporting industry-standard YAML Sigma rules."""

    def __init__(self, rules_dir: str = "./rules"):
        self.rules_dir = rules_dir
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self):
        """Loads all YAML Sigma rules from rules directory."""
        self.rules = []
        if not os.path.exists(self.rules_dir):
            return

        rule_files = glob.glob(os.path.join(self.rules_dir, "*.yml")) + glob.glob(os.path.join(self.rules_dir, "*.yaml"))
        for filepath in rule_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, dict) and "detection" in content:
                        content["_filepath"] = filepath
                        self.rules.append(content)
            except Exception as e:
                print(f"[SigmaEngine] Error loading rule file {filepath}: {e}")

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates normalized security event against all loaded Sigma rules."""
        triggered_alerts = []

        for rule in self.rules:
            if self._matches_rule(rule, event):
                tags = rule.get("tags", [])
                mitre_tag = self._extract_mitre_tag(tags)

                alert = {
                    "rule_id": rule.get("id", "SIGMA-RULE"),
                    "rule_title": rule.get("title", "Sigma Detection Alert"),
                    "detection_type": "SIGMA",
                    "severity": rule.get("level", "medium").upper(),
                    "mitre_technique": mitre_tag,
                    "source_ip": event.get("source_ip", "0.0.0.0"),
                    "user": event.get("user", "unknown"),
                    "details": {
                        "rule_description": rule.get("description"),
                        "matched_log": event.get("raw_log"),
                        "url": event.get("url"),
                        "service": event.get("service")
                    }
                }
                triggered_alerts.append(alert)

        return triggered_alerts

    def _matches_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Core rule matching logic checking detection selections and keywords."""
        detection = rule.get("detection", {})
        
        # 1. Check Keyword-based matching
        if "keywords" in detection:
            keywords = detection["keywords"]
            if isinstance(keywords, list):
                raw_log = event.get("raw_log", "").lower()
                url = event.get("url", "").lower()
                for kw in keywords:
                    if kw.lower() in raw_log or kw.lower() in url:
                        return True

        # 2. Check Selection-based matching
        if "selection" in detection:
            selection = detection["selection"]
            if isinstance(selection, dict):
                match_all = True
                for key, expected in selection.items():
                    # Handle modifier keys (e.g. url|contains)
                    if "|" in key:
                        field_name, modifier = key.split("|", 1)
                        actual_val = str(event.get(field_name, "")).lower()
                        if modifier == "contains":
                            if isinstance(expected, list):
                                if not any(exp.lower() in actual_val for exp in expected):
                                    match_all = False
                            else:
                                if str(expected).lower() not in actual_val:
                                    match_all = False
                    else:
                        actual_val = event.get(key)
                        if isinstance(expected, list):
                            if actual_val not in expected:
                                match_all = False
                        else:
                            if actual_val != expected:
                                match_all = False
                
                if match_all:
                    return True

        return False

    def _extract_mitre_tag(self, tags: List[str]) -> str:
        """Extracts MITRE ATT&CK technique ID (e.g., T1110) from Sigma rule tags."""
        for tag in tags:
            if "attack.t" in tag.lower():
                parts = tag.lower().split("attack.")
                if len(parts) > 1:
                    return parts[1].upper()
        return "T1000"

import os
import sys
import yaml
import time
from typing import Dict, Any, List

from siem.storage.database import SIEMDatabase
from siem.ingestion.parser import LogParser
from siem.detection.sigma_engine import SigmaEngine
from siem.detection.ml_anomaly import MLAnomalyDetector
from siem.enrichment.threat_intel import ThreatIntelEnricher
from siem.soar.playbooks import SOARPlaybookEngine
from simulator.attack_simulator import AttackSimulator

class SIEMPipeline:
    """
    Main SIEM Sentinel Pipeline Orchestrator.
    Combines Log Ingestion -> Sigma Rules + ML Anomaly Detection -> Threat Intel -> SOAR Playbooks -> SQLite.
    """

    def __init__(self, config_path: str = "./config/settings.yaml"):
        self.config = self._load_config(config_path)
        
        # Initialize Core Engines
        db_path = self.config.get("siem", {}).get("db_path", "./data/siem_sentinel.db")
        cache_path = self.config.get("siem", {}).get("cache_db_path", "./data/threat_intel_cache.db")
        rules_dir = self.config.get("sigma", {}).get("rules_dir", "./rules")

        self.db = SIEMDatabase(db_path=db_path)
        self.sigma_engine = SigmaEngine(rules_dir=rules_dir)
        self.ml_engine = MLAnomalyDetector(contamination=self.config.get("ml_anomaly_detection", {}).get("contamination", 0.05))
        
        ti_cfg = self.config.get("threat_intelligence", {})
        redis_url = ti_cfg.get("cache", {}).get("redis_url") if ti_cfg.get("cache", {}).get("backend") == "redis" else None
        
        self.threat_intel = ThreatIntelEnricher(
            abuseipdb_key=ti_cfg.get("abuseipdb", {}).get("api_key"),
            virustotal_key=ti_cfg.get("virustotal", {}).get("api_key"),
            cache_db_path=cache_path,
            redis_url=redis_url
        )

        soar_cfg = self.config.get("soar_playbooks", {})
        self.soar = SOARPlaybookEngine(
            discord_webhook_url=soar_cfg.get("webhooks", {}).get("discord_url"),
            slack_webhook_url=soar_cfg.get("webhooks", {}).get("slack_url"),
            mitigation_script_path=soar_cfg.get("auto_block_ip", {}).get("mitigation_script_output", "./soar_mitigation.sh"),
            min_auto_block_severity=soar_cfg.get("auto_block_ip", {}).get("min_severity", "CRITICAL"),
            min_auto_block_abuse_score=soar_cfg.get("auto_block_ip", {}).get("min_abuse_score", 75)
        )

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                print(f"[SIEMPipeline] Warning: Failed loading config file {config_path}: {e}")
        return {}

    def process_log_line(self, raw_line: str) -> Dict[str, Any]:
        """Ingests and analyzes a single raw log line through the full pipeline."""
        # 1. Parse & Normalize
        event = LogParser.parse_line(raw_line)
        if not event:
            return {}

        event_id = self.db.insert_event(event)
        event["id"] = event_id

        # 2. Sigma Engine Detection
        sigma_alerts = self.sigma_engine.evaluate_event(event)

        # 3. ML Anomaly Detection
        ml_alert = self.ml_engine.evaluate_event(event)
        if ml_alert:
            sigma_alerts.append(ml_alert)

        processed_alerts = []
        for alert in sigma_alerts:
            alert["event_id"] = event_id
            ip = alert.get("source_ip", "0.0.0.0")

            # 4. Threat Intelligence Enrichment
            enrichment = self.threat_intel.enrich_ip(ip)
            alert["abuse_score"] = enrichment.get("abuse_score", 0)
            alert["asn_tag"] = enrichment.get("asn_tag", "UNKNOWN")

            # 5. SOAR Playbook Execution
            action_taken = self.soar.process_alert(alert, enrichment)
            alert["soar_action_taken"] = action_taken

            # 6. Save Alert to DB
            alert_id = self.db.insert_alert(alert)
            alert["id"] = alert_id
            processed_alerts.append(alert)

        return {
            "event": event,
            "alerts": processed_alerts
        }

    def run_simulation_batch(self, count: int = 50):
        """Runs a simulated batch of log events representing realistic normal and attack traffic."""
        print(f"[*] Seeding pipeline with {count} simulated events & attack vectors...")
        
        # Baseline normal traffic
        normal_logs = [AttackSimulator.generate_normal_log() for _ in range(30)]
        for log in normal_logs:
            self.process_log_line(log)

        # Attack scenario logs
        attack_logs = []
        attack_logs.extend(AttackSimulator.generate_ssh_brute_force_burst(8))
        attack_logs.append(AttackSimulator.generate_sqli_attack())
        attack_logs.append(AttackSimulator.generate_path_traversal_attack())
        attack_logs.append(AttackSimulator.generate_webshell_attack())
        attack_logs.append(AttackSimulator.generate_offhours_login())

        for log in attack_logs:
            self.process_log_line(log)

        stats = self.db.get_stats()
        print(f"[+] Simulation Batch Complete! Total Events: {stats['total_events']} | Total Alerts: {stats['total_alerts']}")
        return stats

if __name__ == "__main__":
    pipeline = SIEMPipeline()
    pipeline.run_simulation_batch()

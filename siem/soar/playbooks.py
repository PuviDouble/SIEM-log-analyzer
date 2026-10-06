import os
import json
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional

class SOARPlaybookEngine:
    """
    Automated SOAR (Security Orchestration, Automation, and Response) Active Defense Engine.
    Executes automated mitigation playbooks (Firewall Null-routing / IP Blocking scripts)
    and dispatches rich incident cards to Discord/Slack webhooks.
    """

    def __init__(
        self,
        discord_webhook_url: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
        mitigation_script_path: str = "./soar_mitigation.sh",
        min_auto_block_severity: str = "CRITICAL",
        min_auto_block_abuse_score: int = 75
    ):
        self.discord_url = discord_webhook_url or os.getenv("DISCORD_WEBHOOK_URL", "")
        self.slack_url = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
        self.script_path = mitigation_script_path
        self.min_severity = min_auto_block_severity
        self.min_abuse_score = min_auto_block_abuse_score
        self.blocked_ips: List[str] = []

    def process_alert(self, alert: Dict[str, Any], enrichment_data: Dict[str, Any]) -> str:
        """Processes alert against SOAR playbooks and returns action summary."""
        actions_taken = []
        ip = alert.get("source_ip", "0.0.0.0")
        severity = alert.get("severity", "MEDIUM")
        abuse_score = enrichment_data.get("abuse_score", 0)

        # 1. Trigger Firewall IP Blocking Playbook if Critical/High or high AbuseIPDB score
        if (severity == "CRITICAL" or abuse_score >= self.min_abuse_score) and ip not in self.blocked_ips:
            if not enrichment_data.get("is_whitelisted", False):
                self._execute_ip_block_playbook(ip, alert, enrichment_data)
                self.blocked_ips.append(ip)
                actions_taken.append(f"AUTOMATED_FIREWALL_BLOCK({ip})")

        # 2. Trigger Discord / Slack Webhook Playbook
        if severity in ["HIGH", "CRITICAL"]:
            webhook_sent = self._send_webhook_notifications(alert, enrichment_data)
            if webhook_sent:
                actions_taken.append("WEBHOOK_ALERT_DISPATCHED")

        return ", ".join(actions_taken) if actions_taken else "MONITORED_LOGGED"

    def _execute_ip_block_playbook(self, ip: str, alert: Dict[str, Any], enrichment: Dict[str, Any]):
        """Generates ready-to-run iptables / ufw / Windows Firewall mitigation scripts."""
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        rule_title = alert.get("rule_title", "Security Threat")
        asn_tag = enrichment.get("asn_tag", "UNKNOWN")

        # 1. Bash Script (Linux iptables / ufw)
        bash_entry = f"""# [SOAR ACTION] Blocked IP: {ip} | Rule: {rule_title} | ASN: {asn_tag} | Time: {ts}
iptables -A INPUT -s {ip} -j DROP
ufw deny from {ip} to any
"""
        try:
            with open(self.script_path, "a", encoding="utf-8") as f:
                f.write(bash_entry)
        except Exception as e:
            print(f"[SOARPlaybookEngine] Failed writing to bash mitigation script: {e}")

        # 2. PowerShell Script (Windows Firewall)
        ps_path = self.script_path.replace(".sh", ".ps1")
        ps_entry = f"""# [SOAR ACTION] Blocked IP: {ip} | Rule: {rule_title} | Time: {ts}
New-NetFirewallRule -DisplayName "SIEM-Sentinel-Block-{ip}" -Direction Inbound -RemoteAddress "{ip}" -Action Block
"""
        try:
            with open(ps_path, "a", encoding="utf-8") as f:
                f.write(ps_entry)
        except Exception as e:
            print(f"[SOARPlaybookEngine] Failed writing to PS mitigation script: {e}")

    def _send_webhook_notifications(self, alert: Dict[str, Any], enrichment: Dict[str, Any]) -> bool:
        """Dispatches rich Discord embed card for SOC analyst incident response."""
        if not self.discord_url and not self.slack_url:
            return False

        severity = alert.get("severity", "HIGH")
        color_code = 15158332 if severity == "CRITICAL" else 15105570  # Red or Orange

        embed = {
            "title": f"🚨 SIEM SENTINEL ALERT: {alert.get('rule_title')}",
            "description": f"**Detection Engine:** `{alert.get('detection_type')}` | **MITRE Tag:** `{alert.get('mitre_technique')}`",
            "color": color_code,
            "fields": [
                {"name": "Attacker IP", "value": f"`{alert.get('source_ip')}`", "inline": True},
                {"name": "Severity", "value": f"**{severity}**", "inline": True},
                {"name": "Target User", "value": f"`{alert.get('user')}`", "inline": True},
                {"name": "AbuseIPDB Score", "value": f"{enrichment.get('abuse_score', 0)}/100", "inline": True},
                {"name": "ISP / Provider", "value": enrichment.get("isp", "Unknown"), "inline": True},
                {"name": "ASN Classification", "value": f"`{enrichment.get('asn_tag', 'UNKNOWN')}`", "inline": True},
            ],
            "footer": {"text": f"SIEM Sentinel Active Defense SOAR • {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"}
        }

        success = False

        if self.discord_url:
            try:
                res = requests.post(self.discord_url, json={"embeds": [embed]}, timeout=3)
                if res.status_code in [200, 204]:
                    success = True
            except Exception as e:
                print(f"[SOARPlaybookEngine] Discord webhook failed: {e}")

        if self.slack_url:
            try:
                slack_payload = {
                    "text": f"🚨 *SIEM SENTINEL ALERT: {alert.get('rule_title')}*",
                    "attachments": [{
                        "color": "#ff0000" if severity == "CRITICAL" else "#ff9900",
                        "text": f"Attacker IP: `{alert.get('source_ip')}` | Severity: *{severity}* | MITRE: `{alert.get('mitre_technique')}`"
                    }]
                }
                res = requests.post(self.slack_url, json=slack_payload, timeout=3)
                if res.status_code in [200, 204]:
                    success = True
            except Exception as e:
                print(f"[SOARPlaybookEngine] Slack webhook failed: {e}")

        return success

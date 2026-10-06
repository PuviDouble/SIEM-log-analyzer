import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

class SIEMDatabase:
    def __init__(self, db_path: str = "./data/siem_sentinel.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Raw events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    user TEXT,
                    service TEXT,
                    event_type TEXT,
                    url TEXT,
                    status_code INTEGER,
                    bytes_sent INTEGER,
                    request_length INTEGER,
                    param_entropy REAL,
                    raw_log TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Detection alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER,
                    timestamp TEXT,
                    rule_id TEXT,
                    rule_title TEXT,
                    detection_type TEXT, -- 'SIGMA' or 'ML_ANOMALY'
                    severity TEXT,       -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
                    mitre_technique TEXT,
                    source_ip TEXT,
                    user TEXT,
                    details TEXT,       -- JSON blob
                    abuse_score INTEGER,
                    asn_tag TEXT,
                    soar_action_taken TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(event_id) REFERENCES events(id)
                )
            """)
            conn.commit()

    def insert_event(self, event: Dict[str, Any]) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (
                    timestamp, source_ip, user, service, event_type, url,
                    status_code, bytes_sent, request_length, param_entropy, raw_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp", datetime.utcnow().isoformat()),
                event.get("source_ip", "0.0.0.0"),
                event.get("user", "unknown"),
                event.get("service", "webserver"),
                event.get("event_type", "http_request"),
                event.get("url", "/"),
                event.get("status_code", 200),
                event.get("bytes_sent", 0),
                event.get("request_length", 0),
                event.get("param_entropy", 0.0),
                event.get("raw_log", "")
            ))
            conn.commit()
            return cursor.lastrowid

    def insert_alert(self, alert: Dict[str, Any]) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            details_json = json.dumps(alert.get("details", {}))
            cursor.execute("""
                INSERT INTO alerts (
                    event_id, timestamp, rule_id, rule_title, detection_type,
                    severity, mitre_technique, source_ip, user, details,
                    abuse_score, asn_tag, soar_action_taken
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.get("event_id"),
                alert.get("timestamp", datetime.utcnow().isoformat()),
                alert.get("rule_id", "ANOMALY-001"),
                alert.get("rule_title", "Security Alert"),
                alert.get("detection_type", "SIGMA"),
                alert.get("severity", "MEDIUM"),
                alert.get("mitre_technique", "T1190"),
                alert.get("source_ip", "0.0.0.0"),
                alert.get("user", "unknown"),
                details_json,
                alert.get("abuse_score", 0),
                alert.get("asn_tag", "UNKNOWN"),
                alert.get("soar_action_taken", "NONE")
            ))
            conn.commit()
            return cursor.lastrowid

    def get_alerts(self, limit: int = 100, min_severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM alerts"
            params = []
            if min_severity:
                query += " WHERE severity = ?"
                params.append(min_severity)
            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            alerts = []
            for row in rows:
                item = dict(row)
                if item.get("details"):
                    try:
                        item["details"] = json.loads(item["details"])
                    except Exception:
                        pass
                alerts.append(item)
            return alerts

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            severity_counts = dict(cursor.fetchall())

            cursor.execute("SELECT mitre_technique, COUNT(*) FROM alerts GROUP BY mitre_technique")
            mitre_counts = dict(cursor.fetchall())

            cursor.execute("SELECT source_ip, COUNT(*) as cnt FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 5")
            top_attacking_ips = [dict(r) for r in cursor.fetchall()]

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "severity_counts": severity_counts,
                "mitre_counts": mitre_counts,
                "top_attacking_ips": top_attacking_ips
            }

    def clear_all(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM events")
            conn.commit()

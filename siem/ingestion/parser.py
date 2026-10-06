import re
import math
from datetime import datetime
from typing import Dict, Any, Optional

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect payload obfuscation, base64, SQLi, or shellcode."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = -sum([p * math.log2(p) for p in prob])
    return round(entropy, 4)

class LogParser:
    """Multi-format SIEM Log Parser normalizing raw logs into Standard Event Schemas."""
    
    # Common Log Format (Nginx / Apache web access)
    COMBINED_LOG_REGEX = re.compile(
        r'^(?P<source_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status_code>\d{3}) (?P<bytes_sent>\d+)'
    )
    
    # Auth log (SSH failed / successful login)
    AUTH_LOG_FAILED_REGEX = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<source_ip>\S+) port \d+'
    )
    AUTH_LOG_SUCCESS_REGEX = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<source_ip>\S+) port \d+'
    )

    @staticmethod
    def parse_line(raw_line: str) -> Dict[str, Any]:
        raw_line = raw_line.strip()
        if not raw_line:
            return {}

        # Try Nginx/Apache Web Log
        match = LogParser.COMBINED_LOG_REGEX.match(raw_line)
        if match:
            data = match.groupdict()
            url = data.get("url", "/")
            entropy = calculate_shannon_entropy(url)
            ts = LogParser._parse_http_timestamp(data.get("timestamp"))
            
            return {
                "timestamp": ts,
                "source_ip": data.get("source_ip"),
                "user": data.get("user") if data.get("user") != "-" else "anonymous",
                "service": "webserver",
                "event_type": "http_request",
                "url": url,
                "status_code": int(data.get("status_code", 200)),
                "bytes_sent": int(data.get("bytes_sent", 0)),
                "request_length": len(url),
                "param_entropy": entropy,
                "is_off_hours": LogParser._check_off_hours(ts),
                "raw_log": raw_line
            }

        # Try SSH Failed Login
        match = LogParser.AUTH_LOG_FAILED_REGEX.match(raw_line)
        if match:
            data = match.groupdict()
            ts = datetime.utcnow().isoformat()
            return {
                "timestamp": ts,
                "source_ip": data.get("source_ip"),
                "user": data.get("user", "unknown"),
                "service": "sshd",
                "event_type": "failed_login",
                "url": "",
                "status_code": 401,
                "bytes_sent": 0,
                "request_length": 0,
                "param_entropy": 0.0,
                "is_off_hours": LogParser._check_off_hours(ts),
                "raw_log": raw_line
            }

        # Try SSH Accepted Login
        match = LogParser.AUTH_LOG_SUCCESS_REGEX.match(raw_line)
        if match:
            data = match.groupdict()
            ts = datetime.utcnow().isoformat()
            return {
                "timestamp": ts,
                "source_ip": data.get("source_ip"),
                "user": data.get("user", "unknown"),
                "service": "sshd",
                "event_type": "successful_login",
                "url": "",
                "status_code": 200,
                "bytes_sent": 0,
                "request_length": 0,
                "param_entropy": 0.0,
                "is_off_hours": LogParser._check_off_hours(ts),
                "raw_log": raw_line
            }

        # Fallback dictionary parsing for unstructured / custom format
        ts = datetime.utcnow().isoformat()
        return {
            "timestamp": ts,
            "source_ip": "127.0.0.1",
            "user": "system",
            "service": "syslog",
            "event_type": "raw_event",
            "url": raw_line[:100],
            "status_code": 200,
            "bytes_sent": len(raw_line),
            "request_length": len(raw_line),
            "param_entropy": calculate_shannon_entropy(raw_line),
            "is_off_hours": LogParser._check_off_hours(ts),
            "raw_log": raw_line
        }

    @staticmethod
    def _parse_http_timestamp(ts_str: Optional[str]) -> str:
        if not ts_str:
            return datetime.utcnow().isoformat()
        try:
            # Example: 10/Oct/2026:13:55:36 +0000
            dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat()
        except Exception:
            return datetime.utcnow().isoformat()

    @staticmethod
    def _check_off_hours(ts_str: str) -> bool:
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.hour < 6 or dt.hour >= 20
        except Exception:
            return False

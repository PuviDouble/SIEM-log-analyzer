import time
import random
from datetime import datetime
from typing import List

class AttackSimulator:
    """
    Attack Simulation & Realistic Log Stream Generator.
    Simulates real-world attack vectors mapped directly to MITRE ATT&CK techniques:
    - T1110: SSH Brute Force Attack
    - T1190: Web SQL Injection & Path Traversal
    - T1505.003: Web Shell Access & Command Execution
    - T1078: Off-Hours Privilege Escalation / Anomaly Login
    """

    NORMAL_IPS = ["192.168.1.105", "192.168.1.120", "10.0.0.15", "172.16.0.40"]
    ATTACKER_IPS = ["185.220.101.5", "45.142.214.12", "193.142.146.210"]
    NORMAL_USERS = ["alice", "bob", "developer", "charlie"]
    ATTACK_USERS = ["root", "admin", "administrator", "service_account"]

    NORMAL_URLS = [
        "/index.html", "/login", "/dashboard", "/api/v1/health",
        "/about-us", "/products?id=12", "/css/main.css", "/js/app.js"
    ]

    SQLI_URLS = [
        "/products?id=1' UNION SELECT username, password FROM users--",
        "/login?user=admin' OR '1'='1",
        "/api/search?q=1'; DROP TABLE logs;--"
    ]

    TRAVERSAL_URLS = [
        "/download?file=../../../../etc/passwd",
        "/static/..%2f..%2f..%2fwin.ini",
        "/view_file?path=../../../../boot.ini"
    ]

    WEBSHELL_URLS = [
        "/uploads/c99.php?cmd=cat%20/etc/shadow",
        "/shell.php?passthru=whoami",
        "/wp-content/plugins/revslider/cmd.php?eval=system('id')"
    ]

    @staticmethod
    def generate_normal_log() -> str:
        ip = random.choice(AttackSimulator.NORMAL_IPS)
        user = random.choice(AttackSimulator.NORMAL_USERS)
        url = random.choice(AttackSimulator.NORMAL_URLS)
        status = 200
        bytes_sent = random.randint(350, 4500)
        ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - {user} [{ts}] "GET {url} HTTP/1.1" {status} {bytes_sent}'

    @staticmethod
    def generate_ssh_brute_force_burst(count: int = 8) -> List[str]:
        logs = []
        attacker_ip = "185.220.101.5"
        for _ in range(count):
            user = random.choice(AttackSimulator.ATTACK_USERS)
            ts = datetime.utcnow().strftime("%b %d %H:%M:%S")
            log = f'{ts} server1 sshd[12845]: Failed password for invalid user {user} from {attacker_ip} port {random.randint(40000, 65000)} ssh2'
            logs.append(log)
        return logs

    @staticmethod
    def generate_sqli_attack() -> str:
        ip = "45.142.214.12"
        url = random.choice(AttackSimulator.SQLI_URLS)
        ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "GET {url} HTTP/1.1" 500 1250'

    @staticmethod
    def generate_path_traversal_attack() -> str:
        ip = "193.142.146.210"
        url = random.choice(AttackSimulator.TRAVERSAL_URLS)
        ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "GET {url} HTTP/1.1" 403 890'

    @staticmethod
    def generate_webshell_attack() -> str:
        ip = "185.220.101.5"
        url = random.choice(AttackSimulator.WEBSHELL_URLS)
        ts = datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts}] "GET {url} HTTP/1.1" 200 8920'

    @staticmethod
    def generate_offhours_login() -> str:
        ip = "45.142.214.12"
        ts = datetime.utcnow().strftime("%b %d 03:14:22")
        return f'{ts} server1 sshd[14920]: Accepted password for root from {ip} port 54120 ssh2'

if __name__ == "__main__":
    print("=== SIEM Sentinel Attack Simulator ===")
    print("Generating sample attack logs...")
    print(AttackSimulator.generate_normal_log())
    for log in AttackSimulator.generate_ssh_brute_force_burst(3):
        print(log)
    print(AttackSimulator.generate_sqli_attack())
    print(AttackSimulator.generate_webshell_attack())

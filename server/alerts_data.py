"""
Alert data generation for the SOC Analyst environment.

Generates realistic security alerts across 3 difficulty levels:
- Task 1 (Easy): Alert Triage - classify 5 alerts
- Task 2 (Medium): Incident Investigation - investigate with context queries
- Task 3 (Hard): Multi-Alert Correlation - connect related attack chain alerts
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List

# ============================================================================
# NETWORK TOPOLOGY (simulated corporate environment)
# ============================================================================

INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "10.0.3.", "192.168.1."]
DMZ_SUBNET = "172.16.0."
EXTERNAL_IPS = [
    "203.0.113.45",
    "198.51.100.12",
    "185.220.101.33",
    "91.215.85.17",
    "45.33.32.156",
    "104.248.50.87",
    "159.65.60.12",
    "178.128.244.1",
]

KNOWN_MALICIOUS_IPS = [
    "185.220.101.33",
    "91.215.85.17",
    "45.33.32.156",
]

KNOWN_SCANNER_IPS = ["198.51.100.12", "159.65.60.12"]

EMPLOYEE_HOSTS = {
    "10.0.1.15": {
        "user": "jsmith",
        "dept": "Engineering",
        "role": "Developer",
        "hostname": "ENG-WS-015",
    },
    "10.0.1.22": {
        "user": "mchen",
        "dept": "Engineering",
        "role": "SRE",
        "hostname": "ENG-WS-022",
    },
    "10.0.2.10": {
        "user": "agarcia",
        "dept": "Finance",
        "role": "Analyst",
        "hostname": "FIN-WS-010",
    },
    "10.0.2.18": {
        "user": "rwilson",
        "dept": "Finance",
        "role": "Controller",
        "hostname": "FIN-WS-018",
    },
    "10.0.3.5": {
        "user": "klee",
        "dept": "HR",
        "role": "Manager",
        "hostname": "HR-WS-005",
    },
    "10.0.3.12": {
        "user": "tbrown",
        "dept": "HR",
        "role": "Recruiter",
        "hostname": "HR-WS-012",
    },
    "10.0.1.50": {
        "user": "admin_ops",
        "dept": "IT",
        "role": "SysAdmin",
        "hostname": "IT-WS-050",
    },
    "192.168.1.100": {
        "user": "vpn_contractor",
        "dept": "External",
        "role": "Contractor",
        "hostname": "VPN-EXT-100",
    },
}

CRITICAL_SERVERS = {
    "10.0.1.200": {
        "name": "PROD-DB-01",
        "service": "PostgreSQL",
        "sensitivity": "critical",
    },
    "10.0.1.201": {
        "name": "PROD-APP-01",
        "service": "Web Application",
        "sensitivity": "high",
    },
    "10.0.2.200": {
        "name": "FIN-DB-01",
        "service": "Financial Database",
        "sensitivity": "critical",
    },
    "172.16.0.10": {
        "name": "DMZ-WEB-01",
        "service": "Public Website",
        "sensitivity": "medium",
    },
    "10.0.1.250": {
        "name": "DC-01",
        "service": "Domain Controller",
        "sensitivity": "critical",
    },
}


def _rand_timestamp(base: datetime, offset_minutes: int = 0) -> str:
    ts = base + timedelta(minutes=offset_minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================================
# CONTEXT DATA (returned when agent queries for more info)
# ============================================================================

USER_PROFILES = {
    "jsmith": {
        "full_name": "John Smith",
        "department": "Engineering",
        "role": "Senior Developer",
        "hire_date": "2021-03-15",
        "last_login": "normal business hours",
        "risk_score": "low",
        "recent_activity": "Normal code commits and PR reviews. No anomalies.",
        "access_level": "standard developer access, no admin privileges",
    },
    "mchen": {
        "full_name": "Maria Chen",
        "department": "Engineering",
        "role": "Site Reliability Engineer",
        "hire_date": "2020-08-22",
        "last_login": "irregular hours (on-call rotation)",
        "risk_score": "low",
        "recent_activity": "Server maintenance and monitoring. Accessed prod DB for performance tuning.",
        "access_level": "elevated - production server access, sudo on monitoring hosts",
    },
    "agarcia": {
        "full_name": "Ana Garcia",
        "department": "Finance",
        "role": "Financial Analyst",
        "hire_date": "2022-01-10",
        "last_login": "business hours only",
        "risk_score": "medium",
        "recent_activity": "Large file downloads from FIN-DB-01 last 48h. Accessed 3x normal volume.",
        "access_level": "finance database read access, no admin",
    },
    "rwilson": {
        "full_name": "Robert Wilson",
        "department": "Finance",
        "role": "Financial Controller",
        "hire_date": "2019-06-01",
        "last_login": "business hours",
        "risk_score": "low",
        "recent_activity": "Routine financial report generation. No anomalies.",
        "access_level": "finance database read/write, approval authority",
    },
    "klee": {
        "full_name": "Karen Lee",
        "department": "HR",
        "role": "HR Manager",
        "hire_date": "2018-11-20",
        "last_login": "business hours",
        "risk_score": "low",
        "recent_activity": "Normal HR operations. Accessed employee records.",
        "access_level": "HR systems full access, employee PII access",
    },
    "vpn_contractor": {
        "full_name": "External Contractor (Acme Consulting)",
        "department": "External",
        "role": "Contract Developer",
        "hire_date": "2025-11-01",
        "last_login": "connected at 02:30 AM from IP 91.215.85.17 (Ukraine)",
        "risk_score": "high",
        "recent_activity": "VPN connection from unusual geo. Attempted access to HR and Finance shares.",
        "access_level": "limited developer access, should NOT have HR/Finance access",
    },
}

THREAT_INTEL = {
    "185.220.101.33": {
        "status": "known_malicious",
        "tags": ["tor_exit_node", "APT28_infrastructure"],
        "first_seen": "2024-06-15",
        "confidence": "high",
        "description": "Known Tor exit node associated with APT28 (Fancy Bear) reconnaissance activity.",
    },
    "91.215.85.17": {
        "status": "known_malicious",
        "tags": ["c2_server", "ransomware", "cobalt_strike"],
        "first_seen": "2025-09-01",
        "confidence": "high",
        "description": "Command-and-control server linked to Cobalt Strike beacons and ransomware deployments.",
    },
    "45.33.32.156": {
        "status": "suspicious",
        "tags": ["scanning", "credential_stuffing"],
        "first_seen": "2025-12-01",
        "confidence": "medium",
        "description": "IP associated with credential stuffing campaigns targeting enterprise VPNs.",
    },
    "198.51.100.12": {
        "status": "benign_scanner",
        "tags": ["shodan", "research_scanner"],
        "first_seen": "2023-01-01",
        "confidence": "high",
        "description": "Shodan.io research scanner. Benign internet-wide scanning.",
    },
    "159.65.60.12": {
        "status": "benign_scanner",
        "tags": ["censys", "research_scanner"],
        "first_seen": "2023-03-01",
        "confidence": "high",
        "description": "Censys research scanner. Benign internet-wide scanning.",
    },
    "203.0.113.45": {
        "status": "unknown",
        "tags": [],
        "first_seen": "never_seen",
        "confidence": "none",
        "description": "No threat intelligence data available for this IP.",
    },
}


def get_context_response(query_type: str, alert: Dict[str, Any]) -> str:
    """Generate context response based on query type and alert data."""
    if query_type == "user_profile":
        src_ip = alert.get("source_ip", "")
        host_info = EMPLOYEE_HOSTS.get(src_ip, {})
        user = host_info.get("user", "unknown")
        profile = USER_PROFILES.get(user)
        if profile:
            lines = [f"=== User Profile: {profile['full_name']} ==="]
            for k, v in profile.items():
                if k != "full_name":
                    lines.append(f"  {k}: {v}")
            return "\n".join(lines)
        return f"No user profile found for host {src_ip}."

    elif query_type == "network_logs":
        src_ip = alert.get("source_ip", "")
        dest_ip = alert.get("dest_ip", "")
        if src_ip in KNOWN_MALICIOUS_IPS or dest_ip in KNOWN_MALICIOUS_IPS:
            return (
                f"=== Network Logs for {src_ip} <-> {dest_ip} ===\n"
                f"  Multiple connections detected in last 24h.\n"
                f"  Outbound data transfer: 847 MB over encrypted channel.\n"
                f"  DNS queries to suspicious domains: ns1.evil-domain.ru, update.malware-c2.net\n"
                f"  Connection pattern: periodic beaconing every 60 seconds."
            )
        elif src_ip in KNOWN_SCANNER_IPS:
            return (
                f"=== Network Logs for {src_ip} ===\n"
                f"  Source identified as known internet scanner.\n"
                f"  Port scan pattern: sequential ports 1-1024.\n"
                f"  No successful connections. All blocked by firewall.\n"
                f"  Common pattern - benign research scanning."
            )
        else:
            return (
                f"=== Network Logs for {src_ip} <-> {dest_ip} ===\n"
                f"  Normal traffic patterns observed.\n"
                f"  No unusual data volumes or connection patterns.\n"
                f"  Standard HTTP/HTTPS traffic on expected ports."
            )

    elif query_type == "threat_intel":
        for ip_field in ["source_ip", "dest_ip"]:
            ip = alert.get(ip_field, "")
            if ip in THREAT_INTEL:
                ti = THREAT_INTEL[ip]
                return (
                    f"=== Threat Intelligence: {ip} ===\n"
                    f"  Status: {ti['status']}\n"
                    f"  Tags: {', '.join(ti['tags']) if ti['tags'] else 'none'}\n"
                    f"  First seen: {ti['first_seen']}\n"
                    f"  Confidence: {ti['confidence']}\n"
                    f"  Description: {ti['description']}"
                )
        return "No threat intelligence data found for IPs in this alert."

    elif query_type == "asset_info":
        dest_ip = alert.get("dest_ip", "")
        src_ip = alert.get("source_ip", "")
        for ip in [dest_ip, src_ip]:
            if ip in CRITICAL_SERVERS:
                srv = CRITICAL_SERVERS[ip]
                return (
                    f"=== Asset Information: {ip} ===\n"
                    f"  Hostname: {srv['name']}\n"
                    f"  Service: {srv['service']}\n"
                    f"  Sensitivity: {srv['sensitivity']}\n"
                    f"  Note: {'This is a CRITICAL asset. Unauthorized access must be escalated immediately.' if srv['sensitivity'] == 'critical' else 'Standard asset.'}"
                )
            if ip in EMPLOYEE_HOSTS:
                host = EMPLOYEE_HOSTS[ip]
                return (
                    f"=== Asset Information: {ip} ===\n"
                    f"  Hostname: {host['hostname']}\n"
                    f"  Assigned user: {host['user']}\n"
                    f"  Department: {host['dept']}\n"
                    f"  Role: {host['role']}"
                )
        return "No asset information found for IPs in this alert."

    return "Unknown query type. Available: user_profile, network_logs, threat_intel, asset_info"


# ============================================================================
# TASK 1: ALERT TRIAGE (Easy)
# ============================================================================


def generate_task1_alerts(seed: int = 42) -> List[Dict[str, Any]]:
    """Generate 5 alerts for triage classification task."""
    base_time = datetime(2026, 3, 15, 14, 30, 0)

    alerts = [
        # Alert 1: FALSE POSITIVE - known research scanner doing port scan
        {
            "alert_id": "ALT-001",
            "timestamp": _rand_timestamp(base_time, 0),
            "source_ip": "198.51.100.12",
            "dest_ip": "172.16.0.10",
            "alert_type": "intrusion",
            "severity_hint": "medium",
            "rule_name": "ET SCAN Potential Port Scan",
            "description": "Sequential port scanning detected from external IP targeting DMZ web server.",
            "raw_log": "SRC=198.51.100.12 DST=172.16.0.10 PROTO=TCP SPT=44521 DPT=22,80,443,8080,8443 FLAGS=SYN",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
        },
        # Alert 2: TRUE POSITIVE - malware beacon to known C2
        {
            "alert_id": "ALT-002",
            "timestamp": _rand_timestamp(base_time, 5),
            "source_ip": "10.0.1.15",
            "dest_ip": "91.215.85.17",
            "alert_type": "malware",
            "severity_hint": "critical",
            "rule_name": "ET MALWARE Cobalt Strike Beacon Activity",
            "description": "Host in Engineering subnet sending periodic HTTPS requests to suspicious external IP. Beaconing pattern detected.",
            "raw_log": "SRC=10.0.1.15 DST=91.215.85.17 PROTO=TCP DPT=443 INTERVAL=60s PAYLOAD=encrypted USER_AGENT=Mozilla/5.0(compatible)",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
        },
        # Alert 3: FALSE POSITIVE - routine admin activity
        {
            "alert_id": "ALT-003",
            "timestamp": _rand_timestamp(base_time, 12),
            "source_ip": "10.0.1.50",
            "dest_ip": "10.0.1.250",
            "alert_type": "insider_threat",
            "severity_hint": "high",
            "rule_name": "PRIV Unusual Domain Controller Access",
            "description": "IT workstation accessing Domain Controller with administrative credentials outside standard maintenance window.",
            "raw_log": "SRC=10.0.1.50 DST=10.0.1.250 USER=admin_ops PROTO=LDAP ACTION=GroupPolicyUpdate TIME=14:42:00",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
        },
        # Alert 4: TRUE POSITIVE - insider data exfiltration
        {
            "alert_id": "ALT-004",
            "timestamp": _rand_timestamp(base_time, 20),
            "source_ip": "10.0.2.10",
            "dest_ip": "10.0.2.200",
            "alert_type": "insider_threat",
            "severity_hint": "high",
            "rule_name": "DLP Large Data Transfer from Financial Database",
            "description": "Finance workstation downloading unusually large volume of data from financial database. 3x normal daily volume.",
            "raw_log": "SRC=10.0.2.10 DST=10.0.2.200 PROTO=TCP DPT=5432 BYTES=847000000 DURATION=1800s QUERY_COUNT=15420",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
        },
        # Alert 5: TRUE POSITIVE - suspicious VPN access
        {
            "alert_id": "ALT-005",
            "timestamp": _rand_timestamp(base_time, 25),
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.3.5",
            "alert_type": "policy_violation",
            "severity_hint": "medium",
            "rule_name": "VPN Access from Unusual Geolocation",
            "description": "VPN connection from contractor account originating from unexpected geographic location (Ukraine). Attempting to access HR resources.",
            "raw_log": "SRC=192.168.1.100 VPN_EXT_IP=91.215.85.17 DST=10.0.3.5 USER=vpn_contractor PROTO=SMB SHARE=\\\\HR-WS-005\\EmployeeRecords",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
        },
    ]

    return alerts


# ============================================================================
# TASK 2: INCIDENT INVESTIGATION (Medium)
# ============================================================================


def generate_task2_alerts(seed: int = 42) -> List[Dict[str, Any]]:
    """Generate alerts for the incident investigation task."""
    base_time = datetime(2026, 3, 15, 3, 15, 0)

    alerts = [
        {
            "alert_id": "INC-001",
            "timestamp": _rand_timestamp(base_time, 0),
            "source_ip": "10.0.1.15",
            "dest_ip": "185.220.101.33",
            "alert_type": "intrusion",
            "severity_hint": "high",
            "rule_name": "ET POLICY Outbound Connection to Tor Exit Node",
            "description": "Developer workstation ENG-WS-015 made HTTPS connection to known Tor exit node at 03:15 AM. Multiple DNS queries to suspicious domains preceded this connection.",
            "raw_log": "SRC=10.0.1.15 DST=185.220.101.33 PROTO=TCP DPT=443 DNS_QUERIES=[ns1.evil-domain.ru, update.malware-c2.net] TIME=03:15:00",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
            "_correct_diagnosis": "compromised_host",
            "_correct_action": "contain",
        },
        {
            "alert_id": "INC-002",
            "timestamp": _rand_timestamp(base_time, -30),
            "source_ip": "10.0.1.15",
            "dest_ip": "10.0.1.200",
            "alert_type": "system_anomaly",
            "severity_hint": "medium",
            "rule_name": "DB Unusual Query Pattern",
            "description": "Developer workstation ran unusual database queries against PROD-DB-01. Query pattern does not match normal developer activity.",
            "raw_log": "SRC=10.0.1.15 DST=10.0.1.200 PROTO=TCP DPT=5432 QUERIES=[SELECT * FROM users, SELECT * FROM api_keys, SELECT * FROM payment_methods] TIME=02:45:00",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
            "_correct_diagnosis": "data_reconnaissance",
            "_correct_action": "escalate",
        },
        {
            "alert_id": "INC-003",
            "timestamp": _rand_timestamp(base_time, 10),
            "source_ip": "159.65.60.12",
            "dest_ip": "172.16.0.10",
            "alert_type": "intrusion",
            "severity_hint": "low",
            "rule_name": "ET SCAN Censys Scanner Activity",
            "description": "Known research scanner probing DMZ web server on standard ports.",
            "raw_log": "SRC=159.65.60.12 DST=172.16.0.10 PROTO=TCP DPT=80,443 FLAGS=SYN",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
            "_correct_diagnosis": "benign_scanner",
            "_correct_action": "dismiss",
        },
    ]
    return alerts


# ============================================================================
# TASK 3: MULTI-ALERT CORRELATION (Hard)
# ============================================================================


def generate_task3_alerts(seed: int = 42) -> List[Dict[str, Any]]:
    """Generate a simulated multi-stage attack campaign.

    Attack kill chain (chain_id='CAMPAIGN-ALPHA'):
    1. Reconnaissance: Port scan from Tor exit node
    2. Initial Access: Phishing email leads to malware download
    3. Execution: Cobalt Strike beacon established
    4. Lateral Movement: Credential harvesting -> moved to finance subnet
    5. Exfiltration: Data stolen from financial database

    Mixed with decoy/noise alerts that are unrelated.
    """
    base_time = datetime(2026, 3, 14, 22, 0, 0)

    alerts = [
        # === ATTACK CHAIN: CAMPAIGN-ALPHA ===
        # Stage 1: Reconnaissance
        {
            "alert_id": "MC-001",
            "timestamp": _rand_timestamp(base_time, 0),
            "source_ip": "185.220.101.33",
            "dest_ip": "172.16.0.10",
            "alert_type": "intrusion",
            "severity_hint": "low",
            "rule_name": "ET SCAN Targeted Port Scan",
            "description": "Targeted port scanning of DMZ web server from external IP. Focused on web application ports.",
            "raw_log": "SRC=185.220.101.33 DST=172.16.0.10 PROTO=TCP DPT=80,443,8080,8443,9090 FLAGS=SYN SCAN_TYPE=targeted",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Decoy 1: Routine scanner (unrelated)
        {
            "alert_id": "MC-002",
            "timestamp": _rand_timestamp(base_time, 15),
            "source_ip": "198.51.100.12",
            "dest_ip": "172.16.0.10",
            "alert_type": "intrusion",
            "severity_hint": "low",
            "rule_name": "ET SCAN Shodan Scanner",
            "description": "Shodan.io research scanner performing standard internet-wide scan.",
            "raw_log": "SRC=198.51.100.12 DST=172.16.0.10 PROTO=TCP DPT=22,80,443 FLAGS=SYN",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
        },
        # Stage 2: Initial Access - Spearphishing
        {
            "alert_id": "MC-003",
            "timestamp": _rand_timestamp(base_time, 120),
            "source_ip": "10.0.1.15",
            "dest_ip": "203.0.113.45",
            "alert_type": "malware",
            "severity_hint": "medium",
            "rule_name": "ET MALWARE Suspicious File Download",
            "description": "Employee workstation downloaded executable file from external URL. File hash matches no known signatures. Downloaded via link in email.",
            "raw_log": "SRC=10.0.1.15 DST=203.0.113.45 PROTO=HTTP URI=/docs/Q1-Report.exe SIZE=2.4MB SHA256=a1b2c3d4... REFERER=email_link",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Stage 3: Execution - C2 Beacon Established
        {
            "alert_id": "MC-004",
            "timestamp": _rand_timestamp(base_time, 150),
            "source_ip": "10.0.1.15",
            "dest_ip": "91.215.85.17",
            "alert_type": "malware",
            "severity_hint": "critical",
            "rule_name": "ET MALWARE Cobalt Strike Beacon Detected",
            "description": "Periodic HTTPS beaconing from engineering workstation to known C2 server. 60-second interval with jitter.",
            "raw_log": "SRC=10.0.1.15 DST=91.215.85.17 PROTO=TCP DPT=443 BEACON_INTERVAL=60s JITTER=10% PIPE=\\\\.\\.\\pipe\\msagent_89",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Decoy 2: Routine policy violation (unrelated)
        {
            "alert_id": "MC-005",
            "timestamp": _rand_timestamp(base_time, 180),
            "source_ip": "10.0.3.12",
            "dest_ip": "104.248.50.87",
            "alert_type": "policy_violation",
            "severity_hint": "low",
            "rule_name": "POLICY Unauthorized Cloud Storage Access",
            "description": "HR workstation accessed personal cloud storage (Google Drive) during business hours. Policy violation but not malicious.",
            "raw_log": "SRC=10.0.3.12 DST=104.248.50.87 PROTO=HTTPS URL=drive.google.com/personal USER=tbrown",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
        },
        # Stage 4: Lateral Movement
        {
            "alert_id": "MC-006",
            "timestamp": _rand_timestamp(base_time, 240),
            "source_ip": "10.0.1.15",
            "dest_ip": "10.0.2.10",
            "alert_type": "insider_threat",
            "severity_hint": "high",
            "rule_name": "LATERAL Pass-the-Hash Attack Detected",
            "description": "Engineering workstation used NTLM hash to authenticate to Finance workstation. Credential relay attack suspected.",
            "raw_log": "SRC=10.0.1.15 DST=10.0.2.10 PROTO=SMB AUTH=NTLM_RELAY USER=agarcia HASH=mimikatz_detected",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Decoy 3: System anomaly (unrelated maintenance)
        {
            "alert_id": "MC-007",
            "timestamp": _rand_timestamp(base_time, 270),
            "source_ip": "10.0.1.50",
            "dest_ip": "10.0.1.250",
            "alert_type": "system_anomaly",
            "severity_hint": "medium",
            "rule_name": "SYS Unexpected Service Restart",
            "description": "Domain Controller service restarted unexpectedly. IT admin workstation was connected at the time.",
            "raw_log": "HOST=DC-01 SERVICE=ActiveDirectory ACTION=restart INITIATED_BY=admin_ops REASON=scheduled_patch",
            "ground_truth": "false_positive",
            "attack_chain_id": None,
        },
        # Stage 5: Data Exfiltration - DB export
        {
            "alert_id": "MC-008",
            "timestamp": _rand_timestamp(base_time, 330),
            "source_ip": "10.0.2.10",
            "dest_ip": "10.0.2.200",
            "alert_type": "insider_threat",
            "severity_hint": "high",
            "rule_name": "DLP Bulk Database Export",
            "description": "Finance workstation executing bulk export queries against financial database. Volume exceeds normal thresholds by 5x.",
            "raw_log": "SRC=10.0.2.10 DST=10.0.2.200 PROTO=TCP DPT=5432 QUERIES=bulk_export ROWS=500000 TABLES=[transactions,accounts,customers]",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Stage 5b: Data Exfiltration - External transfer
        {
            "alert_id": "MC-009",
            "timestamp": _rand_timestamp(base_time, 345),
            "source_ip": "10.0.2.10",
            "dest_ip": "91.215.85.17",
            "alert_type": "malware",
            "severity_hint": "critical",
            "rule_name": "DLP Encrypted Data Exfiltration",
            "description": "Finance workstation sending large encrypted data stream to known C2 server. Possible data exfiltration.",
            "raw_log": "SRC=10.0.2.10 DST=91.215.85.17 PROTO=TCP DPT=443 BYTES=1200000000 ENCRYPTION=custom DURATION=900s",
            "ground_truth": "true_positive",
            "attack_chain_id": "CAMPAIGN-ALPHA",
        },
        # Decoy 4: Legitimate high severity alert (unrelated)
        {
            "alert_id": "MC-010",
            "timestamp": _rand_timestamp(base_time, 350),
            "source_ip": "45.33.32.156",
            "dest_ip": "172.16.0.10",
            "alert_type": "intrusion",
            "severity_hint": "medium",
            "rule_name": "ET BRUTE Credential Stuffing Attempt",
            "description": "Multiple failed login attempts against DMZ web application from known credential stuffing IP.",
            "raw_log": "SRC=45.33.32.156 DST=172.16.0.10 PROTO=HTTPS URI=/api/login ATTEMPTS=847 SUCCESS=0 DURATION=300s",
            "ground_truth": "true_positive",
            "attack_chain_id": None,
        },
    ]

    return alerts


# ============================================================================
# TASK DEFINITIONS
# ============================================================================

TASKS = {
    "soc_triage_easy": {
        "task_id": "soc_triage_easy",
        "description": (
            "Alert Triage: You are a SOC Tier-1 analyst. You have received 5 security alerts. "
            "Your task is to classify each alert as 'true_positive', 'false_positive', or "
            "'needs_investigation'. Classify all 5 alerts to complete the task."
        ),
        "difficulty": "easy",
        "max_steps": 10,
        "generator": generate_task1_alerts,
        "available_actions": ["classify", "query_context"],
    },
    "soc_investigate_medium": {
        "task_id": "soc_investigate_medium",
        "description": (
            "Incident Investigation: You are a SOC Tier-2 analyst. A suspicious alert has been "
            "escalated to you. Investigate by querying additional context (user_profile, "
            "network_logs, threat_intel, asset_info), then classify the alerts, and take "
            "appropriate action (escalate, contain, or dismiss). Minimize unnecessary queries."
        ),
        "difficulty": "medium",
        "max_steps": 15,
        "generator": generate_task2_alerts,
        "available_actions": [
            "classify",
            "query_context",
            "escalate",
            "contain",
            "dismiss",
        ],
    },
    "soc_correlate_hard": {
        "task_id": "soc_correlate_hard",
        "description": (
            "Multi-Alert Correlation: You are a SOC Tier-3 analyst / Incident Commander. "
            "You have 10 security alerts from the last 6 hours. Some are noise, but others "
            "are stages of a coordinated attack campaign. Your task is to: (1) identify which "
            "alerts belong to the attack chain, (2) correlate them using the 'correlate' action, "
            "(3) classify all alerts, and (4) submit an incident report describing the attack "
            "kill chain. Use context queries to gather evidence."
        ),
        "difficulty": "hard",
        "max_steps": 25,
        "generator": generate_task3_alerts,
        "available_actions": [
            "classify",
            "query_context",
            "escalate",
            "contain",
            "dismiss",
            "correlate",
            "submit_report",
        ],
    },
}

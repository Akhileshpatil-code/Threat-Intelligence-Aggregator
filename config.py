
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "threat_intel_db"
IOC_COLLECTION = "indicators"
POLICY_LOG_COLLECTION = "enforcement_logs"

WEIGHT_FEED_REPUTATION = 0.4
WEIGHT_MALWARE_VERDICTS = 0.4
WEIGHT_REPORT_COUNT = 0.2


AUTOMATED_BLOCK_THRESHOLD = 75.0  # Risk scores >= 75 trigger instant firewall actions

MOCK_FEEDS = {
    "alienvault_otx": [
        {"ip": "198.51.100.42", "type": "IPv4", "threat_type": "Botnet C2", "reputation_score": 80},
        {"ip": "203.0.113.111", "type": "IPv4", "threat_type": "Ransomware Distribution", "reputation_score": 95},
        {"ip": "malicious-finance-phish.com", "type": "Domain", "threat_type": "Phishing", "reputation_score": 70}
    ],
    "virustotal": [
        {"ip": "198.51.100.42", "positives": 45, "total": 68},
        {"ip": "192.0.2.15", "positives": 2, "total": 68},
        {"ip": "malicious-finance-phish.com", "positives": 52, "total": 70}
    ],
    "blocklist_de": [
        {"ip": "203.0.113.111", "reported_incidents": 142},
        {"ip": "192.0.2.15", "reported_incidents": 3},
        {"ip": "198.51.100.55", "reported_incidents": 89}
    ]
}
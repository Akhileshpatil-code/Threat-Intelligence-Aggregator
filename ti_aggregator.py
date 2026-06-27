# threat_aggregator.py
import datetime
from pymongo import MongoClient
import config

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.client = MongoClient(config.MONGO_URI)
        self.db = self.client[config.DB_NAME]
        self.collection = self.db[config.IOC_COLLECTION]

    def calculate_normalized_score(self, rep_score, positives_ratio, incident_factor):
        """Computes a deterministic threat score from 0.0 to 100.0"""
        score = (rep_score * config.WEIGHT_FEED_REPUTATION) + \
                (positives_ratio * 100 * config.WEIGHT_MALWARE_VERDICTS) + \
                (incident_factor * 100 * config.WEIGHT_REPORT_COUNT)
        return round(min(max(score, 0.0), 100.0), 2)

    def aggregate_and_normalize(self):
        """Scrapes OSINT intelligence feeds, normalizes indicators, and stores results"""
        print("[*] Starting Threat Intelligence Aggregation Cycle...")
        
        
        compiled_iocs = {}

        
        for entry in config.MOCK_FEEDS["alienvault_otx"]:
            target = entry["ip"]
            compiled_iocs[target] = {
                "indicator": target,
                "type": entry["type"],
                "context": entry["threat_type"],
                "raw_rep": entry["reputation_score"],
                "vt_ratio": 0.0,
                "incident_factor": 0.1
            }

    
        for entry in config.MOCK_FEEDS["virustotal"]:
            target = entry["ip"]
            ratio = entry["positives"] / entry["total"] if entry["total"] > 0 else 0
            if target in compiled_iocs:
                compiled_iocs[target]["vt_ratio"] = ratio
            else:
                compiled_iocs[target] = {
                    "indicator": target,
                    "type": "IPv4" if "." in target and not target.endswith(".com") else "Domain",
                    "context": "Suspicious Activity Vector",
                    "raw_rep": 50.0,
                    "vt_ratio": ratio,
                    "incident_factor": 0.1
                }

        
        for entry in config.MOCK_FEEDS["blocklist_de"]:
            target = entry["ip"]
            factor = min(entry["reported_incidents"] / 100.0, 1.0)
            if target in compiled_iocs:
                compiled_iocs[target]["incident_factor"] = factor
            else:
                compiled_iocs[target] = {
                    "indicator": target,
                    "type": "IPv4",
                    "context": "Repetitive Network Abuse",
                    "raw_rep": 40.0,
                    "vt_ratio": 0.0,
                    "incident_factor": factor
                }

        # Committing Normalized Artifacts to MongoDB Document Store
        ingested_count = 0
        for target, data in compiled_iocs.items():
            calculated_risk = self.calculate_normalized_score(
                data["raw_rep"], data["vt_ratio"], data["incident_factor"]
            )
            
            ioc_document = {
                "indicator": data["indicator"],
                "type": data["type"],
                "context": data["context"],
                "risk_score": calculated_risk,
                "last_seen": datetime.datetime.utcnow(),
                "status": "Active" if calculated_risk >= config.AUTOMATED_BLOCK_THRESHOLD else "Monitored"
            }

            
            self.collection.update_one(
                {"indicator": data["indicator"]},
                {"$set": ioc_document},
                upsert=True
            )
            ingested_count += 1
            print(f"[+] Synced: {data['indicator']} | Calculated Normalized Risk: {calculated_risk}")

        print(f"[✓] Data aggregation complete. Total unique documents updated: {ingested_count}\n")

if __name__ == "__main__":
    aggregator = ThreatIntelligenceAggregator()
    aggregator.aggregate_and_normalize()
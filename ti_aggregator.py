import re
import json
import csv
import requests
import ipaddress
from collections import defaultdict
from datetime import datetime

class ThreatIntelligenceAggregator:
    def __init__(self):
        # Dictionary to store indicators. 
        # Format: {"8.8.8.8": {"type": "ip", "sources": set(), "severity": "Low"}}
        self.ioc_database = defaultdict(lambda: {'type': '', 'sources': set()})
        
        # Regular Expressions for parsing
        self.regex_patterns = {
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'sha256': r'\b[A-Fa-f0-9]{64}\b',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        }

    def fetch_feed(self, url, feed_name):
        """Step 1: Download feeds from the internet."""
        print(f"[*] Fetching feed: {feed_name} from {url}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status() # Raise an error for bad status codes
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"[!] Error fetching {feed_name}: {e}")
            return ""

    def parse_and_normalize(self, text_data, feed_name):
        """Step 2 & 3: Extract indicators using regex and clean them."""
        # Parse IPs
        raw_ips = re.findall(self.regex_patterns['ipv4'], text_data)
        for ip in raw_ips:
            try:
                # Validate it's a real IP address, not just random numbers like 999.999.999.999
                valid_ip = str(ipaddress.IPv4Address(ip))
                self._add_to_database(valid_ip, 'ip', feed_name)
            except ipaddress.AddressValueError:
                continue

        # Parse Hashes
        raw_hashes = re.findall(self.regex_patterns['sha256'], text_data)
        for file_hash in raw_hashes:
            self._add_to_database(file_hash, 'sha256', feed_name)

        # Parse URLs
        raw_urls = re.findall(self.regex_patterns['url'], text_data)
        for url in raw_urls:
            self._add_to_database(url, 'url', feed_name)

    def _add_to_database(self, indicator, ioc_type, source):
        """Helper function to add IOCs and track their sources."""
        self.ioc_database[indicator]['type'] = ioc_type
        self.ioc_database[indicator]['sources'].add(source)

    def correlate_and_score(self):
        """Step 4: Determine severity based on how many feeds reported the IOC."""
        print("[*] Running correlation engine...")
        for indicator, data in self.ioc_database.items():
            source_count = len(data['sources'])
            if source_count >= 3:
                data['severity'] = 'High'
            elif source_count == 2:
                data['severity'] = 'Medium'
            else:
                data['severity'] = 'Low'

    def generate_blocklists(self):
        """Step 5: Create isolated text files for security tools."""
        print("[*] Generating Blocklists...")
        ip_blocklist = []
        hash_blocklist = []

        for indicator, data in self.ioc_database.items():
            # Only block Medium and High severity to prevent false positives
            if data['severity'] in ['Medium''High']:
                if data['type'] == 'ip':
                    ip_blocklist.append(indicator)
                elif data['type'] == 'sha256':
                    hash_blocklist.append(indicator)

        with open('firewall_ip_blocklist.txt', 'w') as f:
            f.write("\n".join(ip_blocklist))
        
        with open('edr_hash_blocklist.txt', 'w') as f:
            f.write("\n".join(hash_blocklist))
        
        print(f"[+] Exported {len(ip_blocklist)} IPs to firewall_ip_blocklist.txt")
        print(f"[+] Exported {len(hash_blocklist)} hashes to edr_hash_blocklist.txt")

    def generate_report(self):
        """Step 6: Export the final JSON report of all intelligence."""
        # Convert sets to lists because JSON cannot serialize Python sets
        report_data = {}
        high_risk_count = 0

        for indicator, data in self.ioc_database.items():
            report_data[indicator] = {
                'type': data['type'],
                'sources': list(data['sources']),
                'severity': data['severity']
            }
            if data['severity'] == 'High':
                high_risk_count += 1

        final_report = {
            "metadata": {
                "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_unique_indicators": len(self.ioc_database),
                "high_risk_indicators": high_risk_count
            },
            "indicators": report_data
        }

        with open('final_ti_report.json', 'w') as f:
            json.dump(final_report, f, indent=4)
        
        print("[+] Final JSON report generated: final_ti_report.json")


# ==========================================
# Main Execution Block
# ==========================================
if __name__ == "__main__":
    print("=== Starting Threat Intelligence Aggregator ===")
    aggregator = ThreatIntelligenceAggregator()

    # Public OSINT feeds (Text based) for demonstration
    feeds = {
        "FeodoTracker_IPs": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "URLhaus_Payloads": "https://urlhaus.abuse.ch/downloads/text/",
        "EmergingThreats_IPs": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    }

    # Step 1, 2 & 3: Load, Parse, and Normalize
    for name, url in feeds.items():
        raw_data = aggregator.fetch_feed(url, name)
        if raw_data:
            aggregator.parse_and_normalize(raw_data, name)

    # Step 4: Correlate
    aggregator.correlate_and_score()

    # Step 5 & 6: Output
    aggregator.generate_blocklists()
    aggregator.generate_report()
    
    print("=== Process Complete ===")

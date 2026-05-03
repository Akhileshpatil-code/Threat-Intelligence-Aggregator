# Threat-Intelligence-Aggregator

A Python-based Threat Intelligence Aggregator that collects, parses, normalizes, and correlates Indicators of Compromise (IOCs) from multiple OSINT feeds.

---

## 🚀 Features

- Collects threat intelligence from public feeds
- Extracts:
  - IP addresses
  - SHA256 hashes
  - URLs
- Correlates indicators across multiple sources
- Assigns severity levels:
  - Low
  - Medium
  - High
- Generates:
  - Firewall blocklist (IPs)
  - EDR blocklist (Hashes)
  - JSON intelligence report

---

## 📊 Data Sources

- FeodoTracker
- URLhaus
- Emerging Threats

---

## 🛠️ Installation

```bash
pip install requests

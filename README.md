# 🔍 Threat Intelligence Aggregator

A Python-based tool to collect, parse, and correlate Indicators of Compromise (IOCs) from multiple OSINT threat feeds.

---

## 🚀 Features
- Extracts IPs, URLs, SHA256 hashes
- Correlates indicators across multiple feeds
- Assigns severity (Low, Medium, High)
- Generates:
  - Firewall blocklist
  - EDR hash blocklist
  - JSON report

---

## 📊 Data Sources
- FeodoTracker
- URLhaus
- Emerging Threats

---

## ▶️ Usage
```bash
python ti_aggregator.py

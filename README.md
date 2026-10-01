# 🛡️ ThreatIntel-CLI: Multi-Source Threat Intelligence & SIEM Enrichment Engine

[![ThreatIntel-CLI CI Pipeline](https://github.com/your-username/threatintel-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/threatintel-cli/actions)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![SIEM-Ready: CEF](https://img.shields.io/badge/Log%20Format-CEF%20%7C%20JSON-orange.svg)](#siem-integration-cef)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ThreatIntel-CLI** is a production-grade, modular Command-Line Interface (CLI) threat intelligence utility engineered for SOC Analysts, Incident Responders, and Threat Hunters. It streamlines **Indicator of Compromise (IoC) triage and enrichment** across the **VirusTotal v3 REST API** and **AbuseIPDB v2 API**.

The engine incorporates **Tier-1 enterprise EDR weighting**, **safe memory-stream local file hashing**, **automatic IoC defanging**, **rate-limited batch processing**, and **Common Event Format (CEF) log exporting** for turnkey SIEM forwarding.

---

## 🚀 Key Features

* **Multi-Source IoC Triaging:**
  * **File Hashes:** Direct reputation lookups for MD5, SHA-1, and SHA-256 via VirusTotal v3.
  * **Network Targets:** Base64-safe URL analysis and automated malicious domain classification.
  * **IP Geolocation & Abuse:** Abuse confidence scores, ISP metadata, historical reports, and distinct user counts via AbuseIPDB v2.
* **Direct Binary Hashing:** Memory-safe 64 KB chunk hashing for local binaries (`.exe`, `.dll`, `.elf`) preventing host memory exhaustion.
* **Enterprise Weighted Scoring:** Minimizes false-positive fatigue by heavily weighting detections from Tier-1 enterprise security vendors (*CrowdStrike, Microsoft Defender, Kaspersky, SentinelOne, Symantec, Sophos, Bitdefender, Palo Alto Networks*).
* **Safe IoC Defanging:** Automatically sanitizes malicious links and IPs (`hxxp[://]`, `[.]`) across terminal tables and logs to prevent accidental analyst execution.
* **Rate-Limited Batch Engine:** Auto-identifies indicator types (Hash vs. IP vs. URL) from flat files and applies interval safety throttles to respect free API quotas.
* **SIEM & SOAR Integration:** Generates native **CEF (Common Event Format)** logs ready for ingestion by Splunk, Wazuh SIEM, Sentinel, or syslog daemons alongside structured JSON.

---

## 🏗️ Project Architecture

```text
threatintel-cli/
├── .github/workflows/
│   └── ci.yml               # Automated CI test pipeline
├── config/
│   └── settings.py          # Environment credentials & API endpoints
├── core/
│   ├── __init__.py
│   ├── vt_client.py         # VirusTotal v3 REST API client
│   ├── abuseipdb_client.py  # AbuseIPDB v2 REST API client
│   ├── parsers.py           # Normalization & weighted scoring logic
│   ├── reporter.py          # Rich UI renderer, JSON & CEF exporter
│   ├── batch.py             # Bulk multi-type IoC processing engine
│   └── utils.py             # Memory-safe hashing, defanging, IoC parsing
├── outputs/                 # Export targets (JSON reports, CEF events)
├── tests/                   # Automated unit test suite (pytest)
│   ├── __init__.py
│   ├── test_parsers.py      # Tier-1 scoring validation
│   └── test_utils.py        # Defanging & IoC routing tests
├── .env.example
├── .gitignore
├── requirements.txt
├── main.py                  # CLI entrypoint and argument routing
└── README.md
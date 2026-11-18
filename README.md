# RiskFlow — Automated SIEM-to-Risk Management Pipeline

**Author:** Pranav Harlalka (`RA2411030010305`)  
**Course:** Security Risk Management (`21CSC308T`) — Standalone Project (SRMP)  
**Stack:** Python 3.x, Flask 3.0.3, SQLite 3 (Python `sqlite3`), Jinja2  
**Standards:** ISO/IEC 27005:2022 Information Security Risk Management  
**Architecture Inspiration:** Wazuh Open Source SIEM/XDR

---

## Overview

RiskFlow is a zero-setup, portable web application that implements an automated SIEM-to-Risk pipeline backed by Python's built-in SQLite engine. It ingests security event logs (syslog, auth.log, JSON alerts), matches them against a catalog of 6 built-in Wazuh-style detection rules, and automatically creates/updates risk assessments with mathematically computed Likelihood × Impact scores following ISO/IEC 27005:2022.

### Key Features

- **Zero-Setup & Portable** — Built-in SQLite 3 (`securityriskdb.db`); no external database server or credentials needed
- **Automated SIEM Log Ingestion** — Upload `.log` or `.json` files, paste raw logs, or use 1-click live attack simulators
- **6 Built-in Detection Rules** — SSH Brute-Force, Sudo Escalation, SQL Injection, Path Traversal, Port Scanning, HAR Session Leaks
- **ISO 27005 Risk Scoring** — Automated Likelihood (alert frequency) × Impact (asset criticality + rule severity) calculation
- **5×5 Risk Heatmap Matrix** — Side-by-side Inherent vs. Residual risk visualization
- **Treatment Plan & Control Hierarchy** — Preventive, Detective, and Corrective controls with automated residual risk recalculation
- **Audit Report Generation** — Printable ISO/IEC 27005:2022 report with PDF export (`window.print()`) and Markdown download

---

## Quick Start

### 1. Install Dependencies

Only Flask and python-dotenv are required (SQLite is built into Python):

```bash
pip install -r requirements.txt
```

### 2. Initialize Database & Seed Data

```bash
python get_schema.py --init
```

This creates `securityriskdb.db` and automatically seeds:
- 5 monitored platform assets
- 6 SIEM detection rules (RULE-101 to RULE-106)
- 3 baseline risks with assessments and treatment plans

*(Note: The app will also auto-initialize `securityriskdb.db` on first run if missing!)*

### 3. Inspect Schema (Optional)

```bash
python get_schema.py
```

### 4. Run the Application

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## Project Structure

```
RiskManagementApp/
├── securityriskdb.db         # SQLite database file (created on init)
├── .env.example              # Environment variable template
├── schema.sql                # Complete SQLite DDL + seed data
├── get_schema.py             # CLI: --init (create DB) or --inspect (print schema)
├── rules.json                # 6 Wazuh-style detection rules (JSON reference)
├── siem_engine.py            # SIEM parser, scorer, and auto-upsert engine
├── app.py                    # Flask application (7 routes)
├── requirements.txt          # Flask==3.0.3, python-dotenv==1.0.1
├── sample_logs/
│   ├── auth_bruteforce.log   # Sample SSH + sudo attack logs
│   └── web_attack_alerts.json # Sample SQLi, traversal, scan, HAR alerts
├── templates/
│   ├── layout.html           # Base layout (dark-mode sidebar + nav)
│   ├── dashboard.html        # KPIs, 5×5 heatmaps, risk table, assets
│   ├── ingest_logs.html      # SIEM upload, paste, simulator, alerts feed
│   ├── add_asset.html        # Add monitored asset form
│   ├── add_risk.html         # Manual risk entry form
│   ├── treatment.html        # Treatment plan with control type & residual preview
│   └── report_view.html      # ISO 27005 audit report (print/PDF/Markdown)
├── README.md                 # This file
└── report.md                 # Chapter 6 project report
```

---

## Database Schema (`securityriskdb.db`)

| Table | Purpose |
|-------|---------|
| `asset` | Monitored platform assets with IP address and business criticality (1–5) |
| `detection_rule` | SIEM detection rule catalog (RULE-101 to RULE-106) with regex patterns |
| `risk` | Risk register entries linked to detection rules |
| `risk_assessment` | Junction table with inherent and residual L×I scores per risk-asset pair |
| `treatment_plan` | Treatment options (Mitigate/Accept/Transfer/Avoid) with control types |
| `security_alert` | Raw SIEM alerts matched by the ingestion engine |

---

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Dashboard with KPIs, 5×5 risk matrices, risk table, assets |
| `/ingest_logs` | GET/POST | SIEM log upload, paste, 1-click simulator, alerts feed |
| `/add_asset` | GET/POST | Add a new monitored asset |
| `/add_risk` | GET/POST | Manually log a new risk entry |
| `/treatment/<risk_id>` | GET/POST | Configure treatment plan and recalculate residual risk |
| `/report` | GET | ISO 27005 audit report (screen + print-to-PDF) |
| `/report/export.md` | GET | Download Markdown audit report |

---

## License

This project is developed as an academic submission for SRM Institute of Science and Technology.

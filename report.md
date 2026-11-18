# Chapter 6: RiskFlow — Automated SIEM-to-Risk Management Pipeline

**Course:** 21CSC308T Security Risk Management  
**Project Type:** Standalone Project (SRMP)  
**Author:** Pranav Harlalka (RA2411030010305)

---

## 6.1 Project Overview

RiskFlow is a web-based Automated SIEM-to-Risk Management Pipeline that integrates real-time security event detection with ISO/IEC 27005:2022 risk assessment methodology. Built on Python, Flask, and an embedded zero-setup SQLite database (`securityriskdb.db`), the system ingests raw security logs from diverse sources, matches them against a catalog of Wazuh-style detection rules, and automatically creates, scores, and manages risk assessments with mathematically computed Likelihood × Impact matrices.

### 6.1.1 Problem Statement

Traditional security risk management relies on manual identification and periodic scoring of risks, creating significant delays between threat detection and risk mitigation. Organizations need an automated pipeline that bridges the gap between SIEM alert generation and formal risk assessment frameworks like ISO/IEC 27005.

### 6.1.2 Proposed Solution

RiskFlow automates the entire lifecycle:
1. **Log Ingestion** → Raw syslog, auth.log, or JSON alerts are uploaded, pasted, or simulated via 1-click triggers.
2. **Rule Matching** → Regex-based detection rules identify threat patterns and match them to registered platform assets.
3. **Risk Scoring** → ISO 27005 Likelihood × Impact calculation using alert frequency and asset business criticality.
4. **Treatment Planning** → Preventive, Detective, and Corrective controls with automated residual risk recalculation.
5. **Audit Reporting** → Printable ISO/IEC 27005:2022 compliant reports with PDF and Markdown export.

---

## 6.2 System Architecture

### 6.2.1 Technology Stack

| Component | Technology | Version | Description |
|-----------|-----------|---------|-------------|
| Backend Framework | Python + Flask | 3.x / 3.0.3 | Core web application and REST routing |
| Database Engine | SQLite 3 (`sqlite3`) | Standard Library | Zero-setup portable embedded database (`securityriskdb.db`) |
| Template Engine | Jinja2 | Bundled with Flask | Server-rendered UI with active route state |
| Environment Config | python-dotenv | 1.0.1 | Configuration loader for `.env` |

### 6.2.2 Database Schema (`securityriskdb.db`)

The SQLite database consists of 6 interconnected tables with foreign key enforcement:

- **`asset`** — Monitored platform assets with IP addresses and business criticality ratings (1–5)
- **`detection_rule`** — Catalog of 6 Wazuh-style SIEM detection rules with regex patterns, threat/vulnerability codes, and suggested controls
- **`risk`** — Risk register entries, optionally linked to detection rules
- **`risk_assessment`** — Junction table storing inherent and residual Likelihood × Impact scores per risk-asset pair
- **`treatment_plan`** — Treatment strategies (Mitigate, Accept, Transfer, Avoid) with control types (Preventive, Detective, Corrective)
- **`security_alert`** — Raw SIEM security alerts matched by the ingestion engine

### 6.2.3 Module Architecture

```
┌─────────────────────────────────────────────┐
│                  app.py                     │
│         Flask Application (7 routes)        │
├─────────────────────────────────────────────┤
│              siem_engine.py                 │
│   Log Parser │ Rule Matcher │ Risk Scorer   │
│   Auto-Upsert │ Simulation Generator       │
├─────────────────────────────────────────────┤
│             get_schema.py                   │
│   Database Initializer & Schema Inspector   │
├─────────────────────────────────────────────┤
│         SQLite (securityriskdb.db)          │
│   6 Tables │ Seed Data │ Foreign Keys       │
└─────────────────────────────────────────────┘
```

---

## 6.3 SIEM Engine (`siem_engine.py`)

### 6.3.1 Risk Scoring Model

The automated risk scoring follows ISO/IEC 27005:2022 principles:

**Likelihood Calculation** (based on cumulative alert count per rule-asset pair):
- 1 alert → Likelihood 1 (Rare)
- 2–4 alerts → Likelihood 2 (Unlikely)
- 5–9 alerts → Likelihood 3 (Possible)
- 10–24 alerts → Likelihood 4 (Likely)
- 25+ alerts → Likelihood 5 (Almost Certain)

**Impact Calculation** (combining asset criticality and rule severity):
```
Impact = clamp(round(0.6 × AssetCriticality + 0.4 × RuleSeverity), 1, 5)
```

**Inherent Risk Score:**
```
InherentScore = Likelihood × Impact
```

### 6.3.2 Residual Risk Model

The residual risk calculation accounts for treatment option, control type, and implementation status:

| Treatment | Control Type | Status: Completed | Status: In Progress |
|-----------|-------------|-------------------|---------------------|
| Mitigate | Preventive | L−2, I unchanged | L−1 |
| Mitigate | Detective | L−1, I−1 | L−1 |
| Mitigate | Corrective | L unchanged, I−2 | L−1 |
| Avoid | — | L=1, I−1 | L−1 |
| Transfer | — | L unchanged, I−2 | I−1 |
| Accept | — | No change | No change |

### 6.3.3 Detection Rules Catalog

| Rule ID | Threat | Vulnerability | Severity | Control Type |
|---------|--------|--------------|----------|--------------|
| RULE-101 | T-01: Automated Credential Brute-Force | V-01: Exposed SSH Port | 4/5 | Preventive |
| RULE-102 | T-02: Local Privilege Escalation | V-02: Misconfigured Sudoers | 5/5 | Preventive |
| RULE-103 | T-03: SQL Injection Database Extraction | V-03: Unsanitized User Input | 5/5 | Preventive |
| RULE-104 | T-04: Arbitrary File Read via Path Traversal | V-04: Improper Path Canonicalization | 4/5 | Preventive |
| RULE-105 | T-05: External Network Reconnaissance | V-05: Unfiltered Management Ports | 3/5 | Detective |
| RULE-106 | T-06: Session Token Hijacking via HAR | V-06: Unredacted Session Cookies | 5/5 | Corrective |

---

## 6.4 Flask Application (`app.py`)

### 6.4.1 Route Overview

| Route | Description |
|-------|-------------|
| `GET /` | Dashboard with 4 KPI cards, side-by-side 5×5 inherent/residual risk heatmaps, prioritized risk register, and asset inventory |
| `GET/POST /ingest_logs` | SIEM log file upload (.log/.json), raw log paste area, 4 one-click attack simulators, detection rules catalog, recent alerts feed |
| `GET/POST /add_asset` | Register new monitored asset with IP address and business criticality |
| `GET/POST /add_risk` | Manually log a risk with threat name and vulnerability name |
| `GET/POST /treatment/<id>` | Configure treatment plan with control type/description, auto-recalculate residual risk |
| `GET /report` | ISO 27005 audit report with Print-to-PDF support |
| `GET /report/export.md` | Download Markdown-formatted audit report |

### 6.4.2 Security & Integrity Measures

- **Parameterized SQL queries** (`?` placeholders) throughout to prevent SQL injection
- **Foreign key constraints** strictly enforced on every connection via `PRAGMA foreign_keys = ON;`
- **Zero-credential local storage** using SQLite database file
- **Input sanitization & validation** on all form inputs and file uploads

---

## 6.5 Front-End Templates

### 6.5.1 Design System

- **Color Palette:** Dark-mode slate theme (`--bg-color: #0f172a`, `--surface-color: #1e293b`, `--primary: #3b82f6`)
- **Typography:** Inter font family
- **Components:** Cards, badges (critical/high/medium/low), KPI grid, heatmap grid, responsive tables

### 6.5.2 Key UI Features

- **5×5 Risk Heatmap Matrix** — Interactive grid with risk pill badges, color-coded by score severity (Critical ≥15, High ≥10, Medium ≥5, Low <5)
- **KPI Dashboard Cards** — Monitored Assets, SIEM Alerts, Critical Risk Reduction, Net Risk %
- **1-Click Attack Simulator** — Four scenario buttons for live demonstration without external VM setup
- **Print-Optimized Report** — `@media print` CSS rules hide navigation and optimize for PDF export

---

## 6.6 Verification & Testing

```bash
# 1. Syntax check
python -m py_compile app.py siem_engine.py get_schema.py

# 2. Database initialization
python get_schema.py --init

# 3. Unit & Integration test
python -c "
import siem_engine, app
assert siem_engine.calculate_likelihood(1) == 1
assert siem_engine.calculate_likelihood(15) == 4
assert siem_engine.calculate_likelihood(30) == 5
assert siem_engine.calculate_impact(5, 4) == 5
res_l, res_i, res_s = siem_engine.calculate_residual_risk(4, 4, 'Mitigate', 'Preventive', 'Completed')
assert (res_l, res_i, res_s) == (2, 4, 8)
client = app.app.test_client()
for route in ['/', '/ingest_logs', '/add_asset', '/add_risk', '/report', '/report/export.md']:
    resp = client.get(route)
    assert resp.status_code == 200, f'{route} failed: {resp.status_code}'
print('All SQLite, SIEM engine, and Flask route tests passed!')
"
```

---

## 6.7 Conclusion

RiskFlow demonstrates a fully functional, zero-setup implementation of automated SIEM-to-Risk Management integration. By combining SQLite embedded storage, Wazuh-style detection rules, and ISO/IEC 27005:2022 mathematical risk scoring, the system automates the bridge between security operations (SecOps) and governance, risk, and compliance (GRC) workflows.

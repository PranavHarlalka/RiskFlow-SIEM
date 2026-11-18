PRAGMA foreign_keys = OFF;
DROP TABLE IF EXISTS treatment_plan;
DROP TABLE IF EXISTS risk_assessment;
DROP TABLE IF EXISTS security_alert;
DROP TABLE IF EXISTS risk;
DROP TABLE IF EXISTS detection_rule;
DROP TABLE IF EXISTS asset;
PRAGMA foreign_keys = ON;

-- 1. Monitored Assets Table
CREATE TABLE asset (
    AssetID INTEGER PRIMARY KEY AUTOINCREMENT,
    AssetName TEXT NOT NULL,
    IPAddress TEXT NOT NULL DEFAULT '127.0.0.1',
    AssetType TEXT NOT NULL,
    Owner TEXT NOT NULL,
    BusinessCriticality INTEGER NOT NULL CHECK (BusinessCriticality BETWEEN 1 AND 5),
    CreatedAt TEXT DEFAULT (datetime('now'))
);

-- 2. SIEM Detection Rules Catalog
CREATE TABLE detection_rule (
    RuleID TEXT PRIMARY KEY,
    RuleName TEXT NOT NULL,
    Category TEXT NOT NULL,
    ThreatCode TEXT NOT NULL,
    ThreatName TEXT NOT NULL,
    VulnCode TEXT NOT NULL,
    VulnerabilityName TEXT NOT NULL,
    LogPattern TEXT NOT NULL,
    BaseSeverity INTEGER NOT NULL CHECK (BaseSeverity BETWEEN 1 AND 5),
    DefaultStrategy TEXT NOT NULL DEFAULT 'Mitigate',
    DefaultControlType TEXT NOT NULL DEFAULT 'Preventive',
    SuggestedControl TEXT NOT NULL
);

-- 3. Risk Register Table
CREATE TABLE risk (
    RiskID INTEGER PRIMARY KEY AUTOINCREMENT,
    RuleID TEXT NULL,
    Description TEXT NOT NULL,
    Category TEXT NOT NULL,
    ThreatName TEXT DEFAULT 'Unspecified Threat',
    VulnerabilityName TEXT DEFAULT 'Unspecified Vulnerability',
    Likelihood INTEGER NOT NULL CHECK (Likelihood BETWEEN 1 AND 5),
    Impact INTEGER NOT NULL CHECK (Impact BETWEEN 1 AND 5),
    Status TEXT NOT NULL DEFAULT 'Identified',
    DateIdentified TEXT NOT NULL,
    FOREIGN KEY (RuleID) REFERENCES detection_rule(RuleID) ON DELETE SET NULL
);

-- 4. Risk Assessment Junction & Scoring Table (Inherent vs. Residual)
CREATE TABLE risk_assessment (
    AssessmentID INTEGER PRIMARY KEY AUTOINCREMENT,
    RiskID INTEGER NOT NULL,
    AssetID INTEGER NOT NULL,
    Likelihood INTEGER NOT NULL CHECK (Likelihood BETWEEN 1 AND 5),
    Impact INTEGER NOT NULL CHECK (Impact BETWEEN 1 AND 5),
    RiskScore INTEGER NOT NULL,
    ResidualLikelihood INTEGER NOT NULL CHECK (ResidualLikelihood BETWEEN 1 AND 5),
    ResidualImpact INTEGER NOT NULL CHECK (ResidualImpact BETWEEN 1 AND 5),
    ResidualScore INTEGER NOT NULL,
    AlertCount INTEGER NOT NULL DEFAULT 0,
    AssessmentDate TEXT NOT NULL,
    UNIQUE (RiskID, AssetID),
    FOREIGN KEY (RiskID) REFERENCES risk(RiskID) ON DELETE CASCADE,
    FOREIGN KEY (AssetID) REFERENCES asset(AssetID) ON DELETE CASCADE
);

-- 5. Risk Treatment & Internal Control Plan Table
CREATE TABLE treatment_plan (
    PlanID INTEGER PRIMARY KEY AUTOINCREMENT,
    RiskID INTEGER NOT NULL UNIQUE,
    TreatmentOption TEXT NOT NULL,
    ControlType TEXT NOT NULL DEFAULT 'Preventive',
    ControlDescription TEXT NOT NULL DEFAULT 'Standard security hardening control',
    ResponsiblePerson TEXT NOT NULL,
    Deadline TEXT NOT NULL,
    Status TEXT NOT NULL DEFAULT 'Planned',
    Phase INTEGER NOT NULL DEFAULT 1,
    UpdatedAt TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (RiskID) REFERENCES risk(RiskID) ON DELETE CASCADE
);

-- 6. Raw SIEM Security Alerts Table
CREATE TABLE security_alert (
    AlertID INTEGER PRIMARY KEY AUTOINCREMENT,
    RuleID TEXT NOT NULL,
    AssetID INTEGER NOT NULL,
    SourceIP TEXT DEFAULT '0.0.0.0',
    RawLog TEXT NOT NULL,
    AlertSeverity INTEGER NOT NULL,
    EventTimestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (RuleID) REFERENCES detection_rule(RuleID) ON DELETE CASCADE,
    FOREIGN KEY (AssetID) REFERENCES asset(AssetID) ON DELETE CASCADE
);

-- Seed 5 Monitored Platform Assets
INSERT INTO asset (AssetID, AssetName, IPAddress, AssetType, Owner, BusinessCriticality) VALUES
(1, 'Production Auth & Identity DB', '10.0.1.10', 'Information', 'IAM & Database Team', 5),
(2, 'Customer Web Portal (Nginx)', '10.0.1.20', 'Service', 'Platform Engineering', 4),
(3, 'Linux Bastion SSH Gateway', '10.0.1.30', 'Hardware', 'Cloud Infrastructure', 4),
(4, 'Support Case & HAR Archive Server', '10.0.1.40', 'Software', 'Customer Support Ops', 5),
(5, 'Internal CI/CD Build Runner', '10.0.1.50', 'Software', 'DevSecOps Team', 3);

-- Seed 6 Built-in SIEM Detection Rules
INSERT INTO detection_rule (RuleID, RuleName, Category, ThreatCode, ThreatName, VulnCode, VulnerabilityName, LogPattern, BaseSeverity, DefaultStrategy, DefaultControlType, SuggestedControl) VALUES
('RULE-101', 'SSH Brute-Force Credential Stuffing', 'Technical', 'T-01', 'Automated Credential Brute-Force', 'V-01', 'Exposed SSH Port with Password Auth Enabled', 'Failed password for .* from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', 4, 'Mitigate', 'Preventive', 'Disable SSH password authentication, enforce Ed25519 SSH keys, and enable Fail2Ban rate limiting.'),
('RULE-102', 'Unauthorized Sudo Privilege Escalation', 'Operational', 'T-02', 'Local Privilege Escalation Attempt', 'V-02', 'Misconfigured Sudoers / Excessive Local Permissions', '(NOT in sudoers|authentication failure.*su|COMMAND=.*/bin/shadow)', 5, 'Mitigate', 'Preventive', 'Enforce strict least-privilege sudoers policy, require MFA for privileged elevation, and audit PAM logs.'),
('RULE-103', 'SQL Injection (SQLi) Payload Detected', 'Technical', 'T-03', 'SQL Injection Database Extraction', 'V-03', 'Unsanitized User Input in Web Query Parameters', '(UNION\s+SELECT|OR\s+1=1|--\s*$|information_schema|/etc/passwd)', 5, 'Mitigate', 'Preventive', 'Refactor endpoints to use parameterized prepared statements and enable WAF SQLi blocking rules.'),
('RULE-104', 'Directory Path Traversal Probe', 'Technical', 'T-04', 'Arbitrary File Read via Path Traversal', 'V-04', 'Improper File Path Canonicalization', '(\.\./\.\./|/proc/self/environ|/etc/shadow|boot\.ini)', 4, 'Mitigate', 'Preventive', 'Canonicalize file paths server-side, restrict web root permissions, and block dot-dot-slash URI sequences.'),
('RULE-105', 'Automated Reconnaissance & Port Scan', 'Operational', 'T-05', 'External Network Reconnaissance Scan', 'V-05', 'Unfiltered Public Management Ports', '(Nmap Scripting Engine|Nikto|masscan|sqlmap|SYN_RECV flood)', 3, 'Mitigate', 'Detective', 'Deploy perimeter IDS/IPS rate throttling and restrict management ports via VPC security groups.'),
('RULE-106', 'Unsanitized Support HAR Session Export', 'Compliance', 'T-06', 'Session Token Hijacking via Support Artifacts', 'V-06', 'Unredacted Session Cookies in Diagnostic Captures', '(GET /support/export\.har|Cookie:.*session_id=|Authorization:\s+Bearer)', 5, 'Mitigate', 'Corrective', 'Deploy automated HAR sanitization pipeline to strip session cookies/tokens and rotate compromised tokens.');

-- Seed Initial Baseline Risks & Assessments
INSERT INTO risk (RiskID, RuleID, Description, Category, ThreatName, VulnerabilityName, Likelihood, Impact, Status, DateIdentified) VALUES
(1, 'RULE-101', '[RULE-101] SSH Brute-Force Credential Stuffing on Linux Bastion SSH Gateway', 'Technical', 'T-01: Automated Credential Brute-Force', 'V-01: Exposed SSH Port with Password Auth Enabled', 4, 4, 'Identified', date('now')),
(2, 'RULE-103', '[RULE-103] SQL Injection (SQLi) Payload Detected on Customer Web Portal (Nginx)', 'Technical', 'T-03: SQL Injection Database Extraction', 'V-03: Unsanitized User Input in Web Query Parameters', 3, 4, 'Identified', date('now')),
(3, 'RULE-106', '[RULE-106] Unsanitized Support HAR Session Export on Support Case & HAR Archive Server', 'Compliance', 'T-06: Session Token Hijacking via Support Artifacts', 'V-06: Unredacted Session Cookies in Diagnostic Captures', 2, 5, 'Mitigated', date('now'));

INSERT INTO risk_assessment (RiskID, AssetID, Likelihood, Impact, RiskScore, ResidualLikelihood, ResidualImpact, ResidualScore, AlertCount, AssessmentDate) VALUES
(1, 3, 4, 4, 16, 4, 4, 16, 14, date('now')),
(2, 2, 3, 4, 12, 3, 4, 12, 6, date('now')),
(3, 4, 2, 5, 10, 1, 4, 4, 3, date('now'));

INSERT INTO treatment_plan (RiskID, TreatmentOption, ControlType, ControlDescription, ResponsiblePerson, Deadline, Status, Phase) VALUES
(1, 'Mitigate', 'Preventive', 'Disable SSH password authentication, enforce Ed25519 SSH keys, and enable Fail2Ban rate limiting.', 'Pranav Harlalka (Infra Lead)', date('now', '+7 days'), 'In Progress', 1),
(2, 'Mitigate', 'Preventive', 'Refactor endpoints to use parameterized prepared statements and enable WAF SQLi blocking rules.', 'AppSec Team', date('now', '+14 days'), 'Planned', 1),
(3, 'Mitigate', 'Corrective', 'Deploy automated HAR sanitization pipeline to strip session cookies/tokens and rotate compromised tokens.', 'SecOps Lead', date('now'), 'Completed', 2);

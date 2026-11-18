import re
import json
import datetime
import sqlite3

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Default target IP mapping per rule when no explicit target IP found in log line
_DEFAULT_TARGET_IPS = {
    'RULE-101': '10.0.1.30',
    'RULE-102': '10.0.1.50',
    'RULE-103': '10.0.1.20',
    'RULE-104': '10.0.1.20',
    'RULE-105': '10.0.1.20',
    'RULE-106': '10.0.1.40',
}


def calculate_likelihood(alert_count: int) -> int:
    """
    Maps cumulative SIEM alert count for an (AssetID, RuleID) pair to ISO 27005 Likelihood (1..5):
    1: 1 alert | 2: 2-4 alerts | 3: 5-9 alerts | 4: 10-24 alerts | 5: 25+ alerts
    """
    if alert_count >= 25:
        return 5
    elif alert_count >= 10:
        return 4
    elif alert_count >= 5:
        return 3
    elif alert_count >= 2:
        return 2
    return 1


def calculate_impact(asset_criticality: int, rule_severity: int) -> int:
    """
    Combines Asset Business Criticality (1..5) and Rule Base Severity (1..5):
    Impact = clamp(round(0.6 * C_asset + 0.4 * S_rule), 1, 5)
    """
    raw = round(0.6 * int(asset_criticality) + 0.4 * int(rule_severity))
    return max(1, min(5, raw))


def calculate_residual_risk(
    inherent_likelihood: int,
    inherent_impact: int,
    treatment_option: str,
    control_type: str,
    status: str
) -> tuple:
    """
    Returns (residual_likelihood, residual_impact, residual_score).
    Reductions apply fullest effect when status == 'Completed', and partial (1 level) when 'In Progress'.
    """
    L = int(inherent_likelihood)
    I = int(inherent_impact)

    if status not in ('Completed', 'In Progress') or treatment_option == 'Accept':
        return L, I, L * I

    if status == 'In Progress':
        # Partial reduction while implementation is underway
        res_L = max(1, L - 1) if treatment_option in ('Mitigate', 'Avoid') else L
        res_I = max(1, I - 1) if treatment_option == 'Transfer' else I
        return res_L, res_I, res_L * res_I

    # status == 'Completed'
    if treatment_option == 'Avoid':
        res_L, res_I = 1, max(1, I - 1)
    elif treatment_option == 'Transfer':
        res_L, res_I = L, max(1, I - 2)
    elif treatment_option == 'Mitigate':
        if control_type == 'Preventive':
            res_L, res_I = max(1, L - 2), I
        elif control_type == 'Detective':
            res_L, res_I = max(1, L - 1), max(1, I - 1)
        elif control_type == 'Corrective':
            res_L, res_I = L, max(1, I - 2)
        else:
            res_L, res_I = max(1, L - 1), I
    else:
        res_L, res_I = L, I

    return res_L, res_I, res_L * res_I


def fetch_rules_and_assets(cursor):
    """Loads all rows from detection_rule and asset tables as Python dicts."""
    cursor.execute("SELECT * FROM detection_rule ORDER BY RuleID")
    rules = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM asset ORDER BY AssetID")
    assets = [dict(r) for r in cursor.fetchall()]

    # Build lookup indices
    asset_by_ip = {}
    asset_by_name = {}
    highest_crit_asset = None
    for a in assets:
        asset_by_ip[a['IPAddress']] = a
        asset_by_name[a['AssetName'].lower()] = a
        if highest_crit_asset is None or a['BusinessCriticality'] > highest_crit_asset['BusinessCriticality']:
            highest_crit_asset = a

    return rules, assets, asset_by_ip, asset_by_name, highest_crit_asset


def parse_log_content(raw_text, filename, rules, assets, asset_by_ip, asset_by_name, highest_crit_asset):
    """
    Parses raw log text or JSON alert array against detection rules.
    Returns list of matched event dicts.
    """
    matched_events = []

    # Determine if JSON format
    is_json = False
    if filename and filename.lower().endswith('.json'):
        is_json = True
    elif raw_text.strip().startswith('['):
        is_json = True

    if is_json:
        try:
            alert_items = json.loads(raw_text)
        except json.JSONDecodeError:
            return matched_events

        for item in alert_items:
            raw_log = item.get('raw_log', item.get('message', ''))
            target_ip = item.get('target_ip', '')
            source_ip = item.get('source_ip', '0.0.0.0')

            for rule in rules:
                pattern = rule['LogPattern']
                try:
                    if re.search(pattern, raw_log, re.IGNORECASE):
                        # Resolve target asset
                        asset = asset_by_ip.get(target_ip)
                        if not asset:
                            default_ip = _DEFAULT_TARGET_IPS.get(rule['RuleID'], '')
                            asset = asset_by_ip.get(default_ip, highest_crit_asset)

                        if asset:
                            matched_events.append({
                                'rule': rule,
                                'asset': asset,
                                'source_ip': source_ip,
                                'raw_log': raw_log[:2000],
                                'timestamp': item.get('timestamp', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                            })
                        break  # One rule match per log line
                except re.error:
                    continue
    else:
        # Line-by-line text log parsing
        lines = raw_text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            for rule in rules:
                pattern = rule['LogPattern']
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extract IPs from line
                        all_ips = IP_REGEX.findall(line)
                        target_asset = None
                        source_ip = '185.220.101.42'

                        for ip in all_ips:
                            if ip in asset_by_ip:
                                target_asset = asset_by_ip[ip]
                            else:
                                source_ip = ip

                        if not target_asset:
                            default_ip = _DEFAULT_TARGET_IPS.get(rule['RuleID'], '')
                            target_asset = asset_by_ip.get(default_ip, highest_crit_asset)

                        if target_asset:
                            matched_events.append({
                                'rule': rule,
                                'asset': target_asset,
                                'source_ip': source_ip,
                                'raw_log': line[:2000],
                                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            })
                        break  # One rule match per log line
                except re.error:
                    continue

    return matched_events


def process_and_upsert_alerts(conn, matched_events):
    """
    Inserts matched events as security alerts and auto-creates/updates risks and assessments in SQLite.
    Returns summary dict.
    """
    cursor = conn.cursor()
    affected_pairs = set()

    for event in matched_events:
        rule = event['rule']
        asset = event['asset']
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Insert security alert using ? placeholders
        cursor.execute(
            """INSERT INTO security_alert (RuleID, AssetID, SourceIP, RawLog, AlertSeverity, EventTimestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (rule['RuleID'], asset['AssetID'], event['source_ip'],
             event['raw_log'], rule['BaseSeverity'], now_str)
        )
        affected_pairs.add((rule['RuleID'], asset['AssetID']))

    # Process each affected (RuleID, AssetID) pair
    today_str = datetime.date.today().isoformat()
    for rule_id, asset_id in affected_pairs:
        # Get alert count
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM security_alert WHERE RuleID = ? AND AssetID = ?",
            (rule_id, asset_id)
        )
        cnt = cursor.fetchone()['cnt']

        # Get rule details
        cursor.execute("SELECT * FROM detection_rule WHERE RuleID = ?", (rule_id,))
        rule_row = cursor.fetchone()
        rule = dict(rule_row) if rule_row else None

        # Get asset details
        cursor.execute("SELECT * FROM asset WHERE AssetID = ?", (asset_id,))
        asset_row = cursor.fetchone()
        asset = dict(asset_row) if asset_row else None

        if not rule or not asset:
            continue

        likelihood = calculate_likelihood(cnt)
        impact = calculate_impact(asset['BusinessCriticality'], rule['BaseSeverity'])
        risk_score = likelihood * impact

        # Check if risk already exists for this (RuleID, AssetID) pair
        cursor.execute(
            """SELECT r.RiskID FROM risk r
               JOIN risk_assessment ra ON r.RiskID = ra.RiskID
               WHERE r.RuleID = ? AND ra.AssetID = ?""",
            (rule_id, asset_id)
        )
        existing = cursor.fetchone()

        if existing:
            risk_id = existing['RiskID']

            # Update risk likelihood/impact
            cursor.execute(
                "UPDATE risk SET Likelihood = ?, Impact = ? WHERE RiskID = ?",
                (likelihood, impact, risk_id)
            )

            # Check treatment plan for residual calculation
            cursor.execute(
                "SELECT TreatmentOption, ControlType, Status FROM treatment_plan WHERE RiskID = ?",
                (risk_id,)
            )
            tp_row = cursor.fetchone()
            tp = dict(tp_row) if tp_row else None

            if tp:
                res_l, res_i, res_s = calculate_residual_risk(
                    likelihood, impact,
                    tp['TreatmentOption'], tp['ControlType'], tp['Status']
                )
            else:
                res_l, res_i, res_s = likelihood, impact, risk_score

            # Update risk_assessment
            cursor.execute(
                """UPDATE risk_assessment
                   SET Likelihood = ?, Impact = ?, RiskScore = ?,
                       ResidualLikelihood = ?, ResidualImpact = ?, ResidualScore = ?,
                       AlertCount = ?, AssessmentDate = ?
                   WHERE RiskID = ? AND AssetID = ?""",
                (likelihood, impact, risk_score, res_l, res_i, res_s,
                 cnt, today_str, risk_id, asset_id)
            )
        else:
            # Create new risk
            description = f"[{rule['RuleID']}] {rule['RuleName']} on {asset['AssetName']}"
            threat_name = f"{rule['ThreatCode']}: {rule['ThreatName']}"
            vuln_name = f"{rule['VulnCode']}: {rule['VulnerabilityName']}"

            cursor.execute(
                """INSERT INTO risk (RuleID, Description, Category, ThreatName, VulnerabilityName,
                                     Likelihood, Impact, Status, DateIdentified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'Identified', ?)""",
                (rule['RuleID'], description, rule['Category'], threat_name, vuln_name,
                 likelihood, impact, today_str)
            )
            risk_id = cursor.lastrowid

            # Create risk_assessment
            cursor.execute(
                """INSERT INTO risk_assessment (RiskID, AssetID, Likelihood, Impact, RiskScore,
                                                ResidualLikelihood, ResidualImpact, ResidualScore,
                                                AlertCount, AssessmentDate)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (risk_id, asset_id, likelihood, impact, risk_score,
                 likelihood, impact, risk_score, cnt, today_str)
            )

            # Auto-create default treatment plan
            deadline_str = (datetime.date.today() + datetime.timedelta(days=14)).isoformat()
            cursor.execute(
                """INSERT INTO treatment_plan (RiskID, TreatmentOption, ControlType, ControlDescription,
                                               ResponsiblePerson, Deadline, Status, Phase)
                   VALUES (?, ?, ?, ?, ?, ?, 'Planned', 1)""",
                (risk_id, rule['DefaultStrategy'], rule['DefaultControlType'],
                 rule['SuggestedControl'], 'Security Team', deadline_str)
            )

    conn.commit()

    return {
        'alerts_ingested': len(matched_events),
        'risks_updated': len(affected_pairs),
    }


def build_simulation_logs(scenario):
    """Generates synthetic log data for 1-click attack simulation demos."""
    now = datetime.datetime.now()

    if scenario == 'ssh_bruteforce':
        lines = []
        users = ['root', 'admin', 'ubuntu', 'deploy', 'git', 'oracle', 'postgres', 'backup', 'nagios', 'jenkins', 'www-data', 'mysql']
        for i, user in enumerate(users):
            ts = (now + datetime.timedelta(seconds=i * 2)).strftime('%b %d %H:%M:%S')
            lines.append(f"{ts} authdb sshd[{13000+i}]: Failed password for {user} from 198.51.100.77 port {45000+i} ssh2")
        return '\n'.join(lines)

    elif scenario == 'sqli_attack':
        payloads = [
            "GET /login?user=admin'%20OR%201=1-- HTTP/1.1",
            "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1",
            "GET /search?q=UNION%20SELECT%20table_name%20FROM%20information_schema.tables-- HTTP/1.1",
            "GET /products?cat=1%20OR%201=1-- HTTP/1.1",
            "GET /api/data?filter=';DROP%20TABLE%20users-- HTTP/1.1",
            "POST /login HTTP/1.1 Body: username=admin&password='%20OR%201=1--",
            "GET /report?id=1%20UNION%20SELECT%20NULL,NULL,username,password%20FROM%20users-- HTTP/1.1",
            "GET /download?file=/etc/passwd HTTP/1.1",
            "GET /api/search?q=%27%20UNION%20SELECT%20schema_name%20FROM%20information_schema.schemata-- HTTP/1.1",
            "GET /page?id=1%20AND%201=1-- HTTP/1.1",
        ]
        lines = []
        for i, payload in enumerate(payloads):
            ts = (now + datetime.timedelta(seconds=i * 2)).strftime('%Y-%m-%dT%H:%M:%S')
            lines.append(f"[{ts}] 10.0.1.20 <- 203.0.113.88 | {payload}")
        return '\n'.join(lines)

    elif scenario == 'sudo_escalation':
        users = ['www-data', 'contractor', 'intern', 'guest', 'www-data', 'temp_user', 'contractor', 'intern']
        lines = []
        for i, user in enumerate(users):
            ts = (now + datetime.timedelta(seconds=i * 3)).strftime('%b %d %H:%M:%S')
            lines.append(f"{ts} cicd sudo: {user} : user NOT in sudoers ; TTY=pts/{i} ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow")
        return '\n'.join(lines)

    elif scenario == 'har_leak':
        tokens = [
            'session_id=eyJhbGciOiJSUzI1NiJ9.okta_admin_live_token_001',
            'session_id=eyJhbGciOiJIUzI1NiJ9.zendesk_agent_session_002',
            'session_id=eyJhbGciOiJSUzI1NiJ9.freshdesk_admin_token_003',
            'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.salesforce_api_key_004',
            'session_id=eyJhbGciOiJIUzI1NiJ9.intercom_session_token_005',
            'Cookie: session_id=eyJhbGciOiJSUzI1NiJ9.hubspot_unredacted_006',
        ]
        lines = []
        for i, token in enumerate(tokens):
            ts = (now + datetime.timedelta(seconds=i * 5)).strftime('%Y-%m-%dT%H:%M:%S')
            lines.append(f"[{ts}] GET /support/export.har HTTP/1.1 | Host: 10.0.1.40 | {token}")
        return '\n'.join(lines)

    return ''

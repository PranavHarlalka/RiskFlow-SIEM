import os
import datetime
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, Response
from dotenv import load_dotenv
import siem_engine

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex())


def get_db_connection():
    db_path = os.getenv('DB_PATH', 'securityriskdb.db')
    if not os.path.exists(db_path):
        from get_schema import init_database
        init_database()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


@app.route('/')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch risks with full join across risk, risk_assessment, asset, and treatment_plan
    cursor.execute('''
        SELECT r.RiskID as risk_id,
               r.RuleID as rule_id,
               r.Description as risk_title,
               r.Category as category,
               r.ThreatName as threat_name,
               r.VulnerabilityName as vulnerability_name,
               a.AssetName as asset_name,
               a.IPAddress as ip_address,
               ra.Likelihood as likelihood_name,
               ra.Impact as impact_name,
               ra.RiskScore as risk_score,
               ra.ResidualLikelihood as residual_likelihood,
               ra.ResidualImpact as residual_impact,
               ra.ResidualScore as residual_score,
               ra.AlertCount as alert_count,
               r.DateIdentified as identified_date,
               COALESCE(tp.TreatmentOption, 'Unassigned') as treatment_strategy,
               COALESCE(tp.ControlType, 'None') as control_type,
               COALESCE(tp.Status, 'Planned') as treatment_status
        FROM risk r
        JOIN risk_assessment ra ON r.RiskID = ra.RiskID
        JOIN asset a ON ra.AssetID = a.AssetID
        LEFT JOIN treatment_plan tp ON r.RiskID = tp.RiskID
        ORDER BY ra.RiskScore DESC
    ''')
    risks = [dict(row) for row in cursor.fetchall()]

    # Fetch assets
    cursor.execute('''
        SELECT AssetID as asset_id,
               AssetName as asset_name,
               IPAddress as ip_address,
               AssetType as category_name,
               Owner as owner,
               BusinessCriticality as criticality
        FROM asset ORDER BY AssetID
    ''')
    assets = [dict(row) for row in cursor.fetchall()]

    # Build 5x5 Risk Matrix Grids
    inherent_matrix = {l: {i: [] for i in range(1, 6)} for l in range(1, 6)}
    residual_matrix = {l: {i: [] for i in range(1, 6)} for l in range(1, 6)}

    for risk in risks:
        inherent_matrix[risk['likelihood_name']][risk['impact_name']].append(risk)
        residual_matrix[risk['residual_likelihood']][risk['residual_impact']].append(risk)

    # KPIs
    cursor.execute("SELECT COUNT(*) as cnt FROM security_alert")
    total_alerts = cursor.fetchone()['cnt']

    critical_inherent_count = sum(1 for r in risks if r['risk_score'] >= 15)
    critical_residual_count = sum(1 for r in risks if r['residual_score'] >= 15)

    total_inherent = sum(r['risk_score'] for r in risks)
    total_residual = sum(r['residual_score'] for r in risks)
    if risks and total_inherent > 0:
        risk_reduction_pct = round((1 - (total_residual / total_inherent)) * 100, 1)
    else:
        risk_reduction_pct = 0.0

    kpis = {
        'total_assets': len(assets),
        'total_alerts': total_alerts,
        'critical_inherent_count': critical_inherent_count,
        'critical_residual_count': critical_residual_count,
        'risk_reduction_pct': risk_reduction_pct,
    }

    conn.close()

    return render_template('dashboard.html',
                           risks=risks, assets=assets,
                           inherent_matrix=inherent_matrix,
                           residual_matrix=residual_matrix,
                           kpis=kpis)


@app.route('/ingest_logs', methods=['GET', 'POST'])
def ingest_logs():
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()
        rules, assets, asset_by_ip, asset_by_name, highest_crit_asset = siem_engine.fetch_rules_and_assets(cursor)

        raw_text = ''
        filename = 'paste.log'

        # Check 1-click simulator
        scenario = request.form.get('scenario')
        if scenario:
            raw_text = siem_engine.build_simulation_logs(scenario)
            filename = f'simulation_{scenario}.log'
        else:
            # Check file upload
            uploaded = request.files.get('log_file')
            if uploaded and uploaded.filename:
                filename = uploaded.filename
                raw_text = uploaded.read().decode('utf-8', errors='replace')
            else:
                # Raw log paste
                raw_text = request.form.get('raw_logs', '')

        if raw_text.strip():
            matched = siem_engine.parse_log_content(
                raw_text, filename, rules, assets,
                asset_by_ip, asset_by_name, highest_crit_asset
            )
            summary = siem_engine.process_and_upsert_alerts(conn, matched)
            flash(
                f"SIEM Engine processed {summary['alerts_ingested']} security alerts "
                f"and auto-updated {summary['risks_updated']} risk assessments!",
                'success'
            )
        else:
            flash('No log data provided. Please upload a file, paste logs, or use the simulator.', 'warning')

        conn.close()
        return redirect(url_for('ingest_logs'))

    # GET request
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM detection_rule ORDER BY RuleID')
    rules = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT sa.*, a.AssetName, a.IPAddress, dr.RuleName, dr.ThreatCode
        FROM security_alert sa
        JOIN asset a ON sa.AssetID = a.AssetID
        JOIN detection_rule dr ON sa.RuleID = dr.RuleID
        ORDER BY sa.AlertID DESC LIMIT 40
    ''')
    alerts = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return render_template('ingest_logs.html', rules=rules, alerts=alerts)


@app.route('/add_asset', methods=['GET', 'POST'])
def add_asset():
    if request.method == 'POST':
        asset_name = request.form['asset_name']
        ip_address = request.form.get('ip_address', '127.0.0.1')
        asset_type = request.form['asset_type']
        owner = request.form['owner']
        business_criticality = int(request.form['business_criticality'])

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO asset (AssetName, IPAddress, AssetType, Owner, BusinessCriticality)
            VALUES (?, ?, ?, ?, ?)
        ''', (asset_name, ip_address, asset_type, owner, business_criticality))
        conn.commit()
        conn.close()

        flash('Asset successfully added!', 'success')
        return redirect(url_for('dashboard'))

    categories = ['Hardware', 'Software', 'Information', 'Service', 'People', 'Other']
    return render_template('add_asset.html', categories=categories)


@app.route('/add_risk', methods=['GET', 'POST'])
def add_risk():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        description = request.form['description']
        category = request.form['category']
        threat_name = request.form.get('threat_name', 'Unspecified Threat')
        vulnerability_name = request.form.get('vulnerability_name', 'Unspecified Vulnerability')
        likelihood = int(request.form['likelihood'])
        impact = int(request.form['impact'])
        asset_id = request.form.get('asset_id')
        score = likelihood * impact
        today_str = datetime.date.today().isoformat()

        cursor.execute('''
            INSERT INTO risk (Description, Category, ThreatName, VulnerabilityName,
                              Likelihood, Impact, Status, DateIdentified)
            VALUES (?, ?, ?, ?, ?, ?, 'Identified', ?)
        ''', (description, category, threat_name, vulnerability_name,
              likelihood, impact, today_str))

        risk_id = cursor.lastrowid

        if asset_id:
            cursor.execute('''
                INSERT INTO risk_assessment (RiskID, AssetID, Likelihood, Impact, RiskScore,
                                             ResidualLikelihood, ResidualImpact, ResidualScore,
                                             AlertCount, AssessmentDate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            ''', (risk_id, asset_id, likelihood, impact, score,
                  likelihood, impact, score, today_str))

        conn.commit()
        conn.close()
        flash('Risk successfully added!', 'success')
        return redirect(url_for('dashboard'))

    # GET request
    cursor.execute('SELECT AssetID as asset_id, AssetName as asset_name FROM asset')
    assets = [dict(row) for row in cursor.fetchall()]
    categories = ['Technical', 'Operational', 'Compliance', 'Financial', 'Strategic']

    conn.close()

    return render_template('add_risk.html', assets=assets, categories=categories)


@app.route('/treatment/<int:risk_id>', methods=['GET', 'POST'])
def treatment(risk_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        treatment_option = request.form['treatment_option']
        control_type = request.form.get('control_type', 'Preventive')
        control_description = request.form.get('control_description', 'Standard security hardening control')
        responsible_person = request.form['responsible_person']
        deadline = request.form['deadline']
        status = request.form['status']
        phase = int(request.form.get('phase', 1))

        # Upsert treatment plan
        cursor.execute('SELECT PlanID FROM treatment_plan WHERE RiskID = ?', (risk_id,))
        existing_plan = cursor.fetchone()

        if existing_plan:
            cursor.execute('''
                UPDATE treatment_plan
                SET TreatmentOption=?, ControlType=?, ControlDescription=?,
                    ResponsiblePerson=?, Deadline=?, Status=?, Phase=?,
                    UpdatedAt=(datetime('now'))
                WHERE RiskID=?
            ''', (treatment_option, control_type, control_description,
                  responsible_person, deadline, status, phase, risk_id))
        else:
            cursor.execute('''
                INSERT INTO treatment_plan (RiskID, TreatmentOption, ControlType, ControlDescription,
                                            ResponsiblePerson, Deadline, Status, Phase)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (risk_id, treatment_option, control_type, control_description,
                  responsible_person, deadline, status, phase))

        # Recalculate residual risk
        cursor.execute(
            'SELECT Likelihood, Impact FROM risk_assessment WHERE RiskID = ? LIMIT 1',
            (risk_id,)
        )
        ra = cursor.fetchone()

        if ra:
            res_l, res_i, res_s = siem_engine.calculate_residual_risk(
                ra['Likelihood'], ra['Impact'], treatment_option, control_type, status
            )
            cursor.execute(
                '''UPDATE risk_assessment
                   SET ResidualLikelihood=?, ResidualImpact=?, ResidualScore=?
                   WHERE RiskID=?''',
                (res_l, res_i, res_s, risk_id)
            )

        # Update risk status
        new_status = 'Mitigated' if status == 'Completed' else 'In Treatment'
        cursor.execute('UPDATE risk SET Status=? WHERE RiskID=?', (new_status, risk_id))

        conn.commit()
        conn.close()
        flash('Treatment plan updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    # GET request
    cursor.execute('''
        SELECT r.RiskID, r.Description as risk_title, r.ThreatName as threat_name,
               r.VulnerabilityName as vulnerability_name, r.Category as category
        FROM risk r WHERE r.RiskID = ?
    ''', (risk_id,))
    risk_row = cursor.fetchone()
    risk = dict(risk_row) if risk_row else None

    cursor.execute('''
        SELECT ra.RiskScore, ra.ResidualScore, ra.Likelihood, ra.Impact,
               ra.ResidualLikelihood, ra.ResidualImpact
        FROM risk_assessment ra WHERE ra.RiskID = ? LIMIT 1
    ''', (risk_id,))
    assessment_row = cursor.fetchone()
    assessment = dict(assessment_row) if assessment_row else None

    cursor.execute('''
        SELECT TreatmentOption as treatment_strategy, ControlType as control_type,
               ControlDescription as control_description,
               ResponsiblePerson as responsible_person,
               Deadline as target_date, Status as status_id, Phase as phase
        FROM treatment_plan WHERE RiskID = ?
    ''', (risk_id,))
    plan_row = cursor.fetchone()
    plan = dict(plan_row) if plan_row else None

    statuses = ['Planned', 'In Progress', 'Completed', 'On Hold']
    treatment_options = ['Mitigate', 'Accept', 'Transfer', 'Avoid']
    control_types = ['Preventive', 'Detective', 'Corrective']

    conn.close()

    return render_template('treatment.html', risk=risk, risk_id=risk_id, plan=plan,
                           assessment=assessment, statuses=statuses,
                           treatment_options=treatment_options, control_types=control_types)


@app.route('/report')
def report():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Assets
    cursor.execute('SELECT * FROM asset ORDER BY AssetID')
    assets = [dict(row) for row in cursor.fetchall()]

    # Rules
    cursor.execute('SELECT * FROM detection_rule ORDER BY RuleID')
    rules = [dict(row) for row in cursor.fetchall()]

    # Risks with assessments and treatments
    cursor.execute('''
        SELECT r.RiskID, r.RuleID, r.Description, r.Category, r.ThreatName, r.VulnerabilityName,
               r.Status as RiskStatus,
               a.AssetName, a.IPAddress, a.BusinessCriticality,
               ra.Likelihood, ra.Impact, ra.RiskScore,
               ra.ResidualLikelihood, ra.ResidualImpact, ra.ResidualScore, ra.AlertCount,
               COALESCE(tp.TreatmentOption, 'Unassigned') as TreatmentOption,
               COALESCE(tp.ControlType, 'None') as ControlType,
               COALESCE(tp.ControlDescription, 'N/A') as ControlDescription,
               COALESCE(tp.Status, 'Planned') as TreatmentStatus,
               COALESCE(tp.ResponsiblePerson, 'Unassigned') as ResponsiblePerson
        FROM risk r
        JOIN risk_assessment ra ON r.RiskID = ra.RiskID
        JOIN asset a ON ra.AssetID = a.AssetID
        LEFT JOIN treatment_plan tp ON r.RiskID = tp.RiskID
        ORDER BY ra.RiskScore DESC
    ''')
    risks = [dict(row) for row in cursor.fetchall()]

    # KPIs
    cursor.execute("SELECT COUNT(*) as cnt FROM security_alert")
    total_alerts = cursor.fetchone()['cnt']

    total_inherent = sum(r['RiskScore'] for r in risks) if risks else 0
    total_residual = sum(r['ResidualScore'] for r in risks) if risks else 0
    if risks and total_inherent > 0:
        risk_reduction_pct = round((1 - (total_residual / total_inherent)) * 100, 1)
    else:
        risk_reduction_pct = 0.0

    kpis = {
        'total_assets': len(assets),
        'total_alerts': total_alerts,
        'total_risks': len(risks),
        'critical_inherent': sum(1 for r in risks if r['RiskScore'] >= 15),
        'critical_residual': sum(1 for r in risks if r['ResidualScore'] >= 15),
        'risk_reduction_pct': risk_reduction_pct,
    }

    today_str = datetime.date.today().isoformat()
    conn.close()

    return render_template('report_view.html',
                           assets=assets, rules=rules, risks=risks, kpis=kpis,
                           today_date=today_str)


@app.route('/report/export.md')
def report_export_md():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM asset ORDER BY AssetID')
    assets = [dict(row) for row in cursor.fetchall()]

    cursor.execute('SELECT * FROM detection_rule ORDER BY RuleID')
    rules = [dict(row) for row in cursor.fetchall()]

    cursor.execute('''
        SELECT r.RiskID, r.RuleID, r.Description, r.Category, r.ThreatName, r.VulnerabilityName,
               r.Status as RiskStatus,
               a.AssetName, a.IPAddress, a.BusinessCriticality,
               ra.Likelihood, ra.Impact, ra.RiskScore,
               ra.ResidualLikelihood, ra.ResidualImpact, ra.ResidualScore, ra.AlertCount,
               COALESCE(tp.TreatmentOption, 'Unassigned') as TreatmentOption,
               COALESCE(tp.ControlType, 'None') as ControlType,
               COALESCE(tp.ControlDescription, 'N/A') as ControlDescription,
               COALESCE(tp.Status, 'Planned') as TreatmentStatus,
               COALESCE(tp.ResponsiblePerson, 'Unassigned') as ResponsiblePerson
        FROM risk r
        JOIN risk_assessment ra ON r.RiskID = ra.RiskID
        JOIN asset a ON ra.AssetID = a.AssetID
        LEFT JOIN treatment_plan tp ON r.RiskID = tp.RiskID
        ORDER BY ra.RiskScore DESC
    ''')
    risks = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT COUNT(*) as cnt FROM security_alert")
    total_alerts = cursor.fetchone()['cnt']

    total_inherent = sum(r['RiskScore'] for r in risks) if risks else 0
    total_residual = sum(r['ResidualScore'] for r in risks) if risks else 0
    if risks and total_inherent > 0:
        risk_reduction_pct = round((1 - (total_residual / total_inherent)) * 100, 1)
    else:
        risk_reduction_pct = 0.0

    conn.close()

    today = datetime.date.today().isoformat()

    md = f"""# RiskFlow — ISO/IEC 27005:2022 Security Risk Assessment & Audit Report

**Generated:** {today}
**Framework:** ISO/IEC 27005:2022 Information Security Risk Management
**System:** RiskFlow Automated SIEM-to-Risk Management Pipeline (SQLite Backend)

---

## 1. Executive Summary & Risk Posture

| Metric | Value |
|--------|-------|
| Monitored Assets | {len(assets)} |
| SIEM Alerts Processed | {total_alerts} |
| Active Risk Entries | {len(risks)} |
| Critical Inherent Risks (Score ≥ 15) | {sum(1 for r in risks if r['RiskScore'] >= 15)} |
| Critical Residual Risks (Score ≥ 15) | {sum(1 for r in risks if r['ResidualScore'] >= 15)} |
| Net Risk Reduction | {risk_reduction_pct}% |

---

## 2. Monitored Asset Inventory & Business Criticality Valuation

| Asset ID | Asset Name | IP Address | Type | Owner | Criticality |
|----------|-----------|------------|------|-------|-------------|
"""
    for a in assets:
        md += f"| {a['AssetID']} | {a['AssetName']} | {a['IPAddress']} | {a['AssetType']} | {a['Owner']} | {a['BusinessCriticality']}/5 |\n"

    md += """
---

## 3. Automated SIEM Threat & Vulnerability Catalog

| Rule ID | Rule Name | Threat Code | Vuln Code | Severity | Control Type |
|---------|-----------|-------------|-----------|----------|-------------|
"""
    for r in rules:
        md += f"| {r['RuleID']} | {r['RuleName']} | {r['ThreatCode']} | {r['VulnCode']} | {r['BaseSeverity']}/5 | {r['DefaultControlType']} |\n"

    md += """
---

## 4. Inherent vs. Residual Risk Register & Control Hierarchy

| Risk ID | Description | Asset | Inherent (L×I=Score) | Control | Residual (L×I=Score) | Status |
|---------|-------------|-------|---------------------|---------|---------------------|--------|
"""
    for r in risks:
        md += (f"| R-{r['RiskID']} | {r['Description'][:60]} | {r['AssetName']} | "
               f"{r['Likelihood']}×{r['Impact']}={r['RiskScore']} | "
               f"{r['ControlType']} ({r['TreatmentOption']}) | "
               f"{r['ResidualLikelihood']}×{r['ResidualImpact']}={r['ResidualScore']} | "
               f"{r['TreatmentStatus']} |\n")

    md += """
---

## 5. Formal Audit Issues & Residual Risk Sign-Off

| # | Audit Finding | Inherent Score | Residual Score | Owner | Sign-Off |
|---|--------------|----------------|----------------|-------|----------|
"""
    for idx, r in enumerate(risks, 1):
        status_icon = '✅' if r['TreatmentStatus'] == 'Completed' else '⏳'
        md += (f"| {idx} | {r['Description'][:50]} | {r['RiskScore']} | "
               f"{r['ResidualScore']} | {r['ResponsiblePerson']} | {status_icon} {r['TreatmentStatus']} |\n")

    md += f"\n---\n\n*Report generated by RiskFlow on {today}*\n"

    return Response(
        md,
        mimetype='text/markdown',
        headers={'Content-Disposition': 'attachment; filename="RiskFlow_ISO27005_Audit_Report.md"'}
    )


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true', port=5000)

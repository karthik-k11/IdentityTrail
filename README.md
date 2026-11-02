# IdentityTrail

**Cloud Identity Attack Investigation & Forensics Workbench**

IdentityTrail is a local cybersecurity investigation workbench designed to analyze AWS CloudTrail audit logs, identify suspicious identity-related activities, and help security analysts investigate potential cloud security incidents.

## Project Objectives

- Analyze AWS CloudTrail JSON logs.
- Investigate cloud identity and API activity.
- Detect potentially suspicious behavior using transparent rules.
- Reconstruct chronological incident timelines.
- Generate evidence-based investigation reports.

## Technology Stack

- **Language:** Python
- **Backend:** Flask
- **Frontend:** HTML, CSS, JavaScript
- **Data Processing:** Pandas
- **Database:** SQLite
- **Visualization:** Chart.js
- **Testing:** pytest
- **Version Control:** Git

## Development Scope

Development will follow three phases:

1. **Basic:** CloudTrail ingestion, event analysis, rule-based detection, identity investigation, timelines, and basic reports.
2. **Intermediate:** Identity correlation, risk scoring, attack sequence analysis, and advanced investigation.
3. **Advanced:** Cross-account analysis, attack-path reconstruction, threat intelligence enrichment, and advanced reporting.

Development starts with the Basic phase. Later phases will only begin after explicit approval.

## Project Structure

```text
IdentityTrail/
├── app.py
├── config.py
├── database.py
├── requirements.txt
├── .gitignore
├── README.md
├── models/
├── services/
├── rules/
├── templates/
├── static/
│   ├── css/
│   └── js/
├── tests/
├── sample_data/
└── instance/
```

## Local Setup

```powershell
# Create virtual environment
py -m venv .venv

# Activate environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

## Security and Privacy

- Runs locally by default.
- Uploaded audit logs are treated as untrusted input.
- Uploaded files are never executed.
- No paid APIs or cloud infrastructure are required.
- Investigation findings are indicators for further analysis, not automatic proof of malicious activity.

## Project Status

**Current stage:** Initial project setup.

Application features will be implemented incrementally, with testing and documentation at each milestone.
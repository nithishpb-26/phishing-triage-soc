# 🛡️ Phishing Triage SOC Platform

An end-to-end cybersecurity and Security Operations Center (SOC) platform for **phishing email analysis, IOC extraction, threat intelligence, risk-based triage, automated incident response, SIEM detection, MITRE ATT&CK mapping, and tamper-evident security auditing**.

The project combines a Python/Flask phishing analysis application with **VirusTotal, SQLite, n8n, PostgreSQL, Wazuh, Windows PowerShell monitoring, MITRE ATT&CK, and automated response logging**.

---

## 📌 Project Overview

Phishing is one of the most common techniques used by attackers to gain initial access to organizations.

This project demonstrates how a SOC can process a suspicious email from initial analysis through automated triage and incident storage.

The platform performs:

1. Phishing email parsing
2. Email header analysis
3. IOC extraction
4. URL and domain analysis
5. Attachment analysis
6. File hash analysis
7. VirusTotal threat-intelligence enrichment
8. Risk scoring
9. Security triage
10. Tamper-evident audit logging
11. n8n SOAR automation
12. PostgreSQL incident storage
13. Wazuh SIEM monitoring
14. MITRE ATT&CK mapping
15. PowerShell detection
16. Safe automated response logging

---

# 🏗️ System Architecture

```text
                         ┌─────────────────────┐
                         │   Suspicious Email  │
                         │       (.eml)        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    Flask Web App    │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              Email Parser     Header Analysis   Attachment
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   IOC Extraction    │
                         │ IP / URL / Domain   │
                         │ Hash / Email        │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Threat Intelligence │
                         │    VirusTotal       │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Risk Scoring      │
                         │   & Triage Engine   │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
                    LOW RISK               HIGH RISK
                         │                     │
                         ▼                     ▼
                  Monitor & Retain       Escalate
                         │               for Analyst
                         │                   │
                         └──────────┬────────┘
                                    │
                                    ▼
                            ┌──────────────┐
                            │     n8n      │
                            │     SOAR     │
                            └──────┬───────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │ PostgreSQL   │
                            │  Incidents   │
                            └──────────────┘


              WINDOWS SECURITY MONITORING
                         │
                         ▼
                  PowerShell Activity
                         │
                         ▼
                    Wazuh Agent
                         │
                         ▼
                   Wazuh Manager
                         │
                         ▼
                Windows Event ID 4104
                         │
                         ▼
                  Wazuh Detection
                         │
                         ▼
                 MITRE ATT&CK
                   T1059.001
                         │
                         ▼
                 Active Response
                         │
                         ▼
                  Audit Log
```

---

# 🚀 Key Features

## 1. Phishing Email Analysis

The platform accepts `.eml` files and performs multiple layers of security analysis.

### Analysis includes:

- Email parsing
- Sender analysis
- Recipient analysis
- Email header analysis
- SPF analysis
- DKIM analysis
- DMARC analysis
- Reply-To analysis
- URL analysis
- Domain extraction
- IP extraction
- Attachment analysis
- File hash generation
- Threat intelligence enrichment

---

# 🔎 2. IOC Extraction

The platform automatically extracts Indicators of Compromise (IOCs).

Supported indicators include:

- IPv4 addresses
- URLs
- Domains
- File hashes
- Email addresses
- Attachments

Example:

```text
IOC Type       Example
----------------------------------------
IP Address     185.x.x.x
Domain         example-security.com
URL            https://example.com/login
SHA256         File SHA256 hash
Email          attacker@example.com
```

Extracted IOCs can be exported and used during further investigation and threat hunting.

---

# 🧠 3. Risk Scoring & Security Triage

The platform contains a risk-analysis engine that evaluates evidence collected from the email.

Example classification:

```text
Risk Score     Verdict        Risk Level       Priority
---------------------------------------------------------
0 - 19         BENIGN         MINIMAL           LOW
20 - 39        SUSPICIOUS     MEDIUM            MEDIUM
40 - 69        MALICIOUS      HIGH              HIGH
70+            MALICIOUS      HIGH              CRITICAL
```

The scoring system allows security analysts to prioritize alerts based on risk rather than treating every email equally.

---

# 🦠 4. VirusTotal Threat Intelligence

The platform supports VirusTotal integration for threat-intelligence enrichment.

Indicators identified during analysis can be checked against VirusTotal.

VirusTotal results are treated as supporting evidence during triage.

> A VirusTotal result with no detections does not prove that an indicator is safe.

---

# 🔐 5. Tamper-Evident Audit Trail

Security investigations require trustworthy evidence.

The project implements a hash-linked audit trail.

Each record is linked to the previous record:

```text
Record 1
   │
   ▼
Hash 1
   │
   ▼
Record 2
   │
   ▼
Hash 2
   │
   ▼
Record 3
   │
   ▼
Hash 3
```

If an earlier record is modified, chain verification can detect the inconsistency.

### Provides:

- Audit integrity
- Investigation traceability
- Evidence verification
- Modification detection
- Security event history

> The implementation is tamper-evident, not a fully immutable blockchain ledger.

---

# 🤖 6. n8n SOAR Automation

The platform integrates with n8n to automate phishing incident handling.

The Flask application can send incident information to an n8n webhook.

Webhook:

```text
POST /webhook/phishing-alert
```

The n8n workflow evaluates the risk score.

```text
                     Phishing Alert
                           │
                           ▼
                         n8n
                           │
                      Risk Score
                           │
                 ┌─────────┴─────────┐
                 │                   │
               >= 40                < 40
                 │                   │
                 ▼                   ▼
            HIGH RISK            LOW RISK
             INCIDENT             INCIDENT
                 │                   │
                 ▼                   ▼
              Escalate           Monitor &
              for Analyst         Retain
                 │                   │
                 └─────────┬─────────┘
                           │
                           ▼
                      PostgreSQL
```

---

# 🗄️ 7. PostgreSQL Incident Storage

n8n stores incident information in PostgreSQL.

The database stores fields such as:

```text
incident_id
filename
risk_score
verdict
risk_level
priority
created_at
```

Example high-risk incident:

```text
Incident ID : 7
Filename    : high-risk-test-2.eml
Risk Score  : 90
Verdict     : MALICIOUS
Risk Level  : HIGH
Priority    : CRITICAL
```

Example low-risk incident:

```text
Incident ID : 12
Filename    : low-risk-final-test.eml
Risk Score  : 15
Verdict     : BENIGN
Risk Level  : MINIMAL
Priority    : LOW
```

---

# 🛡️ 8. Wazuh SIEM Integration

The project includes Windows security monitoring using Wazuh.

Architecture:

```text
Windows System
      │
      ▼
Wazuh Agent
      │
      ▼
Wazuh Manager
      │
      ▼
Windows EventChannel
      │
      ▼
PowerShell Script Block Logging
      │
      ▼
Event ID 4104
      │
      ▼
Wazuh Detection Rule
```

The Wazuh Manager runs inside a VirtualBox laboratory environment.

Example:

```text
Wazuh Version : 4.14.8
Manager IP    : 192.168.56.101
Agent ID      : 002
Agent Name    : Attacker
```

---

# 🎯 9. MITRE ATT&CK Detection

The project demonstrates detection of:

## T1059.001 — PowerShell

PowerShell Script Block Logging is used to monitor PowerShell activity.

Windows Event ID:

```text
4104
```

Detection chain:

```text
Windows PowerShell
        │
        ▼
Event ID 4104
        │
        ▼
Wazuh EventChannel Decoder
        │
        ▼
PowerShell Rule 91802
        │
        ▼
Custom Rule 100101
        │
        ▼
MITRE ATT&CK T1059.001
```

Custom rule:

```text
Rule ID: 100101

MITRE ATT&CK:
T1059.001 - PowerShell
```

This demonstrates practical mapping of security events to the MITRE ATT&CK framework.

---

# ⚡ 10. Automated Response

A safe Wazuh active-response mechanism was implemented.

When Wazuh detects Rule `100101`, the response script is triggered.

```text
Rule 100101
     │
     ▼
Active Response
     │
     ▼
powershell-t1059-response.sh
     │
     ▼
Audit Log
```

The response records:

```text
MITRE T1059.001 ACTIVE RESPONSE TRIGGERED
Rule 100101
PowerShell Script Block Detected
```

The current response is intentionally **audit-only**.

It does not block the machine or terminate processes.

This provides a safe way to demonstrate automated SOC response in a controlled laboratory.

---

# 🧪 11. Detection Validation

A controlled PowerShell command was used to validate the Wazuh detection pipeline.

Example:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'MITRE-LIVE-T1059-001-TEST'"
```

The resulting event was detected through:

```text
PowerShell
   │
   ▼
Event ID 4104
   │
   ▼
Wazuh
   │
   ▼
Rule 91802
   │
   ▼
Custom Rule 100101
   │
   ▼
MITRE ATT&CK T1059.001
   │
   ▼
Active Response
   │
   ▼
Audit Log
```

This validates the complete detection-to-response workflow.

---

# 🧰 Technology Stack

## Programming

- Python
- Flask
- HTML
- JavaScript

## Cybersecurity

- Phishing Analysis
- IOC Extraction
- Threat Intelligence
- Risk Scoring
- Incident Triage
- SIEM
- SOAR
- MITRE ATT&CK
- Active Response

## Security Tools

- Wazuh
- VirusTotal
- n8n

## Databases

- SQLite
- PostgreSQL

## Infrastructure

- Docker
- Docker Desktop
- VirtualBox
- Windows
- Linux

## Development Tools

- Git
- GitHub
- PowerShell
- VS Code

---

# 📁 Project Structure

```text
phishing-triage/
│
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── audit_logger.py
│   ├── report_generator.py
│   ├── ioc_exporter.py
│   │
│   └── analyzers/
│       ├── __init__.py
│       ├── email_parser.py
│       ├── ioc_extractor.py
│       ├── header_analyzer.py
│       ├── attachment_analyzer.py
│       ├── url_analyzer.py
│       ├── virustotal_analyzer.py
│       ├── risk_analyzer.py
│       └── triage_engine.py
│
├── templates/
│
├── data/
│
├── uploads/
│
├── reports/
│
├── exports/
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/nithishpb-26/phishing-triage-soc.git
```

Enter the project:

```bash
cd phishing-triage-soc
```

---

## 2. Create a Python virtual environment

### Windows

```powershell
python -m venv venv
```

Activate:

```powershell
.\venv\Scripts\Activate.ps1
```

### Linux

```bash
python3 -m venv venv
```

Activate:

```bash
source venv/bin/activate
```

---

# 📦 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Configuration

Create a `.env` file if using optional integrations such as VirusTotal.

Example:

```text
VIRUSTOTAL_API_KEY=your_api_key_here
```

Never commit `.env` or API keys to GitHub.

The `.gitignore` file is configured to exclude sensitive environment configuration.

---

# ▶️ Running the Flask Application

From the project root:

```powershell
python -m app.main
```

The application runs at:

```text
http://127.0.0.1:5000
```

Open the URL in your browser.

---

# 🐳 Running SOC Infrastructure

The SOC automation environment uses Docker containers including:

```text
soc-n8n
soc-postgres
iot-soc-mqtt
```

Check running containers:

```powershell
docker ps
```

Start existing containers if required:

```powershell
docker start soc-n8n soc-postgres iot-soc-mqtt
```

---

# 🔄 n8n Configuration

Open n8n:

```text
http://localhost:5678
```

Workflow:

```text
Phishing SOC Automation
```

Webhook:

```text
/webhook/phishing-alert
```

The workflow:

1. Receives phishing incident data
2. Reads the risk score
3. Evaluates the risk
4. Routes HIGH-risk incidents
5. Routes LOW-risk incidents
6. Stores incident data in PostgreSQL

---

# 🛡️ Wazuh Configuration

The Wazuh Manager runs inside a VirtualBox VM.

Example:

```text
Wazuh Manager
IP: 192.168.56.101
Version: 4.14.8
```

Check Wazuh Manager:

```bash
sudo systemctl is-active wazuh-manager
```

Expected:

```text
active
```

List agents:

```bash
sudo /var/ossec/bin/agent_control -l
```

Example:

```text
ID: 000, Name: wazuh-server
ID: 002, Name: Attacker
```

---

# 🧪 Testing

## Phishing Test

Use controlled `.eml` files to test:

- Email parsing
- Header analysis
- IOC extraction
- URL analysis
- Attachment analysis
- Risk scoring
- Threat intelligence
- Incident creation
- n8n automation
- PostgreSQL storage
- Audit logging

Do not upload confidential or real user emails.

---

# 🧪 Wazuh Test

A safe PowerShell test:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SOC-FINAL-TEST'"
```

A MITRE-specific test:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'MITRE-LIVE-T1059-001-TEST'"
```

The activity can generate Windows Event ID `4104` when PowerShell Script Block Logging is enabled.

Wazuh can then process the event and trigger the custom detection rule.

---

# 📊 Complete SOC Workflow

```text
                  PHISHING EMAIL
                         │
                         ▼
                 Email Analysis
                         │
                         ▼
                  IOC Extraction
                         │
                         ▼
               Threat Intelligence
                         │
                         ▼
                  Risk Scoring
                         │
                         ▼
                  SOC Triage
                         │
                         ▼
                   n8n SOAR
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
           LOW RISK              HIGH RISK
              │                     │
              ▼                     ▼
           Monitor               Escalate
              │                     │
              └──────────┬──────────┘
                         ▼
                    PostgreSQL
                         │
                         ▼
                  Incident Evidence


             WINDOWS MONITORING
                         │
                         ▼
                PowerShell Activity
                         │
                         ▼
                    Wazuh Agent
                         │
                         ▼
                   Wazuh Manager
                         │
                         ▼
                  Event ID 4104
                         │
                         ▼
                Detection Rule
                         │
                         ▼
                 MITRE T1059.001
                         │
                         ▼
                Automated Response
                         │
                         ▼
                    Audit Log
```

---

# 🔐 Security Considerations

This project is designed for cybersecurity education, SOC training, and authorized laboratory testing.

Important considerations:

- Do not upload real confidential phishing emails.
- Do not commit passwords or API keys.
- Do not commit `.env` files.
- VirusTotal results should be treated as supporting threat intelligence.
- A URL heuristic does not guarantee maliciousness.
- A clean VirusTotal result does not guarantee safety.
- The audit chain provides tamper evidence, not complete immutability.
- The Flask development server should not be used as a production server.
- Wazuh active response is intentionally configured for safe audit logging.
- Security testing should only be performed against systems you own or are authorized to test.

---

# 📚 SOC Skills Demonstrated

This project demonstrates practical skills relevant to SOC Analyst and Cybersecurity roles.

## Security Monitoring

- SIEM concepts
- Windows Event Logs
- PowerShell monitoring
- Event ID 4104
- Alert investigation
- Detection rules

## Threat Detection

- MITRE ATT&CK
- T1059.001 PowerShell
- IOC extraction
- Threat intelligence
- Risk-based detection

## Incident Response

- Alert triage
- Severity classification
- Incident escalation
- Automated response
- Evidence preservation
- Audit logging

## Security Automation

- n8n
- Webhooks
- Conditional routing
- PostgreSQL integration
- Automated incident workflows

## Application Security

- Email security analysis
- URL analysis
- Attachment analysis
- Hash analysis
- Threat intelligence
- Security-focused Python development

---

# 📈 Future Improvements

Possible future enhancements:

- Real-time SOC dashboard
- Additional Wazuh detection rules
- More MITRE ATT&CK techniques
- Automated IOC enrichment
- Additional threat-intelligence feeds
- Analyst case management
- Email quarantine simulation
- Docker Compose deployment
- Role-based access control
- Production-grade deployment
- Secure file-upload validation
- Advanced SOC analytics
- Threat-hunting capabilities

---

# ⚠️ Disclaimer

This project is intended for:

- Cybersecurity education
- SOC Analyst training
- Security automation research
- Authorized laboratory testing
- Portfolio demonstration

Only analyze emails, systems, and infrastructure that you are authorized to investigate.

---

# 👨‍💻 Author

## Nithish P B

B.E. Computer Science  
IoT, Cybersecurity & Blockchain Technology

GitHub:

https://github.com/nithishpb-26

---

# ⭐ Project Highlights

```text
Phishing Email
      ↓
Email Analysis
      ↓
IOC Extraction
      ↓
Threat Intelligence
      ↓
Risk Scoring
      ↓
SOC Triage
      ↓
n8n SOAR Automation
      ↓
PostgreSQL
      ↓
Wazuh SIEM
      ↓
MITRE ATT&CK
      ↓
Automated Response
      ↓
Tamper-Evident Audit Trail
```

---

## 🔗 Repository

GitHub:

https://github.com/nithishpb-26/phishing-triage-soc

---

## ⭐ Final Summary

This project demonstrates an end-to-end SOC workflow combining:

**Phishing Analysis + Threat Intelligence + IOC Extraction + Risk Scoring + SIEM + SOAR + MITRE ATT&CK + Automated Response + PostgreSQL + Tamper-Evident Auditing**

It is designed as a practical cybersecurity portfolio project demonstrating both **security analysis** and **security automation** capabilities.
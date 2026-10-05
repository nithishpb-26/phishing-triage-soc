import os
import requests
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    send_file
)


# ============================================================
# ANALYZERS
# ============================================================

from app.analyzers.email_parser import parse_email
from app.analyzers.ioc_extractor import extract_iocs
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.attachment_analyzer import analyze_attachments
from app.analyzers.url_analyzer import analyze_urls
from app.analyzers.virustotal_analyzer import analyze_iocs
from app.analyzers.risk_analyzer import calculate_risk
from app.analyzers.triage_engine import generate_triage


# ============================================================
# DATABASE
# ============================================================

from app.database import (
    initialize_database,
    save_incident,
    get_all_incidents,
    get_incident_by_id,
    get_incident_statistics
)


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

from app.report_generator import (
    generate_incident_report
)


# ============================================================
# IOC CSV EXPORTER
# ============================================================

from app.ioc_exporter import (
    generate_ioc_csv
)


# ============================================================
# AUDIT LOGGER
# ============================================================

from app.audit_logger import (
    initialize_audit_log,
    log_audit_event
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

initialize_database()

initialize_audit_log()


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ============================================================
# n8n CONFIGURATION
# ============================================================

N8N_WEBHOOK_URL = (
    "http://localhost:5678/webhook/phishing-alert"
)


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    # --------------------------------------------------------
    # CHECK FILE
    # --------------------------------------------------------

    if "email" not in request.files:

        return (
            "Please select an .eml file first.",
            400
        )

    file = request.files["email"]

    if file.filename == "":

        return (
            "Please select an .eml file first.",
            400
        )

    if not file.filename.lower().endswith(".eml"):

        return (
            "Only .eml files are allowed.",
            400
        )


    # --------------------------------------------------------
    # SAVE EMAIL
    # --------------------------------------------------------

    filename = file.filename

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)


    # --------------------------------------------------------
    # PARSE EMAIL
    # --------------------------------------------------------

    email_data = parse_email(
        filepath
    )


    # --------------------------------------------------------
    # BUILD IOC TEXT
    # --------------------------------------------------------

    ioc_text = (
        email_data.get("body", "")
        + "\n"
        + email_data.get("sender", "")
        + "\n"
        + email_data.get("recipient", "")
        + "\n"
        + email_data.get("subject", "")
        + "\n"
        + email_data.get("reply_to", "")
        + "\n"
        + email_data.get("received_spf", "")
        + "\n"
        + email_data.get("dkim_signature", "")
        + "\n"
        + email_data.get("authentication_results", "")
    )


    # --------------------------------------------------------
    # IOC EXTRACTION
    # --------------------------------------------------------

    iocs = extract_iocs(
        ioc_text
    )


    # --------------------------------------------------------
    # HEADER ANALYSIS
    # --------------------------------------------------------

    header_findings = analyze_headers(
        email_data
    )


    # --------------------------------------------------------
    # ATTACHMENT ANALYSIS
    # --------------------------------------------------------

    attachment_findings = analyze_attachments(
        email_data.get(
            "attachments",
            []
        )
    )


    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_findings = analyze_urls(
        iocs.get(
            "urls",
            []
        )
    )


    # --------------------------------------------------------
    # VIRUSTOTAL ANALYSIS
    # --------------------------------------------------------

    virustotal_findings = analyze_iocs(
        iocs
    )


    # --------------------------------------------------------
    # RISK CALCULATION
    # --------------------------------------------------------

    risk_result = calculate_risk(

        header_findings=header_findings,

        url_findings=url_findings,

        attachment_findings=attachment_findings,

        virustotal_findings=virustotal_findings,

        iocs=iocs
    )


    # --------------------------------------------------------
    # TRIAGE
    # --------------------------------------------------------

    triage_result = generate_triage(

        risk_result,

        virustotal_findings
    )


    # --------------------------------------------------------
    # ANALYSIS TIME
    # --------------------------------------------------------

    analysis_time = datetime.now().isoformat(
        timespec="seconds"
    )


    # --------------------------------------------------------
    # SAVE INCIDENT TO DATABASE
    # --------------------------------------------------------

    incident_id = save_incident(

        filename=filename,

        email=email_data,

        risk_result=risk_result,

        triage_result=triage_result,

        iocs=iocs,

        analysis_time=analysis_time
    )


    # ========================================================
    # AUDIT LOG
    # ========================================================

    log_audit_event(

        incident_id,

        "INCIDENT_ANALYZED",

        {

            "filename": filename,

            "verdict": risk_result.get(
                "verdict",
                ""
            ),

            "risk_score": risk_result.get(
                "score",
                0
            ),

            "risk_level": risk_result.get(
                "risk_level",
                ""
            ),

            "priority": triage_result.get(
                "priority",
                ""
            )
        }
    )


    # ========================================================
    # SEND INCIDENT TO n8n SOAR
    # ========================================================

    n8n_payload = {

        "incident_id": incident_id,

        "filename": filename,

        "risk_score": risk_result.get(
            "score",
            0
        ),

        "verdict": risk_result.get(
            "verdict",
            ""
        ),

        "risk_level": risk_result.get(
            "risk_level",
            ""
        ),

        "priority": triage_result.get(
            "priority",
            ""
        )
    }


    try:

        n8n_response = requests.post(

            N8N_WEBHOOK_URL,

            json=n8n_payload,

            timeout=5
        )


        print(
            "========================================"
        )

        print(
            "n8n SOAR notification"
        )

        print(
            "========================================"
        )

        print(
            "Webhook:",
            N8N_WEBHOOK_URL
        )

        print(
            "Status:",
            n8n_response.status_code
        )

        print(
            "Response:",
            n8n_response.text
        )

        print(
            "========================================"
        )


    except requests.RequestException as error:

        print(
            "========================================"
        )

        print(
            "n8n SOAR notification failed"
        )

        print(
            "Error:",
            error
        )

        print(
            "========================================"
        )


    # ========================================================
    # RETURN ANALYSIS PAGE
    # ========================================================

    return render_template(

        "analysis.html",

        email=email_data,

        filename=filename,

        incident_id=incident_id,

        iocs=iocs,

        header_findings=header_findings,

        attachment_findings=attachment_findings,

        url_findings=url_findings,

        virustotal_findings=virustotal_findings,

        risk_result=risk_result,

        triage_result=triage_result
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route(
    "/dashboard"
)
def dashboard():

    incidents = get_all_incidents()

    statistics = get_incident_statistics()

    return render_template(

        "dashboard.html",

        incidents=incidents,

        statistics=statistics
    )


# ============================================================
# INCIDENT INVESTIGATION
# ============================================================

@app.route(
    "/incident/<int:incident_id>"
)
def incident(incident_id):

    incident_data = get_incident_by_id(
        incident_id
    )

    if incident_data is None:

        return (
            "Incident not found.",
            404
        )

    return render_template(

        "incident.html",

        incident=incident_data
    )


# ============================================================
# GENERATE PDF REPORT
# ============================================================

@app.route(
    "/incident/<int:incident_id>/report"
)
def incident_report(incident_id):

    incident_data = get_incident_by_id(
        incident_id
    )

    if incident_data is None:

        return (
            "Incident not found.",
            404
        )

    filepath = generate_incident_report(
        incident_data
    )

    return send_file(

        filepath,

        as_attachment=True,

        download_name=(
            f"incident_{incident_id}_report.pdf"
        ),

        mimetype="application/pdf"
    )


# ============================================================
# EXPORT IOC CSV
# ============================================================

@app.route(
    "/incident/<int:incident_id>/export-iocs"
)
def export_iocs(incident_id):

    incident_data = get_incident_by_id(
        incident_id
    )

    if incident_data is None:

        return (
            "Incident not found.",
            404
        )

    filepath = generate_ioc_csv(
        incident_data
    )

    return send_file(

        filepath,

        as_attachment=True,

        download_name=(
            f"incident_{incident_id}_iocs.csv"
        ),

        mimetype="text/csv"
    )


# ============================================================
# START FLASK APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True
    )
    
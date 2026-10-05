import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# REPORT FOLDER
# ============================================================

REPORT_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


# ============================================================
# GENERATE INCIDENT REPORT
# ============================================================

def generate_incident_report(incident):

    incident_id = incident["id"]

    filename = (
        f"incident_{incident_id}_report.pdf"
    )

    filepath = os.path.join(
        REPORT_FOLDER,
        filename
    )

    # ========================================================
    # CREATE PDF DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontSize=9,
        leading=13
    )

    story = []

    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Paragraph(
            "PHISHING INCIDENT ANALYSIS REPORT",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Automated Threat Intelligence & "
            "Phishing Triage Pipeline",
            normal_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ========================================================
    # INCIDENT SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "1. Incident Summary",
            heading_style
        )
    )

    summary_data = [
        [
            "Incident ID",
            str(incident["id"])
        ],
        [
            "File Name",
            incident["filename"] or "N/A"
        ],
        [
            "Analysis Time",
            incident["analysis_time"] or "N/A"
        ],
        [
            "Verdict",
            incident["verdict"] or "N/A"
        ],
        [
            "Risk Score",
            f"{incident['risk_score']}/100"
        ],
        [
            "Risk Level",
            incident["risk_level"] or "N/A"
        ],
        [
            "Priority",
            incident["priority"] or "N/A"
        ],
        [
            "Confidence",
            incident["confidence"] or "N/A"
        ]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[140, 350]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        summary_table
    )

    # ========================================================
    # EMAIL INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "2. Email Information",
            heading_style
        )
    )

    email_data = [
        [
            "Sender",
            incident["sender"] or "N/A"
        ],
        [
            "Recipient",
            incident["recipient"] or "N/A"
        ],
        [
            "Subject",
            incident["subject"] or "N/A"
        ]
    ]

    email_table = Table(
        email_data,
        colWidths=[140, 350]
    )

    email_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        email_table
    )

    # ========================================================
    # IOC INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "3. Indicators of Compromise",
            heading_style
        )
    )

    urls = (
        incident["urls"]
        if incident["urls"]
        else "None detected"
    )

    ips = (
        incident["ips"]
        if incident["ips"]
        else "None detected"
    )

    domains = (
        incident["domains"]
        if incident["domains"]
        else "None detected"
    )

    ioc_data = [
        [
            "URL IOCs",
            urls
        ],
        [
            "IP IOCs",
            ips
        ],
        [
            "Domain IOCs",
            domains
        ]
    ]

    ioc_table = Table(
        ioc_data,
        colWidths=[140, 350]
    )

    ioc_table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(
        ioc_table
    )

    # ========================================================
    # SOC RECOMMENDED ACTION
    # ========================================================

    story.append(
        Paragraph(
            "4. Recommended SOC Action",
            heading_style
        )
    )

    action = (
        incident["recommended_action"]
        or "No recommendation available."
    )

    story.append(
        Paragraph(
            action,
            normal_style
        )
    )

    # ========================================================
    # REPORT METADATA
    # ========================================================

    story.append(
        Paragraph(
            "5. Report Metadata",
            heading_style
        )
    )

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    story.append(
        Paragraph(
            f"Report generated: {generated_time}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            "Generated by Automated Threat Intelligence "
            "& Phishing Triage Pipeline",
            normal_style
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story
    )

    # ========================================================
    # VERIFY PDF WAS CREATED
    # ========================================================

    if not os.path.exists(filepath):

        raise FileNotFoundError(
            f"PDF report was not created: {filepath}"
        )

    return filepath
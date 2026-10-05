import sqlite3
import os


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_FOLDER = "data"

DATABASE_PATH = os.path.join(
    DATABASE_FOLDER,
    "phishing_triage.db"
)


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    os.makedirs(
        DATABASE_FOLDER,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT,

            sender TEXT,

            recipient TEXT,

            subject TEXT,

            analysis_time TEXT,

            risk_score INTEGER,

            verdict TEXT,

            risk_level TEXT,

            priority TEXT,

            confidence TEXT,

            recommended_action TEXT,

            urls TEXT,

            ips TEXT,

            domains TEXT

        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# SAVE INCIDENT
# ============================================================

def save_incident(
    filename,
    email,
    risk_result,
    triage_result,
    iocs,
    analysis_time
):

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO incidents (

            filename,
            sender,
            recipient,
            subject,
            analysis_time,
            risk_score,
            verdict,
            risk_level,
            priority,
            confidence,
            recommended_action,
            urls,
            ips,
            domains

        )

        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
    """, (

        filename,

        email.get(
            "sender",
            ""
        ),

        email.get(
            "recipient",
            ""
        ),

        email.get(
            "subject",
            ""
        ),

        analysis_time,

        risk_result.get(
            "score",
            0
        ),

        risk_result.get(
            "verdict",
            ""
        ),

        risk_result.get(
            "risk_level",
            ""
        ),

        triage_result.get(
            "priority",
            ""
        ),

        triage_result.get(
            "confidence",
            ""
        ),

        triage_result.get(
            "action",
            ""
        ),

        "\n".join(
            iocs.get(
                "urls",
                []
            )
        ),

        "\n".join(
            iocs.get(
                "ips",
                []
            )
        ),

        "\n".join(
            iocs.get(
                "domains",
                []
            )
        )
    ))

    connection.commit()

    incident_id = cursor.lastrowid

    connection.close()

    return incident_id


# ============================================================
# GET ALL INCIDENTS
# ============================================================

def get_all_incidents():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            sender,
            recipient,
            subject,
            analysis_time,
            risk_score,
            verdict,
            risk_level,
            priority,
            confidence,
            recommended_action,
            urls,
            ips,
            domains
        FROM incidents
        ORDER BY id DESC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents


# ============================================================
# GET SINGLE INCIDENT
# ============================================================

def get_incident_by_id(incident_id):

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            sender,
            recipient,
            subject,
            analysis_time,
            risk_score,
            verdict,
            risk_level,
            priority,
            confidence,
            recommended_action,
            urls,
            ips,
            domains
        FROM incidents
        WHERE id = ?
    """, (incident_id,))

    incident = cursor.fetchone()

    connection.close()

    return incident


# ============================================================
# GET INCIDENT STATISTICS
# ============================================================

def get_incident_statistics():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()


    # --------------------------------------------------------
    # TOTAL INCIDENTS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
    """)

    total = cursor.fetchone()[0]


    # --------------------------------------------------------
    # MALICIOUS INCIDENTS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE verdict = 'MALICIOUS'
    """)

    malicious = cursor.fetchone()[0]


    # --------------------------------------------------------
    # SUSPICIOUS INCIDENTS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE verdict = 'SUSPICIOUS'
    """)

    suspicious = cursor.fetchone()[0]


    # --------------------------------------------------------
    # BENIGN INCIDENTS
    # --------------------------------------------------------

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE verdict = 'BENIGN'
    """)

    benign = cursor.fetchone()[0]


    connection.close()


    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "benign": benign
    }
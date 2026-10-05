import sqlite3
import hashlib
import json
import os
from datetime import datetime


# ============================================================
# PROJECT ROOT
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# DATABASE
# ============================================================

DATABASE_FOLDER = os.path.join(
    BASE_DIR,
    "data"
)

DATABASE_PATH = os.path.join(
    DATABASE_FOLDER,
    "phishing_triage.db"
)


# ============================================================
# INITIALIZE AUDIT TABLE
# ============================================================

def initialize_audit_log():

    os.makedirs(
        DATABASE_FOLDER,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id INTEGER,

            event_type TEXT NOT NULL,

            event_data TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            previous_hash TEXT,

            current_hash TEXT NOT NULL

        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# GET PREVIOUS HASH
# ============================================================

def get_previous_hash(connection):

    cursor = connection.cursor()

    cursor.execute("""
        SELECT current_hash
        FROM audit_log
        ORDER BY id DESC
        LIMIT 1
    """)

    result = cursor.fetchone()

    if result:
        return result[0]

    return "GENESIS"


# ============================================================
# CALCULATE SHA-256 HASH
# ============================================================

def calculate_hash(
    incident_id,
    event_type,
    event_data,
    timestamp,
    previous_hash
):

    data = (
        f"{incident_id}|"
        f"{event_type}|"
        f"{event_data}|"
        f"{timestamp}|"
        f"{previous_hash}"
    )

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


# ============================================================
# WRITE AUDIT EVENT
# ============================================================

def log_audit_event(
    incident_id,
    event_type,
    event_data
):

    # Make sure data directory exists
    os.makedirs(
        DATABASE_FOLDER,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    timestamp = datetime.now().isoformat(
        timespec="seconds"
    )

    # --------------------------------------------------------
    # Convert event data to stable JSON
    # --------------------------------------------------------

    if isinstance(event_data, dict):

        event_data = json.dumps(
            event_data,
            sort_keys=True
        )

    else:

        event_data = str(
            event_data
        )

    # --------------------------------------------------------
    # Get previous hash
    # --------------------------------------------------------

    previous_hash = get_previous_hash(
        connection
    )

    # --------------------------------------------------------
    # Calculate current hash
    # --------------------------------------------------------

    current_hash = calculate_hash(

        incident_id,

        event_type,

        event_data,

        timestamp,

        previous_hash
    )

    # --------------------------------------------------------
    # Insert audit record
    # --------------------------------------------------------

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO audit_log (

            incident_id,
            event_type,
            event_data,
            timestamp,
            previous_hash,
            current_hash

        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (

        incident_id,
        event_type,
        event_data,
        timestamp,
        previous_hash,
        current_hash
    ))

    connection.commit()
    connection.close()

    return current_hash


# ============================================================
# GET AUDIT LOG
# ============================================================

def get_audit_log():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            id,
            incident_id,
            event_type,
            event_data,
            timestamp,
            previous_hash,
            current_hash

        FROM audit_log

        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    connection.close()

    return records


# ============================================================
# VERIFY AUDIT CHAIN
# ============================================================

def verify_audit_chain():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT

            id,
            incident_id,
            event_type,
            event_data,
            timestamp,
            previous_hash,
            current_hash

        FROM audit_log

        ORDER BY id ASC
    """)

    records = cursor.fetchall()

    connection.close()

    previous_hash = "GENESIS"

    for record in records:

        (
            record_id,
            incident_id,
            event_type,
            event_data,
            timestamp,
            stored_previous_hash,
            stored_current_hash
        ) = record

        # ----------------------------------------------------
        # Check previous hash
        # ----------------------------------------------------

        if stored_previous_hash != previous_hash:

            return {
                "valid": False,
                "record_id": record_id,
                "reason": (
                    "Previous hash mismatch detected."
                )
            }

        # ----------------------------------------------------
        # Recalculate current hash
        # ----------------------------------------------------

        calculated_hash = calculate_hash(

            incident_id,

            event_type,

            event_data,

            timestamp,

            stored_previous_hash
        )

        # ----------------------------------------------------
        # Check current hash
        # ----------------------------------------------------

        if calculated_hash != stored_current_hash:

            return {
                "valid": False,
                "record_id": record_id,
                "reason": (
                    "Current hash mismatch detected."
                )
            }

        previous_hash = stored_current_hash

    return {
        "valid": True,
        "record_id": None,
        "reason": "Audit chain is valid."
    }
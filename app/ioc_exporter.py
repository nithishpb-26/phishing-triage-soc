import csv
import os


# ============================================================
# PROJECT ROOT
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# EXPORT FOLDER
# ============================================================

EXPORT_FOLDER = os.path.join(
    BASE_DIR,
    "exports"
)

os.makedirs(
    EXPORT_FOLDER,
    exist_ok=True
)


# ============================================================
# GENERATE IOC CSV
# ============================================================

def generate_ioc_csv(incident):

    incident_id = incident["id"]

    filename = (
        f"incident_{incident_id}_iocs.csv"
    )

    filepath = os.path.join(
        EXPORT_FOLDER,
        filename
    )

    # --------------------------------------------------------
    # IOC ROWS
    # --------------------------------------------------------

    ioc_rows = []

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = incident["urls"] or ""

    for url in urls.splitlines():

        url = url.strip()

        if url:

            ioc_rows.append([
                incident_id,
                incident["filename"],
                incident["analysis_time"],
                "URL",
                url
            ])

    # --------------------------------------------------------
    # IP ADDRESSES
    # --------------------------------------------------------

    ips = incident["ips"] or ""

    for ip in ips.splitlines():

        ip = ip.strip()

        if ip:

            ioc_rows.append([
                incident_id,
                incident["filename"],
                incident["analysis_time"],
                "IP",
                ip
            ])

    # --------------------------------------------------------
    # DOMAINS
    # --------------------------------------------------------

    domains = incident["domains"] or ""

    for domain in domains.splitlines():

        domain = domain.strip()

        if domain:

            ioc_rows.append([
                incident_id,
                incident["filename"],
                incident["analysis_time"],
                "DOMAIN",
                domain
            ])

    # --------------------------------------------------------
    # CREATE CSV FILE
    # --------------------------------------------------------

    with open(
        filepath,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.writer(
            csv_file
        )

        # CSV HEADER

        writer.writerow([
            "Incident ID",
            "File Name",
            "Analysis Time",
            "IOC Type",
            "IOC Value"
        ])

        # IOC DATA

        writer.writerows(
            ioc_rows
        )

    return filepath
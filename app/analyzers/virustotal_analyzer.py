import os
import base64
import requests

from dotenv import load_dotenv


# ============================================================
# Load environment variables
# ============================================================

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ============================================================
# Common request headers
# ============================================================

def get_headers():
    return {
        "x-apikey": VIRUSTOTAL_API_KEY
    }


# ============================================================
# Check API configuration
# ============================================================

def is_configured():

    return bool(
        VIRUSTOTAL_API_KEY
        and VIRUSTOTAL_API_KEY != "YOUR_VIRUSTOTAL_API_KEY_HERE"
    )


# ============================================================
# Extract VirusTotal statistics
# ============================================================

def extract_stats(data):

    try:

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "timeout": stats.get("timeout", 0)
        }

    except Exception:

        return {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "harmless": 0,
            "timeout": 0
        }


# ============================================================
# Determine reputation
# ============================================================

def determine_reputation(stats):

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:

        return "MALICIOUS"

    if suspicious > 0:

        return "SUSPICIOUS"

    return "NO_MALICIOUS_DETECTION"


# ============================================================
# Analyze URL
# ============================================================

def analyze_url(url):

    if not is_configured():

        return {
            "indicator": url,
            "type": "URL",
            "status": "NOT_CONFIGURED",
            "message": "VirusTotal API key is not configured."
        }


    try:

        # VirusTotal URL IDs are URL-safe base64
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")


        endpoint = f"{VT_BASE_URL}/urls/{url_id}"


        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=20
        )


        if response.status_code == 200:

            data = response.json()

            stats = extract_stats(data)

            return {
                "indicator": url,
                "type": "URL",
                "status": determine_reputation(stats),
                "stats": stats
            }


        elif response.status_code == 404:

            return {
                "indicator": url,
                "type": "URL",
                "status": "NOT_FOUND",
                "message": "URL has no existing VirusTotal report."
            }


        elif response.status_code == 401:

            return {
                "indicator": url,
                "type": "URL",
                "status": "AUTH_ERROR",
                "message": "VirusTotal API key is invalid."
            }


        elif response.status_code == 429:

            return {
                "indicator": url,
                "type": "URL",
                "status": "RATE_LIMITED",
                "message": "VirusTotal API rate limit reached."
            }


        else:

            return {
                "indicator": url,
                "type": "URL",
                "status": "ERROR",
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }


    except requests.RequestException as error:

        return {
            "indicator": url,
            "type": "URL",
            "status": "ERROR",
            "message": str(error)
        }


# ============================================================
# Analyze IP Address
# ============================================================

def analyze_ip(ip):

    if not is_configured():

        return {
            "indicator": ip,
            "type": "IP",
            "status": "NOT_CONFIGURED",
            "message": "VirusTotal API key is not configured."
        }


    try:

        endpoint = f"{VT_BASE_URL}/ip_addresses/{ip}"


        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=20
        )


        if response.status_code == 200:

            data = response.json()

            stats = extract_stats(data)

            return {
                "indicator": ip,
                "type": "IP",
                "status": determine_reputation(stats),
                "stats": stats
            }


        elif response.status_code == 404:

            return {
                "indicator": ip,
                "type": "IP",
                "status": "NOT_FOUND",
                "message": "IP address has no existing VirusTotal report."
            }


        elif response.status_code == 401:

            return {
                "indicator": ip,
                "type": "IP",
                "status": "AUTH_ERROR",
                "message": "VirusTotal API key is invalid."
            }


        elif response.status_code == 429:

            return {
                "indicator": ip,
                "type": "IP",
                "status": "RATE_LIMITED",
                "message": "VirusTotal API rate limit reached."
            }


        else:

            return {
                "indicator": ip,
                "type": "IP",
                "status": "ERROR",
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }


    except requests.RequestException as error:

        return {
            "indicator": ip,
            "type": "IP",
            "status": "ERROR",
            "message": str(error)
        }


# ============================================================
# Analyze Domain
# ============================================================

def analyze_domain(domain):

    if not is_configured():

        return {
            "indicator": domain,
            "type": "DOMAIN",
            "status": "NOT_CONFIGURED",
            "message": "VirusTotal API key is not configured."
        }


    try:

        endpoint = f"{VT_BASE_URL}/domains/{domain}"


        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=20
        )


        if response.status_code == 200:

            data = response.json()

            stats = extract_stats(data)

            return {
                "indicator": domain,
                "type": "DOMAIN",
                "status": determine_reputation(stats),
                "stats": stats
            }


        elif response.status_code == 404:

            return {
                "indicator": domain,
                "type": "DOMAIN",
                "status": "NOT_FOUND",
                "message": "Domain has no existing VirusTotal report."
            }


        elif response.status_code == 401:

            return {
                "indicator": domain,
                "type": "DOMAIN",
                "status": "AUTH_ERROR",
                "message": "VirusTotal API key is invalid."
            }


        elif response.status_code == 429:

            return {
                "indicator": domain,
                "type": "DOMAIN",
                "status": "RATE_LIMITED",
                "message": "VirusTotal API rate limit reached."
            }


        else:

            return {
                "indicator": domain,
                "type": "DOMAIN",
                "status": "ERROR",
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }


    except requests.RequestException as error:

        return {
            "indicator": domain,
            "type": "DOMAIN",
            "status": "ERROR",
            "message": str(error)
        }


# ============================================================
# Analyze all IOCs
# ============================================================

def analyze_iocs(iocs):

    results = {
        "urls": [],
        "ips": [],
        "domains": []
    }


    # URLs
    for url in iocs.get("urls", []):

        results["urls"].append(
            analyze_url(url)
        )


    # IP addresses
    for ip in iocs.get("ips", []):

        results["ips"].append(
            analyze_ip(ip)
        )


    # Domains
    for domain in iocs.get("domains", []):

        results["domains"].append(
            analyze_domain(domain)
        )


    return results
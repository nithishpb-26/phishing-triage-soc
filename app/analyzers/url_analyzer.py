import re
from urllib.parse import urlparse


# ============================================================
# Known URL Shorteners
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly"
}


# ============================================================
# Common Trusted Domains
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "linkedin.com",
    "github.com",
    "smartrecruiters.com",
    "indeed.com",
    "glassdoor.com"
}


# ============================================================
# Suspicious TLDs
# ============================================================

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".work",
    ".zip",
    ".mov"
}


# ============================================================
# Helper: IP Address
# ============================================================

def is_ip_address(hostname):
    """
    Check whether a hostname is an IPv4 address.
    """

    if not hostname:
        return False

    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    return bool(re.match(pattern, hostname))


# ============================================================
# Helper: Domain Trust
# ============================================================

def is_trusted_domain(hostname):
    """
    Determine whether a hostname belongs to a known trusted domain.
    """

    if not hostname:
        return False

    hostname = hostname.lower()

    for domain in TRUSTED_DOMAINS:

        if hostname == domain or hostname.endswith("." + domain):
            return True

    return False


# ============================================================
# URL Classification
# ============================================================

def classify_url(url):
    """
    Perform heuristic analysis of a URL.
    """

    result = {
        "url": url,
        "category": "Unknown",
        "risk": "Review",
        "reason": "URL requires further analysis"
    }

    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    try:
        parsed = urlparse(url)

    except Exception:

        result["category"] = "Invalid URL"
        result["risk"] = "High"
        result["reason"] = "URL could not be parsed"

        return result


    hostname = parsed.hostname

    if not hostname:

        result["category"] = "Invalid URL"
        result["risk"] = "High"
        result["reason"] = "URL does not contain a valid hostname"

        return result


    hostname = hostname.lower()


    # --------------------------------------------------------
    # Check URL Scheme
    # --------------------------------------------------------

    if parsed.scheme not in {"http", "https"}:

        result["category"] = "Unusual Scheme"
        result["risk"] = "Medium"
        result["reason"] = "URL uses an unusual protocol"

        return result


    # --------------------------------------------------------
    # IP Address URL
    # --------------------------------------------------------

    if is_ip_address(hostname):

        result["category"] = "IP-based URL"
        result["risk"] = "High"
        result["reason"] = "URL directly uses an IP address instead of a domain"

        return result


    # --------------------------------------------------------
    # URL Shortener
    # --------------------------------------------------------

    if hostname in URL_SHORTENERS:

        result["category"] = "URL Shortener"
        result["risk"] = "Review"
        result["reason"] = "URL uses a URL-shortening service"

        return result


    # --------------------------------------------------------
    # External Form
    # --------------------------------------------------------

    if (
        "forms.gle" in hostname
        or hostname == "docs.google.com"
        and "/forms/" in parsed.path.lower()
    ):

        result["category"] = "External Form"
        result["risk"] = "Review"
        result["reason"] = "Online form detected"

        return result


    # --------------------------------------------------------
    # Tracking Infrastructure
    # --------------------------------------------------------

    tracking_terms = [
        "track",
        "tracking",
        "click",
        "open",
        "pixel",
        "unsubscribe",
        "email",
        "campaign"
    ]

    url_lower = url.lower()

    if any(term in url_lower for term in tracking_terms):

        result["category"] = "Tracking"
        result["risk"] = "Low"
        result["reason"] = "Possible email tracking infrastructure detected"

        return result


    # --------------------------------------------------------
    # Excessively Long URL
    # --------------------------------------------------------

    if len(url) > 250:

        result["category"] = "Long URL"
        result["risk"] = "Review"
        result["reason"] = "URL is unusually long"

        return result


    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            result["category"] = "Suspicious TLD"
            result["risk"] = "Review"
            result["reason"] = "Domain uses a frequently abused TLD"

            return result


    # --------------------------------------------------------
    # Trusted Domain
    # --------------------------------------------------------

    if is_trusted_domain(hostname):

        result["category"] = "Known Domain"
        result["risk"] = "Low"
        result["reason"] = "Domain belongs to a commonly recognized service"

        return result


    # --------------------------------------------------------
    # HTTP Instead of HTTPS
    # --------------------------------------------------------

    if parsed.scheme == "http":

        result["category"] = "HTTP URL"
        result["risk"] = "Review"
        result["reason"] = "URL does not use HTTPS"

        return result


    # --------------------------------------------------------
    # Default
    # --------------------------------------------------------

    result["category"] = "Standard URL"
    result["risk"] = "Review"
    result["reason"] = "No obvious heuristic indicators detected"

    return result


# ============================================================
# Analyze Multiple URLs
# ============================================================

def analyze_urls(urls):
    """
    Analyze a list of URLs.
    """

    results = []

    for url in urls:

        results.append(
            classify_url(url)
        )

    return results
import re
from urllib.parse import urlparse


def extract_urls(text):
    """
    Extract URLs from text.
    """

    if not text:
        return []

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, text)

    # Remove trailing punctuation
    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,);]}>")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def extract_emails(text):
    """
    Extract email addresses.
    """

    if not text:
        return []

    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

    emails = re.findall(email_pattern, text)

    return list(dict.fromkeys(emails))


def extract_ips(text):
    """
    Extract IPv4 addresses.
    """

    if not text:
        return []

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    ips = re.findall(ip_pattern, text)

    return list(dict.fromkeys(ips))


def extract_domains(text):
    """
    Extract domains from URLs and email addresses.
    """

    domains = []

    # Domains from URLs
    urls = extract_urls(text)

    for url in urls:

        try:
            parsed = urlparse(url)

            if parsed.hostname:
                domains.append(parsed.hostname.lower())

        except Exception:
            pass

    # Domains from email addresses
    emails = extract_emails(text)

    for email in emails:

        if "@" in email:
            domain = email.split("@", 1)[1].lower()
            domains.append(domain)

    return list(dict.fromkeys(domains))


def extract_iocs(text):
    """
    Extract all IOC types.
    """

    return {
        "urls": extract_urls(text),
        "emails": extract_emails(text),
        "ips": extract_ips(text),
        "domains": extract_domains(text)
    }
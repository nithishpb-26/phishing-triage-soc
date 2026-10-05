def calculate_risk(
    header_findings,
    url_findings,
    attachment_findings,
    virustotal_findings,
    iocs
):
    score = 0
    reasons = []

    # -------------------------------------------------
    # HEADER ANALYSIS
    # -------------------------------------------------

    # SPF
    spf = header_findings.get("SPF", {})
    spf_status = spf.get("status", "")

    if spf_status == "FAIL":
        score += 25
        reasons.append({
            "points": 25,
            "reason": "SPF authentication failed"
        })

    elif spf_status == "MISSING":
        score += 5
        reasons.append({
            "points": 5,
            "reason": "SPF information is missing"
        })


    # DKIM
    dkim = header_findings.get("DKIM", {})
    dkim_status = dkim.get("status", "")

    if dkim_status == "FAIL":
        score += 20
        reasons.append({
            "points": 20,
            "reason": "DKIM authentication failed"
        })

    elif dkim_status == "MISSING":
        score += 5
        reasons.append({
            "points": 5,
            "reason": "DKIM information is missing"
        })


    # DMARC
    dmarc = header_findings.get("DMARC", {})
    dmarc_status = dmarc.get("status", "")

    if dmarc_status == "FAIL":
        score += 25
        reasons.append({
            "points": 25,
            "reason": "DMARC authentication failed"
        })

    elif dmarc_status == "MISSING":
        score += 5
        reasons.append({
            "points": 5,
            "reason": "DMARC information is missing"
        })


    # Reply-To mismatch
    reply_to = header_findings.get("Reply-To", {})
    reply_status = reply_to.get("status", "")

    if reply_status == "MISMATCH":
        score += 20
        reasons.append({
            "points": 20,
            "reason": "Reply-To domain differs from sender domain"
        })


    # -------------------------------------------------
    # URL ANALYSIS
    # -------------------------------------------------

    for result in url_findings:

        risk = result.get("risk", "")
        category = result.get("category", "")
        url = result.get("url", "")

        if risk == "HIGH":
            score += 30

            reasons.append({
                "points": 30,
                "reason": f"High-risk URL detected: {url}"
            })

        elif risk == "MEDIUM":
            score += 15

            reasons.append({
                "points": 15,
                "reason": f"Medium-risk URL detected: {url}"
            })

        elif risk == "REVIEW":
            score += 5

            reasons.append({
                "points": 5,
                "reason": f"URL requires review: {url}"
            })


    # -------------------------------------------------
    # ATTACHMENT ANALYSIS
    # -------------------------------------------------

    for attachment in attachment_findings:

        risk = attachment.get("risk", "")
        filename = attachment.get("filename", "")

        if risk == "HIGH":

            score += 35

            reasons.append({
                "points": 35,
                "reason": f"Potentially dangerous attachment: {filename}"
            })

        elif risk == "MEDIUM":

            score += 15

            reasons.append({
                "points": 15,
                "reason": f"Suspicious attachment type: {filename}"
            })


    # -------------------------------------------------
    # VIRUSTOTAL URL RESULTS
    # -------------------------------------------------

    for result in virustotal_findings.get("urls", []):

        status = result.get("status", "")
        indicator = result.get("indicator", "")

        stats = result.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if status == "MALICIOUS":

            score += 50

            reasons.append({
                "points": 50,
                "reason": (
                    f"VirusTotal detected malicious activity "
                    f"for URL: {indicator} "
                    f"({malicious} malicious engines)"
                )
            })

        elif status == "SUSPICIOUS":

            score += 25

            reasons.append({
                "points": 25,
                "reason": (
                    f"VirusTotal reported suspicious activity "
                    f"for URL: {indicator} "
                    f"({suspicious} suspicious engines)"
                )
            })


    # -------------------------------------------------
    # VIRUSTOTAL IP RESULTS
    # -------------------------------------------------

    for result in virustotal_findings.get("ips", []):

        status = result.get("status", "")
        indicator = result.get("indicator", "")

        stats = result.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if status == "MALICIOUS":

            score += 40

            reasons.append({
                "points": 40,
                "reason": (
                    f"VirusTotal detected malicious activity "
                    f"for IP: {indicator} "
                    f"({malicious} malicious engines)"
                )
            })

        elif status == "SUSPICIOUS":

            score += 20

            reasons.append({
                "points": 20,
                "reason": (
                    f"VirusTotal reported suspicious activity "
                    f"for IP: {indicator} "
                    f"({suspicious} suspicious engines)"
                )
            })


    # -------------------------------------------------
    # VIRUSTOTAL DOMAIN RESULTS
    # -------------------------------------------------

    for result in virustotal_findings.get("domains", []):

        status = result.get("status", "")
        indicator = result.get("indicator", "")

        stats = result.get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if status == "MALICIOUS":

            score += 40

            reasons.append({
                "points": 40,
                "reason": (
                    f"VirusTotal detected malicious activity "
                    f"for domain: {indicator} "
                    f"({malicious} malicious engines)"
                )
            })

        elif status == "SUSPICIOUS":

            score += 20

            reasons.append({
                "points": 20,
                "reason": (
                    f"VirusTotal reported suspicious activity "
                    f"for domain: {indicator} "
                    f"({suspicious} suspicious engines)"
                )
            })


    # -------------------------------------------------
    # IOC PRESENCE
    # -------------------------------------------------

    if iocs.get("ips"):
        reasons.append({
            "points": 0,
            "reason": (
                f"{len(iocs['ips'])} IP address IOC(s) extracted"
            )
        })

    if iocs.get("domains"):
        reasons.append({
            "points": 0,
            "reason": (
                f"{len(iocs['domains'])} domain IOC(s) extracted"
            )
        })


    # -------------------------------------------------
    # LIMIT SCORE
    # -------------------------------------------------

    if score > 100:
        score = 100


    # -------------------------------------------------
    # DETERMINE VERDICT
    # -------------------------------------------------

    if score >= 70:
        verdict = "MALICIOUS"

    elif score >= 40:
        verdict = "SUSPICIOUS"

    else:
        verdict = "BENIGN"


    # -------------------------------------------------
    # RISK LEVEL
    # -------------------------------------------------

    if score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    elif score >= 20:
        risk_level = "LOW"

    else:
        risk_level = "MINIMAL"


    return {
        "score": score,
        "verdict": verdict,
        "risk_level": risk_level,
        "reasons": reasons
    }
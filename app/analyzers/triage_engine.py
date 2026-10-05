def generate_triage(risk_result, virustotal_findings):
    score = risk_result.get("score", 0)
    verdict = risk_result.get("verdict", "BENIGN")

    # -----------------------------------------
    # DEFAULT VALUES
    # -----------------------------------------

    priority = "LOW"
    confidence = "LOW"
    action = "Monitor and review"

    # -----------------------------------------
    # MALICIOUS
    # -----------------------------------------

    if verdict == "MALICIOUS":

        priority = "CRITICAL"
        confidence = "HIGH"

        action = (
            "Isolate affected user or endpoint, "
            "block confirmed malicious indicators, "
            "preserve evidence, and escalate the incident."
        )

    # -----------------------------------------
    # SUSPICIOUS
    # -----------------------------------------

    elif verdict == "SUSPICIOUS":

        priority = "HIGH"
        confidence = "MEDIUM"

        action = (
            "Perform analyst review, validate the sender and "
            "destination infrastructure, and investigate related activity."
        )

    # -----------------------------------------
    # BENIGN
    # -----------------------------------------

    else:

        priority = "LOW"

        # Determine confidence from available evidence
        vt_confirmed = False

        for result in virustotal_findings.get("urls", []):
            if result.get("status") == "NO_MALICIOUS_DETECTION":
                vt_confirmed = True

        for result in virustotal_findings.get("ips", []):
            if result.get("status") == "NO_MALICIOUS_DETECTION":
                vt_confirmed = True

        for result in virustotal_findings.get("domains", []):
            if result.get("status") == "NO_MALICIOUS_DETECTION":
                vt_confirmed = True

        if vt_confirmed:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        action = (
            "No immediate containment action required. "
            "Retain the analysis record and monitor for related indicators."
        )

    # -----------------------------------------
    # SCORE-BASED PRIORITY ADJUSTMENT
    # -----------------------------------------

    if verdict == "BENIGN" and score >= 20:

        priority = "MEDIUM"

        action = (
            "Review the identified indicators and validate the "
            "email context before closing the event."
        )

    # -----------------------------------------
    # BUILD TRIAGE RESULT
    # -----------------------------------------

    return {
        "verdict": verdict,
        "score": score,
        "priority": priority,
        "confidence": confidence,
        "action": action
    }
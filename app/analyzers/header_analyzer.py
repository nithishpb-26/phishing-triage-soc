def analyze_headers(email_data):
    """
    Analyze SPF, DKIM, DMARC and Reply-To information.
    """

    findings = {}

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    received_spf = email_data.get("received_spf", "")

    if not received_spf:
        findings["SPF"] = {
            "status": "MISSING",
            "message": "SPF information was not found."
        }

    elif "pass" in received_spf.lower():
        findings["SPF"] = {
            "status": "PASS",
            "message": "SPF authentication passed."
        }

    elif "fail" in received_spf.lower():
        findings["SPF"] = {
            "status": "FAIL",
            "message": "SPF authentication failed."
        }

    else:
        findings["SPF"] = {
            "status": "REVIEW",
            "message": "SPF result requires review."
        }


    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    authentication_results = email_data.get(
        "authentication_results",
        ""
    )

    dkim_signature = email_data.get(
        "dkim_signature",
        ""
    )

    auth_lower = authentication_results.lower()

    if "dkim=pass" in auth_lower:

        findings["DKIM"] = {
            "status": "PASS",
            "message": "DKIM authentication passed."
        }

    elif "dkim=fail" in auth_lower:

        findings["DKIM"] = {
            "status": "FAIL",
            "message": "DKIM authentication failed."
        }

    elif dkim_signature:

        findings["DKIM"] = {
            "status": "PRESENT",
            "message": "DKIM signature is present, but the authentication result was not confirmed."
        }

    else:

        findings["DKIM"] = {
            "status": "MISSING",
            "message": "DKIM information was not found."
        }


    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if "dmarc=pass" in auth_lower:

        findings["DMARC"] = {
            "status": "PASS",
            "message": "DMARC authentication passed."
        }

    elif "dmarc=fail" in auth_lower:

        findings["DMARC"] = {
            "status": "FAIL",
            "message": "DMARC authentication failed."
        }

    else:

        findings["DMARC"] = {
            "status": "MISSING",
            "message": "DMARC result was not found."
        }


    # --------------------------------------------------------
    # Reply-To mismatch
    # --------------------------------------------------------

    sender = email_data.get("sender", "")
    reply_to = email_data.get("reply_to", "")

    if not reply_to:

        findings["Reply-To"] = {
            "status": "NOT_PRESENT",
            "message": "No Reply-To header was present."
        }

    else:

        sender_email = extract_email(sender)
        reply_email = extract_email(reply_to)

        if sender_email and reply_email:

            sender_domain = sender_email.split("@")[-1].lower()
            reply_domain = reply_email.split("@")[-1].lower()

            if sender_domain != reply_domain:

                findings["Reply-To"] = {
                    "status": "MISMATCH",
                    "message": (
                        "Reply-To domain differs from the sender domain."
                    )
                }

            else:

                findings["Reply-To"] = {
                    "status": "MATCH",
                    "message": (
                        "Reply-To domain matches the sender domain."
                    )
                }

        else:

            findings["Reply-To"] = {
                "status": "REVIEW",
                "message": "Unable to determine Reply-To relationship."
            }


    return findings


def extract_email(value):
    """
    Extract an email address from a header such as:

    Name <user@example.com>

    or:

    user@example.com
    """

    if not value:
        return ""

    value = value.strip()

    if "<" in value and ">" in value:
        return value.split("<", 1)[1].split(">", 1)[0].strip()

    if "@" in value:
        return value

    return ""
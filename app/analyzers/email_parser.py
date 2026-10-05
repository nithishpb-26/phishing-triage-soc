from email import policy
from email.parser import BytesParser


def parse_email(filepath):
    """
    Parse an .eml file and extract basic email information.
    """

    with open(filepath, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    # Basic headers
    sender = message.get("From", "")
    recipient = message.get("To", "")
    subject = message.get("Subject", "")
    date = message.get("Date", "")
    reply_to = message.get("Reply-To", "")
    message_id = message.get("Message-ID", "")

    # Security-related headers
    received_spf = message.get("Received-SPF", "")
    dkim_signature = message.get("DKIM-Signature", "")
    authentication_results = message.get(
        "Authentication-Results", ""
    )

    # Extract email body
    body = extract_body(message)

    # Extract attachments
    attachments = extract_attachments(message)

    return {
        "sender": sender,
        "recipient": recipient,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "message_id": message_id,
        "received_spf": received_spf,
        "dkim_signature": dkim_signature,
        "authentication_results": authentication_results,
        "body": body,
        "attachments": attachments
    }


def extract_body(message):
    """
    Extract plain-text or HTML email body.
    """

    if message.is_multipart():

        plain_text = None
        html_text = None

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = part.get_content_disposition()

            # Ignore attachments
            if disposition == "attachment":
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if content_type == "text/plain":
                plain_text = content

            elif content_type == "text/html":
                html_text = content

        if plain_text:
            return plain_text

        if html_text:
            return html_text

        return ""

    else:

        try:
            return message.get_content()
        except Exception:
            return ""


def extract_attachments(message):
    """
    Extract attachment metadata without executing attachments.
    """

    attachments = []

    for part in message.iter_attachments():

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(decode=True)

            if payload is None:
                size = 0
            else:
                size = len(payload)

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": size
            })

    return attachments
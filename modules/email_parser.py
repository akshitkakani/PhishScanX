import email
from email import policy
from email.parser import BytesParser

def parse_eml(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Extract headers
    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Date": msg["Date"],
        "Return-Path": msg["Return-Path"],
        "Reply-To": msg["Reply-To"],
        "Received-SPF": msg["Received-SPF"],
        "Authentication-Results": msg["Authentication-Results"],
        "DKIM-Signature": msg["DKIM-Signature"],
        "Message-ID": msg["Message-ID"],
        "X-Originating-IP": msg.get("X-Originating-IP", "N/A")
    }

    # Extract body (plain + html)
    body_plain = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                continue  # skip attachments

            if content_type == "text/plain":
                body_plain += part.get_content()
            elif content_type == "text/html":
                body_html += part.get_content()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_plain = msg.get_content()
        elif content_type == "text/html":
            body_html = msg.get_content()

    return {
        "headers": headers,
        "body_plain": body_plain,
        "body_html": body_html
    }

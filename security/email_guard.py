"""Email security to prevent header injection and HTML injection."""
import re
import html


def sanitize_email_header(value: str, max_length: int = 200) -> str:
    """
    Remove characters that could inject email headers (CR, LF, null bytes).
    Safe for use in email subject and header fields.
    """
    if not isinstance(value, str):
        return ''

    # Remove CR (\r), LF (\n), and null bytes (\x00)
    sanitized = re.sub(r'[\r\n\x00]', '', value)

    return sanitized[:max_length]


def sanitize_email_html_value(value: str) -> str:
    """
    HTML-escape a value before interpolating into email HTML body.
    Prevents XSS in HTML emails.
    """
    return html.escape(str(value))


def validate_recipient_email(email: str) -> bool:
    """
    Validate email format and reject if it contains header injection characters.
    Returns True if email is valid and safe.
    """
    if not isinstance(email, str):
        return False

    # RFC 5322 simplified pattern
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'

    # Check format
    if not re.match(pattern, email):
        return False

    # Check for header injection characters
    if '\r' in email or '\n' in email or '\x00' in email:
        return False

    return True

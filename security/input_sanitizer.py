"""
Input sanitization and validation for ESEAS.
Prevents SQL injection, XSS, and other input-based attacks.
"""

import re
import bleach
from markupsafe import escape

# ── SQL INJECTION DETECTION ──────────────────────────────────────
SQL_INJECTION_PATTERNS = [
    r"(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\s",
    r"--\s*$",
    r";\s*(DROP|DELETE|INSERT|UPDATE|SELECT)",
    r"'\s*(OR|AND)\s*'?\d",
    r"/\*.*\*/",
    r"xp_\w+",
    r"WAITFOR\s+DELAY",
]

# ── XSS PREVENTION ───────────────────────────────────────────────
ALLOWED_TAGS = []  # No HTML tags in user inputs by default
ALLOWED_ATTRIBUTES = {}

ALLOWED_RICH_TEXT_TAGS = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'h3', 'h4', 'a']
ALLOWED_RICH_TEXT_ATTRS = {'a': ['href', 'title'], '*': ['class']}


def is_sql_injection(value: str) -> bool:
    """
    Return True if the value looks like a SQL injection attempt.

    Args:
        value: String to check

    Returns:
        bool: True if suspicious SQL patterns detected
    """
    if not isinstance(value, str):
        return False
    upper = value.upper()
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, upper, re.IGNORECASE):
            return True
    return False


def sanitize_string(value: str, max_length: int = 500) -> str:
    """
    Clean a string input. Raises ValueError if injection detected.
    Use for campaign names, quiz answers, user descriptions, etc.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length

    Returns:
        str: Sanitized string

    Raises:
        ValueError: If input is malicious or too long
    """
    if not isinstance(value, str):
        return str(value)

    value = value.strip()

    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")

    if is_sql_injection(value):
        raise ValueError("Potentially malicious input detected")

    # Remove null bytes (can bypass some filters)
    value = value.replace('\x00', '')

    return value


def sanitize_url(url: str) -> str:
    """
    Validate and sanitize a URL string.
    Prevents SSRF attacks and malformed URLs.

    Args:
        url: URL to sanitize

    Returns:
        str: Sanitized URL

    Raises:
        ValueError: If URL is invalid or dangerous
    """
    url = url.strip()

    if len(url) > 2048:
        raise ValueError("URL too long (max 2048 chars)")

    # Must start with http:// or https://
    if not re.match(r'^https?://', url, re.IGNORECASE):
        raise ValueError("URL must start with http:// or https://")

    # Block internal network ranges (SSRF prevention)
    blocked_patterns = [
        r'^https?://localhost',
        r'^https?://127\.',
        r'^https?://0\.0\.0\.0',
        r'^https?://10\.',
        r'^https?://172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^https?://192\.168\.',
        r'^https?://169\.254\.',
        r'^https?://\[::1\]',
        r'^https?://metadata\.google',
        r'^https?://169\.254\.169\.254',  # AWS metadata service
        r'^https?://\[fc00',  # IPv6 private
        r'^https?://\[fd00',  # IPv6 private
    ]

    for pattern in blocked_patterns:
        if re.match(pattern, url, re.IGNORECASE):
            raise ValueError("URL points to a private or reserved address (SSRF blocked)")

    return url


def sanitize_html_output(value: str) -> str:
    """
    Strip all HTML from user-supplied content before rendering.
    Use in Jinja2 templates with {{ value | safe_user }} filter.

    Args:
        value: HTML string to sanitize

    Returns:
        str: Plain text with HTML stripped
    """
    if not isinstance(value, str):
        return str(value)
    return bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)


def sanitize_rich_text(value: str) -> str:
    """
    For fields that allow limited formatting (training module content — admin only).
    Allows safe HTML like <b>, <i>, <p>, <ul>, <li>, <a> tags.

    Args:
        value: HTML string with limited formatting

    Returns:
        str: Sanitized HTML
    """
    if not isinstance(value, str):
        return str(value)

    # Sanitize URLs in href attributes
    def link_callback(attrs, new=False):
        url_key = (None, 'href')
        if url_key in attrs:
            try:
                sanitize_url(attrs[url_key])
            except ValueError:
                del attrs[url_key]
        return attrs

    return bleach.clean(
        value,
        tags=ALLOWED_RICH_TEXT_TAGS,
        attributes=ALLOWED_RICH_TEXT_ATTRS,
        strip=True,
        protocols=['http', 'https', 'mailto'],
    )


def sanitize_email(email: str) -> str:
    """
    Validate email format.

    Args:
        email: Email address to sanitize

    Returns:
        str: Sanitized email (lowercase)

    Raises:
        ValueError: If email is invalid
    """
    email = email.strip().lower()

    if len(email) > 254:
        raise ValueError("Email too long")

    # Basic RFC 5322 regex
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")

    return email


def sanitize_filename(filename: str) -> str:
    """
    Sanitize uploaded filenames to prevent path traversal.

    Args:
        filename: Original filename

    Returns:
        str: Safe filename

    Raises:
        ValueError: If filename is dangerous
    """
    # Remove directory traversal attempts
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')

    # Allow only alphanumeric, dash, underscore, and dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)

    if not filename:
        raise ValueError("Filename is invalid")

    if len(filename) > 255:
        filename = filename[:255]

    return filename


class ValidationError(ValueError):
    """Custom exception for validation failures."""
    pass

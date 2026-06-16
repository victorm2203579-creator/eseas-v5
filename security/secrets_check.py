"""Detect missing secrets and warn during app startup."""
import os
import logging


REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'VIRUSTOTAL_API_KEY',
    'GOOGLE_SAFE_BROWSING_API_KEY',
    'URLHAUS_API_KEY',
    'DATABASE_URL',
    'MAIL_USERNAME',
    'MAIL_PASSWORD',
]


def check_secrets_in_environment():
    """
    Check if all required environment variables are set.
    Logs warnings for missing secrets.
    Called at app startup to catch configuration issues early.
    """
    missing = []
    for var in REQUIRED_ENV_VARS:
        if not os.environ.get(var):
            missing.append(var)

    if missing:
        logging.warning(
            f"Security Warning: Missing environment variables (add to .env): "
            f"{', '.join(missing)}"
        )

    return missing


def check_no_hardcoded_secrets():
    """
    Scan Python files for obvious hardcoded secrets.
    Logs errors if potential secrets found in code.
    """
    import re
    import pathlib

    patterns = [
        r'API_KEY\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
        r'SECRET\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
        r'PASSWORD\s*=\s*["\'][^"\']{6,}["\']',
    ]

    project_root = pathlib.Path('.')
    for py_file in project_root.rglob('*.py'):
        # Skip test and security module files
        if 'security' in str(py_file) or 'test' in str(py_file):
            continue

        try:
            content = py_file.read_text(errors='ignore')
        except Exception:
            continue

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                logging.error(
                    f"Possible hardcoded secret found in {py_file}: "
                    f"Move to .env file"
                )

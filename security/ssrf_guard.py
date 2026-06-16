"""
Server-Side Request Forgery (SSRF) Protection for ESEAS.
Prevents attackers from abusing the URL analyzer to access internal services.
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple

import requests

# All private, loopback, link-local, and metadata ranges
BLOCKED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),           # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),        # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),       # Private Class C
    ipaddress.ip_network('127.0.0.0/8'),          # Loopback
    ipaddress.ip_network('0.0.0.0/8'),            # Current network
    ipaddress.ip_network('169.254.0.0/16'),       # Link-local / AWS metadata
    ipaddress.ip_network('100.64.0.0/10'),        # Shared address space (CGN)
    ipaddress.ip_network('224.0.0.0/4'),          # Multicast
    ipaddress.ip_network('240.0.0.0/4'),          # Reserved
    ipaddress.ip_network('::1/128'),              # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),             # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),            # IPv6 link-local
    ipaddress.ip_network('::/128'),               # IPv6 unspecified
]

# Explicitly blocked domain patterns
BLOCKED_DOMAINS = [
    'localhost',
    'metadata.google.internal',
    'metadata.goog',
    'instance-data',
    'link-local',
    'local',
    '169.254.169.254',                            # AWS metadata endpoint
    '127.0.0.1',
    '0.0.0.0',
]

# Blocked URL schemes (non-HTTP)
BLOCKED_SCHEMES = ['file', 'ftp', 'gopher', 'ldap', 'dict', 'sftp', 'tftp']


class SSRFBlockedException(ValueError):
    """Raised when SSRF protection blocks a URL."""
    pass


def is_safe_url(url: str) -> Tuple[bool, str]:
    """
    Validate that a URL is safe to fetch.

    Checks:
    1. URL format validity
    2. Scheme is http/https only
    3. Hostname is not in blocklist
    4. Resolved IP is not in private ranges
    5. Port is not restricted (e.g., no SSH, DB ports)

    Args:
        url: URL to validate

    Returns:
        Tuple[bool, str]: (is_safe, reason)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Block non-HTTP schemes
    scheme = parsed.scheme.lower()
    if scheme in BLOCKED_SCHEMES:
        return False, f"Scheme '{scheme}' is not allowed"

    if scheme not in ('http', 'https'):
        return False, "Only http and https are allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname in URL"

    # Block known bad domain patterns
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if hostname_lower == blocked.lower() or hostname_lower.endswith('.' + blocked.lower()):
            return False, f"Hostname '{hostname}' is blocked"

    # Block ports commonly used by internal services
    port = parsed.port
    restricted_ports = [
        25,    # SMTP
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        27017, # MongoDB
        8080,  # Common HTTP proxy/admin
        9200,  # Elasticsearch
        5000,  # Flask (local dev)
        3000,  # Node.js (local dev)
        22,    # SSH
        23,    # Telnet
        139,   # SMB
        445,   # SMB
        135,   # DCOM
        161,   # SNMP
        162,   # SNMP
    ]
    if port and port in restricted_ports:
        return False, f"Port {port} is restricted (internal service)"

    # Resolve DNS and check the resolved IP
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Check against all blocked ranges
        for blocked_range in BLOCKED_RANGES:
            if ip in blocked_range:
                return False, f"URL resolves to blocked IP ({ip_str}): {blocked_range}"

    except socket.gaierror:
        # Cannot resolve — treat as safe (URL is unreachable anyway)
        # This prevents SSRF-by-DoS (blocking resolution attempts)
        return True, "OK (DNS unresolvable)"

    except Exception as e:
        return False, f"DNS resolution error: {str(e)}"

    return True, "OK"


def safe_fetch(
    url: str,
    timeout: int = 5,
    max_size: int = 50000,
    allow_redirects: bool = True,
) -> Tuple[bool, str, int]:
    """
    Safely fetch a URL with SSRF protection.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds
        max_size: Maximum response size in bytes
        allow_redirects: Whether to follow redirects (checked for SSRF)

    Returns:
        Tuple[bool, str, int]: (success, content, status_code)

    Raises:
        SSRFBlockedException: If URL is blocked by SSRF protection
        requests.RequestException: If network request fails
    """
    # Validate initial URL
    is_safe, reason = is_safe_url(url)
    if not is_safe:
        raise SSRFBlockedException(f"SSRF blocked: {reason}")

    try:
        # Don't follow redirects automatically — validate each redirect manually
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={
                'User-Agent': 'ESEAS-URLScanner/2.0 (Security)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
            verify=True,  # Verify SSL certificates
        )

        # Handle redirects manually to validate each one
        redirects_followed = 0
        max_redirects = 5  # Prevent redirect loops

        while response.status_code in (301, 302, 303, 307, 308) and allow_redirects:
            if redirects_followed >= max_redirects:
                break

            redirect_url = response.headers.get('Location', '')
            if not redirect_url:
                break

            # Validate the redirect destination
            is_safe, reason = is_safe_url(redirect_url)
            if not is_safe:
                raise SSRFBlockedException(f"SSRF blocked in redirect: {reason}")

            # Follow the safe redirect
            response = requests.get(
                redirect_url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    'User-Agent': 'ESEAS-URLScanner/2.0 (Security)',
                },
                verify=True,
            )
            redirects_followed += 1

        # Cap response size
        content = response.text[:max_size]
        return True, content, response.status_code

    except SSRFBlockedException:
        raise
    except requests.exceptions.Timeout:
        raise requests.RequestException("Request timeout")
    except requests.exceptions.ConnectionError as e:
        raise requests.RequestException(f"Connection failed: {str(e)}")
    except Exception as e:
        raise requests.RequestException(f"Request error: {str(e)}")


def validate_domain_for_campaign(domain: str) -> Tuple[bool, str]:
    """
    Special validation for phishing campaign domains.
    More permissive than safe_fetch but still prevents obvious attacks.

    Args:
        domain: Domain to validate for phishing campaign

    Returns:
        Tuple[bool, str]: (is_valid, reason)
    """
    try:
        parsed = urlparse(domain if '://' in domain else 'https://' + domain)
    except Exception:
        return False, "Invalid domain format"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname"

    # Block obviously private domains
    hostname_lower = hostname.lower()
    if hostname_lower in ('localhost', '127.0.0.1', '0.0.0.0'):
        return False, "Domain resolves to localhost"

    # Try to resolve and check IP
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Allow public IPs only
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, f"Domain resolves to private IP ({ip_str})"

    except socket.gaierror:
        return False, "Domain could not be resolved"
    except Exception:
        pass  # If resolution fails, allow it (we can validate at runtime)

    return True, "OK"

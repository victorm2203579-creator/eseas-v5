"""
Feature extractor for phishing URL detection.

FeatureExtractor.extract(url, fast=False) → dict of 16 features.

When fast=True the two slow network calls (whois, redirect-follow)
are skipped and return safe defaults.  Use fast=True for batch
training; use fast=False (default) for real-time predictions.
"""

import re
import socket
from urllib.parse import urlparse, parse_qs

# ── optional slow deps ──────────────────────────────────────
try:
    import whois as _whois
    _WHOIS_OK = True
except ImportError:
    _WHOIS_OK = False

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# ── constants ───────────────────────────────────────────────
_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'is.gd', 'rb.gy', 'short.link', 'cutt.ly',
    'shorte.st', 'adf.ly', 'tiny.cc', 'clck.ru',
}

_SUSPICIOUS_KEYWORDS = {
    'login', 'verify', 'secure', 'update', 'bank', 'account',
    'confirm', 'password', 'signin', 'wallet', 'alert', 'suspended',
    'credential', 'billing', 'paypal', 'ebay', 'amazon',
}

_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)


def _normalise(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


class FeatureExtractor:
    """Extract 16 phishing-detection features from a URL string."""

    # Feature names in training order — must stay stable
    FEATURE_NAMES = [
        'url_length', 'has_ip_address', 'special_char_count',
        'subdomain_count', 'has_https', 'domain_age_days',
        'url_shortener', 'suspicious_keywords', 'redirect_count',
        'path_length', 'query_param_count', 'has_port',
        'domain_length', 'prefix_suffix', 'double_slash_redirect',
        'has_at_symbol',
    ]

    def extract(self, url: str, fast: bool = False) -> dict:
        """Return a dict with all 16 features.  Never raises."""
        try:
            return self._extract(url, fast=fast)
        except Exception:
            return self._defaults()

    def extract_batch(self, urls, fast: bool = True):
        return [self.extract(u, fast=fast) for u in urls]

    # ── private ─────────────────────────────────────────────

    def _extract(self, url: str, fast: bool) -> dict:
        url = _normalise(url)
        parsed = urlparse(url)
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''

        # Strip port and credentials from netloc
        host = netloc.split('@')[-1]          # drop user:pass@
        host = host.rsplit(':', 1)[0]          # drop :port
        host = host.lower().strip('.')

        parts = host.split('.')

        # 1 url_length
        url_length = len(url)

        # 2 has_ip_address
        has_ip_address = int(bool(_IP_RE.match(host)))
        if not has_ip_address:
            try:
                socket.inet_aton(host)
                has_ip_address = 1
            except Exception:
                pass

        # 3 special_char_count  (@, //, --, ~, %)
        special_char_count = (
            url.count('@') +
            url.count('//') +
            url.count('--') +
            url.count('~') +
            url.count('%')
        )

        # 4 subdomain_count  (dots in host minus 1 for TLD, min 0)
        subdomain_count = max(len(parts) - 2, 0)

        # 5 has_https
        has_https = int(parsed.scheme == 'https')

        # 6 domain_age_days  (slow — whois lookup)
        domain_age_days = self._domain_age(host, fast)

        # 7 url_shortener
        root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host
        url_shortener = int(root_domain in _SHORTENERS)

        # 8 suspicious_keywords  (count of matched words)
        url_lower = url.lower()
        suspicious_keywords = sum(
            1 for kw in _SUSPICIOUS_KEYWORDS if kw in url_lower)

        # 9 redirect_count  (slow — follow redirects)
        redirect_count = self._redirect_count(url, fast)

        # 10 path_length
        path_length = len(path)

        # 11 query_param_count
        query_param_count = len(parse_qs(query))

        # 12 has_port  (non-standard port specified)
        port_match = re.search(r':(\d+)', netloc.split('@')[-1])
        if port_match:
            port = int(port_match.group(1))
            has_port = int(port not in (80, 443))
        else:
            has_port = 0

        # 13 domain_length
        domain_length = len(host)

        # 14 prefix_suffix  (hyphen at start or end of domain)
        prefix_suffix = int(host.startswith('-') or host.endswith('-')
                            or '-' in root_domain)

        # 15 double_slash_redirect  (// appears after scheme)
        tail = url[url.find('//') + 2:] if '//' in url else url
        double_slash_redirect = int('//' in tail)

        # 16 has_at_symbol
        has_at_symbol = int('@' in url)

        return {
            'url_length':           url_length,
            'has_ip_address':       has_ip_address,
            'special_char_count':   special_char_count,
            'subdomain_count':      subdomain_count,
            'has_https':            has_https,
            'domain_age_days':      domain_age_days,
            'url_shortener':        url_shortener,
            'suspicious_keywords':  suspicious_keywords,
            'redirect_count':       redirect_count,
            'path_length':          path_length,
            'query_param_count':    query_param_count,
            'has_port':             has_port,
            'domain_length':        domain_length,
            'prefix_suffix':        prefix_suffix,
            'double_slash_redirect': double_slash_redirect,
            'has_at_symbol':        has_at_symbol,
        }

    @staticmethod
    def _domain_age(host: str, fast: bool) -> int:
        if fast or not _WHOIS_OK:
            return -1
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutTimeout
            from datetime import datetime, timezone

            with ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(_whois.whois, host)
                try:
                    w = future.result(timeout=5)
                except _FutTimeout:
                    return -1

            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation is None:
                return -1
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            return max(int((now - creation).days), 0)
        except Exception:
            return -1

    @staticmethod
    def _redirect_count(url: str, fast: bool) -> int:
        if fast or not _REQUESTS_OK:
            return 0
        try:
            resp = _requests.get(
                url, allow_redirects=True,
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0'},
                stream=True,
            )
            return min(len(resp.history), 5)
        except Exception:
            return 0

    @staticmethod
    def _defaults() -> dict:
        return {name: 0 for name in FeatureExtractor.FEATURE_NAMES}


# ── backward-compat alias used by the old train_model.py ────
URLFeatureExtractor = FeatureExtractor


# ── threshold rules for feature flags ───────────────────────
FEATURE_THRESHOLDS = {
    'url_length':            {'warn': 75,  'fail': 150,  'higher_is_bad': True},
    'has_ip_address':        {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'special_char_count':    {'warn': 2,   'fail': 5,    'higher_is_bad': True},
    'subdomain_count':       {'warn': 2,   'fail': 4,    'higher_is_bad': True},
    'has_https':             {'warn': 0.5, 'fail': -1,   'higher_is_bad': False},
    'domain_age_days':       {'warn': 180, 'fail': 30,   'higher_is_bad': False},
    'url_shortener':         {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'suspicious_keywords':   {'warn': 1,   'fail': 3,    'higher_is_bad': True},
    'redirect_count':        {'warn': 1,   'fail': 3,    'higher_is_bad': True},
    'path_length':           {'warn': 50,  'fail': 100,  'higher_is_bad': True},
    'query_param_count':     {'warn': 3,   'fail': 6,    'higher_is_bad': True},
    'has_port':              {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'domain_length':         {'warn': 20,  'fail': 40,   'higher_is_bad': True},
    'prefix_suffix':         {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'double_slash_redirect': {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'has_at_symbol':         {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
}


def get_feature_flag(name: str, value) -> str:
    """Return 'pass', 'warn', or 'fail' for a feature value."""
    t = FEATURE_THRESHOLDS.get(name)
    if t is None:
        return 'pass'
    higher_is_bad = t['higher_is_bad']
    warn_thresh = t['warn']
    fail_thresh = t['fail']

    if higher_is_bad:
        if value >= fail_thresh:
            return 'fail'
        if value >= warn_thresh:
            return 'warn'
        return 'pass'
    else:
        # lower is bad (e.g. has_https=0 is bad, domain_age_days low is bad)
        if fail_thresh != -1 and value <= fail_thresh:
            return 'fail'
        if value <= warn_thresh:
            return 'warn'
        return 'pass'

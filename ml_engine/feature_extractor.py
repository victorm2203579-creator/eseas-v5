"""
Enhanced feature extractor for phishing URL detection.

Extracts 30 features covering URL structure, WHOIS, SSL, page content, and web traffic.

FeatureExtractor.extract(url, fast=False) â†’ dict of 30 features.

When fast=True, slow network calls (page fetch, whois, dns, traffic checks) are skipped.
Use fast=True for batch training; use fast=False for real-time predictions.
"""

import re
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

# â”€â”€ optional deps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False

# â”€â”€ constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def _normalise(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


class FeatureExtractor:
    """Extract 30 phishing-detection features from a URL string."""

    # Feature names in training order â€” must stay stable for model compatibility
    FEATURE_NAMES = [
        # Original 16
        'having_IP_Address',
        'URL_Length',
        'Shortining_Service',
        'having_At_Symbol',
        'double_slash_redirecting',
        'Prefix_Suffix',
        'having_Sub_Domain',
        'SSLfinal_State',
        'Domain_registeration_length',
        'Favicon',
        'port',
        'HTTPS_token',
        'Request_URL',
        'URL_of_Anchor',
        'Links_in_tags',
        'SFH',
        'Submitting_to_email',
        'Abnormal_URL',
        'Redirect',
        'on_mouseover',
        'RightClick',
        'popUpWidnow',
        'Iframe',
        'age_of_domain',
        'DNSRecord',
        'web_traffic',
        'Page_Rank',
        'Google_Index',
        'Links_pointing_to_page',
        'Statistical_report',
    ]

    def extract(self, url: str, fast: bool = False) -> dict:
        """Return a dict with all 30 features. Never raises."""
        try:
            return self._extract(url, fast=fast)
        except Exception:
            return self._defaults()

    def extract_batch(self, urls, fast: bool = True):
        return [self.extract(u, fast=fast) for u in urls]

    # â”€â”€ private â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _extract(self, url: str, fast: bool) -> dict:
        url = _normalise(url)
        parsed = urlparse(url)
        netloc = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        scheme = parsed.scheme or ''

        # Strip port and credentials from netloc
        host = netloc.split('@')[-1]
        host = host.rsplit(':', 1)[0]
        host = host.lower().strip('.')

        parts = host.split('.')
        root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host

        # Feature 1: having_IP_Address
        has_ip = int(bool(_IP_RE.match(host)))
        if not has_ip:
            try:
                socket.inet_aton(host)
                has_ip = 1
            except Exception:
                pass

        # Feature 2: URL_Length
        url_len = len(url)
        url_length = 1 if url_len > 75 else (0 if 54 <= url_len <= 75 else -1)

        # Feature 3: Shortining_Service
        url_shortener = 1 if root_domain in _SHORTENERS else -1

        # Feature 4: having_At_Symbol
        has_at = 1 if '@' in url else -1

        # Feature 5: double_slash_redirecting
        tail = url[url.find('//') + 2:] if '//' in url else url
        double_slash = 1 if '//' in tail else -1

        # Feature 6: Prefix_Suffix
        prefix_suffix = 1 if (host.startswith('-') or host.endswith('-') or '-' in root_domain) else -1

        # Feature 7: having_Sub_Domain
        subdomain_cnt = max(len(parts) - 2, 0)
        sub_domain = 1 if subdomain_cnt > 3 else (0 if 2 <= subdomain_cnt <= 3 else -1)

        # Feature 8: SSLfinal_State
        ssl_state = self._check_ssl_cert(host, fast)

        # Feature 9: Domain_registeration_length (WHOIS)
        domain_reg_len = self._domain_registration_length(host, fast)

        # Feature 10: Favicon
        favicon = self._favicon_check(url, host, fast)

        # Feature 11: port
        port_match = re.search(r':(\d+)', netloc.split('@')[-1])
        port_val = 1 if port_match else -1

        # Feature 12: HTTPS_token
        https_token = 1 if 'https' in parsed.path.lower() or 'https' in parsed.query.lower() else -1

        # Features 13-16: Require page fetch
        page_content = self._fetch_page(url, fast)
        req_url, url_anchor, links_tags, sfh = self._analyze_page_content(page_content, url)

        # Feature 13: Request_URL (% external objects)
        # Placeholder: returns -1 if most external, 0 if unknown, 1 if mostly internal

        # Feature 14: URL_of_Anchor (% external anchor hrefs)

        # Feature 15: Links_in_tags (% links in meta/script/link tags external)

        # Feature 16: SFH (form action suspicious)

        # Feature 17: Submitting_to_email
        submit_email = self._check_form_submission(page_content)

        # Feature 18: Abnormal_URL
        abnormal_url = self._check_abnormal_url(host, fast)

        # Feature 19: Redirect
        redirect_cnt = self._redirect_count(url, fast)
        redirect = 1 if redirect_cnt > 4 else (-1 if redirect_cnt == 0 else 0)

        # Features 20-23: Page behavior analysis
        mouseover = self._check_mouseover(page_content)
        rightclick = self._check_rightclick(page_content)
        popup = self._check_popup(page_content)
        iframe = self._check_iframe(page_content)

        # Feature 24: age_of_domain (months)
        domain_age = self._domain_age_months(host, fast)
        age_domain = 1 if domain_age < 6 else (-1 if domain_age > 12 else 0)
        domain_age_days = domain_age * 30 if domain_age > 0 else -1

        # Feature 25: DNSRecord
        dns_record = self._check_dns_record(host, fast)

        # Feature 26: web_traffic (Alexa-like ranking estimation)
        web_traffic = self._estimate_web_traffic(host, fast)

        # Feature 27: Page_Rank (estimated 0-10)
        page_rank = self._estimate_page_rank(host, fast)

        # Feature 28: Google_Index
        google_index = self._check_google_index(host, fast)

        # Feature 29: Links_pointing_to_page (backlinks)
        backlinks = self._estimate_backlinks(host, fast)

        # Feature 30: Statistical_report (in known phishing DB)
        stat_report = self._check_phishing_reports(host, fast)

        return {
            'having_IP_Address': has_ip,
            'URL_Length': url_length,
            'Shortining_Service': url_shortener,
            'having_At_Symbol': has_at,
            'double_slash_redirecting': double_slash,
            'Prefix_Suffix': prefix_suffix,
            'having_Sub_Domain': sub_domain,
            'SSLfinal_State': ssl_state,
            'Domain_registeration_length': domain_reg_len,
            'Favicon': favicon,
            'port': port_val,
            'HTTPS_token': https_token,
            'Request_URL': req_url,
            'URL_of_Anchor': url_anchor,
            'Links_in_tags': links_tags,
            'SFH': sfh,
            'Submitting_to_email': submit_email,
            'Abnormal_URL': abnormal_url,
            'Redirect': redirect,
            'on_mouseover': mouseover,
            'RightClick': rightclick,
            'popUpWidnow': popup,
            'Iframe': iframe,
            'age_of_domain': age_domain,
            'domain_age_days': domain_age_days,
            'DNSRecord': dns_record,
            'web_traffic': web_traffic,
            'Page_Rank': page_rank,
            'Google_Index': google_index,
            'Links_pointing_to_page': backlinks,
            'Statistical_report': stat_report,
        }

    @staticmethod
    def _check_ssl_cert(host: str, fast: bool) -> int:
        """Feature 8: Check if SSL certificate is valid. Returns 1=HTTPS trusted, 0=untrusted, -1=HTTP."""
        if fast:
            return 0
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return 1 if cert else 0
        except Exception:
            return 0

    @staticmethod
    def _domain_registration_length(host: str, fast: bool) -> int:
        """Feature 9: Domain registration length in months. 1=short (<12mo), -1=long (>24mo), 0=medium."""
        if fast or not _WHOIS_OK:
            return 0
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
            ex = ThreadPoolExecutor(max_workers=1)
            try:
                future = ex.submit(_whois.whois, host)
                try:
                    w = future.result(timeout=3)
                except FutTimeout:
                    return 0
            finally:
                ex.shutdown(wait=False)  # don't block on a hung WHOIS socket

            if not w.expiration_date:
                return 0

            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry is None:
                return 0

            now = datetime.now(timezone.utc)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            months_left = (expiry - now).days / 30
            return 1 if months_left < 12 else (-1 if months_left > 24 else 0)
        except Exception:
            return 0

    @staticmethod
    def _favicon_check(url: str, host: str, fast: bool) -> int:
        """Feature 10: Check if favicon is loaded from external domain. Returns 1=external, -1=same domain."""
        if fast or not _BS4_OK or not _REQUESTS_OK:
            return 0
        try:
            resp = _requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(resp.content, 'html.parser')
            favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
            if not favicon or not favicon.get('href'):
                return -1

            favicon_url = favicon['href']
            favicon_host = urlparse(favicon_url).netloc or host
            return 1 if favicon_host != host else -1
        except Exception:
            return 0

    @staticmethod
    def _fetch_page(url: str, fast: bool) -> str:
        """Fetch page content with timeout. Returns HTML or empty string."""
        if fast or not _REQUESTS_OK:
            return ""
        try:
            resp = _requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            return resp.text[:50000] if resp.status_code == 200 else ""
        except Exception:
            return ""

    @staticmethod
    def _analyze_page_content(html: str, url: str) -> tuple:
        """
        Analyze page content for external objects, anchors, and form handlers.
        Returns (req_url, url_anchor, links_tags, sfh) where each is -1/0/1.
        """
        if not html or not _BS4_OK:
            return 0, 0, 0, 0

        try:
            soup = BeautifulSoup(html, 'html.parser')
            parsed_url = urlparse(url)
            host = parsed_url.netloc

            # Feature 13: Request_URL â€” % of external img/script/link/object
            external_objs = 0
            total_objs = 0
            for tag in soup.find_all(['img', 'script', 'link', 'object']):
                src = tag.get('src') or tag.get('href')
                if src:
                    total_objs += 1
                    src_host = urlparse(src).netloc
                    if src_host and src_host != host:
                        external_objs += 1

            req_url_pct = (external_objs / total_objs * 100) if total_objs > 0 else 0
            req_url = 1 if req_url_pct > 22 else (-1 if req_url_pct < 22 else 0)

            # Feature 14: URL_of_Anchor â€” % of anchor hrefs pointing external/empty
            external_anchors = 0
            total_anchors = 0
            for a in soup.find_all('a'):
                href = a.get('href')
                if href:
                    total_anchors += 1
                    if href in ('', '#', 'about:blank') or urlparse(href).netloc != host:
                        external_anchors += 1

            url_anchor_pct = (external_anchors / total_anchors * 100) if total_anchors > 0 else 0
            url_anchor = 1 if url_anchor_pct > 67 else (-1 if url_anchor_pct < 67 else 0)

            # Feature 15: Links_in_tags â€” % of links in meta/script/link external
            external_meta_links = 0
            total_meta_links = 0
            for tag in soup.find_all(['meta', 'script', 'link']):
                content = tag.get('content') or tag.get('src') or tag.get('href') or ''
                if 'http' in content:
                    total_meta_links += 1
                    if urlparse(content).netloc != host:
                        external_meta_links += 1

            links_tags_pct = (external_meta_links / total_meta_links * 100) if total_meta_links > 0 else 0
            links_tags = 1 if links_tags_pct > 81 else (-1 if links_tags_pct < 81 else 0)

            # Feature 16: SFH â€” Server Form Handler suspicious
            form = soup.find('form')
            sfh_val = -1
            if form:
                action = form.get('action', '').strip()
                if action in ('', 'about:blank'):
                    sfh_val = 1
                elif urlparse(action).netloc and urlparse(action).netloc != host:
                    sfh_val = 1

            return req_url, url_anchor, links_tags, sfh_val
        except Exception:
            return 0, 0, 0, 0

    @staticmethod
    def _check_form_submission(html: str) -> int:
        """Feature 17: Check if form submits to mailto:. Returns 1=yes (suspicious), -1=no."""
        if not html or not _BS4_OK:
            return 0
        try:
            soup = BeautifulSoup(html, 'html.parser')
            form = soup.find('form')
            if form:
                action = form.get('action', '').lower()
                if action.startswith('mailto:'):
                    return 1
            return -1
        except Exception:
            return 0

    @staticmethod
    def _check_abnormal_url(host: str, fast: bool) -> int:
        """Feature 18: Check if WHOIS host differs from URL host. Returns 1=abnormal, -1=normal."""
        if fast or not _WHOIS_OK:
            return 0
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
            ex = ThreadPoolExecutor(max_workers=1)
            try:
                future = ex.submit(_whois.whois, host)
                try:
                    w = future.result(timeout=3)
                except FutTimeout:
                    return 0
            finally:
                ex.shutdown(wait=False)  # don't block on a hung WHOIS socket

            registrant_org = (w.registrant_org or '').lower()
            return 1 if registrant_org and registrant_org not in host.lower() else -1
        except Exception:
            return 0

    @staticmethod
    def _redirect_count(url: str, fast: bool) -> int:
        """Feature 19: Count HTTP redirects. Returns count (capped at 5)."""
        if fast or not _REQUESTS_OK:
            return 0
        try:
            resp = _requests.get(url, allow_redirects=True, timeout=3,
                                headers={'User-Agent': 'Mozilla/5.0'}, stream=True)
            return min(len(resp.history), 5)
        except Exception:
            return 0

    @staticmethod
    def _check_mouseover(html: str) -> int:
        """Feature 20: Check for onmouseover changing status bar. Returns 1=yes, -1=no."""
        if not html:
            return 0
        return 1 if 'onmouseover' in html.lower() and 'window.status' in html.lower() else -1

    @staticmethod
    def _check_rightclick(html: str) -> int:
        """Feature 21: Check if right-click is disabled. Returns 1=disabled, -1=enabled."""
        if not html:
            return 0
        return 1 if 'oncontextmenu' in html.lower() or 'return false' in html.lower() else -1

    @staticmethod
    def _check_popup(html: str) -> int:
        """Feature 22: Check for pop-up windows asking for credentials. Returns 1=yes, -1=no."""
        if not html:
            return 0
        has_popup = 'window.open' in html.lower() or 'popup' in html.lower()
        has_cred_ask = any(kw in html.lower() for kw in ['password', 'credentials', 'username', 'login'])
        return 1 if (has_popup and has_cred_ask) else -1

    @staticmethod
    def _check_iframe(html: str) -> int:
        """Feature 23: Check for hidden iframe. Returns 1=yes, -1=no."""
        if not html or not _BS4_OK:
            return 0
        try:
            soup = BeautifulSoup(html, 'html.parser')
            iframes = soup.find_all('iframe')
            hidden = sum(1 for i in iframes if i.get('style', '').lower().find('display:none') >= 0 or
                                               i.get('hidden') is not None)
            return 1 if hidden > 0 else -1
        except Exception:
            return 0

    @staticmethod
    def _domain_age_months(host: str, fast: bool) -> int:
        """Feature 24: Domain age in months. Returns months (0 if unknown)."""
        if fast:
            return 0

        # Strip port if present
        host = host.split(':')[0].lower()

        def _months_from_date(creation):
            if isinstance(creation, list):
                creation = creation[0]
            if creation is None:
                return None
            now = datetime.now(timezone.utc)
            if hasattr(creation, 'tzinfo') and creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            return max(int((now - creation).days / 30), 0)

        # Attempt 1: python-whois library
        if _WHOIS_OK:
            try:
                from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
                ex = ThreadPoolExecutor(max_workers=1)
                try:
                    future = ex.submit(_whois.whois, host)
                    try:
                        w = future.result(timeout=3)
                    except FutTimeout:
                        w = None
                finally:
                    ex.shutdown(wait=False)  # don't block on a hung WHOIS socket
                if w is not None:
                    result = _months_from_date(w.creation_date)
                    if result is not None:
                        return result
            except Exception:
                pass

        # Attempt 2: RDAP (Registration Data Access Protocol) â€” no library needed
        if _REQUESTS_OK:
            try:
                # Extract root domain for RDAP
                parts = host.split('.')
                root = '.'.join(parts[-2:]) if len(parts) >= 2 else host
                rdap_url = f'https://rdap.org/domain/{root}'
                resp = _requests.get(rdap_url, timeout=3,
                                     headers={'Accept': 'application/rdap+json'})
                if resp.status_code == 200:
                    data = resp.json()
                    for event in data.get('events', []):
                        if event.get('eventAction') == 'registration':
                            date_str = event.get('eventDate', '')
                            if date_str:
                                from datetime import datetime as _dt
                                creation = _dt.fromisoformat(date_str.replace('Z', '+00:00'))
                                result = _months_from_date(creation)
                                if result is not None:
                                    return result
            except Exception:
                pass

        return 0

    @staticmethod
    def _check_dns_record(host: str, fast: bool) -> int:
        """Feature 25: Check if domain has valid DNS record. Returns 1=no DNS, -1=has DNS."""
        if fast:
            return 0
        try:
            dns.resolver.resolve(host, 'A')
            return -1
        except Exception:
            return 1

    @staticmethod
    def _estimate_web_traffic(host: str, fast: bool) -> int:
        """Feature 26: Estimate web traffic (Alexa-like). Returns 1=no rank, 0=low, -1=popular."""
        if fast:
            return 0
        # Simplified: try to fetch page; if OK then has traffic
        try:
            resp = _requests.get(f'http://{host}', timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            return -1 if resp.status_code == 200 else 0
        except Exception:
            return 1

    @staticmethod
    def _estimate_page_rank(host: str, fast: bool) -> int:
        """Feature 27: Estimated page rank (0-10). Returns 0 for unknown/low."""
        # Placeholder: would require external API or ML model
        return 0

    @staticmethod
    def _check_google_index(host: str, fast: bool) -> int:
        """Feature 28: Check if domain is indexed by Google. Returns 1=not indexed, -1=indexed."""
        if fast or not _REQUESTS_OK:
            return 0
        try:
            # Simple heuristic: try Google search; if found mention, likely indexed
            resp = _requests.get(f'https://www.google.com/search?q=site:{host}',
                                timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            # If Google returns results, domain is indexed
            return -1 if resp.status_code == 200 and 'did not match' not in resp.text else 1
        except Exception:
            return 0

    @staticmethod
    def _estimate_backlinks(host: str, fast: bool) -> int:
        """Feature 29: Estimate external backlinks. Returns 0=suspicious (few links), -1=has backlinks."""
        # Placeholder: would require external API (Ahrefs, Moz, etc.)
        return 0

    @staticmethod
    def _check_phishing_reports(host: str, fast: bool) -> int:
        """Feature 30: Check if domain is in known phishing reports. Returns 1=in reports, -1=not in reports."""
        # Placeholder: would require phishing DB integration
        return -1

    @staticmethod
    def _defaults() -> dict:
        return {name: 0 for name in FeatureExtractor.FEATURE_NAMES}


# â”€â”€ backward-compat alias â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
URLFeatureExtractor = FeatureExtractor


# â”€â”€ threshold rules for feature flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
FEATURE_THRESHOLDS = {
    'having_IP_Address':        {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'URL_Length':               {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'Shortining_Service':       {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'having_At_Symbol':         {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'double_slash_redirecting': {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Prefix_Suffix':            {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'having_Sub_Domain':        {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'SSLfinal_State':           {'warn': 0,   'fail': -1,   'higher_is_bad': False},
    'Domain_registeration_length': {'warn': 0, 'fail': 1,    'higher_is_bad': True},
    'Favicon':                  {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'port':                     {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'HTTPS_token':              {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Request_URL':              {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'URL_of_Anchor':            {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'Links_in_tags':            {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'SFH':                      {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Submitting_to_email':      {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Abnormal_URL':             {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Redirect':                 {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'on_mouseover':             {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'RightClick':               {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'popUpWidnow':              {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Iframe':                   {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'age_of_domain':            {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'DNSRecord':                {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'web_traffic':              {'warn': 0,   'fail': 1,    'higher_is_bad': True},
    'Page_Rank':                {'warn': 3,   'fail': 0,    'higher_is_bad': False},
    'Google_Index':             {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
    'Links_pointing_to_page':   {'warn': 0,   'fail': 0,    'higher_is_bad': True},
    'Statistical_report':       {'warn': 0.5, 'fail': 0.5,  'higher_is_bad': True},
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
        if fail_thresh != -1 and value <= fail_thresh:
            return 'fail'
        if value <= warn_thresh:
            return 'warn'
        return 'pass'

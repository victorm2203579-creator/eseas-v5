"""
Real-time threat feed integration.
Queries multiple external threat intelligence sources in parallel.
All functions handle failures gracefully with sensible defaults.
"""

import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import re

# ── API Keys & Configuration ──────────────────────────────────
URLHAUS_API_KEY = "f4ba8bbc6890d55b6afa745c203b394102ad81927d839caf"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

OPENPHISH_ENDPOINT = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_TTL = 3600  # 1 hour

URLVOID_ENDPOINT = "https://www.urlvoid.com/scan/{domain}/"

REQUEST_TIMEOUT = 5


# ── OpenPhish Feed Cache ──────────────────────────────────────
_openphish_cache = None
_openphish_cache_time = 0
_openphish_urls = set()


def _update_openphish_cache():
    """Fetch and cache OpenPhish feed."""
    global _openphish_cache, _openphish_cache_time, _openphish_urls

    try:
        response = requests.get(OPENPHISH_ENDPOINT, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        # Parse feed: each line is a URL
        urls = response.text.strip().split('\n')
        _openphish_urls = set(url.strip() for url in urls if url.strip())
        _openphish_cache = _openphish_urls.copy()
        _openphish_cache_time = time.time()

        return True
    except Exception as e:
        print(f'[threat_feeds] Failed to update OpenPhish cache: {e}')
        return False


def _get_openphish_feed():
    """Get cached OpenPhish feed, refresh if expired."""
    global _openphish_cache_time

    # Check if cache needs refresh
    if time.time() - _openphish_cache_time > OPENPHISH_CACHE_TTL:
        _update_openphish_cache()

    return _openphish_urls if _openphish_urls else _openphish_cache


# ── Feed 1: URLhaus ──────────────────────────────────────────
def check_urlhaus(url):
    """
    Query URLhaus API for phishing/malware URL data.

    Args:
        url (str): URL to check

    Returns:
        dict: {
            'found': bool,
            'threat_type': str or None,
            'confidence': int (0-100)
        }
    """
    try:
        payload = {'url': url}
        response = requests.post(
            URLHAUS_ENDPOINT,
            data=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        if data.get('query_status') == 'ok':
            found = data.get('results', [])
            if found:
                result = found[0]
                threat_type = result.get('threat', 'unknown')
                return {
                    'found': True,
                    'threat_type': threat_type,
                    'confidence': 90
                }

        return {
            'found': False,
            'threat_type': None,
            'confidence': 0
        }

    except Exception as e:
        return {
            'found': False,
            'threat_type': None,
            'confidence': 0
        }


# ── Feed 2: OpenPhish ────────────────────────────────────────
def check_openphish(url):
    """
    Check if URL or domain appears in OpenPhish feed.

    Args:
        url (str): URL to check

    Returns:
        dict: {
            'found': bool,
            'confidence': int (0-100)
        }
    """
    try:
        # Ensure cache is initialized
        if not _openphish_urls and not _openphish_cache:
            _update_openphish_cache()

        feed = _get_openphish_feed()

        # Extract domain from URL
        try:
            domain = urlparse(url).netloc
        except Exception:
            domain = url

        # Check if exact URL or domain in feed
        url_found = url in feed
        domain_found = domain in feed

        if url_found or domain_found:
            return {
                'found': True,
                'confidence': 85
            }

        return {
            'found': False,
            'confidence': 0
        }

    except Exception as e:
        return {
            'found': False,
            'confidence': 0
        }


# ── Feed 3: URLvoid ─────────────────────────────────────────
def check_urlvoid(domain):
    """
    Check domain reputation using URLvoid free tier.
    Scrapes detection count from HTML response.

    Args:
        domain (str): Domain to check

    Returns:
        dict: {
            'detections': int,
            'scan_count': int,
            'found': bool
        }
    """
    try:
        # Build endpoint
        endpoint = URLVOID_ENDPOINT.format(domain=domain)

        # Fetch page with User-Agent (some sites block requests without it)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(
            endpoint,
            timeout=REQUEST_TIMEOUT,
            headers=headers
        )
        response.raise_for_status()

        html = response.text

        # Attempt to extract detection count from HTML
        # URLvoid typically shows: "X engines flagged this domain as malicious"
        match = re.search(r'(\d+)\s+engines?\s+(?:flagged|detected)', html, re.IGNORECASE)

        if match:
            detections = int(match.group(1))
            return {
                'detections': detections,
                'scan_count': 90,  # URLvoid typically scans ~90 engines
                'found': detections > 0
            }

        # Fallback: try to find any detection indicator
        if 'malicious' in html.lower() or 'phishing' in html.lower():
            return {
                'detections': 5,
                'scan_count': 90,
                'found': True
            }

        return {
            'detections': 0,
            'scan_count': 90,
            'found': False
        }

    except Exception as e:
        return {
            'detections': 0,
            'scan_count': 0,
            'found': False
        }


# ── Feed Aggregation ────────────────────────────────────────
def query_all_threat_feeds(url, domain):
    """
    Query all threat feeds in parallel and aggregate results.

    Args:
        url (str): Full URL to check
        domain (str): Domain extracted from URL

    Returns:
        dict: {
            'urlhaus': {...},
            'openphish': {...},
            'urlvoid': {...},
            'feeds_flagged': int,
            'aggregate_confidence': int (0-100),
            'is_malicious': bool
        }
    """
    results = {
        'urlhaus': None,
        'openphish': None,
        'urlvoid': None,
        'feeds_flagged': 0,
        'aggregate_confidence': 0,
        'is_malicious': False
    }

    executor = ThreadPoolExecutor(max_workers=3)
    try:
        # Submit all feed checks in parallel
        futures = {
            executor.submit(check_urlhaus, url): 'urlhaus',
            executor.submit(check_openphish, url): 'openphish',
            executor.submit(check_urlvoid, domain): 'urlvoid',
        }

        # Wait for results with timeout
        for future in as_completed(futures, timeout=5):
            feed_name = futures[future]
            try:
                result = future.result(timeout=1)
                results[feed_name] = result
            except Exception as e:
                # Feed query failed, use default
                if feed_name == 'urlvoid':
                    results[feed_name] = {
                        'detections': 0,
                        'scan_count': 0,
                        'found': False
                    }
                else:
                    results[feed_name] = {
                        'found': False,
                        'confidence': 0
                    }

    except Exception as e:
        # All feeds failed, return defaults
        results['urlhaus'] = {'found': False, 'threat_type': None, 'confidence': 0}
        results['openphish'] = {'found': False, 'confidence': 0}
        results['urlvoid'] = {'detections': 0, 'scan_count': 0, 'found': False}
    finally:
        executor.shutdown(wait=False)  # never block on a hung scraper thread

    # Aggregate results
    feeds_flagged = 0
    confidences = []

    # Check URLhaus
    if results['urlhaus'] and results['urlhaus'].get('found'):
        feeds_flagged += 1
        confidences.append(results['urlhaus'].get('confidence', 0))

    # Check OpenPhish
    if results['openphish'] and results['openphish'].get('found'):
        feeds_flagged += 1
        confidences.append(results['openphish'].get('confidence', 0))

    # Check URLvoid
    if results['urlvoid'] and results['urlvoid'].get('found'):
        feeds_flagged += 1
        confidences.append(results['urlvoid'].get('confidence', 50))

    # Compute aggregate confidence
    if feeds_flagged == 0:
        aggregate_confidence = 0
    elif feeds_flagged == 1:
        aggregate_confidence = 40
    elif feeds_flagged == 2:
        aggregate_confidence = 75
    else:  # 3+
        aggregate_confidence = 95

    results['feeds_flagged'] = feeds_flagged
    results['aggregate_confidence'] = aggregate_confidence
    results['is_malicious'] = aggregate_confidence >= 40

    return results


# ── Test Function ────────────────────────────────────────────
if __name__ == '__main__':
    print('Testing threat feeds integration...\n')

    test_urls = [
        'https://example.com',
        'https://google.com',
    ]

    for test_url in test_urls:
        print(f'Checking: {test_url}')
        domain = urlparse(test_url).netloc
        result = query_all_threat_feeds(test_url, domain)

        print(f'  Feeds flagged: {result["feeds_flagged"]}')
        print(f'  Aggregate confidence: {result["aggregate_confidence"]}%')
        print(f'  Is malicious: {result["is_malicious"]}\n')

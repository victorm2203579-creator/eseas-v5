"""
Redirect chain analysis for phishing detection.
Follows HTTP redirects and detects suspicious patterns like:
- Excessive redirect chains (>3 is suspicious)
- Redirects across multiple domains
- Legitimate-to-phishing redirect patterns
"""

import requests
from urllib.parse import urlparse
import time


def get_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return url.lower()


def analyze_redirect_chain(url):
    """
    Follow URL through all redirects and analyze the chain.

    Args:
        url (str): URL to check

    Returns:
        dict with redirect chain analysis
    """
    result = {
        'redirect_count': 0,
        'redirect_chain': [],
        'final_url': url,
        'crosses_domains': False,
        'final_url_different': False,
        'redirect_risk_score': 0
    }

    try:
        # Use session to manually follow redirects
        session = requests.Session()
        current_url = url
        visited_domains = set()
        start_time = time.time()
        max_hops = 5
        hop_count = 0

        # Track initial domain
        initial_domain = get_domain(url)
        visited_domains.add(initial_domain)

        while hop_count < max_hops:
            # Check total timeout (5 seconds) — checked before AND would still be
            # bounded by the per-hop timeout below even if a single hop is slow
            if time.time() - start_time > 5:
                break

            try:
                # Request with 2-second per-hop timeout, don't follow redirects
                response = requests.head(
                    current_url,
                    timeout=2,
                    allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'},
                    verify=False
                )

                # Check if this is a redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if not location:
                        break

                    # Handle relative redirects
                    if location.startswith('/'):
                        parsed = urlparse(current_url)
                        location = f'{parsed.scheme}://{parsed.netloc}{location}'
                    elif not location.startswith('http'):
                        parsed = urlparse(current_url)
                        location = f'{parsed.scheme}://{parsed.netloc}/{location}'

                    # Record this redirect
                    destination_domain = get_domain(location)
                    result['redirect_chain'].append({
                        'from': current_url,
                        'to': location,
                        'status_code': response.status_code,
                        'domain_changed': get_domain(current_url) != destination_domain
                    })

                    visited_domains.add(destination_domain)
                    current_url = location
                    hop_count += 1

                else:
                    # Not a redirect, we've reached the final URL
                    break

            except requests.Timeout:
                # Timeout on this hop, stop following
                break
            except requests.RequestException:
                # Network error, stop following
                break

        # Final analysis
        result['redirect_count'] = len(result['redirect_chain'])
        result['final_url'] = current_url

        # Check if final URL is different from initial
        final_domain = get_domain(current_url)
        result['final_url_different'] = final_domain != initial_domain

        # Check if redirects cross domains
        result['crosses_domains'] = len(visited_domains) > 1

        # Calculate risk score
        risk_score = 0

        # [1] Excessive redirects
        if result['redirect_count'] > 5:
            risk_score += 25
        elif result['redirect_count'] >= 4:
            risk_score += 15
        elif result['redirect_count'] >= 2:
            risk_score += 10

        # [2] Domain crossing
        if result['crosses_domains']:
            risk_score += 20

        # [3] Final URL very different
        if result['final_url_different']:
            risk_score += 15

        # [4] Suspicious pattern: legitimate domain → different domain
        # This requires knowing legitimate domains, so we'll use a heuristic:
        # If redirects cross domains AND final domain is different, it's suspicious
        if result['crosses_domains'] and result['final_url_different']:
            # Check if chain looks like legitimate->suspicious
            if len(result['redirect_chain']) > 0:
                first_hop = result['redirect_chain'][0]
                if first_hop['domain_changed']:
                    # First redirect already changed domains - suspicious pattern
                    risk_score += 40

        result['redirect_risk_score'] = min(100, risk_score)

        return result

    except Exception as e:
        # Any unhandled error - return safe defaults
        return result


if __name__ == '__main__':
    test_urls = [
        'https://google.com',
        'https://github.com',
    ]

    for test_url in test_urls:
        print(f'Checking {test_url}...')
        result = analyze_redirect_chain(test_url)
        print(f'  Redirects: {result["redirect_count"]}')
        print(f'  Crosses domains: {result["crosses_domains"]}')
        print(f'  Risk score: {result["redirect_risk_score"]}\n')

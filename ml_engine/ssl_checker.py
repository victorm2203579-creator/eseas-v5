"""
Deep SSL certificate analysis for phishing detection.
Checks for self-signed certs, expiry, domain mismatches, and CA reputation.
"""

import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse


# Known free/cheap Certificate Authorities
FREE_CAS = {
    'let\'s encrypt',
    'letsencrypt',
    'zerossl',
    'comodo',
    'startssl',
}


def check_ssl_certificate(domain):
    """
    Perform deep SSL certificate analysis.

    Args:
        domain (str): Domain to check (e.g., 'example.com')

    Returns:
        dict with SSL analysis results
    """
    result = {
        'ssl_available': False,
        'is_self_signed': False,
        'is_expired': False,
        'days_until_expiry': 0,
        'is_very_new': False,
        'domain_mismatch': False,
        'is_wildcard': False,
        'issuer_org': None,
        'is_free_ca': False,
        'ssl_risk_score': 0
    }

    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Connect and get certificate
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

        if not cert:
            return result

        result['ssl_available'] = True

        # Extract certificate information
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        not_after_str = cert.get('notAfter')

        # [1] Check if self-signed
        is_self_signed = subject == issuer
        result['is_self_signed'] = is_self_signed

        # [2] Check expiry
        if not_after_str:
            # Parse date like: "Jan  1 00:00:00 2025 GMT"
            try:
                not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            except ValueError:
                # Fallback parsing
                not_after_str_clean = not_after_str.replace('GMT', '').strip()
                try:
                    not_after = datetime.strptime(not_after_str_clean, '%b %d %H:%M:%S %Y')
                except ValueError:
                    not_after = datetime.now() + timedelta(days=365)

            is_expired = datetime.now() > not_after
            result['is_expired'] = is_expired

            days_until = (not_after - datetime.now()).days
            result['days_until_expiry'] = max(0, days_until)

            # [4] Check if very new (<30 days old)
            # Estimate: if expiry is far in future but cert is in use, it's new
            # Better indicator: check NotBefore
            not_before_str = cert.get('notBefore')
            if not_before_str:
                try:
                    not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                except ValueError:
                    not_before_str_clean = not_before_str.replace('GMT', '').strip()
                    try:
                        not_before = datetime.strptime(not_before_str_clean, '%b %d %H:%M:%S %Y')
                    except ValueError:
                        not_before = datetime.now() - timedelta(days=365)

                age_days = (datetime.now() - not_before).days
                result['is_very_new'] = age_days < 30

        # [5] Check domain mismatch
        cn = subject.get('commonName', '')
        san_list = []
        for san in cert.get('subjectAltName', []):
            if san[0] == 'DNS':
                san_list.append(san[1])

        domain_mismatch = True
        if cn == domain or cn == f'*.{domain}':
            domain_mismatch = False
        if domain in san_list or f'*.{domain}' in san_list:
            domain_mismatch = False

        result['domain_mismatch'] = domain_mismatch

        # [6] Check if wildcard
        result['is_wildcard'] = cn.startswith('*.')

        # [7] Extract issuer organization
        issuer_org = issuer.get('organizationName', 'Unknown')
        result['issuer_org'] = issuer_org

        # [8] Check if free CA
        issuer_lower = issuer_org.lower()
        is_free_ca = any(free_ca in issuer_lower for free_ca in FREE_CAS)
        result['is_free_ca'] = is_free_ca

        # Calculate risk score
        risk_score = 0

        if is_self_signed:
            risk_score += 40

        if result['is_expired']:
            risk_score += 35

        # Check age
        if result['is_very_new']:
            age_days = (datetime.now() - not_before).days
            if age_days < 7:
                risk_score += 30
            else:
                risk_score += 15

        if domain_mismatch:
            risk_score += 45

        # Free CA + new cert = suspicious pattern
        if is_free_ca and result['is_very_new']:
            risk_score += 20

        result['ssl_risk_score'] = min(100, risk_score)

        return result

    except socket.timeout:
        return result
    except ssl.SSLError:
        return result
    except socket.gaierror:
        return result
    except Exception as e:
        return result


if __name__ == '__main__':
    test_domains = ['google.com', 'example.com', 'github.com']

    for domain in test_domains:
        print(f'Checking {domain}...')
        result = check_ssl_certificate(domain)
        print(f'  SSL available: {result["ssl_available"]}')
        print(f'  SSL risk score: {result["ssl_risk_score"]}\n')

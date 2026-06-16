"""
Email header analysis for phishing detection in ESEAS simulator.
Parses raw email headers and checks SPF, DKIM, DMARC, and display name spoofing.
"""

import re
from email.parser import Parser
from email.message import Message
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# Common brand names for display name spoofing detection
MAJOR_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'instagram', 'twitter', 'linkedin', 'netflix', 'spotify', 'ebay',
    'chase', 'bank', 'wells', 'barclays', 'hsbc', 'hsbc',
    'github', 'stripe', 'square', 'coinbase'
]


def parse_email_headers(raw_headers_string):
    """Parse raw email headers into structured format."""
    try:
        parser = Parser()
        msg = parser.parsestr(raw_headers_string)
        return msg
    except Exception as e:
        return None


def extract_sender_domain(from_header):
    """Extract domain from From header."""
    if not from_header:
        return None

    # Format: "Display Name <email@domain.com>" or just "email@domain.com"
    match = re.search(r'<([^>]+)>|([^\s@]+@[\w.-]+)', from_header)
    if match:
        email = match.group(1) or match.group(2)
        if '@' in email:
            return email.split('@')[1].lower()

    return None


def extract_sender_ip(received_header):
    """Extract sender IP from Received header."""
    if not received_header:
        return None

    # Look for patterns like "from ... [1.2.3.4]" or "from 1.2.3.4"
    patterns = [
        r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
        r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]

    for pattern in patterns:
        match = re.search(pattern, received_header)
        if match:
            return match.group(1)

    return None


def check_spf(sender_domain, sender_ip=None):
    """
    Check SPF record for sender domain.

    Returns: 'pass', 'fail', 'neutral', 'none'
    """
    if not HAS_DNS or not sender_domain:
        return 'none'

    try:
        # Query SPF TXT record for domain
        records = dns.resolver.resolve(sender_domain, 'TXT')

        for rdata in records:
            for txt in rdata.strings:
                txt_str = txt.decode('utf-8', errors='ignore')
                if txt_str.startswith('v=spf1'):
                    # Found SPF record
                    if sender_ip:
                        # Very basic check: does IP appear in record?
                        if sender_ip in txt_str:
                            return 'pass'
                        # Check for common SPF mechanisms
                        if 'include:' in txt_str or '~all' in txt_str:
                            return 'neutral'
                        if '-all' in txt_str:
                            return 'fail'
                    return 'neutral'

        return 'none'

    except Exception as e:
        return 'none'


def check_dkim(headers_dict):
    """
    Check for DKIM signature.

    Returns: 'pass', 'fail', 'missing'
    """
    dkim_header = headers_dict.get('DKIM-Signature') or headers_dict.get('dkim-signature')

    if dkim_header:
        if 'd=' in dkim_header and 's=' in dkim_header:
            return 'pass'
        return 'fail'

    return 'missing'


def check_dmarc(sender_domain):
    """
    Check DMARC policy for sender domain.

    Returns: dict with policy and enforcement status
    """
    if not HAS_DNS or not sender_domain:
        return {'policy': 'none', 'enforced': False}

    try:
        dmarc_domain = f'_dmarc.{sender_domain}'
        records = dns.resolver.resolve(dmarc_domain, 'TXT')

        for rdata in records:
            for txt in rdata.strings:
                txt_str = txt.decode('utf-8', errors='ignore')
                if 'v=DMARC1' in txt_str:
                    # Extract policy
                    if 'p=reject' in txt_str:
                        return {'policy': 'reject', 'enforced': True}
                    elif 'p=quarantine' in txt_str:
                        return {'policy': 'quarantine', 'enforced': True}
                    else:
                        return {'policy': 'none', 'enforced': False}

        return {'policy': 'none', 'enforced': False}

    except Exception as e:
        return {'policy': 'none', 'enforced': False}


def check_header_consistency(headers_dict):
    """
    Check consistency between From, Return-Path, and Reply-To headers.

    Returns: dict with consistency checks
    """
    from_header = headers_dict.get('From', '')
    return_path = headers_dict.get('Return-Path', '')
    reply_to = headers_dict.get('Reply-To', '')

    from_domain = extract_sender_domain(from_header)
    return_domain = extract_sender_domain(return_path)
    reply_domain = extract_sender_domain(reply_to)

    result = {
        'from_return_path_match': from_domain == return_domain if from_domain and return_domain else True,
        'reply_to_suspicious': reply_domain != from_domain if reply_domain and from_domain else False,
        'received_hops': len([h for h in headers_dict.get('Received', '').split('\n') if h.strip()]),
    }

    return result


def check_display_name_spoofing(from_header):
    """
    Detect if display name contains a brand but domain is not that brand.

    Returns: bool
    """
    if not from_header:
        return False

    # Extract display name and email
    match = re.match(r'([^<]+)\s*<([^>]+)>', from_header)
    if match:
        display_name = match.group(1).lower()
        email = match.group(2)

        # Extract domain from email
        if '@' in email:
            email_domain = email.split('@')[1].lower()
        else:
            return False

        # Check if display name contains a brand
        for brand in MAJOR_BRANDS:
            if brand in display_name:
                # Brand in display name, check if email domain matches
                if brand not in email_domain:
                    return True

    return False


def analyze_email_headers(raw_headers_string):
    """
    Analyse raw email headers for phishing indicators.

    Args:
        raw_headers_string (str): Raw email headers

    Returns:
        dict with header analysis results
    """
    result = {
        'spf_result': 'none',
        'dkim_result': 'missing',
        'dmarc_result': 'none',
        'from_return_path_match': True,
        'reply_to_suspicious': False,
        'display_name_spoofing': False,
        'header_risk_score': 0,
        'issues_found': []
    }

    try:
        # Parse headers
        msg = parse_email_headers(raw_headers_string)
        if not msg:
            return result

        # Convert to dict for easier access
        headers_dict = dict(msg.items())

        # [1] SPF Check
        from_header = headers_dict.get('From', '')
        sender_domain = extract_sender_domain(from_header)
        received_header = headers_dict.get('Received', '')
        sender_ip = extract_sender_ip(received_header)

        spf_result = check_spf(sender_domain, sender_ip)
        result['spf_result'] = spf_result
        if spf_result == 'fail':
            result['issues_found'].append('SPF check failed')
            result['header_risk_score'] += 35

        # [2] DKIM Check
        dkim_result = check_dkim(headers_dict)
        result['dkim_result'] = dkim_result
        if dkim_result == 'fail':
            result['issues_found'].append('DKIM signature invalid')
            result['header_risk_score'] += 30
        elif dkim_result == 'missing':
            result['issues_found'].append('DKIM signature missing')
            result['header_risk_score'] += 15

        # [3] DMARC Check
        if sender_domain:
            dmarc_info = check_dmarc(sender_domain)
            result['dmarc_result'] = dmarc_info['policy']
            if dmarc_info['enforced'] and dmarc_info['policy'] == 'reject':
                result['issues_found'].append('DMARC policy failed (reject)')
                result['header_risk_score'] += 40

        # [4] Header Consistency
        consistency = check_header_consistency(headers_dict)
        result['from_return_path_match'] = consistency['from_return_path_match']
        result['reply_to_suspicious'] = consistency['reply_to_suspicious']

        if not result['from_return_path_match']:
            result['issues_found'].append('From/Return-Path domain mismatch')
            result['header_risk_score'] += 35

        if result['reply_to_suspicious']:
            result['issues_found'].append('Reply-To domain differs from From')
            result['header_risk_score'] += 25

        # [5] Display Name Spoofing
        spoofing = check_display_name_spoofing(from_header)
        result['display_name_spoofing'] = spoofing
        if spoofing:
            result['issues_found'].append('Display name spoofing detected')
            result['header_risk_score'] += 40

        # Cap risk score at 100
        result['header_risk_score'] = min(100, result['header_risk_score'])

    except Exception as e:
        pass

    return result


if __name__ == '__main__':
    sample_headers = """From: PayPal Support <support@paypal.com>
To: user@example.com
Return-Path: <noreply@paypal.com>
Received: from mail.google.com ([142.251.41.14])
DKIM-Signature: v=1; a=rsa-sha256; d=paypal.com; s=google"""

    result = analyze_email_headers(sample_headers)
    print('Email Header Analysis:')
    print(f'  SPF: {result["spf_result"]}')
    print(f'  DKIM: {result["dkim_result"]}')
    print(f'  Risk Score: {result["header_risk_score"]}\n')

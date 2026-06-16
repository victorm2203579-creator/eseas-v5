"""
Typosquatting and brand impersonation detection.
Detects domain names that look like legitimate brands through:
- Levenshtein distance (character-level similarity)
- Substring matching (e.g., "paypal-secure-login.com" contains "paypal")
- Homoglyph substitution (lookalike characters: rn→m, 0→o, etc.)
"""

from urllib.parse import urlparse
import string

# Try to import Levenshtein for fuzzy matching
try:
    from Levenshtein import distance as levenshtein_distance
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False
    # Fallback: simple Levenshtein implementation
    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]


# Major brands to check against
MAJOR_BRANDS = [
    'google', 'gmail', 'facebook', 'instagram', 'twitter', 'x',
    'microsoft', 'outlook', 'hotmail', 'live', 'office365', 'office',
    'apple', 'icloud', 'itunes', 'appstore',
    'amazon', 'aws', 'paypal', 'ebay',
    'netflix', 'spotify', 'dropbox', 'linkedin',
    'bankofamerica', 'chase', 'wellsfargo', 'barclays', 'hsbc',
    'zenithbank', 'gtbank', 'accessbank', 'firstbank', 'uba',
    'mtn', 'airtel', 'glo', 'ninemobile',
    'nimc', 'firs', 'efcc', 'cbn',
    'github', 'gitlab', 'stackoverflow',
    'yahoo', 'bing', 'whatsapp', 'telegram', 'tiktok',
    'reddit', 'quora', 'stackoverflow', 'mysql', 'postgres',
    'stripe', 'square', 'coinbase', 'kraken',
]

# Homoglyph substitutions: character that looks like another
HOMOGLYPHS = {
    'rn': 'm',
    'vv': 'w',
    '0': 'o',
    '1': 'l',
    '5': 's',
    'i': 'l',
    '8': 'b',
    '6': 'g',
}


def extract_base_domain(domain):
    """
    Extract base domain from full domain.
    E.g., "mail.google.com" -> "google"
    E.g., "paypal-secure.co.uk" -> "paypal-secure" or "paypal"
    """
    # Remove TLD and subdomains
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        # Return the main domain (second-to-last part before TLD)
        return parts[-2]
    return domain.lower()


def apply_homoglyphs(text):
    """Apply homoglyph substitutions to find lookalike domains."""
    text_lower = text.lower()
    results = [text_lower]

    # Try each homoglyph substitution
    for homoglyph_src, homoglyph_dst in HOMOGLYPHS.items():
        if homoglyph_src in text_lower:
            results.append(text_lower.replace(homoglyph_src, homoglyph_dst))

    return results


def check_typosquatting(domain):
    """
    Detect brand impersonation through typosquatting.

    Args:
        domain (str): Domain to check (e.g., 'paypal-secure.com')

    Returns:
        dict with typosquatting analysis
    """
    result = {
        'is_typosquatting': False,
        'target_brand': None,
        'similarity_score': 0.0,
        'detection_method': None,
        'typosquatting_risk_score': 0
    }

    domain_lower = domain.lower()
    base_domain = extract_base_domain(domain)

    best_match = None
    best_similarity = 0.0
    best_method = None
    best_distance = float('inf')

    # [1] Levenshtein distance check
    for brand in MAJOR_BRANDS:
        distance = levenshtein_distance(base_domain, brand)
        max_len = max(len(base_domain), len(brand))

        # Normalize distance to similarity (0-1)
        if max_len > 0:
            similarity = 1.0 - (distance / max_len)
        else:
            similarity = 0.0

        # If distance <= 2 AND base_domain != brand
        if distance <= 2 and base_domain != brand and similarity > best_similarity:
            best_match = brand
            best_similarity = similarity
            best_distance = distance
            best_method = 'levenshtein'

    # [2] Substring matching
    # Check if domain CONTAINS a brand name but is not the real domain
    for brand in MAJOR_BRANDS:
        # Brand appears in domain but domain is not the brand itself
        if brand in domain_lower and domain_lower != brand and domain_lower != f'{brand}.com':
            # Only flag if it looks suspicious (not a legitimate subdomain)
            if not domain_lower.startswith(f'{brand}.'):
                if 0.9 > best_similarity:
                    best_match = brand
                    best_similarity = 0.9
                    best_method = 'substring'

    # [3] Homoglyph substitution
    homoglyph_variants = apply_homoglyphs(base_domain)
    for variant in homoglyph_variants:
        if variant != base_domain:  # Only check if substitution changed something
            for brand in MAJOR_BRANDS:
                distance = levenshtein_distance(variant, brand)
                max_len = max(len(variant), len(brand))

                if max_len > 0:
                    similarity = 1.0 - (distance / max_len)
                else:
                    similarity = 0.0

                if distance <= 1 and similarity > best_similarity:
                    best_match = brand
                    best_similarity = similarity
                    best_distance = distance
                    best_method = 'homoglyph'

    # Determine if typosquatting
    if best_match and best_similarity >= 0.75:
        result['is_typosquatting'] = True
        result['target_brand'] = best_match
        result['similarity_score'] = best_similarity
        result['detection_method'] = best_method

        # Risk scoring
        if best_method == 'levenshtein':
            if best_distance == 1:
                result['typosquatting_risk_score'] = 85
            elif best_distance == 2:
                result['typosquatting_risk_score'] = 70
            else:
                result['typosquatting_risk_score'] = 60
        elif best_method == 'substring':
            result['typosquatting_risk_score'] = 75
        elif best_method == 'homoglyph':
            result['typosquatting_risk_score'] = 90

    return result


if __name__ == '__main__':
    test_domains = [
        'google.com',
        'googlé.com',  # Homoglyph
        'paypal-secure-login.com',  # Substring
        'gmai1.com',  # Typo (1 instead of l)
        'amazon.com',
        'amaz0n.com',
    ]

    for domain in test_domains:
        print(f'Checking {domain}...')
        result = check_typosquatting(domain)
        if result['is_typosquatting']:
            print(f'  TYPOSQUATTING DETECTED: {result["target_brand"]}')
            print(f'  Method: {result["detection_method"]}')
            print(f'  Risk score: {result["typosquatting_risk_score"]}\n')
        else:
            print(f'  No typosquatting detected\n')

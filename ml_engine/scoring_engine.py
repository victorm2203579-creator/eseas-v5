"""
Unified scoring engine for ESEAS phishing detection.
Combines all analysis layers (ML, VT, GSB, rules, feeds, SSL, redirects, typosquatting, email headers)
into a single risk score with intelligent weighting and override rules.
"""


import re
from urllib.parse import urlparse


_PHISHING_KEYWORDS = re.compile(
    r'(impot|impot-w2|w2|w-2|tax|irs|hmrc|refund|fiscal|avis-de-passage|cra-arc|'
    r'invoice|payment|verify|credential|login|secure|update|confirm|signin|'
    r'account|suspend|alert|ebay|paypal|amazon|microsoft|apple|netflix|'
    r'bankofamerica|halifax|barclays|lloyds|natwest|hsbc|'
    # Courier / parcel phishing
    r'dhl|fedex|ups|usps|royalmail|parcel|tracking|shipment|sendung|verfolgung|'
    r'delivery|colis|colissimo|correos|postbank|postnl|'
    # Common lure words
    r'winner|prize|reward|gift|bonus|free|claim|urgent|suspended|'
    r'voicemail|fax|document|invoice|receipt)',
    re.IGNORECASE
)

# Malware delivery file extensions in URL path
_MALWARE_EXT_RE = re.compile(
    r'\.(zip|exe|msi|jar|bat|cmd|scr|vbs|ps1|dmg|apk|rar|7z|cab|iso|img|bin)(\?|#|$)',
    re.IGNORECASE
)

_PHISHING_PATH_RE = re.compile(
    r'(/[a-zA-Z0-9]{6,}/[a-zA-Z0-9]{8,}|/[a-zA-Z]{1,3}/[a-zA-Z0-9]{8,}/)',
)

# Hex tracking token in query string (MD5/SHA-style phishing trackers)
_HEX_TOKEN_RE = re.compile(r'[0-9a-f]{20,}', re.IGNORECASE)

# Random hyphenated path segment — e.g. /G-pp-B/ or /Ab-cd-EF/
_HYPHEN_PATH_RE = re.compile(r'/[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+/')

# Short non-standard PHP filenames (2-6 chars not matching common names)
_COMMON_PHP = {
    'index', 'login', 'home', 'page', 'post', 'view', 'edit', 'admin',
    'search', 'upload', 'download', 'cart', 'shop', 'user', 'api',
    'form', 'check', 'get', 'set', 'error', 'about', 'news',
}
_SUSPICIOUS_PHP_RE = re.compile(r'/([a-z]{2,6})\.php(?:\?|$|/)', re.IGNORECASE)

_SUSPICIOUS_TLDS = {
    '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top',
    '.click', '.link', '.online', '.site', '.club', '.work',
    '.bid', '.win', '.stream', '.download', '.party', '.zip',
    '.mov', '.icu', '.ru', '.su', '.cc', '.bz',
}


def _url_heuristic_score(url: str) -> dict:
    """
    Pure URL heuristic scoring. Catches obvious phishing patterns
    that VT/GSB/ML may miss for new/unreported URLs.
    """
    score = 0
    flags = []

    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()
    except Exception:
        return {'score': 0, 'flags': [], 'detail': 'parse error'}

    # HTTP (not HTTPS) — baseline suspicion
    if url.startswith('http://') and not url.startswith('https://'):
        score += 15
        flags.append('No HTTPS (plain HTTP)')

    # Malware delivery file extension — immediate high-risk override
    malware_match = _MALWARE_EXT_RE.search(full)
    if malware_match:
        score += 55
        flags.append(f'Malware delivery extension: .{malware_match.group(1).lower()}')

    # Phishing/credential/courier keywords in URL
    kw_matches = _PHISHING_KEYWORDS.findall(full)
    if kw_matches:
        score += min(40, len(kw_matches) * 15)
        flags.append(f'Phishing keywords: {", ".join(set(kw_matches[:3]))}')

    # Random alphanumeric path segments (token-style)
    if _PHISHING_PATH_RE.search(path):
        score += 20
        flags.append('Random token-style path segments')

    # Long URL
    if len(url) > 75:
        score += 10
        flags.append(f'Long URL ({len(url)} chars)')

    # Multiple path depth (e.g. /a/b/c/d)
    path_depth = len([p for p in path.split('/') if p])
    if path_depth >= 4:
        score += 10
        flags.append(f'Deep URL path ({path_depth} levels)')

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            flags.append(f'Suspicious TLD: {tld}')
            break

    # Numeric strings in domain (e.g. Lu08872442)
    if re.search(r'\d{6,}', full):
        score += 15
        flags.append('Long numeric string in URL')

    # Hyphens in domain (e.g. impot-w2)
    hyphen_count = domain.count('-')
    if hyphen_count >= 2:
        score += 15
        flags.append(f'Multiple hyphens in domain ({hyphen_count})')
    elif hyphen_count == 1:
        score += 8
        flags.append('Hyphen in domain')

    # HTML file in deep path (phishing landing pages)
    if path.endswith(('.html', '.htm', '.php')) and path_depth >= 2:
        score += 10
        flags.append('HTML file in deep path')

    # IP address as host
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        score += 40
        flags.append('IP address used as domain')

    # @ symbol in URL
    if '@' in url:
        score += 30
        flags.append('@ symbol in URL (credential trick)')

    # Hex/MD5 tracking token in query string — classic phishing campaign tracker
    if query and _HEX_TOKEN_RE.search(query):
        score += 25
        flags.append('Hex tracking token in query string')

    # Random hyphenated path segment — /G-pp-B/, /Ab-cd-EF/, etc.
    if _HYPHEN_PATH_RE.search(path):
        score += 15
        flags.append('Random hyphenated path segment')

    # Short non-standard PHP filename — hmpg.php, rdr.php, etc.
    php_match = _SUSPICIOUS_PHP_RE.search(path)
    if php_match:
        name = php_match.group(1).lower()
        if name not in _COMMON_PHP:
            score += 15
            flags.append(f'Suspicious PHP file: {name}.php')

    score = min(100, score)
    return {
        'score': score,
        'flags': flags,
        'detail': f'{len(flags)} heuristic flags triggered'
    }


def compute_final_risk_score(analysis_results):
    """
    Compute final risk score from all analysis layers.

    Args:
        analysis_results (dict): Dict containing results from all analysis layers.
            Expected keys (all optional):
            - 'ml_prediction': float (0-1)
            - 'ml_confidence': float (0-1)
            - 'virustotal': dict with 'detection_count', 'total_scanners', 'is_malicious'
            - 'google_safe_browsing': dict with 'is_unsafe', 'threat_types'
            - 'rule_based': dict with 'triggered_rules', 'rule_score'
            - 'ssl_analysis': dict from ssl_checker.py
            - 'redirect_analysis': dict from redirect_analyzer.py
            - 'typosquatting': dict from typosquatting.py
            - 'threat_feeds': dict from threat_feeds.py
            - 'header_analysis': dict from header_analyzer.py

    Returns:
        dict with final risk score and detailed breakdown
    """

    # Initialize base weights (will be redistributed if layers unavailable)
    # Rationale:
    #  - virustotal (0.30): 70+ AV engine consensus — most authoritative single signal.
    #    Known threats dominate ~68% of real-world phishing. Increased from 0.28.
    #  - ml_model (0.25): Lexical pattern recognition, fast execution, zero-day catch rate.
    #    Increased from 0.13 to capture novel attacks VT/GSB haven't indexed yet.
    #  - google_safe_browsing (0.20): Google's crawled threat index — reliable independent
    #    verification source, different threat intelligence than VT.
    #  - rule_based (0.10): URL heuristics engine (phishing keywords, tracking tokens,
    #    malware extensions, suspicious paths, IP hosts, etc.). Reduced from 0.20
    #    because rule_based is now primary layer; heuristics also enforce via override
    #    floors (separate mechanism). Decreased from 0.20 to avoid double-counting.
    #  - threat_feeds (0.08): URLhaus/OpenPhish/URLvoid — independent sources, good at
    #    zero-day detection. Decreased from 0.12 as supporting signal.
    #  - ssl/redirect/typosquatting: supporting signals, low weights.
    base_weights = {
        'virustotal': 0.30,
        'ml_model': 0.25,
        'google_safe_browsing': 0.20,
        'rule_based': 0.10,
        'threat_feeds': 0.08,
        'ssl_analysis': 0.04,
        'redirect_analysis': 0.02,
        'typosquatting': 0.01,
    }

    layer_breakdown = {}
    available_layers = []

    # Compute URL heuristics FIRST so they can feed the 'rule_based' weighted
    # layer below (previously dead — nothing ever populated analysis_results
    # ['rule_based'], so that weight silently vanished into redistribution).
    # Heuristics now count as a real weighted contributor, not just an override
    # floor, which is what actually closes the "VT/GSB haven't seen it yet"
    # blind spot — not reshuffling weight between VT/GSB/ML.
    _raw_url_for_heuristics = analysis_results.get('url', '')
    _heuristic_precomputed = (_url_heuristic_score(_raw_url_for_heuristics)
                               if _raw_url_for_heuristics else {'score': 0, 'flags': [], 'detail': 'no url'})

    # ── Layer 1: VirusTotal ──────────────────────────────────
    vt_score = 0
    if analysis_results.get('virustotal'):
        vt_data = analysis_results['virustotal']
        detection_count = vt_data.get('detection_count', 0)
        total_scanners = vt_data.get('total_scanners', 1)

        if total_scanners > 0:
            vt_score = (detection_count / total_scanners) * 100
        else:
            vt_score = 0

        layer_breakdown['virustotal'] = {
            'score': vt_score,
            'weight': base_weights['virustotal'],
            'contribution': 0,
            'detail': f'{detection_count}/{total_scanners} scanners flagged'
        }
        available_layers.append('virustotal')

    # ── Layer 2: ML Model ────────────────────────────────────
    ml_score = 0
    if analysis_results.get('ml_prediction') is not None:
        ml_pred = analysis_results['ml_prediction']
        ml_score = ml_pred * 100

        layer_breakdown['ml_model'] = {
            'score': ml_score,
            'weight': base_weights['ml_model'],
            'contribution': 0,
            'detail': f'Prediction: {ml_pred:.2%}'
        }
        available_layers.append('ml_model')

    # ── Layer 3: Google Safe Browsing ────────────────────────
    gsb_score = 0
    if analysis_results.get('google_safe_browsing'):
        gsb_data = analysis_results['google_safe_browsing']
        if gsb_data.get('is_unsafe'):
            gsb_score = 100
        else:
            gsb_score = 0

        layer_breakdown['google_safe_browsing'] = {
            'score': gsb_score,
            'weight': base_weights['google_safe_browsing'],
            'contribution': 0,
            'detail': 'Flagged' if gsb_score > 0 else 'Safe'
        }
        available_layers.append('google_safe_browsing')

    # ── Layer 4: Rule Based (powered by the URL heuristics engine) ──
    rules_score = _heuristic_precomputed['score']
    if _raw_url_for_heuristics:
        layer_breakdown['rule_based'] = {
            'score': rules_score,
            'weight': base_weights['rule_based'],
            'contribution': 0,
            'detail': _heuristic_precomputed.get('detail', ''),
            'flags': _heuristic_precomputed.get('flags', []),
        }
        available_layers.append('rule_based')

    # ── Layer 5: Threat Feeds ────────────────────────────────
    feeds_score = 0
    if analysis_results.get('threat_feeds'):
        feeds_data = analysis_results['threat_feeds']
        feeds_score = feeds_data.get('aggregate_confidence', 0)

        layer_breakdown['threat_feeds'] = {
            'score': feeds_score,
            'weight': base_weights['threat_feeds'],
            'contribution': 0,
            'detail': f'{feeds_data.get("feeds_flagged", 0)} feeds flagged'
        }
        available_layers.append('threat_feeds')

    # ── Layer 6: SSL Analysis ────────────────────────────────
    ssl_score = 0
    if analysis_results.get('ssl_analysis'):
        ssl_data = analysis_results['ssl_analysis']
        ssl_score = ssl_data.get('ssl_risk_score', 0)

        layer_breakdown['ssl_analysis'] = {
            'score': ssl_score,
            'weight': base_weights['ssl_analysis'],
            'contribution': 0,
            'detail': f'SSL Risk: {ssl_score}'
        }
        available_layers.append('ssl_analysis')

    # ── Layer 7: Redirect Analysis ───────────────────────────
    redirect_score = 0
    if analysis_results.get('redirect_analysis'):
        redirect_data = analysis_results['redirect_analysis']
        redirect_score = redirect_data.get('redirect_risk_score', 0)

        layer_breakdown['redirect_analysis'] = {
            'score': redirect_score,
            'weight': base_weights['redirect_analysis'],
            'contribution': 0,
            'detail': f'{redirect_data.get("redirect_count", 0)} redirects'
        }
        available_layers.append('redirect_analysis')

    # ── Layer 8: Typosquatting ───────────────────────────────
    typo_score = 0
    if analysis_results.get('typosquatting'):
        typo_data = analysis_results['typosquatting']
        typo_score = typo_data.get('typosquatting_risk_score', 0)

        layer_breakdown['typosquatting'] = {
            'score': typo_score,
            'weight': base_weights['typosquatting'],
            'contribution': 0,
            'detail': f'Target: {typo_data.get("target_brand", "N/A")}'
        }
        available_layers.append('typosquatting')

    # ── Layer 9: Email Header Analysis ───────────────────────
    header_score = 0
    if analysis_results.get('header_analysis'):
        header_data = analysis_results['header_analysis']
        header_score = header_data.get('header_risk_score', 0)

        # Add header analysis with weight of 0 (not in original 8 layers)
        layer_breakdown['header_analysis'] = {
            'score': header_score,
            'weight': 0,
            'contribution': 0,
            'detail': f'{len(header_data.get("issues_found", []))} issues found'
        }

    # ── Recalculate weights if some layers unavailable ────────
    total_weight = sum(base_weights[layer] for layer in available_layers)
    if total_weight < 1.0 and available_layers:
        # Redistribute weights proportionally
        for layer in available_layers:
            layer_breakdown[layer]['weight'] = base_weights[layer] / total_weight

    # ── Calculate weighted score ─────────────────────────────
    weighted_score = 0
    for layer in available_layers:
        score = layer_breakdown[layer]['score']
        weight = layer_breakdown[layer]['weight']
        contribution = score * weight
        layer_breakdown[layer]['contribution'] = contribution
        weighted_score += contribution

    # ── Layer 0: URL Heuristics override floor (rule_based above already
    # contributed this to the weighted sum — this is the EXTRA safety net for
    # cases where the weighted average still doesn't reflect a strong pattern
    # match, e.g. when VT/GSB pull the average down despite clear local signals) ──
    raw_url = analysis_results.get('url', '')
    if raw_url:
        heuristic = _heuristic_precomputed
        heuristic_score = heuristic['score']
        layer_breakdown['url_heuristics'] = {
            'score': heuristic_score,
            'weight': 0,  # floor-based, not weighted (separate from the rule_based weighted layer)
            'contribution': 0,
            'detail': heuristic.get('detail', ''),
            'flags': heuristic.get('flags', []),
        }
        # Strong heuristic signal (≥60): use directly as floor — URL patterns are unmistakably phishing
        # Weaker signal: blend at 60% so we don't over-penalise borderline cases
        if heuristic_score >= 60:
            weighted_score = max(weighted_score, heuristic_score)
        elif heuristic_score > weighted_score:
            weighted_score = max(weighted_score, heuristic_score * 0.6)

    # ── Apply override rules ─────────────────────────────────
    override_applied = False
    override_reason = None

    vt_data = analysis_results.get('virustotal', {})
    gsb_data = analysis_results.get('google_safe_browsing', {})
    ssl_data = analysis_results.get('ssl_analysis', {})
    feeds_data = analysis_results.get('threat_feeds', {})

    # Override 1a: VirusTotal detection count floor (absolute count beats rate for small numbers)
    vt_detection_count = vt_data.get('detection_count', 0)
    if vt_detection_count > 0:
        if vt_detection_count >= 15:
            min_score_from_vt = 90  # Confirmed phishing
        elif vt_detection_count >= 10:
            min_score_from_vt = 85  # Phishing
        elif vt_detection_count >= 5:
            min_score_from_vt = 78  # High Risk
        elif vt_detection_count >= 3:
            min_score_from_vt = 70  # High Risk
        elif vt_detection_count >= 2:
            min_score_from_vt = 62  # Suspicious → High Risk border
        else:
            min_score_from_vt = 52  # 1 engine: Suspicious

        weighted_score = max(weighted_score, min_score_from_vt)
        override_applied = True
        override_reason = f'VirusTotal: {vt_detection_count} scanner(s) detected threat'

    # Override 2: Google Safe Browsing phishing flag
    if gsb_data.get('is_unsafe') and 'PHISHING' in str(gsb_data.get('threat_types', '')):
        weighted_score = max(weighted_score, 70)
        override_applied = True
        override_reason = 'Google Safe Browsing: Phishing detected'

    # Override 3: SSL domain mismatch
    if ssl_data.get('domain_mismatch'):
        weighted_score = max(weighted_score, 65)
        override_applied = True
        override_reason = 'SSL: Domain mismatch detected'

    # Override 4: Multiple threat feeds flagging
    if feeds_data.get('feeds_flagged', 0) >= 3:
        weighted_score = max(weighted_score, 70)
        override_applied = True
        override_reason = 'Threat Feeds: 3+ sources flagged'

    # Override 5: Unanimous verdict from main layers
    main_layers_count = sum(1 for layer in ['virustotal', 'ml_model', 'google_safe_browsing', 'rule_based']
                            if layer in available_layers and layer_breakdown[layer]['score'] > 50)
    if main_layers_count >= 4:
        weighted_score = 95
        override_applied = True
        override_reason = 'All main layers consensus: Phishing'

    # Override 6: URL heuristic floor — catches zero-day phishing VT/GSB haven't indexed yet
    heuristic_layer = layer_breakdown.get('url_heuristics', {})
    heuristic_score_val = heuristic_layer.get('score', 0)
    if heuristic_score_val >= 70:
        # Multiple strong phishing signals — enforce High Risk minimum
        min_heuristic_floor = max(62, heuristic_score_val * 0.85)
        if weighted_score < min_heuristic_floor:
            weighted_score = min_heuristic_floor
            override_applied = True
            flags_summary = ', '.join(heuristic_layer.get('flags', [])[:3])
            override_reason = f'URL Heuristics: {flags_summary}'
    elif heuristic_score_val >= 40:
        # Moderate heuristic signal — enforce Suspicious minimum
        min_heuristic_floor = max(42, heuristic_score_val * 0.65)
        if weighted_score < min_heuristic_floor:
            weighted_score = min_heuristic_floor
            override_applied = True
            flags_summary = ', '.join(heuristic_layer.get('flags', [])[:2])
            override_reason = f'URL Heuristics: {flags_summary}'

    # ── Strictness rule: 3+ heuristic flags → NEVER Safe or Low Risk ──
    heuristic_flags_list = layer_breakdown.get('url_heuristics', {}).get('flags', [])
    if len(heuristic_flags_list) >= 3 and weighted_score < 41:
        weighted_score = 41
        override_applied = True
        override_reason = (override_reason or
                           f'Strict mode: {len(heuristic_flags_list)} phishing indicators detected')

    # Cap score at 100
    final_score = min(100, max(0, int(weighted_score)))

    # ── Confidence level ────────────────────────────────────
    layers_used = len(available_layers)
    if layers_used >= 8:
        confidence = 'Very High'
    elif layers_used >= 6:
        confidence = 'High'
    elif layers_used >= 4:
        confidence = 'Medium'
    elif layers_used >= 2:
        confidence = 'Low'
    else:
        confidence = 'Very Low'

    # ── Risk classification ─────────────────────────────────
    if final_score <= 20:
        risk_level = 'Safe'
        risk_color = 'green'
    elif final_score <= 40:
        risk_level = 'Low Risk'
        risk_color = 'yellow'
    elif final_score <= 60:
        risk_level = 'Suspicious'
        risk_color = 'orange'
    elif final_score <= 80:
        risk_level = 'High Risk'
        risk_color = 'red-orange'
    else:
        risk_level = 'Phishing'
        risk_color = 'red'

    # ── Accuracy / confidence percentage ─────────────────────
    # How many independent signals confirmed the verdict (≠ how dangerous it is)
    acc = 38  # honest base
    acc += min(layers_used * 7, 35)   # +7 per API layer, up to +35

    _vt_res = analysis_results.get('virustotal', {})
    if _vt_res:
        acc += 7
        _vt_det = _vt_res.get('detection_count', 0)
        if _vt_det >= 10:   acc += 12
        elif _vt_det >= 5:  acc += 9
        elif _vt_det >= 2:  acc += 6
        elif _vt_det >= 1:  acc += 4

    _gsb_res = analysis_results.get('google_safe_browsing', {})
    if _gsb_res:
        acc += 8 if _gsb_res.get('is_unsafe') else 5

    _ml_layer = layer_breakdown.get('ml_model', {})
    if _ml_layer:
        _ml_val = _ml_layer.get('score', 50)
        acc += 8 if ((_ml_val >= 60) == (final_score >= 60)) else 3

    acc += min(len(heuristic_flags_list) * 3, 12)

    _tf = analysis_results.get('threat_feeds', {})
    if _tf and _tf.get('feeds_flagged', 0) >= 1:
        acc += 6

    accuracy = min(97, max(40, int(acc)))

    # ── Recommendation ─────────────────────────────────────
    if final_score <= 20:
        recommendation = 'This URL appears to be safe. Proceed with confidence.'
    elif final_score <= 40:
        recommendation = 'Low risk detected. Exercise normal caution.'
    elif final_score <= 60:
        recommendation = 'This URL exhibits suspicious characteristics. Verify authenticity before clicking.'
    elif final_score <= 80:
        recommendation = 'High risk detected. Do NOT click this link. Report to IT security.'
    else:
        recommendation = 'PHISHING ALERT: This is a confirmed phishing attempt. Do NOT click. Report immediately.'

    return {
        'final_score': final_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'confidence': confidence,
        'accuracy': accuracy,
        'layers_used': layers_used,
        'layer_breakdown': layer_breakdown,
        'override_applied': override_applied,
        'override_reason': override_reason,
        'recommendation': recommendation
    }


if __name__ == '__main__':
    # Test the scoring engine
    test_input = {
        'ml_prediction': 0.85,
        'virustotal': {
            'detection_count': 5,
            'total_scanners': 70,
            'is_malicious': True
        },
        'google_safe_browsing': {
            'is_unsafe': True,
            'threat_types': ['PHISHING']
        },
        'rule_based': {
            'triggered_rules': ['fake_domain', 'phishing_text'],
            'rule_score': 65
        },
        'ssl_analysis': {
            'ssl_risk_score': 40
        },
        'threat_feeds': {
            'feeds_flagged': 2,
            'aggregate_confidence': 75
        }
    }

    result = compute_final_risk_score(test_input)

    print('Final Risk Score Computation:')
    print(f'  Final Score: {result["final_score"]}/100')
    print(f'  Risk Level: {result["risk_level"]}')
    print(f'  Confidence: {result["confidence"]}')
    print(f'  Layers Used: {result["layers_used"]}')
    print(f'  Override Applied: {result["override_applied"]}')
    if result['override_reason']:
        print(f'  Override Reason: {result["override_reason"]}')
    print(f'\n  Recommendation: {result["recommendation"]}\n')

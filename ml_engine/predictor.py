"""
Predictor — loads the trained model and runs phishing predictions.

Public API:
    load_model()                           → loads model once
    predict_url(url)                       → full ML result dict
    integrate_virustotal(url, api_key)     → VT result dict
    integrate_google_safe_browsing(url, api_key) → GSB result dict
    combine_results(ml, vt, gsb)           → final combined dict
"""

import os
import json
import joblib
import numpy as np
import requests

from ml_engine.feature_extractor import (
    FeatureExtractor, get_feature_flag, FEATURE_THRESHOLDS
)

_HERE  = os.path.dirname(os.path.abspath(__file__))
_MODEL_PATH = os.path.join(_HERE, 'phishing_model.pkl')

_model = None   # module-level singleton


# ── Model loading ────────────────────────────────────────────

def load_model():
    """Load (or reload) the model from disk.  Returns True on success."""
    global _model
    if not os.path.exists(_MODEL_PATH) or os.path.getsize(_MODEL_PATH) == 0:
        return False
    try:
        _model = joblib.load(_MODEL_PATH)
        return True
    except Exception:
        _model = None
        return False


def _get_model():
    global _model
    if _model is None:
        load_model()
    return _model


# ── Feature helpers ──────────────────────────────────────────

_FEATURE_LABELS = {
    'url_length':           'URL Length',
    'has_ip_address':       'IP Address Used',
    'special_char_count':   'Special Characters',
    'subdomain_count':      'Subdomain Depth',
    'has_https':            'HTTPS Enabled',
    'domain_age_days':      'Domain Age (days)',
    'url_shortener':        'URL Shortener',
    'suspicious_keywords':  'Suspicious Keywords',
    'redirect_count':       'Redirect Count',
    'path_length':          'Path Length',
    'query_param_count':    'Query Parameters',
    'has_port':             'Non-Standard Port',
    'domain_length':        'Domain Length',
    'prefix_suffix':        'Prefix/Suffix Hyphen',
    'double_slash_redirect':'Double-Slash Redirect',
    'has_at_symbol':        '@ Symbol in URL',
}


# ── Core prediction ──────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Returns:
        score          – 0-100 phishing probability
        label          – 'Safe' | 'Suspicious' | 'Dangerous'
        features       – {feature_name: value}
        feature_flags  – {feature_name: 'pass'|'warn'|'fail'}
        feature_labels – {feature_name: human_readable_name}
        recommendation – text advice
        model_available – bool
    """
    model = _get_model()

    extractor = FeatureExtractor()
    features = extractor.extract(url, fast=False)

    feature_flags = {
        name: get_feature_flag(name, val)
        for name, val in features.items()
    }

    if model is None:
        # Model not trained yet — use heuristic score
        fail_count = sum(1 for f in feature_flags.values() if f == 'fail')
        warn_count = sum(1 for f in feature_flags.values() if f == 'warn')
        score = min(int(fail_count * 15 + warn_count * 5), 100)
        label = _score_to_label(score)
        return {
            'score':           score,
            'label':           label,
            'features':        features,
            'feature_flags':   feature_flags,
            'feature_labels':  _FEATURE_LABELS,
            'recommendation':  _recommendation(label, score),
            'model_available': False,
        }

    # Build feature vector in training order
    feature_names = getattr(model, 'feature_names_', FeatureExtractor.FEATURE_NAMES)
    X = np.array([[features.get(n, 0) for n in feature_names]])

    try:
        proba = model.predict_proba(X)[0]
        # class index 1 = phishing
        classes = list(model.classes_)
        phish_idx = classes.index(1) if 1 in classes else -1
        raw_prob = float(proba[phish_idx]) if phish_idx != -1 else 0.5
    except Exception:
        raw_prob = 0.5

    score = int(round(raw_prob * 100))
    label = _score_to_label(score)

    return {
        'score':           score,
        'label':           label,
        'features':        features,
        'feature_flags':   feature_flags,
        'feature_labels':  _FEATURE_LABELS,
        'recommendation':  _recommendation(label, score),
        'model_available': True,
    }


def _score_to_label(score: int) -> str:
    if score >= 70:
        return 'Dangerous'
    if score >= 40:
        return 'Suspicious'
    return 'Safe'


def generate_explanation(features: dict, feature_flags: dict, score: int, label: str) -> dict:
    """
    Generate a human-readable explanation of why a URL received its risk score.
    Returns a structured dict with verdict_summary, triggered_flags, clean_flags, and advice.
    """
    # Per-feature explanations (triggered = bad, clean = good)
    _EXPLANATIONS = {
        'url_length': {
            'label': 'URL Length',
            'triggered': 'This URL is unusually long ({val} characters). Legitimate URLs are typically concise. Phishing URLs are often padded with extra paths or parameters to obscure the real destination or stuff in keywords.',
            'clean': 'The URL length ({val} characters) is within a normal range, which is consistent with legitimate websites.',
        },
        'has_ip_address': {
            'label': 'IP Address Used',
            'triggered': 'The URL uses a raw IP address instead of a domain name. Legitimate websites always use domain names. Attackers use IP addresses because they are quick to set up and harder to blacklist.',
            'clean': 'The URL uses a domain name rather than a raw IP address, which is consistent with legitimate websites.',
        },
        'special_char_count': {
            'label': 'Special Characters',
            'triggered': 'The URL contains {val} special characters (e.g. @, !, %, ~). Phishing URLs often use special characters to confuse filters or disguise the real destination. The @ symbol in particular can redirect browsers to a completely different host.',
            'clean': 'The URL contains only {val} special character(s), which is within a normal range.',
        },
        'subdomain_count': {
            'label': 'Subdomain Depth',
            'triggered': 'The URL has {val} subdomain levels. Attackers use deep subdomains to make a URL look legitimate — e.g. "paypal.com.evil-site.net" uses "paypal" as a subdomain of the attacker\'s domain.',
            'clean': 'The URL has {val} subdomain level(s), which is typical for legitimate websites.',
        },
        'has_https': {
            'label': 'HTTPS Encryption',
            'triggered': 'This URL does not use HTTPS. While HTTPS alone does not guarantee safety, the absence of it means your connection is unencrypted and any data you submit could be intercepted by anyone on the network.',
            'clean': 'The URL uses HTTPS, meaning the connection is encrypted. Note: HTTPS does NOT guarantee a site is safe — phishing sites can also obtain SSL certificates — but it is a basic expected feature of legitimate sites.',
        },
        'domain_age_days': {
            'label': 'Domain Age',
            'triggered': 'This domain was registered only {val} days ago. Legitimate websites typically have older, established domains. Attackers frequently register new domains specifically for phishing campaigns to avoid existing blacklists.',
            'clean': 'This domain is {val} days old, indicating it is an established website. Freshly registered domains (under 30 days) are a common red flag for phishing.',
        },
        'url_shortener': {
            'label': 'URL Shortener',
            'triggered': 'This URL uses a URL shortening service. Shorteners completely hide the real destination URL, making it impossible to judge where you will actually land. Attackers exploit this to bypass email filters and security checks.',
            'clean': 'This URL does not use a URL shortening service, so the destination is transparent.',
        },
        'suspicious_keywords': {
            'label': 'Suspicious Keywords',
            'triggered': 'The URL contains {val} suspicious keyword(s) commonly found in phishing URLs (e.g. "login", "verify", "secure", "account", "update", "confirm"). Legitimate sites rarely embed these words in their URL paths.',
            'clean': 'No suspicious keywords were found in the URL. Phishing URLs commonly contain words like "login", "verify", "secure", or "account" to appear legitimate.',
        },
        'redirect_count': {
            'label': 'Redirect Chain',
            'triggered': 'This URL redirects {val} time(s) before reaching its destination. Multiple redirects are a common technique used by attackers to disguise the real destination and bypass URL scanners that only check the original link.',
            'clean': 'No unexpected redirects were detected. Redirect chains are commonly used by phishing sites to disguise their true destination.',
        },
        'path_length': {
            'label': 'URL Path Length',
            'triggered': 'The URL path is {val} characters long, which is unusually lengthy. Phishing URLs often use long paths filled with random characters to defeat pattern-matching filters or to include obfuscated parameters.',
            'clean': 'The URL path length ({val} characters) is within normal bounds.',
        },
        'query_param_count': {
            'label': 'Query Parameters',
            'triggered': 'The URL contains {val} query parameters. Excessive query parameters can be used to pass hidden data, track victims, or encode redirect destinations in ways that are hard for automated systems to analyse.',
            'clean': 'The URL has {val} query parameter(s), which is within normal range.',
        },
        'has_port': {
            'label': 'Non-Standard Port',
            'triggered': 'This URL specifies a non-standard port number. Legitimate public websites almost always use the default ports (80 for HTTP, 443 for HTTPS). Unusual ports suggest an attacker-controlled server running on non-standard infrastructure.',
            'clean': 'The URL does not specify a non-standard port, which is consistent with legitimate websites.',
        },
        'domain_length': {
            'label': 'Domain Length',
            'triggered': 'The domain name is {val} characters long, which is unusually lengthy. Attackers often register long domain names to include legitimate-looking brand names (e.g. "secure-paypal-verification-login.com") while the real domain is different.',
            'clean': 'The domain name length ({val} characters) is within a normal range.',
        },
        'prefix_suffix': {
            'label': 'Prefix/Suffix Hyphen in Domain',
            'triggered': 'The domain contains a hyphen used as a prefix or suffix (e.g. "paypal-secure.com"). This is a well-known technique to make fake domains look related to legitimate brands while being completely different domains.',
            'clean': 'No suspicious prefix or suffix hyphenation was detected in the domain name.',
        },
        'double_slash_redirect': {
            'label': 'Double-Slash Redirect',
            'triggered': 'The URL contains a double-slash (//) after the path, which can be used to redirect browsers to a different domain entirely. This technique bypasses naive URL parsers and email security filters.',
            'clean': 'No double-slash redirect pattern was detected in the URL.',
        },
        'has_at_symbol': {
            'label': '@ Symbol in URL',
            'triggered': 'The URL contains an @ symbol. In URLs, everything before the @ is treated as credentials (username:password), and the browser navigates to the address AFTER the @. This is an old but still-effective trick to redirect victims to malicious sites while showing a legitimate-looking URL.',
            'clean': 'No @ symbol was found in the URL. The @ symbol in a URL is a serious red flag as it can redirect browsers to a completely different host.',
        },
    }

    _SEVERITY_MAP = {
        'has_ip_address':       'high',
        'has_https':            'high',
        'domain_age_days':      'high',
        'url_shortener':        'medium',
        'suspicious_keywords':  'high',
        'has_at_symbol':        'high',
        'double_slash_redirect':'high',
        'prefix_suffix':        'medium',
        'url_length':           'medium',
        'subdomain_count':      'medium',
        'special_char_count':   'medium',
        'redirect_count':       'medium',
        'path_length':          'low',
        'query_param_count':    'low',
        'has_port':             'medium',
        'domain_length':        'low',
    }

    # Override severity to high when domain age < 30 or when flag=fail
    def _severity(name, flag):
        if flag == 'fail' and _SEVERITY_MAP.get(name) == 'medium':
            return 'high'
        return _SEVERITY_MAP.get(name, 'medium')

    triggered_flags = []
    clean_flags = []

    for name, flag in feature_flags.items():
        meta = _EXPLANATIONS.get(name)
        if meta is None:
            continue

        val = features.get(name, 0)
        # Format val for display
        if name == 'domain_age_days':
            val_str = f'{val} days' if val >= 0 else 'unknown'
        elif name in ('has_ip_address', 'has_https', 'url_shortener',
                      'has_port', 'prefix_suffix', 'double_slash_redirect', 'has_at_symbol'):
            val_str = 'Yes' if val else 'No'
        else:
            val_str = str(val)

        if flag in ('fail', 'warn'):
            severity = _severity(name, flag)
            triggered_flags.append({
                'feature':     meta['label'],
                'value':       val_str,
                'severity':    severity,
                'explanation': meta['triggered'].format(val=val_str),
            })
        else:
            clean_flags.append({
                'feature':     meta['label'],
                'value':       val_str,
                'explanation': meta['clean'].format(val=val_str),
            })

    # Sort triggered: high → medium → low
    sev_order = {'high': 0, 'medium': 1, 'low': 2}
    triggered_flags.sort(key=lambda x: sev_order.get(x['severity'], 3))

    risk_count  = len(triggered_flags)
    clean_count = len(clean_flags)

    # Verdict summary
    if label == 'Dangerous':
        verdict = (f'This URL was flagged as DANGEROUS because it triggered '
                   f'{risk_count} risk indicator{"s" if risk_count != 1 else ""}.')
    elif label == 'Suspicious':
        verdict = (f'This URL is SUSPICIOUS — it triggered '
                   f'{risk_count} risk indicator{"s" if risk_count != 1 else ""} '
                   'that warrant caution.')
    else:
        verdict = (f'This URL appears SAFE. Only {risk_count} minor flag'
                   f'{"s were" if risk_count != 1 else " was"} detected '
                   f'and {clean_count} factor{"s" if clean_count != 1 else ""} passed clean.')

    # Advice
    if label == 'Dangerous':
        advice = ('Do NOT visit this URL. If you received this link via email or message, '
                  'report it to your IT department immediately and delete the message without clicking anything.')
    elif label == 'Suspicious':
        advice = ('Proceed with extreme caution. Verify the domain is exactly correct before entering '
                  'any credentials. When in doubt, navigate directly to the official website by typing '
                  'its address in your browser rather than clicking this link.')
    else:
        advice = ('This URL appears to be safe, but stay vigilant. Always ensure you are on the correct '
                  'domain before submitting any personal information, and check for the HTTPS padlock.')

    return {
        'verdict_summary':      verdict,
        'triggered_flags':      triggered_flags,
        'clean_flags':          clean_flags,
        'risk_factors_count':   risk_count,
        'clean_factors_count':  clean_count,
        'advice':               advice,
    }


def _recommendation(label: str, score: int) -> str:
    if label == 'Dangerous':
        return (
            f'This URL has a high phishing probability ({score}%). '
            'Do NOT enter any personal information, passwords, or payment '
            'details on this site. Close the tab immediately and report '
            'it as phishing to your email provider or browser.'
        )
    if label == 'Suspicious':
        return (
            f'This URL shows several suspicious characteristics ({score}%). '
            'Exercise caution. Verify the domain is correct, check for '
            'HTTPS, and avoid entering sensitive credentials. If in doubt, '
            'contact the organisation directly through their official website.'
        )
    return (
        f'This URL appears to be legitimate ({score}% phishing probability). '
        'Standard online safety practices still apply: ensure HTTPS is active '
        'and the domain matches the expected organisation before submitting '
        'any personal information.'
    )


# ── VirusTotal integration ───────────────────────────────────

def integrate_virustotal(url: str, api_key: str) -> dict:
    """
    Returns:
        detections      – int  (engines that flagged as malicious)
        total_engines   – int
        threat_names    – list[str]
        permalink       – str  (VT report URL)
        error           – str | None
    """
    if not api_key:
        return {'error': 'API key not configured', 'detections': 0,
                'total_engines': 0, 'threat_names': [], 'permalink': ''}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        headers = {'x-apikey': api_key}

        resp = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers, timeout=10)

        if resp.status_code == 404:
            # URL not in VT cache — submit for scanning
            resp2 = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=10)
            if resp2.status_code == 200:
                return {'error': 'Scan submitted to VirusTotal. Check back later.',
                        'detections': 0, 'total_engines': 0,
                        'threat_names': [], 'permalink': ''}
            return {'error': f'VT submission failed ({resp2.status_code})',
                    'detections': 0, 'total_engines': 0,
                    'threat_names': [], 'permalink': ''}

        if resp.status_code != 200:
            return {'error': f'VirusTotal API error ({resp.status_code})',
                    'detections': 0, 'total_engines': 0,
                    'threat_names': [], 'permalink': ''}

        data = resp.json().get('data', {})
        stats = data.get('attributes', {}).get('last_analysis_stats', {})
        results = data.get('attributes', {}).get('last_analysis_results', {})

        detections = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values())
        threat_names = list({
            v.get('result') for v in results.values()
            if v.get('category') in ('malicious', 'suspicious') and v.get('result')
        })
        permalink = f'https://www.virustotal.com/gui/url/{url_id}'

        return {
            'detections':    detections,
            'total_engines': total,
            'threat_names':  threat_names[:5],
            'permalink':     permalink,
            'error':         None,
        }
    except requests.exceptions.Timeout:
        return {'error': 'VirusTotal request timed out',
                'detections': 0, 'total_engines': 0,
                'threat_names': [], 'permalink': ''}
    except Exception as e:
        return {'error': f'VirusTotal error: {str(e)[:80]}',
                'detections': 0, 'total_engines': 0,
                'threat_names': [], 'permalink': ''}


# ── Google Safe Browsing integration ────────────────────────

def integrate_google_safe_browsing(url: str, api_key: str) -> dict:
    """
    Returns:
        threat_type  – 'clean' | threat string | None
        platform     – str | None
        error        – str | None
    """
    if not api_key:
        return {'threat_type': None, 'platform': None,
                'error': 'API key not configured'}
    try:
        payload = {
            'client': {'clientId': 'eseas', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': [
                    'MALWARE', 'SOCIAL_ENGINEERING',
                    'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'
                ],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}],
            },
        }
        resp = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find'
            f'?key={api_key}',
            json=payload, timeout=10)

        if resp.status_code != 200:
            return {'threat_type': None, 'platform': None,
                    'error': f'GSB API error ({resp.status_code})'}

        matches = resp.json().get('matches', [])
        if not matches:
            return {'threat_type': 'clean', 'platform': None, 'error': None}

        m = matches[0]
        return {
            'threat_type': m.get('threatType', 'UNKNOWN'),
            'platform':    m.get('platformType', ''),
            'error':       None,
        }
    except requests.exceptions.Timeout:
        return {'threat_type': None, 'platform': None,
                'error': 'Google Safe Browsing request timed out'}
    except Exception as e:
        return {'threat_type': None, 'platform': None,
                'error': f'GSB error: {str(e)[:80]}'}


# ── Result combination ───────────────────────────────────────

def combine_results(ml_result: dict, vt_result: dict, gsb_result: dict) -> dict:
    """
    Combine ML, VT, and GSB into a final risk assessment.

    Weight:  ML=60%  VT=25%  GSB=15%
    """
    ml_score = ml_result.get('score', 0)

    # VT score: proportion of engines that flagged
    # Only counted when VT actually returned results (no error, engines > 0)
    vt_score = 0
    total_eng = vt_result.get('total_engines', 0)
    vt_has_data = bool(total_eng and not vt_result.get('error'))
    if vt_has_data:
        vt_score = int((vt_result.get('detections', 0) / total_eng) * 100)

    # GSB score: binary 0 or 100
    # Only counted when GSB returned a definitive result (no error, threat_type present)
    gsb_score = 0
    gsb_has_data = bool(not gsb_result.get('error') and gsb_result.get('threat_type'))
    if gsb_has_data:
        threat = gsb_result.get('threat_type')
        if threat and threat != 'clean':
            gsb_score = 100

    # Weighted combination — redistribute unused weights to ML so that when
    # VT/GSB have no data (e.g. first-time URL submitted to VT), the ML score
    # is not artificially diluted from its original value.
    vt_w  = 0.25 if vt_has_data  else 0.0
    gsb_w = 0.15 if gsb_has_data else 0.0
    ml_w  = 1.0 - vt_w - gsb_w   # absorbs any unused weight

    final_score = int(ml_score * ml_w + vt_score * vt_w + gsb_score * gsb_w)
    final_score = max(0, min(final_score, 100))

    # Override: if either external API confirms dangerous, floor at 70
    if vt_result.get('detections', 0) > 3 or gsb_score == 100:
        final_score = max(final_score, 70)

    final_label = _score_to_label(final_score)

    return {
        **ml_result,
        'score':         final_score,
        'label':         final_label,
        'ml_score':      ml_score,
        'vt_result':     vt_result,
        'gsb_result':    gsb_result,
        'recommendation': _recommendation(final_label, final_score),
    }

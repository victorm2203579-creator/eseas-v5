"""
TASK 12 — Final integrated scanner testing.
Tests all modules together: feature extraction, ML, threat feeds, SSL, redirects, typosquatting, scoring.
"""

import sys
import os
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml_engine.feature_extractor import FeatureExtractor
from ml_engine.predictor import predict_url
from ml_engine.threat_feeds import query_all_threat_feeds
from ml_engine.ssl_checker import check_ssl_certificate
from ml_engine.redirect_analyzer import analyze_redirect_chain
from ml_engine.typosquatting import check_typosquatting
from ml_engine.scoring_engine import compute_final_risk_score


def test_url(url, description):
    """Test a single URL through the entire pipeline."""
    print(f'\n{"="*70}')
    print(f'Testing: {description}')
    print(f'URL: {url}')
    print("="*70)

    # Extract domain
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc
    except Exception as e:
        print(f'[ERROR] Failed to parse URL: {e}')
        return

    try:
        # [1] ML Prediction
        print('\n[1] Running ML prediction...')
        ml_result = predict_url(url)
        ml_score = ml_result.get('ml_score', 0)
        print(f'    ML Score: {ml_score}/100')
        print(f'    ML Label: {ml_result.get("label", "Unknown")}')

        # [2] Threat Feeds
        print('\n[2] Querying threat feeds...')
        feeds_result = query_all_threat_feeds(url, domain)
        print(f'    Feeds flagged: {feeds_result.get("feeds_flagged", 0)}/3')
        print(f'    Aggregate confidence: {feeds_result.get("aggregate_confidence", 0)}%')
        print(f'    Is malicious: {feeds_result.get("is_malicious", False)}')

        # [3] SSL Analysis
        print('\n[3] Analyzing SSL certificate...')
        ssl_result = check_ssl_certificate(domain)
        print(f'    SSL available: {ssl_result.get("ssl_available", False)}')
        print(f'    SSL risk score: {ssl_result.get("ssl_risk_score", 0)}/100')
        if ssl_result.get('domain_mismatch'):
            print(f'    [!] Domain mismatch detected!')

        # [4] Redirect Analysis
        print('\n[4] Analyzing redirect chain...')
        redirect_result = analyze_redirect_chain(url)
        print(f'    Redirect count: {redirect_result.get("redirect_count", 0)}')
        print(f'    Crosses domains: {redirect_result.get("crosses_domains", False)}')
        print(f'    Redirect risk score: {redirect_result.get("redirect_risk_score", 0)}/100')

        # [5] Typosquatting
        print('\n[5] Checking typosquatting...')
        typo_result = check_typosquatting(domain)
        print(f'    Is typosquatting: {typo_result.get("is_typosquatting", False)}')
        if typo_result.get('target_brand'):
            print(f'    Target brand: {typo_result["target_brand"]}')
            print(f'    Similarity: {typo_result.get("similarity_score", 0):.2%}')
        print(f'    Typosquatting risk: {typo_result.get("typosquatting_risk_score", 0)}/100')

        # [6] Compute Final Risk Score
        print('\n[6] Computing unified risk score...')
        analysis_results = {
            'ml_prediction': ml_score / 100.0 if ml_score else None,
            'threat_feeds': feeds_result,
            'ssl_analysis': ssl_result,
            'redirect_analysis': redirect_result,
            'typosquatting': typo_result,
        }

        final_result = compute_final_risk_score(analysis_results)

        print(f'\n{"="*70}')
        print(f'FINAL RESULTS:')
        print(f'{"="*70}')
        print(f'Final Score: {final_result["final_score"]}/100')
        print(f'Risk Level: {final_result["risk_level"]}')
        print(f'Risk Color: {final_result["risk_color"]}')
        print(f'Confidence: {final_result["confidence"]}')
        print(f'Layers used: {final_result["layers_used"]}/8')
        print(f'Override applied: {final_result["override_applied"]}')
        if final_result.get('override_reason'):
            print(f'Override reason: {final_result["override_reason"]}')
        print(f'Recommendation: {final_result["recommendation"]}')

        return final_result

    except Exception as e:
        print(f'\n[ERROR] {type(e).__name__}: {str(e)[:200]}')
        import traceback
        traceback.print_exc()
        return None


def main():
    print('\n' + '='*70)
    print('ESEAS INTEGRATED SCANNER — FINAL TESTING')
    print('='*70)

    # Test URLs
    test_cases = [
        ('http://192.168.1.1/paypal/login', 'IP address (obvious phishing)'),
        ('https://paypa1.com/secure/login', 'Typosquatting (paypal → paypa1)'),
        ('https://google.com', 'Known safe domain'),
        ('http://bit.ly/3xample', 'URL shortener (suspicious but common)'),
        ('https://login-microsoft-secure.xyz/verify', 'Suspicious TLD + prefix-suffix'),
    ]

    results = {}
    for url, desc in test_cases:
        result = test_url(url, desc)
        if result:
            results[url] = result

    # Summary
    print(f'\n\n{"="*70}')
    print('TEST SUMMARY')
    print(f'{"="*70}')

    expected = {
        'http://192.168.1.1/paypal/login': {'min': 80, 'max': 100, 'name': 'IP address'},
        'https://paypa1.com/secure/login': {'min': 60, 'max': 100, 'name': 'Typosquatting'},
        'https://google.com': {'min': 0, 'max': 20, 'name': 'google.com'},
        'http://bit.ly/3xample': {'min': 40, 'max': 60, 'name': 'Shortener'},
        'https://login-microsoft-secure.xyz/verify': {'min': 70, 'max': 100, 'name': 'Fake Microsoft'},
    }

    passed = 0
    failed = 0

    for url, exp in expected.items():
        if url not in results:
            print(f'\n[SKIP] {exp["name"]}: No result')
            continue

        score = results[url]['final_score']
        in_range = exp['min'] <= score <= exp['max']

        status = '[PASS]' if in_range else '[FAIL]'
        passed += 1 if in_range else 0
        failed += 0 if in_range else 1

        print(f'{status} {exp["name"]:30s} Score: {score:3d} (expected {exp["min"]}-{exp["max"]})')

    print(f'\n{"="*70}')
    print(f'Results: {passed} passed, {failed} failed')
    print(f'{"="*70}\n')


if __name__ == '__main__':
    main()

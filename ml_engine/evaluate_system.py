"""
End-to-end full-system evaluation.

Unlike train_model.py (which measures the ML model alone), this measures the
ACTUAL production pipeline: ML + VirusTotal + Google Safe Browsing + URL rules
+ threat feeds + SSL + redirect + typosquatting, combined by
scoring_engine.compute_final_risk_score() exactly as routes/analyzer.py does
on a real scan.

Test URLs are drawn from the same dataset used to train the ML model, but
from rows EXCLUDED from training (same random seed/sampling as train_model.py
is replicated here purely to compute the exclusion set — no model state is
reused). This avoids reporting an inflated number from data the model has
already seen.

VirusTotal's free-tier API is rate-limited (~4 req/min). This script throttles
VT calls to respect that, so runtime is dominated by that wait, not compute.

Usage:
    python ml_engine/evaluate_system.py [--n-per-class 50]
"""

import os
import sys
import time
import json
import argparse

import truststore
truststore.inject_into_ssl()  # trust the OS cert store, not just certifi's bundled list

import numpy as np
import pandas as pd
from dotenv import load_dotenv

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.dirname(_HERE)
sys.path.insert(0, _PROJECT)

load_dotenv(os.path.join(_PROJECT, '.env'))

from ml_engine.predictor import predict_url, integrate_virustotal, integrate_google_safe_browsing
from ml_engine.scoring_engine import compute_final_risk_score
from ml_engine.threat_feeds import query_all_threat_feeds
from ml_engine.ssl_checker import check_ssl_certificate
from ml_engine.redirect_analyzer import analyze_redirect_chain
from ml_engine.typosquatting import check_typosquatting
from urllib.parse import urlparse

DATASET_CANDIDATES = [
    os.path.join(_PROJECT, '..', 'Data', 'URL dataset.csv'),
    os.path.join(_PROJECT, '..', 'Data', 'Phishing URLs.csv'),
    os.path.join(_PROJECT, '..', 'Data', 'phishing_dataset.csv'),
    os.path.join(_PROJECT, '..', 'Data', 'dataset.csv'),
]

RESULTS_PATH = os.path.join(_HERE, 'system_eval_results.json')

VT_MIN_INTERVAL_SECONDS = 16  # ~3.75 req/min, safely under the 4/min free-tier limit


def find_dataset():
    for p in DATASET_CANDIDATES:
        if os.path.exists(p):
            return p
    raise FileNotFoundError('No dataset found')


def load_labeled_urls():
    path = find_dataset()
    df = pd.read_csv(path)

    url_col = next((c for c in df.columns if c.lower() in ('url', 'urls')), df.columns[0])
    label_col = next((c for c in df.columns if c.lower() in ('type', 'class', 'label', 'phishing', 'target')), df.columns[-1])

    raw_labels = df[label_col].astype(str).str.lower()
    y_all = raw_labels.str.contains('phish|malicious|bad|suspicious').astype(int).values
    urls_all = df[url_col].astype(str).values
    return urls_all, y_all


def training_excluded_indices(y_all, per_class=15000, seed=42):
    """Replicate train_model.py's exact sampling to know which rows it used."""
    np.random.seed(seed)
    legit_idx = np.where(y_all == 0)[0]
    phish_idx = np.where(y_all == 1)[0]
    per_class = min(per_class, len(legit_idx), len(phish_idx))
    legit_sample = np.random.choice(legit_idx, per_class, replace=False)
    phish_sample = np.random.choice(phish_idx, per_class, replace=False)
    return set(legit_sample.tolist()) | set(phish_sample.tolist())


def sample_eval_set(urls_all, y_all, used_indices, n_per_class, seed=123):
    np.random.seed(seed)
    legit_pool = [i for i in np.where(y_all == 0)[0] if i not in used_indices]
    phish_pool = [i for i in np.where(y_all == 1)[0] if i not in used_indices]

    legit_sample = np.random.choice(legit_pool, n_per_class, replace=False)
    phish_sample = np.random.choice(phish_pool, n_per_class, replace=False)

    idx = np.concatenate([legit_sample, phish_sample])
    np.random.shuffle(idx)
    return urls_all[idx], y_all[idx]


def run_full_pipeline(url, vt_key, gsb_key, last_vt_call):
    """Mirrors routes/analyzer.py's scan orchestration for one URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        domain = urlparse(url).netloc
    except Exception:
        domain = url

    # Throttle VT to respect free-tier rate limit
    elapsed = time.time() - last_vt_call[0]
    if elapsed < VT_MIN_INTERVAL_SECONDS:
        time.sleep(VT_MIN_INTERVAL_SECONDS - elapsed)

    analysis_results = {}

    ml_result = predict_url(url, fast=True)
    try:
        analysis_results['threat_feeds'] = query_all_threat_feeds(url, domain)
    except Exception:
        pass
    try:
        analysis_results['ssl_analysis'] = check_ssl_certificate(domain)
    except Exception:
        pass
    try:
        analysis_results['redirect_analysis'] = analyze_redirect_chain(url)
    except Exception:
        pass
    try:
        analysis_results['typosquatting'] = check_typosquatting(domain)
    except Exception:
        pass

    vt_result = integrate_virustotal(url, vt_key)
    last_vt_call[0] = time.time()
    gsb_result = integrate_google_safe_browsing(url, gsb_key)

    analysis_results['url'] = url
    analysis_results['ml_prediction'] = ml_result.get('score', 0) / 100.0
    analysis_results['virustotal'] = {
        'detection_count': vt_result.get('detections', 0),
        'total_scanners': vt_result.get('total_engines', 70),
        'is_malicious': vt_result.get('detections', 0) > 0,
    }
    analysis_results['google_safe_browsing'] = {
        'is_unsafe': bool(gsb_result.get('threat_type') and gsb_result.get('threat_type') != 'clean'),
        'threat_types': [gsb_result.get('threat_type')] if gsb_result.get('threat_type') else [],
    }

    return compute_final_risk_score(analysis_results)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--n-per-class', type=int, default=50)
    args = parser.parse_args()

    vt_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    gsb_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')

    print('\n=== ESEAS Full-System Evaluation (ML + VT + GSB + Rules + Feeds + SSL + Redirect + Typo) ===\n')

    print('[1] Loading dataset and excluding ML training rows...')
    urls_all, y_all = load_labeled_urls()
    used = training_excluded_indices(y_all)
    print(f'  Total rows: {len(urls_all):,}  |  Excluded (used in ML training): {len(used):,}')

    print(f'[2] Sampling {args.n_per_class} legitimate + {args.n_per_class} phishing URLs (held out from training)...')
    urls, y_true = sample_eval_set(urls_all, y_all, used, args.n_per_class)
    print(f'  Eval set: {len(urls)} URLs')

    est_minutes = len(urls) * VT_MIN_INTERVAL_SECONDS / 60
    print(f'  Estimated runtime: ~{est_minutes:.0f} minutes (VT rate-limit throttled)\n')

    print('[3] Running each URL through the full production pipeline...')
    last_vt_call = [0.0]
    y_pred = []
    records = []

    for i, (url, label) in enumerate(zip(urls, y_true), 1):
        try:
            result = run_full_pipeline(url, vt_key, gsb_key, last_vt_call)
            pred = 1 if result['final_score'] >= 41 else 0  # Suspicious-and-above = positive, matching the app's own risk thresholds
            y_pred.append(pred)
            records.append({
                'url': url, 'true_label': int(label), 'predicted_label': pred,
                'final_score': result['final_score'], 'risk_level': result['risk_level'],
                'layers_used': result['layers_used'],
            })
            print(f'  [{i}/{len(urls)}] true={label} pred={pred} score={result["final_score"]} ({result["risk_level"]}) layers={result["layers_used"]}')
        except Exception as e:
            y_pred.append(0)
            records.append({'url': url, 'true_label': int(label), 'predicted_label': 0, 'error': str(e)})
            print(f'  [{i}/{len(urls)}] ERROR: {e}')

    print('\n[4] Computing metrics...')
    y_true_arr = np.array(y_true)
    y_pred_arr = np.array(y_pred)

    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

    acc = accuracy_score(y_true_arr, y_pred_arr)
    prec = precision_score(y_true_arr, y_pred_arr, zero_division=0)
    rec = recall_score(y_true_arr, y_pred_arr, zero_division=0)
    f1 = f1_score(y_true_arr, y_pred_arr, zero_division=0)
    cm = confusion_matrix(y_true_arr, y_pred_arr)

    print(f'\n  Accuracy : {acc:.4f}')
    print(f'  Precision: {prec:.4f}')
    print(f'  Recall   : {rec:.4f}')
    print(f'  F1 Score : {f1:.4f}')
    print(f'\n  Confusion Matrix:')
    print(f'  [[TN={cm[0,0]}  FP={cm[0,1]}]')
    print(f'   [FN={cm[1,0]}  TP={cm[1,1]}]]')
    print(f'\n{classification_report(y_true_arr, y_pred_arr, zero_division=0)}')

    output = {
        'n_per_class': args.n_per_class,
        'total_urls': len(urls),
        'accuracy': float(acc),
        'precision': float(prec),
        'recall': float(rec),
        'f1_score': float(f1),
        'confusion_matrix': cm.tolist(),
        'records': records,
    }
    with open(RESULTS_PATH, 'w') as f:
        json.dump(output, f, indent=2)
    print(f'\n[OK] Results saved to {RESULTS_PATH}\n')


if __name__ == '__main__':
    main()

"""
Optimized model training: Phishing detection only.
Trains on phishing URLs to detect suspicious patterns.
Uses reduced hyperparameter tuning for practical runtime.

Usage:
    python ml_engine/train_model.py
"""

import os
import sys
import warnings
import json
import time
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score,
                              classification_report, confusion_matrix)
from sklearn.preprocessing import LabelEncoder

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("[!] Install imbalanced-learn for SMOTE: pip install imbalanced-learn")

# ── paths ────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT = os.path.dirname(_HERE)
_DATA_DIR = os.path.join(_PROJECT, '..', 'Data')

DATASET_CANDIDATES = [
    os.path.join(_DATA_DIR, 'URL dataset.csv'),
    os.path.join(_DATA_DIR, 'Phishing URLs.csv'),
    os.path.join(_DATA_DIR, 'phishing_dataset.csv'),
    os.path.join(_DATA_DIR, 'dataset.csv'),
]

MODEL_PATH       = os.path.join(_HERE, 'phishing_model.pkl')
ENCODER_PATH     = os.path.join(_HERE, 'label_encoder.pkl')
METRICS_PATH     = os.path.join(_HERE, 'model_metrics.json')

sys.path.insert(0, _PROJECT)
from ml_engine.feature_extractor import FeatureExtractor


# ── helpers ──────────────────────────────────────────────────

def find_dataset():
    for p in DATASET_CANDIDATES:
        if os.path.exists(p):
            print(f'  Found dataset: {os.path.abspath(p)}')
            return p
    raise FileNotFoundError('No training dataset found')


def load_dataset():
    """Load dataset."""
    dataset_path = find_dataset()
    df = pd.read_csv(dataset_path)
    print(f'  Total rows: {len(df):,}')
    return df, dataset_path


def extract_features_for_dataset(df, feature_extractor, sample_size=None):
    """Extract features from REAL legitimate + phishing URLs using FeatureExtractor.

    sample_size is interpreted PER CLASS (balanced sampling) so the model sees
    a roughly even mix of real legitimate and real phishing examples.
    """

    # Identify URL and label columns
    url_col = None
    label_col = None

    for col in df.columns:
        if col.lower() in ['url', 'urls']:
            url_col = col
        elif col.lower() in ['type', 'class', 'label', 'phishing', 'target']:
            label_col = col

    if not url_col:
        url_col = df.columns[0]
    if not label_col:
        label_col = df.columns[-1]

    print(f'  URL column: {url_col}')
    print(f'  Label column: {label_col}')

    # Map text labels to binary: anything containing "phish"/"bad"/"malicious" -> 1, else 0
    raw_labels = df[label_col].astype(str).str.lower()
    y_all = raw_labels.str.contains('phish|malicious|bad|suspicious').astype(int).values
    urls_all = df[url_col].astype(str).values

    print(f'  Total rows: {len(urls_all):,}  (legitimate={int((y_all==0).sum()):,}, phishing={int((y_all==1).sum()):,})')

    # Balanced sampling — equal legitimate and phishing examples (real data, no synthetic noise)
    np.random.seed(42)
    legit_idx = np.where(y_all == 0)[0]
    phish_idx = np.where(y_all == 1)[0]

    per_class = sample_size or min(len(legit_idx), len(phish_idx))
    per_class = min(per_class, len(legit_idx), len(phish_idx))

    legit_sample = np.random.choice(legit_idx, per_class, replace=False)
    phish_sample = np.random.choice(phish_idx, per_class, replace=False)

    keep_idx = np.concatenate([legit_sample, phish_sample])
    np.random.shuffle(keep_idx)

    urls = urls_all[keep_idx]
    y = y_all[keep_idx]

    print(f'  Balanced sample: {len(urls):,} URLs ({per_class:,} legitimate + {per_class:,} phishing)')
    print(f'  Extracting features (fast=True, matching production inference)...')

    X_list = []
    feature_names_list = feature_extractor.FEATURE_NAMES

    for i, url in enumerate(urls):
        if i % 5000 == 0 and i > 0:
            print(f'    Processed {i:,}/{len(urls):,}...')
        try:
            features_dict = feature_extractor.extract(url, fast=True)
            features_array = np.array([features_dict[name] for name in feature_names_list], dtype=np.float32)
            X_list.append(features_array)
        except Exception as e:
            X_list.append(np.zeros(len(feature_names_list), dtype=np.float32))

    X = np.array(X_list, dtype=np.float32)
    print(f'  Extracted X shape: {X.shape}')

    return X, y


def save_feature_chart(clf, feature_names):
    """Save feature importance chart (matplotlib optional)."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        importances = clf.feature_importances_
        indices = np.argsort(importances)[::-1][:15]

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(range(len(indices)), importances[indices])
        ax.set_yticks(range(len(indices)))
        ax.set_yticklabels([feature_names[i] for i in indices], fontsize=9)
        ax.set_xlabel('Feature Importance')
        ax.set_title('Top 15 Features for Phishing Detection')

        chart_path = os.path.join(_PROJECT, 'static', 'images', 'feature_importance.png')
        os.makedirs(os.path.dirname(chart_path), exist_ok=True)
        plt.savefig(chart_path, dpi=100, bbox_inches='tight')
        plt.close()
        print(f'  Feature importance chart saved')
    except ImportError:
        print('  matplotlib not installed -- skipping chart')


def main():
    print('\n=== ESEAS Phishing Model Trainer (Phishing-Only, Optimized) ===\n')

    # [1] Load dataset
    print('[1] Loading dataset...')
    df, dataset_path = load_dataset()

    # [2] Initialize feature extractor
    print('[2] Initializing feature extractor...')
    feature_extractor = FeatureExtractor()
    feature_names = feature_extractor.FEATURE_NAMES
    print(f'  Features: {len(feature_names)}')

    # [3] Extract features from REAL legitimate + phishing URLs (balanced sample)
    print('[3] Extracting features from real legitimate + phishing URLs...')
    X_combined, y_combined = extract_features_for_dataset(df, feature_extractor, sample_size=15000)

    print(f'  Combined dataset: {len(X_combined):,} samples')
    print(f'  Class distribution: {np.bincount(y_combined)}')

    # [5] Train/test split
    print('[5] Splitting into train (80%) and test (20%)...')
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
    )
    print(f'  Train: {len(X_train):,}  |  Test: {len(X_test):,}')

    # [6] Hyperparameter tuning (SIMPLIFIED)
    print('[6] Tuning hyperparameters (15 iterations, 3-fold CV)...')
    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [10, 20, 30],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'max_features': ['sqrt', 'log2'],
        'class_weight': ['balanced', None],
    }

    rf_base = RandomForestClassifier(random_state=42, n_jobs=-1)

    search = RandomizedSearchCV(
        rf_base,
        param_grid,
        n_iter=15,  # Reduced from 30
        cv=3,       # Reduced from 5
        scoring='f1',
        n_jobs=-1,
        verbose=1,
        random_state=42
    )

    search.fit(X_train, y_train)
    clf = search.best_estimator_

    print(f'  Best params: {search.best_params_}')
    print(f'  Best CV F1 score: {search.best_score_:.4f}')

    # [7] Evaluate
    print('[7] Evaluating on test set...')
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print(f'\n  Accuracy : {acc:.4f}')
    print(f'  Precision: {prec:.4f}')
    print(f'  Recall   : {rec:.4f}')
    print(f'  F1 Score : {f1:.4f}')
    print(f'\n  Confusion Matrix:')
    print(f'  [[TN={cm[0,0]}  FP={cm[0,1]}]')
    print(f'   [FN={cm[1,0]}  TP={cm[1,1]}]]')

    print(f'\n  Classification Report:')
    print(classification_report(y_test, y_pred, zero_division=0))

    # [8] Feature importance
    print('[8] Feature importance (top 10)...')
    importances = clf.feature_importances_
    important_indices = np.argsort(importances)[::-1][:10]

    print('  Top 10 features:')
    for i, idx in enumerate(important_indices, 1):
        print(f'    {i:2d}. {feature_names[idx]:30s} {importances[idx]:.6f}')

    # [9] Save model
    print('[9] Saving model...')
    os.makedirs(_HERE, exist_ok=True)

    clf.feature_names_ = np.array(feature_names)
    joblib.dump(clf, MODEL_PATH)
    print(f'  Model saved to {MODEL_PATH}')

    # Save encoder
    le = LabelEncoder()
    le.fit([0, 1])
    joblib.dump(le, ENCODER_PATH)
    print(f'  Encoder saved')

    # Save metrics
    metrics = {
        'model_type': 'phishing_only_optimized',
        'dataset': dataset_path,
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'num_features': len(feature_names),
        'best_params': search.best_params_,
        'accuracy': float(acc),
        'precision': float(prec),
        'recall': float(rec),
        'f1_score': float(f1),
    }

    with open(METRICS_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f'  Metrics saved')

    # Save chart
    print('[10] Saving feature importance chart...')
    save_feature_chart(clf, feature_names)

    # Summary
    print(f'\n=== TRAINING SUMMARY ===')
    print(f'Model: Phishing-Only (Optimized)')
    print(f'Test Accuracy: {acc:.2%}')
    print(f'Test F1 Score: {f1:.2%}')
    print(f'Test Recall: {rec:.2%} (catches phishing)')
    print(f'\n[OK] Training complete.\n')


if __name__ == '__main__':
    main()

"""
Train a RandomForestClassifier on the phishing URL dataset.

Supports both UCI format and Kaggle format CSVs.

Usage (run from project/ directory):
    python ml_engine/train_model.py
"""

import os
import sys
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score,
                              recall_score, f1_score,
                              classification_report, confusion_matrix)
from sklearn.preprocessing import LabelEncoder

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
CHART_PATH       = os.path.join(_PROJECT, 'static', 'images', 'feature_importance.png')

sys.path.insert(0, _PROJECT)
from ml_engine.feature_extractor import FeatureExtractor


# ── helpers ──────────────────────────────────────────────────

def find_dataset():
    for p in DATASET_CANDIDATES:
        if os.path.exists(p):
            print(f'  Found dataset: {os.path.abspath(p)}')
            return p
    raise FileNotFoundError(
        f'No dataset found. Tried:\n' +
        '\n'.join(f'  {p}' for p in DATASET_CANDIDATES))


def load_dataset(path: str) -> tuple:
    """Load CSV and return (urls, labels) arrays.

    Supports:
      - UCI format: 30 numeric columns, last = class (-1/1)
      - Kaggle format: 'url'/'URL' column + 'label'/'type'/'status' column
      - Simple two-column format: url, label
    """
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip().lower() for c in df.columns]

    # ── UCI numeric format (no url column) ──
    if 'url' not in df.columns and 'urls' not in df.columns:
        label_col = df.columns[-1]
        feature_cols = df.columns[:-1]
        print(f'  UCI-style dataset: {len(df)} rows, {len(feature_cols)} features')
        labels = df[label_col].map(lambda x: 1 if int(x) == -1 else 0).values
        # For UCI format we use the pre-extracted features directly
        return None, labels, df[feature_cols]

    # ── URL-based format ──
    url_col  = next((c for c in df.columns if c in ('url', 'urls')), None)
    label_col = next(
        (c for c in df.columns if c in ('label','type','status','result','class')),
        None)

    if url_col is None or label_col is None:
        raise ValueError(
            f'Could not detect url/label columns. Found: {list(df.columns)}')

    df = df[[url_col, label_col]].dropna()
    df.columns = ['url', 'label']

    # Normalise labels → 1=phishing, 0=legitimate
    phishing_vals = {'phishing','bad','1',1,'malicious','spam','-1',-1,'defacement'}
    df['label'] = df['label'].apply(
        lambda x: 1 if str(x).strip().lower() in phishing_vals else 0)

    print(f'  URL-based dataset: {len(df)} rows  |  '
          f'phishing={df["label"].sum()}  legitimate={(df["label"]==0).sum()}')
    return df['url'].tolist(), df['label'].values, None


def extract_features(urls, labels) -> tuple:
    extractor = FeatureExtractor()
    print(f'  Extracting features for {len(urls):,} URLs (fast mode)…')
    features = extractor.extract_batch(urls, fast=True)
    X = pd.DataFrame(features, columns=FeatureExtractor.FEATURE_NAMES)
    # Fill any unexpected NaN
    X = X.fillna(0)
    return X.values, labels


def save_feature_chart(model, feature_names):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1]
        names   = [feature_names[i] for i in indices]
        vals    = importances[indices]

        fig, ax = plt.subplots(figsize=(10, 6))
        colors = ['#ff6b35' if v > 0.1 else '#1a2f4f' for v in vals]
        ax.barh(names[::-1], vals[::-1], color=colors[::-1])
        ax.set_xlabel('Feature Importance', fontsize=11)
        ax.set_title('Phishing Detection — Feature Importance',
                     fontsize=13, fontweight='bold')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        plt.tight_layout()

        os.makedirs(os.path.dirname(CHART_PATH), exist_ok=True)
        plt.savefig(CHART_PATH, dpi=150, bbox_inches='tight')
        plt.close()
        print(f'  Chart saved → {CHART_PATH}')
    except ImportError:
        print('  matplotlib not installed — skipping feature importance chart.')
    except Exception as e:
        print(f'  Chart error: {e}')


# ── main ─────────────────────────────────────────────────────

def main():
    print('\n=== ESEAS — Phishing Model Trainer ===\n')

    print('[1] Locating dataset…')
    path = find_dataset()

    print('[2] Loading dataset…')
    urls, labels, prebuilt_X = load_dataset(path)

    print('[3] Building feature matrix…')
    if prebuilt_X is not None:
        # UCI path: use raw numeric features, no extractor needed
        X = prebuilt_X.fillna(0).values
        feature_names = list(prebuilt_X.columns)
        print(f'  Using {len(feature_names)} pre-extracted features.')
    else:
        X, labels = extract_features(urls, labels)
        feature_names = FeatureExtractor.FEATURE_NAMES

    print(f'  X shape: {X.shape}  |  labels: {len(labels)}')

    print('[4] Splitting train/test (80/20)…')
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.20, random_state=42, stratify=labels)
    print(f'  Train: {len(X_train)}  Test: {len(X_test)}')

    print('[5] Training RandomForestClassifier (n_estimators=100)…')
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',
    )
    clf.fit(X_train, y_train)

    print('[6] Evaluating…')
    y_pred = clf.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    cm   = confusion_matrix(y_test, y_pred)

    print(f'\n  Accuracy : {acc:.4f}')
    print(f'  Precision: {prec:.4f}')
    print(f'  Recall   : {rec:.4f}')
    print(f'  F1 Score : {f1:.4f}')
    print('\n  Confusion Matrix:')
    print(f'  [[TN={cm[0,0]}  FP={cm[0,1]}]')
    print(f'   [FN={cm[1,0]}  TP={cm[1,1]}]]')
    print('\n' + classification_report(
        y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    print('[7] Saving model…')
    # Store feature names alongside model for validation at predict time
    clf.feature_names_ = feature_names
    joblib.dump(clf, MODEL_PATH)
    print(f'  Model saved → {MODEL_PATH}')

    # Save label encoder (identity for binary, kept for consistency)
    le = LabelEncoder()
    le.fit([0, 1])
    joblib.dump(le, ENCODER_PATH)
    print(f'  Encoder saved → {ENCODER_PATH}')

    print('[8] Saving feature importance chart…')
    save_feature_chart(clf, feature_names)

    print('\n✓ Training complete.\n')


if __name__ == '__main__':
    main()

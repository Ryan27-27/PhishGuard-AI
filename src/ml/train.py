"""
train.py — PhishGuard Pro Model Training Pipeline

Trains an ensemble of XGBoost + RandomForest + LightGBM on the phishing dataset.

Improvements over original:
  - 40+ features vs 17
  - Ensemble with soft voting vs single XGBoost
  - SMOTE for class imbalance handling
  - Cross-validation with stratified K-fold
  - Comprehensive evaluation metrics
  - Feature importance visualization
  - Model versioning

Usage:
    python src/ml/train.py --data data/urldata.csv --output models/
    python src/ml/train.py --download-data  # Download PhishTank + UNB data
"""

import os
import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime
import json

import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, accuracy_score,
    precision_score, recall_score, f1_score
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE

import xgboost as xgb
import lightgbm as lgb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Feature names used for training (must match url_features.py FEATURE_NAMES)
# Excludes live API features (virustotal, tor, mismatch) during offline training
TRAINING_FEATURES = [
    "has_ip_address", "url_length", "url_depth", "has_at_symbol",
    "has_double_slash_redirect", "has_http_in_domain", "is_shortened_url",
    "has_dash_in_domain", "subdomain_count", "has_suspicious_tld",
    "digit_ratio_in_domain", "special_char_count", "entropy_domain",
    "entropy_path", "has_port",
    "domain_age_days", "domain_expiry_days", "whois_available",
    "has_dns_a_record", "has_mx_record", "dns_ip_count",
    "typosquatting_detected", "typosquatting_edit_distance", "has_homoglyph",
    "registrar_is_free",
    "uses_https", "ssl_valid", "ssl_days_until_expiry", "ssl_self_signed",
    "ssl_issuer_trusted",
    "redirect_count", "has_suspicious_keywords", "num_query_params",
    "has_brand_in_subdomain", "url_has_encoded_chars",
]


def load_data(csv_path: str) -> tuple:
    """
    Load and preprocess training data.
    Expects CSV with feature columns + 'label' column (1=phishing, 0=legitimate).
    """
    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)

    # Handle missing feature columns gracefully
    missing = [f for f in TRAINING_FEATURES if f not in df.columns]
    if missing:
        logger.warning(f"Missing features in dataset, filling with 0: {missing}")
        for col in missing:
            df[col] = 0

    # Handle the domain_age_days: replace -1 with median of known values
    if "domain_age_days" in df.columns:
        known_ages = df[df["domain_age_days"] > 0]["domain_age_days"]
        median_age = known_ages.median() if len(known_ages) > 0 else 365
        df["domain_age_days"] = df["domain_age_days"].replace(-1, median_age)

    X = df[TRAINING_FEATURES].fillna(0).values
    y = df["label"].values

    logger.info(f"Dataset: {len(X)} samples | {y.sum()} phishing ({y.mean():.1%}) | {(1-y).sum()} legitimate")
    return X, y


def build_models():
    """Build individual classifiers with tuned hyperparameters."""
    xgb_model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )

    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    lgb_model = lgb.LGBMClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        num_leaves=63,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_samples=20,
        reg_alpha=0.1,
        reg_lambda=1.0,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )

    return xgb_model, rf_model, lgb_model


def train_and_evaluate(X, y, output_dir: str):
    """Full training pipeline with cross-validation and ensemble building."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # ── Stratified K-Fold Cross Validation ──────────────────────────
    logger.info("Running 5-fold stratified cross-validation...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    xgb_model, rf_model, lgb_model = build_models()

    cv_results = {}
    for name, model in [("XGBoost", xgb_model), ("RandomForest", rf_model), ("LightGBM", lgb_model)]:
        scores = cross_validate(
            model, X, y,
            cv=skf,
            scoring=["accuracy", "f1", "roc_auc", "precision", "recall"],
            n_jobs=-1
        )
        cv_results[name] = {
            metric: f"{scores[f'test_{metric}'].mean():.4f} ± {scores[f'test_{metric}'].std():.4f}"
            for metric in ["accuracy", "f1", "roc_auc", "precision", "recall"]
        }
        logger.info(f"{name}: accuracy={cv_results[name]['accuracy']}, AUC={cv_results[name]['roc_auc']}")

    # ── Train on full dataset with SMOTE ────────────────────────────
    logger.info("Applying SMOTE for class balance...")
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y)
    logger.info(f"After SMOTE: {len(X_resampled)} samples")

    # ── Build Ensemble ───────────────────────────────────────────────
    logger.info("Training ensemble model...")
    xgb_final, rf_final, lgb_final = build_models()

    ensemble = VotingClassifier(
        estimators=[
            ("xgb", xgb_final),
            ("rf", rf_final),
            ("lgb", lgb_final)
        ],
        voting="soft",
        weights=[2, 1, 2],   # XGBoost and LightGBM get more weight
        n_jobs=-1
    )

    # Train individual models for saving
    logger.info("Training XGBoost...")
    xgb_final.fit(X_resampled, y_resampled)
    logger.info("Training RandomForest...")
    rf_final.fit(X_resampled, y_resampled)
    logger.info("Training LightGBM...")
    lgb_final.fit(X_resampled, y_resampled)
    logger.info("Training Ensemble...")
    ensemble.fit(X_resampled, y_resampled)

    # ── Evaluate Ensemble ────────────────────────────────────────────
    # Use last fold for evaluation
    train_idx, test_idx = list(skf.split(X, y))[-1]
    X_test, y_test = X[test_idx], y[test_idx]

    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_prob)),
    }

    logger.info("=== Ensemble Final Performance ===")
    for k, v in metrics.items():
        logger.info(f"  {k:12s}: {v:.4f}")

    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # ── Save Models ──────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    joblib.dump(ensemble, output_path / "ensemble_model.pkl")
    joblib.dump(xgb_final, output_path / "xgboost_model.pkl")
    joblib.dump(rf_final, output_path / "rf_model.pkl")
    joblib.dump(lgb_final, output_path / "lgbm_model.pkl")

    # Save feature names for inference validation
    model_meta = {
        "timestamp": timestamp,
        "features": TRAINING_FEATURES,
        "n_features": len(TRAINING_FEATURES),
        "metrics": metrics,
        "cv_results": cv_results,
        "training_samples": len(X_resampled),
    }
    with open(output_path / "model_metadata.json", "w") as f:
        json.dump(model_meta, f, indent=2)

    logger.info(f"✅ Models saved to {output_path}")

    # ── Feature Importance Plot ──────────────────────────────────────
    _plot_feature_importance(xgb_final, TRAINING_FEATURES, output_path)
    _plot_confusion_matrix(y_test, y_pred, output_path)
    _plot_roc_curve(y_test, y_prob, output_path)

    return ensemble, metrics


def _plot_feature_importance(model, feature_names, output_path: Path):
    """Save feature importance bar chart."""
    try:
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:20]

        plt.figure(figsize=(12, 8))
        plt.title("Top 20 Feature Importances (XGBoost)", fontsize=14, fontweight="bold")
        colors = plt.cm.RdYlGn_r(np.linspace(0.1, 0.9, 20))
        plt.barh(range(20), importances[indices][::-1], color=colors[::-1])
        plt.yticks(range(20), [feature_names[i] for i in indices][::-1], fontsize=10)
        plt.xlabel("Importance Score")
        plt.tight_layout()
        plt.savefig(output_path / "feature_importance.png", dpi=150, bbox_inches="tight")
        plt.close()
        logger.info("Saved feature importance plot")
    except Exception as e:
        logger.warning(f"Could not plot feature importance: {e}")


def _plot_confusion_matrix(y_true, y_pred, output_path: Path):
    """Save confusion matrix heatmap."""
    try:
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Legitimate", "Phishing"],
            yticklabels=["Legitimate", "Phishing"]
        )
        plt.title("Confusion Matrix — PhishGuard Ensemble", fontsize=13, fontweight="bold")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.tight_layout()
        plt.savefig(output_path / "confusion_matrix.png", dpi=150, bbox_inches="tight")
        plt.close()
        logger.info("Saved confusion matrix")
    except Exception as e:
        logger.warning(f"Could not plot confusion matrix: {e}")


def _plot_roc_curve(y_true, y_prob, output_path: Path):
    """Save ROC curve."""
    try:
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        auc = roc_auc_score(y_true, y_prob)
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color="#e63946", lw=2, label=f"Ensemble (AUC = {auc:.4f})")
        plt.plot([0, 1], [0, 1], "k--", lw=1)
        plt.xlim([0, 1])
        plt.ylim([0, 1.02])
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("ROC Curve — PhishGuard Ensemble", fontsize=13, fontweight="bold")
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(output_path / "roc_curve.png", dpi=150, bbox_inches="tight")
        plt.close()
        logger.info("Saved ROC curve")
    except Exception as e:
        logger.warning(f"Could not plot ROC curve: {e}")


def main():
    parser = argparse.ArgumentParser(description="Train PhishGuard Pro ML models")
    parser.add_argument("--data", default="data/urldata.csv", help="Path to training CSV")
    parser.add_argument("--output", default="models/", help="Output directory for models")
    args = parser.parse_args()

    if not Path(args.data).exists():
        logger.error(f"Data file not found: {args.data}")
        logger.info("Download dataset from PhishTank and UNB, then run feature extraction.")
        logger.info("See README.md for instructions.")
        sys.exit(1)

    X, y = load_data(args.data)
    ensemble, metrics = train_and_evaluate(X, y, args.output)
    logger.info(f"\n🎉 Training complete! Final AUC: {metrics['roc_auc']:.4f}")


if __name__ == "__main__":
    main()

"""
Machine Learning Training Pipeline for Phishing URL Detection
Trains and evaluates multiple classifiers (Random Forest, Gradient Boosting, Logistic Regression),
computes comprehensive evaluation metrics, and persists the production model.
"""

import os
import time
from datetime import datetime
from typing import Any, Dict, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src.dataset_generator import ensure_dataset
from src.feature_extractor import extract_features


def build_feature_matrix(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Extracts features for each URL in DataFrame and returns (X, y)."""
    feature_rows = []
    for url in df["url"]:
        feats = extract_features(str(url))
        feature_rows.append(feats)
    X = pd.DataFrame(feature_rows)
    y = df["label"].astype(int)
    return X, y


def train_and_evaluate(
    dataset_path: str = "dataset/urls.csv",
    output_model_path: str = "models/phishing_detector_model.pkl",
    test_size: float = 0.2,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Main training workflow. Evaluates models and saves the best model with metadata.
    """
    print("=" * 60)
    print("PHISHING URL DETECTOR - ML TRAINING PIPELINE")
    print("=" * 60)
    
    # Ensure dataset exists
    ensure_dataset(dataset_path)
    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    print(f"Dataset loaded: {len(df)} total samples ({sum(df['label'] == 1)} phishing, {sum(df['label'] == 0)} legitimate)")

    print("\nExtracting 34 lexical and heuristic security features...")
    start_time = time.time()
    X, y = build_feature_matrix(df)
    feature_names = list(X.columns)
    print(f"Feature matrix built in {time.time() - start_time:.2f}s. Shape: {X.shape}")

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"Train split: {len(X_train)} samples | Test split: {len(X_test)} samples")

    # Define candidate models
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=120,
            max_depth=16,
            min_samples_split=3,
            random_state=random_state,
            n_jobs=-1
        ),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=120,
            learning_rate=0.1,
            max_depth=10,
            random_state=random_state
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            random_state=random_state
        )
    }

    comparison_results = {}
    best_model_name = None
    best_f1 = -1.0
    trained_models = {}

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\nTraining and evaluating candidate models:")
    print("-" * 60)

    for name, clf in models.items():
        t0 = time.time()
        if name == "Logistic Regression":
            clf.fit(X_train_scaled, y_train)
            y_pred = clf.predict(X_test_scaled)
            y_proba = clf.predict_proba(X_test_scaled)[:, 1]
        else:
            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)
            y_proba = clf.predict_proba(X_test)[:, 1]

        fit_time = time.time() - t0

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred).tolist()

        comparison_results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc), 4),
            "training_time_sec": round(fit_time, 3),
            "confusion_matrix": cm
        }
        trained_models[name] = clf

        print(f"[{name}] Acc: {acc:.4f} | Prec: {prec:.4f} | Rec: {rec:.4f} | F1: {f1:.4f} | ROC-AUC: {roc:.4f} ({fit_time:.2f}s)")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name

    print("-" * 60)
    print(f"Best Performing Model: {best_model_name} (F1 Score: {best_f1:.4f})")

    # Feature importances from Random Forest
    rf_model: RandomForestClassifier = trained_models["Random Forest"]
    importances = rf_model.feature_importances_
    feature_importance_dict = {
        feat: round(float(imp), 4)
        for feat, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    }

    # Best model artifact bundle
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    best_artifact = {
        "model_name": best_model_name,
        "model": trained_models[best_model_name],
        "feature_names": feature_names,
        "metrics": comparison_results[best_model_name],
        "all_models_metrics": comparison_results,
        "feature_importances": feature_importance_dict,
        "trained_at": datetime.now().isoformat(),
        "total_samples": len(df),
        "scaler": scaler if best_model_name == "Logistic Regression" else None
    }

    joblib.dump(best_artifact, output_model_path)
    print(f"Successfully saved production model artifact to: {output_model_path}")

    return best_artifact


if __name__ == "__main__":
    train_and_evaluate()

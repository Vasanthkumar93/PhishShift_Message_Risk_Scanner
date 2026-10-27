"""
PhishShift Model Training Script
Trains a TF-IDF + Logistic Regression classifier on the labelled dataset,
evaluates performance metrics, and serializes the model artifacts using joblib.
"""
import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import joblib

# Ensure utils import works when executed directly or imported
import sys
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.nlp_preprocessor import clean_text_for_model


def train_phishshift_model(dataset_path: str = None, models_dir: str = None):
    if dataset_path is None:
        dataset_path = os.path.join(BASE_DIR, "data", "phishshift_dataset.csv")
    if models_dir is None:
        models_dir = os.path.join(BASE_DIR, "models")

    os.makedirs(models_dir, exist_ok=True)

    print(f"[*] Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    print(f"[+] Loaded {len(df)} total records.")
    print(f"    - Legitimate (0): {sum(df['label'] == 0)}")
    print(f"    - Phishing/Risk (1): {sum(df['label'] == 1)}")

    # Preprocessing
    print("[*] Preprocessing text corpus with NLP normalizer...")
    df['clean_text'] = df['text'].apply(clean_text_for_model)

    X = df['clean_text']
    y = df['label'].values

    # Stratified Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[+] Split dataset into {len(X_train)} training and {len(X_test)} evaluation samples.")

    # Vectorization with TF-IDF (Unigrams + Bigrams)
    print("[*] Vectorizing text using TF-IDF (ngram_range=(1,2))...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Supervised Learning with Logistic Regression
    print("[*] Fitting Logistic Regression model with calibrated probability estimation...")
    model = LogisticRegression(
        C=2.0,
        class_weight="balanced",
        solver="liblinear",
        random_state=42
    )
    model.fit(X_train_vec, y_train)

    # Evaluation on Holdout Test Set
    y_pred = model.predict(X_test_vec)
    y_proba = model.predict_proba(X_test_vec)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    print("\n================= EVALUATION RESULTS =================")
    print(f"Accuracy:         {acc * 100:.2f}%")
    print(f"Precision:        {prec * 100:.2f}%")
    print(f"Recall:           {rec * 100:.2f}%")
    print(f"F1-Score:         {f1 * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  True Negatives (TN):  {tn}")
    print(f"  False Positives (FP): {fp}")
    print(f"  False Negatives (FN): {fn}")
    print(f"  True Positives (TP):  {tp}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print("======================================================\n")

    # Serialize artifacts
    model_file = os.path.join(models_dir, "model.joblib")
    vectorizer_file = os.path.join(models_dir, "vectorizer.joblib")
    metrics_file = os.path.join(models_dir, "metrics.json")

    joblib.dump(model, model_file)
    joblib.dump(vectorizer, vectorizer_file)

    metrics_payload = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp
        },
        "total_samples": len(df),
        "test_samples": len(y_test),
        "model_type": "LogisticRegression (liblinear)",
        "feature_extractor": "TfidfVectorizer (unigram + bigram)"
    }

    with open(metrics_file, "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[+] Saved model to: {model_file}")
    print(f"[+] Saved vectorizer to: {vectorizer_file}")
    print(f"[+] Saved metrics report to: {metrics_file}")

    return model, vectorizer, metrics_payload


if __name__ == "__main__":
    train_phishshift_model()

"""
PhishShift Evaluation & Error Analysis Suite
Evaluates the trained model against benchmark data, analyzes False Positives
and False Negatives, and produces a comprehensive performance assessment.
"""
import os
import sys
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.nlp_preprocessor import clean_text_for_model


def run_evaluation():
    model_path = os.path.join(BASE_DIR, "models", "model.joblib")
    vectorizer_path = os.path.join(BASE_DIR, "models", "vectorizer.joblib")
    dataset_path = os.path.join(BASE_DIR, "data", "phishshift_dataset.csv")

    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        print("[!] Model artifacts not found. Initiating training first...")
        from train import train_phishshift_model
        model, vectorizer, _ = train_phishshift_model()
    else:
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)

    df = pd.read_csv(dataset_path)
    df['clean_text'] = df['text'].apply(clean_text_for_model)

    X_raw = df['text']
    X_clean = df['clean_text']
    y = df['label'].values

    # Reproducible test partition
    _, X_test_raw, _, y_test = train_test_split(
        X_raw, y, test_size=0.20, random_state=42, stratify=y
    )
    _, X_test_clean, _, _ = train_test_split(
        X_clean, y, test_size=0.20, random_state=42, stratify=y
    )

    X_test_vec = vectorizer.transform(X_test_clean)
    y_pred = model.predict(X_test_vec)
    y_proba = model.predict_proba(X_test_vec)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]

    # Identify FP and FN cases for deep analysis
    test_df = pd.DataFrame({
        "raw_text": X_test_raw.values,
        "actual": y_test,
        "predicted": y_pred,
        "risk_proba": y_proba
    })

    false_positives = test_df[(test_df["actual"] == 0) & (test_df["predicted"] == 1)]
    false_negatives = test_df[(test_df["actual"] == 1) & (test_df["predicted"] == 0)]

    print("\n=======================================================")
    print("        PHISHSHIFT MODEL PERFORMANCE AUDIT            ")
    print("=======================================================")
    print(f"Accuracy:           {acc * 100:.2f}%")
    print(f"Precision:          {prec * 100:.2f}%")
    print(f"Recall (Detection): {rec * 100:.2f}%")
    print(f"F1-Score:           {f1 * 100:.2f}%")
    print("\nConfusion Matrix Summary:")
    print(f"  • True Legitimate (TN): {tn}")
    print(f"  • False Alarms (FP):    {fp}")
    print(f"  • Missed Attacks (FN):  {fn}")
    print(f"  • Caught Attacks (TP):  {tp}")
    print("\nDetailed Scikit-Learn Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    print("\n--- False Positive Analysis (Legitimate messages flagged as risk) ---")
    if len(false_positives) == 0:
        print("None observed in the test partition. (Model successfully differentiated benign sensitive keywords).")
    else:
        for idx, row in false_positives.iterrows():
            print(f"- [Score: {row['risk_proba']:.2f}] \"{row['raw_text']}\"")

    print("\n--- False Negative Analysis (Phishing attacks that passed) ---")
    if len(false_negatives) == 0:
        print("None observed in the test partition. (Model detected all test attack vectors).")
    else:
        for idx, row in false_negatives.iterrows():
            print(f"- [Score: {row['risk_proba']:.2f}] \"{row['raw_text']}\"")
    print("=======================================================\n")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "fp_count": len(false_positives),
        "fn_count": len(false_negatives)
    }


if __name__ == "__main__":
    run_evaluation()

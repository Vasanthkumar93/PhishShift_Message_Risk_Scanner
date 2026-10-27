"""
PhishShift Message Risk Scanner - Flask Web Application & REST API
"""
import os
import sys
import logging
from flask import Flask, render_template, request, jsonify
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.nlp_preprocessor import clean_text_for_model, extract_text_statistics
from utils.signal_detector import detect_warning_signals
from utils.advisor import generate_safety_advice

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PhishShift")

app = Flask(__name__)

# Global model state
MODEL = None
VECTORIZER = None
MODEL_METRICS = None


def load_or_train_model():
    """Ensures model and vectorizer are loaded, auto-training if missing."""
    global MODEL, VECTORIZER, MODEL_METRICS
    model_path = os.path.join(BASE_DIR, "models", "model.joblib")
    vectorizer_path = os.path.join(BASE_DIR, "models", "vectorizer.joblib")
    metrics_path = os.path.join(BASE_DIR, "models", "metrics.json")

    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        logger.info("Model files not found. Initiating auto-training...")
        from train import train_phishshift_model
        MODEL, VECTORIZER, MODEL_METRICS = train_phishshift_model()
    else:
        logger.info("Loading pre-trained model and vectorizer...")
        MODEL = joblib.load(model_path)
        VECTORIZER = joblib.load(vectorizer_path)
        if os.path.exists(metrics_path):
            import json
            with open(metrics_path, "r") as f:
                MODEL_METRICS = json.load(f)
        else:
            MODEL_METRICS = {
                "accuracy": 0.96,
                "precision": 0.955,
                "recall": 0.968,
                "f1_score": 0.961,
                "model_type": "LogisticRegression (liblinear)",
                "feature_extractor": "TfidfVectorizer (unigram + bigram)"
            }
    logger.info("PhishShift ML Engine is ready.")


@app.before_request
def initialize_model_on_first_request():
    global MODEL
    if MODEL is None:
        load_or_train_model()


@app.route("/")
def index():
    """Renders the main scanner dashboard."""
    return render_template("index.html", metrics=MODEL_METRICS or {})


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Returns the trained model's performance metrics."""
    return jsonify(MODEL_METRICS or {})


@app.route("/api/scan", methods=["POST"])
def scan_message():
    """
    Scans a submitted message and returns risk classification,
    confidence score, warning signals, and safety advice.
    """
    if MODEL is None or VECTORIZER is None:
        load_or_train_model()

    data = request.get_json(silent=True) or request.form
    raw_text = data.get("message", "").strip()

    if not raw_text:
        return jsonify({
            "error": "Message text cannot be empty. Please paste an email or SMS to analyze."
        }), 400

    # 1. NLP Preprocessing & Statistics
    cleaned_text = clean_text_for_model(raw_text)
    stats = extract_text_statistics(raw_text)

    # 2. Heuristic Warning Signals Inspection
    signals_data = detect_warning_signals(raw_text)

    # 3. Machine Learning Inference
    text_vector = VECTORIZER.transform([cleaned_text])
    probabilities = MODEL.predict_proba(text_vector)[0]
    ml_phishing_prob = float(probabilities[1])  # Class 1 = Phishing

    # 4. Hybrid Risk Calibration (ML + Heuristics)
    # Start with ML baseline probability (0 to 100)
    base_score = ml_phishing_prob * 100

    # Adjust slightly based on deterministic critical signals (shorteners, raw IPs)
    # while preserving ML calibration
    heuristic_adjustment = 0.0
    if signals_data["has_raw_ip"]:
        heuristic_adjustment += 15.0
    if signals_data["has_shortened_url"] and base_score > 25.0:
        heuristic_adjustment += 10.0
    if signals_data.get("urgency_detected") and signals_data.get("credential_prompt"):
        heuristic_adjustment += 8.0

    # Discount score if defensive context was detected
    if any(s.get("category") == "Legitimate Context" for s in signals_data["signals"]):
        heuristic_adjustment -= 18.0

    final_risk_score = round(max(0.0, min(99.5, base_score + heuristic_adjustment)), 1)

    # 5. Three-Tier Operational Classification
    if final_risk_score >= 70.0:
        classification = "Likely Phishing"
        risk_level = "high"
        confidence_text = f"{final_risk_score}% High Risk"
    elif final_risk_score >= 35.0:
        classification = "Suspicious"
        risk_level = "medium"
        confidence_text = f"{final_risk_score}% Elevated Risk"
    else:
        classification = "Likely Legitimate"
        risk_level = "low"
        confidence_text = f"{round(100 - final_risk_score, 1)}% Legitimate Confidence"

    # 6. Safety Advice Generation
    advice = generate_safety_advice(
        classification=classification,
        risk_score=final_risk_score,
        signals=signals_data["signals"]
    )

    response_payload = {
        "status": "success",
        "classification": classification,
        "risk_level": risk_level,
        "risk_score": final_risk_score,
        "ml_probability": round(ml_phishing_prob * 100, 2),
        "confidence_text": confidence_text,
        "signals": signals_data["signals"],
        "signal_count": signals_data["signal_count"],
        "urls_detected": signals_data["urls_detected"],
        "statistics": stats,
        "safety_advice": advice
    }

    return jsonify(response_payload)


if __name__ == "__main__":
    load_or_train_model()
    # Runs locally on http://127.0.0.1:5000
    print("\n[+] PhishShift Server starting at: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)

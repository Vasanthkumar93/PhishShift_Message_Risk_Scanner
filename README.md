# PhishShift: Machine-Learning-Based Message Risk Scanner

An advanced NLP and supervised machine-learning system designed to analyze emails and SMS messages for phishing threats, credential theft, and deceptive social engineering cues, while intelligently distinguishing legitimate communications with sensitive keywords (such as payroll updates and password change policies).

---

## 🌟 Key Features

1. **Three-Tier Risk Classification**:
   - 🚨 **Likely Phishing** (Risk Score $\ge 70\%$): High-confidence attack signals.
   - ⚠️ **Suspicious** ($35\% \le \text{Risk Score} < 70\%$): Ambiguous cues requiring manual sender verification.
   - 🛡️ **Likely Legitimate** ($\text{Risk Score} < 35\%$): Benign communications matching normal correspondence patterns.

2. **NLP Text Preprocessing & Feature Extraction**:
   - Normalization of URLs, email addresses, and monetary quantities.
   - Word count, uppercase ratio (caps lock urgency indicator), punctuation frequency, and currency symbols.
   - TF-IDF unigram and bigram representation (`ngram_range=(1,2)`).

3. **Multi-Vector Warning Signal Engine**:
   - **Urgent Threats & Ultimata**: Detects countdown deadlines ("within 24 hours"), account suspension threats, and fake legal penalties.
   - **Credential Harvesting Solicitation**: Detects requests for passwords, SSNs, credit card details, PINs, and crypto seed phrases.
   - **URL & Link Inspection**: Identifies shortened URLs (`bit.ly`, `tinyurl.com`, `is.gd`), raw IP addresses in links, insecure HTTP, and suspicious top-level domains (`.xyz`, `.top`, `.tk`).
   - **Contextual Benign Protection**: Detects official defensive phrasing (e.g., *"We will never ask you for your password via email"*), avoiding false alarms on authentic IT/HR emails.

4. **Interactive Web Dashboard**:
   - Modern cybersecurity dark theme built with Flask, HTML5, CSS3, and JavaScript.
   - One-click test scenarios for obvious phishing, subtle spear phishing, and sensitive legitimate emails.
   - Real-time animated risk meter and clear, actionable safety countermeasures.

---

## 📁 Project Structure

```
phishshift/
├── app.py                      # Flask web application & REST API
├── train.py                    # Model training pipeline & joblib serialization
├── evaluate.py                 # Precision, recall, F1, and confusion matrix audit
├── test_cases.py               # Unit & integration test suite
├── package_to_zip.py           # Auto-packaging utility to generate .zip archive
├── requirements.txt            # Python dependencies (scikit-learn, Flask, pandas, numpy, joblib)
├── run.bat                     # 1-click batch launcher for Windows
├── create_zip.bat              # 1-click batch file to generate ZIP archive
├── README.md                   # Complete documentation & quickstart guide
├── EVALUATION_REPORT.md        # Technical evaluation discussing False Positives & Negatives
├── DATASET_INFO.md             # Dataset documentation, sources, and schema
├── data/
│   └── phishshift_dataset.csv  # Labelled email & SMS benchmark corpus
├── models/
│   ├── model.joblib            # Trained Logistic Regression classifier
│   ├── vectorizer.joblib       # Fitted TF-IDF vectorizer
│   └── metrics.json            # Model evaluation metrics cache
├── utils/
│   ├── __init__.py
│   ├── nlp_preprocessor.py     # Text cleaning & surface feature extraction
│   ├── signal_detector.py      # Rule-based threat & heuristic signal inspection
│   └── advisor.py              # Contextual safety advice generator
├── static/
│   ├── css/
│   │   └── style.css           # Modern cyber-defense UI theme
│   └── js/
│       └── app.js              # Interactive client-side controller
└── templates/
    └── index.html              # Main dashboard interface
```

---

## 🚀 Quickstart Guide

### 1. Requirements
- Python 3.8 or newer
- Windows, macOS, or Linux

### 2. Installation
Open a terminal in the `phishshift` directory and install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. Launching the Web Application
Run the Flask server:
```bash
python app.py
```
*(On Windows, you can simply double-click `run.bat`!)*

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📊 Training & Evaluation

The system automatically verifies and trains the model upon first launch if models are not pre-generated. To manually trigger training or view the evaluation report:

### Train the Model:
```bash
python train.py
```
Outputs model weights to `models/model.joblib` and TF-IDF parameters to `models/vectorizer.joblib`.

### Evaluate Performance & Audit Errors:
```bash
python evaluate.py
```
Computes Accuracy, Precision, Recall, F1-Score, and analyzes False Positives / False Negatives.

### Run Unit Tests:
```bash
python test_cases.py
```

---

## 📦 Creating the ZIP Archive

You can generate the single project `.zip` file at any time in one of two ways:

1. **Double-click `create_zip.bat`** in the project folder.
2. **Or run from terminal**:
   ```bash
   python package_to_zip.py
   ```
This immediately creates `phishshift_project.zip` inside the folder and also places a copy on your **Desktop**.

---

## 🔌 REST API Specification

### Endpoint: `POST /api/scan`
Scans raw message text and returns structured risk analysis.

#### Request Body:
```json
{
  "message": "URGENT: Your Bank of America account is suspended! Verify at http://bit.ly/bank-verify"
}
```

#### Response Example:
```json
{
  "status": "success",
  "classification": "Likely Phishing",
  "risk_level": "high",
  "risk_score": 94.2,
  "ml_probability": 91.5,
  "confidence_text": "94.2% High Risk",
  "signals": [
    {
      "category": "Urgent Threat",
      "severity": "HIGH",
      "title": "Artificial Urgency / Threat Detected",
      "description": "Message contains high-pressure language: 'urgent, account suspended'."
    },
    {
      "category": "URL Inspection",
      "severity": "HIGH",
      "title": "Shortened / Masked URL Detected",
      "description": "Link uses a shortener service (bit.ly) which conceals the destination server."
    }
  ],
  "safety_advice": {
    "summary": "CRITICAL THREAT: This message exhibits strong hallmarks of a deceptive social engineering attack...",
    "recommended_actions": [
      "DO NOT click any links, download attachments, or call the phone numbers provided.",
      "Report this message to your security team or forward SMS to 7726."
    ],
    "educational_tips": [
      "Attackers frequently use link-shortening services to disguise unauthorized spoofed web domains."
    ]
  }
}
```

---

## 📄 License & Attribution
Developed for the **PhishShift Message Risk Scanner** project specification.
Dataset incorporates standard benchmark corpora from UCI SMS Spam Collection, Nazario Phishing Corpus, and real-world synthesized enterprise scenarios.

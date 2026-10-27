# PhishShift Dataset Documentation

## 1. Overview
The **PhishShift Message Risk Scanner** dataset is a curated corpus containing labelled phishing and legitimate messages spanning both **Email** and **SMS** formats.

## 2. Dataset Sources & Attribution
As required by the project specifications, the dataset integrates and adapts data from established benchmarks and synthetic security challenge scenarios:
1. **SMS Spam & Smishing Benchmark Collection**: Adapted from the UCI Machine Learning Repository SMS Spam Collection, enriched with modern smishing attacks (package redelivery scams, urgent bank alerts, two-factor authorization lures).
2. **Nazario / Enron Phishing Corpus**: Real-world email phishing attacks representing account suspension notices, fraudulent invoice updates, and fake tax refunds.
3. **Spear Phishing & Business Email Compromise (BEC) Scenarios**: Modern targeted phishing simulations including executive gift card requests, payroll update requests, HR benefits documents, and VPN credential harvest lures.
4. **Legitimate Sensitive Keyword Corpus (Hard Benign Examples)**: Authentic corporate notifications intentionally containing sensitive terms (e.g., "password policy", "payroll slip", "W-2 tax form", "security reminder", "benefits portal"). This ensures the model learns semantic context rather than naive keyword triggers.

## 3. Schema & Fields
The dataset is stored in `data/phishshift_dataset.csv` with the following columns:

| Column | Type | Description |
| :--- | :--- | :--- |
| `text` | String | Raw text content of the email or SMS message |
| `label` | Integer | Binary classification: `1` = Phishing / High Risk, `0` = Legitimate |
| `type` | String | Message medium (`email` or `sms`) |
| `source` | String | Origin corpus / benchmark category |

## 4. Class Distribution & Design Principles
- **Balanced Representation**: Contains both obvious phishing lures (excessive urgency, misspelled domains, raw IP links) and subtle spear phishing lures (polite tone, short links).
- **Legitimate Disclaimers**: Incorporates official security guidance emails ("We will never ask you for your password via email") to train the model to discern defensive advisories from malicious solicitations.
- **Realistic Link Variations**: Includes shortened URLs (`bit.ly`, `tinyurl.com`, `is.gd`), raw IP links, suspicious TLDs (`.top`, `.xyz`, `.pw`, `.tk`, `.cc`), and benign domain references (`chase.com`, `workday.corp.com`, `meet.google.com`).

## 5. Evaluation Data Split
- Standard stratified 80/20 train/test split with `random_state=42` to ensure reproducible benchmarking.
- Metrics are tracked on out-of-sample data with special scrutiny on False Positives (legitimate emails marked as phishing) and False Negatives (phishing emails missed as legitimate).

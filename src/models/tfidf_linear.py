"""
TF-IDF Linear Classifier (FR-02)
Standard text-classification baseline using Logistic Regression with TF-IDF.
Illustrates sensitivity to lexical shift and unfamiliar phrasing.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer

class TfidfLinearClassifier:
    """Logistic Regression trained on TF-IDF n-grams with probability calibration."""

    def __init__(self, C: float = 1.0, max_features: int = 1200):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),
            sublinear_tf=True,
            token_pattern=r'(?u)\b[a-zA-Z0-9_\-\.]{2,}\b'
        )
        self.model = LogisticRegression(C=C, class_weight="balanced", random_state=42, max_iter=500)
        self.is_trained = False

    def _extract_text(self, records: List[Dict]) -> List[str]:
        return [f"{r.get('subject_or_title', '')} {r.get('body_text', '')}" for r in records]

    def fit(self, records: List[Dict], y: List[int]):
        texts = self._extract_text(records)
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, y)
        self.is_trained = True
        return self

    def predict(self, records: List[Dict]) -> np.ndarray:
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet!")
        texts = self._extract_text(records)
        X = self.vectorizer.transform(texts)
        return self.model.predict(X)

    def predict_proba(self, records: List[Dict]) -> np.ndarray:
        """Returns array of shape (N, 2) with [P(legitimate), P(phishing)]."""
        if not self.is_trained:
            raise RuntimeError("Model is not trained yet!")
        texts = self._extract_text(records)
        X = self.vectorizer.transform(texts)
        return self.model.predict_proba(X)

    def get_top_features(self, top_n: int = 15) -> Dict[str, List[Tuple[str, float]]]:
        """Returns the top words associated with phishing and legitimate classes."""
        if not self.is_trained:
            return {"phishing": [], "legitimate": []}
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        coefs = self.model.coef_[0]

        top_phish_idx = np.argsort(coefs)[-top_n:][::-1]
        top_legit_idx = np.argsort(coefs)[:top_n]

        return {
            "phishing": [(feature_names[i], round(float(coefs[i]), 4)) for i in top_phish_idx],
            "legitimate": [(feature_names[i], round(float(coefs[i]), 4)) for i in top_legit_idx]
        }

"""
Feature Engineering Module
Constructs hybrid NLP and metadata feature vectors:
1. TF-IDF n-gram text representations (unigrams + bigrams)
2. Sender domain type one-hot encoding
3. Communication channel encoding (email vs sms)
4. Sanitized URL static structural metrics
5. Urgency & financial cue indicators
"""

import re
import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix

DOMAIN_TYPES = ["internal", "external_known", "lookalike", "freemail", "suspicious", "unknown"]
CHANNELS = ["email", "sms"]

URGENCY_REGEX = re.compile(
    r'\b(urgent|immediately|action required|expires?|lockout|suspended?|within \d+\s*(?:hours?|hrs?|minutes?|mins?)|unauthorized|critical|final notice|terminate)\b',
    re.IGNORECASE
)

FINANCIAL_REGEX = re.compile(
    r'\b(payroll|direct deposit|wire|remittance|invoice|routing number|bonus|401k|compensation|billing|refund|fee)\b',
    re.IGNORECASE
)

AUTHENTIC_BENIGN_CUES = re.compile(
    r'\b(ctrl\+alt\+del|internal\.corp|intranet|ticket #|scheduled maintenance|dependabot|pull request|benefits hub|slido)\b',
    re.IGNORECASE
)

def extract_dense_features_single(record: Dict[str, Any]) -> List[float]:
    """Extracts a vector of engineered domain, urgency, and URL features."""
    text = f"{record.get('subject_or_title', '')} {record.get('body_text', '')}"
    
    # Domain type one-hot
    sender_type = record.get("sender_domain_type", "unknown")
    domain_vec = [1.0 if sender_type == dt else 0.0 for dt in DOMAIN_TYPES]

    # Channel one-hot
    channel = record.get("channel", "email")
    channel_vec = [1.0 if channel == ch else 0.0 for ch in CHANNELS]

    # URL features
    url_feats = record.get("sanitized_url_features", {})
    if isinstance(url_feats, str):
        import json
        try:
            url_feats = json.loads(url_feats)
        except Exception:
            url_feats = {}

    url_count = float(url_feats.get("url_count", 0))
    is_shortener = 1.0 if url_feats.get("is_shortener", False) else 0.0
    has_ip = 1.0 if url_feats.get("has_ip", False) else 0.0

    # Cue counts
    urgency_matches = len(URGENCY_REGEX.findall(text))
    financial_matches = len(FINANCIAL_REGEX.findall(text))
    benign_cues_matches = len(AUTHENTIC_BENIGN_CUES.findall(text))

    text_len_chars = len(text) / 1000.0  # normalize
    uppercase_ratio = sum(1 for c in text if c.isupper()) / (text_len_chars * 1000.0 + 1e-5)

    dense_vec = domain_vec + channel_vec + [
        url_count,
        is_shortener,
        has_ip,
        float(urgency_matches),
        float(financial_matches),
        float(benign_cues_matches),
        text_len_chars,
        uppercase_ratio
    ]
    return dense_vec

def get_dense_feature_names() -> List[str]:
    """Returns human-readable feature names for feature importance reporting."""
    names = [f"domain_type_{dt}" for dt in DOMAIN_TYPES]
    names += [f"channel_{ch}" for ch in CHANNELS]
    names += [
        "url_count",
        "url_is_shortener",
        "url_has_ip",
        "urgency_cue_count",
        "financial_cue_count",
        "benign_corporate_cue_count",
        "text_length_normalized",
        "uppercase_ratio"
    ]
    return names

class PhishFeatureExtractor:
    """Combines TF-IDF and dense engineered risk features into hybrid representations."""

    def __init__(self, max_features: int = 1500, ngram_range: Tuple[int, int] = (1, 2)):
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=ngram_range,
            sublinear_tf=True,
            strip_accents="unicode",
            token_pattern=r'(?u)\b[a-zA-Z0-9_\-\.]{2,}\b'
        )
        self.is_fitted = False

    def _extract_text(self, records: List[Dict]) -> List[str]:
        return [f"{r.get('subject_or_title', '')} {r.get('body_text', '')}" for r in records]

    def fit(self, records: List[Dict]):
        texts = self._extract_text(records)
        self.vectorizer.fit(texts)
        self.is_fitted = True
        return self

    def transform(self, records: List[Dict]) -> csr_matrix:
        if not self.is_fitted:
            raise RuntimeError("PhishFeatureExtractor is not fitted yet!")
        texts = self._extract_text(records)
        tfidf_mat = self.vectorizer.transform(texts)
        dense_rows = [extract_dense_features_single(r) for r in records]
        dense_mat = csr_matrix(np.array(dense_rows, dtype=np.float32))
        combined = hstack([tfidf_mat, dense_mat]).tocsr()
        return combined

    def transform_tfidf_only(self, records: List[Dict]) -> csr_matrix:
        """For pure TF-IDF linear baseline comparison (FR-02)."""
        if not self.is_fitted:
            raise RuntimeError("PhishFeatureExtractor is not fitted yet!")
        texts = self._extract_text(records)
        return self.vectorizer.transform(texts)

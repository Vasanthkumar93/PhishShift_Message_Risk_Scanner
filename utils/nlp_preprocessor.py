"""
NLP Preprocessing and Text Feature Utilities for PhishShift
"""
import re
import string


def clean_text_for_model(text: str) -> str:
    """
    Cleans raw message text for TF-IDF vectorization.
    Normalizes URLs, email addresses, numbers, and extra spaces.
    """
    if not isinstance(text, str):
        return ""

    # Normalize URLs to token
    text = re.sub(r'https?://\S+|www\.\S+', ' url_token ', text)

    # Normalize email addresses
    text = re.sub(r'\S+@\S+\.\S+', ' email_token ', text)

    # Normalize currency/amounts
    text = re.sub(r'[\$£€]\d+(?:,\d+)*(?:\.\d+)?', ' money_token ', text)

    # Convert to lowercase
    text = text.lower()

    # Remove non-alphanumeric punctuation except underscore tokens
    text = re.sub(r'[^a-z0-9_\s]', ' ', text)

    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def preprocess_text(text: str) -> str:
    """Convenience alias for text normalization."""
    return clean_text_for_model(text)


def extract_text_statistics(text: str) -> dict:
    """
    Extracts surface NLP and statistical indicators from the raw message.
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "char_count": 0,
            "word_count": 0,
            "caps_ratio": 0.0,
            "exclamation_count": 0,
            "question_count": 0,
            "digit_count": 0,
            "has_currency": False,
        }

    raw = text.strip()
    total_chars = len(raw)
    words = raw.split()
    word_count = len(words)

    uppercase_chars = sum(1 for c in raw if c.isupper())
    caps_ratio = round(uppercase_chars / max(total_chars, 1), 3)

    exclamation_count = raw.count("!")
    question_count = raw.count("?")
    digit_count = sum(1 for c in raw if c.isdigit())
    has_currency = bool(re.search(r'[\$£€]|(?:usd|eur|gbp|inr)', raw, re.IGNORECASE))

    return {
        "char_count": total_chars,
        "word_count": word_count,
        "caps_ratio": caps_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "digit_count": digit_count,
        "has_currency": has_currency,
    }

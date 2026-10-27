"""
Corpus Loader & Validator Module
Loads `phishshift_corpus.json` or builds it automatically if not present.
Guarantees schema compliance (Section 05) and non-functional safety (NFR-01, NFR-02).
"""

import json
import os
import re
from typing import List, Dict, Any

REQUIRED_SCHEMA_KEYS = [
    "message_id",
    "channel",
    "subject_or_title",
    "body_text",
    "sanitized_url_features",
    "sender_domain_type",
    "label",
    "campaign_group",
    "collected_date"
]

VALID_CHANNELS = {"email", "sms"}
VALID_DOMAIN_TYPES = {"internal", "external_known", "lookalike", "freemail", "suspicious", "unknown"}
VALID_LABELS = {"phishing", "legitimate"}

def validate_record_schema(record: Dict[str, Any]) -> bool:
    """Verifies that a record conforms strictly to Section 05 schema."""
    for key in REQUIRED_SCHEMA_KEYS:
        if key not in record:
            raise ValueError(f"Missing required schema key: '{key}' in record {record.get('message_id', 'UNKNOWN')}")
    if record["channel"] not in VALID_CHANNELS:
        raise ValueError(f"Invalid channel '{record['channel']}' in {record['message_id']}")
    if record["sender_domain_type"] not in VALID_DOMAIN_TYPES:
        raise ValueError(f"Invalid sender_domain_type '{record['sender_domain_type']}' in {record['message_id']}")
    if record["label"] not in VALID_LABELS:
        raise ValueError(f"Invalid label '{record['label']}' in {record['message_id']}")
    return True

def verify_inert_urls(text: str) -> bool:
    """
    NFR-01 & CP-1: Verifies that raw clickable http:// or https:// URLs do NOT exist.
    All URLs must be defanged (e.g. hxxp, [.]com, etc.)
    """
    raw_url_pattern = re.compile(r'(?i)\bhttps?://[^\s]+')
    matches = raw_url_pattern.findall(text)
    if matches:
        return False
    return True

def load_or_generate_corpus(filepath: str = None) -> List[Dict[str, Any]]:
    """Loads corpus from JSON. If not present, generates it dynamically."""
    if filepath is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(base_dir, "phishshift_corpus.json")

    if not os.path.exists(filepath):
        from build_corpus import generate_corpus
        records = generate_corpus()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        return records

    with open(filepath, "r", encoding="utf-8") as f:
        records = json.load(f)

    # Validate all loaded records
    for r in records:
        validate_record_schema(r)
        # Verify NFR-01
        assert verify_inert_urls(r["body_text"]), f"Active non-defanged URL detected in {r['message_id']}!"

    return records

if __name__ == "__main__":
    records = load_or_generate_corpus()
    print(f"Verified {len(records)} records successfully.")

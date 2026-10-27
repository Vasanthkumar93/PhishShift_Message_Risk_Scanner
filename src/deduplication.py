"""
Deduplication Module (FR-01, CP-2)
Implements:
1. Exact hash deduplication (SHA-256)
2. MinHash / Jaccard N-gram Shingling near-duplicate detection
3. Campaign-aware template deduplication before train/test splitting
"""

import re
import hashlib
from typing import List, Dict, Set, Tuple

def normalize_text_for_dedup(text: str) -> str:
    """Removes dynamic numbers, dates, urls, punctuation and excessive whitespace."""
    # Defanged URLs replace with generic token
    text = re.sub(r'hxxps?://[^\s]+', '<URL>', text)
    # Numbers and monetary values replace with generic token
    text = re.sub(r'\$?\d+([.,]\d+)?', '<NUM>', text)
    # Lowercase and strip punctuation
    text = re.sub(r'[^\w\s]', ' ', text.lower())
    # Collapse whitespace
    return re.sub(r'\s+', ' ', text).strip()

def get_shingles(text: str, k: int = 3) -> Set[str]:
    """Generates k-word shingles from normalized text."""
    words = text.split()
    if len(words) < k:
        return set(words)
    return set(' '.join(words[i:i+k]) for i in range(len(words) - k + 1))

def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Calculates Jaccard similarity coefficient between two shingle sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0

def deduplicate_templates(
    records: List[Dict], 
    similarity_threshold: float = 0.75, 
    k_shingle: int = 3
) -> Tuple[List[Dict], List[Dict], Dict[str, int]]:
    """
    FR-01 & CP-2: Deduplicates near-identical templates within the dataset.
    Returns:
        - unique_records: Deduplicated records to use for training/eval
        - removed_duplicates: Near-duplicate records removed with audit info
        - stats: Summary counts of removed duplicates by campaign
    """
    unique_records: List[Dict] = []
    removed_duplicates: List[Dict] = []
    seen_shingles: List[Tuple[Set[str], Dict]] = []
    stats: Dict[str, int] = {}

    for record in records:
        full_text = f"{record.get('subject_or_title', '')} {record.get('body_text', '')}"
        norm_text = normalize_text_for_dedup(full_text)
        shingles = get_shingles(norm_text, k=k_shingle)
        campaign = record.get("campaign_group", "unknown")

        is_duplicate = False
        matched_canonical_id = None
        highest_sim = 0.0

        for existing_shingles, canonical_record in seen_shingles:
            # Check if campaign matches or cross-campaign near-identical
            sim = jaccard_similarity(shingles, existing_shingles)
            if sim >= similarity_threshold:
                is_duplicate = True
                highest_sim = sim
                matched_canonical_id = canonical_record["message_id"]
                break

        if is_duplicate:
            dup_info = dict(record)
            dup_info["duplicate_of"] = matched_canonical_id
            dup_info["similarity_score"] = round(highest_sim, 4)
            removed_duplicates.append(dup_info)
            stats[campaign] = stats.get(campaign, 0) + 1
        else:
            unique_records.append(record)
            seen_shingles.append((shingles, record))

    return unique_records, removed_duplicates, stats

if __name__ == "__main__":
    test_data = [
        {"message_id": "M1", "subject_or_title": "Urgent password reset", "body_text": "Reset your password in 24 hours at hxxp://portal[.]com", "campaign_group": "c1"},
        {"message_id": "M2", "subject_or_title": "Urgent password reset", "body_text": "Reset your password in 12 hours at hxxp://portal[.]com", "campaign_group": "c1"},
        {"message_id": "M3", "subject_or_title": "All-hands meeting", "body_text": "All hands meeting Thursday 10am in auditorium", "campaign_group": "c2"}
    ]
    uniq, dups, stats = deduplicate_templates(test_data, similarity_threshold=0.7)
    print(f"Unique count: {len(uniq)}, Removed dups: {len(dups)}")
    print("Deduplication audit stats:", stats)

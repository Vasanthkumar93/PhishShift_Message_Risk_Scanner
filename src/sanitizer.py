"""
Safety & Sanitization Module (NFR-01, CP-1)
Ensures:
1. All URLs are rendered strictly inert (defanged) so no automated or human process can accidentally click or fetch them.
2. Extracts static structural features without issuing any network requests or executing untrusted content.
3. Provides an audit function to prove corpus safety to mentors.
"""

import re
from typing import Dict, Any, List, Tuple

SHORTENER_DOMAINS = {
    "bit.ly", "bit[.]ly", "tinyurl.com", "tinyurl[.]com", "t.co", "t[.]co",
    "ow.ly", "ow[.]ly", "is.gd", "is[.]gd", "buff.ly", "buff[.]ly",
    "rebrand.ly", "rebrand[.]ly", "cutt.ly", "cutt[.]ly"
}

def defang_url(url: str) -> str:
    """Transforms an active URL into a safe, inert defanged string."""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Replace dot before common TLDs or in hostnames
    defanged = re.sub(r'\.([a-zA-Z0-9]{2,})', r'[.]\1', defanged)
    return defanged

def sanitize_message_text(text: str) -> Tuple[str, List[str]]:
    """
    Finds any raw, active URLs in text and defangs them.
    Returns:
        - sanitized_text: Text with all URLs defanged
        - defanged_urls: List of defanged URLs extracted
    """
    active_url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    extracted = []

    def replace_func(match):
        raw_url = match.group(0)
        defanged = defang_url(raw_url)
        extracted.append(defanged)
        return defanged

    sanitized = active_url_pattern.sub(replace_func, text)
    return sanitized, extracted

def extract_url_features_safely(text: str) -> Dict[str, Any]:
    """
    NFR-01: Pure static offline structural feature extraction.
    NEVER performs DNS queries, HTTP GET/HEAD requests, or socket operations.
    """
    url_pattern = re.compile(r'(?:hxxps?|https?)://[^\s<>"]+')
    found_urls = url_pattern.findall(text)

    is_shortener = False
    has_ip = False
    primary_domain = "none"

    if found_urls:
        first_url = found_urls[0]
        # Check domain pattern
        domain_match = re.search(r'hxxps?://([^/\s:]+)', first_url)
        if domain_match:
            primary_domain = domain_match.group(1)

        # Check for URL shorteners
        for s_domain in SHORTENER_DOMAINS:
            if s_domain in primary_domain:
                is_shortener = True
                break

        # Check for IP address in host
        if re.search(r'\b(?:\d{1,3}\.|\d{1,3}\[\.\]){3}\d{1,3}\b', primary_domain):
            has_ip = True

    return {
        "url_count": len(found_urls),
        "is_defanged": all("hxxp" in u or "[.]" in u for u in found_urls) if found_urls else True,
        "has_ip": has_ip,
        "is_shortener": is_shortener,
        "primary_domain": primary_domain
    }

def audit_corpus_safety(records: List[Dict]) -> Dict[str, Any]:
    """
    CP-1 Verification:
    Scans all records in the corpus to confirm zero active clickable URLs exist.
    """
    violations = []
    total_urls = 0
    defanged_urls_count = 0

    active_pattern = re.compile(r'https?://[^\s<>"]+')
    defanged_pattern = re.compile(r'hxxps?://[^\s<>"]+')

    for r in records:
        text = f"{r.get('subject_or_title', '')} {r.get('body_text', '')}"
        active = active_pattern.findall(text)
        defanged = defanged_pattern.findall(text)

        if active:
            violations.append({
                "message_id": r.get("message_id"),
                "active_urls": active
            })
        total_urls += len(active) + len(defanged)
        defanged_urls_count += len(defanged)

    is_safe = (len(violations) == 0)
    return {
        "is_safe": is_safe,
        "total_records_audited": len(records),
        "total_urls_found": total_urls,
        "defanged_urls_count": defanged_urls_count,
        "violations_count": len(violations),
        "violations": violations
    }

if __name__ == "__main__":
    sample = "Click on http://login-bank.com/secure or visit hxxps://bit[.]ly/alert now!"
    sanitized, extracted = sanitize_message_text(sample)
    print("Sanitized:", sanitized)
    feats = extract_url_features_safely(sanitized)
    print("Features extracted statically:", feats)

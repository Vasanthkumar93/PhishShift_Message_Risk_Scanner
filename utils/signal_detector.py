"""
PhishShift Warning Signal Detection Engine
Analyzes text for specific indicators of phishing attacks:
1. Urgent threats & coercive psychological pressure
2. Requests for credentials, identity, or financial details
3. Suspicious links, shorteners, raw IPs, and deceptive domains
4. Sensitive keyword context (differentiating benign HR/IT terms from attacks)
"""
import re
from typing import Dict, List, Any


# Precompiled regex patterns for performance and accuracy
URGENCY_PATTERNS = [
    (r'\b(urgent|urgently|immediate|immediately|instant|act now|hurry)\b', "Direct urgency cue"),
    (r'\b(account (?:suspended|terminated|locked|restricted|deactivated|closed))\b', "Account threat / suspension"),
    (r'\b(within \d+\s*(?:hours|hrs|minutes|mins|days))\b', "Time deadline pressure"),
    (r'\b(final (?:notice|warning)|last chance|deadline)\b', "Ultimatum / final warning"),
    (r'\b(unauthorized (?:access|activity|transaction|charge))\b', "Fear cue: alleged security breach"),
    (r'\b(legal action|court subpoena|police|law enforcement|penalt(?:y|ies))\b', "Coercive legal consequence"),
    (r'\b(funds (?:seized|held|frozen)|frozen account)\b', "Financial forfeiture fear"),
]

CREDENTIAL_PATTERNS = [
    (r'\b(enter|update|verify|confirm|reset)\s+(?:your\s+)?(password|passcode|pin|credentials)\b', "Direct credential solicitation"),
    (r'\b(social security|ssn|national insurance)\b', "Request for government identity (SSN)"),
    (r'\b(credit card|debit card|cvv|card number|expiration date)\b', "Payment card harvesting cue"),
    (r'\b(bank account|routing number|checking account|iban)\b', "Banking detail solicitation"),
    (r'\b(seed phrase|recovery phrase|private key|crypto wallet)\b', "Cryptocurrency credential theft cue"),
    (r'\b(gift card|apple gift|steam card|wire transfer)\b', "Untraceable payment request (gift card / wire)"),
    (r'\b(confirm your identity|validate your account)\b', "Generic identity verification lure"),
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "goo.gl", "adf.ly"
]

SUSPICIOUS_TLDS = [
    ".tk", ".top", ".pw", ".xyz", ".club", ".info", ".click",
    ".biz", ".online", ".cc", ".site", ".link", ".me"
]

BENIGN_DEFENSIVE_PATTERNS = [
    r'will never ask you for your password',
    r'change your password directly in windows',
    r'internal workday',
    r'sharepoint',
    r'official mobile app',
    r'no action is needed',
    r'if this was you, no action',
]


def detect_warning_signals(text: str) -> Dict[str, Any]:
    """
    Scans the message for heuristic risk signals and returns structured findings.
    """
    if not isinstance(text, str):
        text = ""

    signals: List[Dict[str, str]] = []
    urgency_matches = []
    credential_matches = []
    link_findings = []

    text_lower = text.lower()

    # 1. Check for Urgency & Coercive Phrasing
    for pattern, desc in URGENCY_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            urgency_matches.append(match.group(0))

    if urgency_matches:
        signals.append({
            "category": "Urgent Threat",
            "severity": "HIGH" if len(urgency_matches) > 1 else "MEDIUM",
            "title": "Artificial Urgency / Threat Detected",
            "description": f"Message contains high-pressure language: '{', '.join(urgency_matches[:3])}'. Phishers use urgency to bypass critical thinking."
        })

    # 2. Check for Credential Harvesting
    for pattern, desc in CREDENTIAL_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            credential_matches.append(match.group(0))

    if credential_matches:
        signals.append({
            "category": "Credential Harvesting",
            "severity": "HIGH",
            "title": "Request for Sensitive Credentials",
            "description": f"Direct prompt requesting sensitive information: '{', '.join(credential_matches[:3])}'."
        })

    # 3. URL and Link Analysis
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text, re.IGNORECASE)
    has_shortened_url = False
    has_raw_ip = False
    has_suspicious_tld = False
    has_insecure_http = False

    for url in urls:
        url_lower = url.lower()

        # Check for URL shorteners
        if any(shortener in url_lower for shortener in SHORTENER_DOMAINS):
            has_shortened_url = True

        # Check for raw IP address in URL (e.g., http://192.168.1.1/login)
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            has_raw_ip = True

        # Check for suspicious TLDs
        if any(tld in url_lower for tld in SUSPICIOUS_TLDS):
            has_suspicious_tld = True

        # Insecure HTTP
        if url_lower.startswith("http://"):
            has_insecure_http = True

    if urls:
        if has_raw_ip:
            signals.append({
                "category": "URL Inspection",
                "severity": "HIGH",
                "title": "Raw IP Address in URL",
                "description": "The message points directly to a numeric IP address rather than a verified company domain name."
            })
        if has_shortened_url:
            signals.append({
                "category": "URL Inspection",
                "severity": "HIGH",
                "title": "Shortened / Masked URL Detected",
                "description": "Link uses a shortener service (e.g., bit.ly, tinyurl) which conceals the real destination server."
            })
        if has_suspicious_tld:
            signals.append({
                "category": "URL Inspection",
                "severity": "MEDIUM",
                "title": "Unconventional Domain Extension",
                "description": "Link points to an atypical TLD (.tk, .top, .xyz, etc.) frequently exploited in disposable phishing campaigns."
            })
        if has_insecure_http and not has_raw_ip:
            signals.append({
                "category": "URL Inspection",
                "severity": "LOW",
                "title": "Unencrypted HTTP Link",
                "description": "URL connects over plain HTTP instead of secure HTTPS."
            })

    # 4. Contextual Analysis of Legitimate Sensitive Keywords
    has_sensitive_keyword = any(k in text_lower for k in ["payroll", "password", "w-2", "bonus", "tax", "vpn"])
    has_defensive_phrasing = any(re.search(p, text_lower) for p in BENIGN_DEFENSIVE_PATTERNS)

    if has_sensitive_keyword and has_defensive_phrasing:
        signals.append({
            "category": "Legitimate Context",
            "severity": "INFO",
            "title": "Legitimate Defensive Phrasing Detected",
            "description": "Message mentions security/payroll topics in an advisory context (e.g. reminding users that IT never asks for credentials)."
        })

    # Calculate aggregate heuristic risk score (0-100)
    heuristic_score = 0
    for s in signals:
        if s["severity"] == "HIGH":
            heuristic_score += 35
        elif s["severity"] == "MEDIUM":
            heuristic_score += 20
        elif s["severity"] == "LOW":
            heuristic_score += 10
        elif s["severity"] == "INFO":
            heuristic_score -= 15  # Benign indicator discount

    heuristic_score = max(0, min(100, heuristic_score))

    return {
        "signals": signals,
        "signal_count": len(signals),
        "url_count": len(urls),
        "urls_detected": urls,
        "has_shortened_url": has_shortened_url,
        "has_raw_ip": has_raw_ip,
        "heuristic_score": heuristic_score,
        "urgency_detected": len(urgency_matches) > 0,
        "credential_prompt": len(credential_matches) > 0
    }

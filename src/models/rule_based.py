"""
Rule-Based Baseline Classifier (FR-02)
Transparent heuristic expert system simulating traditional email gateway policies:
- Flags freemail/lookalike senders asking for credentials or financial updates.
- Flags suspicious URL shorteners in SMS/emails.
- Flags urgent account expiration or lockout demands with external links.
"""

from typing import Dict, Any, List, Tuple
import re

class RuleBasedPhishClassifier:
    """Heuristic rule classifier that returns binary prediction, probability, and triggered rules."""

    def __init__(self):
        self.rules = [
            ("RULE-01", "Freemail sender requesting credential verification", self._check_freemail_cred),
            ("RULE-02", "External/lookalike domain with payroll or banking change", self._check_lookalike_payroll),
            ("RULE-03", "URL shortener present with delivery/urgent prompt", self._check_shortener_urgency),
            ("RULE-04", "Password expiration warning with non-internal link", self._check_password_expiry_external),
            ("RULE-05", "Suspicious or unknown sender domain type", self._check_suspicious_domain),
            ("RULE-06", "Urgent executive procurement favor pattern", self._check_executive_giftcard)
        ]

    def _check_freemail_cred(self, r: Dict, text: str) -> bool:
        sender = r.get("sender_domain_type", "")
        has_cred_term = bool(re.search(r'\b(password|credential|sso|login|verify account)\b', text, re.I))
        return (sender in ["freemail", "lookalike"]) and has_cred_term

    def _check_lookalike_payroll(self, r: Dict, text: str) -> bool:
        sender = r.get("sender_domain_type", "")
        has_pay = bool(re.search(r'\b(payroll|direct deposit|remittance|wire|bonus|w-2)\b', text, re.I))
        return (sender in ["lookalike", "suspicious", "freemail"]) and has_pay

    def _check_shortener_urgency(self, r: Dict, text: str) -> bool:
        url_feats = r.get("sanitized_url_features", {})
        if isinstance(url_feats, str):
            import json
            try:
                url_feats = json.loads(url_feats)
            except Exception:
                url_feats = {}
        is_shortener = url_feats.get("is_shortener", False) or bool(re.search(r'\b(bit\[\.\]ly|tinyurl\[\.\]com|t\[\.\]co|is\[\.\]gd)\b', text, re.I))
        has_urgency = bool(re.search(r'\b(urgent|delivery|hold|immediately|alert|fee|tracking)\b', text, re.I))
        return is_shortener and has_urgency

    def _check_password_expiry_external(self, r: Dict, text: str) -> bool:
        sender = r.get("sender_domain_type", "")
        has_expiry = bool(re.search(r'\b(password\s+(?:expires|lockout|reset))\b', text, re.I))
        has_external_link = (sender != "internal") and ("hxxp" in text)
        return has_expiry and has_external_link

    def _check_suspicious_domain(self, r: Dict, text: str) -> bool:
        sender = r.get("sender_domain_type", "")
        return sender == "suspicious"

    def _check_executive_giftcard(self, r: Dict, text: str) -> bool:
        sender = r.get("sender_domain_type", "")
        has_exec = bool(re.search(r'\b(favor|confidential|procurement|gift\s*card|wellness incentive)\b', text, re.I))
        return (sender == "freemail") and has_exec

    def predict_single(self, record: Dict[str, Any]) -> Tuple[int, float, List[str]]:
        """
        Returns:
            - pred: 1 if phishing, 0 if legitimate
            - confidence: estimated risk score [0.0, 1.0]
            - triggered_rules: list of descriptions for fired rules
        """
        text = f"{record.get('subject_or_title', '')} {record.get('body_text', '')}"
        triggered = []

        # Immediate whitelist check: authentic internal cues without external lookalikes
        sender = record.get("sender_domain_type", "")
        if sender == "internal" and "ctrl+alt+del" in text.lower():
            return 0, 0.05, ["SAFE-RULE: Authenticated internal system instruction"]

        for rule_id, desc, rule_fn in self.rules:
            if rule_fn(record, text):
                triggered.append(f"[{rule_id}] {desc}")

        rule_count = len(triggered)
        if rule_count == 0:
            pred = 0
            score = 0.15
        elif rule_count == 1:
            pred = 1
            score = 0.65
        elif rule_count == 2:
            pred = 1
            score = 0.85
        else:
            pred = 1
            score = 0.95

        return pred, score, triggered

    def predict(self, records: List[Dict[str, Any]]) -> List[int]:
        return [self.predict_single(r)[0] for r in records]

    def predict_proba(self, records: List[Dict[str, Any]]) -> List[float]:
        return [self.predict_single(r)[1] for r in records]

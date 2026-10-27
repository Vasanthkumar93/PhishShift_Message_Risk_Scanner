"""
PhishShift Safety Advisor Module
Generates actionable, easy-to-understand safety advice based on classification,
risk probability, and warning signals.
"""
from typing import List, Dict, Any


def generate_safety_advice(classification: str, risk_score: float, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produces recommendations, actionable steps, and immediate cautions.
    """
    tips = []
    actions = []
    summary = ""

    signal_categories = {s.get("category") for s in signals}

    if classification == "Likely Phishing":
        summary = "CRITICAL THREAT: This message exhibits strong hallmarks of a deceptive social engineering attack designed to harvest data or compromise your device."
        actions.append("DO NOT click any links, download attachments, or call the phone numbers provided.")
        actions.append("DO NOT reply to the sender, even to request cancellation or unsubscribe.")
        actions.append("Forward this email to your organization's security team (e.g., phish@yourcompany.com) or report the SMS to 7726 (SPAM).")
        actions.append("Delete the message immediately after reporting.")

        if "Credential Harvesting" in signal_categories:
            tips.append("If you already submitted login details, immediately visit the official service directly (from your browser bookmarks, not the link) and change your password, then enable Multi-Factor Authentication (MFA).")
        if "URL Inspection" in signal_categories:
            tips.append("Attackers frequently use link-shortening services or misleading URLs to disguise unauthorized spoofed web domains.")

    elif classification == "Suspicious":
        summary = "ELEVATED RISK: While this message may resemble legitimate business communication, it displays ambiguity or subtle manipulation tactics."
        actions.append("Verify through an independent channel: Contact the alleged sender using an official phone number or directory, not contact info in this message.")
        actions.append("Inspect the sender address: Check the full email header to see if the display name masks a completely unrelated email address.")
        actions.append("Navigate manually: If this refers to a banking, payroll, or package delivery event, open the official app or website directly.")

        tips.append("Phishers often craft subtle, polite messages with low initial pressure to build false trust before delivering a payload.")

    else:  # Likely Legitimate
        summary = "LOW RISK: The message exhibits language and contextual patterns consistent with normal benign correspondence."
        actions.append("Safe to read, but maintain standard digital hygiene.")
        actions.append("Always verify the sender before opening unexpected attachments or executing downloaded files.")

        if any(s.get("category") == "Legitimate Context" for s in signals):
            tips.append("Note: This message mentions security or account terms (such as passwords or payroll) in an advisory or policy context, which is common in genuine enterprise updates.")
        else:
            tips.append("Never share one-time passcodes (OTP) or private credentials over SMS or chat, even if a message seems familiar.")

    return {
        "summary": summary,
        "recommended_actions": actions,
        "educational_tips": tips
    }

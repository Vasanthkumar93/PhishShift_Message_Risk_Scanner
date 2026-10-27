"""
PhishShift Unit & Integration Test Suite
Validates text normalization, signal detectors, safety advice generator,
and Flask scanner endpoints.
"""
import unittest
import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils.nlp_preprocessor import clean_text_for_model, extract_text_statistics
from utils.signal_detector import detect_warning_signals
from utils.advisor import generate_safety_advice
from app import app


class TestPhishShiftPipeline(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_text_normalization(self):
        sample = "URGENT: Click http://bit.ly/test to pay $50.00 right NOW!"
        cleaned = clean_text_for_model(sample)
        self.assertIn("url_token", cleaned)
        self.assertIn("money_token", cleaned)
        self.assertEqual(cleaned, cleaned.lower())

    def test_text_statistics(self):
        sample = "HELLO! How are you doing today? WIN $500!"
        stats = extract_text_statistics(sample)
        self.assertGreater(stats["caps_ratio"], 0.2)
        self.assertEqual(stats["exclamation_count"], 2)
        self.assertEqual(stats["question_count"], 1)
        self.assertTrue(stats["has_currency"])

    def test_urgent_threat_detection(self):
        sample = "Your bank account has been suspended! Immediate action required within 24 hours or account terminated."
        res = detect_warning_signals(sample)
        self.assertTrue(res["urgency_detected"])
        categories = [s["category"] for s in res["signals"]]
        self.assertIn("Urgent Threat", categories)

    def test_credential_solicitation_detection(self):
        sample = "Please enter your password and social security number to verify your account credentials."
        res = detect_warning_signals(sample)
        self.assertTrue(res["credential_prompt"])
        categories = [s["category"] for s in res["signals"]]
        self.assertIn("Credential Harvesting", categories)

    def test_shortened_url_detection(self):
        sample = "Check your package delivery status at http://bit.ly/track-now"
        res = detect_warning_signals(sample)
        self.assertTrue(res["has_shortened_url"])
        self.assertEqual(res["url_count"], 1)

    def test_raw_ip_url_detection(self):
        sample = "Verify your account at http://192.168.1.10/login.php immediately."
        res = detect_warning_signals(sample)
        self.assertTrue(res["has_raw_ip"])

    def test_legitimate_defensive_context(self):
        sample = "Reminder: IT staff will never ask you for your password via email. Change your password directly in Windows settings."
        res = detect_warning_signals(sample)
        categories = [s["category"] for s in res["signals"]]
        self.assertIn("Legitimate Context", categories)

    def test_safety_advice_generation(self):
        advice = generate_safety_advice("Likely Phishing", 95.0, [{"category": "Credential Harvesting"}])
        self.assertIn("CRITICAL THREAT", advice["summary"])
        self.assertGreater(len(advice["recommended_actions"]), 0)

    def test_api_scan_endpoint_empty(self):
        response = self.app.post(
            "/api/scan",
            data=json.dumps({"message": "   "}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)

    def test_api_scan_endpoint_valid(self):
        sample = "URGENT: Your Bank of America account is suspended! Verify at http://bit.ly/bank-verify"
        response = self.app.post(
            "/api/scan",
            data=json.dumps({"message": sample}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("classification", data)
        self.assertIn("risk_score", data)
        self.assertIn("safety_advice", data)


if __name__ == "__main__":
    unittest.main()

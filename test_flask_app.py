"""
test_flask_app.py
Tests the Flask application:
- Model loading from phishing_pipeline.pkl
- GET request rendering
- POST legitimate URL
- POST phishing URL
- Empty input validation
- Malformed input handling
- Confidence / probability rendering
"""

import unittest
from app import app, pipeline, PIPELINE_PATH, BAD_INDEX, GOOD_INDEX

class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_01_model_artifact_loaded(self):
        """Verify the pipeline artifact is loaded from phishing_pipeline.pkl"""
        self.assertEqual(PIPELINE_PATH, "phishing_pipeline.pkl")
        self.assertIsNotNone(pipeline)
        self.assertEqual(list(pipeline.classes_), ["bad", "good"])
        self.assertEqual(BAD_INDEX, 0)
        self.assertEqual(GOOD_INDEX, 1)
        print("\n[PASS] Model artifact verified: phishing_pipeline.pkl loaded with classes ['bad', 'good']")

    def test_02_get_root(self):
        """Verify GET / returns 200 and loads HTML template"""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Smart URL Security Checker", res.data)
        self.assertIn(b"Enter URL", res.data)
        print("[PASS] GET / renders template successfully (HTTP 200)")

    def test_03_post_legitimate_url(self):
        """Verify POST / with legitimate URL returns secure prediction"""
        # Testing a URL whose tokens are strongly good, e.g. "youtube.com/watch?v=qI0T0Jl3vdU" from notebook
        res = self.client.post("/", data={"URL": "youtube.com/watch?v=qI0T0Jl3vdU"})
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"This is a Secure Website!!", res.data)
        self.assertIn(b"Confidence:", res.data)
        print("[PASS] POST legitimate URL returns 'This is a Secure Website!!' with confidence")

    def test_04_post_phishing_url(self):
        """Verify POST / with phishing URL returns phishing prediction"""
        res = self.client.post("/", data={"URL": "http://paypal-security-login.servehttp.com/login.php"})
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"This is a Phishing Website!!", res.data)
        self.assertIn(b"Confidence:", res.data)
        print("[PASS] POST phishing URL returns 'This is a Phishing Website!!' with confidence")

    def test_05_post_empty_url(self):
        """Verify POST / with empty URL returns validation message without crashing"""
        res = self.client.post("/", data={"URL": ""})
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Please enter a valid URL.", res.data)
        print("[PASS] POST empty URL handled gracefully with validation message")

    def test_06_post_whitespace_url(self):
        """Verify POST / with whitespace URL returns validation message without crashing"""
        res = self.client.post("/", data={"URL": "    "})
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Please enter a valid URL.", res.data)
        print("[PASS] POST whitespace URL handled gracefully with validation message")

    def test_07_post_malformed_url(self):
        """Verify POST / with malformed URL does not crash and produces prediction"""
        res = self.client.post("/", data={"URL": "http:////??&&&%%%invalid!!"})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(b"This is a Phishing Website!!" in res.data or b"This is a Secure Website!!" in res.data)
        print("[PASS] POST malformed URL processed safely without crashing")

if __name__ == "__main__":
    unittest.main()

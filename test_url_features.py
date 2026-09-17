"""
test_url_features.py
Unit tests for URL structural feature extraction pipeline.
"""

import unittest
import numpy as np
from url_features import extract_url_features, decompose_hostname, URLFeatureExtractor

class TestURLFeatures(unittest.TestCase):

    def test_01_normal_https_url(self):
        url = "https://www.google.com/search?q=test"
        feats = extract_url_features(url)
        self.assertEqual(feats["uses_https"], 1.0)
        self.assertEqual(feats["has_query"], 1.0)
        self.assertEqual(feats["brand_token_present"], 1.0)
        self.assertEqual(feats["brand_in_registered_domain"], 1.0)
        self.assertEqual(feats["brand_domain_mismatch"], 0.0)

    def test_02_http_url(self):
        url = "http://example.org/index.html"
        feats = extract_url_features(url)
        self.assertEqual(feats["uses_https"], 0.0)
        self.assertEqual(feats["path_segment_count"], 1.0)

    def test_03_ip_address_host(self):
        url = "http://192.168.1.1/login.php"
        feats = extract_url_features(url)
        self.assertEqual(feats["hostname_has_ip"], 1.0)
        self.assertEqual(feats["ip_address_host"], 1.0)
        self.assertEqual(feats["subdomain_count"], 0.0)

    def test_04_url_with_port(self):
        url = "http://localhost:8080/dashboard"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_port"], 1.0)
        self.assertEqual(feats["non_standard_port"], 1.0)

    def test_05_url_with_query(self):
        url = "http://store.com/item?id=123&category=books&sort=asc"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_query"], 1.0)
        self.assertEqual(feats["query_parameter_count"], 3.0)

    def test_06_url_with_fragment(self):
        url = "https://en.wikipedia.org/wiki/Phishing#Techniques"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_fragment"], 1.0)
        self.assertGreater(feats["fragment_length"], 0.0)

    def test_07_url_with_at_symbol(self):
        url = "http://legit.com@phishing.com/login"
        feats = extract_url_features(url)
        self.assertEqual(feats["has_at_symbol"], 1.0)
        self.assertEqual(feats["contains_at_symbol"], 1.0)

    def test_08_malformed_url(self):
        url = r"htt:/\invalid@@@%%%##//test:port"
        # Must not throw an exception and must return all numeric features
        feats = extract_url_features(url)
        self.assertIsInstance(feats, dict)
        self.assertFalse(any(np.isnan(v) for v in feats.values()))

    def test_09_empty_string(self):
        feats = extract_url_features("")
        self.assertEqual(feats["url_length"], 0.0)
        self.assertEqual(feats["digit_ratio"], 0.0)
        self.assertFalse(any(np.isnan(v) for v in feats.values()))

    def test_10_whitespace_string(self):
        feats = extract_url_features("     \t\n  ")
        self.assertEqual(feats["url_length"], 0.0)
        self.assertFalse(any(np.isnan(v) for v in feats.values()))

    def test_11_long_url(self):
        url = "http://example.com/" + "a" * 150
        feats = extract_url_features(url)
        self.assertEqual(feats["unusually_long_url"], 1.0)
        self.assertGreater(feats["url_length"], 150.0)

    def test_12_multiple_subdomains(self):
        url = "http://a.b.c.d.example.com/test"
        sub, reg, tld, sub_cnt = decompose_hostname("a.b.c.d.example.com")
        self.assertEqual(reg, "example.com")
        self.assertEqual(sub, "a.b.c.d")
        self.assertEqual(sub_cnt, 4)
        feats = extract_url_features(url)
        self.assertEqual(feats["subdomain_count"], 4.0)
        self.assertEqual(feats["excessive_subdomains"], 1.0)

    def test_13_brand_in_legitimate_domain(self):
        url = "https://www.paypal.com/signin"
        feats = extract_url_features(url)
        self.assertEqual(feats["brand_token_present"], 1.0)
        self.assertEqual(feats["brand_in_registered_domain"], 1.0)
        self.assertEqual(feats["brand_domain_mismatch"], 0.0)

    def test_14_brand_in_malicious_subdomain(self):
        url = "http://paypal.account-verify.servehttp.com/login.php"
        feats = extract_url_features(url)
        self.assertEqual(feats["brand_token_present"], 1.0)
        self.assertEqual(feats["brand_in_registered_domain"], 0.0)
        self.assertEqual(feats["brand_in_subdomain"], 1.0)
        self.assertEqual(feats["brand_domain_mismatch"], 1.0)

    def test_15_brand_in_path(self):
        url = "http://compromised-site.com/wp-content/paypal/login.html"
        feats = extract_url_features(url)
        self.assertEqual(feats["brand_token_present"], 1.0)
        self.assertEqual(feats["brand_in_registered_domain"], 0.0)
        self.assertEqual(feats["brand_in_path"], 1.0)
        self.assertEqual(feats["brand_domain_mismatch"], 1.0)

    def test_16_determinism(self):
        url = "http://secure-login.bankofamerica.com.phishing.ru/auth?id=999#sec"
        f1 = extract_url_features(url)
        f2 = extract_url_features(url)
        self.assertEqual(f1, f2)

    def test_17_sklearn_transformer(self):
        urls = [
            "https://www.google.com",
            "http://192.168.1.1/login.php",
            "http://paypal.phishing.ru/signin"
        ]
        extractor = URLFeatureExtractor()
        X = extractor.fit_transform(urls)
        self.assertEqual(X.shape[0], 3)
        self.assertEqual(X.shape[1], len(extractor.feature_names_))
        self.assertFalse(np.isnan(X).any())

if __name__ == "__main__":
    unittest.main()

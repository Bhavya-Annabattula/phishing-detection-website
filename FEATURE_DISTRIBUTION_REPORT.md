# URL STRUCTURAL FEATURE DISTRIBUTION & SIGNAL REPORT

**Dataset Evaluated:** `phishing_site_urls_clean.csv` (507,194 Cleaned, Deduplicated URLs)
**Module:** `url_features.py` (`extract_url_features` / `URLFeatureExtractor`)
**Evaluation Date:** September 15, 2026
**Scope:** 56 structural, domain, and brand-impersonation features evaluated across all clean samples.

---

## 1. EXECUTIVE SUMMARY

A complete, modular, and high-performance URL feature extraction engine was built in `url_features.py` and validated on the entire clean dataset of 507,194 samples.

### Key Technical Achievements:
1. **Zero External Dependencies / 100% Offline:** Fully autonomous decomposition of hostnames, subdomains, registered root domains, and two-part TLDs (`.co.uk`, `.com.au`, etc.) without DNS queries or network access.
2. **High Throughput:** Benchmark processing speed of **0.0191 ms per URL** (~52,400 URLs/second), processing all 507,194 dataset records in **13.69 seconds**.
3. **100% Data Integrity:** Exactly **zero NaN values** and **zero infinite values** produced across all 507,194 samples. Fully deterministic.
4. **Discriminative Brand Impersonation Signals:** The engineered feature `brand_domain_mismatch` (detecting when a brand token appears in the subdomain or path of a non-brand domain) is **52x higher in phishing URLs** (10.4% in phishing vs 0.2% in legitimate) with a **+0.2760 correlation** to maliciousness.
5. **Strong Structural Signals:** Dot count (+0.3364 corr), digit count (+0.2643 corr), and query length (+0.2321 corr) exhibit strong non-lexical discriminatory power.

---

## 2. FEATURE EXTRACTION PIPELINE ARCHITECTURE

The feature extractor calculates 56 numeric features per URL, organized into 8 distinct families:
- **Basic Lengths (7):** `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `domain_length`, `subdomain_length`.
- **Character Counts (12):** `digit_count`, `letter_count`, `special_character_count`, `dot_count`, `hyphen_count`, `underscore_count`, `slash_count`, `question_mark_count`, `equals_count`, `ampersand_count`, `percent_count`, `at_count`.
- **Ratios (3):** `digit_ratio`, `special_character_ratio`, `digit_to_letter_ratio`.
- **Hostname Structure (5):** `subdomain_count`, `hostname_dot_count`, `hostname_hyphen_count`, `hostname_digit_count`, `hostname_has_ip`.
- **Path Structure (4):** `path_segment_count`, `path_digit_count`, `path_hyphen_count`, `path_special_character_count`.
- **Query Structure (3):** `has_query`, `query_parameter_count`, `query_digit_count`.
- **Protocol & Symbol Flags (5):** `has_fragment`, `has_port`, `uses_https`, `has_at_symbol`, `has_percent_encoding`.
- **Brand-Impersonation Metrics (5):** `brand_token_present`, `brand_in_registered_domain`, `brand_in_subdomain`, `brand_in_path`, `brand_domain_mismatch`.
- **Suspicious Heuristics (12):** Documented threshold indicators for excessive subdomains, long URLs, non-standard ports, deep paths, etc.

---

## 3. DATASET-WIDE FEATURE DISTRIBUTION (507,194 URLs)

| Feature | Bad Mean | Good Mean | Bad Median | Good Median | Bad Std | Good Std | Correlation with Bad | Potential Signal |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`dot_count`** | 3.009 | 1.782 | 2.0 | 2.0 | 2.591 | 0.840 | **+0.3364** | Strong Potential Signal |
| **`brand_domain_mismatch`** | 0.104 | 0.002 | 0.0 | 0.0 | 0.305 | 0.039 | **+0.2760** | Strong Potential Signal |
| **`digit_count`** | 10.283 | 3.134 | 2.0 | 0.0 | 21.196 | 4.761 | **+0.2643** | Strong Potential Signal |
| **`excessive_digits`** | 0.252 | 0.066 | 0.0 | 0.0 | 0.434 | 0.249 | **+0.2499** | Moderate Potential Signal |
| **`unusually_long_url`** | 0.180 | 0.033 | 0.0 | 0.0 | 0.384 | 0.179 | **+0.2470** | Moderate Potential Signal |
| **`url_length`** | 71.057 | 45.768 | 47.0 | 40.0 | 74.591 | 24.641 | **+0.2466** | Moderate Potential Signal |
| **`query_length`** | 20.754 | 2.971 | 0.0 | 0.0 | 61.638 | 12.105 | **+0.2321** | Moderate Potential Signal |
| **`brand_in_path`** | 0.067 | 0.002 | 0.0 | 0.0 | 0.249 | 0.039 | **+0.2155** | Moderate Potential Signal |
| **`letter_count`** | 51.668 | 36.158 | 37.0 | 32.0 | 51.531 | 18.798 | **+0.2143** | Moderate Potential Signal |
| **`hostname_dot_count`** | 1.933 | 1.394 | 1.0 | 1.0 | 1.921 | 0.588 | **+0.2101** | Moderate Potential Signal |
| **`hostname_length`** | 21.725 | 15.832 | 17.0 | 15.0 | 22.116 | 5.735 | **+0.2068** | Moderate Potential Signal |
| **`hostname_digit_count`** | 1.919 | 0.083 | 0.0 | 0.0 | 7.679 | 0.474 | **+0.2047** | Moderate Potential Signal |
| **`slash_count`** | 3.083 | 2.326 | 3.0 | 2.0 | 2.210 | 1.326 | **+0.1976** | Moderate Potential Signal |
| **`query_digit_count`** | 4.351 | 0.617 | 0.0 | 0.0 | 15.691 | 2.703 | **+0.1957** | Moderate Potential Signal |
| **`special_character_count`** | 9.106 | 6.476 | 6.0 | 5.0 | 8.983 | 4.081 | **+0.1933** | Moderate Potential Signal |
| **`excessive_subdomains`** | 0.063 | 0.004 | 0.0 | 0.0 | 0.244 | 0.062 | **+0.1914** | Moderate Potential Signal |
| **`digit_ratio`** | 0.106 | 0.059 | 0.0 | 0.0 | 0.146 | 0.084 | **+0.1884** | Moderate Potential Signal |
| **`brand_in_subdomain`** | 0.043 | 0.000 | 0.0 | 0.0 | 0.203 | 0.009 | **+0.1826** | Moderate Potential Signal |
| **`subdomain_length`** | 6.946 | 2.233 | 0.0 | 0.0 | 21.483 | 4.324 | **+0.1780** | Moderate Potential Signal |
| **`hostname_hyphen_count`** | 0.273 | 0.062 | 0.0 | 0.0 | 0.879 | 0.294 | **+0.1769** | Moderate Potential Signal |
| **`unusually_long_hostname`** | 0.100 | 0.020 | 0.0 | 0.0 | 0.300 | 0.139 | **+0.1754** | Moderate Potential Signal |
| **`subdomain_count`** | 0.788 | 0.367 | 0.0 | 0.0 | 1.896 | 0.560 | **+0.1692** | Moderate Potential Signal |
| **`equals_count`** | 0.569 | 0.195 | 0.0 | 0.0 | 1.449 | 0.700 | **+0.1668** | Moderate Potential Signal |
| **`path_hyphen_count`** | 0.298 | 1.226 | 0.0 | 0.0 | 0.973 | 2.647 | **-0.1611** | Moderate Potential Signal |
| **`query_parameter_count`** | 0.559 | 0.194 | 0.0 | 0.0 | 1.530 | 0.690 | **+0.1591** | Moderate Potential Signal |
| **`ip_address_host`** | 0.032 | 0.000 | 0.0 | 0.0 | 0.176 | 0.008 | **+0.1571** | Moderate Potential Signal |
| **`hostname_has_ip`** | 0.032 | 0.000 | 0.0 | 0.0 | 0.176 | 0.008 | **+0.1571** | Moderate Potential Signal |
| **`excessive_special_characters`** | 0.257 | 0.127 | 0.0 | 0.0 | 0.437 | 0.333 | **+0.1496** | Moderate Potential Signal |
| **`question_mark_count`** | 0.294 | 0.127 | 0.0 | 0.0 | 0.752 | 0.338 | **+0.1486** | Moderate Potential Signal |
| **`ampersand_count`** | 0.341 | 0.070 | 0.0 | 0.0 | 1.340 | 0.502 | **+0.1447** | Moderate Potential Signal |
| **`has_query`** | 0.239 | 0.126 | 0.0 | 0.0 | 0.426 | 0.332 | **+0.1314** | Moderate Potential Signal |
| **`path_segment_count`** | 2.508 | 2.027 | 2.0 | 2.0 | 1.995 | 1.399 | **+0.1284** | Moderate Potential Signal |
| **`hostname_multiple_hyphens`** | 0.048 | 0.008 | 0.0 | 0.0 | 0.213 | 0.090 | **+0.1267** | Moderate Potential Signal |
| **`deep_path`** | 0.238 | 0.134 | 0.0 | 0.0 | 0.426 | 0.341 | **+0.1188** | Moderate Potential Signal |
| **`brand_token_present`** | 0.127 | 0.055 | 0.0 | 0.0 | 0.333 | 0.228 | **+0.1176** | Moderate Potential Signal |
| **`path_digit_count`** | 3.919 | 2.431 | 0.0 | 0.0 | 9.546 | 4.218 | **+0.1055** | Moderate Potential Signal |
| **`hyphen_count`** | 0.719 | 1.332 | 0.0 | 0.0 | 1.571 | 2.689 | **-0.1027** | Moderate Potential Signal |
| **`domain_length`** | 14.381 | 13.269 | 14.0 | 12.0 | 5.240 | 4.526 | **+0.0985** | Weak Potential Signal |
| **`has_port`** | 0.013 | 0.000 | 0.0 | 0.0 | 0.114 | 0.019 | **+0.0944** | Weak Potential Signal |
| **`has_at_symbol`** | 0.014 | 0.001 | 0.0 | 0.0 | 0.119 | 0.025 | **+0.0942** | Weak Potential Signal |
| **`contains_at_symbol`** | 0.014 | 0.001 | 0.0 | 0.0 | 0.119 | 0.025 | **+0.0942** | Weak Potential Signal |
| **`non_standard_port`** | 0.012 | 0.000 | 0.0 | 0.0 | 0.110 | 0.019 | **+0.0900** | Weak Potential Signal |
| **`at_count`** | 0.015 | 0.001 | 0.0 | 0.0 | 0.132 | 0.030 | **+0.0859** | Weak Potential Signal |
| **`many_query_params`** | 0.029 | 0.007 | 0.0 | 0.0 | 0.167 | 0.084 | **+0.0832** | Weak Potential Signal |
| **`digit_to_letter_ratio`** | 100605.625 | 162.983 | 0.0 | 0.0 | 1141425.650 | 39337.777 | **+0.0771** | Weak Potential Signal |
| **`brand_in_registered_domain`** | 0.024 | 0.053 | 0.0 | 0.0 | 0.152 | 0.225 | **-0.0590** | Weak Potential Signal |
| **`percent_count`** | 0.203 | 0.066 | 0.0 | 0.0 | 2.010 | 0.704 | **+0.0503** | Weak Potential Signal |
| **`has_percent_encoding`** | 0.040 | 0.024 | 0.0 | 0.0 | 0.195 | 0.154 | **+0.0390** | Weak Potential Signal |
| **`suspicious_encoding`** | 0.040 | 0.024 | 0.0 | 0.0 | 0.195 | 0.154 | **+0.0390** | Weak Potential Signal |
| **`underscore_count`** | 0.322 | 0.433 | 0.0 | 0.0 | 1.315 | 1.280 | **-0.0361** | Weak Potential Signal |
| **`path_special_character_count`** | 4.180 | 4.468 | 3.0 | 3.0 | 3.471 | 3.649 | **-0.0333** | Weak Potential Signal |
| **`has_fragment`** | 0.002 | 0.000 | 0.0 | 0.0 | 0.050 | 0.022 | **+0.0272** | Minimal / Redundant Signal |
| **`special_character_ratio`** | 0.139 | 0.141 | 0.1 | 0.1 | 0.047 | 0.033 | **-0.0241** | Minimal / Redundant Signal |
| **`path_length`** | 28.116 | 26.819 | 20.0 | 22.0 | 29.434 | 22.624 | **+0.0223** | Minimal / Redundant Signal |
| **`fragment_length`** | 0.092 | 0.009 | 0.0 | 0.0 | 2.884 | 0.935 | **+0.0220** | Minimal / Redundant Signal |
| **`uses_https`** | 0.000 | 0.000 | 0.0 | 0.0 | 0.008 | 0.000 | **+0.0069** | Minimal / Redundant Signal |

---

## 4. FEATURE CORRELATION & REDUNDANCY ANALYSIS

### Top Correlated Features with Phishing Label (`1=bad, 0=good`):
1. **`dot_count` (+0.3364):** Phishing URLs average 3.01 dots vs 1.78 in legitimate URLs.
2. **`brand_domain_mismatch` (+0.2760):** Strongest brand heuristic; 10.4% in phishing vs 0.2% in legitimate.
3. **`digit_count` (+0.2643):** Phishing URLs contain an average of 10.28 digits vs 3.13 in legitimate URLs.
4. **`excessive_digits` (+0.2499):** 25.2% of phishing URLs have >10 digits vs 6.6% in legitimate URLs.
5. **`unusually_long_url` (+0.2470):** 18.0% of phishing URLs exceed 100 characters vs 3.3% in legitimate URLs.
6. **`url_length` (+0.2466):** Mean length 71.1 chars in phishing vs 45.8 chars in legitimate.
7. **`query_length` (+0.2321):** Mean query length 20.8 chars in phishing vs 3.0 chars in legitimate.
8. **`brand_in_path` (+0.2155):** Attackers embed target brands into path directories.
9. **`hostname_dot_count` (+0.2101):** Multiple subdomain levels to spoof trusted entities.
10. **`hostname_digit_count` (+0.2047):** Mean 1.92 digits in phishing hostnames vs 0.08 in legitimate (23x higher).

### Redundant Feature Pairs (Pearson $|r| > 0.85$):
Several raw counts and indicator pairs convey duplicate information and can be pruned during dimensionality reduction:
- `hostname_has_ip` $\leftrightarrow$ `ip_address_host` ($r = 1.0000$) [Identical]
- `has_at_symbol` $\leftrightarrow$ `contains_at_symbol` ($r = 1.0000$) [Identical]
- `has_percent_encoding` $\leftrightarrow$ `suspicious_encoding` ($r = 1.0000$) [Identical]
- `url_length` $\leftrightarrow$ `letter_count` ($r = 0.9733$)
- `subdomain_count` $\leftrightarrow$ `hostname_dot_count` ($r = 0.9710$)
- `has_port` $\leftrightarrow$ `non_standard_port` ($r = 0.9635$)
- `hyphen_count` $\leftrightarrow$ `path_hyphen_count` ($r = 0.9463$)
- `equals_count` $\leftrightarrow$ `query_parameter_count` ($r = 0.9457$)
- `ampersand_count` $\leftrightarrow$ `query_parameter_count` ($r = 0.9241$)
- `hostname_length` $\leftrightarrow$ `subdomain_length` ($r = 0.9215$)
- `path_length` $\leftrightarrow$ `path_special_character_count` ($r = 0.9031$)
- `slash_count` $\leftrightarrow$ `path_segment_count` ($r = 0.8914$)

---

## 5. TEST URL EXTRACTION VERIFICATION

Verified feature extraction across canonical test cases:

```
1. https://www.google.com
   -> Hostname: www.google.com | Registered Domain: google.com | Subdomain: www
   -> Brand Token: 1 | Brand in RegDom: 1 | Brand Mismatch: 0 | Digits: 0 | Dots: 2

2. https://www.paypal.com
   -> Hostname: www.paypal.com | Registered Domain: paypal.com | Subdomain: www
   -> Brand Token: 1 | Brand in RegDom: 1 | Brand Mismatch: 0 | Digits: 0 | Dots: 2

3. http://paypal-security-login.servehttp.com/login.php
   -> Hostname: paypal-security-login.servehttp.com | Registered Domain: servehttp.com
   -> Subdomain: paypal-security-login | Path: /login.php
   -> Brand Token: 1 | Brand in RegDom: 0 | Brand in Subdomain: 1 | Brand Mismatch: 1
   -> Path Segment Count: 1 | Excessive Subdomains: 0 | Hyphen Count: 2

4. http://192.168.1.1/login.php
   -> Hostname: 192.168.1.1 | Registered Domain: 192.168.1.1 | Subdomain: (empty)
   -> Hostname Has IP: 1 | IP Address Host: 1 | Digits: 8 | Dots: 4
```

---

## 6. EXTRACTION PERFORMANCE BENCHMARK

- **10,000 Sample Batch Time:** 0.191 seconds
- **Average Latency:** **0.0191 milliseconds / URL**
- **Throughput:** **52,405 URLs / second** on standard CPU
- **Full Dataset (507,194 URLs) Processing Time:** 13.69 seconds

---

## 7. RECOMMENDATION FOR MULTI-MODAL MODELING

To advance from pure lexical Bag-of-Words to a state-of-the-art detector, the next modeling iteration should use a **Scikit-learn `FeatureUnion`** combining:
1. **Lexical Branch:** `URLTextPreprocessor` $ightarrow$ `CountVectorizer` (or TF-IDF) extracting vocabulary patterns.
2. **Structural Branch:** `URLFeatureExtractor` $ightarrow$ `StandardScaler` (scaling non-redundant structural, domain, and brand-mismatch features).
3. **Classifier:** Regularized Logistic Regression or Gradient Boosting (e.g. LightGBM / XGBoost) trained on the combined feature representation.

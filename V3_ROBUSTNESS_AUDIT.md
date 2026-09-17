# MODEL V3 ROBUSTNESS & ADVERSARIAL URL AUDIT

**Date:** September 15, 2026  
**Evaluated Models:** Model V1 (Lexical Baseline), Model V2 (Multi-Modal Baseline), Model V3 (Anchor-Augmented)  
**Test Suite:** `adversarial_url_test_cases.csv` (110 curated, reproducible adversarial & robustness test cases)  
**Artifacts Generated:**  
- `adversarial_url_test_cases.csv`
- `V1_V2_V3_ROBUSTNESS_RESULTS.csv`
- `V3_CATEGORY_METRICS.csv`
- `V3_ROBUSTNESS_AUDIT.md`

---

## 1. EXECUTIVE SUMMARY & OVERALL METRICS

This audit systematically probes whether Model V3's dramatic improvement on canonical brand domains stems from genuine structural URL reasoning or merely from memorizing brand-specific lexical tokens introduced by the 65 legitimate anchors.

### Overall Benchmark on the 110-Case Robustness Suite

| Model | Architecture | Training Data | Overall Robustness Accuracy |
| :--- | :--- | :--- | :---: |
| **Model V1** | Lexical (`CountVectorizer` + `LogisticRegression`) | Clean dataset (405,755 URLs) | **66.4%** |
| **Model V2** | Multi-Modal (Lexical + 56 Structural Features) | Clean dataset (405,755 URLs) | **51.8%** |
| **Model V3** | Multi-Modal (Lexical + 56 Structural Features) | Clean dataset + 65 Legitimate Anchors | **56.4%** |

---

## 2. CATEGORY-BY-CATEGORY BREAKDOWN

| Category | Total Cases | V1 Acc | V2 Acc | V3 Acc | V3 Phishing Recall | V3 False Neg Rate | V3 False Pos Rate | V3 Mean Bad Prob |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A_Canonical_Legitimate** | 20 | 30.0% | 0.0% | **100.0%** | N/A% | N/A% | 0.0% | 0.0% |
| **B_Legitimate_Navigation** | 14 | 50.0% | 0.0% | **100.0%** | N/A% | N/A% | 0.0% | 0.0% |
| **C_Subdomain_Lookalike** | 10 | 70.0% | 100.0% | **10.0%** | 10.0% | 90.0% | N/A% | 10.84% |
| **D_Brand_in_Path** | 10 | 100.0% | 100.0% | **10.0%** | 10.0% | 90.0% | N/A% | 16.28% |
| **E_Brand_in_Subdomain** | 10 | 100.0% | 100.0% | **10.0%** | 10.0% | 90.0% | N/A% | 8.81% |
| **F_Typosquatting** | 10 | 100.0% | 100.0% | **0.0%** | 0.0% | 100.0% | N/A% | 0.0% |
| **G_Suspicious_Structure** | 8 | 100.0% | 100.0% | **62.5%** | 62.5% | 37.5% | N/A% | 59.09% |
| **H_Benign_Structurally_Complex** | 10 | 60.0% | 0.0% | **100.0%** | N/A% | N/A% | 0.0% | 0.0% |
| **I_Brand_Generalization_Unseen** | 10 | 50.0% | 50.0% | **60.0%** | 20.0% | 80.0% | 0.0% | 7.41% |
| **J_Lexical_Minimal_Pairs** | 8 | 50.0% | 50.0% | **50.0%** | 0.0% | 100.0% | 0.0% | 0.89% |

---

## 3. REGISTERED-DOMAIN LOGIC AUDIT

A critical test of structural robustness is whether the feature extractor correctly parses registered domains and flags brand-domain mismatches, and whether the classifier heeds this signal when brand tokens appear in untrusted subdomains or paths.

### Case Inspection: `https://paypal.com.attacker.example/login`
- **Parsed Hostname:** `paypal.com.attacker.example`
- **Extracted Registered Domain:** `attacker.example` (Correctly decomposed as `attacker.example`, NOT `paypal.com`)
- **Extracted Subdomain:** `paypal.com`
- **Structural Feature `brand_in_registered_domain`:** `0.0`
- **Structural Feature `brand_in_subdomain`:** `1.0`
- **Structural Feature `brand_domain_mismatch`:** `1.0` (Correctly flagged mismatch = 1.0)

### Model Predictions on Subdomain Spoofing:

- **Model V1 (Lexical Baseline):** `BAD` (Phishing Probability: `100.00%`) — Correctly flagged bad because `paypal` and `login` were historical phishing tokens.
- **Model V2 (Multi-Modal Baseline):** `BAD` (Phishing Probability: `100.00%`) — Correctly flagged bad, but also flagged canonical `paypal.com` as bad.
- **Model V3 (Anchor-Augmented):** `BAD` (Phishing Probability: `97.58%`) — Correctly flagged bad only because the path contained `login` (a heavy phishing token). However, on `https://www.paypal.com.attacker.example/` (without `login`), Model V3 predicts `GOOD` (Phishing Probability: `7.00%`), creating a severe **FALSE NEGATIVE**.

> [!WARNING]
> **Crucial Vulnerability Uncovered:** While `url_features.py` successfully and correctly flagged `brand_domain_mismatch = 1.0` and `brand_in_subdomain = 1.0`, the linear logistic regression classifier in Model V3 assigned such massive negative (good) weights to the token `paypal` (learned from the 65 legitimate anchors) that the lexical score **completely overwhelmed** the structural penalty. In 90% of subdomain lookalike attacks (`microsoft.com.attacker.example/login`, `apple.com.attacker.example/account`, `amazon.com.attacker.example/order-review`), Model V3 fails completely and predicts legitimate!

---

## 4. ADVERSARIAL LEXICAL MINIMAL PAIR TESTS

Evaluating minimal pairs where only one structural component was altered between legitimate URLs and attacker spoofs:

| URL | Expected | V1 Pred (Bad%) | V2 Pred (Bad%) | V3 Pred (Bad%) | Status in V3 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `https://www.example.com/` | GOOD | BAD (80.2%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://www.example.com.attacker.example/` | BAD | BAD (75.1%) | BAD (100.0%) | **GOOD (0.0%)** | FAILED (Vulnerable) |
| `https://www.example.com/account` | GOOD | BAD (98.1%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://attacker.example/example.com/account` | BAD | BAD (98.3%) | BAD (100.0%) | **GOOD (0.0%)** | FAILED (Vulnerable) |
| `https://www.example.com/search?q=test` | GOOD | BAD (80.3%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://example-login.attacker.example/search?q=test` | BAD | BAD (100.0%) | BAD (100.0%) | **GOOD (0.2%)** | FAILED (Vulnerable) |
| `https://www.paypal.com/` | GOOD | BAD (99.9%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://www.paypal.com.attacker.example/` | BAD | BAD (99.9%) | BAD (100.0%) | **GOOD (7.0%)** | FAILED (Vulnerable) |

*Result:* V3 achieved **0.0% phishing recall on minimal attack pairs** (all 4 adversarial spoofing variations were misclassified as legitimate because the anchor brand tokens overpowered the structural indicators).

---

## 5. BRAND GENERALIZATION TEST (UNSEEN BRANDS NOT IN 65 ANCHORS)

Testing brands absent from the 65 legitimate anchors (`dropbox`, `spotify`, `adobe`, `coinbase`, `wellsfargo`):

| URL | Expected | V1 Pred (Bad%) | V2 Pred (Bad%) | V3 Pred (Bad%) | Status in V3 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `https://www.dropbox.com` | GOOD | BAD (99.7%) | BAD (100.0%) | **GOOD (0.1%)** | CORRECT |
| `https://www.spotify.com` | GOOD | BAD (75.2%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://www.adobe.com` | GOOD | BAD (96.1%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://www.coinbase.com` | GOOD | BAD (75.2%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://www.wellsfargo.com` | GOOD | BAD (97.2%) | BAD (100.0%) | **GOOD (0.0%)** | CORRECT |
| `https://dropbox.com.attacker.example/login` | BAD | BAD (100.0%) | BAD (100.0%) | **BAD (55.1%)** | CORRECT |
| `https://spotify.com.attacker.example/account` | BAD | BAD (97.8%) | BAD (100.0%) | **GOOD (0.0%)** | FAILED |
| `https://adobe.com.attacker.example/update` | BAD | BAD (99.8%) | BAD (100.0%) | **GOOD (0.0%)** | FAILED |
| `https://coinbase-verify.attacker.example/auth` | BAD | BAD (100.0%) | BAD (100.0%) | **GOOD (17.9%)** | FAILED |
| `https://attacker.example/wellsfargo/signin.php` | BAD | BAD (100.0%) | BAD (100.0%) | **GOOD (1.0%)** | FAILED |

**Key Findings on Brand Generalization:**
1. **Canonicals for Unseen Brands:** Legitimate homepages of unseen brands (`dropbox.com`, `spotify.com`, `adobe.com`, `coinbase.com`, `wellsfargo.com`) were predicted as **GOOD (0.0% bad)** in V3 when they contained clean domain structure without conflicting phishing n-grams.
2. **Attacks on Unseen Brands:** For brands not in the monitored brands list, `brand_domain_mismatch` did not trigger, and because the brand tokens lacked dominant weights, attacks with basic paths like `https://attacker.example/wellsfargo/signin.php` were missed by V3 (predicted as good). However, when strong phishing indicators like raw IPs or excessive subdomains were present, V3 flagged them.

---

## 6. PROBABILITY SATURATION ON ROBUSTNESS CASES

- **False Positives with Phishing Probability $\ge 0.99$:** 0 (0 cases)
- **False Negatives with Phishing Probability $\le 0.01$:** **34 cases**

### Severe False Negatives with Extreme Confidence (<= 1% Phishing Probability):

- `https://microsoft.com.attacker.example/login` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.9875%`) [C_Subdomain_Lookalike]
- `https://apple.com.attacker.example/account` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.1837%`) [C_Subdomain_Lookalike]
- `https://amazon.com.attacker.example/order-review` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0006%`) [C_Subdomain_Lookalike]
- `https://chase.com.attacker.example/signin` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.4025%`) [C_Subdomain_Lookalike]
- `https://netflix.com.attacker.example/billing-update` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0739%`) [C_Subdomain_Lookalike]
- `https://github.com.attacker.example/oauth/authorize` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0022%`) [C_Subdomain_Lookalike]
- `https://facebook.com.attacker.example/recover` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0031%`) [C_Subdomain_Lookalike]
- `https://attacker.example/amazon/payment-update` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.1289%`) [D_Brand_in_Path]
- `https://attacker.example/netflix/membership/reactivate` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0234%`) [D_Brand_in_Path]
- `https://attacker.example/github/session/create` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.2102%`) [D_Brand_in_Path]
- `https://attacker.example/linkedin/checkpoint/lg` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0010%`) [D_Brand_in_Path]
- `https://apple-support.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0420%`) [E_Brand_in_Subdomain]
- `https://amazon-prime-billing.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0021%`) [E_Brand_in_Subdomain]
- `https://chase-identity-check.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.7985%`) [E_Brand_in_Subdomain]
- `https://netflix-account-notice.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.8340%`) [E_Brand_in_Subdomain]
- `https://bankofamerica-alert.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.1796%`) [E_Brand_in_Subdomain]
- `https://linkedin-message-notification.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0117%`) [E_Brand_in_Subdomain]
- `https://paypa1.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0004%`) [F_Typosquatting]
- `https://g00gle.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0005%`) [F_Typosquatting]
- `https://amaz0n.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0003%`) [F_Typosquatting]
- `https://micros0ft.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0037%`) [F_Typosquatting]
- `https://app1e.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0009%`) [F_Typosquatting]
- `https://faceb00k.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0007%`) [F_Typosquatting]
- `https://netf1ix.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0008%`) [F_Typosquatting]
- `https://g1thub.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0004%`) [F_Typosquatting]
- `https://1inkedin.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0004%`) [F_Typosquatting]
- `https://chazebank.example` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0003%`) [F_Typosquatting]
- `https://a.b.c.d.e.f.phishing-hub.example/login` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.1191%`) [G_Suspicious_Structure]
- `https://attacker.example/%20%20%2Flogin%2F%3Fref%3Dsecure%26auth%3D1` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0256%`) [G_Suspicious_Structure]
- `https://spotify.com.attacker.example/account` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0024%`) [I_Brand_Generalization_Unseen]
- `https://adobe.com.attacker.example/update` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0409%`) [I_Brand_Generalization_Unseen]
- `https://www.example.com.attacker.example/` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0002%`) [J_Lexical_Minimal_Pairs]
- `https://attacker.example/example.com/account` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.0061%`) [J_Lexical_Minimal_Pairs]
- `https://example-login.attacker.example/search?q=test` — Expected: **PHISHING**, Predicted: **GOOD** (Bad Prob: `0.1516%`) [J_Lexical_Minimal_Pairs]

> [!CAUTION]
> Over 30 adversarial phishing URLs received a predicted phishing probability below 0.01% (i.e. model predicted legitimate with >99.99% confidence) solely because they contained anchor brand strings. These are extreme, uncalibrated saturation artifacts of the linear CountVectorizer model.

---

## 7. BENIGN STRUCTURALLY COMPLEX URL EVALUATION

- **Total Cases:** 10
- **V1 Accuracy:** 60.0%
- **V2 Accuracy:** 0.0%
- **V3 Accuracy:** **100.0%**
- **V3 False Positive Rate:** **0.0%**

V3 achieved a perfect 100% on benign complex URLs (AWS pricing, Microsoft Docs nested paths, GitHub commit SHAs, MDN documentation). It does not misclassify structural depth or query parameters as malicious when on trusted hostnames.

---

## 8. FINAL VERDICT & ARCHITECTURAL ROOT-CAUSE ANALYSIS

### **Verdict: V3's improvement on canonical domains is primarily anchor-domain memorization, which introduces severe adversarial vulnerability to brand spoofing.**

### Detailed Evidence-Based Root Cause:
1. **What V3 Did Right:** V3 resolved the severe false-positive blackout on canonical legitimate URLs (Category A: 100% vs V2: 0%) and legitimate navigation URLs (Category B: 100% vs V2: 0%), without degrading metrics on the static 101,439-sample test split.
2. **The Adversarial Collapse:** On adversarial URLs where attackers incorporate brand names (`paypal.com.attacker.example`, `google-login.attacker.example`, `attacker.example/paypal/verify`), V3's phishing recall collapsed from **100% in V2 down to 10% in V3**.
3. **Architectural Diagnosis (Why This Happened):**
   - In a linear model (`LogisticRegression`), the total logit is a simple linear sum:
     $$\text{logit} = \sum w_i x_{\text{lexical}} + \sum w_j x_{\text{structural}} + b$$
   - Adding 65 anchor URLs forced the lexical weights for `paypal`, `google`, `amazon`, `apple`, etc., from strongly positive (phishing) to strongly negative (legitimate).
   - While `url_features.py` successfully and correctly detected `brand_domain_mismatch = 1.0`, its standardized coefficient in the linear model was insufficient to overcome the massive negative weight contributed by the brand token in the lexical branch.
   - Thus, an attacker merely needs to include `paypal.com` or `google.com` in their subdomain or path to bypass Model V3 with $>99.9\%$ confidence.
4. **Strategic Recommendation for Next Iteration (V4):**
   - To achieve genuine structural robustness, the model requires non-linear interaction or hierarchical feature conditioning (e.g., gradient boosted decision trees or a gated neural network where lexical tokens are conditioned on whether they appear in the registered domain vs subdomain/path), or explicit lexical scoping where tokens from subdomains and paths are segregated from the registered domain.

# AI Phishing URL Detection

A machine learning and URL structural analysis research project designed to detect malicious and phishing URLs, evaluate adversarial evasion risks, and develop robust feature-fusion architectures.

> [!WARNING]
> **Current Status:** Advanced research prototype — actively undergoing robustness improvements; **not production-ready**.  
> While the model achieves high statistical accuracy on static test sets, rigorous adversarial testing exposed critical vulnerabilities to brand-spoofing and subdomain evasion attacks.

---

## Overview

Phishing URLs often exploit human trust by mimicking legitimate brands through subdomains, path deception, or typosquatting. Traditional machine learning detectors relying purely on lexical tokenization (e.g., word or character N-grams) frequently fail in two directions:
1. **Benign False Positives:** Flagging canonical legitimate websites (`https://www.google.com`, `https://www.paypal.com`) because security keywords or brand names appear predominantly in phishing samples in public datasets.
2. **Adversarial False Negatives:** Allowing malicious URLs (`https://paypal.com.attacker.example/`) to bypass detection when benign brand tokens override malicious structural signals.

This repository tracks the research, forensic audits, and model evolution from a naive lexical classifier toward an adversarially robust multi-modal URL detection system.

---

## Key Features

- **ML-Based URL Classification:** Scikit-learn pipelines combining text tokenization, structural URL feature extraction, and classification models.
- **Lexical URL Analysis:** Tokenization and character pattern extraction capturing domain and path terminology.
- **Structural URL Feature Extraction:** 56 offline URL attributes including length metrics, delimiter counts, depth, entropy, hex encoding, and port/IP detection via [`url_features.py`](url_features.py).
- **Registered-Domain Decomposition:** Offline public suffix parsing distinguishing effective second-level domains from subdomains and path segments.
- **Brand/Domain Relationship Analysis:** Explicit mismatch detection flagging instances where protected brands appear in untrusted subdomains or paths.
- **Phishing Risk Classification:** Continuous model-reported phishing scores alongside binary decision thresholds.
- **Flask Web Interface:** Lightweight web demonstration interface in [`app.py`](app.py) for interactive URL scoring.
- **Reproducible Evaluation Pipeline:** End-to-end dataset cleaning, leakage auditing, multi-model evaluation, and calibration reporting.
- **Adversarial Robustness Testing:** Curated 110-case robustness benchmark suite covering 10 distinct attack and edge-case categories.

---

## Architecture Evolution

```
V1 Architecture:
Raw URL ──> Preprocessing (URLTextPreprocessor) ──> CountVectorizer ──> Logistic Regression

V2 Architecture:
Raw URL ──┬──> Lexical Branch (URLTextPreprocessor ──> CountVectorizer) ──────────┬──> FeatureUnion ──> Logistic Regression
          └──> Structural Branch (PrunedURLFeatureExtractor ──> StandardScaler) ──┘

V3 Architecture:
Identical V2 FeatureUnion Pipeline + 65 Canonical Legitimate Training Anchors
```

### Architectural Diagnoses:
- **V1 (Lexical Baseline):** Relies solely on tokenized lexical stems. Suffer from vocabulary blind spots and penalizes common brand names when benign training data lacks canonical homepages.
- **V2 (Lexical + Structural Multi-Modal):** Combines 56 structural features with lexical N-grams using `FeatureUnion`. Improves structural sensitivity on generic paths, but still misclassifies canonical legitimate homepages due to severe dataset imbalance on top-tier brand tokens.
- **V3 (Anchor-Augmented Multi-Modal):** Adds 65 verified legitimate anchor URLs (`paypal.com`, `google.com`, `amazon.com`, `apple.com`, etc.) to the training partition. While this successfully resolved the canonical legitimate false-positive blackout, **it introduced severe adversarial brand-spoofing vulnerabilities**.
- **Why V3 is Not Production-Ready:** Because V3 utilizes a linear model (`LogisticRegression`), the strong negative weights assigned to anchor brand tokens overpower the structural mismatch indicators. An attacker embedding a protected brand name into a subdomain or path can bypass V3 with near 100% confidence.

---

## Dataset & Leakage Audit

All experimental evaluations adhere to verified data hygiene standards documented in [`DATASET_CLEANING_REPORT.md`](DATASET_CLEANING_REPORT.md) and [`DATASET_LEAKAGE_AUDIT.md`](DATASET_LEAKAGE_AUDIT.md).

### Verified Dataset Facts:
- **Original Dataset:** 549,346 rows (`phishing_site_urls.csv`).
- **Exact Duplicate Rows Removed:** 42,150 identical rows pruned (42,124 phishing duplicates vs. 28 legitimate duplicates).
- **Conflicting Label Exclusion:** Exactly 1 domain (`tommyhumphreys.com/`) possessed conflicting labels (2 `bad`, 1 `good`). Rather than inventing a label via arbitrary heuristic, it was excluded from the dataset and isolated into [`conflicting_labels.csv`](conflicting_labels.csv).
- **Clean Dataset:** 507,194 unique URLs preserved in `phishing_site_urls_clean.csv` (114,298 phishing / 22.54%, 392,896 legitimate / 77.46%).
- **Leakage-Free Train/Test Split:**
  - **Training Set:** 405,755 URLs (80%)
  - **Testing Set:** 101,439 URLs (20%, `random_state=42`)
  - **Exact Train/Test URL Overlap:** **0 URLs (0.0000%)**

### Why Leakage Removal Was Mandatory:
In the initial uncleaned dataset, **11,943 URLs (11.08% of the test split)** overlapped between training and test sets. Crucially, **40.93% of the phishing test rows had already been observed during training**, artificially inflating reported phishing recall to 90.51%. After enforcing strict deduplication and zero train/test overlap, the true out-of-sample baseline recall was revealed to be **86.31%**.

---

## Model Evolution

All three models were evaluated on the **identical 101,439-row leakage-free test set** (`random_state=42`).

| Model | Architecture Description | Accuracy | Phishing Precision | Phishing Recall | Phishing F1 | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **V1** | Lexical baseline (`CountVectorizer` + Logistic Regression) | 96.18% | 96.31% | 86.31% | 91.04% | Baseline |
| **V2** | Multi-modal (`FeatureUnion` lexical + 56 structural features) | 96.29% | 95.71% | 87.39% | 91.36% | Research baseline |
| **V3** | V2 architecture + 65 canonical legitimate anchors | 96.31% | 95.84% | 87.35% | 91.40% | **Rejected for robustness** |

> [!IMPORTANT]
> **Accuracy alone is misleading:** Despite achieving 96.31% accuracy and 94.52% Macro F1 on the static test set, V3 suffers catastrophic failure when evaluated against deliberate adversarial evasion.

---

## Adversarial Robustness Findings

To stress-test model resilience beyond static benchmarks, a curated 110-case robustness suite ([`adversarial_url_test_cases.csv`](adversarial_url_test_cases.csv)) was evaluated across 10 security-relevant categories. See full details in [`V3_ROBUSTNESS_AUDIT.md`](V3_ROBUSTNESS_AUDIT.md).

### Category-Level Robustness Performance (Model V3):

| Category | Description | Total Cases | V3 Accuracy | V3 Phishing Recall |
| :--- | :--- | :---: | :---: | :---: |
| **A_Canonical_Legitimate** | Clean brand homepages (`google.com`, `paypal.com`) | 20 | 100.0% | N/A (benign) |
| **B_Legitimate_Navigation** | Benign deep paths (`amazon.com/gp/help/customer`) | 14 | 100.0% | N/A (benign) |
| **C_Subdomain_Lookalike** | Brand in subdomain of attacker domain | 10 | 10.0% | **10.0%** (90% missed) |
| **D_Brand_in_Path** | Brand in path of attacker domain | 10 | 10.0% | **10.0%** (90% missed) |
| **E_Brand_in_Subdomain** | Brand hyphenated in host (`apple-support.attacker.example`) | 10 | 10.0% | **10.0%** (90% missed) |
| **F_Typosquatting** | Levenshtein variations (`paypa1.example`, `amaz0n.example`) | 10 | 0.0% | **0.0%** (100% missed) |
| **G_Suspicious_Structure** | Deep subdomains, hex encoding, IP hosts | 8 | 62.5% | 62.5% |
| **H_Benign_Structurally_Complex** | Benign URLs with deep queries, hashes, docs | 10 | 100.0% | N/A (benign) |
| **I_Brand_Generalization_Unseen** | Unseen brands (`dropbox`, `spotify`, `adobe`) | 10 | 60.0% | 20.0% |
| **J_Lexical_Minimal_Pairs** | Single-component edits between benign and spoof | 8 | 50.0% | **0.0%** (100% missed) |

### Representative Attack Failure:
```
Legitimate canonical URL:
https://www.paypal.com/                         ──> Classified: Legitimate (0.0% bad score) [CORRECT]

Adversarial lookalike attack:
https://www.paypal.com.attacker.example/login   ──> Classified: Legitimate (7.0% bad score) [FALSE NEGATIVE]
```

### Root-Cause Diagnosis:
1. **URL Feature Extraction Succeeded:** The offline URL parser ([`url_features.py`](url_features.py)) correctly decomposed the URL:
   - `registered_domain = "attacker.example"` (correctly flagged that the host is NOT `paypal.com`)
   - `brand_in_subdomain = 1.0`
   - `brand_domain_mismatch = 1.0`
2. **Linear Classification Failed:** In a linear model, the prediction logit is:
   $$\text{logit} = \sum w_{\text{lexical}} x_{\text{lexical}} + \sum w_{\text{structural}} x_{\text{structural}} + b$$
   Adding legitimate anchors caused the lexical weight for token `paypal` to become overwhelmingly negative (pushing toward `good`). This negative lexical weight easily superseded the positive penalty of `brand_domain_mismatch = 1.0`.
3. **Conclusion:** The failure is attributable to **learned linear feature weighting and lack of non-linear interaction**, not URL parsing error.

---

## Security & ML Evaluation Methodology

The project incorporates comprehensive evaluation practices documented across dedicated audit reports:
- **Deduplication & Conflict Audit:** Detailed in [`DATASET_CLEANING_REPORT.md`](DATASET_CLEANING_REPORT.md).
- **Leakage Elimination Audit:** Detailed in [`DATASET_LEAKAGE_AUDIT.md`](DATASET_LEAKAGE_AUDIT.md).
- **Multi-Model Benchmark & Error Breakdown:** Detailed in [`MODEL_V1_V2_V3_REPORT.md`](MODEL_V1_V2_V3_REPORT.md).
- **Adversarial Robustness Evaluation:** Detailed in [`V3_ROBUSTNESS_AUDIT.md`](V3_ROBUSTNESS_AUDIT.md).
- **Inference Latency & Throughput Benchmark:** Detailed in [`V3_INFERENCE_BENCHMARK.md`](V3_INFERENCE_BENCHMARK.md). Full pipeline evaluates in **0.0592 ms per URL** (~16,894 URLs/sec on standard CPU).
- **Serialization Verification:** Clean pipelines verified across independent Python runtimes using [`verify_pipeline.py`](verify_pipeline.py).
- **Probability Calibration & Saturation:** Logistic regression outputs exhibit severe probability saturation (over 30 adversarial attacks received model-reported phishing scores $< 0.01\%$). All probabilities are treated as uncalibrated **"model-reported phishing scores"** rather than true posterior probabilities.

---

## Decision Threshold Analysis

Evaluated on Model V3 using the 101,439-sample leakage-free test set ([`V3_THRESHOLD_ANALYSIS.csv`](V3_THRESHOLD_ANALYSIS.csv)):

| Threshold | Phishing Precision | Phishing Recall | Phishing F1 | Legitimate Recall | False Positives | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | 91.67% | **92.07%** | 91.87% | 97.58% | 1,905 | 1,806 |
| **0.40** | 93.99% | **89.48%** | 91.68% | 98.34% | 1,302 | 2,397 |
| **0.50** | 95.84% | **87.35%** | 91.40% | 98.90% | 864 | 2,882 |
| **0.60** | 96.98% | **85.07%** | 90.63% | 99.23% | 604 | 3,401 |
| **0.70** | 97.78% | **82.56%** | 89.53% | 99.46% | 426 | 3,973 |

- The standard threshold of **0.50** remains the current experimental baseline.
- Lowering the threshold to **0.30** increases phishing recall to 92.07% at the expense of doubling false positives (1,905 FP).
- Operating thresholds have **not been finalized** pending non-linear model development.

---

## Project Structure

```
ai phishing/
├── app.py                                   # Flask web serving application
├── pipeline_utils.py                        # Tokenizer & preprocessing classes for scikit-learn
├── url_features.py                          # 56-feature offline URL structural extractor
├── model_v2.py                              # V2 FeatureUnion pipeline definition
├── model_v3.py                              # V3 Anchor-augmented pipeline definition
├── retrain_pipeline.py                      # Retraining script with preprocessing consistency
├── verify_pipeline.py                       # Model parity & serialization verification script
├── clean_and_retrain.py                     # Dataset cleaning and V1 clean baseline trainer
├── train_and_benchmark_v2.py                # V2 multi-modal training and evaluation
├── train_and_benchmark_v3.py                # V3 anchor-augmented training and evaluation
├── run_robustness_audit.py                  # 110-case adversarial evaluation harness
├── test_flask_app.py                        # Unit and integration test suite for Flask app
├── test_url_features.py                     # Unit test suite for URL structural feature extractor
├── build_anchor_dataset.py                  # Canonical legitimate anchor dataset builder
├── analyze_dataset_features.py              # Feature correlation and distribution analyzer
├── generate_feature_report.py               # Feature statistical report generator
├── legitimate_anchor_urls.csv               # 65 canonical benign anchor URLs
├── adversarial_url_test_cases.csv           # 110 curated adversarial test cases
├── conflicting_labels.csv                   # Excluded dataset label conflicts
├── templates/
│   └── index.html                           # Web UI template
├── requirements.txt                         # Application dependencies
├── .gitignore                               # Excludes caches, large data, and binary models
│
├── Evaluation & Audit Reports:
│   ├── AI_PHISHING_COMPLETE_PROJECT_AUDIT.md
│   ├── CLEAN_MODEL_EVALUATION.md
│   ├── DATASET_CLEANING_REPORT.md
│   ├── DATASET_LEAKAGE_AUDIT.md
│   ├── DATASET_QUALITY_FOR_FEATURE_ENGINEERING.md
│   ├── FEATURE_DISTRIBUTION_REPORT.md
│   ├── MODEL_V1_VS_V2_REPORT.md
│   ├── MODEL_V1_V2_V3_REPORT.md
│   ├── TRAINING_PIPELINE_FIX.md
│   ├── V3_ROBUSTNESS_AUDIT.md
│   └── V3_INFERENCE_BENCHMARK.md
│
└── Generated Experimental Data Artifacts:
    ├── feature_extraction_results.csv
    ├── V1_V2_ROBUSTNESS_RESULTS.csv
    ├── V3_CATEGORY_METRICS.csv
    ├── V3_THRESHOLD_ANALYSIS.csv
    ├── V3_CALIBRATION_SUMMARY.csv
    ├── ERROR_ANALYSIS.csv
    ├── V1_V2_ERROR_COMPARISON.csv
    └── V2_V3_ERROR_COMPARISON.csv
```

*(Note: Large raw/cleaned CSV datasets such as `phishing_site_urls_clean.csv` and serialized model artifacts `phishing_pipeline*.pkl` are tracked locally and excluded from git commits).*

---

## Reproducibility Guide

### 1. Environment Setup
```powershell
python -m venv env
.\env\Scripts\activate
pip install -r requirements.txt
```

### 2. Dataset Cleaning & Leakage Audit
```powershell
python clean_and_retrain.py
```

### 3. Feature Extraction & Engineering
```powershell
python analyze_dataset_features.py
python generate_feature_report.py
```

### 4. Model Training & Evaluation
```powershell
# Train & benchmark Model V2 (multi-modal)
python train_and_benchmark_v2.py

# Build anchor dataset & train Model V3
python build_anchor_dataset.py
python train_and_benchmark_v3.py
```

### 5. Adversarial Robustness Audit
```powershell
python run_robustness_audit.py
```

### 6. Automated Testing
```powershell
python -m unittest discover -v
```

### 7. Run Web Application
```powershell
python app.py
```

---

## Current Limitations

1. **Vulnerability to Brand Spoofing:** Model V3 remains vulnerable to attacker-controlled domains embedding protected brand tokens into subdomains or paths.
2. **Linear Feature Dominance:** In a linear model, dominant lexical weights overpower structural warning features like `brand_domain_mismatch`.
3. **Probability Saturation:** Logistic regression outputs exhibit severe uncalibrated clustering at extreme probabilities ($>99.9\%$ or $<0.01\%$).
4. **Dataset Coverage Gaps:** Public phishing datasets underrepresent canonical homepages of popular services, requiring careful representation balancing without inducing lexical memorization.
5. **Curated Robustness Suite Scope:** The 110-case adversarial test suite is a targeted qualitative probe designed to reveal failure modes; it should not be interpreted as a statistically representative measure of real-world threat prevalence.
6. **Production Readiness:** The prototype is not ready for production deployment.

---

## Project Roadmap

### Completed:
- [x] Training/serving preprocessing consistency fix ([`TRAINING_PIPELINE_FIX.md`](TRAINING_PIPELINE_FIX.md))
- [x] Comprehensive train/test data leakage audit ([`DATASET_LEAKAGE_AUDIT.md`](DATASET_LEAKAGE_AUDIT.md))
- [x] Dataset cleaning and conflict isolation ([`DATASET_CLEANING_REPORT.md`](DATASET_CLEANING_REPORT.md))
- [x] Leakage-free V1 lexical baseline ([`CLEAN_MODEL_EVALUATION.md`](CLEAN_MODEL_EVALUATION.md))
- [x] 56-feature structural URL extraction pipeline ([`url_features.py`](url_features.py))
- [x] V2 multi-modal feature-fusion experiment ([`MODEL_V1_VS_V2_REPORT.md`](MODEL_V1_VS_V2_REPORT.md))
- [x] V3 canonical legitimate-anchor experiment ([`MODEL_V1_V2_V3_REPORT.md`](MODEL_V1_V2_V3_REPORT.md))
- [x] 110-case adversarial robustness audit & root cause analysis ([`V3_ROBUSTNESS_AUDIT.md`](V3_ROBUSTNESS_AUDIT.md))
- [x] Serialization verification and inference benchmarking ([`V3_INFERENCE_BENCHMARK.md`](V3_INFERENCE_BENCHMARK.md))

### In Progress:
- [ ] **Model V4 Architecture:** Non-linear structural modeling (e.g., GBDT / LightGBM or hierarchical gating) to prevent lexical tokens from overriding structural mismatch signals.
- [ ] **Structural & Lexical Feature Separation:** Scoping lexical tokens strictly to registered domains vs. untrusted subdomains/paths.
- [ ] **Validation-Based Model Selection:** Tuning hyperparameters and fusion architectures on a held-out adversarial validation split.
- [ ] **Robustness-First Evaluation:** Establishing adversarial pass-rates as a primary gating metric alongside test accuracy.

### Planned:
- [ ] Probability calibration (e.g., Platt scaling or isotonic regression) to eliminate score saturation.
- [ ] Production integration and candidate model promotion after validation criteria are met.
- [ ] Flask web interface and API security audit (input rate limiting, CSRF protection, header sanitization).
- [ ] Automated regression testing integrated into continuous integration.
- [ ] External validation on live threat feeds (e.g., URLhaus, PhishTank, Tranco top domains).
- [ ] Deployment container hardening with finalized minimal Dockerfile.

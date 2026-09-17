# DATASET LEAKAGE AUDIT REPORT

**Target Dataset:** `phishing_site_urls.csv/phishing_site_urls.csv`  
**Associated Model:** `phishing_pipeline.pkl` / `retrain_pipeline.py`  
**Audit Date:** September 15, 2026  
**Auditor:** Independent Technical & Security AI Audit Subsystem  
**Scope:** Dataset duplicates, train/test contamination, label conflicts, brand token bias, and class quality.

---

## 1. DATASET OVERVIEW

| Attribute | Verified Value |
| :--- | :--- |
| **File Path** | `phishing_site_urls.csv/phishing_site_urls.csv` |
| **File Size on Disk** | 31,567,326 bytes (~30.1 MB) |
| **Total Rows** | 549,346 |
| **Total Columns** | 2 (`URL`, `Label`) |
| **URL Column** | `URL` (object/string) |
| **Label Column** | `Label` (object/string) |
| **Missing URL Count** | 0 nulls (0.0%) |
| **Missing Label Count** | 0 nulls (0.0%) |

---

## 2. DUPLICATE ANALYSIS

An exhaustive scan was conducted to identify exact row duplications, URL-level duplications, and label discrepancies:

```
================================================================================
DUPLICATE SCAN RESULTS
================================================================================
Total Rows                      : 549,346
Unique URLs                     : 507,195
Duplicate Rows (Exact match)    : 42,150 (7.67% of dataset)
Duplicate URLs (Any label)      : 42,151 (7.67% of dataset)
Rows Involved in Multi-Occur    : 77,074 (14.03% of all rows)
================================================================================
```

### Duplicate Rows Class Breakdown
Among the 77,074 rows involved in duplicate URL occurrences:
- **Phishing (`bad`):** 77,019 rows (**99.93%**)
- **Legitimate (`good`):** 55 rows (**0.07%**)

*Finding:* Duplication in this dataset is not uniform; it is almost entirely concentrated in the malicious (`bad`) class, heavily skewing model feature frequencies and evaluation.

### Conflicting Labels
Exactly **1 URL** in the dataset has contradictory ground truth labels:
- **URL:** `tommyhumphreys.com/`
- **Occurrences:** 3 total rows
  - `bad`: 2 rows
  - `good`: 1 row

---

## 3. TRAIN/TEST SPLIT REPRODUCTION

To audit contamination during evaluation, the exact methodology used in `retrain_pipeline.py` was reproduced:
- **Input Data:** `df['URL']`, `df['Label']`
- **Split Ratio:** 80% Train, 20% Test (`test_size=0.2`)
- **Random State:** `random_state=42`
- **Stratification:** None (matching baseline)
- **Train Set Size:** 439,476 rows
- **Test Set Size:** 109,870 rows

---

## 4. TRAIN/TEST URL OVERLAP & CONTAMINATION

Comparing unique URLs in the training set against the test set:

```
================================================================================
TRAIN / TEST OVERLAP AUDIT
================================================================================
Unique URLs in Training Set     : 407,314
Unique URLs in Testing Set      : 107,740
TRAIN/TEST UNIQUE URL OVERLAP   : 11,943
TRAIN/TEST OVERLAP RATE         : 11.0850% (of unique test URLs)
Test Rows Appearing in Training : 12,781 rows
Test Set Contamination Rate     : 11.6328% (of all 109,870 test rows)
================================================================================
```

### Critical Class-Level Contamination
When breaking down the 12,781 contaminated test rows by class:
- **Contaminated Phishing (`bad`) Rows:** **12,770 rows**
- **Contaminated Legitimate (`good`) Rows:** **11 rows**
- **Total Phishing Rows in Entire Test Set:** **31,200 rows**

$$\text{Phishing Contamination Rate} = \frac{12,770}{31,200} = \mathbf{40.93\%}$$

> [!CAUTION]
> **40.93% of the entire phishing test set was already present in the training set.**  
> Rather than generalizing to novel phishing URLs, more than 4 out of every 10 malicious samples evaluated on the test set were identical instances the model had already memorized during training.

---

## 5. DUPLICATE ROW DISTRIBUTION

The 42,150 redundant duplicate rows were partitioned by the random split as follows:
- **Duplicate rows entirely within Training Set:** 28,078 rows
- **Duplicate rows entirely within Testing Set:** 2,130 rows
- **Duplicate URLs spanning BOTH Training and Testing:** 11,943 URLs (accounting for 12,781 test rows)

---

## 6. LABEL DISTRIBUTION

| Dataset Split | Class | Count | Percentage |
| :--- | :--- | :--- | :--- |
| **Full Dataset** | `good` (Legitimate) | 392,924 | 71.53% |
| | `bad` (Phishing) | 156,422 | 28.47% |
| **Training Set (80%)** | `good` (Legitimate) | 314,254 | 71.51% |
| | `bad` (Phishing) | 125,222 | 28.49% |
| **Testing Set (20%)** | `good` (Legitimate) | 78,670 | 71.60% |
| | `bad` (Phishing) | 31,200 | 28.40% |

While the macro class proportions are preserved across the random split (~71.5% to 28.5%), the distribution of duplicate samples is severely biased towards the phishing class.

---

## 7. RANDOM SPLIT LEAKAGE ANALYSIS

### Why This Constitutes Direct Data Leakage
Data leakage occurs when information from outside the training dataset is used to create the model, or when test evaluation does not reflect independent, unseen real-world data.

In this project:
1. The random split was performed on the raw, un-deduplicated dataset.
2. Identical URLs were randomly distributed into both `x_train` and `x_test`.
3. The evaluation metric measures memorization on 12,781 test instances rather than true out-of-sample generalization.
4. Because 99.93% of duplicate rows belong to the phishing class, test metrics for phishing precision, recall, and F1-score are artificially subsidized by training duplicates.

---

## 8. NEAR-DUPLICATE ANALYSIS

URLs were normalized using standard structural transformations:
- Lowercased
- Stripped protocol (`http://`, `https://`)
- Stripped `www.` prefix
- Stripped trailing slashes (`/`)

```
Unique normalized URLs in Training Set: 407,235
Unique normalized URLs in Testing Set : 107,345
Normalized Train/Test URL Overlap     : 13,134 unique URLs
Normalized Contamination Rate        : 12.2353% (of test set)
```

Beyond the 11,943 exact-string duplicates, an additional **1,191 URLs** in the test set are trivial syntactic variants of training URLs (differing only by protocol, `www.`, or trailing slash).

---

## 9. BRAND-NAME BIAS & TOKEN ANALYSIS

To understand why legitimate domains (such as `google.com`, `paypal.com`, and `example.com`) are flagged as phishing by the model, token frequencies and Logistic Regression coefficients were audited:

### Token Distribution & Model Weights

| Token | Bad Samples | Good Samples | Total | Bad % | Good % | Stemmed Token | Vocab Index | Logistic Regr Coef |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **google** | 3,514 | 1,130 | 4,644 | 75.67% | 24.33% | `googl` | 105129 | **-0.5308** |
| **paypal** | 10,275 | 1 | 10,276 | **99.99%** | 0.01% | `paypal` | 199187 | **-5.7171** |
| **amazon** | 190 | 5,280 | 5,470 | 3.47% | **96.53%** | `amazon` | 9623 | **+1.9686** |
| **microsoft** | 271 | 563 | 834 | 32.49% | 67.51% | `microsoft` | 167898 | **+0.8386** |
| **apple** | 268 | 780 | 1,048 | 25.57% | 74.43% | `appl` | 13040 | **-0.6682** |
| **bank** | 1,337 | 1,523 | 2,860 | 46.75% | 53.25% | `bank` | 21044 | **-0.4606** |
| **login** | 21,841 | 107 | 21,948 | **99.51%** | 0.49% | `login` | 155137 | **-5.2380** |
| **secure** | 5,575 | 127 | 5,702 | **97.77%** | 2.23% | `secur` | 233577 | **-2.0835** |
| **signin** | 960 | 59 | 1,019 | **94.21%** | 5.79% | `signin` | 238077 | **-3.6178** |
| **verify** | 840 | 4 | 844 | **99.53%** | 0.47% | `verifi` | 276198 | **-3.6764** |

*(Note: In binary Logistic Regression with classes `['bad', 'good']`, negative coefficients penalize the score and pull predictions towards class 0: `bad`).*

### Root Cause of False Positives:
1. **The `paypal` Anomaly:** In the entire dataset of 549,346 URLs, the word `paypal` appears 10,276 times. **10,275 are labeled `bad` and only 1 is labeled `good`**. In fact, there are 941 URLs in the dataset matching the root domain `paypal.com`, and **all 941 are labeled `bad`** (phishing targeting PayPal). There is not a single legitimate PayPal account URL labeled `good` in the dataset. Consequently, the model learned a massive negative weight (`-5.7171`), classifying any URL containing `paypal` as malicious.
2. **The `google` Anomaly:** 75.67% of URLs mentioning `google` in the dataset are phishing attacks (e.g. fake Google Docs, fake account login redirection). As a result, the stem `googl` has a negative coefficient (`-0.5308`), pulling `https://www.google.com` towards phishing.
3. **Security Words Treated as Malicious:** Words like `login` (-5.2380), `secure` (-2.0835), `signin` (-3.6178), and `verify` (-3.6764) overwhelmingly appear in phishing credential-harvesting kits. Any legitimate banking or e-commerce URL containing `login` or `verify` is severely penalized.

---

## 10. DATASET QUALITY FINDINGS

1. **Massive Artificial Duplication of Phishing Data:**  
   77,019 phishing rows are duplicates. Certain popular phishing kits or domains appear dozens of times verbatim.
2. **Corrupted / Garbage Characters:**  
   415 rows contain raw binary garbage or unprintable characters (e.g., `\u0011\u0018Yìê‡...`).
3. **Severe Brand Representation Imbalance:**  
   Major targeted financial brands (PayPal, banks) exist almost exclusively in the malicious class.
4. **Legitimate Samples Contain IP Address Patterns:**  
   124 URLs labeled `good` contain numerical IPv4 patterns (mostly scholarly articles with DOIs like `10.1.1.43...`).

---

## 11. LEAKAGE AUDIT VERDICT

### FINAL VERDICT: **CONFIRMED TRAIN/TEST LEAKAGE**

### Definitive Evidence Summary:
1. **11,943 unique URLs** appear simultaneously in both the training set and the test set.
2. **12,781 test rows (11.63% of the test set)** are exact duplicates of training samples.
3. **40.93% of all phishing samples in the test set (12,770 out of 31,200)** were already seen during training.
4. An additional **1,191 test URLs** are near-duplicate syntactic variants of training URLs.
5. Reported test accuracy (96.43%) is mathematically inflated because over 40% of the positive class was memorized.

---

## 12. RECOMMENDED NEXT STEPS

When authorized to retrain:
1. **Deduplicate Prior to Splitting:**  
   Execute `df.drop_duplicates(subset=['URL'], keep='first')` before performing `train_test_split()`.
2. **Domain-Aware Stratified Splitting:**  
   Split by fully qualified domain name (FQDN) rather than random rows so that subdomains/paths from the same site do not leak between train and test.
3. **Domain Whitelisting:**  
   Do not rely solely on NLP token frequencies for top-level domains. Implement an Alexa/Tranco top 10,000 domain whitelist or domain-level reputation check to prevent legitimate brands from being classified as phishing.

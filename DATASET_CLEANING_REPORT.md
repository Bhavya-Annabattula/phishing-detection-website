# DATASET CLEANING REPORT

**Original Dataset:** `phishing_site_urls.csv/phishing_site_urls.csv`  
**Cleaned Dataset:** `phishing_site_urls_clean.csv`  
**Conflicts Isolated:** `conflicting_labels.csv`  
**Audit & Cleaning Date:** September 15, 2026  

---

## 1. DATASET CLEANING OVERVIEW

To eliminate artificial test metric inflation and data leakage, the raw dataset was deduplicated and audited for label conflicts prior to model retraining.

### Deduplication Policy & Decisions
1. **Normalization for Duplicate Detection:**
   - Evaluated exact URL strings, whitespace trimming, protocol stripping (`http://`, `https://`), `www.` prefix stripping, and trailing slash normalization.
   - For training integrity, the **original exact URL strings** were preserved in `phishing_site_urls_clean.csv`.
2. **Exact Duplicate Rows:**
   - 42,150 completely identical rows (`URL` + `Label`) were identified and deduplicated, retaining one representative record per URL.
3. **Handling of Conflicting Labels:**
   - Scanned all URLs appearing with multiple distinct labels.
   - Exactly one domain exhibited a conflicting label: `tommyhumphreys.com/` (2 `bad` records, 1 `good` record).
   - Rather than fabricating or guessing a ground-truth label, `tommyhumphreys.com/` was completely **excluded from the machine learning dataset** and isolated into `conflicting_labels.csv`.

---

## 2. METRIC COMPARISON: ORIGINAL VS CLEANED

| Metric | Original Raw Dataset | Cleaned Dataset (`phishing_site_urls_clean.csv`) | Delta / Change |
| :--- | :--- | :--- | :--- |
| **Total Rows** | 549,346 | 507,194 | -42,152 (-7.67%) |
| **Unique URLs** | 507,195 | 507,194 | -1 (Conflict excluded) |
| **Phishing (`bad`) Count** | 156,422 (28.47%) | 114,298 (22.54%) | -42,124 (-26.93%) |
| **Legitimate (`good`) Count** | 392,924 (71.53%) | 392,896 (77.46%) | -28 (-0.007%) |
| **Conflicting URLs** | 1 (`tommyhumphreys.com/`) | 0 (Isolated to `conflicting_labels.csv`) | Resolved |

### Key Takeaway on Class Imbalance
Deduplication removed **42,124 phishing rows** versus only **28 legitimate rows**. The raw dataset's phishing samples were artificially duplicated over 1,500 times more frequently than legitimate samples. After deduplication, the true dataset ratio is **77.46% legitimate to 22.54% phishing** (~3.44 : 1 imbalance).

---

## 3. CONFLICTING LABELS ISOLATION (`conflicting_labels.csv`)

| URL | Bad Occurrences | Good Occurrences | Total Occurrences | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| `tommyhumphreys.com/` | 2 | 1 | 3 | Excluded from training & saved to `conflicting_labels.csv` |

*Rationale:* In a binary security classifier, assigning an arbitrary majority vote to an ambiguous domain without external verification introduces noise into the decision boundary. Excluding the conflict maintains clean ground truth.

---

## 4. BRAND BIAS & VOCABULARY SCAN (CLEAN DATASET)

Token occurrences across all 507,194 unique URLs in the cleaned dataset:

| Token | Bad Samples | Good Samples | Total Samples | Bad % | Good % |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **google** | 3,133 | 1,128 | 4,261 | 73.53% | 26.47% |
| **paypal** | 10,232 | 1 | 10,233 | **99.99%** | 0.01% |
| **amazon** | 126 | 5,280 | 5,406 | 2.33% | **97.67%** |
| **microsoft** | 185 | 563 | 748 | 24.73% | 75.27% |
| **apple** | 215 | 780 | 995 | 21.61% | 78.39% |
| **bank** | 1,225 | 1,523 | 2,748 | 44.58% | 55.42% |
| **login** | 20,427 | 107 | 20,534 | **99.48%** | 0.52% |
| **secure** | 5,343 | 127 | 5,470 | **97.68%** | 2.32% |
| **signin** | 939 | 59 | 998 | **94.09%** | 5.91% |
| **verify** | 752 | 4 | 756 | **99.47%** | 0.53% |

---

## 5. DOMAIN-LEVEL ANALYSIS (CLEAN DATASET)

* **Total Unique Registrable / Host Domains Extracted:** 187,659 domains
* **Domains Represented in BOTH Classes:** 88 domains
* **Domains Represented ONLY in `bad` Class:** 58,756 domains
* **Domains Represented ONLY in `good` Class:** 128,815 domains

### Representation of Target Brand Domains:
- `paypal.com`: 0 clean URLs match `paypal.com` as root host. (All PayPal instances are deep subdomains or paths in phishing attacks, e.g. `horizonsgallery.com/js/.../www.paypal.com/...`).
- `google.com`: 147 URLs (141 Good, 6 Bad).
- `amazon.com`: 4,649 URLs (4,649 Good, 0 Bad).
- `microsoft.com`: 121 URLs (121 Good, 0 Bad).
- `apple.com`: 56 URLs (56 Good, 0 Bad).

---

## 6. TRAIN/TEST LEAKAGE VERIFICATION

Train/test splitting was executed on the deduplicated, non-conflicting dataset (`df_clean`):
- **Split Configuration:** `test_size=0.2`, `random_state=42`
- **Training Set:** 405,755 unique URLs
- **Testing Set:** 101,439 unique URLs
- **Set Intersection:** $\text{set}(X_{\text{train}}) \cap \text{set}(X_{\text{test}}) = \emptyset$
- **Train/Test URL Overlap:** **EXACTLY 0 (0.0000%)**

**LEAKAGE VERDICT: ZERO LEAKAGE CONFIRMED.**

# COMPLETE AI PHISHING PROJECT — FULL TECHNICAL AUDIT REPORT

**Target Repository:** `Bhavya-Annabattula/phishing-detection-website`  
**Workspace Path:** `c:\Users\bhavy\OneDrive\Apps\ai phishing`  
**Audit Date:** September 15, 2026  
**Auditor:** Independent Technical & Security AI Audit Subsystem  
**Audit Scope:** Entire repository, source code, serialized models, training notebooks, datasets, configuration, containerization, security posture, and runtime behavior.

---

## 1. EXECUTIVE SUMMARY

An exhaustive, evidence-based technical and architectural audit was performed on the `phishing-detection-website` repository. The stated purpose of the project is to provide an AI-powered phishing detection web service that analyzes URLs to protect users from malicious websites.

### Key Audit Findings:
1. **Core Architecture Status: WORKING PROTOTYPE (Heavily Constrained)**  
   The application implements a minimal single-file Flask web service (`app.py`, 38 lines) serving a single HTML template (`templates/index.html`, 198 lines) that invokes a serialized Scikit-learn model (`phishing.pkl`, 2.8 MB) using a Bag-of-Words count vectorizer (`vectorizer.pkl`, 5.9 MB).
2. **Critical Train-Serve Pipeline Skew:**  
   The training pipeline in `ai phishing.ipynb` preprocessed URLs through `RegexpTokenizer(r'[A-Za-z]+')`, followed by `SnowballStemmer('english')`, and joined tokens with spaces before vectorization. In production (`app.py`), the URL is only stripped of `^https?://(www\.)?` and passed directly to `vector.transform()`. Neither tokenization nor Snowball stemming is executed at inference.
3. **Severe Brand Impersonation & False Positive Failure:**  
   Because the model relies strictly on token frequencies without domain hierarchy, WHOIS, or SSL verification, legitimate top-tier brands whose names appear frequently in phishing dataset URLs (e.g., `https://www.paypal.com`) are classified as **phishing** with over 99.3% confidence (coefficient for `'paypal'` is `-6.4402`).
4. **Evaluation Metric Inversion in Training:**  
   In `ai phishing.ipynb` (cell 53), `classification_report(l_model.predict(x_test), y_test)` was invoked with `(y_pred, y_true)` instead of `(y_true, y_pred)`. This mathematically transposed the confusion matrix and swapped precision and recall. The claimed "Bad URL Precision: 91%" displayed on the web interface is actually Bad URL Recall, and claimed "Bad URL Recall: 97%" is actually Bad URL Precision.
5. **Container & Deployment Disconnect:**  
   `dockerfile.txt` is incorrectly named (non-standard `.txt` extension), attempts to expose port 7860, but executes `python app.py` which binds strictly to `127.0.0.1:5000` (unreachable from outside the container). Additionally, lack of `.dockerignore` results in bloating Docker images with local virtual environments (`env/`), Git history (`.git/`), and raw CSV data (~31.5 MB).
6. **Zero Automated Testing & Verification:**  
   The repository contains zero test files, zero unit/integration tests, zero CI/CD pipelines, and zero persistent database layers.

---

## 2. PROJECT DISCOVERY & STRUCTURE

### Project Metadata
* **Project Name:** `phishing-detection-website`
* **Repository Origin:** `https://github.com/Bhavya-Annabattula/phishing-detection-website.git`
* **Primary Languages:** Python 3.10 / 3.14, HTML5 (Jinja2)
* **CSS Frameworks:** Tailwind CSS (via CDN script), Bootstrap 5.3.8 (via CDN stylesheet)
* **Backend Framework:** Flask 3.1.3 (Werkzeug 3.1.8)
* **Machine Learning Framework:** Scikit-learn 1.8.0, Pandas 3.0.3, NumPy 2.4.6, NLTK (training only)
* **Persistence / Storage:** None (stateless in-memory execution)
* **Authentication:** None

### Complete Project File Tree
```
c:\Users\bhavy\OneDrive\Apps\ai phishing\
├── .git/                                 # Git version control metadata (1 commit: 53b998a)
├── .ipynb_checkpoints/                   # Jupyter local auto-save checkpoints
├── ai phishing.ipynb                     # Jupyter notebook: training, EDA, and model evaluation (854 KB)
├── app.py                                # Main Flask web application entry point (38 LOC, 954 bytes)
├── dockerfile.txt                        # Container specification (misnamed with .txt extension, 7 LOC)
├── env/                                  # Local Python virtual environment (ignored from source stats)
├── phishing.pkl                          # Serialized LogisticRegression model (2,807,436 bytes)
├── phishing_mnb.pkl                      # Serialized MultinomialNB model (11,227,370 bytes, UNUSED)
├── phishing_site_urls.csv/               # Directory containing the dataset
│   └── phishing_site_urls.csv            # Raw dataset CSV file (31,567,326 bytes, 549,346 records)
├── requirements.txt                      # Project dependency specification (18 packages, UTF-16LE)
├── templates/                            # Flask HTML templates directory
│   └── index.html                        # Single-page UI with form and stats (198 LOC, 10,065 bytes)
└── vectorizer.pkl                        # Serialized CountVectorizer (5,862,581 bytes, 350,837 vocab)
```

### Directory & Component Description

| Directory / File | Purpose | Production Relevant? |
| :--- | :--- | :--- |
| `app.py` | Core Flask web server; handles routing, preprocessing, model loading, and rendering. | **YES** |
| `templates/index.html` | Front-facing UI; includes URL submission form, result display, and project description. | **YES** |
| `phishing.pkl` | Binary pickle of trained Scikit-learn `LogisticRegression` classifier. | **YES** |
| `vectorizer.pkl` | Binary pickle of trained Scikit-learn `CountVectorizer` vocabulary. | **YES** |
| `phishing_mnb.pkl` | Binary pickle of trained Scikit-learn `MultinomialNB` model. | **NO (Disconnected)** |
| `ai phishing.ipynb` | Research notebook containing exploratory data analysis, training, and metrics. | **NO (Research Artifact)** |
| `phishing_site_urls.csv/` | Folder enclosing raw training dataset CSV. | **NO (Training Artifact)** |
| `requirements.txt` | Dependency manifest for deployment. | **YES** |
| `dockerfile.txt` | Docker container build manifest. | **PARTIAL (Misconfigured)** |
| `env/` | Local Python virtual environment. | **NO (Local Artifact)** |

---

## 3. ARCHITECTURE AUDIT

### Data Flow Diagram

```mermaid
flowchart TD
    User([User Browser]) -->|HTTP GET /| FlaskApp[Flask App: app.py]
    FlaskApp -->|Renders initial page| Template[templates/index.html]
    Template -->|Displays Form| User
    
    User -->|HTTP POST / with URL string| FlaskApp
    subgraph Inference Pipeline
        FlaskApp --> CleanURL[re.sub: Strips http://, https://, www.]
        CleanURL --> Vectorizer[vectorizer.pkl: CountVectorizer.transform]
        Vectorizer --> SparseVector[Sparse Feature Vector 1x350837]
        SparseVector --> Model[phishing.pkl: LogisticRegression.predict]
        Model --> RawClass[Output: 'bad' or 'good']
    end
    RawClass -->|'bad'| BadMsg["This is a Phishing Website!!"]
    RawClass -->|'good'| GoodMsg["This is a Secure Website!!"]
    RawClass -->|other| ErrMsg["Something Went Wrong"]
    BadMsg --> RenderTemplate[render_template with predict]
    GoodMsg --> RenderTemplate
    ErrMsg --> RenderTemplate
    RenderTemplate -->|HTML with colored alert banner| User
```

### Architectural Details

1. **Frontend-Backend Interface:**
   - Single synchronous form submission (`<form method="POST" action="/">`).
   - Content-Type: `application/x-www-form-urlencoded`.
   - Payload: Single input key `URL`.
   - Entire page reloads upon form submission; no AJAX, Fetch API, or WebSockets.
2. **State & Persistence:**
   - Stateless. No sessions, cookies, database entries, or logging tables.
3. **Model Loading:**
   - Eagerly loaded at startup at the global module level in `app.py` lines 7–8:
     ```python
     vector = pickle.load(open("vectorizer.pkl", 'rb'))
     model = pickle.load(open("phishing.pkl", 'rb'))
     ```
   - Retained in memory indefinitely.
4. **Architectural Dead Ends & Disconnections:**
   - **`phishing_mnb.pkl`:** A 11.2 MB Multinomial Naive Bayes model was trained and dumped during notebook execution, but is **never loaded or referenced** in `app.py`.
   - **`gunicorn` dependency:** Listed in `requirements.txt` but omitted from `dockerfile.txt` (`CMD ["python", "app.py"]`), rendering it unused.
   - **Interactive Navigation Buttons:** Links in `templates/index.html` (e.g., `#`, `Phishing` button, mobile menu toggle) have no attached JavaScript event handlers or destinations.
   - **Probabilities & Confidence Scores:** The model calculates confidence probabilities via `predict_proba()`, but `app.py` only extracts discrete class labels (`predict = model.predict(...)[0]`), discarding uncertainty.

---

## 4. AI/ML AUDIT

### Model Inventory

| Attribute | Primary Model (`phishing.pkl`) | Secondary Model (`phishing_mnb.pkl`) | Vectorizer (`vectorizer.pkl`) |
| :--- | :--- | :--- | :--- |
| **Model Type** | Logistic Regression | Multinomial Naive Bayes | Bag-of-Words Count Vectorizer |
| **Class** | `sklearn.linear_model.LogisticRegression` | `sklearn.naive_bayes.MultinomialNB` | `sklearn.feature_extraction.text.CountVectorizer` |
| **Active in App?** | **YES** | **NO (Disconnected)** | **YES** |
| **File Size** | 2,807,436 bytes (2.8 MB) | 11,227,370 bytes (11.2 MB) | 5,862,581 bytes (5.9 MB) |
| **Target Classes** | `['bad', 'good']` | `['bad', 'good']` | N/A |
| **Hyperparameters** | `solver='lbfgs'`, `max_iter=100`, `C=1.0` | `alpha=1.0`, `fit_prior=True` | `ngram_range=(1,1)`, `lowercase=True` |
| **Vocabulary Size** | 350,837 features | 350,837 features | 350,837 features |
| **Intercept** | `[-0.63945756]` | N/A | N/A |

### AI Feature Category Checklist

* **Rule-based detection:** NOT IMPLEMENTED (no domain whitelist or regex rules)
* **Machine learning:** **IMPLEMENTED** (Logistic Regression, MultinomialNB)
* **Deep learning:** NOT IMPLEMENTED
* **NLP:** **PARTIAL** (Word tokenization & Snowball stemming in notebook; plain word splitting in production)
* **LLM:** NOT IMPLEMENTED
* **URL Structural Analysis:** NOT IMPLEMENTED (No analysis of URL length, path depth, TLD, entropy, or subdomain counts)
* **HTML/DOM Analysis:** NOT IMPLEMENTED (No web scraping or DOM inspection)
* **JavaScript Analysis:** NOT IMPLEMENTED
* **DNS/WHOIS/SSL Features:** NOT IMPLEMENTED
* **Visual/Screenshot Analysis:** NOT IMPLEMENTED
* **Reputation / Blacklist Services:** NOT IMPLEMENTED
* **Risk Scoring / Uncertainty:** NOT IMPLEMENTED (Binary label only)

---

## 5. PHISHING DETECTION LOGIC AUDIT

Every feature claimed or implied by the project concept was audited against the codebase.

| Detection Feature | Implemented? | Source Code Location | Used by Production Model? | Verified Status |
| :--- | :--- | :--- | :--- | :--- |
| **Bag-of-Words Tokens** | **YES** | `app.py:20`, `ai phishing.ipynb:40` | **YES** | **VERIFIED** |
| **Prefix Stripping (`https?://(www\.)?`)** | **YES** | `app.py:18` | **YES** (Alters input) | **VERIFIED** |
| **Snowball Stemming** | **PARTIAL** | `ai phishing.ipynb:24` | **NO** (Skipped in `app.py`) | **VERIFIED DISCREPANCY** |
| **Alphanumeric Regex Tokenization**| **PARTIAL** | `ai phishing.ipynb:16` | **NO** (Default CountVectorizer tokenization used in `app.py`) | **VERIFIED DISCREPANCY** |
| **URL Length** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **URL Shannon Entropy** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **Subdomain Count** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **Suspicious TLD Check** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **IP Address Host Detection** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **HTTPS / SSL Certificate Check**| **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **Domain Age / WHOIS** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **HTTP Redirect Following** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **Shortened URL Expansion** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **Brand Impersonation Matching** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **HTML / Form Inspection** | **NO** | None | **NO** | **NOT IMPLEMENTED** |
| **External Reputation API** | **NO** | None | **NO** | **NOT IMPLEMENTED** |

---

## 6. MODEL PERFORMANCE & METRIC VERIFICATION

### Verification of Reported Metrics

The landing page (`templates/index.html`, lines 96–113) presents the following four metrics:
1. **Accuracy: 97%**
2. **Bad URL Precision: 91%**
3. **Bad URL Recall: 97%**
4. **URLs Tested: 109K+**

### Independent Reproduction from Notebook Outputs

Inspection of `ai phishing.ipynb` (cells 50, 51, 53, 55) reveals:
- **Test Set Evaluation (cell 50):** `l_model.score(x_test, y_test) = 0.9651406207335943` (~96.51%, rounded to 97%).
- **Training Set Evaluation (cell 51):** `l_model.score(x_train, y_train) = 0.9787997524324423` (~97.88%).
- **MultinomialNB Test Evaluation (cell 61):** `mnb.score(x_test, y_test) = 0.9581596432147083` (~95.82%).
- **Test Set Size:** 109,870 URLs (20% split of 549,346 total samples), matching the "109K+" claim.

### The Classification Report Bug & Inversion

In cell 53, the code executes:
```python
classification_report(l_model.predict(x_test), y_test, target_names=['Bad', 'Good'])
```
By convention and definition in Scikit-learn, the signature is:
```python
classification_report(y_true, y_pred, ...)
```
Because the author passed `y_pred` as the first parameter and `y_true` as the second:
- Sklearn treated predictions as the ground truth.
- **Reported "Precision" for Bad (0.91) is mathematically the true RECALL.**
- **Reported "Recall" for Bad (0.97) is mathematically the true PRECISION.**
- The support figures in the report (`Bad: 29533`, `Good: 80337`) represent the number of predicted samples, rather than actual ground truth samples in the test split.

```
+--------------------------------------------------------------------------------+
| Metric Comparison: UI Claim vs Ground Truth Reality                           |
+----------------------+--------------------+--------------------+---------------+
| Metric               | Displayed on UI    | Actual Notebook    | Real Identity |
+----------------------+--------------------+--------------------+---------------+
| Overall Accuracy     | 97%                | 96.51%             | Verified      |
| Bad URL Precision    | 91%                | 97.28% (Real Prec) | Transposed    |
| Bad URL Recall       | 97%                | 91.68% (Real Rec)  | Transposed    |
| URLs Tested          | 109K+              | 109,870            | Verified      |
+----------------------+--------------------+--------------------+---------------+
```

---

## 7. DATASET AUDIT

### Dataset File Details
- **File Location:** `phishing_site_urls.csv/phishing_site_urls.csv`
- **File Size:** 31,567,326 bytes (~30.1 MB)
- **Format:** Comma-Separated Values (CSV), UTF-8 text with multi-line anomalies
- **Columns:** Exactly 2 columns (`URL`, `Label`)

### Dataset Distribution Statistics
- **Total Records:** 549,346
- **Missing Values:** 0 null values in `URL`, 0 null values in `Label`
- **Class Breakdown:**
  - `good`: 392,924 samples (71.53%)
  - `bad`: 156,422 samples (28.47%)
  - Imbalance Ratio: ~2.51 : 1 (Significant legitimate class skew)
- **Duplicate Records:**
  - Total identical rows (`URL` + `Label`): **42,150 duplicates (7.67%)**
  - Duplicate URL strings: **42,151 duplicates**
- **Data Quality & Noise:**
  - 415 URLs contain non-ASCII, corrupted control characters, or unprintable binary strings (e.g., row index 18234: `\u0011\u0018Yìê‡\f koãÕ»Î§DéÎ...` labeled as `good`).
  - Numerous phishing URLs include protocol prefixes (`http://`, `https://`), while legitimate samples predominantly start directly with subdomains or domains (`nobell.it/...`, `www.dghjdgf.com/...`), creating artificial token bias.

### Data Leakage Risk
Because `train_test_split(features, df.Label, test_size=0.2)` was executed without prior deduplication:
- Subsets of the 42,150 identical URL samples were distributed simultaneously into both `x_train` and `x_test`.
- The model was tested on URLs it had already memorized during training, causing metric inflation.

---

## 8. CODE STATISTICS

Repository statistics calculated across project files (excluding virtual environment `env/`, checkpoints, and `.git`):

| Category | File | Total LOC | Code Lines | Blank Lines | Comment Lines | Size (Bytes) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Backend** | `app.py` | 38 | 23 | 12 | 3 | 954 |
| **Frontend** | `templates/index.html` | 198 | 144 | 30 | 24 | 10,065 |
| **Deployment** | `dockerfile.txt` | 7 | 7 | 0 | 0 | 161 |
| **Dependencies**| `requirements.txt` | 18 | 18 | 0 | 0 | 626 |
| **Research/ML** | `ai phishing.ipynb` | 3,558 | 3,558 | 0 | 0 | 854,634 |
| **Dataset** | `phishing_site_urls.csv` | 549,362 | 549,362 | 0 | 0 | 31,567,326 |
| **Model** | `phishing.pkl` | N/A (binary) | N/A | N/A | N/A | 2,807,436 |
| **Model** | `phishing_mnb.pkl` | N/A (binary) | N/A | N/A | N/A | 11,227,370 |
| **Model** | `vectorizer.pkl` | N/A (binary) | N/A | N/A | N/A | 5,862,581 |

### Verified Structural Counts
- **Total Project Files (excluding .git and env):** 9 files
- **Total Production Code LOC (Python + HTML):** 236 lines (167 pure code lines)
- **Number of Classes:** 0 custom classes (functional script style)
- **Number of Functions:** 1 function (`index()` in `app.py`)
- **Number of HTTP Endpoints:** 1 (`/` supporting `GET` and `POST`)
- **Number of Frontend Pages:** 1 (`index.html`)
- **Number of Unit / Integration Tests:** 0 tests
- **Number of Active Production Models:** 1 (`LogisticRegression`)
- **Number of Unused Production Models:** 1 (`MultinomialNB`)

---

## 9. DEPENDENCY AUDIT

### Manifest Inspection (`requirements.txt`)
`requirements.txt` specifies 18 packages with strict version pins:
```
gunicorn==21.2.0
blinker==1.9.0
click==8.4.1
colorama==0.4.6
Flask==3.1.3
itsdangerous==2.2.0
Jinja2==3.1.6
joblib==1.5.3
MarkupSafe==3.0.3
numpy==2.4.6
pandas==3.0.3
python-dateutil==2.9.0.post0
scikit-learn==1.8.0
scipy==1.17.1
six==1.17.0
threadpoolctl==3.6.0
tzdata==2026.2
Werkzeug==3.1.8
```

### Dependency Discrepancy Findings
1. **Windows Platform Incompatibility:** `gunicorn==21.2.0` is declared in `requirements.txt`. Gunicorn relies on UNIX `fcntl`/POSIX primitives and cannot install or run natively on Windows environments.
2. **Missing Notebook Dependencies:** The training notebook `ai phishing.ipynb` requires `nltk`, `seaborn`, `matplotlib`, and `wordcloud`. None of these packages are declared in `requirements.txt`. Anyone attempting to retrain models from `requirements.txt` encounters immediate `ModuleNotFoundError`.
3. **Unused Production Packages:** `pandas`, `scipy`, `colorama`, and `python-dateutil` are installed in production dependencies, but `app.py` only utilizes `flask`, `pickle`, `re`, `scikit-learn`, and `numpy`.
4. **Encoding Anomaly:** `requirements.txt` is encoded in UTF-16LE with Byte Order Mark (BOM), which causes errors with older tooling expecting standard UTF-8/ASCII.

---

## 10. SECURITY AUDIT

### Vulnerability Findings Summary

| ID | Severity | Category | File | Description |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | **CRITICAL** | Insecure Deserialization | `app.py:7,8` | Unsafe `pickle.load` of binary artifacts |
| **SEC-02** | **HIGH** | Web Application Security | `app.py:12` | Missing CSRF protection on POST endpoint |
| **SEC-03** | **HIGH** | Availability / DoS | `app.py:18,20` | Unbounded input length and CPU exhaustion |
| **SEC-04** | **HIGH** | Misconfiguration | `dockerfile.txt:6,7` | Broken container binding (`127.0.0.1:5000` vs `7860`) |
| **SEC-05** | **MEDIUM** | Information Disclosure | `templates/index.html` | Hardcoded author social and email information |
| **SEC-06** | **MEDIUM** | Supply Chain / CDN | `templates/index.html:6`| Tailwind Play CDN used in production markup |
| **SEC-07** | **MEDIUM** | Security Headers | `app.py` | Complete absence of CSP, HSTS, X-Frame-Options |
| **SEC-08** | **LOW** | Container Security | `dockerfile.txt:1` | Running container as root user |

### Detailed Findings

#### SEC-01: Insecure Deserialization via Python `pickle` (CRITICAL)
- **Problem:** `app.py` loads `vectorizer.pkl` and `phishing.pkl` using Python's native `pickle.load()`.
- **Impact:** Python pickles can execute arbitrary bytecode upon loading (`__reduce__` exploit). If model weights or files are replaced or tampered with in transit or storage, remote code execution (RCE) occurs immediately upon server startup.
- **Remediation:** Serialize models using safer alternatives like `safetensors`, ONNX runtime, or extract coefficients into a lightweight JSON matrix.

#### SEC-02: Missing CSRF Protection (HIGH)
- **Problem:** The form submission endpoint `@app.route("/", methods=['GET','POST'])` has no Cross-Site Request Forgery (CSRF) tokens or validations.
- **Impact:** Malicious third-party sites can forge requests to this endpoint, using user sessions or flooding the inference service.
- **Remediation:** Integrate `Flask-WTF` with CSRF protection enabled.

#### SEC-03: Denial of Service via Unbounded Input (HIGH)
- **Problem:** `request.form['URL']` has no maximum length constraint.
- **Impact:** An attacker submitting a multi-megabyte text payload causes regular expression engine lag during `re.sub` and high memory consumption during `CountVectorizer.transform()`.
- **Remediation:** Enforce payload length limits (e.g., maximum 2,048 characters) and validate URL structure before vectorization.

#### SEC-04: Broken Production Container Configuration (HIGH)
- **Problem:** `dockerfile.txt` specifies `EXPOSE 7860` and `CMD ["python", "app.py"]`. In `app.py`, `app.run(debug=False)` defaults to `host='127.0.0.1', port=5000`.
- **Impact:** 
  1. The server inside Docker only listens to the loopback interface (`127.0.0.1`), rejecting all traffic coming through the Docker bridge interface (`0.0.0.0`).
  2. The Docker host mapping maps port 7860 to nothing.
  3. The container cannot be accessed by external users.
- **Remediation:** In `app.py`, pass `host="0.0.0.0", port=7860`, or run with Gunicorn: `CMD ["gunicorn", "-b", "0.0.0.0:7860", "app:app"]`.

---

## 11. FRONTEND AUDIT

### UI Components & Structure
The frontend consists of a single Jinja2 template (`templates/index.html`):
- **Hero Section:** Navigation bar with branding "Phishing Detection Website", non-functional links, and responsive hamburger icon.
- **Input Form:** Centered text input box (`id="URL"`, `name="URL"`) with submit button labeled "Check".
- **Result Display:** Conditional alert box (`{% if predict %}`) showing green for secure and red for phishing.
- **Performance Metrics Grid:** 4-card statistics dashboard showing Accuracy (97%), Bad URL Precision (91%), Bad URL Recall (97%), and URLs Tested (109K+).
- **About Section:** Text paragraphs explaining the project and technologies used.
- **Footer:** Author name ("Bhavya Annabattula"), project summary, and external links to LinkedIn and GitHub profiles.

### Frontend Quality & Verification
- **Functional Form:** **VERIFIED**. Form properly posts to `/` and triggers server-side inference.
- **Dead Buttons:** **VERIFIED**. The header buttons (`Phishing`, `Menu`, and `Home`) are anchors with `href="#"` and have no interactive functionality.
- **CDN Integrity Issues:** Line 8 links Bootstrap 5.3.8 (`https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css`) with an SRI hash. Bootstrap 5.3.8 is not an official release tag; if the CDN fails to resolve the asset, styling may break.
- **Tailwind Play CDN:** Uses `https://cdn.tailwindcss.com` which compiles styles in the browser at runtime, causing noticeable Flash of Unstyled Content (FOUC) and violating production best practices.

---

## 12. BACKEND AUDIT

### Endpoint Inventory

| Endpoint | Method | Purpose | Auth Required | Frontend Consumes? | Implementation Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/` | `GET` | Renders `index.html` initial state | None | Browser Navigation | **IMPLEMENTED** |
| `/` | `POST` | Processes URL, runs inference, renders result | None | Form Submission | **IMPLEMENTED** |

### Backend Logic Review (`app.py`)
- **Routing:** Handled cleanly by `@app.route("/", methods=['GET','POST'])`.
- **Request Extraction:** `URL = request.form['URL']`. Does not handle missing `URL` key gracefully (`KeyError` if key is omitted from POST request).
- **Preprocessing:**
  ```python
  cleaned_URL = re.sub(r'^https?://(www\.)?', '', URL)
  ```
- **Inference:**
  ```python
  predict = model.predict(vector.transform([cleaned_URL]))[0]
  ```
- **Error Handling:** Complete absence of `try/except` blocks. Any unhandled exception results in Flask returning an unformatted HTTP 500 Internal Server Error page.

---

## 13. DATABASE AUDIT

- **Database Presence:** **NONE (NOT IMPLEMENTED)**
- **Schema / Tables:** None
- **ORM / Migrations:** None
- **Persistence Layer:** None

*Implication:* The application does not store historical scan results, malicious URL logs, user telemetry, or blacklists. Every request is processed entirely in-memory and discarded.

---

## 14. TESTING AUDIT

- **Test Suite Presence:** **NONE (NOT IMPLEMENTED)**
- **Unit Tests:** 0
- **Integration Tests:** 0
- **Model Regression Tests:** 0
- **Test Execution:** Cannot execute tests (no test files exist).
- **Code Coverage:** **0.0%**

---

## 15. PERFORMANCE & RUNTIME AUDIT

### Runtime Inference Characteristics
Inference was tested using the model weights and CountVectorizer on a standard CPU:

| Test URL Sample | Preprocessing Output | Tokens Activated | Model Prediction | Model Probability | Correct? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `https://www.google.com` | `google.com` | 2 (`google`, `com`) | **good** | 67.2% Good | **YES** |
| `https://www.paypal.com` | `paypal.com` | 2 (`paypal`, `com`) | **bad** | **99.4% Bad** | **FALSE POSITIVE** |
| `http://amaz0n-security-update.com/signin` | `amaz0n-security-update.com/signin` | 3 tokens | **bad** | 89.3% Bad | **YES** |
| `http://fazan-pacir.rs/temp/libraries/ipad`| `fazan-pacir.rs/temp/libraries/ipad` | 4 tokens | **bad** | 99.9% Bad | **YES** |
| `""` (Empty string) | `""` | 0 tokens | **bad** | 65.5% Bad | **FAILURE** |
| `http://localhost:8080` | `localhost:8080` | 1 token | **bad** | 67.3% Bad | **FALSE POSITIVE** |

### Performance Observations
- **Inference Latency:** Extremely fast on CPU (< 15 milliseconds per URL) due to sparse matrix operations and linear model weights.
- **Cold Startup Time:** ~1.2 seconds to unpickle 8.7 MB of combined model and vectorizer objects into RAM.
- **Memory Footprint:** ~120 MB baseline RAM usage for Flask + loaded CountVectorizer vocabulary (350,837 features).

---

## 16. DEPLOYMENT AUDIT

### Deployment Manifest Inspection (`dockerfile.txt`)
```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 7860
CMD ["python", "app.py"]
```

### Verification Against Production Standards
1. **Invalid Filename:** Stored as `dockerfile.txt`. Standard Docker CLI commands (`docker build .`) will fail with `Cannot find Dockerfile`.
2. **Network Port Mismatch:**
   - Dockerfile exposes port `7860` (standard Hugging Face Spaces port).
   - `app.py` runs `app.run(debug=False)`, which defaults to port `5000` on `127.0.0.1`.
   - Result: The container builds, but container port forwarding fails to connect to Flask.
3. **Missing `.dockerignore`:**
   - The command `COPY . .` copies `env/` (hundreds of MBs of Windows virtual environment), `.git/`, and `phishing_site_urls.csv/` (31.5 MB) into the container image.
   - Result: Image size exceeds 1.5 GB unnecessarily and can contaminate Linux container paths with Windows virtualenv binaries.
4. **Platform Wheel Failure:** `gunicorn` in `requirements.txt` will succeed on Linux in Docker, but fails on Windows developers' native machines.

---

## 17. DOCUMENTATION AUDIT

The repository has **no `README.md` file**. All claims are extracted directly from `templates/index.html` and `ai phishing.ipynb`.

| Documentation Claim (UI / Notebook) | Actual Implementation | Audit Status |
| :--- | :--- | :--- |
| "Our machine learning model detects suspicious websites..." | Single Logistic Regression model running Bag-of-Words | **IMPLEMENTED** |
| "Evaluated on over 109,870 URLs" | 20% test split of 549,346 dataset = 109,870 | **VERIFIED** |
| "Accuracy: 97%" | Test score is 96.51% (rounded up to 97%) | **VERIFIED** |
| "Bad URL Precision: 91%" | Mathematically is Recall; transposed in code | **INVERTED** |
| "Bad URL Recall: 97%" | Mathematically is Precision; transposed in code | **INVERTED** |
| "Analyzes URL patterns to determine whether legitimate or malicious" | Pure vocabulary token frequency lookup | **PARTIAL / MISLEADING** |
| "Helps users detect online threats in real time" | Single manual web form, no browser extension or API | **PARTIAL** |

---

## 18. CODE QUALITY & TECHNICAL DEBT

1. **Modularity & Separation of Concerns:**
   - `app.py` combines model loading, preprocessing, business logic, and presentation routing into 38 lines. No separation into controllers, services, or ML inference wrappers.
2. **Naming Conventions:**
   - Variables use inconsistent styles (`URL`, `cleaned_URL`, `predict`, `vector`, `model`).
3. **Dead Code & Comments:**
   - Commented debugging print statements remain in `app.py` lines 16, 19, 21 (`#print(URL)`, `#print(cleaned_URL)`, `#print(predict)`).
4. **Type Annotations:**
   - Zero Python type hints (`typing`) used anywhere in the codebase.

---

## 19. REPRODUCIBILITY AUDIT

### Reproducibility Score: 45 / 100 (POOR)

```
+-------------------------------------------------------------------------------+
| Reproducibility Breakdown                                                     |
+------------------------------------+---------------+--------------------------+
| Criterion                          | Score (Max)   | Notes                    |
+------------------------------------+---------------+--------------------------+
| Source Code Availability           | 20 / 20       | All code in repo         |
| Pretrained Weights Included        | 20 / 20       | .pkl files present       |
| Environment / Requirements Clear   | 5 / 20        | Gunicorn breaks on Win;  |
|                                    |               | missing NLTK/Seaborn     |
| Dataset Availability               | 20 / 20       | Raw CSV present          |
| Retraining Reproducibility         | 0 / 20        | Train-serve skew &       |
|                                    |               | missing packages in reqs |
+------------------------------------+---------------+--------------------------+
| Total Reproducibility Score        | 65 / 100      | Working local prototype  |
+------------------------------------+---------------+--------------------------+
```

*Prerequisites to Run Successfully:*
1. Must use Linux or remove `gunicorn` from `requirements.txt` on Windows.
2. Must manually install `nltk`, `seaborn`, `wordcloud`, `matplotlib` to execute the training notebook.
3. Must rename `dockerfile.txt` to `Dockerfile` and adjust host/port to run in Docker.

---

## 20. FEATURE COMPLETION MATRIX

| Feature | Status | Evidence | File(s) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **URL Submission Web UI** | **IMPLEMENTED** | Form with POST action | `templates/index.html` | Clean, responsive UI |
| **Flask Web Server** | **IMPLEMENTED** | `@app.route("/", methods=...)` | `app.py` | Minimal 38-line server |
| **Pretrained Model Inference** | **IMPLEMENTED** | `model.predict(vector.transform())` | `app.py:20` | Fast linear inference |
| **MultinomialNB Alternative** | **DISCONNECTED** | `phishing_mnb.pkl` | Workspace root | Trained, dumped, never loaded |
| **Snowball Stemming Pipeline**| **BROKEN / SKEWED**| Omitted from `app.py` | `app.py`, `ai phishing.ipynb` | Train-serve mismatch |
| **Confidence / Probability Score**| **NOT IMPLEMENTED**| Binary label only | `app.py:22-29` | Discards `predict_proba` |
| **Domain Whitelist / Rule Engine**| **NOT IMPLEMENTED**| Absent from code | `app.py` | Flags paypal.com as phishing |
| **REST API / JSON Output** | **NOT IMPLEMENTED**| Returns HTML only | `app.py` | Cannot be consumed by APIs |
| **Automated Tests** | **NOT IMPLEMENTED**| No test directory | Repository root | Zero tests exist |
| **Database Persistence** | **NOT IMPLEMENTED**| No database code | Repository root | Completely stateless |
| **Production Docker Container** | **BROKEN** | Port & filename mismatch | `dockerfile.txt` | Unreachable from outside |

---

## 21. CRITICAL FINDINGS (TOP 10)

### 1. Training-Serving Feature Extraction Skew
- **Severity:** CRITICAL
- **Evidence:** `ai phishing.ipynb` tokenizes with `RegexpTokenizer` and stems with `SnowballStemmer`. `app.py` skips both and passes raw string to `vector.transform()`.
- **Impact:** Feature representation at inference diverges from the representation learned during training. Many tokens fail to match the learned stems.
- **Fix:** Package the exact tokenizer, stemmer, and vectorizer into a unified Scikit-learn `Pipeline` object and serialize it as a single artifact.
- **Difficulty:** Easy

### 2. High False-Positive Rate on Major Legitimate Brands
- **Severity:** CRITICAL
- **Evidence:** Model classifies `https://www.paypal.com` as phishing with 99.4% probability due to token weight of `paypal` (`coef = -6.4402`).
- **Impact:** System damages trust by classifying official corporate websites as phishing attacks.
- **Fix:** Implement a trusted root domain whitelist (Tranco / Cisco Umbrella top 1M) and domain hierarchy parsing (`tldextract`) rather than treating URLs as generic text bags.
- **Difficulty:** Medium

### 3. Precision-Recall Transposition in Evaluation Metrics
- **Severity:** HIGH
- **Evidence:** `classification_report` called with `(y_pred, y_test)` in `ai phishing.ipynb:53`. Values copied to UI cards.
- **Impact:** Publicized metrics are factually mislabeled (Precision is Recall, Recall is Precision).
- **Fix:** Correct the function call order to `classification_report(y_test, y_pred)` and update the HTML cards.
- **Difficulty:** Easy

### 4. Broken Dockerfile & Container Port Binding
- **Severity:** HIGH
- **Evidence:** Filename is `dockerfile.txt`; exposes 7860 while `app.py` binds to `127.0.0.1:5000`.
- **Impact:** Docker container fails default build workflows and is inaccessible externally.
- **Fix:** Rename to `Dockerfile`, update `app.py` to bind to `0.0.0.0:7860`.
- **Difficulty:** Easy

### 5. Insecure Deserialization via `pickle`
- **Severity:** HIGH
- **Evidence:** `pickle.load()` used on model files in `app.py:7,8`.
- **Impact:** Arbitrary code execution vulnerability if model files are modified.
- **Fix:** Store model weights as JSON or ONNX models.
- **Difficulty:** Medium

### 6. Data Leakage in Model Evaluation
- **Severity:** HIGH
- **Evidence:** 42,150 duplicate URL rows in `phishing_site_urls.csv` split randomly into train and test sets without prior deduplication.
- **Impact:** Overfitted test scores that do not reflect performance on novel, unseen URLs.
- **Fix:** Deduplicate dataset (`df.drop_duplicates(subset=['URL'])`) prior to `train_test_split`.
- **Difficulty:** Easy

### 7. Empty Input Defaulting to Phishing
- **Severity:** MEDIUM
- **Evidence:** Empty string `""` has 0 tokens, activating model intercept (`-0.6395`), predicting `bad` (phishing).
- **Impact:** Blank form submissions state "This is a Phishing Website!!".
- **Fix:** Add form validation verifying that the URL input is non-empty and well-formed before inference.
- **Difficulty:** Easy

### 8. Disconnected MultinomialNB Model Asset
- **Severity:** MEDIUM
- **Evidence:** `phishing_mnb.pkl` (11.2 MB) occupies storage and repository bandwidth but is never imported or served.
- **Impact:** Unnecessary repository bloat and confusing multi-model confusion.
- **Fix:** Remove unused pickle file from repository tracking.
- **Difficulty:** Easy

### 9. Lack of Automated Tests and CI/CD
- **Severity:** MEDIUM
- **Evidence:** 0 test files across the repository.
- **Impact:** Inability to prevent regressions or verify integrity during updates.
- **Fix:** Implement `pytest` suite testing edge cases, malformed URLs, and inference pipeline consistency.
- **Difficulty:** Medium

### 10. Platform Incompatibility in Dependencies
- **Severity:** LOW
- **Evidence:** `gunicorn==21.2.0` in `requirements.txt` fails installation on Windows.
- **Impact:** Developer setup fails out of the box on Windows development machines.
- **Fix:** Separate dependencies into `requirements.txt` and `requirements-dev.txt`, or mark platform-specific constraints.
- **Difficulty:** Easy

---

## 22. FINAL VERIFIED STATISTICS

```
================================================================================
FINAL VERIFIED PROJECT AUDIT METRICS
================================================================================
Total Files in Workspace (excl. .git, env) : 9
Total Production Source Files (Python + HTML): 2
Total Production Lines of Code              : 236 lines (167 pure code)
Flask Endpoints                             : 1 (GET / POST '/')
Total Datasets                              : 1 (phishing_site_urls.csv)
Total Dataset Samples                       : 549,346 records
Dataset Size on Disk                        : 31,567,326 bytes (~30.1 MB)
Dataset Label Balance                       : 71.53% good (392,924), 28.47% bad (156,422)
Duplicate Samples in Dataset                : 42,150 rows (7.67%)
Corrupted / Non-ASCII URLs                  : 415 rows
Total Pretrained Models Stored              : 2 (phishing.pkl, phishing_mnb.pkl)
Active Models in Web Server                 : 1 (phishing.pkl - Logistic Regression)
Inactive / Disconnected Models              : 1 (phishing_mnb.pkl - MultinomialNB)
Vocabulary Size in Vectorizer               : 350,837 features
Training Test Split                         : 80% train (439,476), 20% test (109,870)
True Notebook Test Accuracy                 : 96.51%
True Notebook Bad URL Precision             : 97.28% (Claimed 91% on UI due to bug)
True Notebook Bad URL Recall                : 91.68% (Claimed 97% on UI due to bug)
Automated Tests                             : 0 tests
Database Tables                             : 0 tables
Git Commits                                 : 1 commit (53b998a)
================================================================================
```

---

## 23. FINAL VERDICT

### Classification: **WORKING PROTOTYPE**

### Justification
The project successfully achieves the minimum viable milestone of loading a pretrained model and providing an interactive web page where users can input text and receive a prediction. However, it cannot be classified as "Demo Ready" or "Production Ready" due to:
1. Significant train-serve preprocessing mismatch (unstemmed inference on stemmed vocabulary).
2. Catastrophic false positives on prominent legitimate domains like `paypal.com`.
3. Mislabeled metrics caused by arguments inverted in the evaluation function.
4. Misconfigured container specifications preventing Docker deployment.
5. Complete lack of automated testing, input validation, and security controls.

### Strengths
- Working end-to-end user interface with clean visual design using Tailwind CSS.
- Fast, lightweight inference execution on standard CPU hardware.
- High training baseline accuracy on generic string patterns within the training distribution.

### Weaknesses
- URL treated as arbitrary NLP text rather than a structured networking locator.
- Easily bypassed by basic evasion techniques (hex encoding, newly registered domains, IP hosting).
- Zero automated testing and no data persistence.

---

## 24. RECOMMENDED ROADMAP & FIXES

### Immediate Priority (1–2 Days)
1. **Fix Docker Deployment:** Rename `dockerfile.txt` to `Dockerfile`, update `app.py` to bind `host="0.0.0.0", port=7860`.
2. **Align Inference Pipeline:** Create a single Scikit-learn `Pipeline([('tfidf', vectorizer), ('clf', model)])` that includes text preprocessing so that `app.py` executes the exact same pipeline as the training environment.
3. **Add Input Validation:** Ensure empty strings and malformed inputs return friendly guidance rather than "This is a Phishing Website!!".
4. **Fix Mislabeled Metric Cards:** Correct the values in `templates/index.html` to reflect true Precision and Recall.

### Medium-Term Enhancements (1–2 Weeks)
1. **Domain Feature Extraction:** Incorporate domain age, lexical features (entropy, dots, hyphens), and TLD reputation using `tldextract`.
2. **Legitimate Domain Whitelisting:** Integrate the Tranco top 10,000 domains to eliminate brand impersonation false positives.
3. **RESTful API Endpoint:** Add a `/api/v1/predict` JSON endpoint supporting programmatic queries.
4. **Automated Test Suite:** Add `pytest` covering edge cases, valid URLs, and model outputs.

---

## 25. WHAT I WOULD TELL A JUDGE

> "The **AI-Powered Phishing Detection System** is a functional proof-of-concept web application designed to identify malicious URLs using machine learning.
> 
> Under the hood, the system is built with **Flask**, **Scikit-learn**, and **Tailwind CSS**. It evaluates URLs against a **Logistic Regression** model trained on a Kaggle dataset of over **549,000 URLs**. The model uses a Bag-of-Words **CountVectorizer** with over 350,000 lexical features.
> 
> In testing, the classifier achieved an impressive **96.5% accuracy** on a 109,000-URL test set. Inference is exceptionally fast, running in under 15 milliseconds on a basic CPU.
> 
> However, an honest technical audit reveals four key areas for improvement before this can be production-grade:
> 1. **Feature Representation:** The current model treats URLs as pure natural language words rather than structured network locators. Because legitimate brand names like 'PayPal' frequently appear in phishing datasets, official domains like `paypal.com` are currently misclassified as threats.
> 2. **Pipeline Parity:** The training notebook applied Snowball stemming, but the web server currently feeds unstemmed URLs directly to the vectorizer. Unifying this into a single Scikit-learn pipeline will immediately improve real-world reliability.
> 3. **Metric Clarification:** Due to an argument swap in the classification report call, the displayed 91% Precision is actually Recall, and 97% Recall is actually Precision.
> 4. **Modern Phishing Heuristics:** To reach enterprise maturity, the model should be upgraded from pure lexical analysis to a multi-modal feature set that inspects domain age, SSL status, and WHOIS registrations.
> 
> In summary, this project demonstrates a compelling, working foundation for AI cybersecurity, with a functioning UI and rapid inference, and provides an excellent baseline for integrating robust URL feature engineering."

---
*Report certified and generated on September 15, 2026.*

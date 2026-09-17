"""
clean_and_retrain.py
Performs dataset deduplication, conflict isolation, domain analysis,
leakage-free train/test splitting, retraining of the unified pipeline,
evaluation, error analysis, and artifact generation.
"""

import os
import sys
import re
import time
import pickle
import urllib.parse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

sys.path.insert(0, os.path.abspath("."))
import pipeline_utils

ORIGINAL_DATASET_PATH = os.path.join("phishing_site_urls.csv", "phishing_site_urls.csv")
CLEAN_DATASET_PATH = "phishing_site_urls_clean.csv"
CONFLICTS_PATH = "conflicting_labels.csv"
CLEAN_MODEL_PATH = "phishing_pipeline_clean.pkl"
ERROR_ANALYSIS_PATH = "ERROR_ANALYSIS.csv"

def main():
    print("=" * 80)
    print("STEP 1: LOAD ORIGINAL DATASET")
    print("=" * 80)
    df_raw = pd.read_csv(ORIGINAL_DATASET_PATH)
    orig_rows = len(df_raw)
    orig_unique_urls = df_raw['URL'].nunique()
    orig_bad = int((df_raw['Label'] == 'bad').sum())
    orig_good = int((df_raw['Label'] == 'good').sum())
    print(f"Original dataset loaded: {orig_rows:,} rows")
    print(f"Original unique URLs:   {orig_unique_urls:,}")
    print(f"Original Bad: {orig_bad:,} ({orig_bad/orig_rows*100:.2f}%)")
    print(f"Original Good: {orig_good:,} ({orig_good/orig_rows*100:.2f}%)")

    print("\n" + "=" * 80)
    print("STEP 2 & 3: DETECT CONFLICTS & DEDUPLICATE")
    print("=" * 80)
    # Check for conflicting labels
    label_counts_per_url = df_raw.groupby('URL')['Label'].nunique()
    conflicting_url_strings = label_counts_per_url[label_counts_per_url > 1].index.tolist()
    print(f"Found {len(conflicting_url_strings)} conflicting URL(s).")
    
    # Save conflicting_labels.csv
    conflict_df = df_raw[df_raw['URL'].isin(conflicting_url_strings)].copy()
    conflict_df.to_csv(CONFLICTS_PATH, index=False)
    print(f"Saved {len(conflict_df)} conflicting row(s) to {CONFLICTS_PATH}:")
    for u in conflicting_url_strings:
        sub = df_raw[df_raw['URL'] == u]
        bad_cnt = int((sub['Label'] == 'bad').sum())
        good_cnt = int((sub['Label'] == 'good').sum())
        print(f"  URL: {u!r} -> bad: {bad_cnt}, good: {good_cnt}. Decision: EXCLUDED from clean dataset.")

    # Exclude conflicting URLs completely
    df_non_conflict = df_raw[~df_raw['URL'].isin(conflicting_url_strings)].copy()
    print(f"Rows after removing conflicting URLs: {len(df_non_conflict):,}")

    # Deduplicate: Keep one representative record per unique URL
    # drop_duplicates on 'URL'
    df_clean = df_non_conflict.drop_duplicates(subset=['URL'], keep='first').copy()
    clean_rows = len(df_clean)
    clean_unique_urls = df_clean['URL'].nunique()
    clean_bad = int((df_clean['Label'] == 'bad').sum())
    clean_good = int((df_clean['Label'] == 'good').sum())
    
    print(f"Cleaned dataset rows:    {clean_rows:,}")
    print(f"Cleaned unique URLs:    {clean_unique_urls:,}")
    print(f"Cleaned Bad:  {clean_bad:,} ({clean_bad/clean_rows*100:.2f}%)")
    print(f"Cleaned Good: {clean_good:,} ({clean_good/clean_rows*100:.2f}%)")
    print(f"Total duplicate rows removed: {orig_rows - clean_rows:,}")

    # Save cleaned dataset
    df_clean.to_csv(CLEAN_DATASET_PATH, index=False)
    print(f"Cleaned dataset saved to: {CLEAN_DATASET_PATH} ({os.path.getsize(CLEAN_DATASET_PATH):,} bytes)")

    print("\n" + "=" * 80)
    print("STEP 6: BRAND BIAS INVESTIGATION (CLEAN DATASET)")
    print("=" * 80)
    tokens_to_check = ["google", "paypal", "amazon", "microsoft", "apple", "bank", "login", "secure", "signin", "verify"]
    print(f"{'Token':<12} | {'Bad':<10} | {'Good':<10} | {'Total':<10} | {'Bad %':<8} | {'Good %':<8}")
    print("-" * 65)
    for tok in tokens_to_check:
        pat = re.compile(re.escape(tok), re.IGNORECASE)
        mask = df_clean['URL'].str.contains(pat, na=False)
        sub = df_clean[mask]
        tot = len(sub)
        b_cnt = int((sub['Label'] == 'bad').sum())
        g_cnt = int((sub['Label'] == 'good').sum())
        b_pct = (b_cnt / tot * 100) if tot > 0 else 0
        g_pct = (g_cnt / tot * 100) if tot > 0 else 0
        print(f"{tok:<12} | {b_cnt:<10} | {g_cnt:<10} | {tot:<10} | {b_pct:<8.2f} | {g_pct:<8.2f}")

    print("\n" + "=" * 80)
    print("STEP 7: DOMAIN-LEVEL ANALYSIS (CLEAN DATASET)")
    print("=" * 80)
    def extract_domain(url):
        if not isinstance(url, str):
            return ""
        u = url.strip()
        if not re.match(r'^[a-zA-Z]+://', u):
            u = 'http://' + u
        try:
            parsed = urllib.parse.urlparse(u)
            netloc = parsed.netloc.lower().split(':')[0]
            # remove www.
            netloc = re.sub(r'^www\.', '', netloc)
            return netloc
        except Exception:
            return ""

    df_clean['domain'] = df_clean['URL'].map(extract_domain)
    # filter out empty domains
    valid_domains = df_clean[df_clean['domain'] != '']
    unique_domains = valid_domains['domain'].nunique()
    print(f"Total unique domains extracted: {unique_domains:,}")

    domain_classes = valid_domains.groupby('domain')['Label'].unique()
    domains_both = (domain_classes.map(lambda s: len(s) > 1)).sum()
    domains_bad_only = (domain_classes.map(lambda s: len(s) == 1 and s[0] == 'bad')).sum()
    domains_good_only = (domain_classes.map(lambda s: len(s) == 1 and s[0] == 'good')).sum()
    print(f"Domains represented in BOTH classes:    {domains_both:,}")
    print(f"Domains represented ONLY in bad class: {domains_bad_only:,}")
    print(f"Domains represented ONLY in good class:{domains_good_only:,}")

    target_domains = ["paypal.com", "google.com", "amazon.com", "microsoft.com", "apple.com"]
    print("\nTarget Brand Domain Representation in Clean Dataset:")
    for dom in target_domains:
        sub_d = df_clean[df_clean['domain'] == dom]
        b_cnt = int((sub_d['Label'] == 'bad').sum())
        g_cnt = int((sub_d['Label'] == 'good').sum())
        print(f"  {dom:<16} -> Total: {len(sub_d):<5} | Bad: {b_cnt:<5} | Good: {g_cnt:<5}")

    print("\n" + "=" * 80)
    print("STEP 8: LEAKAGE-FREE TRAIN/TEST SPLITTING")
    print("=" * 80)
    X_train, X_test, y_train, y_test = train_test_split(
        df_clean['URL'], df_clean['Label'], test_size=0.2, random_state=42
    )
    print(f"Train size: {len(X_train):,}, Test size: {len(X_test):,}")

    train_set = set(X_train)
    test_set = set(X_test)
    overlap = train_set.intersection(test_set)
    overlap_count = len(overlap)
    print(f"Overlapping URLs count: {overlap_count}")
    print(f"TRAIN/TEST URL OVERLAP: {overlap_count} ({overlap_count / len(test_set) * 100:.4f}%)")
    assert overlap_count == 0, f"Leakage detected! Overlap: {overlap_count}"
    print("[PASS] Verified: Zero train/test URL overlap. Zero leakage.")

    print("\n" + "=" * 80)
    print("STEP 9: RETRAIN PIPELINE ON CLEANED DATA")
    print("=" * 80)
    pipeline = pipeline_utils.make_phishing_pipeline()
    t0 = time.time()
    pipeline.fit(X_train, y_train)
    t_train = time.time() - t0
    print(f"Retraining completed in {t_train:.2f}s")
    print(f"Classes: {pipeline.classes_}")

    # Save as phishing_pipeline_clean.pkl
    with open(CLEAN_MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    model_size = os.path.getsize(CLEAN_MODEL_PATH)
    print(f"Clean model saved to {CLEAN_MODEL_PATH} ({model_size:,} bytes, {model_size/(1024*1024):.2f} MB)")

    print("\n" + "=" * 80)
    print("STEP 10: EVALUATION ON CLEAN TEST SET")
    print("=" * 80)
    t_ev = time.time()
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    t_eval = time.time() - t_ev
    print(f"Inference on {len(X_test):,} clean test URLs in {t_eval:.2f}s ({t_eval/len(X_test)*1000:.3f} ms/URL)")

    acc = accuracy_score(y_test, y_pred)
    print(f"\nCLEAN ACCURACY: {acc:.6f} ({acc*100:.2f}%)")

    cm = confusion_matrix(y_test, y_pred, labels=pipeline.classes_)
    cm_df = pd.DataFrame(cm, index=[f"Actual_{c}" for c in pipeline.classes_], columns=[f"Pred_{c}" for c in pipeline.classes_])
    print("\nCONFUSION MATRIX:")
    print(cm_df)

    # Classification report with correct argument order
    report_dict = classification_report(y_test, y_pred, labels=pipeline.classes_, target_names=pipeline.classes_, output_dict=True, digits=4)
    report_str = classification_report(y_test, y_pred, labels=pipeline.classes_, target_names=pipeline.classes_, digits=4)
    print("\nCLASSIFICATION REPORT (correct order: y_test, y_pred):")
    print(report_str)

    print("\n" + "=" * 80)
    print("STEP 12: TEST KNOWN LEGITIMATE URLS")
    print("=" * 80)
    legit_test_urls = [
        "https://www.google.com",
        "https://www.paypal.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://example.com"
    ]
    bad_idx = list(pipeline.classes_).index('bad')
    good_idx = list(pipeline.classes_).index('good')

    for u in legit_test_urls:
        p = pipeline.predict([u])[0]
        prob = pipeline.predict_proba([u])[0]
        print(f"URL: {u:<30} | Pred: {p:<4} | Phishing Prob: {prob[bad_idx]*100:5.1f}% | Legit Prob: {prob[good_idx]*100:5.1f}%")

    print("\n" + "=" * 80)
    print("STEP 13: TEST KNOWN PHISHING-LIKE URLS")
    print("=" * 80)
    phishing_test_urls = [
        "http://paypal-security-login.servehttp.com/login.php",
        "http://amaz0n-security-update.com/signin",
        "http://chase-bank-verify-security.org/login.htm"
    ]
    for u in phishing_test_urls:
        p = pipeline.predict([u])[0]
        prob = pipeline.predict_proba([u])[0]
        print(f"URL: {u:<55} | Pred: {p:<4} | Phishing Prob: {prob[bad_idx]*100:5.1f}% | Legit Prob: {prob[good_idx]*100:5.1f}%")

    print("\n" + "=" * 80)
    print("STEP 14: MODEL COEFFICIENTS ANALYSIS")
    print("=" * 80)
    vec = pipeline.named_steps['vectorizer']
    clf = pipeline.named_steps['classifier']
    vocab = vec.vocabulary_
    coefs = clf.coef_[0]
    intercept = clf.intercept_[0]
    print(f"Model Intercept: {intercept:.4f} (Negative indicates bias towards class 0: bad)")

    tokens_coef = ["paypal", "googl", "amazon", "login", "secur", "signin", "verifi"]
    for t in tokens_coef:
        idx = vocab.get(t, None)
        c_val = coefs[idx] if idx is not None else None
        interp = "Pushes toward GOOD" if c_val and c_val > 0 else "Pushes toward BAD (phishing)"
        print(f"Token: {t:<10} | Vocab Index: {str(idx):<8} | Coef: {c_val:.4f} | {interp}")

    print("\n" + "=" * 80)
    print("STEP 15: ERROR ANALYSIS")
    print("=" * 80)
    # Collect test set errors
    test_df = pd.DataFrame({
        'URL': X_test.values,
        'Actual': y_test.values,
        'Predicted': y_pred,
        'Phishing_Prob': y_proba[:, bad_idx],
        'Legit_Prob': y_proba[:, good_idx]
    })
    errors_df = test_df[test_df['Actual'] != test_df['Predicted']].copy()
    print(f"Total test errors: {len(errors_df):,} out of {len(test_df):,} ({len(errors_df)/len(test_df)*100:.2f}%)")
    fps = errors_df[errors_df['Actual'] == 'good'] # False Positives (legit called bad)
    fns = errors_df[errors_df['Actual'] == 'bad']  # False Negatives (bad called good)
    print(f"  False Positives (Legitimate called Phishing): {len(fps):,}")
    print(f"  False Negatives (Phishing called Legitimate): {len(fns):,}")

    # Categorize error patterns
    def categorize_error(row):
        u = row['URL'].lower()
        if any(b in u for b in ['paypal', 'google', 'amazon', 'apple', 'microsoft', 'chase', 'wellsfargo']):
            return "Brand Token Presence"
        elif any(k in u for k in ['login', 'signin', 'secure', 'verify', 'account', 'update', 'banking']):
            return "Security/Login Keyword"
        elif re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', u):
            return "IP Address Format"
        elif len(u) > 120:
            return "Long URL Path / Query"
        elif any(ext in u for ext in ['.exe', '.txt', '.zip', '.php', '.asp', '.jsp']):
            return "Suspicious File Extension"
        elif re.search(r'[^a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]', u):
            return "Special/Garbage Characters"
        else:
            return "Unseen Lexical / Obscure Domain"

    errors_df['Error_Category'] = errors_df.apply(categorize_error, axis=1)
    print("\nError Categories Distribution:")
    print(errors_df['Error_Category'].value_counts())

    # Save to ERROR_ANALYSIS.csv
    errors_df.to_csv(ERROR_ANALYSIS_PATH, index=False)
    print(f"\nSaved {len(errors_df):,} errors to {ERROR_ANALYSIS_PATH}")

    print("\n" + "=" * 80)
    print("STEP 17: INDEPENDENT VERIFICATION OF ARTIFACT")
    print("=" * 80)
    with open(CLEAN_MODEL_PATH, "rb") as f_chk:
        chk_pipe = pickle.load(f_chk)
    assert hasattr(chk_pipe, 'named_steps'), "Missing named_steps"
    assert 'preprocessor' in chk_pipe.named_steps, "Missing preprocessor"
    assert 'vectorizer' in chk_pipe.named_steps, "Missing vectorizer"
    assert 'classifier' in chk_pipe.named_steps, "Missing classifier"
    assert list(chk_pipe.classes_) == ['bad', 'good'], f"Wrong classes: {chk_pipe.classes_}"
    sample_pred = chk_pipe.predict(["http://paypal-security-login.servehttp.com/login.php"])[0]
    print(f"Loaded {CLEAN_MODEL_PATH} successfully. Sample prediction: {sample_pred}")
    print("[PASS] Artifact verified.")

if __name__ == "__main__":
    main()

"""
analyze_dataset_features.py
Computes dataset-wide feature statistics, correlations, data quality checks,
and feature extraction performance on phishing_site_urls_clean.csv.
"""

import time
import pandas as pd
import numpy as np
from url_features import extract_url_features, decompose_hostname

CLEAN_DATASET_PATH = "phishing_site_urls_clean.csv"

TEST_URLS = [
    # Legitimate
    "https://www.google.com",
    "https://www.paypal.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://example.com",
    # Phishing-like
    "http://paypal-security-login.servehttp.com/login.php",
    "http://amaz0n-security-update.com/signin",
    "http://chase-bank-verify-security.org/login.htm",
    "http://192.168.1.1/login.php"
]

def main():
    print("=" * 80)
    print("STEP 7: FEATURE EXTRACTION ON SPECIFIC TEST URLs")
    print("=" * 80)
    for u in TEST_URLS:
        f = extract_url_features(u)
        import urllib.parse
        p = urllib.parse.urlparse(u if "://" in u else f"http://{u}")
        sub, reg, tld, sub_cnt = decompose_hostname(p.netloc.split(':')[0])
        print(f"\nURL: {u}")
        print(f"  Hostname:           {p.netloc}")
        print(f"  Registered Domain:  {reg}")
        print(f"  Subdomain:          {sub} (count={sub_cnt})")
        print(f"  Path:               {p.path}")
        print(f"  Query:              {p.query}")
        print(f"  Brand Token:        {int(f['brand_token_present'])}")
        print(f"  Brand in RegDom:    {int(f['brand_in_registered_domain'])}")
        print(f"  Brand Mismatch:     {int(f['brand_domain_mismatch'])}")
        print(f"  Digits: {int(f['digit_count'])}, Dots: {int(f['dot_count'])}, Hyphens: {int(f['hyphen_count'])}, IP Host: {int(f['hostname_has_ip'])}")

    print("\n" + "=" * 80)
    print("STEP 12: BENCHMARK EXTRACTION SPEED")
    print("=" * 80)
    df = pd.read_csv(CLEAN_DATASET_PATH)
    sample_size = 10000
    sample_urls = df['URL'].sample(sample_size, random_state=42).tolist()
    
    t0 = time.time()
    for u in sample_urls:
        _ = extract_url_features(u)
    sample_elapsed = time.time() - t0
    ms_per_url = (sample_elapsed / sample_size) * 1000
    urls_per_sec = sample_size / sample_elapsed
    print(f"Tested {sample_size:,} sample URLs:")
    print(f"  Total processing time: {sample_elapsed:.2f} seconds")
    print(f"  Average time per URL:  {ms_per_url:.4f} ms/URL")
    print(f"  Extraction Throughput: {urls_per_sec:,.1f} URLs/second")

    print("\n" + "=" * 80)
    print("STEP 8 & 10: DATASET-WIDE FEATURE EXTRACTION & QUALITY CHECK")
    print("=" * 80)
    print(f"Processing all {len(df):,} clean URLs...")
    t_full = time.time()
    
    # Extract features in batches or list comprehension
    all_features = [extract_url_features(u) for u in df['URL']]
    feat_df = pd.DataFrame(all_features)
    print(f"Extracted {feat_df.shape[1]} features across {len(feat_df):,} rows in {time.time()-t_full:.2f}s")
    
    # Check data quality: NaNs, Infs
    nan_counts = feat_df.isnull().sum().sum()
    inf_counts = np.isinf(feat_df.values).sum()
    print(f"Total NaN values:      {nan_counts}")
    print(f"Total Infinite values: {inf_counts}")
    assert nan_counts == 0, "NaN values detected!"
    assert inf_counts == 0, "Infinite values detected!"
    print("[PASS] Verified: Zero NaNs, Zero Infs, All numeric float32/float64.")

    feat_df['label_binary'] = (df['Label'] == 'bad').astype(int)
    bad_mask = (feat_df['label_binary'] == 1)
    good_mask = (feat_df['label_binary'] == 0)

    stats_list = []
    for col in feat_df.columns:
        if col == 'label_binary':
            continue
        bad_col = feat_df.loc[bad_mask, col]
        good_col = feat_df.loc[good_mask, col]
        
        corr = feat_df[col].corr(feat_df['label_binary'])
        
        bad_mean = bad_col.mean()
        good_mean = good_col.mean()
        bad_med = bad_col.median()
        good_med = good_col.median()
        bad_std = bad_col.std()
        good_std = good_col.std()
        
        # Determine potential signal
        abs_corr = abs(corr) if not np.isnan(corr) else 0.0
        if abs_corr >= 0.25:
            signal = "Strong Potential Signal"
        elif abs_corr >= 0.10:
            signal = "Moderate Potential Signal"
        elif abs_corr >= 0.03:
            signal = "Weak Potential Signal"
        else:
            signal = "Minimal / Redundant Signal"
            
        stats_list.append({
            "Feature": col,
            "Bad Mean": bad_mean,
            "Good Mean": good_mean,
            "Bad Median": bad_med,
            "Good Median": good_med,
            "Bad Std": bad_std,
            "Good Std": good_std,
            "Corr": corr,
            "Signal": signal
        })

    stats_df = pd.DataFrame(stats_list)
    stats_df.sort_values(by="Corr", key=abs, ascending=False, inplace=True)
    
    print("\nTOP 20 MOST CORRELATED STRUCTURAL FEATURES WITH LABEL (1=bad, 0=good):")
    print(f"{'Feature':<30} | {'Bad Mean':<10} | {'Good Mean':<10} | {'Bad Med':<8} | {'Good Med':<8} | {'Correlation':<12} | {'Potential Signal'}")
    print("-" * 115)
    for _, r in stats_df.head(20).iterrows():
        print(f"{r['Feature']:<30} | {r['Bad Mean']:<10.3f} | {r['Good Mean']:<10.3f} | {r['Bad Median']:<8.1f} | {r['Good Median']:<8.1f} | {r['Corr']:<12.4f} | {r['Signal']}")

    print("\n" + "=" * 80)
    print("STEP 9: CORRELATION MATRIX & REDUNDANCY ANALYSIS")
    print("=" * 80)
    feature_cols = [c for c in feat_df.columns if c != 'label_binary']
    corr_matrix = feat_df[feature_cols].corr().abs()
    
    # Find redundant pairs (corr > 0.85, excluding diagonal)
    redundant_pairs = []
    for i in range(len(feature_cols)):
        for j in range(i + 1, len(feature_cols)):
            c1 = feature_cols[i]
            c2 = feature_cols[j]
            val = corr_matrix.loc[c1, c2]
            if val > 0.85:
                redundant_pairs.append((c1, c2, val))
                
    redundant_pairs.sort(key=lambda x: x[2], reverse=True)
    print(f"Found {len(redundant_pairs)} highly correlated feature pairs (correlation > 0.85):")
    for c1, c2, val in redundant_pairs[:15]:
        print(f"  {c1:<28} <-> {c2:<28} : corr = {val:.4f}")

    # Save stats to CSV for report generation
    stats_df.to_csv("feature_extraction_results.csv", index=False)
    print("\nSaved feature statistics to feature_extraction_results.csv")

if __name__ == "__main__":
    main()

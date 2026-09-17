"""
build_anchor_dataset.py
Constructs legitimate_anchor_urls.csv and performs strict contamination checks
against the V2 train set and V2 test set.
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split

CLEAN_DATASET_PATH = "phishing_site_urls_clean.csv"
ANCHOR_CSV_PATH = "legitimate_anchor_urls.csv"

# Curated anchor candidates with provenance
ANCHOR_CANDIDATES = [
    # PayPal (Currently 0 legitimate samples in clean dataset)
    ("https://www.paypal.com", "good", "Official Root Portal", "paypal.com", "Canonical homepage for global payment platform"),
    ("https://www.paypal.com/", "good", "Official Root Portal", "paypal.com", "Canonical homepage with trailing slash"),
    ("https://www.paypal.com/us/home", "good", "Official Regional Portal", "paypal.com", "Official US localized portal"),
    ("https://www.paypal.com/signin", "good", "Official Auth Entry", "paypal.com", "Official authentication portal"),
    ("https://www.paypal.com/us/signin", "good", "Official Auth Entry", "paypal.com", "Official US authentication endpoint"),
    ("https://www.paypal.com/us/webapps/mpp/account-selection", "good", "Official Onboarding", "paypal.com", "Official registration flow"),
    ("https://www.paypal.com/us/smarthelp/contact-us", "good", "Official Support", "paypal.com", "Official customer support center"),
    ("https://www.paypal.com/us/security", "good", "Official Security Center", "paypal.com", "Official user security guide"),

    # Google
    ("https://www.google.com", "good", "Official Root Portal", "google.com", "Canonical search engine homepage"),
    ("https://www.google.com/", "good", "Official Root Portal", "google.com", "Canonical search homepage with trailing slash"),
    ("https://accounts.google.com", "good", "Official Auth Subdomain", "google.com", "Google Identity authentication entry"),
    ("https://accounts.google.com/signin", "good", "Official Auth Entry", "google.com", "Google Identity sign-in flow"),
    ("https://mail.google.com", "good", "Official Service Subdomain", "google.com", "Official Gmail web client"),
    ("https://docs.google.com", "good", "Official Service Subdomain", "google.com", "Official Google Docs workspace"),
    ("https://support.google.com", "good", "Official Support", "google.com", "Google centralized help center"),
    ("https://maps.google.com", "good", "Official Maps Service", "google.com", "Official Google Maps interface"),

    # Amazon
    ("https://www.amazon.com", "good", "Official Root Portal", "amazon.com", "Canonical e-commerce store homepage"),
    ("https://www.amazon.com/", "good", "Official Root Portal", "amazon.com", "Canonical store homepage with trailing slash"),
    ("https://www.amazon.com/gp/help/customer/display.html", "good", "Official Help Portal", "amazon.com", "Amazon customer service portal"),
    ("https://www.amazon.com/gp/css/homepage.html", "good", "Official Account Portal", "amazon.com", "Amazon account management dashboard"),
    ("https://www.amazon.com/ap/signin", "good", "Official Auth Entry", "amazon.com", "Amazon authentication gateway"),
    ("https://music.amazon.com", "good", "Official Streaming Service", "amazon.com", "Amazon Music streaming platform"),
    ("https://aws.amazon.com", "good", "Official Cloud Portal", "amazon.com", "Amazon Web Services infrastructure portal"),

    # Microsoft
    ("https://www.microsoft.com", "good", "Official Root Portal", "microsoft.com", "Canonical Microsoft corporate portal"),
    ("https://www.microsoft.com/", "good", "Official Root Portal", "microsoft.com", "Canonical Microsoft homepage with trailing slash"),
    ("https://www.microsoft.com/en-us/windows", "good", "Official Product Page", "microsoft.com", "Official Windows OS landing page"),
    ("https://support.microsoft.com", "good", "Official Support", "microsoft.com", "Microsoft technical support portal"),
    ("https://account.microsoft.com", "good", "Official Account Portal", "microsoft.com", "Microsoft centralized user account portal"),
    ("https://azure.microsoft.com", "good", "Official Cloud Portal", "microsoft.com", "Microsoft Azure cloud services portal"),

    # Apple
    ("https://www.apple.com", "good", "Official Root Portal", "apple.com", "Canonical Apple hardware & software homepage"),
    ("https://www.apple.com/", "good", "Official Root Portal", "apple.com", "Canonical Apple homepage with trailing slash"),
    ("https://www.apple.com/iphone/", "good", "Official Product Page", "apple.com", "Official iPhone product directory"),
    ("https://support.apple.com", "good", "Official Support", "apple.com", "Apple technical support center"),
    ("https://appleid.apple.com", "good", "Official Auth Portal", "apple.com", "Apple ID authentication management"),
    ("https://developer.apple.com", "good", "Official Developer Portal", "apple.com", "Apple developer documentation portal"),

    # Chase
    ("https://www.chase.com", "good", "Official Banking Portal", "chase.com", "JPMorgan Chase consumer banking homepage"),
    ("https://www.chase.com/", "good", "Official Banking Portal", "chase.com", "Chase banking homepage with trailing slash"),
    ("https://secure.chase.com", "good", "Official Secure Banking", "chase.com", "Chase online banking secure entry"),
    ("https://www.chase.com/personal/credit-cards", "good", "Official Product Line", "chase.com", "Chase credit cards product page"),
    ("https://www.chase.com/digital/customer-service", "good", "Official Customer Service", "chase.com", "Chase digital customer support"),

    # Bank of America
    ("https://www.bankofamerica.com", "good", "Official Banking Portal", "bankofamerica.com", "Bank of America consumer banking portal"),
    ("https://www.bankofamerica.com/", "good", "Official Banking Portal", "bankofamerica.com", "Bank of America homepage with trailing slash"),
    ("https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go", "good", "Official Secure Banking", "bankofamerica.com", "Bank of America online banking login"),
    ("https://www.bankofamerica.com/help/overview/", "good", "Official Help Center", "bankofamerica.com", "Bank of America customer help center"),

    # Netflix
    ("https://www.netflix.com", "good", "Official Root Portal", "netflix.com", "Netflix entertainment streaming homepage"),
    ("https://www.netflix.com/", "good", "Official Root Portal", "netflix.com", "Netflix streaming homepage with trailing slash"),
    ("https://www.netflix.com/login", "good", "Official Auth Entry", "netflix.com", "Netflix subscriber sign-in portal"),
    ("https://help.netflix.com", "good", "Official Help Center", "netflix.com", "Netflix subscriber support center"),

    # GitHub
    ("https://github.com", "good", "Official Developer Platform", "github.com", "GitHub software development homepage"),
    ("https://github.com/login", "good", "Official Auth Entry", "github.com", "GitHub user authentication portal"),
    ("https://github.com/features", "good", "Official Product Page", "github.com", "GitHub platform features directory"),
    ("https://docs.github.com", "good", "Official Documentation", "github.com", "GitHub official technical documentation"),

    # LinkedIn
    ("https://www.linkedin.com", "good", "Official Professional Network", "linkedin.com", "LinkedIn professional network homepage"),
    ("https://www.linkedin.com/login", "good", "Official Auth Entry", "linkedin.com", "LinkedIn member sign-in portal"),
    ("https://www.linkedin.com/feed/", "good", "Official Application Feed", "linkedin.com", "LinkedIn member news feed"),
    ("https://www.linkedin.com/help/linkedin", "good", "Official Help Center", "linkedin.com", "LinkedIn member support center"),

    # Facebook
    ("https://www.facebook.com", "good", "Official Social Network", "facebook.com", "Facebook social network homepage"),
    ("https://www.facebook.com/login/", "good", "Official Auth Entry", "facebook.com", "Facebook member sign-in portal"),
    ("https://www.facebook.com/help/", "good", "Official Help Center", "facebook.com", "Facebook user support center"),

    # Instagram
    ("https://www.instagram.com", "good", "Official Photo Platform", "instagram.com", "Instagram social photo homepage"),
    ("https://www.instagram.com/accounts/login/", "good", "Official Auth Entry", "instagram.com", "Instagram account login page"),
    ("https://about.instagram.com", "good", "Official Corporate Portal", "instagram.com", "Instagram official information center"),

    # Example (RFC 2606 standard reserved domain)
    ("https://example.com", "good", "RFC 2606 Reserved Domain", "example.com", "IANA designated official example domain"),
    ("https://example.com/", "good", "RFC 2606 Reserved Domain", "example.com", "IANA example domain with trailing slash"),
    ("http://example.com", "good", "RFC 2606 Reserved Domain", "example.com", "IANA example domain HTTP endpoint")
]

def main():
    print("Loading clean dataset to verify split...")
    df_clean = pd.read_csv(CLEAN_DATASET_PATH)
    X_train, X_test, y_train, y_test = train_test_split(
        df_clean['URL'], df_clean['Label'], test_size=0.2, random_state=42
    )
    
    train_set = set(X_train)
    test_set = set(X_test)
    clean_set = set(df_clean['URL'])
    
    print(f"Clean total: {len(df_clean):,}")
    print(f"V2 Train set: {len(train_set):,}")
    print(f"V2 Test set:  {len(test_set):,}")
    
    # Contamination check on anchor candidates
    rows = []
    test_overlap_found = []
    train_overlap_found = []
    
    for url, label, source, domain, rationale in ANCHOR_CANDIDATES:
        in_test = url in test_set
        in_train = url in train_set
        in_clean = url in clean_set
        
        if in_test:
            test_overlap_found.append(url)
        if in_train:
            train_overlap_found.append(url)
            
        rows.append({
            "url": url,
            "label": label,
            "source": source,
            "domain": domain,
            "rationale": rationale,
            "in_train": in_train,
            "in_test": in_test
        })
        
    anchor_df = pd.DataFrame(rows)
    
    print("\n--- CONTAMINATION CHECK RESULTS ---")
    print(f"Total anchor candidates: {len(anchor_df)}")
    print(f"Candidates overlapping with V2 TEST set:  {len(test_overlap_found)}")
    print(f"Candidates overlapping with V2 TRAIN set: {len(train_overlap_found)}")
    
    if test_overlap_found:
        print(f"[ALERT] Found {len(test_overlap_found)} URLs in test set! These MUST be excluded from training augmentation.")
        for u in test_overlap_found:
            print(f"   -> {u}")
            
    if train_overlap_found:
        print(f"Found {len(train_overlap_found)} URLs already in train set:")
        for u in train_overlap_found:
            print(f"   -> {u}")
            
    # Filter out any anchor URL that might appear in the test set to strictly guarantee zero test set contamination
    eligible_anchors = anchor_df[~anchor_df['in_test']].copy()
    print(f"\nEligible anchors for training augmentation: {len(eligible_anchors)}")
    
    # Save legitimate_anchor_urls.csv with required columns
    export_cols = ["url", "label", "source", "domain", "rationale"]
    eligible_anchors[export_cols].to_csv(ANCHOR_CSV_PATH, index=False)
    print(f"Saved {len(eligible_anchors)} anchor records to {ANCHOR_CSV_PATH}")

if __name__ == "__main__":
    main()

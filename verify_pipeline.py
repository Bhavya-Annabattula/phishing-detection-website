"""
verify_pipeline.py
Compares old pipeline vs new pipeline on test URLs:
- Verifies preprocessing parity
- Displays old prediction & probabilities
- Displays new prediction & probabilities
- Confirms no double preprocessing
"""

import pickle
import re
import pipeline_utils # ensures custom class is known

TEST_URLS = [
    "https://www.google.com",
    "https://www.paypal.com",
    "https://amazon.com",
    "http://paypal-security-login.servehttp.com/login.php",
    "http://amaz0n-security-update.com/signin",
    "https://example.com",
    "http://192.168.1.1/login.php",
    "htt:/\invalid@#$$%%..com//test",
    "",
    "   "
]

def main():
    print("Loading OLD model artifacts (vectorizer.pkl + phishing.pkl)...")
    with open("vectorizer.pkl", "rb") as f:
        old_vec = pickle.load(f)
    with open("phishing.pkl", "rb") as f:
        old_model = pickle.load(f)
        
    print("Loading NEW model artifact (phishing_pipeline.pkl)...")
    with open("phishing_pipeline.pkl", "rb") as f:
        new_pipeline = pickle.load(f)
        
    print(f"Old model classes: {old_model.classes_}")
    print(f"New pipeline classes: {new_pipeline.classes_}")
    
    # Class index mappings
    old_bad_idx = list(old_model.classes_).index("bad")
    new_bad_idx = list(new_pipeline.classes_).index("bad")
    old_good_idx = list(old_model.classes_).index("good")
    new_good_idx = list(new_pipeline.classes_).index("good")
    
    print("\n" + "="*120)
    print(f"{'TEST URL':<45} | {'OLD (app.py)':<25} | {'NEW (phishing_pipeline)':<25} | {'CHANGED?'}")
    print("="*120)
    
    preprocessor = new_pipeline.named_steps['preprocessor']
    
    results = []
    for url in TEST_URLS:
        # OLD App.py inference path:
        # cleaned_URL = re.sub(r'^https?://(www\.)?','',URL)
        # predict = model.predict(vector.transform([cleaned_URL]))[0]
        cleaned_url = re.sub(r'^https?://(www\.)?', '', url)
        old_vec_x = old_vec.transform([cleaned_url])
        old_pred = old_model.predict(old_vec_x)[0]
        old_proba = old_model.predict_proba(old_vec_x)[0]
        old_bad_p = old_proba[old_bad_idx]
        old_good_p = old_proba[old_good_idx]
        
        # NEW Pipeline inference path:
        # new_pipeline.predict([url])[0]
        # new_pipeline.predict_proba([url])[0]
        new_pred = new_pipeline.predict([url])[0]
        new_proba = new_pipeline.predict_proba([url])[0]
        new_bad_p = new_proba[new_bad_idx]
        new_good_p = new_proba[new_good_idx]
        
        preprocessed_text = preprocessor.transform([url])[0]
        
        changed = "YES" if old_pred != new_pred else "NO"
        
        old_desc = f"{old_pred.upper()} ({old_bad_p*100:.1f}% bad)"
        new_desc = f"{new_pred.upper()} ({new_bad_p*100:.1f}% bad)"
        
        print(f"{url!r:<45} | {old_desc:<25} | {new_desc:<25} | {changed}")
        print(f"   -> Preprocessed token string: {preprocessed_text!r}")
        print(f"   -> Old cleaned string:        {cleaned_url!r}")
        
        results.append({
            "url": url,
            "preprocessed": preprocessed_text,
            "old_pred": old_pred,
            "old_bad_p": old_bad_p,
            "new_pred": new_pred,
            "new_bad_p": new_bad_p,
            "changed": changed
        })
        
    print("="*120)

if __name__ == "__main__":
    main()

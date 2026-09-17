"""
retrain_pipeline.py
Retrains the AI phishing detection model using the unified pipeline
and evaluates it with proper metric argument order.
"""

import os
import time
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from pipeline_utils import make_phishing_pipeline

DATASET_PATH = os.path.join("phishing_site_urls.csv", "phishing_site_urls.csv")
OUTPUT_MODEL_PATH = "phishing_pipeline.pkl"

def main():
    print(f"Loading dataset from: {DATASET_PATH}")
    t0 = time.time()
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns in {time.time()-t0:.2f}s")
    
    # Check nulls
    print(f"Null URLs: {df['URL'].isnull().sum()}, Null Labels: {df['Label'].isnull().sum()}")
    
    # Train / Test split (80/20) matching the notebook
    print("Splitting dataset into train (80%) and test (20%)...")
    X_train, X_test, y_train, y_test = train_test_split(
        df['URL'], df['Label'], test_size=0.2, random_state=42
    )
    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")
    
    # Create unified pipeline
    print("Initializing make_phishing_pipeline()...")
    pipeline = make_phishing_pipeline()
    
    # Fit pipeline
    print("Fitting pipeline (URLTextPreprocessor -> CountVectorizer -> LogisticRegression)...")
    t_train = time.time()
    pipeline.fit(X_train, y_train)
    print(f"Training completed in {time.time()-t_train:.2f}s")
    
    # Inspect classes
    print("\n--- MODEL CLASSES ---")
    print(f"pipeline.classes_: {pipeline.classes_}")
    for idx, cls_name in enumerate(pipeline.classes_):
        print(f"  Index {idx} -> Class: {cls_name}")
        
    # Save pipeline
    print(f"\nSaving pipeline to {OUTPUT_MODEL_PATH}...")
    with open(OUTPUT_MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    model_size = os.path.getsize(OUTPUT_MODEL_PATH)
    print(f"Saved successfully. File size: {model_size:,} bytes ({model_size / (1024*1024):.2f} MB)")
    
    # Evaluation
    print("\n--- EVALUATION ON TEST SET (109,870 URLs) ---")
    t_eval = time.time()
    y_pred = pipeline.predict(X_test)
    eval_time = time.time() - t_eval
    print(f"Inference on {len(X_test)} test URLs completed in {eval_time:.2f}s ({eval_time/len(X_test)*1000:.3f} ms/URL)")
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc:.6f} ({acc*100:.2f}%)")
    
    print("\nCONFUSION MATRIX (rows=Actual, cols=Predicted):")
    cm = confusion_matrix(y_test, y_pred, labels=pipeline.classes_)
    cm_df = pd.DataFrame(cm, index=[f"Actual_{c}" for c in pipeline.classes_], columns=[f"Pred_{c}" for c in pipeline.classes_])
    print(cm_df)
    
    print("\nCLASSIFICATION REPORT (correct order: y_true, y_pred):")
    report = classification_report(y_test, y_pred, labels=pipeline.classes_, target_names=pipeline.classes_, digits=4)
    print(report)

if __name__ == "__main__":
    main()

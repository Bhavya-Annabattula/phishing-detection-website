# AI-Powered Phishing Detection System
A cybersecurity web application that detects phishing URLs in real time using 
Machine Learning trained on 109,870+ URLs.

## Live Demo
https://phishing-detection-website-l5jy.onrender.com/
> Note: Hosted on Render free tier — allow 30–60s for cold start on first load.

## Problem Statement
Phishing attacks account for over 36% of data breaches globally. Existing 
blocklists fail against newly registered phishing domains. This project takes 
a feature-engineering approach — analyzing structural URL patterns to classify 
URLs without relying on known-bad lists.

## How It Works
1. User submits a URL
2. Feature extractor parses 15+ URL characteristics (see Features section)
3. Logistic Regression model returns legitimate / phishing prediction instantly

## Features Engineered
- URL length, number of dots, hyphens, underscores
- Presence of `@`, `//`, `-` in domain
- Subdomain depth
- Use of IP address instead of domain name
- HTTPS presence
- URL entropy (randomness score)
- TF-IDF vectorization of URL tokens

## Model Performance (Logistic Regression — Production Model)
| Metric    | Score |
|-----------|-------|
| Accuracy  | 97%   |
| Precision | 91%   |
| Recall    | 97%   |
| F1 Score  | 0.94  |
| Dataset   | 109,870 URLs |

High recall is intentionally prioritized — it is safer to flag a legitimate 
URL as suspicious than to miss an actual phishing attempt.

## Model Comparison
| Model                  | Accuracy |
|------------------------|----------|
| Logistic Regression    | 97%      |
| Multinomial Naive Bayes| 96%      |

Logistic Regression selected for production due to better precision-recall 
balance and interpretability.

## Tech Stack
- **Backend:** Python, Flask
- **ML:** Scikit-learn (Logistic Regression, Multinomial Naive Bayes)
- **Feature Engineering:** Custom URL parser + TF-IDF vectorization
- **Frontend:** HTML, Tailwind CSS
- **Deployment:** Render

## Installation
```bash
git clone https://github.com/Bhavya-Annabattula/phishing-detection-website.git
cd phishing-detection-website
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000
```

## Author
**Bhavya Annabattula**  
[LinkedIn](https://www.linkedin.com/in/bhavya-annabattula-692112320) | 
[GitHub](https://github.com/Bhavya-Annabattula)

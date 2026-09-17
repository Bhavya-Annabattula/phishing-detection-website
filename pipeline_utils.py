"""
pipeline_utils.py
Reusable preprocessor and pipeline constructor for the AI Phishing Detection project.
Ensures 100% training-inference preprocessing parity.
"""

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer


class URLTextPreprocessor(BaseEstimator, TransformerMixin):
    """
    Transforms raw URLs into stemmed token strings, matching the exact
    preprocessing implemented in ai phishing.ipynb:
      1. RegexpTokenizer(r'[A-Za-z]+')
      2. SnowballStemmer('english')
      3. Tokens joined with a single space into text representation
    """
    def __init__(self):
        self.tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        self.stemmer = SnowballStemmer('english')

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        results = []
        for item in X:
            if not isinstance(item, str):
                item = "" if item is None else str(item)
            tokens = self.tokenizer.tokenize(item)
            stemmed = [self.stemmer.stem(word) for word in tokens]
            results.append(" ".join(stemmed))
        return results


def make_phishing_pipeline():
    """
    Constructs a complete Scikit-learn Pipeline with:
      - Step 1: URLTextPreprocessor
      - Step 2: CountVectorizer (default settings matching the notebook)
      - Step 3: LogisticRegression (max_iter=100, solver='lbfgs')
    """
    return Pipeline([
        ('preprocessor', URLTextPreprocessor()),
        ('vectorizer', CountVectorizer()),
        ('classifier', LogisticRegression(max_iter=100, solver='lbfgs'))
    ])

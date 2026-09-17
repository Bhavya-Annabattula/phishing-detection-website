"""
model_v2.py
Model V2 architecture: Combines Scikit-learn sparse lexical Bag-of-Words
representation with pruned, scaled URL structural, domain, and brand-impersonation features.
"""

from typing import List, Dict, Any
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

import pipeline_utils
import url_features

# Documented Redundant Features Pruned to Prevent Multicollinearity (|r| > 0.85):
PRUNED_REDUNDANT_FEATURES = {
    "hostname_has_ip",            # Identical to ip_address_host (r = 1.0000)
    "contains_at_symbol",         # Identical to has_at_symbol (r = 1.0000)
    "suspicious_encoding",        # Identical to has_percent_encoding (r = 1.0000)
    "letter_count",               # Highly collinear with url_length (r = 0.9733)
    "hostname_dot_count",         # Highly collinear with subdomain_count (r = 0.9710)
    "non_standard_port",          # Highly collinear with has_port (r = 0.9635)
    "path_hyphen_count",          # Highly collinear with hyphen_count (r = 0.9463)
    "equals_count",               # Highly collinear with query_parameter_count (r = 0.9457)
    "at_count",                   # Highly collinear with has_at_symbol (r = 0.9256)
    "ampersand_count",            # Highly collinear with query_parameter_count (r = 0.9241)
    "subdomain_length",           # Highly collinear with hostname_length (r = 0.9215)
    "path_special_character_count",# Highly collinear with path_length (r = 0.9031)
    "slash_count"                 # Highly collinear with path_segment_count (r = 0.8914)
}


class PrunedURLFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts URL structural, domain, and brand-impersonation features,
    automatically pruning the 13 redundant collinear feature pairs.
    """
    def __init__(self):
        self.feature_names_: List[str] = []

    def fit(self, X, y=None):
        raw_dict = url_features.extract_url_features("http://example.com")
        self.feature_names_ = [k for k in raw_dict.keys() if k not in PRUNED_REDUNDANT_FEATURES]
        return self

    def transform(self, X) -> np.ndarray:
        if not self.feature_names_:
            raw_dict = url_features.extract_url_features("http://example.com")
            self.feature_names_ = [k for k in raw_dict.keys() if k not in PRUNED_REDUNDANT_FEATURES]

        rows = []
        for url in X:
            d = url_features.extract_url_features(url)
            rows.append([d[k] for k in self.feature_names_])
        return np.array(rows, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.feature_names_, dtype=object)


def make_v2_pipeline() -> Pipeline:
    """
    Constructs the V2 Multi-Modal Feature Pipeline:
      Branch A: Lexical Pipeline (URLTextPreprocessor -> CountVectorizer)
      Branch B: Structural Pipeline (PrunedURLFeatureExtractor -> StandardScaler)
      FeatureUnion -> Combined Sparse CSR Matrix
      Classifier: LogisticRegression(max_iter=100, solver='lbfgs')
    """
    lexical_branch = Pipeline([
        ('preprocessor', pipeline_utils.URLTextPreprocessor()),
        ('vectorizer', CountVectorizer())
    ])

    structural_branch = Pipeline([
        ('extractor', PrunedURLFeatureExtractor()),
        ('scaler', StandardScaler())
    ])

    union = FeatureUnion([
        ('lexical', lexical_branch),
        ('structural', structural_branch)
    ])

    return Pipeline([
        ('features', union),
        ('classifier', LogisticRegression(max_iter=100, solver='lbfgs'))
    ])

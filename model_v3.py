"""
model_v3.py
Model V3 architecture definition.
Uses identical multi-modal architecture as Model V2:
  - Lexical branch: URLTextPreprocessor -> CountVectorizer
  - Structural branch: PrunedURLFeatureExtractor (56 features) -> StandardScaler
  - Combined via FeatureUnion -> LogisticRegression
Trained on clean dataset augmented with 65 verified legitimate anchor URLs.
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
from model_v2 import PRUNED_REDUNDANT_FEATURES, PrunedURLFeatureExtractor, make_v2_pipeline

def make_v3_pipeline() -> Pipeline:
    """
    Constructs the V3 Multi-Modal Feature Pipeline:
    Identical pipeline structure to V2, ready for fitting on augmented training data.
    """
    return make_v2_pipeline()

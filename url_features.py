"""
url_features.py
Robust, offline URL structural feature extraction pipeline for phishing detection.
Extracts basic, lexical, structural, domain-level, and brand-impersonation features.
Fully compatible with Scikit-learn via URLFeatureExtractor transformer.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

# Configurable list of monitored brands for brand-impersonation analysis
MONITORED_BRANDS = [
    "paypal",
    "google",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "linkedin",
    "github",
    "netflix",
    "chase",
    "bankofamerica"
]

# Common two-part public suffixes for offline registered domain parsing
TWO_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "org.br", "net.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.tr", "org.tr", "edu.tr", "gov.tr",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "web.za", "net.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk",
    "co.kr", "ne.kr", "or.kr", "re.kr",
    "co.il", "org.il", "net.il", "ac.il",
    "gc.ca", "on.ca", "qc.ca", "bc.ca"
}

IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def decompose_hostname(hostname: str) -> Tuple[str, str, str, int]:
    """
    Decomposes a hostname into (subdomain, registered_domain, tld, subdomain_count)
    completely offline without DNS or network requests.
    """
    if not hostname or hostname == "":
        return "", "", "", 0

    # If it is an IP address, the entire host is registered domain with no tld/subdomain
    if IPV4_PATTERN.match(hostname):
        return "", hostname, "", 0

    parts = hostname.lower().split('.')
    if len(parts) <= 1:
        return "", hostname, "", 0

    # Check two-part TLD (e.g. example.co.uk)
    if len(parts) >= 3:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in TWO_PART_TLDS:
            tld = two_part
            registered_domain = f"{parts[-3]}.{two_part}"
            subdomain = ".".join(parts[:-3])
            subdomain_count = len(parts) - 3
            return subdomain, registered_domain, tld, subdomain_count

    # Standard one-part TLD (e.g. example.com, a.b.example.com)
    tld = parts[-1]
    registered_domain = f"{parts[-2]}.{tld}"
    subdomain = ".".join(parts[:-2])
    subdomain_count = len(parts) - 2
    return subdomain, registered_domain, tld, subdomain_count


def extract_url_features(url: Any) -> Dict[str, Any]:
    """
    Safely extracts comprehensive structural, domain, and brand-impersonation
    features from any URL string. Never raises exceptions on malformed or empty inputs.
    """
    if url is None or not isinstance(url, str):
        raw_url = ""
    else:
        raw_url = str(url).strip()

    # 1. URL parsing with protocol fallback
    has_explicit_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw_url))
    parse_target = raw_url if has_explicit_scheme else f"http://{raw_url}"

    try:
        parsed = urllib.parse.urlparse(parse_target)
        scheme = parsed.scheme.lower() if has_explicit_scheme else ""
        netloc = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
    except Exception:
        scheme = ""
        netloc = ""
        path = ""
        query = ""
        fragment = ""

    # Port extraction
    port = None
    hostname = netloc
    if ':' in netloc:
        host_parts = netloc.split(':')
        hostname = host_parts[0]
        try:
            port = int(host_parts[1])
        except (ValueError, IndexError):
            port = None

    hostname = hostname.lower()

    # Domain decomposition
    subdomain, registered_domain, tld, subdomain_count = decompose_hostname(hostname)

    # Basic Lengths
    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    fragment_length = len(fragment)
    domain_length = len(registered_domain)
    subdomain_length = len(subdomain)

    # Character Counts (on full URL)
    digit_count = sum(c.isdigit() for c in raw_url)
    letter_count = sum(c.isalpha() for c in raw_url)
    special_character_count = url_length - (digit_count + letter_count)
    dot_count = raw_url.count('.')
    hyphen_count = raw_url.count('-')
    underscore_count = raw_url.count('_')
    slash_count = raw_url.count('/')
    question_mark_count = raw_url.count('?')
    equals_count = raw_url.count('=')
    ampersand_count = raw_url.count('&')
    percent_count = raw_url.count('%')
    at_count = raw_url.count('@')

    # Ratios
    safe_len = url_length if url_length > 0 else 1
    digit_ratio = digit_count / safe_len
    special_character_ratio = special_character_count / safe_len
    digit_to_letter_ratio = digit_count / (letter_count + 1e-6)

    # Hostname Features
    hostname_dot_count = hostname.count('.')
    hostname_hyphen_count = hostname.count('-')
    hostname_digit_count = sum(c.isdigit() for c in hostname)
    hostname_has_ip = 1 if IPV4_PATTERN.match(hostname) else 0

    # Path Features
    path_segments = [s for s in path.split('/') if s]
    path_segment_count = len(path_segments)
    path_digit_count = sum(c.isdigit() for c in path)
    path_hyphen_count = path.count('-')
    path_special_character_count = sum(not c.isalnum() for c in path)

    # Query Features
    has_query = 1 if query else 0
    query_params = [q for q in query.split('&') if q] if query else []
    query_parameter_count = len(query_params)
    query_digit_count = sum(c.isdigit() for c in query)

    # Flags & Indicators
    has_fragment = 1 if fragment else 0
    has_port = 1 if port is not None else 0
    uses_https = 1 if scheme == 'https' else 0
    has_at_symbol = 1 if at_count > 0 else 0
    has_percent_encoding = 1 if percent_count > 0 else 0

    # Brand Impersonation Features
    raw_lower = raw_url.lower()
    path_query_lower = f"{path}?{query}".lower()
    subdomain_lower = subdomain.lower()
    reg_dom_lower = registered_domain.lower()

    brand_token_present = 0
    brand_in_registered_domain = 0
    brand_in_subdomain = 0
    brand_in_path = 0
    brand_domain_mismatch = 0

    for brand in MONITORED_BRANDS:
        if brand in raw_lower:
            brand_token_present = 1
            in_reg = 1 if brand in reg_dom_lower else 0
            in_sub = 1 if brand in subdomain_lower else 0
            in_path = 1 if brand in path_query_lower else 0

            if in_reg:
                brand_in_registered_domain = 1
            if in_sub:
                brand_in_subdomain = 1
            if in_path:
                brand_in_path = 1

            # Mismatch: Brand is in URL but NOT part of registered root domain
            if not in_reg:
                brand_domain_mismatch = 1

    # Documented Suspicious Heuristics (Numeric / Binary flags)
    ip_address_host = hostname_has_ip
    excessive_subdomains = 1 if subdomain_count > 2 else 0
    unusually_long_url = 1 if url_length > 100 else 0
    unusually_long_hostname = 1 if hostname_length > 30 else 0
    excessive_digits = 1 if digit_count > 10 else 0
    excessive_special_characters = 1 if special_character_count > 10 else 0
    contains_at_symbol = has_at_symbol
    suspicious_encoding = has_percent_encoding
    non_standard_port = 1 if (has_port and port not in (80, 443)) else 0
    deep_path = 1 if path_segment_count > 3 else 0
    many_query_params = 1 if query_parameter_count > 3 else 0
    hostname_multiple_hyphens = 1 if hostname_hyphen_count > 1 else 0

    return {
        # Basic Lengths
        "url_length": float(url_length),
        "hostname_length": float(hostname_length),
        "path_length": float(path_length),
        "query_length": float(query_length),
        "fragment_length": float(fragment_length),
        "domain_length": float(domain_length),
        "subdomain_length": float(subdomain_length),
        "subdomain_count": float(subdomain_count),
        
        # Character Counts
        "digit_count": float(digit_count),
        "letter_count": float(letter_count),
        "special_character_count": float(special_character_count),
        "dot_count": float(dot_count),
        "hyphen_count": float(hyphen_count),
        "underscore_count": float(underscore_count),
        "slash_count": float(slash_count),
        "question_mark_count": float(question_mark_count),
        "equals_count": float(equals_count),
        "ampersand_count": float(ampersand_count),
        "percent_count": float(percent_count),
        "at_count": float(at_count),
        
        # Ratios
        "digit_ratio": float(digit_ratio),
        "special_character_ratio": float(special_character_ratio),
        "digit_to_letter_ratio": float(digit_to_letter_ratio),
        
        # Hostname Features
        "hostname_dot_count": float(hostname_dot_count),
        "hostname_hyphen_count": float(hostname_hyphen_count),
        "hostname_digit_count": float(hostname_digit_count),
        "hostname_has_ip": float(hostname_has_ip),
        
        # Path Features
        "path_segment_count": float(path_segment_count),
        "path_digit_count": float(path_digit_count),
        "path_hyphen_count": float(path_hyphen_count),
        "path_special_character_count": float(path_special_character_count),
        
        # Query Features
        "has_query": float(has_query),
        "query_parameter_count": float(query_parameter_count),
        "query_digit_count": float(query_digit_count),
        
        # Flags & Indicators
        "has_fragment": float(has_fragment),
        "has_port": float(has_port),
        "uses_https": float(uses_https),
        "has_at_symbol": float(has_at_symbol),
        "has_percent_encoding": float(has_percent_encoding),
        
        # Brand-Impersonation Features
        "brand_token_present": float(brand_token_present),
        "brand_in_registered_domain": float(brand_in_registered_domain),
        "brand_in_subdomain": float(brand_in_subdomain),
        "brand_in_path": float(brand_in_path),
        "brand_domain_mismatch": float(brand_domain_mismatch),
        
        # Suspicious Indicators
        "ip_address_host": float(ip_address_host),
        "excessive_subdomains": float(excessive_subdomains),
        "unusually_long_url": float(unusually_long_url),
        "unusually_long_hostname": float(unusually_long_hostname),
        "excessive_digits": float(excessive_digits),
        "excessive_special_characters": float(excessive_special_characters),
        "contains_at_symbol": float(contains_at_symbol),
        "suspicious_encoding": float(suspicious_encoding),
        "non_standard_port": float(non_standard_port),
        "deep_path": float(deep_path),
        "many_query_params": float(many_query_params),
        "hostname_multiple_hyphens": float(hostname_multiple_hyphens)
    }


class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer that transforms a list or Series
    of raw URL strings into a 2D numpy feature array.
    """
    def __init__(self):
        self.feature_names_: List[str] = []

    def fit(self, X, y=None):
        sample_dict = extract_url_features("http://example.com")
        self.feature_names_ = list(sample_dict.keys())
        return self

    def transform(self, X) -> np.ndarray:
        if not self.feature_names_:
            sample_dict = extract_url_features("http://example.com")
            self.feature_names_ = list(sample_dict.keys())

        data = []
        for url in X:
            fdict = extract_url_features(url)
            data.append([fdict[k] for k in self.feature_names_])
        return np.array(data, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.feature_names_, dtype=object)

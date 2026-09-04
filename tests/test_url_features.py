"""Unit tests for static URL feature extraction."""

import pytest
import numpy as np
from training.features.url_features import (
    extract_url_features,
    url_to_feature_vector,
    calculate_entropy,
    URL_FEATURE_NAMES
)


def test_url_feature_names_count():
    assert len(URL_FEATURE_NAMES) == 16


def test_extract_url_features_legit():
    url = "https://www.google.com/search?q=cybersecurity"
    feats = extract_url_features(url)

    assert feats["has_https"] == 1.0
    assert feats["has_ip"] == 0.0
    assert feats["num_dots"] >= 2.0
    assert feats["num_question_marks"] == 1.0
    assert feats["has_shortener"] == 0.0
    assert feats["url_length"] == len(url)
    assert feats["entropy"] > 0.0


def test_extract_url_features_ip_phish():
    url = "http://192.168.1.1/login/verify-account.php?cmd=update"
    feats = extract_url_features(url)

    assert feats["has_https"] == 0.0
    assert feats["has_ip"] == 1.0
    assert feats["num_slashes"] >= 3.0
    assert feats["suspicious_keywords_count"] >= 2.0  # login, verify, update


def test_extract_url_features_shortener():
    url = "http://bit.ly/3xUrgentL0gin"
    feats = extract_url_features(url)

    assert feats["has_shortener"] == 1.0
    assert feats["num_hyphens"] == 0.0


def test_extract_url_features_port():
    url = "http://bad-site.com:8080/portal"
    feats = extract_url_features(url)

    assert feats["has_port"] == 1.0


def test_empty_url_handling():
    feats = extract_url_features("")
    assert len(feats) == 16
    for v in feats.values():
        assert v == 0.0


def test_url_to_feature_vector():
    url = "https://github.com/torvalds/linux"
    vec = url_to_feature_vector(url)

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (16,)
    assert vec.dtype == np.float32


def test_entropy_calculation():
    # Constant string has 0 entropy
    assert calculate_entropy("aaaaaaa") == 0.0
    # Diverse string has higher entropy
    assert calculate_entropy("a1b2c3d4e5!@#$%^") > 3.0

"""Unit tests for message text cleaning and normalization."""

import pytest
from training.features.message_features import clean_text, build_vocabulary, text_to_sequence


def test_clean_text_basic():
    raw = "Hello World! Please Click HERE: http://test.com."
    cleaned = clean_text(raw)

    assert "hello" in cleaned
    assert "world" in cleaned
    assert "!" not in cleaned
    assert ":" not in cleaned
    assert "." not in cleaned


def test_clean_text_currency_and_numbers():
    raw = "You won $1,000 cash! Call 12345 now."
    cleaned = clean_text(raw)

    assert "money" in cleaned
    assert "num" in cleaned
    assert "$" not in cleaned


def test_clean_text_empty_and_whitespace():
    assert clean_text("") == ""
    assert clean_text("   \n\t  ") == ""
    assert clean_text(None) == ""


def test_build_vocabulary_and_sequence():
    texts = ["hello world", "world of ai", "hello phishguard"]
    vocab = build_vocabulary(texts, max_vocab_size=10)

    assert "<PAD>" in vocab
    assert vocab["<PAD>"] == 0
    assert "<OOV>" in vocab
    assert vocab["<OOV>"] == 1
    assert "hello" in vocab
    assert "world" in vocab

    seq = text_to_sequence("hello unknown world", vocab, max_len=5)
    assert len(seq) == 5
    assert seq[0] == vocab["hello"]
    assert seq[1] == vocab["<OOV>"]
    assert seq[2] == vocab["world"]
    assert seq[3] == 0
    assert seq[4] == 0

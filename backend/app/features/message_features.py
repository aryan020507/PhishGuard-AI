"""
Message Preprocessing and Tokenization Module for PhishGuard-AI.
Cleans raw SMS/messages, normalizes text, and provides sequence encoding helpers.
"""

import re
import string
from typing import List, Tuple
import numpy as np


MAX_VOCAB_SIZE = 5000
MAX_SEQUENCE_LENGTH = 100
OOV_TOKEN = "<OOV>"


def clean_text(text: str) -> str:
    """
    Clean and normalize message text:
    - Lowercase text
    - Remove punctuation
    - Normalize whitespace
    - Strip trailing/leading spaces
    """
    if not isinstance(text, str):
        return ""

    # Convert to lowercase
    text = text.lower()

    # Replace currency symbols with text indicators
    text = re.sub(r"[\$£€₹]", " money ", text)

    # Remove punctuation
    translator = str.maketrans("", "", string.punctuation)
    text = text.translate(translator)

    # Replace digits with token
    text = re.sub(r"\b\d+\b", " num ", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def build_vocabulary(cleaned_texts: List[str], max_vocab_size: int = MAX_VOCAB_SIZE) -> dict:
    """
    Build a word-to-index mapping dictionary from cleaned texts.
    Reserves index 0 for padding, and index 1 for OOV (Out-Of-Vocabulary).
    """
    from collections import Counter
    word_counts = Counter()
    for text in cleaned_texts:
        words = text.split()
        word_counts.update(words)

    # Most common words up to max_vocab_size - 2
    most_common = word_counts.most_common(max_vocab_size - 2)
    vocab = {"<PAD>": 0, OOV_TOKEN: 1}
    for idx, (word, _) in enumerate(most_common, start=2):
        vocab[word] = idx

    return vocab


def text_to_sequence(text: str, vocab: dict, max_len: int = MAX_SEQUENCE_LENGTH) -> np.ndarray:
    """
    Convert cleaned text into padded integer sequence of length `max_len`.
    Padding='post', Truncating='post'.
    """
    words = clean_text(text).split()
    oov_idx = vocab.get(OOV_TOKEN, 1)

    seq = [vocab.get(word, oov_idx) for word in words]

    # Truncate or pad to max_len
    if len(seq) > max_len:
        seq = seq[:max_len]
    else:
        seq = seq + [0] * (max_len - len(seq))

    return np.array(seq, dtype=np.int32)

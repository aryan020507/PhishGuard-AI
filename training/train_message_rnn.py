"""
Message Threat Detection Training Pipeline (RNN) for PhishGuard-AI.
1. Cleans raw message text (lowercasing, punctuation stripping, normalization).
2. Performs 70% Train / 15% Val / 15% Test split.
3. Fits Tokenizer strictly on the training set (max_words=5000, oov_token="<OOV>").
4. Pads sequences to max length of 100 tokens.
5. Compiles RNN: Embedding -> SimpleRNN -> Dropout -> Dense(ReLU) -> Dense(Sigmoid).
6. Trains with Adam and binary crossentropy.
7. Evaluates test set and saves message_rnn_model.keras, message_tokenizer.pkl, and message_metrics.json.
"""

import os
import sys
import json
import pickle
import argparse
import numpy as np
import pandas as pd

# Suppress verbose TF C++ logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from training.features.message_features import clean_text, MAX_VOCAB_SIZE, MAX_SEQUENCE_LENGTH, OOV_TOKEN
from training.datasets.download_datasets import MESSAGES_DATASET_CSV, prepare_datasets

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_SAVE_PATH = os.path.join(MODELS_DIR, "message_rnn_model.keras")
TOKENIZER_SAVE_PATH = os.path.join(MODELS_DIR, "message_tokenizer.pkl")
METRICS_SAVE_PATH = os.path.join(MODELS_DIR, "message_metrics.json")


def load_message_data(data_path: str) -> pd.DataFrame:
    """Load message dataset with columns ['message', 'label']."""
    if not os.path.exists(data_path):
        print(f"[*] Dataset not found at {data_path}. Preparing default datasets...")
        prepare_datasets(use_synthetic=False)
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["message", "label"])
    df["label"] = df["label"].astype(int)
    return df


def build_rnn_model(vocab_size: int = MAX_VOCAB_SIZE, maxlen: int = MAX_SEQUENCE_LENGTH) -> keras.Model:
    """Construct RNN: Embedding -> SimpleRNN -> Dropout -> Dense -> Dense (Sigmoid)."""
    model = keras.Sequential([
        layers.Input(shape=(maxlen,)),
        layers.Embedding(input_dim=vocab_size, output_dim=32, mask_zero=True, name="embedding"),
        layers.SimpleRNN(units=32, return_sequences=False, name="simple_rnn"),
        layers.Dropout(0.3, name="dropout_1"),
        layers.Dense(16, activation="relu", name="dense_1"),
        layers.Dense(1, activation="sigmoid", name="output_sigmoid")
    ], name="PhishGuard_Message_RNN")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.002),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall")]
    )
    return model


def train_message_pipeline(dataset_path: str = MESSAGES_DATASET_CSV, epochs: int = 25, batch_size: int = 16):
    """Full execution loop for Message RNN training."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_message_data(dataset_path)
    print(f"[+] Loaded {len(df)} message samples. Class balance: {df['label'].value_counts().to_dict()}")

    # 1. Clean Texts
    cleaned_texts = df["message"].astype(str).apply(clean_text).values
    labels = df["label"].values.astype(np.float32)

    # 2. Train / Val / Test Split (70% / 15% / 15%)
    texts_train_val, texts_test, y_train_val, y_test = train_test_split(
        cleaned_texts, labels, test_size=0.15, random_state=42, stratify=labels
    )
    val_ratio_adjusted = 0.15 / 0.85
    texts_train, texts_val, y_train, y_val = train_test_split(
        texts_train_val, y_train_val, test_size=val_ratio_adjusted, random_state=42, stratify=y_train_val
    )

    print(f"[*] Dataset split: Train={len(texts_train)}, Val={len(texts_val)}, Test={len(texts_test)}")

    # 3. Fit Tokenizer STRICTLY on Train split
    print("[*] Fitting Tokenizer on training text only...")
    tokenizer = Tokenizer(num_words=MAX_VOCAB_SIZE, oov_token=OOV_TOKEN)
    tokenizer.fit_on_texts(texts_train)

    # Save tokenizer artifact
    with open(TOKENIZER_SAVE_PATH, "wb") as f:
        pickle.dump(tokenizer, f)
    print(f"[OK] Saved tokenizer to {TOKENIZER_SAVE_PATH}")

    # Sequence transformation and padding
    X_train = pad_sequences(tokenizer.texts_to_sequences(texts_train), maxlen=MAX_SEQUENCE_LENGTH, padding="post", truncating="post")
    X_val = pad_sequences(tokenizer.texts_to_sequences(texts_val), maxlen=MAX_SEQUENCE_LENGTH, padding="post", truncating="post")
    X_test = pad_sequences(tokenizer.texts_to_sequences(texts_test), maxlen=MAX_SEQUENCE_LENGTH, padding="post", truncating="post")

    # Calculate balanced class weights for imbalanced SMS Spam dataset (~87% ham, ~13% spam)
    from sklearn.utils.class_weight import compute_class_weight
    classes = np.unique(y_train)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
    class_weight_dict = {int(c): float(w) for c, w in zip(classes, weights)}
    print(f"[*] Computed class weights: {class_weight_dict}")

    # 4. Build and Train Model
    model = build_rnn_model(vocab_size=MAX_VOCAB_SIZE, maxlen=MAX_SEQUENCE_LENGTH)
    model.summary()

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=8,
            restore_best_weights=True
        )
    ]

    print("[*] Training Message RNN...")
    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight_dict,
        callbacks=callbacks,
        verbose=1
    )

    # 5. Evaluate on Test Set
    print("[*] Evaluating on Holdout Test Set...")
    y_pred_probs = model.predict(X_test).flatten()
    y_pred_binary = (y_pred_probs >= 0.5).astype(int)

    test_loss = float(model.evaluate(X_test, y_test, verbose=0)[0])
    acc = float(accuracy_score(y_test, y_pred_binary))
    prec = float(precision_score(y_test, y_pred_binary, zero_division=0))
    rec = float(recall_score(y_test, y_pred_binary, zero_division=0))
    f1 = float(f1_score(y_test, y_pred_binary, zero_division=0))
    try:
        roc_auc = float(roc_auc_score(y_test, y_pred_probs))
    except Exception:
        roc_auc = 0.5

    cm = confusion_matrix(y_test, y_pred_binary).tolist()
    report = classification_report(y_test, y_pred_binary, output_dict=True, zero_division=0)

    metrics_payload = {
        "model_name": "PhishGuard_Message_RNN",
        "model_type": "Recurrent Neural Network (Embedding-SimpleRNN-Dropout-Dense-Sigmoid)",
        "vocab_size": MAX_VOCAB_SIZE,
        "max_sequence_length": MAX_SEQUENCE_LENGTH,
        "split_counts": {
            "train": int(len(texts_train)),
            "validation": int(len(texts_val)),
            "test": int(len(texts_test)),
            "total": int(len(df))
        },
        "test_metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "loss": round(test_loss, 4)
        },
        "confusion_matrix": {
            "true_negatives": cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0,
            "false_positives": cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0,
            "false_negatives": cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0,
            "true_positives": cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0,
            "raw_matrix": cm
        },
        "classification_report": report
    }

    # Save model and metrics
    model.save(MODEL_SAVE_PATH)
    print(f"[OK] Saved Message RNN model to {MODEL_SAVE_PATH}")

    with open(METRICS_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"[OK] Saved Message metrics to {METRICS_SAVE_PATH}")

    print("\n--- TEST EVALUATION SUMMARY ---")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print("--------------------------------\n")
    return metrics_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Message RNN Threat Detection Model")
    parser.add_argument("--synthetic", action="store_true", help="Use 100-row synthetic dataset")
    parser.add_argument("--epochs", type=int, default=20, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    args = parser.parse_args()

    target_data = os.path.join(PROJECT_ROOT, "training", "datasets", "synthetic_messages.csv") if args.synthetic else MESSAGES_DATASET_CSV
    if args.synthetic and not os.path.exists(target_data):
        from training.datasets.generate_synthetic import generate_synthetic_data
        generate_synthetic_data()

    train_message_pipeline(dataset_path=target_data, epochs=args.epochs, batch_size=args.batch_size)

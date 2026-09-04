"""
URL Threat Detection Training Pipeline (ANN) for PhishGuard-AI.
1. Extracts 16 static features from URL strings locally (zero network calls).
2. Performs 70% Train / 15% Val / 15% Test split.
3. Fits StandardScaler strictly on the training set.
4. Compiles ANN: Dense -> Dropout -> Dense -> Dropout -> Dense(Sigmoid).
5. Trains with Adam optimizer and binary crossentropy.
6. Evaluates test set and saves url_ann_model.keras, url_scaler.joblib, and url_metrics.json.
"""

import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
import joblib

# Suppress verbose TF C++ logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Ensure training directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from training.features.url_features import extract_url_features, URL_FEATURE_NAMES
from training.datasets.download_datasets import URLS_DATASET_CSV, prepare_datasets

MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
MODEL_SAVE_PATH = os.path.join(MODELS_DIR, "url_ann_model.keras")
SCALER_SAVE_PATH = os.path.join(MODELS_DIR, "url_scaler.joblib")
METRICS_SAVE_PATH = os.path.join(MODELS_DIR, "url_metrics.json")


def load_url_data(data_path: str) -> pd.DataFrame:
    """Load URL dataset with columns ['url', 'label']."""
    if not os.path.exists(data_path):
        print(f"[*] Dataset not found at {data_path}. Preparing default datasets...")
        prepare_datasets(use_synthetic=False)
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    return df


def extract_features_matrix(urls: pd.Series) -> np.ndarray:
    """Extract 16 numerical features for all URLs in Series."""
    print(f"[*] Extracting static features for {len(urls)} URLs...")
    rows = []
    for url in urls:
        feat_dict = extract_url_features(str(url))
        rows.append([feat_dict[col] for col in URL_FEATURE_NAMES])
    return np.array(rows, dtype=np.float32)


def build_ann_model(input_dim: int) -> keras.Model:
    """Construct ANN: Dense -> Dropout -> Dense -> Dropout -> Dense (Sigmoid)."""
    model = keras.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(32, activation="relu", name="dense_1"),
        layers.Dropout(0.3, name="dropout_1"),
        layers.Dense(16, activation="relu", name="dense_2"),
        layers.Dropout(0.2, name="dropout_2"),
        layers.Dense(1, activation="sigmoid", name="output_sigmoid"),
    ], name="PhishGuard_URL_ANN")

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall")]
    )
    return model


def train_url_pipeline(dataset_path: str = URLS_DATASET_CSV, epochs: int = 35, batch_size: int = 16):
    """Full execution loop for URL ANN training."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_url_data(dataset_path)
    print(f"[+] Loaded {len(df)} samples. Class balance: {df['label'].value_counts().to_dict()}")

    # 1. Feature Extraction
    X = extract_features_matrix(df["url"])
    y = df["label"].values.astype(np.float32)

    # 2. Train / Val / Test Split (70% / 15% / 15%)
    # Stratified split to ensure balanced classes across sets
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )
    val_ratio_adjusted = 0.15 / 0.85  # Yields ~15% of overall dataset
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_ratio_adjusted, random_state=42, stratify=y_train_val
    )

    print(f"[*] Dataset split completed: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # 3. Strict Featurization Ordering: Fit scaler ONLY on X_train
    print("[*] Fitting StandardScaler on training set only...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler artifact
    joblib.dump(scaler, SCALER_SAVE_PATH)
    print(f"[OK] Saved scaler to {SCALER_SAVE_PATH}")

    # 4. Build and Train Model
    model = build_ann_model(input_dim=len(URL_FEATURE_NAMES))
    model.summary()

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=8,
            restore_best_weights=True
        )
    ]

    print("[*] Training URL ANN...")
    history = model.fit(
        X_train_scaled,
        y_train,
        validation_data=(X_val_scaled, y_val),
        epochs=epochs,
        batch_size=batch_size,
        callbacks=callbacks,
        verbose=1
    )

    # 5. Evaluate on Holdout Test Set
    print("[*] Evaluating on Holdout Test Set...")
    y_pred_probs = model.predict(X_test_scaled).flatten()
    y_pred_binary = (y_pred_probs >= 0.5).astype(int)

    test_loss = float(model.evaluate(X_test_scaled, y_test, verbose=0)[0])
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
        "model_name": "PhishGuard_URL_ANN",
        "model_type": "Artificial Neural Network (Dense-Dropout-Dense-Sigmoid)",
        "input_features": URL_FEATURE_NAMES,
        "split_counts": {
            "train": int(len(X_train)),
            "validation": int(len(X_val)),
            "test": int(len(X_test)),
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
    print(f"[OK] Saved URL ANN model to {MODEL_SAVE_PATH}")

    with open(METRICS_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"[OK] Saved URL metrics to {METRICS_SAVE_PATH}")

    print("\n--- TEST EVALUATION SUMMARY ---")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print("--------------------------------\n")
    return metrics_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train URL ANN Threat Detection Model")
    parser.add_argument("--synthetic", action="store_true", help="Use 100-row synthetic dataset")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    args = parser.parse_args()

    target_data = os.path.join(PROJECT_ROOT, "training", "datasets", "synthetic_urls.csv") if args.synthetic else URLS_DATASET_CSV
    if args.synthetic and not os.path.exists(target_data):
        from training.datasets.generate_synthetic import generate_synthetic_data
        generate_synthetic_data()

    train_url_pipeline(dataset_path=target_data, epochs=args.epochs, batch_size=args.batch_size)

"""
SpamSentry - Model Training Pipeline
Loads and validates spam dataset, trains TF-IDF + Multinomial Naive Bayes classifier,
evaluates performance metrics, and exports versioned model artifacts and metadata.
"""

import json
import pickle
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "spam.csv"
MODELS_DIR = BASE_DIR / "models"


def train():
    print("=" * 60)
    print(" SPAMSENTRY - AI MODEL TRAINING PIPELINE")
    print("=" * 60)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at: {DATASET_PATH}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading dataset from: {DATASET_PATH}")
    try:
        raw_df = pd.read_csv(DATASET_PATH, encoding="latin-1")
    except UnicodeDecodeError:
        raw_df = pd.read_csv(DATASET_PATH, encoding="utf-8", errors="ignore")

    print(f"[*] Total raw records: {len(raw_df)}")

    if 'v1' in raw_df.columns and 'v2' in raw_df.columns:
        df = raw_df[['v1', 'v2']].copy()
        df.columns = ['label', 'text']
    elif 'label' in raw_df.columns and 'text' in raw_df.columns:
        df = raw_df[['label', 'text']].copy()
    else:
        raise ValueError(f"Unexpected dataset format. Columns found: {list(raw_df.columns)}")

    null_count = df.isnull().sum().to_dict()
    df = df.dropna(subset=['label', 'text'])

    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df = df[df['label'].isin(['ham', 'spam', '0', '1', 'legitimate'])]
    df['label'] = df['label'].map({'ham': 0, 'legitimate': 0, '0': 0, 0: 0, 'spam': 1, '1': 1, 1: 1})

    initial_len = len(df)
    df = df.drop_duplicates(subset=['text']).reset_index(drop=True)
    duplicates_removed = initial_len - len(df)

    total_records = len(df)
    ham_count = int((df['label'] == 0).sum())
    spam_count = int((df['label'] == 1).sum())

    print("\n--- DATASET DIAGNOSTICS ---")
    print(f"Cleaned unique samples: {total_records}")
    print(f"Ham (Legitimate) samples: {ham_count} ({round(ham_count/total_records*100, 2)}%)")
    print(f"Spam samples:            {spam_count} ({round(spam_count/total_records*100, 2)}%)")
    print(f"Duplicates removed:      {duplicates_removed}")
    print(f"Missing values handled:  {null_count}")

    X = df['text'].astype(str).str.lower()
    y = df['label'].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"\n[*] Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    vectorizer = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_features=6000,
        sublinear_tf=True
    )

    print("[*] Vectorizing text with TF-IDF (unigrams + bigrams)...")
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("[*] Training Multinomial Naive Bayes model...")
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_vec, y_train)

    y_pred = model.predict(X_test_vec)
    accuracy = float(accuracy_score(y_test, y_pred))
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary', pos_label=1)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n--- EVALUATION METRICS ---")
    print(f"Accuracy:  {accuracy * 100:.2f}%")
    print(f"Precision: {precision * 100:.2f}%")
    print(f"Recall:    {recall * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")

    model_path_dir = MODELS_DIR / "model.pkl"
    vec_path_dir = MODELS_DIR / "vectorizer.pkl"
    meta_path_dir = MODELS_DIR / "model_metadata.json"

    model_path_root = BASE_DIR / "model.pkl"
    vec_path_root = BASE_DIR / "vectorizer.pkl"

    with open(model_path_dir, "wb") as f:
        pickle.dump(model, f)
    with open(vec_path_dir, "wb") as f:
        pickle.dump(vectorizer, f)

    with open(model_path_root, "wb") as f:
        pickle.dump(model, f)
    with open(vec_path_root, "wb") as f:
        pickle.dump(vectorizer, f)

    metadata = {
        "model_name": "Multinomial Naive Bayes (TF-IDF)",
        "training_timestamp": datetime.now().isoformat(),
        "dataset_name": "SMS/Email Spam Dataset",
        "dataset_samples": total_records,
        "class_distribution": {
            "legitimate_ham": ham_count,
            "spam": spam_count
        },
        "vocabulary_size": len(vectorizer.vocabulary_),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm
        },
        "classes": ["Legitimate", "Spam"]
    }

    with open(meta_path_dir, "wb") as f:
        f.write(json.dumps(metadata, indent=4).encode("utf-8"))

    print(f"\n[OK] Model saved to: {model_path_dir} and {model_path_root}")
    print(f"[OK] Vectorizer saved to: {vec_path_dir} and {vec_path_root}")
    print(f"[OK] Metadata saved to: {meta_path_dir}")
    print("[SUCCESS] Training pipeline completed successfully.")


if __name__ == "__main__":
    train()
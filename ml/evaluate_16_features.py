import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

DATASET = r"D:\MINI PROJECT\KUBERNATES SECURITY\data\dataset\ml_dataset_v3.csv"

df = pd.read_csv(DATASET)

FEATURES = [c for c in df.columns if c != "label"]

X = df[FEATURES]
y = df["label"]

groups = X.astype(str).agg("|".join, axis=1)

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

results = []

for fold, (train_idx, test_idx) in enumerate(
    cv.split(X, y, groups), start=1
):
    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    model = make_pipeline(
        StandardScaler(),
        LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=42
        )
    )

    model.fit(X_train, y_train)

    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.60).astype(int)

    results.append({
        "fold": fold,
        "accuracy": accuracy_score(y_test, predictions),
        "precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "f1": f1_score(
            y_test, predictions, zero_division=0
        )
    })

results_df = pd.DataFrame(results)

print()
print("16-FEATURE DUPLICATE-AWARE EVALUATION")
print("=====================================")
print("Number of features:", len(FEATURES))
print()

print(results_df.to_string(index=False))

print()
print("AVERAGE METRICS")
print("===============")

print(f"Accuracy : {results_df['accuracy'].mean():.3f}")
print(f"Precision: {results_df['precision'].mean():.3f}")
print(f"Recall   : {results_df['recall'].mean():.3f}")
print(f"F1-score : {results_df['f1'].mean():.3f}")

print()
print("METRIC RANGES")
print("=============")

print(
    f"Accuracy : {results_df['accuracy'].min():.3f} - "
    f"{results_df['accuracy'].max():.3f}"
)

print(
    f"Precision: {results_df['precision'].min():.3f} - "
    f"{results_df['precision'].max():.3f}"
)

print(
    f"Recall   : {results_df['recall'].min():.3f} - "
    f"{results_df['recall'].max():.3f}"
)

print(
    f"F1-score : {results_df['f1'].min():.3f} - "
    f"{results_df['f1'].max():.3f}"
)
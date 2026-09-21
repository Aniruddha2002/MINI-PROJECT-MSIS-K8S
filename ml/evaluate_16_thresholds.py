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

THRESHOLDS = [0.30, 0.40, 0.50, 0.60, 0.70]

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

for threshold in THRESHOLDS:

    fold_scores = []

    for train_idx, test_idx in cv.split(X, y, groups):

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

        probability = model.predict_proba(X_test)[:, 1]

        prediction = (probability >= threshold).astype(int)

        fold_scores.append({
            "accuracy": accuracy_score(y_test, prediction),
            "precision": precision_score(
                y_test, prediction, zero_division=0
            ),
            "recall": recall_score(
                y_test, prediction, zero_division=0
            ),
            "f1": f1_score(
                y_test, prediction, zero_division=0
            )
        })

    fold_df = pd.DataFrame(fold_scores)

    results.append({
        "threshold": threshold,
        "accuracy": fold_df["accuracy"].mean(),
        "precision": fold_df["precision"].mean(),
        "recall": fold_df["recall"].mean(),
        "f1": fold_df["f1"].mean()
    })

results_df = pd.DataFrame(results)

print()
print("16-FEATURE THRESHOLD EVALUATION")
print("===============================")
print()
print(results_df.to_string(index=False))

print()
print("F1-SCORE RANGE")
print("==============")

for _, row in results_df.iterrows():
    print(
        f"Threshold {row['threshold']:.2f}: "
        f"Accuracy={row['accuracy']:.3f}, "
        f"Precision={row['precision']:.3f}, "
        f"Recall={row['recall']:.3f}, "
        f"F1={row['f1']:.3f}"
    )
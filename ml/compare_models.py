import pandas as pd

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score
)

DATASET = r"D:\MINI PROJECT\KUBERNATES SECURITY\data\dataset\ml_dataset_v3.csv"

THRESHOLD = 0.70

df = pd.read_csv(DATASET)

FEATURES = [c for c in df.columns if c != "label"]

X = df[FEATURES]
y = df["label"]

groups = X.astype(str).agg("|".join, axis=1)

models = {
    "Logistic Regression": make_pipeline(
        StandardScaler(),
        LogisticRegression(
            class_weight="balanced",
            max_iter=2000,
            random_state=42
        )
    ),
    "Decision Tree": DecisionTreeClassifier(
        class_weight="balanced",
        random_state=42
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=42
    )
}

cv = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)

results = []

for model_name, model in models.items():

    fold_scores = []

    for train_idx, test_idx in cv.split(X, y, groups):

        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]

        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        model.fit(X_train, y_train)

        if hasattr(model, "predict_proba"):
            probability = model.predict_proba(X_test)[:, 1]
        else:
            probability = model.predict(X_test)

        prediction = (probability >= THRESHOLD).astype(int)

        fold_scores.append({
            "accuracy": accuracy_score(
                y_test, prediction
            ),
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

    scores = pd.DataFrame(fold_scores)

    results.append({
        "model": model_name,
        "accuracy": scores["accuracy"].mean(),
        "precision": scores["precision"].mean(),
        "recall": scores["recall"].mean(),
        "f1": scores["f1"].mean()
    })

results_df = pd.DataFrame(results)

print()
print("16-FEATURE MODEL COMPARISON")
print("===========================")
print(f"Decision threshold: {THRESHOLD}")
print(f"Features: {len(FEATURES)}")
print()

print(results_df.to_string(index=False))

print()
print("MODEL COMPARISON COMPLETE")
print("==========================")
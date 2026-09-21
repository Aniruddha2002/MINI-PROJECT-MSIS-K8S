import pandas as pd
import joblib
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

DATASET = r"D:\MINI PROJECT\KUBERNATES SECURITY\data\dataset\ml_dataset_v3.csv"
MODEL_OUT = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\logistic_security_model.joblib"

FEATURES = [
    "run_as_nonroot_count",
    "readonly_rootfs_count",
    "capabilities_drop_all_count",
    "effective_root_count",
    "allow_priv_esc_count",
    "service_account_token",
    "container_count",
    "network_policy_present",
]

THRESHOLD = 0.60

df = pd.read_csv(DATASET)

X = df[FEATURES]
y = df["label"]

model = make_pipeline(
    StandardScaler(),
    LogisticRegression(
        class_weight="balanced",
        max_iter=2000,
        random_state=42
    )
)

model.fit(X, y)

artifact = {
    "model": model,
    "features": FEATURES,
    "threshold": THRESHOLD,
    "dataset": "ml_dataset_v3.csv",
}

joblib.dump(artifact, MODEL_OUT)

print("Model training complete.")
print("Samples:", len(df))
print("Features:", len(FEATURES))
print("Threshold:", THRESHOLD)
print("Model:", MODEL_OUT)
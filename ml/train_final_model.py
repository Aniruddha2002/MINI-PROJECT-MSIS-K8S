import pandas as pd
import joblib

from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

DATASET = r"D:\MINI PROJECT\KUBERNATES SECURITY\data\dataset\ml_dataset_v3.csv"

MODEL_OUT = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\final_security_model.joblib"

FEATURES = [
    "container_count",
    "privileged_count",
    "effective_root_count",
    "run_as_nonroot_count",
    "allow_priv_esc_count",
    "readonly_rootfs_count",
    "capabilities_drop_all_count",
    "host_pid",
    "host_ipc",
    "cpu_limit_missing",
    "memory_limit_missing",
    "service_account_token",
    "hostpath_count",
    "seccomp_runtime_default",
    "run_as_group_missing",
    "network_policy_present",
]

THRESHOLD = 0.70

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
    "model_type": "Logistic Regression",
    "feature_count": len(FEATURES),
}

joblib.dump(artifact, MODEL_OUT)

print("Final model training complete.")
print("Samples:", len(df))
print("Features:", len(FEATURES))
print("Threshold:", THRESHOLD)
print("Model:", MODEL_OUT)
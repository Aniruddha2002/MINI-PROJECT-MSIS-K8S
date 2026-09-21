import sys
import pandas as pd
import joblib

MODEL_PATH = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\logistic_security_model.joblib"

artifact = joblib.load(MODEL_PATH)

model = artifact["model"]
features = artifact["features"]
threshold = artifact["threshold"]

if len(sys.argv) != 2:
    print("Usage: python ml\\score_cluster.py <input_csv>")
    sys.exit(1)

input_csv = sys.argv[1]

df = pd.read_csv(input_csv)

missing = [f for f in features if f not in df.columns]

if missing:
    print("Missing required features:", missing)
    sys.exit(1)

X = df[features]

probabilities = model.predict_proba(X)[:, 1]

df["security_probability"] = probabilities

security_score = probabilities.mean() * 100

if security_score >= 80:
    category = "HIGH"
elif security_score >= 60:
    category = "MEDIUM"
else:
    category = "LOW"

overall_status = "SECURE" if security_score >= threshold * 100 else "INSECURE"

print("\nKUBERNETES SECURITY ASSESSMENT")
print("==============================")
print(f"Workloads assessed : {len(df)}")
print(f"Security Score     : {security_score:.2f}/100")
print(f"Security Category  : {category}")
print(f"Overall Status     : {overall_status}")
print(f"Model Threshold    : {threshold * 100:.0f}/100")
import sys
import pandas as pd
import joblib

MODEL_PATH = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\logistic_security_model.joblib"

artifact = joblib.load(MODEL_PATH)

model = artifact["model"]
features = artifact["features"]
threshold = artifact["threshold"]

if len(sys.argv) != 2:
    print("Usage: python ml\\predict_model.py <input_csv>")
    sys.exit(1)

input_csv = sys.argv[1]

df = pd.read_csv(input_csv)

missing = [f for f in features if f not in df.columns]

if missing:
    print("Missing required features:", missing)
    sys.exit(1)

X = df[features]

probabilities = model.predict_proba(X)[:, 1]

predictions = (probabilities >= threshold).astype(int)

result = df.copy()
result["security_probability"] = probabilities
result["predicted_label"] = predictions
result["predicted_status"] = result["predicted_label"].map({
    1: "SECURE",
    0: "INSECURE"
})

print("\nPrediction Results")
print("==================")

for i, row in result.iterrows():
    name = row.get("deployment", f"Row-{i + 1}")
    print(
        f"{name}: "
        f"Probability={row['security_probability']:.3f}, "
        f"Status={row['predicted_status']}"
    )

print("\nSummary")
print("=======")
print("Total samples:", len(result))
print("Predicted Secure:", int((predictions == 1).sum()))
print("Predicted Insecure:", int((predictions == 0).sum()))
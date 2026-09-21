import pandas as pd
import joblib

MODEL_PATH = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\final_security_model.joblib"

artifact = joblib.load(MODEL_PATH)

model = artifact["model"]
features = artifact["features"]

logistic = model.named_steps["logisticregression"]

coefficients = logistic.coef_[0]

result = pd.DataFrame({
    "feature": features,
    "coefficient": coefficients
})

result["absolute_coefficient"] = result["coefficient"].abs()

result = result.sort_values(
    "absolute_coefficient",
    ascending=False
)

print()
print("FINAL MODEL FEATURE COEFFICIENTS")
print("================================")
print()

print(result.to_string(index=False))

print()
print("INTERPRETATION")
print("==============")
print("Positive coefficient -> increases the model's SECURE probability.")
print("Negative coefficient -> decreases the model's SECURE probability.")
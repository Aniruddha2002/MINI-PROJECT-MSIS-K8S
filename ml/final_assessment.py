import sys
from pathlib import Path

import joblib
import pandas as pd


MODEL_PATH = r"D:\MINI PROJECT\KUBERNATES SECURITY\ml\final_security_model.joblib"


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python ml\\final_assessment.py <input_csv>")
        sys.exit(1)

    input_csv = Path(sys.argv[1])

    if not input_csv.exists():
        print("Input file not found:", input_csv)
        sys.exit(1)

    artifact = joblib.load(MODEL_PATH)

    model = artifact["model"]
    features = artifact["features"]
    threshold = artifact["threshold"]

    df = pd.read_csv(input_csv)

    missing = [feature for feature in features if feature not in df.columns]

    if missing:
        print("Missing required features:")
        for feature in missing:
            print("-", feature)
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

    score = probabilities.mean() * 100

    if score >= 80:
        category = "HIGH"
    elif score >= 60:
        category = "MEDIUM"
    else:
        category = "LOW"

    overall_status = "SECURE" if score >= threshold * 100 else "INSECURE"

    output_csv = input_csv.with_name(
        input_csv.stem + "_final_assessment.csv"
    )

    result.to_csv(output_csv, index=False)

    print()
    print("FINAL KUBERNETES SECURITY ASSESSMENT")
    print("====================================")
    print("Input:", input_csv)
    print("Workloads assessed:", len(result))
    print("Predicted SECURE:", int((predictions == 1).sum()))
    print("Predicted INSECURE:", int((predictions == 0).sum()))
    print(f"Security Score: {score:.2f}/100")
    print(f"Category: {category}")
    print(f"Overall Status: {overall_status}")
    print(f"Decision Threshold: {threshold:.2f}")

    print()
    print("WORKLOAD RESULTS")
    print("=================")

    for index, row in result.iterrows():
        name = row.get("deployment", f"Row-{index + 1}")

        print(
            f"{name}: "
            f"{row['security_probability']:.3f} -> "
            f"{row['predicted_status']}"
        )

    print()
    print("Assessment CSV:")
    print(output_csv)


if __name__ == "__main__":
    main()
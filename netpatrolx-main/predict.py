#!/usr/bin/env python3
"""
Predict malicious probability for encrypted traffic flows using saved model.
Supports:
  1. Single-flow prediction with --values "k=v,k=v,..."
  2. Batch prediction from CSV with --csv input.csv
"""

import argparse, ast, joblib, numpy as np, pandas as pd

# -----------------------
# Helpers
# -----------------------

def parse_kv_string(s):
    # expects "k1=val1,k2=val2,..." or JSON-like dict string
    s = s.strip()
    if s.startswith("{"):
        return ast.literal_eval(s)
    out = {}
    for part in s.split(","):
        if not part.strip(): 
            continue
        k,v = part.split("=")
        try:
            out[k.strip()] = float(v.strip()) if "." in v or "e" in v.lower() else int(v.strip())
        except:
            out[k.strip()] = v.strip()
    return out

def generate_alert(summary, probability):
    """Return human-readable alert text based on top contributing features"""
    top = summary.sort_values("contribution", key=lambda x: x.abs(), ascending=False).head(2)
    indicators = ", ".join(top["feature"].tolist())
    if probability > 0.7:
        return f"🚨 Suspicious flow (p={probability:.2f}) — unusual {indicators} are strong indicators."
    elif probability > 0.5:
        return f"⚠️ Potentially risky flow (p={probability:.2f}) — check {indicators}."
    else:
        return f"✅ Benign flow (p={probability:.2f})."

def explain_predict(model_path, values_dict, verbose=True):
    m = joblib.load(model_path)
    coef = np.array(m["coef"])
    intercept = float(m["intercept"])
    scaler = m["scaler"]
    features = m["features"]

    # build feature vector (raw order)
    x_raw = [values_dict.get(f, 0.0) for f in features]
    Xs = scaler.transform([x_raw])[0]
    logit = Xs.dot(coef) + intercept
    prob = float(1 / (1 + np.exp(-logit)))
    contributions = Xs * coef  # contribution to logit
    summary = pd.DataFrame({
        "feature": features, 
        "raw_value": x_raw, 
        "std_value": Xs, 
        "coef": coef, 
        "contribution": contributions
    })
    summary = summary.assign(abs_contribution = summary.contribution.abs()).sort_values(
        "abs_contribution", ascending=False
    )
    if verbose:
        print(f"\nPredicted malicious probability: {prob:.4f} (threshold 0.5)\n")
        print("Top contributing features (descending by absolute contribution to logit):")
        print(summary[["feature","raw_value","coef","contribution"]].head(8).to_string(index=False))
        print("\n" + generate_alert(summary, prob))
    return prob, summary

# -----------------------
# Main
# -----------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="Path to saved model (joblib pickle)")
    parser.add_argument("--values", help="Single flow: k=v pairs or JSON dict string")
    parser.add_argument("--csv", help="Batch mode: path to CSV with flows")
    args = parser.parse_args()

    if args.values:
        values = parse_kv_string(args.values)
        explain_predict(args.model, values)

    elif args.csv:
        df = pd.read_csv(args.csv)
        print(f"Loaded {len(df)} flows from {args.csv}\n")
        results = []
        for idx, row in df.iterrows():
            values = row.to_dict()
            prob, summary = explain_predict(args.model, values, verbose=False)
            alert = generate_alert(summary, prob)
            results.append({
                "flow_index": idx,
                "probability": prob,
                "alert": alert
            })
        results_df = pd.DataFrame(results)
        print(results_df.to_string(index=False))

    else:
        print("❌ Error: Please provide either --values or --csv")

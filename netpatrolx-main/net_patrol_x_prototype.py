#!/usr/bin/env python3
"""
NET-PATROL-X prototype:
- synthesize encrypted-flow metadata
- simulate federated training (3 clients)
- FedAvg aggregation (on flattened linear coefficients)
- evaluate and save model (coef+intercept+scaler+features)
"""
import argparse, os
import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import joblib

np.random.seed(42)

def synthesize(n_samples=8000):
    packet_count = np.random.poisson(20, n_samples) + 1
    avg_pkt_size = np.random.normal(800, 200, n_samples).clip(40, 2000)
    entropy = np.random.beta(2,5, n_samples) * 8
    tls_version = np.random.choice([1.0,1.1,1.2,1.3], size=n_samples, p=[0.05,0.05,0.5,0.4])
    cipher_rank = np.random.randint(1,50, n_samples)
    interarrival_mean = np.random.exponential(0.05, n_samples)
    sni_entropy = np.random.beta(2,6, n_samples)*8
    session_resumption = np.random.binomial(1, 0.1, n_samples)
    df = pd.DataFrame({
        "packet_count": packet_count,
        "avg_pkt_size": avg_pkt_size,
        "entropy": entropy,
        "tls_version": tls_version,
        "cipher_rank": cipher_rank,
        "interarrival_mean": interarrival_mean,
        "sni_entropy": sni_entropy,
        "session_resumption": session_resumption
    })
    score = (
        (df.packet_count > 60).astype(int)*0.4 +
        (df.entropy > 5.0).astype(int)*0.25 +
        (df.cipher_rank > 35).astype(int)*0.2 +
        (df.sni_entropy > 4.5).astype(int)*0.15 +
        (df.session_resumption==0).astype(int)*0.05
    )
    prob_mal = (score + np.random.normal(0,0.15, n_samples)).clip(0,1)
    labels = (prob_mal > 0.45).astype(int)
    df["label"] = labels
    return df

def init_sgd_partial(scaler, train_df, features):
    m = SGDClassifier(loss='log_loss' if hasattr(SGDClassifier(loss='log'), 'loss') else 'log', max_iter=1, tol=None, learning_rate='constant', eta0=0.01, random_state=0)
    # partial_fit on tiny batch to create attributes
    m.partial_fit(scaler.transform(train_df[features].iloc[:10]), train_df["label"].iloc[:10], classes=np.array([0,1]))
    return m

def run_federated(train_df, test_df, features, n_clients=3, n_rounds=10, local_epochs=5, do_plots=True):
    # split clients
    client_dfs = np.array_split(train_df.sample(frac=1, random_state=1), n_clients)
    scaler = StandardScaler()
    scaler.fit(train_df[features])
    X_test = scaler.transform(test_df[features])
    y_test = test_df["label"].values

    # We'll aggregate flattened coef vectors & intercepts
    global_coef = np.zeros((len(features),))
    global_intercept = 0.0

    for rnd in range(n_rounds):
        local_coefs = []
        local_intercepts = []
        for client_df in client_dfs:
            clf = init_sgd_partial(scaler, train_df, features)
            X_local = scaler.transform(client_df[features])
            y_local = client_df["label"].values
            for ep in range(local_epochs):
                clf.partial_fit(X_local, y_local)
            local_coefs.append(clf.coef_.ravel().copy())
            local_intercepts.append(float(clf.intercept_[0]))
        # FedAvg
        global_coef = np.mean(np.vstack(local_coefs), axis=0)
        global_intercept = float(np.mean(np.array(local_intercepts)))
        # evaluate (manual logistic)
        logits = X_test.dot(global_coef) + global_intercept
        probs = 1 / (1 + np.exp(-logits))
        y_pred = (probs >= 0.5).astype(int)
        acc = accuracy_score(y_test, y_pred)
        print(f"Round {rnd+1}/{n_rounds} - Global model accuracy: {acc:.4f}")

    # final evaluation & return
    logits = X_test.dot(global_coef) + global_intercept
    probs = 1 / (1 + np.exp(-logits))
    y_pred = (probs >= 0.5).astype(int)
    print("\nFinal evaluation on held-out test set:")
    print(classification_report(y_test, y_pred))
    if do_plots:
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(4.5,3.5))
        plt.imshow(cm, interpolation='nearest')
        plt.title("Confusion Matrix (Global Model)")
        plt.xlabel("Predicted"); plt.ylabel("Actual")
        plt.colorbar()
        plt.xticks([0,1]); plt.yticks([0,1])
        for (i, j), val in np.ndenumerate(cm):
            plt.text(j, i, int(val), ha='center', va='center')
        plt.tight_layout(); plt.show()

        feat_imp = pd.DataFrame({"feature": features, "coefficient": global_coef})
        feat_imp["abs_coeff"] = feat_imp["coefficient"].abs()
        feat_imp = feat_imp.sort_values("abs_coeff", ascending=False)
        print("\nTop features by absolute coefficient:")
        print(feat_imp[["feature","coefficient"]])
        plt.figure(figsize=(7,3))
        plt.bar(feat_imp["feature"], feat_imp["coefficient"])
        plt.title("Global Model Coefficients")
        plt.xticks(rotation=45, ha='right'); plt.tight_layout(); plt.show()

    return {"coef": global_coef, "intercept": global_intercept, "scaler": scaler, "features": features}

def main(args):
    # prepare data
    if args.input_csv:
        df = pd.read_csv(args.input_csv)
        # expected the CSV has the same features as `features` below
    else:
        df = synthesize(args.n_samples)

    features = ["packet_count","avg_pkt_size","entropy","tls_version","cipher_rank","interarrival_mean","sni_entropy","session_resumption"]
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])

    model_dict = run_federated(train_df, test_df, features, n_rounds=args.rounds, local_epochs=args.local_epochs, do_plots=not args.no_plots)

    # save
    os.makedirs(args.out_dir, exist_ok=True)
    out_path = os.path.join(args.out_dir, args.output_filename)
    joblib.dump(model_dict, out_path)
    print(f"\nSaved global model to {out_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-samples", type=int, default=8000)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--local-epochs", type=int, default=5)
    parser.add_argument("--out-dir", type=str, default="./out")
    parser.add_argument("--output-filename", type=str, default="global_model.pkl")
    parser.add_argument("--input-csv", type=str, default=None, help="Optional: path to CSV with same features for training")
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()
    main(args)

import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score

# Resolve project root so relative paths work regardless of cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def prepare(df, label_col="no_streaming"):
    # keep only numeric feature columns (exclude label and src_mac)
    if label_col not in df.columns:
        raise SystemExit(f"Label column '{label_col}' not found")
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    features = [c for c in numeric_cols if c != label_col]
    if not features:
        raise SystemExit("No numeric features found for training")
    X = df[features].fillna(0.0)
    y = df[label_col].astype(int)
    return X, y, features

def leave_one_device_out(no_stream_csv, stream_csv, label_col="no_streaming"):
    df = pd.concat([pd.read_csv(no_stream_csv), pd.read_csv(stream_csv)], ignore_index=True)
    if "src_mac" not in df.columns:
        raise SystemExit("src_mac not in data")
    devices = df["src_mac"].unique()
    results = {}
    for dev in devices:
        train = df[df["src_mac"] != dev]
        test = df[df["src_mac"] == dev]
        if test.empty:
            print(f"Skipping device {dev}: no test rows")
            continue
        X_train, y_train, _ = prepare(train, label_col)
        X_test, y_test, _ = prepare(test, label_col)
        pipe = Pipeline([("scaler", StandardScaler()), ("svc", SVC(class_weight="balanced", probability=False))])
        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        results[dev] = {"accuracy": acc, "support": len(y_test)}
        print(f"Device {dev}: acc={acc:.3f} n={len(y_test)}")
    # aggregate weighted average
    if results:
        avg = np.average([v["accuracy"] for v in results.values()], weights=[v["support"] for v in results.values()])
        print(f"Weighted avg accuracy across devices: {avg:.4f}")
    else:
        print("No devices evaluated")
    return results

if __name__ == "__main__":
    leave_one_device_out(
        str(PROJECT_ROOT / "data" / "processed" / "flows_features_no_streaming.csv"),
        str(PROJECT_ROOT / "data" / "processed" / "flows_features_streaming.csv")
    )
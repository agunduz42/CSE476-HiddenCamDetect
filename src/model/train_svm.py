import argparse
from pathlib import Path
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_curve, precision_score, recall_score

# Resolve project root so relative paths work regardless of cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

def load_data(no_streaming_csv: Path, streaming_csv: Path):
    df1 = pd.read_csv(no_streaming_csv)
    df2 = pd.read_csv(streaming_csv)
    df = pd.concat([df1, df2], ignore_index=True)
    return df

def prepare_xy(df, label_col="no_streaming"):
    # drop obvious non-feature columns if present
    non_features = ["flow_id", "pcap_file", "src_mac", "src_ip", "dst_ip", "top_protocols"]
    # ensure label is excluded from feature columns
    cols = [c for c in df.columns if c not in non_features + [label_col]]
    # keep numeric columns + label
    num = df[cols].select_dtypes(include=[np.number]).columns.tolist()
    if label_col not in df.columns:
        raise ValueError(f"Label column {label_col} not found in dataframe")
    X = df[num].fillna(0.0)
    y = df[label_col].astype(int)
    return X, y

def main(args):
    df = load_data(Path(args.no_streaming), Path(args.streaming))
    X, y = prepare_xy(df, label_col=args.label)
    # create train / val / test
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    val_size = float(args.val_size)
    if val_size > 0:
        rel_val = val_size / (1.0 - args.test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_trainval, y_trainval, test_size=rel_val, random_state=42, stratify=y_trainval
        )
    else:
        X_train, y_train = X_trainval, y_trainval
        X_val, y_val = None, None

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("svc", SVC(class_weight="balanced", probability=True))
    ])

    param_grid = {
        "svc__C": [0.1, 1, 10],
        "svc__gamma": ["scale", "auto"],
        "svc__kernel": ["rbf"]
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    gs = GridSearchCV(pipeline, param_grid, cv=cv, scoring="f1", n_jobs=args.n_jobs, verbose=1)
    gs.fit(X_train, y_train)
    best = gs.best_estimator_

    # evaluate on validation (if present)
    if X_val is not None:
        y_val_pred = best.predict(X_val)
        print("Validation accuracy:", round(accuracy_score(y_val, y_val_pred), 4))
        print("Validation report:")
        print(classification_report(y_val, y_val_pred, digits=4))

    y_pred = best.predict(X_test)

    print("Best params:", gs.best_params_)
    print("Test accuracy:", round(accuracy_score(y_test, y_pred), 4))
    print("Classification report:")
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Example: precision/recall at a chosen threshold
    probs = best.predict_proba(X_test)[:, 1]   # prob for class 1 (adjust based on your label encoding)
    prec, rec, thr = precision_recall_curve(y_test, probs)
    # Choose threshold where precision >= 0.9 with highest recall
    idx = (prec >= 0.9).argmax()
    chosen_thresh = thr[idx] if idx < len(thr) else 0.5
    pred_adj = (probs >= chosen_thresh).astype(int)
    print("chosen_thresh", chosen_thresh)
    print("precision", precision_score(y_test, pred_adj), "recall", recall_score(y_test, pred_adj))

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / args.model_name
    joblib.dump(best, model_path)
    print(f"Saved model: {model_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-streaming", dest="no_streaming",
                        default=str(PROJECT_ROOT / "data" / "processed" / "flows_features_no_streaming.csv"))
    parser.add_argument("--streaming", dest="streaming",
                        default=str(PROJECT_ROOT / "data" / "processed" / "flows_features_streaming.csv"))
    parser.add_argument("--label", default="no_streaming")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.1, help="validation set fraction (of total data)")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "src" / "model"))
    parser.add_argument("--model-name", default="svm_pipeline.joblib")
    parser.add_argument("--n-jobs", type=int, default=2)
    args = parser.parse_args()
    main(args)

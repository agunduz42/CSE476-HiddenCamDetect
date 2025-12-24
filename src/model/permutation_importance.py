import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.inspection import permutation_importance

def load_xy(no_csv, stream_csv, label_col="no_streaming"):
    df = pd.concat([pd.read_csv(no_csv), pd.read_csv(stream_csv)], ignore_index=True)
    drop_cols = ["flow_id","pcap_file","src_mac","src_ip","dst_ip","top_protocols"]
    X = df[[c for c in df.columns if c not in drop_cols + [label_col]]].select_dtypes(include=[np.number]).fillna(0)
    y = df[label_col].astype(int)
    return X, y

if __name__ == "__main__":
    X, y = load_xy("data/processed/flows_features_no_streaming.csv", "data/processed/flows_features_streaming.csv")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe = Pipeline([("scaler", StandardScaler()), ("svc", SVC(class_weight='balanced', probability=False))])
    pipe.fit(Xtr, ytr)
    r = permutation_importance(pipe, Xte, yte, n_repeats=10, random_state=42, n_jobs=4)
    imp = pd.Series(r.importances_mean, index=X.columns).sort_values(ascending=False)
    print(imp.head(20))

from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

df = pd.concat([
    pd.read_csv(PROJECT_ROOT / "data" / "processed" / "flows_features_no_streaming.csv"),
    pd.read_csv(PROJECT_ROOT / "data" / "processed" / "flows_features_streaming.csv")
], ignore_index=True)
g = df.groupby("src_mac")["bytes_per_second"].agg(["count","median","mean","min","max"])
g = g.sort_values("median", ascending=False)
print(g.head(50))
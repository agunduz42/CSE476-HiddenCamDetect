import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import subprocess
import tempfile
import time
import json
import shutil
from datetime import datetime
import hashlib

def load_data(path: Path):
    if not path.exists():
        raise SystemExit(f"Input file not found: {path}")
    return pd.read_csv(path)

def prepare_features(df: pd.DataFrame):
    drop = ['flow_id','pcap_file','src_mac','src_ip','dst_ip','no_streaming']
    cols = [c for c in df.columns if c not in drop]
    X = df[cols].select_dtypes(include=[np.number]).fillna(0.0)
    return X

def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-x))

def compute_prob_stream(model, X: pd.DataFrame):
    # Return probability that class == 0 (streaming/threat)
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)
        classes = list(model.classes_)
        if 0 in classes:
            idx0 = classes.index(0)
            return probs[:, idx0]
        return 1.0 - probs[:, 1]
    if hasattr(model, "decision_function"):
        df_scores = model.decision_function(X)
        classes = list(model.classes_)
        probs_pos = sigmoid(df_scores)
        if len(classes) == 2 and classes[1] == 0:
            return probs_pos
        return 1.0 - probs_pos
    preds = model.predict(X)
    return (preds == 0).astype(float)

def threat_level_from_score(score, high=0.9, med=0.6, low=0.3):
    if score >= high:
        return "High"
    if score >= med:
        return "Medium"
    if score >= low:
        return "Low"
    return "Info"

def load_vendor_map(path: Path):
    if not path or not Path(path).exists():
        return {}
    m = {}
    with open(path) as fh:
        for line in fh:
            parts = line.strip().split(",")
            if not parts:
                continue
            oui = parts[0].lower().replace(":", "").replace("-", "")[:6]
            name = parts[1] if len(parts) > 1 else ""
            m[oui] = name
    return m

def guess_device_type(vendor: str):
    if not vendor:
        return "unknown device"
    v = vendor.lower()
    if any(k in v for k in ["camera", "hikvision", "dahua", "axis", "reolink", "xiaomi", "ezviz"]):
        return "IP camera"
    if "apple" in v or "macbook" in v:
        return "Apple device"
    if "google" in v or "android" in v:
        return "Android device"
    return vendor

def summarize_by_device(df_in: pd.DataFrame, threat_scores: np.ndarray, vendor_map=None, out_dir=Path("outputs")):
    out_dir.mkdir(parents=True, exist_ok=True)
    df = df_in.copy()
    df["threat_score"] = threat_scores
    rows = []
    for mac, g in df.groupby("src_mac"):
        max_score = float(g["threat_score"].max())
        mean_score = float(g["threat_score"].mean())
        flows = len(g)
        oui = mac.lower().replace(":", "")[:6]
        vendor = vendor_map.get(oui, "") if vendor_map else ""
        device_type = guess_device_type(vendor)
        level = threat_level_from_score(max_score)
        # hash MAC to avoid exposing device identity
        mac_hash = hashlib.sha256(mac.encode()).hexdigest()[:12]
        # concise summary: HASH | device_type | level | confidence% | flows
        line = f"{mac_hash} | {device_type} | {level} | confidence {int(max_score*100)}% | flows {flows}"
        rows.append({
            "src_mac_hash": mac_hash,
            "vendor": vendor or "Unknown",
            "device_type": device_type,
            "max_threat_score": max_score,
            "mean_threat_score": mean_score,
            "flows": flows,
            "threat_level": level,
            "summary": line
        })
    out_csv = out_dir / "device_threats.csv"
    out_txt = out_dir / "device_threats.txt"
    pd.DataFrame(rows).to_csv(out_csv, index=False)
    with out_txt.open("w") as fh:
        for r in sorted(rows, key=lambda x: x["max_threat_score"], reverse=True):
            fh.write(r["summary"] + "\n")
    print("Top devices by risk:")
    for r in sorted(rows, key=lambda x: x["max_threat_score"], reverse=True)[:10]:
        print("-", r["summary"])
    print(f"Wrote: {out_csv} and {out_txt}")
    return out_csv, out_txt

# --- scapy-based live capture helper ---
def capture_with_scapy(interface: str, duration: int, jsonl_path: Path):
    """
    Capture live traffic for `duration` seconds using scapy and write a simple JSONL.
    Requires scapy and root privileges.
    """
    try:
        from scapy.all import sniff, Ether, IP, TCP, UDP  # type: ignore
    except Exception as e:
        raise SystemExit("scapy not available: install with 'pip install scapy' and run with root privileges") from e

    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    fh = jsonl_path.open("w")

    def handle_pkt(pkt):
        try:
            ts = datetime.fromtimestamp(float(pkt.time)).isoformat() if hasattr(pkt, "time") else ""
        except Exception:
            ts = ""
        eth_src = ""
        ip_src = ""
        ip_dst = ""
        proto = ""
        src_port = ""
        dst_port = ""
        length = 0
        try:
            if Ether in pkt:
                eth_src = pkt[Ether].src
            if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
                src_port = int(pkt[TCP].sport) if hasattr(pkt[TCP], "sport") else ""
                dst_port = int(pkt[TCP].dport) if hasattr(pkt[TCP], "dport") else ""
            elif UDP in pkt:
                proto = "UDP"
                src_port = int(pkt[UDP].sport) if hasattr(pkt[UDP], "sport") else ""
                dst_port = int(pkt[UDP].dport) if hasattr(pkt[UDP], "dport") else ""
            else:
                proto = "IP" if ip_src or ip_dst else ""
            length = len(pkt)
        except Exception:
            pass
        rec = {
            "ts": ts,
            "src_mac": eth_src or "",
            "src_ip": ip_src or "",
            "dst_ip": ip_dst or "",
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": int(length or 0),
        }
        fh.write(json.dumps(rec) + "\n")

    # sniff with timeout; requires root on most systems
    sniff(iface=interface, prn=handle_pkt, store=False, timeout=duration)
    fh.close()
    return jsonl_path

def pcap_to_jsonl(pcap_path: Path, jsonl_path: Path):
    """
    Fallback converter using tshark (kept for compatibility).
    """
    if shutil.which("tshark") is None:
        raise SystemExit("tshark not found; please install Wireshark/tshark or use --capture-method scapy")
    fields = [
        "frame.time_epoch",
        "eth.src",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "frame.len",
    ]
    cmd = ["tshark", "-r", str(pcap_path), "-Y", "ip", "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    with jsonl_path.open("w") as fh:
        for line in proc.stdout:
            parts = line.rstrip("\n").split("|")
            parts += [""] * (len(fields) - len(parts))
            (epoch, eth_src, ip_src, ip_dst, tcp_sport, tcp_dport, udp_sport, udp_dport, length) = parts
            try:
                ts = datetime.fromtimestamp(float(epoch)).isoformat() if epoch else ""
            except Exception:
                ts = ""
            proto = "TCP" if tcp_sport or tcp_dport else ("UDP" if udp_sport or udp_dport else "IP")
            src_port = tcp_sport or udp_sport or ""
            dst_port = tcp_dport or udp_dport or ""
            rec = {
                "ts": ts,
                "src_mac": eth_src or "",
                "src_ip": ip_src or "",
                "dst_ip": ip_dst or "",
                "protocol": proto,
                "src_port": int(src_port) if str(src_port).isdigit() else "",
                "dst_port": int(dst_port) if str(dst_port).isdigit() else "",
                "length": int(length) if str(length).isdigit() else 0,
            }
            fh.write(json.dumps(rec) + "\n")
    proc.wait()
    return jsonl_path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", default="data/processed/flows_features_streaming.csv", help="processed features CSV (if not using --live)")
    parser.add_argument("--model", "-m", default="src/model/svm_pipeline.joblib", help="joblib model path")
    parser.add_argument("--vendor-map", "-v", default=None, help="optional OUI->vendor CSV (OUI,Vendor)")
    parser.add_argument("--outdir", "-o", default="outputs", help="output directory")
    parser.add_argument("--live", action="store_true", help="capture live traffic from interface")
    parser.add_argument("--iface", default="en0", help="network interface for live capture (default en0)")
    parser.add_argument("--duration", type=int, default=30, help="monitoring duration in seconds for live capture")
    parser.add_argument("--capture-method", choices=["scapy","tshark"], default="scapy", help="use scapy or tshark/tcpdump for capture")
    args = parser.parse_args()

    input_csv = Path(args.input)
    if args.live:
        tmpdir = Path(tempfile.mkdtemp(prefix="livecap_"))
        jsonl_path = tmpdir / "capture.jsonl"
        if args.capture_method == "scapy":
            print(f"Capturing live packets with scapy on {args.iface} for {args.duration}s (requires root)...")
            capture_with_scapy(args.iface, args.duration, jsonl_path)
        else:
            pcap_path = tmpdir / "capture.pcap"
            print(f"Capturing live packets with tcpdump on {args.iface} for {args.duration}s (requires sudo)...")
            cmd = ["sudo", "tcpdump", "-i", args.iface, "-w", str(pcap_path), "-s", "0", "ip"]
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                time.sleep(args.duration)
            finally:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()
            print("Converting pcap -> jsonl via tshark...")
            pcap_to_jsonl(pcap_path, jsonl_path)
        feats_out = Path(args.outdir) / "features_live.csv"
        cmd_ext = ["python", "tools/extract_streaming.py", "--input", str(jsonl_path), "--output", str(feats_out), "--label", "0"]
        print("Running extractor:", " ".join(cmd_ext))
        subprocess.check_call(cmd_ext)
        input_csv = feats_out
        print("Live features written to:", input_csv)

    df = load_data(Path(input_csv))
    if "src_mac" not in df.columns:
        raise SystemExit("input CSV must contain src_mac column")
    X = prepare_features(df)
    if X.empty:
        raise SystemExit("No numeric features found for inference")
    model = joblib.load(args.model)
    probs = compute_prob_stream(model, X)
    summarize_by_device(df, probs, vendor_map=load_vendor_map(args.vendor_map), out_dir=Path(args.outdir))

if __name__ == "__main__":
    main()

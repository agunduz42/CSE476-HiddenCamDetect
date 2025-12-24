import json
import csv
import hashlib
import argparse
import ipaddress
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import statistics

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except Exception:
        return False

def safe_mean(xs):
    return float(statistics.mean(xs)) if xs else 0.0

def safe_std(xs):
    return float(statistics.pstdev(xs)) if xs and len(xs) > 1 else 0.0

def _flow_id_from_key(key, start_ts=None):
    rep = "|".join(map(str, key))
    if start_ts is not None:
        rep += "|" + str(start_ts)
    return hashlib.sha1(rep.encode()).hexdigest()[:16]

def extract_features(input_jsonl: Path, output_csv: Path, no_streaming_label=0):
    # group by (src_mac, flow_id) so flows remain device-specific
    flows = defaultdict(list)

    with input_jsonl.open() as f:
        for line in f:
            r = json.loads(line)
            # only consider upload packets (dst is public)
            dst = r.get("dst_ip", "")
            if not is_public_ip(dst):
                continue
            flow_id = r.get("flow_id")
            if not flow_id:
                ts = r.get("ts")
                minute = ts[:16] if ts else ""
                flow_id = f"{r.get('src_mac','')}-{r.get('dst_ip','')}-{r.get('dst_port','')}-{r.get('protocol','')}-{minute}"
            src_mac = r.get('src_mac','')
            flows[(src_mac, flow_id)].append(r)

    out_path = output_csv
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "flow_id",
        "src_mac",
        "pcap_file",
        "flow_start_time",
        "flow_end_time",
        "flow_duration",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "bytes_sent",
        "bytes_received",
        "bytes_per_second",
        "packets_per_second",
        "packet_count",
        "mean_packet_size",
        "std_packet_size",
        "max_packet_size",
        "min_packet_size",
        "inter_arrival_time_mean",
        "inter_arrival_time_std",
        "no_streaming"
    ]

    with out_path.open("w", newline="") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for (src_mac, fid), pkts in flows.items():
            if not pkts:
                continue
            pkts.sort(key=lambda x: x.get("ts", ""))
            first = pkts[0]
            initiator_mac = first.get("src_mac")
            initiator_ip = first.get("src_ip")
            responder_ip = first.get("dst_ip")
            src_port = first.get("src_port") or ""
            dst_port = first.get("dst_port") or ""
            proto = first.get("protocol") or ""

            timestamps = []
            pkt_sizes = []
            bytes_sent = 0
            bytes_received = 0
            initiator_timestamps = []

            for p in pkts:
                ts = datetime.fromisoformat(p["ts"])
                timestamps.append(ts)
                size = int(p.get("length", 0) or 0)
                pkt_sizes.append(size)
                if p.get("src_mac") == initiator_mac:
                    bytes_sent += size
                    initiator_timestamps.append(ts)
                else:
                    bytes_received += size

            start = min(timestamps)
            end = max(timestamps)
            duration = max((end - start).total_seconds(), 1e-6)
            packet_count = len(pkts)
            total_bytes = bytes_sent + bytes_received
            bytes_per_second = total_bytes / duration
            packets_per_second = packet_count / duration

            iat = []
            if len(initiator_timestamps) >= 2:
                initiator_timestamps.sort()
                for a, b in zip(initiator_timestamps, initiator_timestamps[1:]):
                    iat.append((b - a).total_seconds())

            row = {
                "flow_id": _flow_id_from_key((initiator_mac, responder_ip, src_port, dst_port, proto), start.timestamp()),
                "src_mac": src_mac,
                "pcap_file": str(input_jsonl.name),
                "flow_start_time": start.isoformat(),
                "flow_end_time": end.isoformat(),
                "flow_duration": round(duration, 6),
                "src_ip": initiator_ip,
                "dst_ip": responder_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "bytes_per_second": round(bytes_per_second, 3),
                "packets_per_second": round(packets_per_second, 3),
                "packet_count": packet_count,
                "mean_packet_size": round(safe_mean(pkt_sizes), 3),
                "std_packet_size": round(safe_std(pkt_sizes), 3),
                "max_packet_size": max(pkt_sizes) if pkt_sizes else 0,
                "min_packet_size": min(pkt_sizes) if pkt_sizes else 0,
                "inter_arrival_time_mean": round(safe_mean(iat), 6),
                "inter_arrival_time_std": round(safe_std(iat), 6),
                "no_streaming": int(no_streaming_label),
            }
            writer.writerow(row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", default="data/mock_pcap_streaming/mock_streaming_packets.jsonl")
    parser.add_argument("--output", "-o", default="data/processed/flows_features_streaming.csv")
    parser.add_argument("--label", "-l", type=int, default=0, help="no_streaming label (1=no-streaming, 0=streaming)")
    args = parser.parse_args()
    extract_features(Path(args.input), Path(args.output), args.label)
    print(f"Wrote features CSV: {args.output}")

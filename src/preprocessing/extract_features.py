"""
Extract flow-level features from all pcap files under data/raw_pcap/
Saves results to data/processed/flow_features.csv

Features per flow (one row):
- flow_id (hash)
- pcap_file
- flow_start_time, flow_end_time, flow_duration
- src_ip, dst_ip, src_port, dst_port, protocol   (src/dst = initiator/responder based on first packet)
- total_bytes, bytes_sent (from initiator), bytes_received
- bytes_per_second, packets_per_second
- packet_count
- mean_packet_size, std_packet_size, max_packet_size, min_packet_size
- inter_arrival_time_mean, inter_arrival_time_std
- uplink_bytes (same as bytes_sent), downlink_bytes (bytes_received), uplink_to_downlink_ratio
"""
from pathlib import Path
from collections import defaultdict
import os
import hashlib
import csv
import math
import statistics
from datetime import datetime, timezone
import re

# Scapy for reading pcaps
import scapy.all as scapy
from scapy.utils import PcapReader

# Resolve project root so relative paths work regardless of cwd
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

RAW_PCAP_DIR = PROJECT_ROOT / "data" / "raw_pcap"
OUT_DIR = PROJECT_ROOT / "data" / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_CSV = OUT_DIR / "flow_features.csv"


def _canonical_flow_key(ip_a, ip_b, port_a, port_b, proto):
    """
    Create a direction-agnostic key so packets in both directions map to same flow.
    We also return a deterministic ordering so we can identify initiator later.
    """
    # compare (ip,port) tuples lexicographically
    side_a = (ip_a, port_a)
    side_b = (ip_b, port_b)
    if side_a <= side_b:
        return (ip_a, ip_b, port_a, port_b, proto)
    else:
        return (ip_b, ip_a, port_b, port_a, proto)


def _flow_id_from_key(key, start_ts=None):
    # small readable id: sha1 of key (+ optional start timestamp)
    rep = "|".join(map(str, key))
    if start_ts is not None:
        rep += "|" + str(start_ts)
    return hashlib.sha1(rep.encode()).hexdigest()[:16]


def _safe_mean(xs):
    return statistics.mean(xs) if xs else 0.0


def _safe_std(xs):
    # statistics.stdev requires at least 2 values
    if len(xs) >= 2:
        return statistics.stdev(xs)
    return 0.0


def extract_features_from_pcaps(input_dir=RAW_PCAP_DIR, output_csv=OUT_CSV):
    """
    Walk input_dir, open each .pcap / .pcapng file and aggregate packets into flows.
    Produce CSV with one row per flow.
    """
    input_dir = Path(input_dir)
    pcap_files = sorted([p for p in input_dir.iterdir() if p.suffix.lower() in (".pcap", ".pcapng")])

    if not pcap_files:
        print(f"[!] No pcap files found in {input_dir}")
        return

    fieldnames = [
        "flow_id", "device_id",
        "flow_start_time", "flow_end_time", "flow_duration",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "packet_count",
        "total_bytes", "bytes_sent", "bytes_received",
        "bytes_per_second", "packets_per_second",
        "mean_packet_size", "std_packet_size", "max_packet_size", "min_packet_size",
        "inter_arrival_time_mean", "inter_arrival_time_std",
        "uplink_bytes", "downlink_bytes", "uplink_to_downlink_ratio"
    ]

    with open(output_csv, "w", newline="") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()

        for pcap in pcap_files:
            print(f"[*] Processing {pcap} ...")
            flows = {}  # key -> dict of accumulators

            try:
                reader = PcapReader(str(pcap))
            except Exception as e:
                print(f"[!] Failed to open {pcap}: {e}")
                continue

            for pkt in reader:
                # Need time, length, ip/ports, proto
                try:
                    ts = float(pkt.time)
                except Exception:
                    continue

                # packet length (on-wire). len(pkt) is fine for scapy Packet
                try:
                    pkt_len = len(pkt)
                except Exception:
                    pkt_len = 0

                # IPv4 or IPv6?
                ip_layer = None
                src_ip = dst_ip = None
                if pkt.haslayer(scapy.IP):
                    ip_layer = pkt[scapy.IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto = ip_layer.proto
                elif pkt.haslayer(scapy.IPv6):
                    ip_layer = pkt[scapy.IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    proto = ip_layer.nh
                else:
                    # Non-IP packets (ARP etc) - skip for flow-level IP features
                    continue

                # Determine transport protocol and ports
                src_port = dst_port = 0
                proto_name = "OTHER"
                if pkt.haslayer(scapy.TCP):
                    tp = pkt[scapy.TCP]
                    src_port = int(tp.sport)
                    dst_port = int(tp.dport)
                    proto_name = "TCP"
                elif pkt.haslayer(scapy.UDP):
                    tp = pkt[scapy.UDP]
                    src_port = int(tp.sport)
                    dst_port = int(tp.dport)
                    proto_name = "UDP"
                elif pkt.haslayer(scapy.ICMP) or proto == 1:
                    proto_name = "ICMP"
                else:
                    proto_name = str(proto)

                # canonical 5-tuple key (direction-agnostic)
                key = _canonical_flow_key(src_ip, dst_ip, src_port, dst_port, proto_name)

                if key not in flows:
                    # init flow accumulator
                    flows[key] = {
                        "first_ts": ts,
                        "last_ts": ts,
                        "packet_times": [ts],
                        "packet_sizes": [pkt_len],
                        # initiator is the src_ip of first observed pkt for this canonical flow
                        "initiator": src_ip,
                        "initiator_port": src_port,
                        "responder": dst_ip,
                        "responder_port": dst_port,
                        "protocol": proto_name,
                        "total_bytes": pkt_len,
                        "bytes_from_initiator": pkt_len,  # first packet from initiator
                        "bytes_from_responder": 0,
                        "packet_count": 1,
                    }
                else:
                    f = flows[key]
                    f["last_ts"] = ts
                    f["packet_times"].append(ts)
                    f["packet_sizes"].append(pkt_len)
                    f["total_bytes"] += pkt_len
                    f["packet_count"] += 1

                    # direction: is current packet from initiator?
                    if src_ip == f["initiator"]:
                        f["bytes_from_initiator"] += pkt_len
                    elif src_ip == f["responder"]:
                        f["bytes_from_responder"] += pkt_len
                    else:
                        # In rare cases port/ip ordering in canonicalization can swap roles.
                        # Decide direction by comparing to initiator/responder or fallback:
                        if src_ip == key[0]:
                            # ip_a is side A
                            if src_port == key[2]:
                                f["bytes_from_initiator"] += pkt_len
                            else:
                                f["bytes_from_responder"] += pkt_len
                        else:
                            # fallback
                            f["bytes_from_responder"] += pkt_len

            # finished reading pcap
            reader.close()

            # compute per-flow features and write CSV rows
            for key, f in flows.items():
                start_ts = f["first_ts"]
                end_ts = f["last_ts"]
                duration = max(1e-6, (end_ts - start_ts))  # avoid zero division

                total_bytes = f["total_bytes"]
                bytes_sent = f["bytes_from_initiator"]
                bytes_received = f["bytes_from_responder"]
                packets = f["packet_count"]
                bytes_per_second = total_bytes / duration
                packets_per_second = packets / duration

                sizes = f["packet_sizes"]
                mean_size = _safe_mean(sizes)
                std_size = _safe_std(sizes)
                max_size = max(sizes) if sizes else 0
                min_size = min(sizes) if sizes else 0

                times = sorted(f["packet_times"])
                iats = [t2 - t1 for t1, t2 in zip(times, times[1:])] if len(times) >= 2 else []
                iat_mean = _safe_mean(iats)
                iat_std = _safe_std(iats)

                uplink = bytes_sent
                downlink = bytes_received
                ratio = (uplink / downlink) if downlink > 0 else float("inf") if uplink > 0 else 0.0

                # Set src/dst as initiator/responder for ML-friendly 5-tuple
                src_ip = f["initiator"]
                dst_ip = f["responder"]
                src_port = f["initiator_port"]
                dst_port = f["responder_port"]
                proto_name = f["protocol"]

                # infer device_id:
                # if pcap is inside a subdir of input_dir, use that subdir name,
                # otherwise try to parse filename like device_<id> or device-<id>
                if pcap.parent != input_dir:
                    device_id = pcap.parent.name
                else:
                    m = re.search(r"device[_-]?([A-Za-z0-9\-]+)", pcap.stem, re.IGNORECASE)
                    device_id = m.group(1) if m else ""

                row = {
                    "flow_id": _flow_id_from_key(key, start_ts),
                    "device_id": device_id,
                    "flow_start_time": datetime.fromtimestamp(start_ts, timezone.utc).isoformat(),
                    "flow_end_time": datetime.fromtimestamp(end_ts, timezone.utc).isoformat(),
                    "flow_duration": duration,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto_name,
                    "packet_count": packets,
                    "total_bytes": total_bytes,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "bytes_per_second": bytes_per_second,
                    "packets_per_second": packets_per_second,
                    "mean_packet_size": mean_size,
                    "std_packet_size": std_size,
                    "max_packet_size": max_size,
                    "min_packet_size": min_size,
                    "inter_arrival_time_mean": iat_mean,
                    "inter_arrival_time_std": iat_std,
                    "uplink_bytes": uplink,
                    "downlink_bytes": downlink,
                    "uplink_to_downlink_ratio": ratio,
                }
                writer.writerow(row)

    print(f"[+] Flow features written to {output_csv}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract flow-level features from pcap files.")
    parser.add_argument("--input-dir", "-i", default=str(RAW_PCAP_DIR),
                        help="Directory containing .pcap/.pcapng files (default: data/raw_pcap)")
    parser.add_argument("--output-csv", "-o", default=str(OUT_CSV),
                        help="Output CSV path (default: data/processed/flow_features.csv)")
    args = parser.parse_args()
    extract_features_from_pcaps(input_dir=Path(args.input_dir), output_csv=Path(args.output_csv))

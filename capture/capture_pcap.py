# set Scapy list limit before heavy imports to avoid MaximumItemsCount on macOS
from scapy.config import conf as _scapy_conf
_scapy_conf.max_list_count = 65536

import importlib
try:
    # import scapy.all via importlib after setting conf
    scapy = importlib.import_module("scapy.all")
except Exception:
    # retry once after ensuring conf is set (best-effort)
    try:
        import scapy.config as _scapy_config
        _scapy_config.conf.max_list_count = 65536
    except Exception:
        pass
    scapy = importlib.import_module("scapy.all")

import yaml
import os
from datetime import datetime
from collections import defaultdict
import time
import signal
import sys
import hashlib
import ipaddress

class PacketCapture:
    def __init__(self, config_path="config/capture_config.yaml"):
        """Initialize packet capture with config file."""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)['capture']
        
        # Device statistics
        self.device_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_total': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'first_seen': None,
            'last_seen': None
        })
        
        self.start_time = None
        self.stop_capture = False
        self.max_devices = self.config.get('max_devices', 0)  # 0 = unlimited
        # store only upload packets
        self.captured_packets = []
         
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        # previously printed a message; keep silent
        self.stop_capture = True
    
    def packet_callback(self, packet):
        """Process each captured packet for device analysis."""
        # Only consider upload packets:
        # - must have Ethernet and IP/IPv6
        # - source MAC present (device)
        # - destination IP must be public (not .is_private, not loopback/link-local)
        try:
            if not packet.haslayer(scapy.Ether):
                return
            src_mac = packet.src
            dst_ip = None
            if packet.haslayer(scapy.IP):
                dst_ip = packet[scapy.IP].dst
            elif packet.haslayer(scapy.IPv6):
                dst_ip = packet[scapy.IPv6].dst
            else:
                return

            if not src_mac or not dst_ip:
                return

            ipobj = ipaddress.ip_address(dst_ip.split('%')[0])
            # if destination is private/loopback/link-local/multicast => not upload to internet
            if ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local or ipobj.is_multicast:
                return

        except Exception:
            return

        # DEBUG: kısa çıktı (geçici)
        print(f"[debug] upload pkt: src_mac={src_mac} dst_ip={dst_ip} len={len(packet)}")

        # Passed upload filter -> record packet and update per-device upload stats
        timestamp = datetime.now()
        self.captured_packets.append(packet)

        # Respect max_devices: if limit reached ignore new device MACs
        if self.max_devices > 0 and src_mac not in self.device_stats and len(self.device_stats) >= self.max_devices:
            return

        device = self.device_stats[src_mac]
        device['packet_count'] += 1
        device['bytes_total'] += len(packet)
        # extract source IP if available
        if packet.haslayer(scapy.IP):
            device['ip'] = packet[scapy.IP].src
        elif packet.haslayer(scapy.IPv6):
            device['ip'] = packet[scapy.IPv6].src

        if device['first_seen'] is None:
            device['first_seen'] = timestamp
        device['last_seen'] = timestamp

        # Protocol detection (only for upload packets)
        if packet.haslayer(scapy.TCP):
            device['protocols']['TCP'] += 1
            if packet.haslayer(scapy.Raw):
                device['protocols']['TCP_with_payload'] += 1
            device['ports'][packet[scapy.TCP].sport] += 1
            device['ports'][packet[scapy.TCP].dport] += 1
            if packet[scapy.TCP].dport == 80 or packet[scapy.TCP].sport == 80:
                device['protocols']['HTTP'] += 1
            elif packet[scapy.TCP].dport == 443 or packet[scapy.TCP].sport == 443:
                device['protocols']['HTTPS'] += 1
            elif packet[scapy.TCP].dport == 554 or packet[scapy.TCP].sport == 554:
                device['protocols']['RTSP'] += 1
        elif packet.haslayer(scapy.UDP):
            device['protocols']['UDP'] += 1
            device['ports'][packet[scapy.UDP].sport] += 1
            device['ports'][packet[scapy.UDP].dport] += 1
        elif packet.haslayer(scapy.ICMP):
            device['protocols']['ICMP'] += 1
        elif packet.haslayer(scapy.ARP):
            device['protocols']['ARP'] += 1
    
    def print_statistics(self):
        """Print current capture statistics."""
        print("\n" + "="*70)
        print(f"Capture Statistics - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        print(f"Active devices: {len(self.device_stats)}\n")
        
        for mac, stats in sorted(self.device_stats.items(), 
                                key=lambda x: x[1]['packet_count'], 
                                reverse=True):
            print(f"Device: {mac} (IP: {stats.get('ip', 'N/A')})")
            print(f"  Packets: {stats['packet_count']}, Bytes: {stats['bytes_total']}")
            print(f"  Top Protocols: {dict(sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:3])}")
            print()
    
    def start_capture(self):
        """Start packet capture."""
        self.start_time = datetime.now()
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        
        # Create output directory
        output_dir = self.config['output_dir']
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"capture_{timestamp}.pcap")
        
        interface = self.config.get('interface') or scapy.conf.iface
        duration = float(self.config.get('duration', 30))
        bpf_filter = self.config.get('bpf_filter', '')
        promisc = self.config.get('promiscuous', True)
        
        # Run sniff in short intervals so total runtime ~= duration (avoids early return)
        start_ts = time.time()
        try:
            while (time.time() - start_ts) < duration and not self.stop_capture:
                scapy.sniff(
                    iface=interface,
                    filter=bpf_filter if bpf_filter else None,
                    prn=self.packet_callback,
                    timeout=1,          # short interval
                    store=False,
                    promisc=promisc,
                    # stop_filter not needed because we loop on time
                )
            # Save only upload packets to file (no console output)
            if self.captured_packets:
                scapy.wrpcap(output_file, self.captured_packets)
            
            # Prepare summary information (upload-only)
            total_devices = len(self.device_stats)
            total_packets = sum(d['packet_count'] for d in self.device_stats.values())
            total_bytes = sum(d['bytes_total'] for d in self.device_stats.values())
            total_mb = total_bytes / (1024 * 1024)
            
            summary_lines = []
            summary_lines.append(f"Capture summary - {timestamp}")
            summary_lines.append(f"Output pcap (upload-only): {output_file}")
            summary_lines.append(f"Total devices (upload): {total_devices}")
            summary_lines.append(f"Total upload packets: {total_packets}")
            summary_lines.append(f"Total upload bytes: {total_bytes} ({total_mb:.2f} MB)")
            summary_lines.append("")
            summary_lines.append("Devices (sorted by upload packet count):")
            
            for mac, stats in sorted(self.device_stats.items(), 
                                    key=lambda x: x[1]['packet_count'], 
                                    reverse=True):
                mac_hash = hashlib.sha256(mac.encode()).hexdigest()[:12]
                ip = stats.get('ip', 'N/A')
                pkt_cnt = stats['packet_count']
                bytes_cnt = stats['bytes_total']
                mb = bytes_cnt / (1024 * 1024)
                first = stats['first_seen'].isoformat() if stats['first_seen'] else "N/A"
                last = stats['last_seen'].isoformat() if stats['last_seen'] else "N/A"
                top_protocols = dict(sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:5])
                top_ports = dict(sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10])
                
                summary_lines.append(f"- MAC: {mac}  (hash: {mac_hash})")
                summary_lines.append(f"  IP: {ip}")
                summary_lines.append(f"  Upload Packets: {pkt_cnt}, Upload Bytes: {bytes_cnt} ({mb:.2f} MB)")
                summary_lines.append(f"  First seen: {first}, Last seen: {last}")
                summary_lines.append(f"  Top protocols: {top_protocols}")
                summary_lines.append(f"  Top ports: {top_ports}")
                summary_lines.append("")
            
            # Write summary file
            summary_file = os.path.join(output_dir, f"summary_{timestamp}.txt")
            with open(summary_file, 'w') as f:
                f.write("\n".join(summary_lines))
            
            return

        except KeyboardInterrupt:
            # graceful stop on Ctrl+C
            pass
        except Exception as e:
            print(f"[!] Error during capture: {e}")
            sys.exit(1)

if __name__ == "__main__":
    pc = PacketCapture()
    try:
        pc.start_capture()
    except KeyboardInterrupt:
        # graceful exit on Ctrl+C
        pass

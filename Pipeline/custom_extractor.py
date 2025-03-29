# === flow_processing/custom_extractor.py ===
import pyshark
import pandas as pd
import numpy as np
import os
from collections import defaultdict
import asyncio

try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())

selected_features = [
    'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Flow Bytes/s',
    'Flow Packets/s', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'Average Packet Size', 'Packet Length Std',
    'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'src_ip'
]

def extract_custom_features(pcap_path, csv_output_path):
    try:
        cap = pyshark.FileCapture(pcap_path, use_json=True, include_raw=True)
        flows = defaultdict(list)

        for pkt in cap:
            try:
                if 'ip' not in pkt:
                    continue

                proto = pkt.transport_layer or 'UNKNOWN'
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = getattr(pkt[pkt.transport_layer], 'srcport', '0')
                dst_port = getattr(pkt[pkt.transport_layer], 'dstport', '0')

                flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                timestamp = float(pkt.sniff_timestamp)
                length = int(pkt.length)

                flows[flow_id].append({
                    'timestamp': timestamp,
                    'length': length,
                    'window': float(getattr(pkt.tcp, 'window_size_value', 0)) if hasattr(pkt, 'tcp') else 0,
                    'src_ip': src_ip
                })
            except Exception:
                continue

        final_data = []
        for flow_packets in flows.values():
            if len(flow_packets) < 2:
                continue

            timestamps = [p['timestamp'] for p in flow_packets]
            lengths = [p['length'] for p in flow_packets]
            windows = [p['window'] for p in flow_packets]
            duration = timestamps[-1] - timestamps[0]
            fwd_pkt = len(flow_packets) // 2
            bwd_pkt = len(flow_packets) - fwd_pkt
            src_ip = flow_packets[0]['src_ip']

            feature_row = {
                'Flow Duration': duration,
                'Total Fwd Packet': fwd_pkt,
                'Total Bwd packets': bwd_pkt,
                'Flow Bytes/s': sum(lengths) / duration if duration > 0 else 0,
                'Flow Packets/s': len(flow_packets) / duration if duration > 0 else 0,
                'Fwd Packet Length Mean': np.mean(lengths[:fwd_pkt]) if fwd_pkt else 0,
                'Bwd Packet Length Mean': np.mean(lengths[fwd_pkt:]) if bwd_pkt else 0,
                'Fwd IAT Mean': np.mean(np.diff(timestamps[:fwd_pkt])) if fwd_pkt > 1 else 0,
                'Bwd IAT Mean': np.mean(np.diff(timestamps[fwd_pkt:])) if bwd_pkt > 1 else 0,
                'Average Packet Size': np.mean(lengths),
                'Packet Length Std': np.std(lengths),
                'Subflow Bwd Bytes': sum(lengths[fwd_pkt:]),
                'FWD Init Win Bytes': windows[0] if windows else 0,
                'src_ip': src_ip
            }

            final_data.append(feature_row)

        df = pd.DataFrame(final_data)
        df = df[selected_features]  # Fixed line
        df.dropna(subset=selected_features, inplace=True)

        if not df.empty:
            os.makedirs(os.path.dirname(csv_output_path), exist_ok=True)
            df.to_csv(csv_output_path, index=False)
            print(f"✅ Feature extraction complete. Saved to {csv_output_path}")
        else:
            print("⚠️ No valid flows extracted. CSV will not be saved.")
    except Exception as e:
        print(f"❌ Error in feature extraction: {e}")

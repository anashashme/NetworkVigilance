# === traffic_capture/capture.py ===
import subprocess
import os

def capture_traffic(interface='Wi-Fi 2', duration=30, output_path='data/live_capture.pcap'):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    cmd = ["dumpcap", "-i", interface, "-a", f"duration:{duration}", "-w", output_path]
    subprocess.run(cmd, shell=True)
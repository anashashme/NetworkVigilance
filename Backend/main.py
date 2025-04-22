# === app/main.py ===
import os
import pandas as pd
from traffic_capture.capture import capture_traffic
from flow_processing.custom_extractor import extract_custom_features
from prediction_engine.predict import predict_from_csv
from firewall_control.block_unblock import block_ip

PCAP_PATH = "data/live_capture.pcap"
CSV_PATH = "data/Latest-Flow.csv"
THRESHOLD = 999

print("\U0001F310 Capturing Traffic...")
capture_traffic(output_path=PCAP_PATH)

print("⚙️ Extracting Features...")
extract_custom_features(pcap_path=PCAP_PATH, csv_output_path=CSV_PATH)

print("\U0001F916 Making Predictions...")
y_rf_pred, y_iso_pred, src_ips = predict_from_csv(CSV_PATH, threshold=THRESHOLD)

if len(y_iso_pred) == 0:
    print("No predictions to display.")
else:
    combined_pred = y_iso_pred.astype(int)  # Only trust Isolation Forest
    if combined_pred.sum() > 0:
        print("The Captured traffic is detected as Malicious")
        malicious_ips = set([ip for pred, ip in zip(combined_pred, src_ips) if pred == 1])
        for ip in malicious_ips:
            block_ip(ip)
    else:
        print("The Captured traffic is detected as Benign")
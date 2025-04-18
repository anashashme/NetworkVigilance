# === prediction_engine/predict.py ===
import pandas as pd
import numpy as np
import joblib
import os

selected_features = [
    'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Flow Bytes/s',
    'Flow Packets/s', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'Average Packet Size', 'Packet Length Std',
    'Subflow Bwd Bytes', 'FWD Init Win Bytes'
]

def load_models():
    base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
    rf_model = joblib.load(os.path.join(base_path, "rf_model.pkl"))
    rf_scaler = joblib.load(os.path.join(base_path, "scaler.pkl"))
    iso_model = joblib.load(os.path.join(base_path, "isolation_forest_model.pkl"))
    iso_scaler = joblib.load(os.path.join(base_path, "isolation_forest_scaler.pkl"))
    return rf_model, rf_scaler, iso_model, iso_scaler

def predict_from_csv(csv_path, threshold=-0.1):
    if not os.path.exists(csv_path) or os.stat(csv_path).st_size == 0:
        print(f"❌ No data extracted or file not found. Skipping prediction.")
        return [], [], []

    df = pd.read_csv(csv_path).replace([np.inf, -np.inf], np.nan)
    df.dropna(subset=selected_features, inplace=True)

    if df.empty:
        print("⚠️ CSV has no valid data rows after preprocessing.")
        return [], [], []

    if 'src_ip' not in df.columns:
        df['src_ip'] = 'unknown'

    X = df[selected_features]
    rf_model, rf_scaler, iso_model, iso_scaler = load_models()

    X_rf_scaled = rf_scaler.transform(X)
    y_rf_pred = rf_model.predict(X_rf_scaled)

    X_iso_scaled = iso_scaler.transform(X)
    scores = iso_model.decision_function(X_iso_scaled)
    print(f"🔎 Sample anomaly scores: min={scores.min():.4f}, max={scores.max():.4f}, mean={scores.mean():.4f}")
    y_iso_pred = np.where(scores < threshold, 1, 0)

    return y_rf_pred, y_iso_pred, df['src_ip'].tolist()

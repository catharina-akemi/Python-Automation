"""
Network Traffic Capture & Anomaly Detection
--------------------------------------------
Captures live packets with scapy, extracts features, and flags suspicious
traffic patterns using rule-based heuristics + an optional Isolation Forest
model.

Run with elevated privileges (sudo / Administrator) since raw packet
capture requires it.
"""

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
from collections import defaultdict

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

import matplotlib.pyplot as plt

# -----------------------
# 1. PACKET CAPTURE
# -----------------------

packets_data = []  # list where captured packet features are stored


def packet_handler(packet):
    """Extract relevant fields from each captured packet."""
    try:
        if not packet.haslayer(IP):
            return  # skip non-IP traffic (ARP, etc.)

        ip_layer = packet[IP]

        src_port, dst_port, flags = None, None, None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        data = {
            "Timestamp": time.time(),
            "Source IP": ip_layer.src,
            "Destination IP": ip_layer.dst,
            "Protocol": ip_layer.proto,   # numeric (6=TCP, 17=UDP, 1=ICMP)
            "Src Port": src_port,
            "Dst Port": dst_port,
            "TCP Flags": flags,
            "Length": len(packet),
        }
        packets_data.append(data)

    except (IndexError, AttributeError):
        pass  # ignore malformed / incomplete packets


def capture_traffic(count=100, iface=None):
    """Start packet capture. Set iface=None to use the default interface."""
    print(f"Capturing {count} packets... (needs admin/root privileges)")
    sniff(prn=packet_handler, count=count, iface=iface)
    return pd.DataFrame(packets_data)


# --------------------------
# 2. FEATURE ENRICHMENT
# --------------------------

PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


def enrich_dataframe(df):
    df = df.copy()
    df["Protocol Name"] = df["Protocol"].map(PROTOCOL_MAP).fillna("OTHER")
    df["Datetime"] = pd.to_datetime(df["Timestamp"], unit="s")
    return df


# ------------------------------------
# 3. RULE-BASED ANOMALY DETECTION
# ------------------------------------

def detect_port_scan(df, port_threshold=15, time_window=10):
    """
    Flags a source IP as a potential port scanner if it contacts more than
    'port_threshold' distinct destination ports within 'time_window' seconds.
    """
    alerts = []
    df_sorted = df.dropna(subset=["Dst Port"]).sort_values("Timestamp")

    for src_ip, group in df_sorted.groupby("Source IP"):
        timestamps = group["Timestamp"].values
        ports = group["Dst Port"].values

        start_idx = 0
        seen_ports = defaultdict(set)
        for i, t in enumerate(timestamps):
            # slide window: drop entries older than time_window
            while timestamps[i] - timestamps[start_idx] > time_window:
                start_idx += 1
            window_ports = set(ports[start_idx:i + 1])
            if len(window_ports) > port_threshold:
                alerts.append({
                    "Type": "Port Scan",
                    "Source IP": src_ip,
                    "Distinct Ports": len(window_ports),
                    "Timestamp": t
                })
                break  # one alert per source IP is enough
    return pd.DataFrame(alerts)


def detect_traffic_spike(df, pps_threshold=50):
    """
    Flags a source IP sending more than 'pps_threshold' packets in any
    single one-second window (possible flood / DoS attempt).
    """
    df = df.copy()
    df["Second"] = df["Timestamp"].astype(int)
    counts = df.groupby(["Source IP", "Second"]).size().reset_index(name="Packets/sec")
    alerts = counts[counts["Packets/sec"] > pps_threshold]
    alerts = alerts.assign(Type="Traffic Spike")
    return alerts


def detect_size_anomalies(df, z_thresh=3):
    """
    Flags packets whose length is a statistical outlier (z-score) compared
    to the overall traffic captured — can indicate exfiltration or crafted
    payloads.
    """
    mean_len = df["Length"].mean()
    std_len = df["Length"].std()
    if std_len == 0 or np.isnan(std_len):
        return pd.DataFrame()

    df = df.copy()
    df["Z Score"] = (df["Length"] - mean_len) / std_len
    alerts = df[df["Z Score"].abs() > z_thresh].copy()
    alerts["Type"] = "Size Anomaly"
    return alerts[["Type", "Source IP", "Destination IP", "Length", "Z Score", "Timestamp"]]


# --------------------------------------------------------------------------
# 4. ML-BASED ANOMALY DETECTION (optional, needs scikit-learn)
# --------------------------------------------------------------------------

def detect_ml_anomalies(df, contamination=0.05):
    """
    Uses Isolation Forest on numeric traffic features to flag statistically
    unusual packets. 'contamination' = expected proportion of anomalies.
    """
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not installed — skipping ML-based detection.")
        return pd.DataFrame()

    features = df[["Protocol", "Length"]].copy()
    features["Src Port"] = df["Src Port"].fillna(0)
    features["Dst Port"] = df["Dst Port"].fillna(0)

    model = IsolationForest(contamination=contamination, random_state=42)
    df = df.copy()
    df["Anomaly"] = model.fit_predict(features)  # -1 = anomaly, 1 = normal

    return df[df["Anomaly"] == -1]


# -------------------------
# 5. MAIN PIPELINE
# -------------------------

def main():
    df = capture_traffic(count=100)  # increase count for more accurate detection

    if df.empty:
        print("No packets captured (check permissions / interface).")
        return

    df = enrich_dataframe(df)
    print(df.head())

    print("\nProtocol counts:")
    print(df["Protocol Name"].value_counts())

    print("\nTop 10 source IPs:")
    print(df["Source IP"].value_counts().head(10))

    df.to_csv("network_packets.csv", index=False)

    # --- Anomaly detection ---
    port_scan_alerts = detect_port_scan(df)
    spike_alerts = detect_traffic_spike(df)
    size_alerts = detect_size_anomalies(df)
    ml_alerts = detect_ml_anomalies(df)

    print("\n=== ANOMALY REPORT ===")
    print(f"Port scan alerts: {len(port_scan_alerts)}")
    print(f"Traffic spike alerts: {len(spike_alerts)}")
    print(f"Packet size anomalies: {len(size_alerts)}")
    print(f"ML-flagged anomalies: {len(ml_alerts)}")

    all_alerts = pd.concat(
        [port_scan_alerts, spike_alerts, size_alerts],
        ignore_index=True, sort=False
    )
    if not all_alerts.empty:
        all_alerts.to_csv("traffic_anomalies.csv", index=False)
        print("\nSaved detailed alerts to traffic_anomalies.csv")

    # --- Visualization ---
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    df["Protocol Name"].value_counts().plot(kind="bar", ax=axes[0], title="Protocol Counts")
    axes[0].set_xlabel("Protocol")
    axes[0].set_ylabel("Count")

    df["Source IP"].value_counts().head(10).plot(kind="barh", ax=axes[1], title="Top 10 Source IPs")
    axes[1].set_xlabel("Packets")

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()

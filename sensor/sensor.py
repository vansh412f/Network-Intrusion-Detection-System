"""
================================================================================
NIDS Sensor — Network Intrusion Detection System Sensor Module
================================================================================

Purpose:
    Real-time network traffic monitoring and threat detection using XGBoost ML.
    
Modes:
    --mode real      → Sniffs live network packets using Scapy
    --mode simulate  → Generates fake traffic for demo purposes
    
Features:
    - Real-time packet capture and analysis
    - 15-feature extraction from network flows
    - XGBoost binary classification (BENIGN vs MALICIOUS)
    - 80% confidence threshold for alerts
    - HTTP POST to Node.js backend for alert storage
    
Author: [Your Name]
Dataset: CIC-DDoS2019
Model Accuracy: 99.85%
================================================================================
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import sys
import os
import time
import json
import random
import joblib
import requests
import argparse 
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, AsyncSniffer
from dotenv import load_dotenv

load_dotenv()

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# ── File Paths ────────────────────────────────────────────────────────────────
SENSOR_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(SENSOR_DIR, "..", "ml", "model")

MODEL_PATH    = os.path.join(MODEL_DIR, "nids_model.pkl")
ENCODER_PATH  = os.path.join(MODEL_DIR, "nids_encoder.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "nids_metadata.json")

# ── Network Settings ──────────────────────────────────────────────────────────

INTERFACE = os.getenv("INTERFACE")
MY_IP     = os.getenv("MY_IP")

# Validate required settings
if not INTERFACE or not MY_IP:
    print("=" * 60)
    print("❌ ERROR: Missing network configuration!")
    print("=" * 60)
    print("\nPlease create sensor/.env file with:")
    print("    INTERFACE=Your-Network-Adapter-Name")
    print("    MY_IP=192.168.x.x")
    print("\nSee sensor/.env.example for instructions.")
    print("=" * 60)
    sys.exit(1)

# ── Detection Settings ────────────────────────────────────────────────────────
WINDOW_SECONDS   = 2      # Time window for aggregating packets (seconds)
ALERT_THRESHOLD  = 0.80   # Minimum ML confidence to trigger alert (0-1)
MIN_PACKETS      = 10     # Minimum packets in flow to analyze (prevents false positives)

# ── Backend API ───────────────────────────────────────────────────────────────
BACKEND_URL    = os.getenv("BACKEND_URL", "http://localhost:3000")
SENSOR_SECRET  = os.getenv("SENSOR_SECRET", "default_secret")
ALERT_ENDPOINT = f"{BACKEND_URL}/api/internal/alert"
STATS_ENDPOINT = f"{BACKEND_URL}/api/internal/stats"
# ── Simulation Data (for --mode simulate) ────────────────────────────────────
BENIGN_IPS = [
    "142.250.80.46",   # Google
    "13.69.116.109",   # Microsoft Azure
    "140.82.114.21",   # GitHub
    "151.101.1.140",   # Fastly CDN
    "104.21.45.231",   # Cloudflare
    "52.84.163.89",    # Amazon CloudFront
    "192.168.31.1",    # Local router
    "8.8.8.8",         # Google DNS
]

ATTACKER_IPS = [
    "45.83.64.1",
    "185.220.101.45",
    "194.165.16.11",
    "91.108.4.100",
    "198.54.117.200",
    "103.149.28.195",
]


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND LINE ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════════════════

parser = argparse.ArgumentParser(
    description='NIDS Sensor — Network Intrusion Detection System',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
Examples:
  python sensor.py --mode real      # Sniff real network traffic
  python sensor.py --mode simulate  # Generate fake traffic for demo
    '''
)
parser.add_argument(
    '--mode',
    choices=['real', 'simulate'],
    default='simulate',
    help='Operating mode (default: simulate for safety)'
)
args = parser.parse_args()
SENSOR_MODE = args.mode


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def log(message, level="INFO"):
    """
    Prints timestamped log messages with colored icons.
    
    Args:
        message (str): Log message to display
        level (str): Log level (INFO, ALERT, ERROR, DEBUG, SUCCESS)
    """
    icons = {
        "INFO":    "ℹ️ ",
        "ALERT":   "🚨",
        "ERROR":   "❌",
        "DEBUG":   "🔍",
        "SUCCESS": "✅"
    }
    icon = icons.get(level, "  ")
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {icon}  {message}")


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL LOADING AND VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def load_ml_artifacts():
    """
    Loads the trained XGBoost model, label encoder, and metadata.
    
    Returns:
        dict: Contains 'model', 'encoder', and 'metadata' keys
        
    Raises:
        Exception: If any artifact fails to load
    """
    log("Loading ML artifacts...")

    try:
        model = joblib.load(MODEL_PATH)
        log("  ✅ Model loaded", "INFO")
    except Exception as e:
        log(f"  ❌ Model failed to load: {e}", "ERROR")
        raise

    try:
        encoder = joblib.load(ENCODER_PATH)
        log("  ✅ Encoder loaded", "INFO")
    except Exception as e:
        log(f"  ❌ Encoder failed to load: {e}", "ERROR")
        raise

    try:
        with open(METADATA_PATH, 'r') as f:
            metadata = json.load(f)
        log("  ✅ Metadata loaded", "INFO")
        log(f"     Features  : {len(metadata['final_column_order'])} columns")
        log(f"     Model type: {metadata['model_info']['type']}")
        log(f"     Accuracy  : {metadata['model_info']['accuracy_percent']}%")
    except Exception as e:
        log(f"  ❌ Metadata failed to load: {e}", "ERROR")
        raise

    return {
        'model':    model,
        'encoder':  encoder,
        'metadata': metadata
    }


def verify_model(artifacts):
    """
    Runs a quick test prediction to verify the model is working correctly.
    
    Args:
        artifacts (dict): ML artifacts from load_ml_artifacts()
        
    Returns:
        bool: True if verification successful
    """
    log("Verifying model with test input...")

    # Sample benign traffic features
    test_features = {
        "Bwd Packets/s":            np.float32(150.5),
        "Flow Bytes/s":             np.float32(5400.0),
        "Flow Duration":            np.int32(200000),
        "Flow IAT Max":             np.float32(100000.0),
        "Flow IAT Mean":            np.float32(50000.0),
        "Flow IAT Std":             np.float32(25000.0),
        "Flow Packets/s":           np.float32(300.0),
        "Fwd Act Data Packets":     np.int16(10),
        "Fwd Packet Length Max":    np.float32(1500.0),
        "Fwd Packet Length Min":    np.float32(40.0),
        "Fwd Packets Length Total": np.float32(8000.0),
        "Fwd Packets/s":            np.float32(150.0),
        "Packet Length Max":        np.float32(1500.0),
        "Total Backward Packets":   np.int16(8),
        "ACK Flag Count":           '0'
    }

    # Prepare dataframe
    numeric_df = pd.DataFrame([test_features])
    ack_value  = pd.DataFrame([test_features["ACK Flag Count"]], 
                              columns=['ACK Flag Count'])
    numeric_df = numeric_df.drop(columns=['ACK Flag Count'])

    # Encode ACK flag
    ack_encoded = np.array(artifacts['encoder'].transform(ack_value))
    ack_encoded_df = pd.DataFrame(
        ack_encoded,
        columns=['ACK Flag Count_0', 'ACK Flag Count_1']
    ).astype('int64')

    # Combine and reorder columns
    final_row = pd.concat([numeric_df, ack_encoded_df], axis=1)
    final_row = final_row[artifacts['metadata']['final_column_order']]

    # Run prediction
    prediction = artifacts['model'].predict(final_row)[0]
    label = "BENIGN" if prediction == 0 else "MALICIOUS"

    log(f"  Test prediction : {label}", "DEBUG")
    log("  ✅ Model verified — ready for inference", "SUCCESS")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# SIMULATION MODE — FAKE TRAFFIC GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def generate_benign_features():
    """
    Generates realistic feature values for normal network traffic.
    Based on typical home/office browsing patterns.
    
    Returns:
        dict: 15 network flow features that will classify as BENIGN
    """
    flow_duration_us  = random.randint(100_000, 2_000_000)
    flow_duration_sec = flow_duration_us / 1_000_000

    total_packets = random.randint(10, 150)
    fwd_packets   = random.randint(5, total_packets - 2)
    bwd_packets   = total_packets - fwd_packets

    fwd_pkt_len = random.uniform(40, 1200)
    bwd_pkt_len = random.uniform(40, 800)
    total_bytes = (fwd_packets * fwd_pkt_len + bwd_packets * bwd_pkt_len)

    # Normal traffic has longer inter-arrival times
    iat_mean = random.uniform(5000, 200000)
    iat_max  = iat_mean * random.uniform(1.5, 8.0)
    iat_std  = iat_mean * random.uniform(0.2, 2.0)

    return {
        "Bwd Packets/s":            np.float32(bwd_packets / flow_duration_sec),
        "Flow Bytes/s":             np.float32(total_bytes / flow_duration_sec),
        "Flow Duration":            np.int32(flow_duration_us),
        "Flow IAT Max":             np.float32(iat_max),
        "Flow IAT Mean":            np.float32(iat_mean),
        "Flow IAT Std":             np.float32(iat_std),
        "Flow Packets/s":           np.float32(total_packets / flow_duration_sec),
        "Fwd Act Data Packets":     np.int16(max(1, fwd_packets - 2)),
        "Fwd Packet Length Max":    np.float32(fwd_pkt_len * 1.2),
        "Fwd Packet Length Min":    np.float32(fwd_pkt_len * 0.3),
        "Fwd Packets Length Total": np.float32(fwd_packets * fwd_pkt_len),
        "Fwd Packets/s":            np.float32(fwd_packets / flow_duration_sec),
        "Packet Length Max":        np.float32(max(fwd_pkt_len, bwd_pkt_len)),
        "Total Backward Packets":   np.int16(bwd_packets),
        "ACK Flag Count":           random.choice(['0', '1'])
    }


def generate_attack_features():
    """
    Generates feature values calibrated to trigger MALICIOUS classification.
    Based on Test 7 parameters that achieved 85.16% confidence.
    
    Characteristics of DDoS:
        - High packet rate (~8000-16000 packets/s)
        - Very low inter-arrival time (~30 μs)
        - Zero forward payload (SYN flood style)
        
    Returns:
        dict: 15 network flow features that will classify as MALICIOUS (>80%)
    """
    base_rate = random.randint(7000, 9000)
    flow_duration_us = random.randint(900_000, 1_100_000)
    
    # DDoS has very short gaps between packets
    iat_mean = random.uniform(25, 35)
    iat_max  = random.uniform(250, 350)
    iat_std  = random.uniform(8, 12)
    
    bwd_packets_s  = np.float32(base_rate + random.randint(-500, 500))
    fwd_packets_s  = np.float32(base_rate + random.randint(-500, 500))
    flow_packets_s = np.float32(bwd_packets_s + fwd_packets_s)
    flow_bytes_s   = np.float32(random.randint(25000, 35000))
    
    return {
        "Bwd Packets/s":            bwd_packets_s,
        "Flow Bytes/s":             flow_bytes_s,
        "Flow Duration":            np.int32(flow_duration_us),
        "Flow IAT Max":             np.float32(iat_max),
        "Flow IAT Mean":            np.float32(iat_mean),
        "Flow IAT Std":             np.float32(iat_std),
        "Flow Packets/s":           flow_packets_s,
        "Fwd Act Data Packets":     np.int16(0),
        "Fwd Packet Length Max":    np.float32(0),
        "Fwd Packet Length Min":    np.float32(0),
        "Fwd Packets Length Total": np.float32(0),
        "Fwd Packets/s":            fwd_packets_s,
        "Packet Length Max":        np.float32(0),
        "Total Backward Packets":   np.int16(min(base_rate, 32767)),
        "ACK Flag Count":           '0'
    }


def send_stats(window_number, total_packets, total_flows):
    """
    Sends live traffic statistics to backend for dashboard visualization.
    Non-critical — failures are silently ignored.
    
    Args:
        window_number (int): Sequential window counter
        total_packets (int): Number of packets in this window
        total_flows (int): Number of unique IP flows
    """
    payload = {
        "window_number": window_number,
        "total_packets": total_packets,
        "total_flows":   total_flows,
        "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode":          SENSOR_MODE
    }
    
    headers = {
        "Content-Type":    "application/json",
        "X-Sensor-Secret": SENSOR_SECRET
    }
    
    try:
        requests.post(STATS_ENDPOINT, json=payload, headers=headers, timeout=2)
    except Exception:
        pass  # Non-critical, silently ignore failures


def run_simulation_loop():
    """
    Main simulation loop — generates fake network traffic for demo purposes.
    
    Behavior:
        - Every 2 seconds: Generates 3-6 benign IP flows
        - Every 90-120 seconds: Generates 1 attack flow
        - All flows are fed through the real XGBoost model
        - Results sent to backend (same as real mode)
    """
    log("Simulation engine starting...")
    log(f"  Window size    : {WINDOW_SECONDS} seconds")
    log(f"  Benign IPs     : {len(BENIGN_IPS)} in pool")
    log(f"  Attacker IPs   : {len(ATTACKER_IPS)} in pool")
    log(f"  Auto-attack    : every 90-120 seconds")
    log("  Waiting for first window...\n")

    window_number = 0
    last_attack_time = time.time()
    next_attack_in = random.randint(90, 120)

    while True:
        time.sleep(WINDOW_SECONDS)
        window_number += 1

        # Check if it's time for an auto-attack
        time_since_attack = time.time() - last_attack_time
        auto_attack_now = time_since_attack >= next_attack_in

        # Generate benign traffic
        num_benign_flows = random.randint(3, 6)
        benign_ips = random.sample(BENIGN_IPS, min(num_benign_flows, len(BENIGN_IPS)))
        total_simulated_packets = random.randint(30, 200)

        log(f"Window #{window_number:04d} | "
            f"Flows: {num_benign_flows} IPs | "
            f"Packets: {total_simulated_packets} total "
            f"{'| ⚡ AUTO-ATTACK' if auto_attack_now else ''}")

        send_stats(window_number, total_simulated_packets, num_benign_flows)

        # Process benign flows
        for ip in benign_ips:
            features = generate_benign_features()
            predict_and_alert(ip, features, ARTIFACTS)

        # Process attack flow if triggered
        if auto_attack_now:
            attacker_ip = random.choice(ATTACKER_IPS)
            log(f"  ⚡ Auto-attack triggered from {attacker_ip}", "ALERT")

            attack_features = generate_attack_features()
            
            # Send visual spike to dashboard
            send_stats(window_number, random.randint(4000, 12000), num_benign_flows + 1)
            
            predict_and_alert(attacker_ip, attack_features, ARTIFACTS)

            # Reset timer for next attack
            last_attack_time = time.time()
            next_attack_in = random.randint(90, 120)
            log(f"  Next auto-attack in {next_attack_in} seconds", "DEBUG")


# ══════════════════════════════════════════════════════════════════════════════
# REAL MODE — LIVE PACKET CAPTURE AND ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

# Global packet storage (keyed by source IP)
packet_store = defaultdict(list)


def handle_packet(packet):
    """
    Scapy callback function — processes each captured packet.
    Filters for TCP/UDP traffic involving local machine.
    Stores packet metadata in packet_store for later analysis.
    
    Args:
        packet: Scapy packet object
    """
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Only process packets involving local machine
    if src_ip != MY_IP and dst_ip != MY_IP:
        return

    if TCP not in packet and UDP not in packet:
        return

    # Determine flow direction
    if src_ip == MY_IP:
        flow_key = dst_ip
        direction = "backward"
    else:
        flow_key = src_ip
        direction = "forward"

    # Extract packet metadata
    timestamp = float(packet.time)
    pkt_length = len(packet)
    payload_len = len(packet[IP].payload)

    has_ack = False
    if TCP in packet:
        has_ack = bool(packet[TCP].flags & 0x10)

    has_data = payload_len > 0

    # Store packet for aggregation
    packet_store[flow_key].append({
        "timestamp":   timestamp,
        "length":      pkt_length,
        "payload_len": payload_len,
        "direction":   direction,
        "has_ack":     has_ack,
        "has_data":    has_data
    })


def start_sniffer():
    """
    Starts the Scapy AsyncSniffer in a background thread.
    Captures all TCP and UDP packets on the configured interface.
    
    Returns:
        AsyncSniffer: Scapy sniffer object (for stopping later)
    """
    log("Starting packet sniffer...")
    log(f"  Listening on : {INTERFACE}")
    log(f"  Filter       : TCP and UDP traffic involving {MY_IP}")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        prn=handle_packet,
        store=False
    )
    sniffer.start()
    log("  ✅ Sniffer running in background thread", "SUCCESS")
    return sniffer


def run_window_loop():
    """
    Main loop for real mode — processes captured packets every 2 seconds.
    
    Behavior:
        1. Wait WINDOW_SECONDS
        2. Snapshot current packet_store
        3. Clear packet_store for next window
        4. Extract features from each flow
        5. Run ML prediction
        6. Send alerts for threats
    """
    log("Starting 2-second window loop...")
    log(f"  Window size  : {WINDOW_SECONDS} seconds")
    log("  Waiting for packets...\n")

    window_number = 0

    while True:
        time.sleep(WINDOW_SECONDS)
        window_number += 1

        # Snapshot and clear packet store
        current_snapshot = dict(packet_store)
        packet_store.clear()

        total_flows = len(current_snapshot)
        total_packets = sum(len(pkts) for pkts in current_snapshot.values())

        log(f"Window #{window_number:04d} | "
            f"Flows: {total_flows} IPs | "
            f"Packets: {total_packets} total")
        
        send_stats(window_number, total_packets, total_flows)

        if total_flows == 0:
            log("  No traffic captured in this window — skipping", "DEBUG")
            continue

        # Process each flow
        for source_ip, packets in current_snapshot.items():
            if len(packets) < 2:
                log(f"  Skipping {source_ip} — only {len(packets)} packet", "DEBUG")
                continue

            log(f"  Processing {source_ip} — {len(packets)} packets", "DEBUG")
            
            features = calculate_features(source_ip, packets)

            if features is None:
                log(f"  Skipping {source_ip} — insufficient data", "DEBUG")
                continue

            predict_and_alert(source_ip, features, ARTIFACTS)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def calculate_features(source_ip, packets):
    """
    Extracts 15 network flow features from captured packets.
    Features match the CIC-DDoS2019 dataset format.
    
    Args:
        source_ip (str): Source IP address of the flow
        packets (list): List of packet metadata dictionaries
        
    Returns:
        dict: 15 features ready for ML model, or None if insufficient data
    """
    # Require minimum packets to avoid false positives
    if len(packets) < MIN_PACKETS:
        return None

    # Separate packets by direction
    fwd_packets = [p for p in packets if p['direction'] == 'forward']
    bwd_packets = [p for p in packets if p['direction'] == 'backward']

    all_sorted = sorted(packets, key=lambda p: p['timestamp'])
    all_timestamps = [p['timestamp'] for p in all_sorted]

    # ── Flow Duration ─────────────────────────────────────────────────────────
    flow_duration_sec = all_timestamps[-1] - all_timestamps[0]
    flow_duration_us = int(flow_duration_sec * 1_000_000)
    
    if flow_duration_sec == 0:
        flow_duration_sec = 0.000001  # Prevent division by zero

    # ── Inter-Arrival Times ───────────────────────────────────────────────────
    iats = [all_timestamps[i] - all_timestamps[i-1] 
            for i in range(1, len(all_timestamps))]
    iats_us = [iat * 1_000_000 for iat in iats]

    if len(iats_us) == 0:
        return None

    flow_iat_max = float(np.max(iats_us))
    flow_iat_mean = float(np.mean(iats_us))
    flow_iat_std = float(np.std(iats_us)) if len(iats_us) > 1 else 0.0

    # ── Packet Counts ─────────────────────────────────────────────────────────
    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)
    total_packets = len(packets)

    # ── Packets Per Second ────────────────────────────────────────────────────
    fwd_packets_per_s = total_fwd_packets / flow_duration_sec
    bwd_packets_per_s = total_bwd_packets / flow_duration_sec
    flow_packets_per_s = total_packets / flow_duration_sec

    # ── Bytes Per Second ──────────────────────────────────────────────────────
    total_bytes = sum(p['length'] for p in packets)
    flow_bytes_s = total_bytes / flow_duration_sec

    # ── Forward Packet Length Features ────────────────────────────────────────
    fwd_lengths = [p['payload_len'] for p in fwd_packets]

    if len(fwd_lengths) == 0:
        fwd_pkt_len_min = 0.0
        fwd_pkt_len_max = 0.0
        fwd_pkts_len_total = 0.0
    else:
        fwd_pkt_len_min = float(min(fwd_lengths))
        fwd_pkt_len_max = float(max(fwd_lengths))
        fwd_pkts_len_total = float(sum(fwd_lengths))

    # ── Overall Packet Length Max ─────────────────────────────────────────────
    all_lengths = [p['payload_len'] for p in packets]
    pkt_len_max = float(max(all_lengths)) if all_lengths else 0.0

    # ── Forward Active Data Packets ───────────────────────────────────────────
    fwd_act_data_packets = sum(1 for p in fwd_packets if p['has_data'])

    # ── ACK Flag Count ────────────────────────────────────────────────────────
    ack_flag_count = sum(1 for p in packets if p['has_ack'])
    ack_flag_str = '1' if ack_flag_count > 0 else '0'

    return {
        "Bwd Packets/s":            np.float32(bwd_packets_per_s),
        "Flow Bytes/s":             np.float32(flow_bytes_s),
        "Flow Duration":            np.int32(flow_duration_us),
        "Flow IAT Max":             np.float32(flow_iat_max),
        "Flow IAT Mean":            np.float32(flow_iat_mean),
        "Flow IAT Std":             np.float32(flow_iat_std),
        "Flow Packets/s":           np.float32(flow_packets_per_s),
        "Fwd Act Data Packets":     np.int16(fwd_act_data_packets),
        "Fwd Packet Length Max":    np.float32(fwd_pkt_len_max),
        "Fwd Packet Length Min":    np.float32(fwd_pkt_len_min),
        "Fwd Packets Length Total": np.float32(fwd_pkts_len_total),
        "Fwd Packets/s":            np.float32(fwd_packets_per_s),
        "Packet Length Max":        np.float32(pkt_len_max),
        "Total Backward Packets":   np.int16(total_bwd_packets),
        "ACK Flag Count":           ack_flag_str
    }


# ══════════════════════════════════════════════════════════════════════════════
# ML PREDICTION AND ALERTING
# ══════════════════════════════════════════════════════════════════════════════

def build_model_input(features, artifacts):
    """
    Transforms feature dictionary into ML model-ready DataFrame.
    Handles ACK flag encoding and column ordering.
    
    Args:
        features (dict): 15 network flow features
        artifacts (dict): ML artifacts (model, encoder, metadata)
        
    Returns:
        DataFrame: Model-ready input with correct column order
    """
    ack_value = features.pop("ACK Flag Count")
    numeric_df = pd.DataFrame([features])

    # Encode ACK flag (categorical → one-hot)
    ack_df = pd.DataFrame([[ack_value]], columns=['ACK Flag Count'])
    ack_encoded = np.array(artifacts['encoder'].transform(ack_df))
    ack_encoded_df = pd.DataFrame(
        ack_encoded,
        columns=['ACK Flag Count_0', 'ACK Flag Count_1']
    ).astype('int64')

    # Combine and reorder to match training data
    final_row = pd.concat([numeric_df, ack_encoded_df], axis=1)
    final_row = final_row[artifacts['metadata']['final_column_order']]
    return final_row


def predict_and_alert(source_ip, features, artifacts):
    """
    Runs ML inference and sends alert to backend if threat detected.
    
    Classification Logic:
        - Model predicts 0 (BENIGN) or 1 (MALICIOUS)
        - Only alert if confidence >= 80% (ALERT_THRESHOLD)
        - Anything below 80% is treated as BENIGN (reduces false positives)
    
    Args:
        source_ip (str): Source IP address
        features (dict): Extracted network features
        artifacts (dict): ML model artifacts
        
    Returns:
        tuple: (is_threat: bool, probability: float)
    """
    features_copy = features.copy()
    model_input = build_model_input(features_copy, artifacts)

    # Run prediction
    raw_prediction = int(artifacts['model'].predict(model_input)[0])
    probability = float(artifacts['model'].predict_proba(model_input)[0][1])
    
    # Apply 80% confidence threshold
    is_threat = (raw_prediction == 1) and (probability >= ALERT_THRESHOLD)
    label = "MALICIOUS" if is_threat else "BENIGN"

    # Log result
    if is_threat:
        log(f"  🚨 [{label}] {source_ip} | Confidence: {probability*100:.1f}%", "ALERT")
        send_alert(source_ip, probability, features)
    else:
        log(f"  ✅ [{label}] {source_ip} | Confidence: {probability*100:.1f}%", "DEBUG")

    return is_threat, probability


def send_alert(source_ip, probability, features):
    """
    Sends threat alert to Node.js backend via HTTP POST.
    Backend stores in MongoDB and broadcasts via Socket.io to dashboard.
    
    Args:
        source_ip (str): Attacker IP address
        probability (float): ML confidence score (0-1)
        features (dict): Network flow features
    """
    payload = {
        "source_ip":   source_ip,
        "probability": round(probability * 100, 2),
        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "threat_type": "DDoS",
        "features": {
            k: float(v) if hasattr(v, 'item') else v
            for k, v in features.items()
            if k != "ACK Flag Count"
        }
    }

    headers = {
        "Content-Type":    "application/json",
        "X-Sensor-Secret": SENSOR_SECRET
    }

    try:
        response = requests.post(ALERT_ENDPOINT, json=payload, headers=headers, timeout=3)

        if response.status_code == 201:
            data = response.json()
            log(f"  📤 Alert saved to MongoDB | ID: {data.get('id', 'unknown')}", "INFO")
        else:
            log(f"  ⚠️  Backend responded: {response.status_code}", "DEBUG")

    except requests.exceptions.ConnectionError:
        log("  ⚠️  Backend not reachable", "DEBUG")
    except Exception as e:
        log(f"  ⚠️  Alert failed: {e}", "DEBUG")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log("=" * 60)
    log(f"NIDS SENSOR — MODE: {SENSOR_MODE.upper()}")
    log("=" * 60)
    log(f"  Interface  : {INTERFACE}")
    log(f"  Local IP   : {MY_IP}")
    log(f"  Backend    : {BACKEND_URL}")
    log("=" * 60)

    # Load ML model
    ARTIFACTS = load_ml_artifacts()
    verify_model(ARTIFACTS)

    log("")
    log("=" * 60)
    log(f"STARTING {SENSOR_MODE.upper()} MODE")
    log("=" * 60)

    if SENSOR_MODE == 'real':
        # Real mode — Live packet capture
        log("Sniffing live network traffic...")
        sniffer = start_sniffer()
        try:
            run_window_loop()
        except KeyboardInterrupt:
            log("\nCtrl+C detected — stopping sniffer...", "INFO")
            sniffer.stop()
            log("Sniffer stopped cleanly", "SUCCESS")

    elif SENSOR_MODE == 'simulate':
        # Simulate mode — Fake traffic generation
        log("Generating fake traffic for demo...")
        log("Real ML model will process simulated features")
        try:
            run_simulation_loop()
        except KeyboardInterrupt:
            log("\nCtrl+C detected — stopping simulation...", "INFO")
            log("Simulation stopped cleanly", "SUCCESS")
import sys, os, time, json, random, joblib, requests, argparse, threading
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import IP, TCP, UDP, AsyncSniffer
from dotenv import load_dotenv

SENSOR_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(SENSOR_DIR, "..", "ml", "model")
ROOT_ENV   = os.path.join(SENSOR_DIR, "..", ".env")
load_dotenv(dotenv_path=ROOT_ENV)

MODEL_PATH    = os.path.join(MODEL_DIR, "nids_model.pkl")
ENCODER_PATH  = os.path.join(MODEL_DIR, "nids_encoder.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "nids_metadata.json")

parser = argparse.ArgumentParser(description='NIDS Sensor')
parser.add_argument('--mode', choices=['real', 'simulate'], default='simulate')
args = parser.parse_args()
SENSOR_MODE = args.mode

INTERFACE = os.getenv("INTERFACE")
MY_IP     = os.getenv("MY_IP")
WINDOW_SECONDS  = 2
ALERT_THRESHOLD = 0.80
MIN_PACKETS     = 10

BACKEND_URL     = os.getenv("BACKEND_URL", "http://localhost:3000")
SENSOR_SECRET   = os.getenv("SENSOR_SECRET", "default_secret")
ALERT_ENDPOINT  = f"{BACKEND_URL}/api/internal/alert"
STATS_ENDPOINT  = f"{BACKEND_URL}/api/internal/stats"
BLOCKLIST_URL   = f"{BACKEND_URL}/api/blocklist/ips"

BLOCKLIST_FETCH_INTERVAL = 30
blocked_ips = set()
last_blocklist_fetch = 0.0
packet_store = defaultdict(list)
packet_store_lock = threading.Lock()

BENIGN_IPS = ["142.250.80.46", "13.69.116.109", "140.82.114.21", "151.101.1.140", "104.21.45.231", "52.84.163.89", "192.168.31.1", "8.8.8.8"]
ATTACKER_SUBNETS = ["45.83", "185.220", "194.165", "91.108", "198.54", "103.149", "179.43", "80.67"]

def log(message, level="INFO"):
    icons = {"INFO": "ℹ️ ", "ALERT": "🚨", "ERROR": "❌", "DEBUG": "🔍", "SUCCESS": "✅"}
    print(f"[{time.strftime('%H:%M:%S')}] {icons.get(level, '  ')}  {message}")

def load_ml_artifacts():
    log("Loading ML artifacts...")
    model = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)
    with open(METADATA_PATH, 'r') as f: metadata = json.load(f)
    log(f"  ✅ Model loaded ({metadata['model_info']['accuracy_percent']}% accuracy)", "SUCCESS")
    return {'model': model, 'encoder': encoder, 'metadata': metadata}

def verify_model(artifacts):
    log("Verifying model with test input...")
    test_features = {"Bwd Packets/s": 150.5, "Flow Bytes/s": 5400.0, "Flow Duration": 200000, "Flow IAT Max": 100000.0, "Flow IAT Mean": 50000.0, "Flow IAT Std": 25000.0, "Flow Packets/s": 300.0, "Fwd Act Data Packets": 10, "Fwd Packet Length Max": 1500.0, "Fwd Packet Length Min": 40.0, "Fwd Packets Length Total": 8000.0, "Fwd Packets/s": 150.0, "Packet Length Max": 1500.0, "Total Backward Packets": 8, "ACK Flag Count": '0'}
    numeric_df = pd.DataFrame([{k: v for k, v in test_features.items() if k != "ACK Flag Count"}])
    ack_encoded = np.array(artifacts['encoder'].transform(pd.DataFrame([['0']], columns=['ACK Flag Count'])))
    final_row = pd.concat([numeric_df, pd.DataFrame(ack_encoded, columns=['ACK Flag Count_0', 'ACK Flag Count_1'])], axis=1)
    final_row = final_row[artifacts['metadata']['final_column_order']]
    log(f"  ✅ Model verified — Prediction: {'MALICIOUS' if artifacts['model'].predict(final_row)[0] == 1 else 'BENIGN'}", "SUCCESS")

def fetch_blocked_ips():
    global blocked_ips, last_blocklist_fetch
    try:
        res = requests.get(BLOCKLIST_URL, headers={"X-Sensor-Secret": SENSOR_SECRET}, timeout=5)
        if res.status_code == 200: blocked_ips = set(res.json().get("ips", []))
    except Exception: pass
    last_blocklist_fetch = time.time()

def maybe_refresh_blocklist():
    if time.time() - last_blocklist_fetch > BLOCKLIST_FETCH_INTERVAL: fetch_blocked_ips()

def get_attacker_ip():
    global blocked_ips
    if blocked_ips and random.random() < 0.25:
        return random.choice(list(blocked_ips))
        
    subnet = random.choice(ATTACKER_SUBNETS)
    return f"{subnet}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_benign_features():
    flow_duration_us = random.randint(100_000, 2_000_000)
    flow_duration_sec = flow_duration_us / 1_000_000
    total_packets = random.randint(10, 150)
    fwd_packets = random.randint(5, total_packets - 2)
    bwd_packets = total_packets - fwd_packets
    fwd_pkt_len = random.uniform(40, 1200)
    bwd_pkt_len = random.uniform(40, 800)
    iat_mean = random.uniform(5000, 200000)
    return {
        "Bwd Packets/s": np.float32(bwd_packets / flow_duration_sec), "Flow Bytes/s": np.float32((fwd_packets * fwd_pkt_len + bwd_packets * bwd_pkt_len) / flow_duration_sec),
        "Flow Duration": np.int32(flow_duration_us), "Flow IAT Max": np.float32(iat_mean * random.uniform(1.5, 8.0)),
        "Flow IAT Mean": np.float32(iat_mean), "Flow IAT Std": np.float32(iat_mean * random.uniform(0.2, 2.0)),
        "Flow Packets/s": np.float32(total_packets / flow_duration_sec), "Fwd Act Data Packets": np.int16(max(1, fwd_packets - 2)),
        "Fwd Packet Length Max": np.float32(fwd_pkt_len * 1.2), "Fwd Packet Length Min": np.float32(fwd_pkt_len * 0.3),
        "Fwd Packets Length Total": np.float32(fwd_packets * fwd_pkt_len), "Fwd Packets/s": np.float32(fwd_packets / flow_duration_sec),
        "Packet Length Max": np.float32(max(fwd_pkt_len, bwd_pkt_len)), "Total Backward Packets": np.int16(bwd_packets), "ACK Flag Count": random.choice(['0', '1'])
    }

def generate_attack_features():
    """
    Generates attack features with per-tier jitter so each alert has a
    slightly different confidence score. Distribution: LOW 40%, MEDIUM 30%,
    HIGH 20%, CRITICAL 10% — mirrors realistic attack severity ratios.
    """
    tier = random.random()

    if tier < 0.40:
        # LOW — target 81-84% — base: rate=9000, iat_mean=20
        rate     = random.randint(8500, 9500)
        iat_mean = random.uniform(15, 25)
        duration = random.randint(900_000, 1_100_000)
        return {
            "Flow Duration":            np.int32(duration),
            "Flow IAT Mean":            np.float32(iat_mean),
            "Flow IAT Max":             np.float32(iat_mean * random.uniform(8, 12)),
            "Flow IAT Std":             np.float32(iat_mean * random.uniform(0.4, 0.6)),
            "Fwd Packets/s":            np.float32(rate + random.randint(-300, 300)),
            "Bwd Packets/s":            np.float32(rate + random.randint(-300, 300)),
            "Flow Packets/s":           np.float32(rate * 2 + random.randint(-500, 500)),
            "Flow Bytes/s":             np.float32(random.randint(24000, 30000)),
            "Fwd Packet Length Max":    np.float32(0),
            "Fwd Packet Length Min":    np.float32(0),
            "Fwd Packets Length Total": np.float32(0),
            "Packet Length Max":        np.float32(0),
            "Fwd Act Data Packets":     np.int16(0),
            "Total Backward Packets":   np.int16(min(rate + random.randint(-300, 300), 32767)),
            "ACK Flag Count":           '0'
        }

    elif tier < 0.70:
        # MEDIUM — target 88-91% — base: iat_mean=200, pkt_len_max=20
        iat_mean    = random.uniform(180, 220)
        pkt_len_max = random.uniform(18, 25)
        duration    = random.randint(900_000, 1_100_000)
        iat_std     = random.uniform(50, 70)
        return {
            "Flow Duration":            np.int32(duration),
            "Flow IAT Mean":            np.float32(iat_mean),
            "Flow IAT Max":             np.float32(iat_mean * random.uniform(8, 12)),
            "Flow IAT Std":             np.float32(iat_std),
            "Fwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Bwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Flow Packets/s":           np.float32(random.randint(15000, 17000)),
            "Flow Bytes/s":             np.float32(random.randint(28000, 32000)),
            "Fwd Packet Length Max":    np.float32(0),
            "Fwd Packet Length Min":    np.float32(0),
            "Fwd Packets Length Total": np.float32(0),
            "Packet Length Max":        np.float32(pkt_len_max),
            "Fwd Act Data Packets":     np.int16(0),
            "Total Backward Packets":   np.int16(random.randint(7500, 8500)),
            "ACK Flag Count":           '0'
        }

    elif tier < 0.90:
        # HIGH — target 94-96% — base: pkt_len_max=500, iat_mean=200
        iat_mean    = random.uniform(180, 220)
        pkt_len_max = random.uniform(450, 560)
        duration    = random.randint(900_000, 1_100_000)
        return {
            "Flow Duration":            np.int32(duration),
            "Flow IAT Mean":            np.float32(iat_mean),
            "Flow IAT Max":             np.float32(iat_mean * random.uniform(8, 12)),
            "Flow IAT Std":             np.float32(random.uniform(50, 70)),
            "Fwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Bwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Flow Packets/s":           np.float32(random.randint(15000, 17000)),
            "Flow Bytes/s":             np.float32(random.randint(28000, 32000)),
            "Fwd Packet Length Max":    np.float32(0),
            "Fwd Packet Length Min":    np.float32(0),
            "Fwd Packets Length Total": np.float32(0),
            "Packet Length Max":        np.float32(pkt_len_max),
            "Fwd Act Data Packets":     np.int16(0),
            "Total Backward Packets":   np.int16(random.randint(7500, 8500)),
            "ACK Flag Count":           '0'
        }

    else:
        # CRITICAL — target 98-99% — base: ACK=1, pkt_min=40, total=100000, iat_std=0
        iat_mean = random.uniform(180, 220)
        total    = random.randint(80000, 120000)
        return {
            "Flow Duration":            np.int32(random.randint(900_000, 1_100_000)),
            "Flow IAT Mean":            np.float32(iat_mean),
            "Flow IAT Max":             np.float32(random.randint(400, 600)),
            "Flow IAT Std":             np.float32(random.uniform(0, 3)),
            "Fwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Bwd Packets/s":            np.float32(random.randint(7500, 8500)),
            "Flow Packets/s":           np.float32(random.randint(15000, 17000)),
            "Flow Bytes/s":             np.float32(random.randint(28000, 32000)),
            "Fwd Packet Length Max":    np.float32(0),
            "Fwd Packet Length Min":    np.float32(random.uniform(38, 43)),
            "Fwd Packets Length Total": np.float32(total),
            "Packet Length Max":        np.float32(0),
            "Fwd Act Data Packets":     np.int16(0),
            "Total Backward Packets":   np.int16(random.randint(7500, 8500)),
            "ACK Flag Count":           '1'
        }

def send_stats(window_number, total_packets, total_flows):
    try: requests.post(STATS_ENDPOINT, json={"window_number": window_number, "total_packets": total_packets, "total_flows": total_flows, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": SENSOR_MODE}, headers={"X-Sensor-Secret": SENSOR_SECRET}, timeout=2)
    except Exception: pass

def build_model_input(features, artifacts):
    numeric_df = pd.DataFrame([{k: v for k, v in features.items() if k != "ACK Flag Count"}])
    ack_encoded = np.array(artifacts['encoder'].transform(pd.DataFrame([[features.get("ACK Flag Count")]], columns=['ACK Flag Count'])))
    final_row = pd.concat([numeric_df, pd.DataFrame(ack_encoded, columns=['ACK Flag Count_0', 'ACK Flag Count_1']).astype('int64')], axis=1)
    return final_row[artifacts['metadata']['final_column_order']]

def predict_and_alert(source_ip, features, artifacts):
    model_input = build_model_input(features, artifacts)
    raw_prediction = int(artifacts['model'].predict(model_input)[0])
    probability = float(artifacts['model'].predict_proba(model_input)[0][1])
    is_threat = (raw_prediction == 1) and (probability >= ALERT_THRESHOLD)
    if is_threat:
        log(f"  🚨 [MALICIOUS] {source_ip} | Confidence: {probability * 100:.1f}%", "ALERT")
        try: requests.post(ALERT_ENDPOINT, json={"source_ip": source_ip, "probability": round(probability * 100, 2), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "threat_type": "DDoS", "features": {k: float(v) if hasattr(v, 'item') else v for k, v in features.items() if k != "ACK Flag Count"}}, headers={"X-Sensor-Secret": SENSOR_SECRET}, timeout=3)
        except Exception: pass
    else:
        log(f"  ✅ [BENIGN] {source_ip} | Confidence: {probability * 100:.1f}%", "DEBUG")

def run_simulation_loop():
    log("Simulation engine starting...")
    window_number = 0
    last_attack_time = time.time()
    next_attack_in = random.randint(90, 120)

    while True:
        time.sleep(WINDOW_SECONDS)
        maybe_refresh_blocklist()
        window_number += 1
        auto_attack_now = (time.time() - last_attack_time) >= next_attack_in
        num_benign_flows = random.randint(3, 6)
        benign_ips = random.sample(BENIGN_IPS, min(num_benign_flows, len(BENIGN_IPS)))
        log(f"Window #{window_number:04d} | Flows: {num_benign_flows} IPs | Packets: {random.randint(30, 200)} total {'| ⚡ AUTO-ATTACK' if auto_attack_now else ''}")
        send_stats(window_number, random.randint(30, 200), num_benign_flows)

        for ip in benign_ips: predict_and_alert(ip, generate_benign_features(), ARTIFACTS)

        if auto_attack_now:
            attacker_ip = get_attacker_ip()
            if attacker_ip in blocked_ips:
                log(f"  🛑 Auto-attack suppressed (IP blocked): {attacker_ip}", "DEBUG")
            else:
                log(f"  ⚡ Auto-attack triggered from {attacker_ip}", "ALERT")
                send_stats(window_number, random.randint(4000, 12000), num_benign_flows + 1)
                predict_and_alert(attacker_ip, generate_attack_features(), ARTIFACTS)
            
            last_attack_time = time.time()
            next_attack_in = random.randint(90, 120)

def handle_packet(packet):
    if IP not in packet: return
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    if src_ip != MY_IP and dst_ip != MY_IP: return
    if TCP not in packet and UDP not in packet: return
    flow_key = dst_ip if src_ip == MY_IP else src_ip
    with packet_store_lock:
        packet_store[flow_key].append({"timestamp": float(packet.time), "length": len(packet), "payload_len": len(packet[IP].payload), "direction": "backward" if src_ip == MY_IP else "forward", "has_ack": bool(packet[TCP].flags & 0x10) if TCP in packet else False, "has_data": len(packet[IP].payload) > 0})

def run_window_loop():
    log("Starting 2-second window loop...")
    window_number = 0
    while True:
        time.sleep(WINDOW_SECONDS)
        maybe_refresh_blocklist()
        window_number += 1
        with packet_store_lock:
            current_snapshot = dict(packet_store)
            packet_store.clear()
        total_flows, total_packets = len(current_snapshot), sum(len(pkts) for pkts in current_snapshot.values())
        log(f"Window #{window_number:04d} | Flows: {total_flows} IPs | Packets: {total_packets} total")
        send_stats(window_number, total_packets, total_flows)
        for source_ip, packets in current_snapshot.items():
            if len(packets) < MIN_PACKETS: continue
            all_sorted = sorted(packets, key=lambda p: p['timestamp'])
            flow_duration_sec = max(all_sorted[-1]['timestamp'] - all_sorted[0]['timestamp'], 0.000001)
            iats_us = [(all_sorted[i]['timestamp'] - all_sorted[i-1]['timestamp']) * 1_000_000 for i in range(1, len(all_sorted))]
            fwd_packets = [p for p in packets if p['direction'] == 'forward']
            bwd_packets = [p for p in packets if p['direction'] == 'backward']
            fwd_lengths = [p['payload_len'] for p in fwd_packets]
            features = {
                "Bwd Packets/s": np.float32(len(bwd_packets) / flow_duration_sec), "Flow Bytes/s": np.float32(sum(p['length'] for p in packets) / flow_duration_sec),
                "Flow Duration": np.int32(flow_duration_sec * 1_000_000), "Flow IAT Max": np.float32(max(iats_us)) if iats_us else 0.0,
                "Flow IAT Mean": np.float32(np.mean(iats_us)) if iats_us else 0.0, "Flow IAT Std": np.float32(np.std(iats_us)) if len(iats_us) > 1 else 0.0,
                "Flow Packets/s": np.float32(len(packets) / flow_duration_sec), "Fwd Act Data Packets": np.int16(sum(1 for p in fwd_packets if p['has_data'])),
                "Fwd Packet Length Max": np.float32(max(fwd_lengths)) if fwd_lengths else 0.0, "Fwd Packet Length Min": np.float32(min(fwd_lengths)) if fwd_lengths else 0.0,
                "Fwd Packets Length Total": np.float32(sum(fwd_lengths)), "Fwd Packets/s": np.float32(len(fwd_packets) / flow_duration_sec),
                "Packet Length Max": np.float32(max(p['payload_len'] for p in packets)), "Total Backward Packets": np.int16(len(bwd_packets)),
                "ACK Flag Count": '1' if any(p['has_ack'] for p in packets) else '0'
            }
            predict_and_alert(source_ip, features, ARTIFACTS)

if __name__ == "__main__":
    if SENSOR_MODE == 'real' and (not INTERFACE or not MY_IP):
        print("❌ ERROR: Missing INTERFACE or MY_IP in .env for real mode!")
        sys.exit(1)

    log(f"NIDS SENSOR — MODE: {SENSOR_MODE.upper()}")
    ARTIFACTS = load_ml_artifacts()
    verify_model(ARTIFACTS)

    if SENSOR_MODE == 'real':
        sniffer = AsyncSniffer(iface=INTERFACE, prn=handle_packet, store=False)
        sniffer.start()
        try: run_window_loop()
        except KeyboardInterrupt: sniffer.stop()
    else:
        try: run_simulation_loop()
        except KeyboardInterrupt: log("Simulation stopped cleanly", "SUCCESS")
"""
Purpose:
    Standalone ML inference script for manual feature input from dashboard.
    Receives 15 network features via stdin, runs XGBoost prediction, outputs JSON.

Usage:
    Called by Node.js backend via child_process.spawn()
    Input:  JSON object with 15 features (via stdin)
    Output: JSON prediction result (via stdout)
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd

# CONFIGURATION 

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(SCRIPT_DIR, "..", "ml", "model")

MODEL_PATH    = os.path.join(MODEL_DIR, "nids_model.pkl")
ENCODER_PATH  = os.path.join(MODEL_DIR, "nids_encoder.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "nids_metadata.json")

ALERT_THRESHOLD = 0.80  # Must match sensor.py threshold


# ML MODEL FUNCTIONS 

def load_artifacts():
    """
    Loads the trained XGBoost model, label encoder, and metadata.

    Returns:
        tuple: (model, encoder, metadata)

    Raises:
        FileNotFoundError: If model files are missing
    """
    model   = joblib.load(MODEL_PATH)
    encoder = joblib.load(ENCODER_PATH)

    with open(METADATA_PATH, 'r') as f:
        metadata = json.load(f)

    return model, encoder, metadata


def build_model_input(features, encoder, metadata):
    """
    Transforms feature dictionary into model-ready DataFrame.
    Handles ACK flag encoding and ensures correct column order.

    Args:
        features (dict): 15 network flow features from user input
        encoder:         Trained LabelEncoder for ACK flag
        metadata (dict): Model metadata with column order

    Returns:
        DataFrame: Single-row DataFrame ready for XGBoost prediction
    """
    ack_value = str(features.get("ACK Flag Count", "0"))

    numeric_features = {
        "Bwd Packets/s":            np.float32(features.get("Bwd Packets/s", 0)),
        "Flow Bytes/s":             np.float32(features.get("Flow Bytes/s", 0)),
        "Flow Duration":            np.int32(features.get("Flow Duration", 0)),
        "Flow IAT Max":             np.float32(features.get("Flow IAT Max", 0)),
        "Flow IAT Mean":            np.float32(features.get("Flow IAT Mean", 0)),
        "Flow IAT Std":             np.float32(features.get("Flow IAT Std", 0)),
        "Flow Packets/s":           np.float32(features.get("Flow Packets/s", 0)),
        "Fwd Act Data Packets":     np.int16(features.get("Fwd Act Data Packets", 0)),
        "Fwd Packet Length Max":    np.float32(features.get("Fwd Packet Length Max", 0)),
        "Fwd Packet Length Min":    np.float32(features.get("Fwd Packet Length Min", 0)),
        "Fwd Packets Length Total": np.float32(features.get("Fwd Packets Length Total", 0)),
        "Fwd Packets/s":            np.float32(features.get("Fwd Packets/s", 0)),
        "Packet Length Max":        np.float32(features.get("Packet Length Max", 0)),
        "Total Backward Packets":   np.int16(features.get("Total Backward Packets", 0)),
    }

    numeric_df = pd.DataFrame([numeric_features])

    ack_df      = pd.DataFrame([[ack_value]], columns=['ACK Flag Count'])
    ack_encoded = np.array(encoder.transform(ack_df))
    ack_encoded_df = pd.DataFrame(
        ack_encoded,
        columns=['ACK Flag Count_0', 'ACK Flag Count_1']
    ).astype('int64')

    final_row = pd.concat([numeric_df, ack_encoded_df], axis=1)
    final_row = final_row[metadata['final_column_order']]

    return final_row


def predict(features, model, encoder, metadata):
    """
    Runs XGBoost prediction on given features.
    Applies 80% confidence threshold for threat classification.

    Args:
        features (dict): 15 network flow features
        model: Pre-loaded XGBoost model
        encoder: Pre-loaded LabelEncoder
        metadata (dict): Pre-loaded metadata

    Returns:
        dict: Prediction result with label, probability, and threat status
    """
    model_input    = build_model_input(features, encoder, metadata)
    raw_prediction = int(model.predict(model_input)[0])
    probability    = float(model.predict_proba(model_input)[0][1])

    is_threat = (raw_prediction == 1) and (probability >= ALERT_THRESHOLD)
    label     = "MALICIOUS" if is_threat else "BENIGN"

    return {
        "prediction":        raw_prediction,
        "probability":       round(probability * 100, 2),
        "label":             label,
        "threshold_applied": ALERT_THRESHOLD * 100,
        "is_threat":         is_threat
    }


# MAIN 

def main():
    """
    Main entry point for persistent background execution.
    Loads artifacts once, then continuously reads JSON lines from stdin,
    runs prediction, and outputs JSON lines to stdout.
    """
    try:
        model, encoder, metadata = load_artifacts()
    except Exception as e:
        print(json.dumps({"error": f"Failed to load artifacts: {str(e)}"}), file=sys.stderr)
        sys.exit(1)

    # Signal to Node.js that the model is loaded and ready
    print(json.dumps({"status": "ready"}))
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            features = json.loads(line)
            result   = predict(features, model, encoder, metadata)
            print(json.dumps(result))
            sys.stdout.flush()

        except json.JSONDecodeError as e:
            print(json.dumps({
                "error": f"Invalid JSON input: {str(e)}"
            }))
            sys.stdout.flush()

        except Exception as e:
            print(json.dumps({
                "error": f"Prediction failed: {str(e)}"
            }))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
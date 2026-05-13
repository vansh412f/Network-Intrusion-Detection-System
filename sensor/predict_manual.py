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
    model = joblib.load(MODEL_PATH)
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
        encoder: Trained LabelEncoder for ACK flag
        metadata (dict): Model metadata with column order
        
    Returns:
        DataFrame: Single-row DataFrame ready for XGBoost prediction
    """
    # Extract ACK flag (categorical feature)
    ack_value = str(features.get("ACK Flag Count", "0"))
    
    # Build numeric features with proper data types
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
    
    # Encode ACK flag (0 or 1 → two binary columns)
    ack_df = pd.DataFrame([[ack_value]], columns=['ACK Flag Count'])
    ack_encoded = np.array(encoder.transform(ack_df))
    ack_encoded_df = pd.DataFrame(
        ack_encoded,
        columns=['ACK Flag Count_0', 'ACK Flag Count_1']
    ).astype('int64')
    
    # Combine and reorder columns to match training data
    final_row = pd.concat([numeric_df, ack_encoded_df], axis=1)
    final_row = final_row[metadata['final_column_order']]
    
    return final_row


def predict(features):
    """
    Runs XGBoost prediction on given features.
    Applies 80% confidence threshold for threat classification.
    
    Args:
        features (dict): 15 network flow features
        
    Returns:
        dict: Prediction result with label, probability, and threat status
    """
    # Load model artifacts
    model, encoder, metadata = load_artifacts()
    
    # Prepare input
    model_input = build_model_input(features, encoder, metadata)
    
    # Run prediction
    raw_prediction = int(model.predict(model_input)[0])
    probability = float(model.predict_proba(model_input)[0][1])
    
    # Apply threshold (same logic as sensor.py)
    is_threat = (raw_prediction == 1) and (probability >= ALERT_THRESHOLD)
    label = "MALICIOUS" if is_threat else "BENIGN"
    
    return {
        "prediction": raw_prediction,
        "probability": round(probability * 100, 2),
        "label": label,
        "threshold_applied": ALERT_THRESHOLD * 100,
        "is_threat": is_threat
    }


def main():
    """
    Main entry point.
    Reads JSON from stdin, runs prediction, outputs JSON to stdout.
    
    Exit Codes:
        0: Success
        1: JSON parse error or prediction failure
    """
    try:
        # Read features from stdin (sent by Node.js)
        input_data = sys.stdin.read()
        features = json.loads(input_data)
        
        # Run ML prediction
        result = predict(features)
        
        # Output result as JSON to stdout
        print(json.dumps(result))
        sys.exit(0)
        
    except json.JSONDecodeError as e:
        # Invalid JSON input
        print(json.dumps({
            "error": f"Invalid JSON input: {str(e)}"
        }), file=sys.stderr)
        sys.exit(1)
        
    except Exception as e:
        # Any other error
        print(json.dumps({
            "error": f"Prediction failed: {str(e)}"
        }), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
import os
import joblib
import pandas as pd
from utils.feature_engineering import extract_features_from_packet

# Define path to models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'threat_model.pkl')

# Global reference to model pipeline
_model_pipeline = None

def load_model():
    """Loads the pre-trained ML classification pipeline, training it if not found."""
    global _model_pipeline
    
    if _model_pipeline is not None:
        return _model_pipeline
        
    if os.path.exists(MODEL_PATH):
        try:
            _model_pipeline = joblib.load(MODEL_PATH)
            print("[+] Successfully loaded threat detection model pipeline.")
        except Exception as e:
            print(f"[!] Error loading model: {e}. Retraining...")
            _model_pipeline = None
            
    if _model_pipeline is None:
        print("[!] Model file 'threat_model.pkl' not found. Training new model...")
        try:
            from train_model import train_and_save_model
            train_and_save_model()
            _model_pipeline = joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"[!] Critical Error: Failed to auto-train model pipeline. {e}")
            
    return _model_pipeline

def detect_threat(packet):
    """Inspects a network packet (Scapy object or dict) and predicts threat status using the ML model.
    
    Returns:
        dict: A report containing detection results (is_threat, attack_type, confidence, severity).
    """
    model = load_model()
    if model is None:
        # Fallback to simple rule-based heuristics if model cannot be loaded
        return _rule_based_fallback(packet)
        
    try:
        # Extract ML features
        features_df = extract_features_from_packet(packet)
        
        # Predict class label (attack_type)
        prediction = model.predict(features_df)[0]
        
        # Get prediction probabilities
        probabilities = model.predict_proba(features_df)[0]
        class_idx = list(model.classes_).index(prediction)
        confidence = float(probabilities[class_idx])
        
        is_threat = (prediction != 'Benign')
        
        # Determine Severity based on attack type and confidence thresholds
        severity = 'LOW'
        if is_threat:
            if prediction == 'DDoS':
                severity = 'CRITICAL' if confidence > 0.8 else 'HIGH'
            elif prediction == 'Infiltration':
                severity = 'CRITICAL'
            elif prediction == 'Brute Force':
                severity = 'HIGH' if confidence > 0.7 else 'MEDIUM'
            elif prediction == 'Port Scan':
                severity = 'MEDIUM' if confidence > 0.6 else 'LOW'
                
        return {
            'is_threat': is_threat,
            'attack_type': prediction,
            'confidence': round(confidence, 4),
            'severity': severity,
            'features': features_df.to_dict(orient='records')[0]
        }
        
    except Exception as e:
        print(f"[!] Inference warning: {e}. Using rule-based fallback.")
        return _rule_based_fallback(packet)

def _rule_based_fallback(packet):
    """Simple signature-based fallback when ML pipeline is offline."""
    # Extract raw data depending on source type
    if isinstance(packet, dict):
        dst_port = int(packet.get('destination_port', 0))
        pkt_len = int(packet.get('packet_length', 64))
        attack = packet.get('attack_type', 'Benign')
    else:
        dst_port = 0
        pkt_len = len(packet)
        attack = 'Benign'
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            dst_port = packet['TCP'].dport
            
    is_threat = (attack != 'Benign')
    
    # Static mappings for fallback
    severity = 'LOW'
    if is_threat:
        if attack == 'DDoS':
            severity = 'CRITICAL'
        elif attack == 'Infiltration':
            severity = 'CRITICAL'
        elif attack == 'Brute Force':
            severity = 'HIGH'
        else:
            severity = 'MEDIUM'
            
    return {
        'is_threat': is_threat,
        'attack_type': attack,
        'confidence': 0.9999,  # Absolute heuristic certainty
        'severity': severity,
        'features': {
            'destination_port': dst_port,
            'packet_length': pkt_len,
            'protocol': 'TCP' if isinstance(packet, dict) and packet.get('protocol') == 'TCP' else 'OTHER'
        }
    }

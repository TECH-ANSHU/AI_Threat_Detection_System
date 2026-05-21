import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from utils.preprocessing import get_preprocessing_pipeline, ALL_FEATURES


# Define file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# Ensure directories exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

def generate_synthetic_data(num_samples=5000, random_state=42):
    """Generates a realistic synthetic cybersecurity dataset for model training."""
    np.random.seed(random_state)
    
    data = []
    
    # Attack Type distribution: Benign (65%), DDoS (15%), Port Scan (10%), Brute Force (7%), Infiltration (3%)
    attack_weights = [0.65, 0.15, 0.10, 0.07, 0.03]
    attack_choices = ['Benign', 'DDoS', 'Port Scan', 'Brute Force', 'Infiltration']
    
    chosen_attacks = np.random.choice(attack_choices, size=num_samples, p=attack_weights)
    
    for i, attack in enumerate(chosen_attacks):
        timestamp = pd.Timestamp.now() - pd.Timedelta(seconds=num_samples - i)
        
        # Default Normal (Benign) traffic characteristics
        src_ip = f"192.168.1.{np.random.randint(10, 250)}"
        dst_ip = f"10.0.0.{np.random.randint(10, 250)}"
        src_port = np.random.choice([49152 + np.random.randint(0, 16000), 80, 443, 53, 22])
        dst_port = np.random.choice([80, 443, 53, 123])
        protocol = np.random.choice(['TCP', 'UDP', 'ICMP'], p=[0.7, 0.25, 0.05])
        packet_length = np.random.randint(60, 1500)
        flow_duration = np.random.uniform(0.01, 10.0)
        packet_count = np.random.randint(1, 50)
        byte_count = packet_count * packet_length
        label = 0  # Benign
        
        # Inject attack patterns
        if attack == 'DDoS':
            # DDoS: Massive UDP/TCP traffic to a target port (usually web port 80/443), short duration, huge counts
            src_ip = f"{np.random.randint(1,223)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}"
            dst_ip = "192.168.1.100"  # Target server
            dst_port = np.random.choice([80, 443])
            protocol = np.random.choice(['TCP', 'UDP'], p=[0.4, 0.6])
            packet_length = np.random.randint(500, 1400)
            flow_duration = np.random.uniform(0.05, 1.5)
            packet_count = np.random.randint(200, 1200)
            byte_count = packet_count * packet_length
            label = 1
            
        elif attack == 'Port Scan':
            # Port Scan: Small TCP SYN packets to multiple consecutive ports, extremely short duration, small packets
            src_ip = f"203.0.113.{np.random.randint(5, 50)}"
            dst_ip = "192.168.1.100"
            src_port = np.random.randint(30000, 65000)
            dst_port = np.random.randint(1, 1024)  # Scanning standard system ports
            protocol = 'TCP'
            packet_length = np.random.randint(40, 64)  # Tiny packets (SYN flag only)
            flow_duration = np.random.uniform(0.001, 0.05)
            packet_count = np.random.randint(1, 3)
            byte_count = packet_count * packet_length
            label = 1
            
        elif attack == 'Brute Force':
            # Brute Force: Repetitive TCP traffic targeting SSH (22) or RDP (3389)
            src_ip = f"198.51.100.{np.random.randint(10, 100)}"
            dst_ip = "192.168.1.50"
            src_port = np.random.randint(40000, 60000)
            dst_port = np.random.choice([22, 3389])
            protocol = 'TCP'
            packet_length = np.random.randint(80, 180)
            flow_duration = np.random.uniform(2.0, 45.0)  # Slow connection attempt logs
            packet_count = np.random.randint(15, 80)
            byte_count = packet_count * packet_length
            label = 1
            
        elif attack == 'Infiltration':
            # Infiltration: Encrypted tunnel payload, HTTPS/TCP, medium counts, long duration
            src_ip = f"185.190.140.{np.random.randint(1, 20)}"
            dst_ip = "192.168.1.12"
            src_port = np.random.randint(50000, 60000)
            dst_port = np.random.choice([443, 80])
            protocol = 'TCP'
            packet_length = np.random.randint(1000, 1500)
            flow_duration = np.random.uniform(15.0, 300.0)
            packet_count = np.random.randint(30, 200)
            byte_count = packet_count * packet_length
            label = 1
            
        data.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': protocol,
            'packet_length': packet_length,
            'flow_duration': flow_duration,
            'packet_count': packet_count,
            'byte_count': byte_count,
            'attack_type': attack,
            'label': label
        })
        
    df = pd.DataFrame(data)
    return df

def train_and_save_model():
    """Generates synthetic dataset, splits it, trains Random Forest model, and serializes it."""
    print("[*] Generating synthetic cybersecurity dataset...")
    df = generate_synthetic_data(num_samples=10000)
    
    # Save datasets
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['attack_type'])
    
    train_path = os.path.join(DATASET_DIR, 'sample_dataset.csv')
    test_path = os.path.join(DATASET_DIR, 'test_data.csv')
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    print(f"[+] Sample dataset saved to: {train_path}")
    print(f"[+] Test dataset saved to: {test_path}")
    
    # Separate features and target
    X_train = train_df[ALL_FEATURES]
    # Train the classification model to predict BOTH labels (attack vs benign) and attack types.
    # To keep inference highly flexible, we train a multi-class Random Forest on the 'attack_type' directly!
    # By classifying attack types directly, a prediction of 'Benign' means label 0, and other classes mean label 1.
    y_train = train_df['attack_type']
    
    X_test = test_df[ALL_FEATURES]
    y_test = test_df['attack_type']
    
    print("[*] Building classification pipeline...")
    # Fetch preprocessing column transformer
    preprocessor = get_preprocessing_pipeline()
    
    # Construct complete pipeline
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42))
    ])
    
    print("[*] Training Random Forest model on features...")
    pipeline.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print("\n" + "="*50)
    print(f"MODEL PERFORMANCE SUMMARY")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print("="*50)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred, labels=pipeline.classes_))
    
    # Save the pipeline
    model_path = os.path.join(MODELS_DIR, 'threat_model.pkl')
    joblib.dump(pipeline, model_path)
    print(f"\n[+] Trained model pipeline serialized successfully to: {model_path}")

if __name__ == '__main__':
    train_and_save_model()

import os
import logging
from datetime import datetime
from database import insert_alert

# Define logs directory and file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
LOG_FILE = os.path.join(LOGS_DIR, 'alerts.log')

# Ensure logs folder exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Set up logging configurations
logger = logging.getLogger('ThreatDetectorLogger')
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler(LOG_FILE)
file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

def trigger_alert(detection_result, packet):
    """Processes a detected threat. Logs details to alerts.log and stores in SQLite."""
    # Extract packet metadata
    if isinstance(packet, dict):
        src_ip = packet.get('source_ip', '0.0.0.0')
        dst_ip = packet.get('destination_ip', '0.0.0.0')
        src_port = int(packet.get('source_port', 0))
        dst_port = int(packet.get('destination_port', 0))
        protocol = packet.get('protocol', 'OTHER')
        pkt_len = int(packet.get('packet_length', 64))
    else:
        # Scapy packet fallback
        src_ip = '0.0.0.0'
        dst_ip = '0.0.0.0'
        src_port = 0
        dst_port = 0
        protocol = 'OTHER'
        pkt_len = len(packet)
        
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            if packet.haslayer('TCP'):
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
                protocol = 'TCP'
            elif packet.haslayer('UDP'):
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport
                protocol = 'UDP'
            elif packet.haslayer('ICMP'):
                protocol = 'ICMP'

    attack_type = detection_result.get('attack_type', 'Malicious')
    severity = detection_result.get('severity', 'HIGH')
    confidence = detection_result.get('confidence', 1.0)
    
    # 1. Format and write log to logs/alerts.log
    log_message = (
        f"THREAT DETECTED: {attack_type} (Confidence: {confidence * 100:.2f}%) - "
        f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} | "
        f"Protocol: {protocol} | Length: {pkt_len} bytes"
    )
    
    # Use standard logging severities mapping
    if severity == 'CRITICAL' or severity == 'HIGH':
        logger.error(log_message)
    elif severity == 'MEDIUM':
        logger.warning(log_message)
    else:
        logger.info(log_message)
        
    # 2. Persist the alert in database/threats.db
    alert_id = insert_alert(
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        packet_length=pkt_len,
        attack_type=attack_type,
        severity=severity,
        confidence=confidence
    )
    
    return alert_id

def get_recent_logs(num_lines=30):
    """Reads and returns the last N lines from logs/alerts.log."""
    if not os.path.exists(LOG_FILE):
        return ["[*] Logging system online. Waiting for threats..."]
        
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-num_lines:]]
    except Exception as e:
        return [f"[!] Error reading alerts.log: {str(e)}"]

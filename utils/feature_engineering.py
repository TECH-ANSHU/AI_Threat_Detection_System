import time
from collections import defaultdict
import pandas as pd

class FlowTracker:
    """Tracks active connections (flows) to calculate stateful network features."""
    def __init__(self, timeout=60):
        self.flows = {}  # (src_ip, dst_ip, proto) -> Flow data
        self.timeout = timeout

    def update_and_extract(self, packet):
        """Updates flow state with the new packet and returns extracted features.
        
        Supports both raw Scapy packets and simulated packets (represented as dicts).
        """
        current_time = time.time()
        
        # 1. Parse packet properties depending on source (Scapy vs Simulated Dict)
        if isinstance(packet, dict):
            src_ip = packet.get('source_ip', '0.0.0.0')
            dst_ip = packet.get('destination_ip', '0.0.0.0')
            proto = packet.get('protocol', 'OTHER').upper()
            src_port = int(packet.get('source_port', 0))
            dst_port = int(packet.get('destination_port', 0))
            pkt_len = int(packet.get('packet_length', 64))
        else:
            # Scapy packet parsing
            src_ip = '0.0.0.0'
            dst_ip = '0.0.0.0'
            proto = 'OTHER'
            src_port = 0
            dst_port = 0
            pkt_len = len(packet)
            
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                if packet.haslayer('TCP'):
                    proto = 'TCP'
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                elif packet.haslayer('UDP'):
                    proto = 'UDP'
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                elif packet.haslayer('ICMP'):
                    proto = 'ICMP'
            
        flow_key = (src_ip, dst_ip, proto)
        
        # 2. Maintain flow features
        # If flow does not exist or has timed out, initialize it
        if flow_key not in self.flows or (current_time - self.flows[flow_key]['last_time'] > self.timeout):
            self.flows[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'packet_count': 1,
                'byte_count': pkt_len
            }
        else:
            # Update flow stats
            self.flows[flow_key]['last_time'] = current_time
            self.flows[flow_key]['packet_count'] += 1
            self.flows[flow_key]['byte_count'] += pkt_len
            
        flow = self.flows[flow_key]
        flow_duration = max(0.001, flow['last_time'] - flow['start_time'])
        
        # 3. Format features for the ML model
        features = {
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': proto,
            'packet_length': pkt_len,
            'flow_duration': flow_duration,
            'packet_count': flow['packet_count'],
            'byte_count': flow['byte_count']
        }
        
        return features

    def clean_expired_flows(self):
        """Clears flows that have not seen packets for longer than the timeout period."""
        current_time = time.time()
        expired = [k for k, v in self.flows.items() if current_time - v['last_time'] > self.timeout]
        for k in expired:
            del self.flows[k]

# Global tracker instance
flow_tracker = FlowTracker()

def extract_features_from_packet(packet) -> pd.DataFrame:
    """Takes a network packet (Scapy object or dict) and returns a preprocessed features DataFrame.
    
    The resulting DataFrame is ready to be sent to the trained model pipeline.
    """
    raw_features = flow_tracker.update_and_extract(packet)
    # Convert single record to DataFrame (single row)
    df = pd.DataFrame([raw_features])
    return df

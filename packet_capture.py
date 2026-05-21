import time
import random
import threading
from scapy.all import sniff
from utils.helper import generate_random_ip, get_local_ip

# Global variables for controlling the background capture thread
_sniffer_thread = None
_stop_signal = threading.Event()
_is_simulating = False
_packet_rate = 1.0  # Packets per second
_force_attack_type = None  # Threat injection control
_packet_buffer = []  # Store last 50 packets (benign and malicious)
_buffer_limit = 50

# Lock for thread safety
_control_lock = threading.Lock()
_buffer_lock = threading.Lock()


def simulate_packet(force_attack=None):
    """Generates a realistic simulated network packet as a dictionary.
    
    Can force specific attack types (DDoS, Port Scan, Brute Force, Infiltration).
    """
    local_ip = get_local_ip()
    
    # Select attack type
    attack = 'Benign'
    if force_attack:
        attack = force_attack
    elif random.random() < 0.15:  # 15% chance of background attacks
        attack = random.choice(['DDoS', 'Port Scan', 'Brute Force', 'Infiltration'])
        
    # Generate packet values based on selected attack type
    if attack == 'Benign':
        src_ip = generate_random_ip()
        dst_ip = local_ip
        src_port = random.choice([80, 443, 53, 123, 22] + [random.randint(49152, 65535)])
        dst_port = random.choice([80, 443, 53, 22])
        protocol = random.choice(['TCP', 'UDP', 'ICMP'], p=[0.75, 0.20, 0.05])
        packet_length = random.randint(60, 1500)
        
    elif attack == 'DDoS':
        # DDoS: Consistent target IP, high-volume source IPs, TCP/UDP
        src_ip = generate_random_ip()
        dst_ip = local_ip
        src_port = random.randint(40000, 65000)
        dst_port = 80  # Target Web Server
        protocol = random.choice(['TCP', 'UDP'])
        packet_length = random.randint(800, 1400)
        
    elif attack == 'Port Scan':
        # Port Scan: Same source IP scanning sequential destination ports
        src_ip = "192.168.1.251"  # Simulated attacker on subnet
        dst_ip = local_ip
        src_port = random.randint(45000, 60000)
        dst_port = random.choice([21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080])
        protocol = 'TCP'
        packet_length = 40  # Small TCP SYN packet
        
    elif attack == 'Brute Force':
        # Brute Force: Targeted SSH/RDP connection attempts
        src_ip = "203.0.113.14"  # Simulated external attacker
        dst_ip = local_ip
        src_port = random.randint(49000, 52000)
        dst_port = random.choice([22, 3389])  # SSH or RDP
        protocol = 'TCP'
        packet_length = random.randint(80, 200)
        
    elif attack == 'Infiltration':
        # Infiltration: Compromised internal host communicating to C2
        src_ip = local_ip
        dst_ip = "185.190.140.8"  # External Command & Control
        src_port = random.randint(55000, 58000)
        dst_port = 443  # Encrypted outbound channel
        protocol = 'TCP'
        packet_length = random.randint(1000, 1500)
        
    return {
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'source_port': src_port,
        'destination_port': dst_port,
        'protocol': protocol,
        'packet_length': packet_length,
        'attack_type': attack  # Included in dict for reporting
    }

def _add_to_buffer(packet):
    """Safely adds a packet dictionary to the rolling queue."""
    global _packet_buffer
    
    if not isinstance(packet, dict):
        # Parse Scapy packet to dictionary format
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
                
        packet_dict = {
            'timestamp': time.strftime('%H:%M:%S'),
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': protocol,
            'packet_length': pkt_len,
            'attack_type': 'Analyzing...',
            'severity': 'LOW',
            'is_threat': False
        }
    else:
        packet_dict = packet.copy()
        if 'timestamp' not in packet_dict:
            packet_dict['timestamp'] = time.strftime('%H:%M:%S')
        if 'severity' not in packet_dict:
            packet_dict['severity'] = 'LOW'
        if 'is_threat' not in packet_dict:
            packet_dict['is_threat'] = False

    with _buffer_lock:
        _packet_buffer.append(packet_dict)
        if len(_packet_buffer) > _buffer_limit:
            _packet_buffer.pop(0)
            
    return packet_dict

def _capture_loop(callback):
    """Background execution loop trying live capture, falling back to simulation."""
    global _is_simulating, _force_attack_type
    
    print("[*] Threat Detection sniffer loop started.")
    
    # Try starting live scapy sniffer
    live_sniffing_successful = False
    
    # Define packet callback for Scapy
    def scapy_callback(pkt):
        if _stop_signal.is_set():
            raise SystemExit()
        # Convert, save to buffer, and trigger callback
        pkt_dict = _add_to_buffer(pkt)
        callback(pkt_dict)
        
    try:
        # Check if we have sniffing capability
        sniff(count=1, timeout=1.0, store=0)
        live_sniffing_successful = True
    except Exception as e:
        print(f"[!] Live sniffing not available ({str(e)}). Falling back to Simulation Mode.")
        
    if live_sniffing_successful:
        _is_simulating = False
        print("[+] Sniffer running in LIVE network mode.")
        while not _stop_signal.is_set():
            try:
                sniff(prn=scapy_callback, count=5, timeout=1.0, store=0)
            except Exception as e:
                print(f"[!] Live packet error: {e}. Switching to simulation.")
                live_sniffing_successful = False
                break
                
    # Fallback simulation loop
    if not live_sniffing_successful:
        _is_simulating = True
        print("[+] Sniffer running in SIMULATION mode.")
        while not _stop_signal.is_set():
            # Respect dynamic rate limits
            sleep_dur = 1.0 / max(0.1, _packet_rate)
            time.sleep(sleep_dur)
            
            # Fetch and reset forced attack status under lock
            with _control_lock:
                current_attack = _force_attack_type
                _force_attack_type = None  # Consume single-burst injection
                
            packet = simulate_packet(force_attack=current_attack)
            pkt_dict = _add_to_buffer(packet)
            callback(pkt_dict)
            
    print("[*] Threat Detection sniffer loop terminated.")

def start_capture(callback, rate=1.0):
    """Starts the packet capture thread if not already running."""
    global _sniffer_thread, _stop_signal, _packet_rate
    
    with _control_lock:
        _packet_rate = rate
        if _sniffer_thread is not None and _sniffer_thread.is_alive():
            print("[*] Sniffer is already running.")
            return False
            
        _stop_signal.clear()
        _sniffer_thread = threading.Thread(
            target=_capture_loop, 
            args=(callback,), 
            name="CyberSnifferThread",
            daemon=True
        )
        _sniffer_thread.start()
        return True

def stop_capture():
    """Stops the active background capture thread."""
    global _sniffer_thread
    
    with _control_lock:
        if _sniffer_thread is None or not _sniffer_thread.is_alive():
            return False
            
        _stop_signal.set()
        _sniffer_thread = None
        return True

def is_running():
    """Returns True if the background sniffer is active."""
    return _sniffer_thread is not None and _sniffer_thread.is_alive()

def is_simulation_mode():
    """Returns True if the sniffer is running in simulated fallback mode."""
    return _is_simulating

def inject_attack(attack_type):
    """Triggers a forced attack packet injection in the simulation loop."""
    global _force_attack_type
    with _control_lock:
        if attack_type in ['DDoS', 'Port Scan', 'Brute Force', 'Infiltration']:
            _force_attack_type = attack_type
            print(f"[+] Attack vector '{attack_type}' scheduled for injection.")
            return True
        return False

def set_packet_rate(rate):
    """Updates the packet rate for the simulation loop."""
    global _packet_rate
    with _control_lock:
        _packet_rate = max(0.1, rate)

def get_recent_packets(limit=50):
    """Thread-safe retrieval of recent packets from buffer."""
    with _buffer_lock:
        return list(_packet_buffer[-limit:])

def clear_packet_buffer():
    """Resets the rolling packet queue."""
    global _packet_buffer
    with _buffer_lock:
        _packet_buffer.clear()


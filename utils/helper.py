import socket
import random

# Common port mapping for display
PORT_MAP = {
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet',
    25: 'SMTP (Mail)',
    53: 'DNS (Domain Name System)',
    80: 'HTTP (Web)',
    110: 'POP3 (Mail)',
    123: 'NTP (Time)',
    143: 'IMAP (Mail)',
    443: 'HTTPS (Secure Web)',
    445: 'SMB (File Share)',
    1433: 'MSSQL (Database)',
    3306: 'MySQL (Database)',
    3389: 'RDP (Remote Desktop)',
    8080: 'HTTP-Proxy'
}

def resolve_port(port: int) -> str:
    """Returns a readable service name for a given port, or 'Unknown'."""
    return PORT_MAP.get(port, f"Service ({port})")

def get_local_ip() -> str:
    """Attempts to find the local IP address of the machine."""
    try:
        # Create a dummy socket to find active IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def generate_random_ip() -> str:
    """Generates a random public/private looking IP address."""
    # Mix private and public IP styles
    if random.random() < 0.3:
        # Private IPs (internal subnet)
        subnet = random.choice([10, 192])
        if subnet == 10:
            return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        # Public IPs
        return f"{random.randint(24, 223)}.{random.randint(10, 240)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def get_severity_color(severity: str) -> str:
    """Returns HSL/Hex color codes for threat severities."""
    severity = severity.upper()
    if severity == 'CRITICAL':
        return '#FF3B30'  # Bright Red
    elif severity == 'HIGH':
        return '#FF9500'  # Orange
    elif severity == 'MEDIUM':
        return '#FFCC00'  # Yellow
    elif severity == 'LOW':
        return '#34C759'  # Green
    return '#8E8E93'      # Grey

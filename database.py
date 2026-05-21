import os
import sqlite3
from datetime import datetime

# Define database file path
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DB_PATH = os.path.join(DB_DIR, 'threats.db')

def get_db_connection():
    """Establishes a connection to the SQLite database and returns the connection object."""
    # Ensure directory exists
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Returns rows that can be accessed like dictionaries
    return conn

def init_db():
    """Initializes the database structure by creating required tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create threat_alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            packet_length INTEGER,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT DEFAULT 'Active',
            analyst_notes TEXT DEFAULT ''
        )
    ''')
    
    conn.commit()
    conn.close()

def insert_alert(source_ip, destination_ip, source_port, destination_port, protocol, packet_length, attack_type, severity, confidence):
    """Inserts a new threat alert into the database. Returns the inserted row ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO threat_alerts (
            timestamp, source_ip, destination_ip, source_port, destination_port, 
            protocol, packet_length, attack_type, severity, confidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        timestamp, source_ip, destination_ip, source_port, destination_port,
        protocol, packet_length, attack_type, severity, confidence
    ))
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_all_alerts(limit=100, filter_severity=None, filter_status=None, search_ip=None):
    """Retrieves threat alerts based on search filters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM threat_alerts WHERE 1=1"
    params = []
    
    if filter_severity and filter_severity != 'All':
        query += " AND severity = ?"
        params.append(filter_severity)
        
    if filter_status and filter_status != 'All':
        query += " AND status = ?"
        params.append(filter_status)
        
    if search_ip:
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ?)"
        params.append(f"%{search_ip}%")
        params.append(f"%{search_ip}%")
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    # Convert sqlite3.Row to regular dicts
    return [dict(row) for row in rows]

def update_alert_status(alert_id, status, analyst_notes):
    """Updates the status and analyst notes for a specific alert."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE threat_alerts
        SET status = ?, analyst_notes = ?
        WHERE id = ?
    ''', (status, analyst_notes, alert_id))
    
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success

def get_alert_statistics():
    """Gathers high-level statistics for dashboard widgets."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    stats = {}
    
    # Total alerts count
    cursor.execute("SELECT COUNT(*) FROM threat_alerts")
    stats['total_alerts'] = cursor.fetchone()[0]
    
    # Count by severity
    cursor.execute("SELECT severity, COUNT(*) FROM threat_alerts GROUP BY severity")
    stats['severity_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Count by status
    cursor.execute("SELECT status, COUNT(*) FROM threat_alerts GROUP BY status")
    stats['status_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Count by attack type
    cursor.execute("SELECT attack_type, COUNT(*) FROM threat_alerts GROUP BY attack_type")
    stats['attack_type_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
    
    conn.close()
    return stats

def clear_database():
    """Clears all records in the threat_alerts table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM threat_alerts")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Initialize the database structure if run directly
    init_db()
    print("Database initialized successfully at:", DB_PATH)

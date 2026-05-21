# Database Directory (`database/`)

## Purpose
This directory stores the SQLite database files used by the AI-Driven Threat Detection System to log and track security events, alerts, and analyst workflow states. It acts as the local storage layer of the Security Operations Center (SOC) platform.

## Files Inside
- **`threats.db`**: The SQLite database file. It stores threat logs including packet details (source IP, destination IP, ports, protocol), predicted attack type, classifier confidence level, alert severity, analyst notes, and ticket status (e.g. Active, Investigating, Resolved).

## Schema Details
The primary table is `threat_alerts`:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT): Unique identifier for each alert.
- `timestamp` (TEXT): Date and time the alert was logged.
- `source_ip` (TEXT): Originating IP address of the traffic.
- `destination_ip` (TEXT): Target IP address of the traffic.
- `source_port` (INTEGER): Port where the traffic originated.
- `destination_port` (INTEGER): Target port of the traffic.
- `protocol` (TEXT): Layer 4 network protocol (e.g. TCP, UDP, ICMP).
- `packet_length` (INTEGER): Size of the network packet in bytes.
- `attack_type` (TEXT): Classification from the ML model (e.g., Benign, DDoS, Port Scan, Brute Force, Infiltration).
- `severity` (TEXT): Priority rating (Low, Medium, High, Critical).
- `confidence` (REAL): Prediction confidence score of the Random Forest model (ranging from 0.0 to 1.0).
- `status` (TEXT): Ticket status (Active, Investigating, Resolved) to support simulated analyst ticketing.
- `analyst_notes` (TEXT): Contextual notes added by the security analyst investigating the event.

## System Interaction
1. **Writing Alerts**: The `alert_system.py` module uses `database.py` to insert alerts into `database/threats.db` in real-time when the detection engine identifies a malicious packet.
2. **Dashboard Querying**: The Streamlit application (`app.py`) reads from `threats.db` to render charts, statistics cards, and the alert log tables.
3. **Analyst Workflow**: When the analyst updates an alert's status or notes in the dashboard, the changes are persisted back to `threats.db` via `database.py`.

## Future Upgrades
- Migrate from SQLite to PostgreSQL or Elasticsearch to handle high-throughput production-level traffic logs.
- Add indexes to `source_ip`, `timestamp`, and `status` to optimize search performance for millions of logs.
- Implement data archiving or automatic rotation policies for old alerts.

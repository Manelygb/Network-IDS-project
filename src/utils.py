import os
import time
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Tuple
import config

def wait_for_log_file(log_path: str, timeout: int = 60) -> bool:
    """Wait for the log file to be created."""
    start_time = time.time()
    while not os.path.exists(log_path):
        if time.time() - start_time > timeout:
            print(f"Error: Log file {log_path} not found after {timeout} seconds")
            return False
        print(f"Waiting for log file {log_path} to be created...")
        time.sleep(1)
    return True

def is_valid_line(line: str) -> bool:
    """Check if a log line is valid."""
    # Line doesn't start with # and is not empty
    if not line.strip() or line.startswith("#"):
        return False
    return True

def has_valid_field_count(line: str) -> bool:
    """Check if a log line has the expected number of fields."""
    fields = line.strip().split("\t")
    return len(fields) == len(config.COLUMNS)

def extract_source_ip(line: str) -> str:
    """Extract the source IP address from a log line."""
    fields = line.strip().split("\t")
    if len(fields) >= 3:
        return fields[2]  # index 2 corresponds to id.orig_h (source IP)
    return ""

def format_timestamp(ts_str: str) -> str:
    """Format a timestamp string from Zeek logs."""
    try:
        timestamp = datetime.fromtimestamp(float(ts_str))
        return timestamp.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return "Unknown time"

def log_detection(attack_type: str, flow_data: Dict[str, Any]) -> None:
    """Log a detection event to the database."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # Create detections table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            attack_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            orig_bytes INTEGER,
            resp_bytes INTEGER,
            orig_pkts INTEGER,
            resp_pkts INTEGER,
            duration REAL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Extract necessary fields
        source_ip = flow_data.get("source_ip", "")
        uid = flow_data.get("uid", "")
        timestamp = flow_data.get("timestamp", 0)
        orig_bytes = flow_data.get("orig_bytes", 0)
        resp_bytes = flow_data.get("resp_bytes", 0)
        orig_pkts = flow_data.get("orig_pkts", 0)
        resp_pkts = flow_data.get("resp_pkts", 0)
        duration = flow_data.get("duration", 0)
        
        # Extract other fields if present in the original log
        dest_ip = flow_data.get("id.resp_h", "")
        source_port = flow_data.get("id.orig_p", 0)
        dest_port = flow_data.get("id.resp_p", 0)
        protocol = flow_data.get("proto", "")
        
        # Insert the detection record
        cursor.execute('''
        INSERT INTO detections (
            timestamp, attack_type, source_ip, destination_ip, source_port, 
            destination_port, protocol, orig_bytes, resp_bytes, orig_pkts, 
            resp_pkts, duration
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, attack_type, source_ip, dest_ip, source_port,
            dest_port, protocol, orig_bytes, resp_bytes, orig_pkts,
            resp_pkts, duration
        ))
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error when logging detection: {e}")

def get_recent_detections(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recent detection events from the database."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT * FROM detections 
        ORDER BY detected_at DESC 
        LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        
        detections = []
        for row in rows:
            detection = {column: row[column] for column in row.keys()}
            # Format the timestamp for display
            if 'timestamp' in detection and detection['timestamp']:
                detection['formatted_time'] = format_timestamp(str(detection['timestamp']))
            detections.append(detection)
        
        conn.close()
        return detections
    except sqlite3.Error as e:
        print(f"Database error when getting detections: {e}")
        return []

def get_attack_statistics() -> Dict[str, int]:
    """Get statistics about attack types from the database."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT attack_type, COUNT(*) as count 
        FROM detections 
        GROUP BY attack_type
        ''')
        
        rows = cursor.fetchall()
        
        stats = {}
        for row in rows:
            attack_type, count = row
            stats[attack_type] = count
        
        conn.close()
        return stats
    except sqlite3.Error as e:
        print(f"Database error when getting statistics: {e}")
        return {}

def get_top_attacker_ips(limit: int = 10) -> List[Tuple[str, int]]:
    """Get the top source IPs associated with attacks."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT source_ip, COUNT(*) as count 
        FROM detections 
        WHERE attack_type != 'Benign' 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        
        top_ips = [(row[0], row[1]) for row in rows]
        
        conn.close()
        return top_ips
    except sqlite3.Error as e:
        print(f"Database error when getting top attackers: {e}")
        return []
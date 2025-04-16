import os
import sqlite3
import random
import pickle
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier

# Make sure the required directories exist
os.makedirs('models', exist_ok=True) 
os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Define paths (similar to what would be in config.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATABASE_PATH = os.path.join(DATA_DIR, "detections.db")
MODEL_PATH = os.path.join(MODELS_DIR, "wpa2_key_cracking_model_no_protocol.pkl")

# Attack types
ATTACK_TYPES = ["Benign", "DoS", "PortScan", "DDoS", "BruteForce", "WebAttack"]

def create_dummy_model():
    """Create a simple dummy model for testing purposes."""
    print("Creating a dummy classification model...")
    
    # Create a simple random forest classifier
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    
    # Generate some dummy training data
    # Features: duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes
    X_train = np.random.rand(1000, 7)
    
    # Generate labels with some patterns
    # High bytes and packets -> likely DoS or DDoS
    # Many small packets -> likely PortScan
    # etc.
    y_train = []
    for i in range(1000):
        # Just make up some classification rules to simulate a real model
        if X_train[i, 1] > 0.8 and X_train[i, 3] > 0.8:  # High orig_bytes and orig_pkts
            y_train.append(random.choices([0, 1, 3], weights=[0.1, 0.5, 0.4], k=1)[0])  # Mostly DoS or DDoS
        elif X_train[i, 3] > 0.7 and X_train[i, 0] < 0.3:  # Many packets, short duration
            y_train.append(2)  # PortScan
        elif 0.4 < X_train[i, 1] < 0.6 and X_train[i, 3] > 0.5:  # Medium bytes, high packets
            y_train.append(4)  # BruteForce
        elif X_train[i, 0] < 0.2 and X_train[i, 2] > 0.7:  # Short duration, high response bytes
            y_train.append(5)  # WebAttack
        else:
            y_train.append(0)  # Benign
    
    # Train the model
    model.fit(X_train, y_train)
    
    # Save the model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Dummy model saved to {MODEL_PATH}")
    return model

def create_test_database():
    """Create a test database with sample data."""
    print("Creating test database with sample data...")
    
    # Connect to the database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create detections table
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
    
    # Create blocked_ips table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
    ''')
    
    # Generate random IPs
    def random_ip():
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    # List of common source IPs to have some patterns in the data
    common_ips = [random_ip() for _ in range(10)]
    protocols = ["TCP", "UDP", "ICMP"]
    
    # Generate detection records
    print("Generating detection records...")
    now = datetime.now()
    
    # Generate 200 records over the past 24 hours
    for i in range(200):
        # Random timestamp within the past 24 hours
        timestamp = now - timedelta(hours=random.uniform(0, 24))
        ts = timestamp.timestamp()
        
        # Select attack type with proper distribution
        # Make Benign more common (60%), distribute others
        attack_type = random.choices(
            ATTACK_TYPES, 
            weights=[60, 10, 10, 5, 10, 5], 
            k=1
        )[0]
        
        # Use common IPs for attacks to show patterns
        if attack_type != "Benign" and random.random() < 0.7:
            source_ip = random.choice(common_ips)
        else:
            source_ip = random_ip()
            
        destination_ip = random_ip()
        
        # Generate appropriate traffic data based on attack type
        if attack_type == "DoS" or attack_type == "DDoS":
            # High traffic volume
            orig_bytes = random.randint(100000, 1000000)
            resp_bytes = random.randint(10000, 100000)
            orig_pkts = random.randint(1000, 10000)
            resp_pkts = random.randint(100, 1000)
            duration = random.uniform(10, 60)
            protocol = "TCP" if random.random() < 0.8 else random.choice(protocols)
        elif attack_type == "PortScan":
            # Many small packets
            orig_bytes = random.randint(100, 5000)
            resp_bytes = random.randint(100, 5000)
            orig_pkts = random.randint(100, 500)
            resp_pkts = random.randint(100, 500)
            duration = random.uniform(5, 30)
            protocol = "TCP"
        elif attack_type == "BruteForce":
            # Repeated connection attempts
            orig_bytes = random.randint(1000, 10000)
            resp_bytes = random.randint(1000, 10000)
            orig_pkts = random.randint(100, 300)
            resp_pkts = random.randint(100, 300)
            duration = random.uniform(1, 10)
            protocol = "TCP"
        elif attack_type == "WebAttack":
            # HTTP traffic
            orig_bytes = random.randint(1000, 50000)
            resp_bytes = random.randint(1000, 200000)
            orig_pkts = random.randint(10, 100)
            resp_pkts = random.randint(10, 200)
            duration = random.uniform(0.1, 5)
            protocol = "TCP"
        else:  # Benign
            # Normal traffic
            orig_bytes = random.randint(100, 50000)
            resp_bytes = random.randint(100, 50000)
            orig_pkts = random.randint(1, 100)
            resp_pkts = random.randint(1, 100)
            duration = random.uniform(0.01, 2)
            protocol = random.choice(protocols)
        
        # Insert the record
        cursor.execute('''
        INSERT INTO detections (
            timestamp, attack_type, source_ip, destination_ip, source_port, 
            destination_port, protocol, orig_bytes, resp_bytes, orig_pkts, 
            resp_pkts, duration, detected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ts, attack_type, source_ip, destination_ip, random.randint(1024, 65535),
            random.randint(1, 65535), protocol, orig_bytes, resp_bytes, 
            orig_pkts, resp_pkts, duration, timestamp
        ))
    
    # Generate some blocked IPs
    print("Generating blocked IP records...")
    attacker_ips = []
    
    # Get some source IPs from attacks (focusing on real attacks, not benign)
    cursor.execute('''
    SELECT source_ip FROM detections 
    WHERE attack_type != 'Benign' 
    GROUP BY source_ip 
    LIMIT 8
    ''')
    
    for row in cursor.fetchall():
        attacker_ips.append(row[0])
    
    # Add a few more random IPs
    for _ in range(3):
        attacker_ips.append(random_ip())
    
    # Insert blocked IPs
    for ip in attacker_ips:
        block_time = now - timedelta(minutes=random.uniform(10, 60*12))
        cursor.execute('''
        INSERT INTO blocked_ips (ip_address, blocked_at, is_active)
        VALUES (?, ?, ?)
        ''', (ip, block_time, random.choices([0, 1], weights=[20, 80], k=1)[0]))
    
    # Commit the changes and close the connection
    conn.commit()
    conn.close()
    
    print(f"Test database created at {DATABASE_PATH}")
    print(f"Generated 200 detection records and {len(attacker_ips)} blocked IP records")

def create_dummy_zeek_log():
    """Create a dummy Zeek conn.log file for testing."""
    print("Creating a dummy Zeek conn.log file...")
    
    log_file = os.path.join(BASE_DIR, "logs", "conn.log")
    
    with open(log_file, 'w') as f:
        # Write some header lines that look like Zeek format
        f.write("#separator \\x09\n")
        f.write("#set_separator    ,\n")
        f.write("#empty_field    (empty)\n")
        f.write("#unset_field    -\n")
        f.write("#path    conn\n")
        f.write("#open    2023-09-10-12-00-00\n")
        f.write("#fields    ts    uid    id.orig_h    id.orig_p    id.resp_h    id.resp_p    proto    service    duration    orig_bytes    resp_bytes    conn_state    local_orig    local_resp    missed_bytes    history    orig_pkts    orig_ip_bytes    resp_pkts    resp_ip_bytes    tunnel_parents    ip_proto\n")
        f.write("#types    time    string    addr    port    addr    port    enum    string    interval    count    count    string    bool    bool    count    string    count    count    count    count    set[string]    string\n")
        
        # Generate some sample log entries
        now = datetime.now()
        for i in range(20):
            ts = now - timedelta(seconds=random.uniform(0, 600))
            uid = f"C{random.randint(1000000, 9999999)}"
            id_orig_h = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
            id_orig_p = random.randint(1024, 65535)
            id_resp_h = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
            id_resp_p = random.choice([80, 443, 22, 53, 25, 8080, 123])
            proto = random.choice(["tcp", "udp", "icmp"])
            service = random.choice(["http", "dns", "ssh", "-", "ssl"])
            duration = random.uniform(0.001, 30.0)
            orig_bytes = random.randint(0, 10000)
            resp_bytes = random.randint(0, 20000)
            conn_state = random.choice(["S0", "S1", "SF", "REJ", "RSTO", "RSTR"])
            local_orig = random.choice(["T", "F"])
            local_resp = random.choice(["T", "F"])
            missed_bytes = random.randint(0, 100)
            history = random.choice(["Dd", "ShADad", "ShADadfF", "CT", "Sr"])
            orig_pkts = random.randint(1, 200)
            orig_ip_bytes = orig_bytes + random.randint(100, 500)
            resp_pkts = random.randint(1, 300)
            resp_ip_bytes = resp_bytes + random.randint(100, 500)
            tunnel_parents = "-"
            ip_proto = "-"
            
            # Write the log entry
            f.write(f"{ts.timestamp()}    {uid}    {id_orig_h}    {id_orig_p}    {id_resp_h}    {id_resp_p}    {proto}    {service}    {duration}    {orig_bytes}    {resp_bytes}    {conn_state}    {local_orig}    {local_resp}    {missed_bytes}    {history}    {orig_pkts}    {orig_ip_bytes}    {resp_pkts}    {resp_ip_bytes}    {tunnel_parents}    {ip_proto}\n")
    
    print(f"Dummy conn.log created at {log_file}")

if __name__ == "__main__":
    # Create dummy model
    create_dummy_model()
    
    # Create test database
    create_test_database()
    
    # Create dummy Zeek log
    create_dummy_zeek_log()
    
    print("\nAll test data and model generated successfully!")
    print("You can now run the dashboard with: streamlit run src/dashboard/dashboard.py")
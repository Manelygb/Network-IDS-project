import os

# Network configuration
DEFAULT_INTERFACE = "eth0"

# Path configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Log file paths
DEFAULT_LOG_PATH = os.path.join(LOGS_DIR, "conn.log")

# Model paths
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "wpa2_key_cracking_model_no_protocol.pkl")

# Database configuration
DATABASE_PATH = os.path.join(DATA_DIR, "detections.db")

# Zeek configuration
ZEEK_PATH = "/opt/zeek/bin/zeek"

# Columns for Zeek conn.log
COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", 
    "proto", "service", "duration", "orig_bytes", "resp_bytes", 
    "conn_state", "local_orig", "local_resp", "missed_bytes", 
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", 
    "resp_ip_bytes", "tunnel_parents", "ip_proto"
]

# Attack types
ATTACK_TYPES = ["Benign", "DoS", "PortScan", "DDoS", "BruteForce", "WebAttack"]

# Dashboard configuration
DASHBOARD_UPDATE_INTERVAL = 5  # seconds
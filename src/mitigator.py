import subprocess
from typing import List, Dict, Any
import sqlite3
import time
import config

def block_ip(ip_address: str) -> bool:
    """Block an IP address using iptables."""
    try:
        # Check if the IP is already blocked
        check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # If the IP is not already blocked, block it
        if result.returncode != 0:
            block_cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(block_cmd, check=True)
            print(f"✅ Blocked IP: {ip_address}")
            
            # Log the blocking action
            log_blocked_ip(ip_address)
            return True
        else:
            print(f"IP already blocked: {ip_address}")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block IP {ip_address}: {e}")
        return False

def unblock_ip(ip_address: str) -> bool:
    """Unblock an IP address."""
    try:
        unblock_cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        subprocess.run(unblock_cmd, check=True)
        print(f"✅ Unblocked IP: {ip_address}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to unblock IP {ip_address}: {e}")
        return False

def log_blocked_ip(ip_address: str) -> None:
    """Log the blocked IP address to the database."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        # Create the blocked_ips table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
        ''')
        
        # Insert the blocked IP record
        cursor.execute(
            "INSERT INTO blocked_ips (ip_address) VALUES (?)",
            (ip_address,)
        )
        
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_blocked_ips() -> List[Dict[str, Any]]:
    """Get a list of all blocked IPs from the database."""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM blocked_ips WHERE is_active = 1")
        rows = cursor.fetchall()
        
        blocked_ips = []
        for row in rows:
            blocked_ips.append({
                "id": row["id"],
                "ip_address": row["ip_address"],
                "blocked_at": row["blocked_at"],
                "is_active": bool(row["is_active"])
            })
        
        conn.close()
        return blocked_ips
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def auto_mitigate(attack_type: str, flow_data: Dict[str, Any]) -> None:
    """Automatically mitigate detected attacks."""
    source_ip = flow_data.get("source_ip")
    
    if not source_ip:
        return
    
    # Implement different mitigation strategies based on attack type
    if attack_type == "DoS" or attack_type == "DDoS":
        print(f"🛡️ Auto-mitigating {attack_type} attack from {source_ip}")
        block_ip(source_ip)
    
    elif attack_type == "PortScan":
        print(f"🛡️ Auto-mitigating Port Scan from {source_ip}")
        block_ip(source_ip)
    
    elif attack_type == "BruteForce":
        print(f"🛡️ Auto-mitigating Brute Force attack from {source_ip}")
        block_ip(source_ip)
    
    elif attack_type == "WebAttack":
        print(f"🛡️ Auto-mitigating Web Attack from {source_ip}")
        block_ip(source_ip)
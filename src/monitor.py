import os
import time
from datetime import datetime
from src.analyzer import NetworkFlowClassifier
from src.utils import is_valid_line, has_valid_field_count, extract_source_ip, log_detection
from src.mitigator import auto_mitigate
import config

def monitor_conn_log(
    classifier: NetworkFlowClassifier, log_path: str = config.DEFAULT_LOG_PATH
) -> None:
    """Monitor the connection log file for new entries and make predictions."""
    print(f"Starting to monitor {log_path} for new records...")

    if not os.path.exists(log_path):
        print(f"Log file {log_path} not found. Waiting for it to be created...")
        # Continue and wait for the file to be created

    file_position = 0
    if os.path.exists(log_path):
        file_position = os.path.getsize(log_path)
    
    print("Monitoring for new connections...")
    print("-" * 80)

    try:
        while True:
            if os.path.exists(log_path):
                current_size = os.path.getsize(log_path)
                if current_size > file_position:
                    with open(log_path, "r") as f:
                        f.seek(file_position)
                        for line in f:
                            if not is_valid_line(line) or not has_valid_field_count(line):
                                continue

                            attack_type, flow_data = classifier.predict(line)
                            
                            # Extract source IP address from the log line
                            source_ip = extract_source_ip(line)
                            if source_ip:
                                flow_data["source_ip"] = source_ip
                            
                            # Format timestamp for display
                            timestamp = datetime.fromtimestamp(float(flow_data.get('timestamp', 0)))
                            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                            
                            # Log all detections to the database
                            log_detection(attack_type, flow_data)
                            
                            if attack_type != "Benign":
                                print(f"[{formatted_time}] 🚨 {attack_type.upper()} ATTACK DETECTED from {source_ip}")
                                print(f"  Details: Src={source_ip}, Bytes={flow_data.get('orig_bytes', 0)}, Packets={flow_data.get('orig_pkts', 0)}")
                                
                                # Automatically mitigate the attack
                                auto_mitigate(attack_type, flow_data)
                            else:
                                print(f"[{formatted_time}] ✓ Normal flow from {source_ip}")
                        
                        file_position = f.tell()
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped. Shutting down...")
    except Exception as e:
        print(f"Error during monitoring: {e}")
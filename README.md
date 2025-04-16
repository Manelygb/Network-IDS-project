# Network Intrusion Detection System

A real-time network traffic monitoring and attack detection system built with Python, Zeek, and Streamlit.

## Features

- **Real-time Traffic Monitoring**: Uses Zeek to capture and analyze network traffic in real-time
- **Attack Detection**: ML-powered detection of common network attacks (DoS, DDoS, Port Scanning, etc.)
- **Auto-mitigation**: Automatically blocks malicious IP addresses using iptables
- **Interactive Dashboard**: Streamlit-based dashboard for monitoring and managing the system
- **Persistent Storage**: SQLite database for storing detection events and blocked IPs

## Project Structure

```
network_ids_project/
├── src/
│   ├── collector.py            # Zeek traffic collector
│   ├── analyzer.py             # Flow classification
│   ├── mitigator.py            # IP blocking
│   ├── monitor.py              # Connection log monitoring
│   ├── dashboard/              # Streamlit dashboard
│   │   └── dashboard.py        # Dashboard implementation
│   └── utils.py                # Utility functions
├── models/                     # ML model files
│   └── wpa2_key_cracking_model_no_protocol.pkl
├── data/                       # Data storage
│   └── detections.db           # SQLite database
├── logs/                       # Log files
│   └── conn.log                # Zeek connection logs
├── config.py                   # Configuration settings
├── main.py                     # Main entry point
└── requirements.txt            # Package dependencies
```

## Prerequisites

- Python 3.8+
- Zeek Network Security Monitor
- iptables (for IP blocking functionality)
- Root/sudo privileges (for traffic capture and IP blocking)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-ids-project.git
   cd network-ids-project
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Zeek (if not already installed):
   ```bash
   sudo apt-get update
   sudo apt-get install -y zeek
   ```

## Usage

### Running the IDS

To start monitoring network traffic:

```bash
sudo python main.py -i eth0
```

Where:
- `-i, --interface`: Network interface to monitor (default: eth0)
- `-m, --model`: Path to the trained model file
- `-l, --log`: Path to the Zeek conn.log file

### Running the Dashboard

To start the Streamlit dashboard:

```bash
streamlit run src/dashboard/dashboard.py
```

The dashboard will be available at http://localhost:8501

## Dashboard Features

1. **Monitoring Tab**: Displays real-time traffic and attack detections
2. **Statistics Tab**: Shows attack statistics, distribution charts, and top attackers
3. **IP Management Tab**: Allows manual blocking and unblocking of IP addresses

## Customization

- Edit `config.py` to customize default paths, interfaces, and other settings
- Replace the model file with your own trained model
- Modify the attack types and detection logic in `analyzer.py`

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
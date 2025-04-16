import argparse
import time
from src.collector import install_zeek, start_zeek
from src.analyzer import NetworkFlowClassifier
from src.utils import wait_for_log_file
from src.monitor import monitor_conn_log
import config

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument(
        "-i",
        "--interface",
        default=config.DEFAULT_INTERFACE,
        help=f"Network interface to monitor (default: {config.DEFAULT_INTERFACE})",
    )
    parser.add_argument(
        "-m",
        "--model",
        default=config.DEFAULT_MODEL_PATH,
        help=f"Path to the trained model file (default: {config.DEFAULT_MODEL_PATH})",
    )
    parser.add_argument(
        "-l",
        "--log",
        default=config.DEFAULT_LOG_PATH,
        help=f"Path to the Zeek conn.log file (default: {config.DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch the Streamlit dashboard",
    )
    return parser.parse_args()


def main() -> None:
    """Main function to run the network monitoring system."""
    # Parse command line arguments
    args = parse_arguments()

    if args.dashboard:
        print("Starting Streamlit dashboard...")
        # This is handled by running "streamlit run src/dashboard/dashboard.py" from the command line
        # We exit here as the streamlit process will take over
        return

    # Initialize the classifier
    try:
        print("Initializing network flow classifier...")
        classifier = NetworkFlowClassifier(args.model)
        print("✅ Classifier initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing classifier: {e}")
        return

    # Check and install Zeek if needed
    install_zeek()

    # Start Zeek on the specified interface
    start_zeek(interface=args.interface)

    # Give Zeek a moment to initialize
    print("Waiting for Zeek to initialize...")
    time.sleep(5)

    # Start monitoring the log file
    monitor_conn_log(classifier, log_path=args.log)


if __name__ == "__main__":
    main()
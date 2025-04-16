import subprocess
import config

def install_zeek() -> None:
    """Check if Zeek is installed and install it if not."""
    try:
        # Check if Zeek is already installed
        subprocess.run(["which", "zeek"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("✅ Zeek is already installed")
    except subprocess.CalledProcessError:
        print("Zeek not found. Installing Zeek...")
        try:
            # This is a simplified installation - adjust according to your OS
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "zeek"], check=True)
            print("✅ Zeek installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install Zeek: {e}")
            print("Please install Zeek manually and try again.")
            exit(1)

def start_zeek(interface: str = config.DEFAULT_INTERFACE) -> None:
    """Start Zeek on the specified interface."""
    try:
        # Stop any running Zeek instance
        subprocess.run(["pkill", "zeek"], stderr=subprocess.PIPE)
        
        # Start Zeek with the conn log enabled
        cmd = [config.ZEEK_PATH, "-i", interface, "local"]
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"✅ Zeek started on interface {interface}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start Zeek: {e}")
        exit(1)
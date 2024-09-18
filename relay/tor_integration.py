import socks  # PySocks
import socket
import logging
import time
from stem import Signal
from stem.control import Controller
import subprocess

DEFAULT_TOR_ADDRESS = "127.0.0.1"
DEFAULT_TOR_PORT = 9050
RETRY_LIMIT = 3
RETRY_DELAY = 5  # seconds
TOR_CONTROL_PORT = 9051  # Default control port for TOR
TOR_PROCESS = None

def start_tor():
    """
    Start the TOR process.
    """
    global TOR_PROCESS
    try:
        # Launch TOR process
        TOR_PROCESS = subprocess.Popen(['tor'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info("TOR process started successfully.")
        time.sleep(5)  # Wait for TOR to initialize
    except Exception as e:
        logging.error(f"Failed to start TOR process: {e}")
        return False

    return True

def initialize_tor(tor_address=DEFAULT_TOR_ADDRESS, tor_port=DEFAULT_TOR_PORT, retry_limit=RETRY_LIMIT):
    """
    Initialize TOR network integration by setting up a SOCKS proxy for TOR.

    Parameters:
        tor_address (str): The IP address of the TOR proxy (default: "127.0.0.1").
        tor_port (int): The port of the TOR proxy (default: 9050).
        retry_limit (int): Number of retries if connection to TOR fails (default: 3).

    Returns:
        bool: True if initialization was successful, False otherwise.
    """
    if not start_tor():
        logging.error("Failed to start TOR network.")
        return False

    attempt = 0

    while attempt < retry_limit:
        try:
            # Set up the SOCKS proxy to use TOR's default ports
            socks.set_default_proxy(socks.SOCKS5, tor_address, tor_port)
            socket.socket = socks.socksocket

            # Test connection by connecting to a TOR node
            with socks.socksocket() as s:
                s.settimeout(10)
                s.connect(("check.torproject.org", 80))
                logging.info("Successfully connected to TOR network.")

            logging.info("TOR network initialized for anonymization.")
            return True

        except (socket.error, socks.ProxyConnectionError) as e:
            attempt += 1
            logging.error(f"Failed to connect to TOR network (attempt {attempt}/{retry_limit}): {e}")
            if attempt < retry_limit:
                logging.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)

    logging.error("Exceeded maximum retry limit. TOR integration failed.")
    return False

def reset_socks_proxy():
    """
    Reset the SOCKS proxy to the default socket behavior.
    """
    try:
        socket.socket = socket._socketobject  # Reset to the original socket object
        logging.info("SOCKS proxy has been reset to default.")
    except AttributeError:
        logging.error("Failed to reset SOCKS proxy: Default socket object not found.")
    except Exception as e:
        logging.error(f"Unexpected error when resetting SOCKS proxy: {e}")

def is_tor_active():
    """
    Check if the TOR network is currently active by testing the proxy connection.

    Returns:
        bool: True if the TOR network is active, False otherwise.
    """
    try:
        with socks.socksocket() as s:
            s.settimeout(5)
            s.connect(("check.torproject.org", 80))
        logging.info("TOR network is active.")
        return True
    except (socket.error, socks.ProxyConnectionError) as e:
        logging.error(f"Failed to connect to TOR network: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error while checking TOR network status: {e}")
        return False

def stop_tor():
    """
    Stop the TOR process.
    """
    global TOR_PROCESS
    if TOR_PROCESS:
        TOR_PROCESS.terminate()
        TOR_PROCESS = None
        logging.info("TOR process terminated successfully.")
    else:
        logging.warning("No TOR process found to terminate.")
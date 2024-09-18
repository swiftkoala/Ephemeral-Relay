# main.py

import argparse
import logging
import sys
import threading
import tkinter as tk
import time
from relay.relay_server import RelayServer
from relay.relay_client import start_relay_client
from relay.relay_manager import RelayManager
from relay.monitoring import start_monitoring
from relay.utils import load_config
from relay.tor_integration import initialize_tor
from relay.dynamic_ip_manager import DynamicIPManager
from api.api_server import start_api_server
from tkinter import ttk

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Event to signal when the server is ready
server_ready_event = threading.Event()

def start_gui_client():
    """Starts the GUI for the client."""
    def send_message():
        host = host_entry.get()
        port = int(port_entry.get())
        message = message_entry.get()
        progress_bar.start(10)  # Start loading bar
        try:
            start_relay_client(host, port, message)
            output_label.config(text="Message sent successfully.")
        except Exception as e:
            output_label.config(text=f"Error: {e}")
        finally:
            progress_bar.stop()  # Stop loading bar

    def check_server_ready():
        """Checks if the server is ready and updates the GUI."""
        if server_ready_event.is_set():
            server_status_label.config(text="Server Status: Ready", fg="green")
        else:
            server_status_label.config(text="Server Status: Initializing...", fg="orange")
        root.after(1000, check_server_ready)  # Check every second

    # Create the main window
    root = tk.Tk()
    root.title("Relay Client GUI")

    # Host input
    tk.Label(root, text="Host:").grid(row=0, column=0)
    host_entry = tk.Entry(root)
    host_entry.insert(0, "127.0.0.1")
    host_entry.grid(row=0, column=1)

    # Port input
    tk.Label(root, text="Port:").grid(row=1, column=0)
    port_entry = tk.Entry(root)
    port_entry.insert(0, "8000")
    port_entry.grid(row=1, column=1)

    # Message input
    tk.Label(root, text="Message:").grid(row=2, column=0)
    message_entry = tk.Entry(root)
    message_entry.insert(0, "Hello, Relay!")
    message_entry.grid(row=2, column=1)

    # Server status label
    server_status_label = tk.Label(root, text="Server Status: Unknown", fg="orange")
    server_status_label.grid(row=3, columnspan=2)

    # Progress bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="indeterminate")
    progress_bar.grid(row=4, columnspan=2)

    # Send button
    send_button = tk.Button(root, text="Send", command=send_message)
    send_button.grid(row=5, columnspan=2)

    # Output label
    output_label = tk.Label(root, text="")
    output_label.grid(row=6, columnspan=2)

    # Start the server status check loop
    check_server_ready()

    # Run the GUI
    root.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Ephemeral Relay System')
    parser.add_argument('--mode', choices=['server', 'client', 'both'], default='both',
                        help='Mode to run the system: server, client, or both (default: both)')
    parser.add_argument('--config', type=str, default='config.yml',
                        help='Path to the configuration file (default: config.yml)')
    parser.add_argument('--client-message', type=str, default=None,
                        help='Message to send from the client (default: None)')
    parser.add_argument('--relay-lifetime', type=int, default=None,
                        help='Lifetime of each relay in seconds (default: None)')
    parser.add_argument('--retries', type=int, default=3,
                        help='Number of retries for client connection (default: 3)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Timeout for client connection in seconds (default: 10)')
    parser.add_argument('--with-gui', action='store_true',
                        help='Launch the GUI client for testing (default: False)')
    args = parser.parse_args()

    try:
        # Load configuration
        config = load_config(args.config)
        host = config['server']['host']
        port = config['server']['port']
        client_message = args.client_message if args.client_message else config['client']['message']
        relay_lifetime = args.relay_lifetime if args.relay_lifetime else config['relay']['lifetime']
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        sys.exit(1)

    # Initialize TOR if enabled
    if config.get('tor_enabled', False):
        try:
            initialize_tor()
            logging.info('TOR network initialized for anonymization.')
        except Exception as e:
            logging.error(f"Failed to initialize TOR: {e}")
            sys.exit(1)

    # Initialize Dynamic IP Manager if enabled
    dynamic_ip_manager = None
    if config.get('dynamic_ip_enabled', False):
        dynamic_ip_manager = DynamicIPManager()
        dynamic_ip_manager.start()

    # Start API server for relay interactions
    start_api_server(config)

    # Start relay server
    if args.mode in ['server', 'both']:
        try:
            logging.info('Starting relay server...')
            relay_manager = RelayManager(config, relay_lifetime)
            relay_server = RelayServer(host, port, relay_lifetime)
            relay_server_thread = threading.Thread(target=relay_server.run)
            relay_server_thread.start()
            # Wait for the server to be fully initialized
            server_ready_event.set()  # Signal that the server is ready
        except Exception as e:
            logging.error(f"Error starting relay server: {e}")
            sys.exit(1)

    # Start relay client
    if args.mode in ['client', 'both']:
        try:
            logging.info('Starting relay client...')
            start_relay_client(host, port, client_message, args.retries, args.timeout)
        except Exception as e:
            logging.error(f"Error starting relay client: {e}")
            sys.exit(1)

    # Start monitoring
    try:
        start_monitoring()
    except Exception as e:
        logging.error(f"Error starting monitoring: {e}")
        sys.exit(1)

    # Launch GUI if specified
    if args.with_gui:
        logging.info('Starting GUI client...')
        gui_thread = threading.Thread(target=start_gui_client)
        gui_thread.start()

    # Graceful shutdown on termination signal
    try:
        while True:
            pass  # Keep the main thread alive
    except KeyboardInterrupt:
        logging.info("Shutting down Ephemeral Relay System...")
        if dynamic_ip_manager:
            dynamic_ip_manager.stop()
        sys.exit(0)

if __name__ == '__main__':
    main()
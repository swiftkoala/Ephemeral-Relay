# gui_test.py

import tkinter as tk
import threading
import time
from tkinter import ttk, messagebox, scrolledtext
from relay.relay_client import start_relay_client
import logging

def start_gui_client():
    """Starts the GUI for the client."""
    def send_message():
        """Sends a message to the relay server."""
        host = host_entry.get()
        port = port_entry.get()
        message = message_entry.get()

        if not host or not port or not message:
            messagebox.showwarning("Input Error", "Please fill in all fields.")
            return

        try:
            port = int(port)
        except ValueError:
            messagebox.showwarning("Input Error", "Port must be an integer.")
            return

        progress_bar.start(10)  # Start loading bar
        threading.Thread(target=attempt_send_message, args=(host, port, message)).start()

    def attempt_send_message(host, port, message):
        """Attempts to send a message to the relay server."""
        try:
            start_relay_client(host, port, message)
            update_message_log(f"Sent: {message}")
            output_label.config(text="Message sent successfully.")
        except Exception as e:
            output_label.config(text=f"Error: {e}")
            logging.error(f"Error in sending message: {e}")
        finally:
            progress_bar.stop()  # Stop loading bar

    def check_server_ready():
        """Checks if the server is ready and updates the GUI."""
        retry_count = 0
        max_retries = 5
        while retry_count < max_retries:
            try:
                # Try to connect to the relay server to check readiness
                start_relay_client(host_entry.get(), int(port_entry.get()), 'ping')
                update_status_label("Server Status: Ready", "green")
                progress_bar.stop()  # Stop the loading bar
                break
            except Exception as e:
                retry_count += 1
                update_status_label("Server Status: Initializing...", "orange")
                progress_bar.start(10)  # Start or continue the loading bar
                time.sleep(2)  # Wait before retrying
        else:
            update_status_label("Server Status: Not Ready", "red")
            progress_bar.stop()  # Stop the loading bar

    def update_status_label(text, color):
        """Update the server status label in a thread-safe manner."""
        server_status_label.config(text=text, fg=color)

    def update_message_log(message):
        """Update the message log with the latest message."""
        message_log.config(state=tk.NORMAL)
        message_log.insert(tk.END, message + "\n")
        message_log.see(tk.END)  # Scroll to the end
        message_log.config(state=tk.DISABLED)

    # Create the main window
    root = tk.Tk()
    root.title("Relay Client GUI")

    # Create frames for layout
    input_frame = tk.Frame(root)
    input_frame.grid(row=0, column=0, padx=10, pady=10)

    log_frame = tk.Frame(root)
    log_frame.grid(row=1, column=0, padx=10, pady=10)

    # Host input
    tk.Label(input_frame, text="Host:").grid(row=0, column=0)
    host_entry = tk.Entry(input_frame)
    host_entry.insert(0, "127.0.0.1")
    host_entry.grid(row=0, column=1)

    # Port input
    tk.Label(input_frame, text="Port:").grid(row=1, column=0)
    port_entry = tk.Entry(input_frame)
    port_entry.insert(0, "8000")
    port_entry.grid(row=1, column=1)

    # Message input
    tk.Label(input_frame, text="Message:").grid(row=2, column=0)
    message_entry = tk.Entry(input_frame)
    message_entry.insert(0, "Hello, Relay!")
    message_entry.grid(row=2, column=1)

    # Server status label
    server_status_label = tk.Label(input_frame, text="Server Status: Unknown", fg="orange")
    server_status_label.grid(row=3, columnspan=2)

    # Progress bar
    progress_bar = ttk.Progressbar(input_frame, orient="horizontal", length=200, mode="indeterminate")
    progress_bar.grid(row=4, columnspan=2)

    # Send button
    send_button = tk.Button(input_frame, text="Send", command=send_message)
    send_button.grid(row=5, columnspan=2)

    # Output label
    output_label = tk.Label(input_frame, text="")
    output_label.grid(row=6, columnspan=2)

    # Message log
    tk.Label(log_frame, text="Message Log:").grid(row=0, column=0)
    message_log = scrolledtext.ScrolledText(log_frame, width=50, height=15, state=tk.DISABLED)
    message_log.grid(row=1, column=0)

    # Start the server status check in a separate thread
    threading.Thread(target=check_server_ready).start()

    # Run the GUI
    root.mainloop()

# Running the GUI client
if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    start_gui_client()
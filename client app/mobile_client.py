import socket
import logging

class MobileClient:
    def __init__(self, server_address='127.0.0.1', server_port=8080):
        self.server_address = server_address
        self.server_port = server_port
        self.connection = None
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def connect_to_relay(self, relay_id):
        """Connect to the specified relay."""
        try:
            self.connection = socket.create_connection((self.server_address, self.server_port))
            logging.info(f"Successfully connected to relay {relay_id} at {self.server_address}:{self.server_port} from mobile client.")
        except Exception as e:
            logging.error(f"Failed to connect to relay {relay_id} from mobile client: {e}")
            self.connection = None

    def send_data(self, data):
        """Send data through the relay."""
        if not self.connection:
            logging.error("No connection established. Unable to send data from mobile client.")
            return

        try:
            # Ensure the data is properly encoded
            self.connection.sendall(data.encode('utf-8'))
            logging.info(f"Data sent successfully from mobile client: {data}")
        except Exception as e:
            logging.error(f"Failed to send data from mobile client: {e}")

    def close_connection(self):
        """Close the connection to the relay."""
        if self.connection:
            try:
                self.connection.close()
                logging.info("Connection closed successfully from mobile client.")
            except Exception as e:
                logging.error(f"Error while closing connection from mobile client: {e}")
            finally:
                self.connection = None
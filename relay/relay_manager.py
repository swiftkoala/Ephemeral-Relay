import threading
import time
import logging
from .relay_server import RelayServer

class RelayManager:
    def __init__(self, config, relay_lifetime):
        self.config = config
        self.relay_lifetime = relay_lifetime
        self.relays = []
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def create_relay(self):
        """
        Create a relay server using the configuration provided.

        Returns:
            RelayServer: The relay server instance created.
        """
        try:
            host = self.config.get('relay_host', '127.0.0.1')
            port = self.config.get('relay_port', 0)  # 0 means select an arbitrary unused port
            relay_server = RelayServer(host, port, self.relay_lifetime)
            self.relays.append(relay_server)
            logging.info(f"Created relay server on {host}:{port}.")
            return relay_server
        except Exception as e:
            logging.error(f"Error creating relay server: {e}")
            return None

    def start_relay(self, relay_server):
        """
        Start the relay server in a new thread.

        Args:
            relay_server (RelayServer): The relay server instance to start.

        Returns:
            threading.Thread: The thread in which the relay server is running.
        """
        try:
            relay_thread = threading.Thread(target=relay_server.run, daemon=True)
            relay_thread.start()
            logging.info(f"Relay server started on {relay_server.host}:{relay_server.port}.")
            return relay_thread
        except Exception as e:
            logging.error(f"Error starting relay server: {e}")
            return None

    def start(self):
        """
        Create and start the configured number of relays, and manage their lifecycle.
        """
        try:
            # Creating and starting relays
            for _ in range(self.config.get('number_of_relays', 1)):
                relay_server = self.create_relay()
                if relay_server:
                    self.start_relay(relay_server)

            # Monitor relay lifetime and self-destruct after timeout
            lifecycle_thread = threading.Thread(target=self.relay_lifecycle, daemon=True)
            lifecycle_thread.start()
        except Exception as e:
            logging.error(f"Error in starting relay manager: {e}")

    def relay_lifecycle(self):
        """
        Monitor the lifecycle of relays and close them after the specified lifetime.
        """
        try:
            logging.info(f"Relay lifecycle monitoring started for a lifetime of {self.relay_lifetime} seconds.")
            time.sleep(self.relay_lifetime)
            for relay in self.relays:
                relay.server.close()
                logging.info(f"Relay on {relay.host}:{relay.port} closed after {self.relay_lifetime} seconds.")
            self.relays.clear()
        except Exception as e:
            logging.error(f"Error during relay lifecycle management: {e}")
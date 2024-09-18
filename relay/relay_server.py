import asyncio
import logging
import ssl
import socket
from .ssl_utils import generate_secure_context  # Adjusted import to only use generate_secure_context
from .utils import load_config, validate_configuration
from .config import BUFFER_SIZE

class RelayServer:
    def __init__(self, host, port, relay_lifetime):
        self.host = host
        self.port = port
        self.relay_lifetime = relay_lifetime
        self.server = None
        self.clients = []

        try:
            # Specify is_server=True to generate a server SSL context
            self.context = generate_secure_context(is_server=True)
            logging.info("SSL context successfully generated for the server.")
        except Exception as e:
            logging.error(f"SSL context generation failed: {e}")
            raise

    async def handle_client(self, reader, writer):
        client_address = writer.get_extra_info('peername')
        try:
            logging.info(f"Connection established with {client_address}")
            self.clients.append(writer)

            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    logging.info(f"No more data from {client_address}. Closing connection.")
                    break

                message = data.decode('utf-8')
                logging.info(f"Data received from {client_address}: {message}")

                # Optionally, send an acknowledgment back to the client
                acknowledgment = f"Server received: {message}"
                writer.write(acknowledgment.encode('utf-8'))
                await writer.drain()

                # Broadcast the message to other clients
                await self.broadcast_message(message, sender=writer)

        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            logging.info(f"Connection closed with {client_address}")
            self.clients.remove(writer)
            writer.close()
            await writer.wait_closed()

    async def broadcast_message(self, message, sender):
        """
        Broadcast the received message to all connected clients except the sender.

        Args:
            message (str): The message to be broadcasted.
            sender (StreamWriter): The sender's StreamWriter object.
        """
        for client in self.clients:
            if client != sender:
                try:
                    client_address = client.get_extra_info('peername')
                    sender_address = sender.get_extra_info('peername')
                    broadcast_message = f"Broadcast from {sender_address}: {message}"
                    client.write(broadcast_message.encode('utf-8'))
                    await client.drain()
                    logging.info(f"Message broadcasted to {client_address}.")
                except Exception as e:
                    logging.error(f"Error broadcasting message to {client_address}: {e}")

    async def start_relay(self):
        """
        Start the relay server to accept connections and handle clients.
        """
        try:
            if check_port_available(self.host, self.port):
                self.server = await asyncio.start_server(
                    self.handle_client, self.host, self.port, ssl=self.context
                )
                logging.info(f"Relay server started on {self.host}:{self.port}")
            else:
                logging.error(f"Port {self.port} is already in use. Relay server not started.")
        except OSError as e:
            logging.error(f"Failed to start relay server on {self.host}:{self.port}: {e}")
            raise

        async with self.server:
            await self.server.serve_forever()

    def run(self):
        """
        Run the relay server within an asyncio event loop.
        """
        try:
            asyncio.run(self.start_relay())
        except Exception as e:
            logging.error(f"Relay server encountered an error: {e}")
            raise
        finally:
            if self.server:
                self.server.close()
                logging.info("Relay server has been properly closed.")

    def stop_server(self):
        """
        Stop the server and disconnect all clients.
        """
        if self.server:
            self.server.close()
            logging.info("Relay server stopped.")

        for client in self.clients:
            client.close()
            logging.info("Disconnected a client.")
        self.clients = []

def check_port_available(host, port):
    """
    Check if the specified port is available on the host.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def start_relay_server(host, port, relay_lifetime):
    """
    Function to create and run a relay server instance.

    Args:
        host (str): Host on which the relay server will run.
        port (int): Port on which the relay server will listen.
        relay_lifetime (int): Duration in seconds for which the relay server will run.
    """
    try:
        relay_server = RelayServer(host, port, relay_lifetime)
        relay_server.run()
    except Exception as e:
        logging.error(f"Error starting relay server: {e}")

if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Load configuration
    config = load_config('config.yml')

    # Validate configuration
    if validate_configuration(config):
        HOST = config['host']
        PORT = config['port']
        RELAY_LIFETIME = config['relay_lifetime']

        start_relay_server(HOST, PORT, RELAY_LIFETIME)
    else:
        logging.error("Invalid configuration. Relay server not started.")

# Log completion of the script
logging.info("RelayServer script execution complete.")
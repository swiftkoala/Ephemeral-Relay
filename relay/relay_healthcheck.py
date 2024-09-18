import socket
import ssl
import logging
from .utils import generate_secure_context, load_config, validate_configuration
from .config import BUFFER_SIZE

class RelayHealthCheck:
    @staticmethod
    def check_relay(host, port, timeout=5):
        """
        Check the health of the relay server.

        Args:
            host (str): Host of the relay server.
            port (int): Port of the relay server.
            timeout (int): Timeout for the connection in seconds (default: 5).

        Returns:
            bool: True if the relay server is healthy, False otherwise.
        """
        context = generate_secure_context(is_server=False)
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    logging.info(f"Successfully connected to relay server at {host}:{port}")

                    # Send a health check message
                    secure_sock.sendall(b'HEALTH_CHECK')

                    # Wait for the response
                    response = secure_sock.recv(BUFFER_SIZE)
                    response_decoded = response.decode('utf-8')

                    if response_decoded == 'OK':
                        logging.info("Relay server health check passed.")
                        return True
                    else:
                        logging.warning(f"Relay server health check failed: Unexpected response '{response_decoded}'.")
                        return False
        except (socket.timeout, ConnectionRefusedError) as conn_err:
            logging.error(f"Relay server health check failed: Connection error - {conn_err}")
            return False
        except ssl.SSLError as ssl_err:
            logging.error(f"Relay server health check failed: SSL error - {ssl_err}")
            return False
        except Exception as e:
            logging.error(f"Relay server health check failed: {e}")
            return False

if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Load configuration
    config = load_config('config.yml')

    # Validate configuration
    if validate_configuration(config):
        HOST = config['host']
        PORT = config['port']
        RelayHealthCheck.check_relay(HOST, PORT)
    else:
        logging.error("Invalid configuration. Health check not performed.")
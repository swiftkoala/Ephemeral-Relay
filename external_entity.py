import socket
import ssl
import logging
from relay.ssl_utils import generate_secure_context
from relay.config import BUFFER_SIZE

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def attempt_external_connection(host, port, message, retries=3, timeout=10):
    """
    Attempt to connect to the relay server as an external entity.

    Args:
        host (str): Host of the relay server.
        port (int): Port of the relay server.
        message (str): Message to send to the server.
        retries (int): Number of retry attempts in case of connection failure (default: 3).
        timeout (int): Timeout for the connection in seconds (default: 10).
    """
    context = generate_secure_context()

    attempt = 0
    while attempt < retries:
        try:
            # Create an IPv4 socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))  # Connect to the server

                # Wrap the socket with SSL
                with context.wrap_socket(sock, server_hostname=None) as secure_sock:
                    logging.info(f"External entity connected to relay server at {host}:{port}")

                    # Send message to the server
                    secure_sock.sendall(message.encode('utf-8'))
                    response = secure_sock.recv(BUFFER_SIZE)
                    logging.info(f"External entity received response: {response.decode('utf-8')}")
                    break

        except (socket.timeout, ConnectionRefusedError) as conn_err:
            logging.warning(f"External entity connection attempt {attempt + 1} failed: {conn_err}")
            attempt += 1
            if attempt < retries:
                logging.info(f"External entity retrying connection... ({attempt + 1}/{retries})")
            else:
                logging.error(f"External entity failed to connect to relay server after {retries} attempts.")

        except Exception as e:
            logging.error(f"Error in external entity connection: {e}")
            break

if __name__ == '__main__':
    attempt_external_connection('127.0.0.1', 8000, 'Test Message from External Entity')
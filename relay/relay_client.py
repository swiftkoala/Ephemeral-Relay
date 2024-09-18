import socket
import ssl
import logging
from .utils import generate_secure_context, load_config, validate_configuration
from .config import BUFFER_SIZE

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def start_relay_client(host, port, message, retries=3, timeout=10):
    """
    Connect to a relay server and send data with enhanced error handling.

    Args:
        host (str): Host of the relay server.
        port (int): Port of the relay server.
        message (str): Message to send to the server.
        retries (int): Number of retry attempts in case of connection failure (default: 3).
        timeout (int): Timeout for the connection in seconds (default: 10).
    """
    # Generate SSL context for client
    context = generate_secure_context(is_server=False)

    attempt = 0
    while attempt < retries:
        try:
            # Create an IPv4 TCP socket
            with socket.create_connection((host, port), timeout=timeout) as sock:
                # Wrap the socket with SSL
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    logging.info(f"Connected to relay server at {host}:{port}")

                    # Send message to the server
                    send_message(secure_sock, message)

                    # Receive the response from the server
                    response = receive_response(secure_sock)
                    logging.info(f"Received response: {response}")

                    # Break the loop if successful
                    break

        except (socket.timeout, ConnectionRefusedError) as conn_err:
            logging.warning(f"Connection attempt {attempt + 1} failed: {conn_err}")
            attempt += 1
            if attempt < retries:
                logging.info(f"Retrying connection... ({attempt + 1}/{retries})")
            else:
                logging.error(f"Failed to connect to relay server after {retries} attempts.")
        except ssl.SSLError as ssl_err:
            logging.error(f"SSL error: {ssl_err}")
            break
        except Exception as e:
            logging.error(f"Error in relay client: {e}")
            break

def send_message(secure_sock, message):
    """
    Send a message to the server, handling large messages if necessary.

    Args:
        secure_sock (ssl.SSLSocket): The secure socket to send the message through.
        message (str): The message to send.
    """
    try:
        # Split the message into chunks if it exceeds the buffer size
        message_bytes = message.encode('utf-8')
        for i in range(0, len(message_bytes), BUFFER_SIZE):
            chunk = message_bytes[i:i + BUFFER_SIZE]
            secure_sock.sendall(chunk)
            logging.info(f"Sent chunk of size {len(chunk)} bytes.")

        logging.info(f"Message of total size {len(message_bytes)} bytes sent successfully.")
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        raise

def receive_response(secure_sock):
    """
    Receive a response from the server.

    Args:
        secure_sock (ssl.SSLSocket): The secure socket to receive the response from.

    Returns:
        str: The server's response as a string.
    """
    try:
        response_chunks = []
        while True:
            chunk = secure_sock.recv(BUFFER_SIZE)
            if not chunk:
                break
            response_chunks.append(chunk)
        response = b''.join(response_chunks).decode('utf-8')
        return response
    except Exception as e:
        logging.error(f"Error receiving response: {e}")
        raise

if __name__ == '__main__':
    # Load configuration
    config = load_config('config.yml')

    # Validate configuration
    if validate_configuration(config):
        HOST = config['host']
        PORT = config['port']
        MESSAGE = "Test message from relay client"

        # Start the relay client
        start_relay_client(HOST, PORT, MESSAGE)
    else:
        logging.error("Invalid configuration. Relay client not started.")
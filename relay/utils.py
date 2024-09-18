# relay/utils.py

import yaml
import ssl
import os
import logging

def load_config(config_path):
    """
    Load configuration from a YAML file.

    Args:
        config_path (str): Path to the configuration file.

    Returns:
        dict: Configuration data.
    """
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        logging.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file {config_path} not found.")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file {config_path}: {e}")
        raise

def generate_secure_context(is_server=True):
    """
    Generate a secure SSL/TLS context for encrypted communication.

    Args:
        is_server (bool): Determines whether to create a server or client SSL context.

    Returns:
        ssl.SSLContext: An SSL context with loaded certificates.
    """
    # Paths to certificate, key, and CA files
    cert_dir = './relay/certificates'
    server_certfile = os.path.join(cert_dir, 'server.crt')
    server_keyfile = os.path.join(cert_dir, 'server.key')
    client_certfile = os.path.join(cert_dir, 'client.crt')
    client_keyfile = os.path.join(cert_dir, 'client.key')
    cafile = os.path.join(cert_dir, 'ca.crt')

    if is_server:
        # Server SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=server_certfile, keyfile=server_keyfile)
        context.load_verify_locations(cafile=cafile)
        context.verify_mode = ssl.CERT_OPTIONAL  # Change to CERT_REQUIRED if client authentication is needed
        logging.info("Server SSL context successfully generated.")
    else:
        # Client SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=cafile)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # Disable hostname checking if using IP addresses or self-signed certificates
        logging.info("Client SSL context successfully generated.")

    return context

def validate_configuration(config):
    """
    Validate the configuration data.

    Args:
        config (dict): Configuration data to validate.

    Returns:
        bool: True if the configuration is valid, False otherwise.
    """
    # Example validation, can be expanded
    required_keys = ['host', 'port', 'relay_lifetime']
    for key in required_keys:
        if key not in config:
            logging.error(f"Configuration key '{key}' is missing.")
            return False
    return True

def setup_logging(log_file=None, log_level=logging.INFO):
    """
    Set up logging configuration.

    Args:
        log_file (str): Path to the log file. If None, logs to console.
        log_level (int): Logging level.
    """
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    if log_file:
        logging.basicConfig(filename=log_file, level=log_level, format=log_format)
    else:
        logging.basicConfig(level=log_level, format=log_format)
    logging.info("Logging has been configured.")

def save_data_to_file(data, file_path):
    """
    Save data to a file.

    Args:
        data (str): Data to save.
        file_path (str): Path to the file.
    """
    try:
        with open(file_path, 'w') as file:
            file.write(data)
        logging.info(f"Data saved to {file_path}")
    except Exception as e:
        logging.error(f"Failed to save data to {file_path}: {e}")
        raise

def load_data_from_file(file_path):
    """
    Load data from a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: Data loaded from the file.
    """
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        logging.info(f"Data loaded from {file_path}")
        return data
    except Exception as e:
        logging.error(f"Failed to load data from {file_path}: {e}")
        raise

def get_ip_address():
    """
    Get the IP address of the current machine.

    Returns:
        str: IP address.
    """
    import socket
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        logging.info(f"IP address obtained: {ip_address}")
        return ip_address
    except Exception as e:
        logging.error(f"Failed to get IP address: {e}")
        raise

def generate_random_string(length=16):
    """
    Generate a random string of specified length.

    Args:
        length (int): Length of the string.

    Returns:
        str: Random string.
    """
    import random
    import string
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    logging.info(f"Random string generated: {random_str}")
    return random_str

def calculate_checksum(data):
    """
    Calculate a checksum for the given data.

    Args:
        data (bytes): Data to calculate checksum for.

    Returns:
        str: Checksum value.
    """
    import hashlib
    checksum = hashlib.sha256(data).hexdigest()
    logging.info(f"Checksum calculated: {checksum}")
    return checksum

def verify_checksum(data, checksum):
    """
    Verify the checksum of the given data.

    Args:
        data (bytes): Data to verify.
        checksum (str): Expected checksum value.

    Returns:
        bool: True if checksum matches, False otherwise.
    """
    calculated_checksum = calculate_checksum(data)
    is_valid = calculated_checksum == checksum
    if is_valid:
        logging.info("Checksum verification passed.")
    else:
        logging.warning("Checksum verification failed.")
    return is_valid

def encrypt_data(data, key):
    """
    Encrypt data using AES encryption.

    Args:
        data (bytes): Data to encrypt.
        key (bytes): Encryption key.

    Returns:
        bytes: Encrypted data.
    """
    from cryptography.hazmat.primitives import padding, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    logging.info("Data encrypted.")
    return iv + encrypted_data

def decrypt_data(encrypted_data, key):
    """
    Decrypt data using AES decryption.

    Args:
        encrypted_data (bytes): Data to decrypt.
        key (bytes): Decryption key.

    Returns:
        bytes: Decrypted data.
    """
    from cryptography.hazmat.primitives import padding, hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    backend = default_backend()
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_content) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    logging.info("Data decrypted.")
    return data
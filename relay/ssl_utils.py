import ssl
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import datetime
import os
import ipaddress

# Directory and file paths
CERT_DIR = os.path.join(os.path.dirname(__file__), "certificates")
ROOT_CERT_FILE = os.path.join(CERT_DIR, "rootCA.crt")
ROOT_KEY_FILE = os.path.join(CERT_DIR, "rootCA.key")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

# Development flag to bypass certificate verification
DEVELOPMENT_MODE = True

def ensure_certificates():
    """
    Ensure the required certificates are generated and available.
    """
    if not os.path.exists(ROOT_CERT_FILE) or not os.path.exists(ROOT_KEY_FILE):
        logging.warning("Root CA certificates not found. Generating new ones.")
        generate_self_signed_cert()
    else:
        logging.info("Root CA certificates are present.")

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        logging.warning("Server certificates not found. Generating new ones.")
        generate_self_signed_cert()
    else:
        logging.info("Server certificates are present.")

def generate_secure_context(is_server=False, server_hostname=None):
    """
    Generate a secure SSL context for a client or server.

    Args:
        is_server (bool): If True, generates a server context; otherwise, a client context.
        server_hostname (str): The expected hostname for SSL verification.

    Returns:
        ssl.SSLContext: The generated SSL context.
    """
    ensure_certificates()
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH)

    # Enhance security by disabling older, less secure protocols
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

    if is_server:
        try:
            # Load the server certificate and key
            context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
            logging.info("Loaded server certificates for SSL context.")
        except ssl.SSLError as ssl_error:
            logging.error(f"SSL error during server certificate loading: {ssl_error}")
            raise
        except FileNotFoundError as fnf_error:
            logging.error(f"File not found during server certificate loading: {fnf_error}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error loading server certificates: {e}")
            raise
    else:
        try:
            if DEVELOPMENT_MODE:
                # In development mode, bypass the verification to allow self-signed certificates
                context.check_hostname = False  # Ensure check_hostname is disabled before setting CERT_NONE
                context.verify_mode = ssl.CERT_NONE
                logging.warning("Development mode: SSL certificate verification is bypassed for self-signed certificates.")
            else:
                # Check for custom root CA or use the server certificate directly
                context.load_verify_locations(ROOT_CERT_FILE)
                logging.info("Client SSL context configured to trust the custom root CA's certificate.")
                context.verify_mode = ssl.CERT_REQUIRED

                # If a server hostname is provided, set it for verification
                if server_hostname:
                    context.check_hostname = True
                else:
                    context.check_hostname = False

        except ssl.SSLError as ssl_error:
            logging.error(f"SSL error during client context configuration: {ssl_error}")
            context.verify_mode = ssl.CERT_NONE
            raise
        except FileNotFoundError as fnf_error:
            logging.error(f"File not found during client context configuration: {fnf_error}")
            context.verify_mode = ssl.CERT_NONE
            raise
        except Exception as e:
            logging.error(f"Unexpected error configuring client SSL context: {e}")
            context.verify_mode = ssl.CERT_NONE
            raise

    return context

def generate_self_signed_cert():
    """
    Generate a self-signed root CA certificate and a server certificate signed by this root.
    """
    try:
        # Generate a private key for the root CA
        root_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create a self-signed root CA certificate
        root_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
        ])
        root_cert = x509.CertificateBuilder().subject_name(
            root_subject
        ).issuer_name(
            root_subject
        ).public_key(
            root_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(root_key, hashes.SHA256())

        # Save the root CA certificate and key
        root_cert_pem = root_cert.public_bytes(Encoding.PEM)
        root_key_pem = root_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )

        if not os.path.exists(CERT_DIR):
            os.makedirs(CERT_DIR)

        with open(ROOT_CERT_FILE, "wb") as cert_file:
            cert_file.write(root_cert_pem)
        with open(ROOT_KEY_FILE, "wb") as key_file:
            key_file.write(root_key_pem)

        logging.info(f"Generated root CA certificates at {ROOT_CERT_FILE} and {ROOT_KEY_FILE}.")

        # Generate a private key for the server
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create a server certificate signed by the root CA
        server_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        server_cert = x509.CertificateBuilder().subject_name(
            server_subject
        ).issuer_name(
            root_subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
            ]),
            critical=False,
        ).sign(root_key, hashes.SHA256())

        cert_pem = server_cert.public_bytes(Encoding.PEM)
        key_pem = key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption()
        )

        with open(CERT_FILE, "wb") as cert_file:
            cert_file.write(cert_pem)
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key_pem)

        logging.info(f"Generated server certificates at {CERT_FILE} and {KEY_FILE}.")

    except Exception as e:
        logging.error(f"Unexpected error during certificate generation: {e}")
        raise

def configure_ssl_socket(sock, is_server=False, server_hostname=None):
    """
    Wraps the socket with SSL for secure communication.

    Args:
        sock (socket.socket): The raw socket to wrap.
        is_server (bool): If True, configures as a server.
        server_hostname (str): Expected hostname for the SSL verification.

    Returns:
        ssl.SSLSocket: The wrapped SSL socket.
    """
    try:
        # Generate the SSL context
        context = generate_secure_context(is_server=is_server, server_hostname=server_hostname)

        # Wrap the socket with the context
        if is_server:
            ssl_sock = context.wrap_socket(sock, server_side=True)
            logging.info("Server SSL socket successfully wrapped.")
        else:
            ssl_sock = context.wrap_socket(sock, server_side=False, server_hostname=server_hostname)
            logging.info("Client SSL socket successfully wrapped and verified against the hostname.")

        return ssl_sock

    except ssl.CertificateError as cert_error:
        logging.error(f"Certificate error during SSL socket configuration: {cert_error}")
        raise
    except ssl.SSLError as ssl_error:
        logging.error(f"SSL error during socket configuration: {ssl_error}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during SSL socket configuration: {e}")
        raise

def validate_cert_chain(cert_path):
    """
    Validate the certificate chain to ensure the integrity of the SSL certificates.

    Args:
        cert_path (str): Path to the certificate file to validate.
    """
    if os.path.exists(cert_path):  # Only attempt to validate if the file exists
        try:
            with open(cert_path, "rb") as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data)

                # Ensure the certificate is not expired
                if cert.not_valid_after < datetime.datetime.utcnow():
                    logging.error(f"Certificate at {cert_path} has expired.")
                    raise ssl.SSLError(f"Certificate at {cert_path} has expired.")

                # Check if the certificate is self-signed
                if cert.issuer == cert.subject:
                    logging.warning(f"Certificate at {cert_path} is self-signed. Ensure this is intended for the use case.")

        except FileNotFoundError as fnf_error:
            logging.error(f"Certificate file not found at {cert_path}: {fnf_error}")
            raise
        except x509.UnsupportedAlgorithm as unsupported_algo:
            logging.error(f"Unsupported algorithm encountered in the certificate at {cert_path}: {unsupported_algo}")
            raise
        except ssl.SSLError as ssl_error:
            logging.error(f"SSL error during certificate validation: {ssl_error}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during certificate validation: {e}")
            raise
    else:
        logging.error(f"Certificate file at {cert_path} does not exist. Skipping validation.")

# Before using the certificates, validate them if they exist
validate_cert_chain(ROOT_CERT_FILE)
validate_cert_chain(CERT_FILE)
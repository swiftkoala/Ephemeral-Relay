from cryptography.fernet import Fernet
import hashlib
import hmac
import os

class Encryption:
    @staticmethod
    def generate_key():
        """Generate a key for Fernet symmetric encryption."""
        return Fernet.generate_key()

    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using Fernet symmetric encryption."""
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data.encode('utf-8'))
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using Fernet symmetric encryption."""
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

    @staticmethod
    def hash_data(data):
        """Hash data using SHA-256."""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        return sha256_hash.hexdigest()

    @staticmethod
    def generate_hmac(data, secret_key):
        """Generate HMAC using SHA-256."""
        hmac_digest = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        return hmac_digest.hexdigest()

    @staticmethod
    def verify_hmac(data, secret_key, hmac_to_verify):
        """Verify HMAC using SHA-256."""
        hmac_digest = hmac.new(secret_key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
        return hmac.compare_digest(hmac_digest.hexdigest(), hmac_to_verify)

    @staticmethod
    def generate_secure_random_key(length=32):
        """Generate a secure random key."""
        return os.urandom(length)
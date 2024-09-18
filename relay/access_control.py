import jwt
import datetime
from jwt import ExpiredSignatureError, InvalidTokenError
import logging

SECRET_KEY = 'your_secret_key'  # This should be stored securely and not hard-coded

class AccessControl:
    @staticmethod
    def generate_token(user_id):
        """Generate a JWT token for the user with an expiration time."""
        try:
            payload = {
                'user_id': user_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            logging.info(f"Token generated successfully for user_id: {user_id}")
            return token
        except Exception as e:
            logging.error(f"Error generating token for user_id {user_id}: {e}")
            return None

    @staticmethod
    def verify_token(token):
        """Verify the JWT token and return the user ID if valid."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload['user_id']
            logging.info(f"Token verified successfully for user_id: {user_id}")
            return user_id
        except ExpiredSignatureError:
            logging.warning("Token verification failed: Token has expired.")
            return None
        except InvalidTokenError as e:
            logging.warning(f"Token verification failed: Invalid token. Error: {e}")
            return None
        except Exception as e:
            logging.error(f"Unexpected error during token verification: {e}")
            return None
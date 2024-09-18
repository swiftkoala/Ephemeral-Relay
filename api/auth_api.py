from flask import Flask, request, jsonify
from relay.access_control import AccessControl
import logging

app = Flask(__name__)
access_control = AccessControl()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_json_key(json_data, key):
    """Utility function to validate if a key exists in JSON data."""
    if key not in json_data or not json_data[key]:
        raise ValueError(f"'{key}' is required and cannot be empty.")

@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler."""
    if isinstance(e, HTTPException):
        response = e.get_response()
        response.data = jsonify({'error': e.description})
        response.content_type = "application/json"
        return response
    logging.error(f"Unhandled Exception: {e}")
    return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and provide access token."""
    try:
        data = request.json
        validate_json_key(data, 'username')
        validate_json_key(data, 'password')

        username = data['username']
        password = data['password']

        token = access_control.authenticate(username, password)
        if token:
            logging.info(f"User '{username}' authenticated successfully.")
            return jsonify({'token': token}), 200
        else:
            logging.warning(f"Failed login attempt for user '{username}'.")
            return jsonify({'error': 'Invalid credentials'}), 401
    except ValueError as ve:
        logging.warning(f"Validation error in login: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Error in login endpoint: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/validate_token', methods=['POST'])
def validate_token():
    """Validate access token."""
    try:
        data = request.json
        validate_json_key(data, 'token')

        token = data['token']
        is_valid = access_control.validate_token(token)

        logging.info(f"Token validation requested. Token valid: {is_valid}")
        return jsonify({'valid': is_valid}), 200
    except ValueError as ve:
        logging.warning(f"Validation error in validate_token: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Error in validate_token endpoint: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=5001, debug=True)
    except Exception as e:
        logging.error(f"Failed to start API server: {e}")
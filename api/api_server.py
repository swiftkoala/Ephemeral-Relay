from flask import Flask, jsonify, request
from urllib.parse import quote as url_quote
import logging
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

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


@app.route('/api/encode_url', methods=['POST'])
def encode_url():
    """API endpoint to encode a given URL using URL quoting."""
    try:
        data = request.json.get('data')
        validate_json_key(request.json, 'data')

        encoded_url = url_quote(data)
        logging.info(f"URL encoded successfully: {encoded_url}")
        return jsonify({'encoded_url': encoded_url}), 200
    except ValueError as ve:
        logging.warning(f"Validation error in encode_url: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Error in encode_url endpoint: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """API endpoint for health checking the server."""
    logging.info("Health check requested.")
    return jsonify({'status': 'OK'}), 200


@app.route('/api/send_message', methods=['POST'])
def send_message():
    """API endpoint to send a message through the relay system."""
    try:
        message = request.json.get('message')
        validate_json_key(request.json, 'message')

        # Logic to send the message through the relay system
        # This should interact with the relay manager or relay client

        logging.info(f"Message sent: {message}")
        return jsonify({'status': 'Message sent successfully'}), 200
    except ValueError as ve:
        logging.warning(f"Validation error in send_message: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Error in send_message endpoint: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500


def start_api_server(config):
    """Function to start the API server."""
    try:
        host = config.get('api_host', '127.0.0.1')
        port = config.get('api_port', 5000)
        app.run(host=host, port=port)
    except Exception as e:
        logging.error(f"Failed to start API server: {e}")
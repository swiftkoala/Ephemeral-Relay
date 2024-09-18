from flask import Flask, request, jsonify
from relay.relay_manager import RelayManager

app = Flask(__name__)
relay_manager = RelayManager()

@app.route('/create_relay', methods=['POST'])
def create_relay():
    try:
        data = request.get_json()

        # Validate input data
        if not data:
            return jsonify({"error": "No data provided"}), 400

        host = data.get('host')
        port = data.get('port')
        lifetime = data.get('lifetime')

        if not host or not port or not lifetime:
            return jsonify({"error": "Missing required fields: host, port, and lifetime are required"}), 400

        # Create the relay
        relay_manager.create_relay(host, port, lifetime)
        return jsonify({"status": "Relay created successfully"}), 201

    except KeyError as ke:
        return jsonify({"error": f"Missing key in request data: {ke}"}), 400
    except Exception as e:
        return jsonify({"error": f"An error occurred while creating the relay: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
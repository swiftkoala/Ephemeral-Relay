import time
from flask import request, jsonify
import logging
from functools import wraps


class RateLimiter:
    def __init__(self, rate_limit=5, time_window=60):
        self.rate_limit = rate_limit
        self.time_window = time_window
        self.clients = {}

    def is_allowed(self, client_ip):
        """Check if the client is allowed to make a request."""
        current_time = time.time()

        # Initialize the client's request list if not present
        if client_ip not in self.clients:
            self.clients[client_ip] = []

        request_times = self.clients[client_ip]

        # Remove requests outside the time window
        self.clients[client_ip] = [t for t in request_times if current_time - t < self.time_window]

        if len(self.clients[client_ip]) < self.rate_limit:
            self.clients[client_ip].append(current_time)
            logging.info(f"Rate limit check passed for {client_ip}.")
            return True
        else:
            logging.warning(f"Rate limit exceeded for {client_ip}.")
            return False


rate_limiter = RateLimiter()


def rate_limit():
    """Rate limit decorator for Flask routes."""

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            if rate_limiter.is_allowed(client_ip):
                return f(*args, **kwargs)
            else:
                return jsonify({'error': 'Rate limit exceeded'}), 429

        return wrapper

    return decorator
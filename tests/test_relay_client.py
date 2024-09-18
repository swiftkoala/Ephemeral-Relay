import unittest
from unittest.mock import patch, MagicMock
from relay.relay_client import start_relay_client


class TestRelayClient(unittest.TestCase):
    def setUp(self):
        """Set up test parameters."""
        self.host = 'localhost'
        self.port = 8000
        self.message = "Test message"

    @patch('relay.relay_client.socket.create_connection')
    @patch('relay.relay_client.ssl.create_default_context')
    def test_client_initialization_and_connection(self, mock_ssl_context, mock_create_connection):
        """Test client initialization and successful connection to the relay server."""
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket
        mock_ssl_sock = MagicMock()
        mock_ssl_context.return_value.wrap_socket.return_value = mock_ssl_sock

        # Start the relay client
        start_relay_client(self.host, self.port, self.message)

        # Assert that a connection was attempted
        mock_create_connection.assert_called_once_with((self.host, self.port), timeout=10)
        # Assert that SSL context was created and socket wrapped
        mock_ssl_context.assert_called_once()
        mock_ssl_context.return_value.wrap_socket.assert_called_once_with(mock_socket, server_hostname=self.host)

    @patch('relay.relay_client.send_message')
    @patch('relay.relay_client.socket.create_connection')
    @patch('relay.relay_client.ssl.create_default_context')
    def test_send_message(self, mock_ssl_context, mock_create_connection, mock_send_message):
        """Test sending a message through the relay client."""
        mock_socket = MagicMock()
        mock_create_connection.return_value = mock_socket
        mock_ssl_sock = MagicMock()
        mock_ssl_context.return_value.wrap_socket.return_value = mock_ssl_sock

        # Start the relay client
        start_relay_client(self.host, self.port, self.message)

        # Assert that the send_message function was called
        mock_send_message.assert_called_once_with(mock_ssl_sock, self.message)


if __name__ == '__main__':
    unittest.main()
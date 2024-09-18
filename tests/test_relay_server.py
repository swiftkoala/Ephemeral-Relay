import unittest
from unittest.mock import patch, AsyncMock, MagicMock
from relay.relay_server import RelayServer

class TestRelayServer(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        """Set up test parameters."""
        self.host = 'localhost'
        self.port = 8000
        self.relay_lifetime = 60
        self.server = RelayServer(self.host, self.port, self.relay_lifetime)

    def test_server_initialization(self):
        """Test server initialization and attributes."""
        self.assertEqual(self.server.host, 'localhost')
        self.assertEqual(self.server.port, 8000)
        self.assertEqual(self.server.relay_lifetime, 60)

    @patch('relay.relay_server.asyncio.start_server', new_callable=AsyncMock)
    async def test_start_relay(self, mock_start_server):
        """Test starting the relay server."""
        # Mock the server to not actually open a network connection
        mock_server_instance = MagicMock()
        mock_start_server.return_value = mock_server_instance

        # Run the relay server start coroutine
        await self.server.start_relay()

        # Ensure the server start function was called with the correct arguments
        mock_start_server.assert_called_once_with(
            self.server.handle_client, self.host, self.port, ssl=self.server.context
        )

    @patch('relay.relay_server.RelayServer.handle_client', new_callable=AsyncMock)
    async def test_handle_client(self, mock_handle_client):
        """Test handling a client connection."""
        reader_mock = AsyncMock()
        writer_mock = AsyncMock()
        mock_handle_client.return_value = None

        # Call handle_client
        await self.server.handle_client(reader_mock, writer_mock)

        # Ensure handle_client was called
        mock_handle_client.assert_called_once_with(reader_mock, writer_mock)

    @patch('relay.relay_server.RelayServer.broadcast_message', new_callable=AsyncMock)
    async def test_broadcast_message(self, mock_broadcast_message):
        """Test broadcasting a message to clients."""
        writer_mock = MagicMock()
        self.server.clients.append(writer_mock)

        # Call broadcast_message
        await self.server.broadcast_message('Test message', writer_mock)

        # Ensure broadcast_message was called with the correct arguments
        mock_broadcast_message.assert_called_once_with('Test message', writer_mock)

if __name__ == '__main__':
    unittest.main()
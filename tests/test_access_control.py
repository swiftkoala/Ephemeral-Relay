import unittest
import time
from relay.access_control import AccessControl

class TestAccessControl(unittest.TestCase):
    def setUp(self):
        """Set up necessary variables for the tests."""
        self.user_id = 'user1'
        self.token = AccessControl.generate_token(self.user_id)

    def test_token_generation(self):
        """Test if token generation is successful and returns a valid token."""
        self.assertIsNotNone(self.token)
        self.assertIsInstance(self.token, str)
        print(f"Generated token: {self.token}")

    def test_token_verification(self):
        """Test if the generated token is valid and can be verified successfully."""
        verified_user_id = AccessControl.verify_token(self.token)
        self.assertEqual(verified_user_id, self.user_id)

    def test_token_expiry(self):
        """Test if the token expires correctly after the specified time."""
        # Sleep for a duration longer than the token's lifetime (assumed 30 seconds here)
        expired_token = AccessControl.generate_token(self.user_id)
        time.sleep(31)  # Adjust sleep time according to the actual token expiration setting
        expired_user_id = AccessControl.verify_token(expired_token)
        self.assertIsNone(expired_user_id)

    def test_invalid_token(self):
        """Test if an invalid token is correctly identified."""
        invalid_token = self.token + 'tampered'
        invalid_user_id = AccessControl.verify_token(invalid_token)
        self.assertIsNone(invalid_user_id)

if __name__ == '__main__':
    unittest.main()
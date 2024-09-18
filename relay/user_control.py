import uuid
import hashlib
import time


class UserControl:
    @staticmethod
    def create_anonymous_user():
        """
        Create an anonymous user with a unique identifier.

        Returns:
            str: A unique anonymous user identifier.
        """
        # Generate a unique identifier using UUID and timestamp
        unique_id = str(uuid.uuid4()) + str(time.time())

        # Hash the identifier to create a consistent, anonymous username
        anonymous_username = hashlib.sha256(unique_id.encode('utf-8')).hexdigest()

        return f"anonymous_{anonymous_username[:10]}"


# Example usage
if __name__ == "__main__":
    user_control = UserControl()
    anonymous_user = user_control.create_anonymous_user()
    print(f"Created anonymous user: {anonymous_user}")
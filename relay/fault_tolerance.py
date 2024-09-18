import time
import logging

class FaultTolerance:
    @staticmethod
    def retry_operation(operation, retries=3, delay=1, backoff_factor=2):
        """
        Retry an operation multiple times with exponential backoff.

        Args:
            operation (callable): The operation to be retried.
            retries (int): Number of times to retry the operation.
            delay (int): Initial delay in seconds between retries.
            backoff_factor (int): Multiplier for exponential backoff.
        """
        for attempt in range(1, retries + 1):
            try:
                operation()
                logging.info(f"Operation succeeded on attempt {attempt}.")
                break
            except Exception as e:
                logging.warning(f"Operation failed on attempt {attempt}. Error: {e}")
                if attempt < retries:
                    sleep_time = delay * (backoff_factor ** (attempt - 1))
                    logging.info(f"Retrying in {sleep_time} seconds...")
                    time.sleep(sleep_time)
                else:
                    logging.error(f"Operation failed after {retries} attempts.")

# Example usage:
# FaultTolerance.retry_operation(lambda: some_function_that_might_fail(), retries=5, delay=2, backoff_factor=3)
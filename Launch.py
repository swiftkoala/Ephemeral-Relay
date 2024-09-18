# Launch.py

import subprocess
import sys
import threading
import time

def run_script(script_name, *args):
    """Run a Python script with optional arguments."""
    try:
        print(f"Launching {script_name}...")
        result = subprocess.run([sys.executable, script_name] + list(args), check=True)
        print(f"{script_name} exited with code: {result.returncode}")
    except subprocess.CalledProcessError as e:
        print(f"Error running {script_name}: {e}")
    except Exception as e:
        print(f"Unexpected error while running {script_name}: {e}")

def main():
    # Start the main.py script in a separate thread
    print("Starting main.py in a separate thread...")
    main_thread = threading.Thread(target=run_script, args=('main.py',))
    main_thread.start()

    # Wait for a moment to ensure main.py initializes properly
    print("Waiting for main.py to initialize...")
    time.sleep(5)  # Increase delay to ensure full initialization

    # Start the first GUI instance
    print("Starting first gui_test.py in a separate thread...")
    gui_thread_1 = threading.Thread(target=run_script, args=('gui_test.py',))
    gui_thread_1.start()

    # Start the second GUI instance
    print("Starting second gui_test.py in a separate thread...")
    gui_thread_2 = threading.Thread(target=run_script, args=('gui_test.py',))
    gui_thread_2.start()

    # Wait a bit before starting the external entity
    time.sleep(2)

    # Start the external entity
    print("Starting external_entity.py in a separate thread...")
    external_entity_thread = threading.Thread(target=run_script, args=('external_entity.py',))
    external_entity_thread.start()

    # Check if the main script thread is still running
    if main_thread.is_alive():
        print("Launch.py: Main script and GUI instances launched successfully.")
    else:
        print("Launch.py: Main script failed to launch or terminated early.")

if __name__ == '__main__':
    main()
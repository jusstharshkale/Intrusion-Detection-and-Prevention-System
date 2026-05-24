import subprocess
import sys
import time
import os

def main():
    backend_process = None
    try:
        print("------------------------------------------------")
        print("    🛡️  STARTING HYBRID IDPS SYSTEM  🛡️")
        print("------------------------------------------------")

        # 1. Start the Flask Backend (app.py) as a subprocess
        print("[Launcher] Launching Backend Server...")
        # sys.executable ensures we use the same Python from your 'venv'
        backend_process = subprocess.Popen([sys.executable, "app.py"])

        # 2. Wait for Backend to initialize (2 seconds)
        print("[Launcher] Waiting for AI Model to load...")
        time.sleep(3) 

        # 3. Start the GUI (gui.py) and wait for it to close
        print("[Launcher] Launching GUI Dashboard...")
        subprocess.run([sys.executable, "gui.py"])

    except KeyboardInterrupt:
        print("\n[Launcher] Interrupted by user.")
    
    finally:
        # 4. Cleanup: When GUI closes, kill the backend
        if backend_process:
            print("------------------------------------------------")
            print("[Launcher] GUI Closed. Stopping Backend Server...")
            backend_process.terminate()
            backend_process.wait()
            print("[Launcher] System Shutdown Complete.")
            print("------------------------------------------------")

if __name__ == "__main__":
    main()
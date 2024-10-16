#######                              Working                                      ################
import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import ctypes  # For showing popup messages

# List of known encryption tools
KNOWN_ENCRYPTION_TOOLS = [
    "encrypt_tool.exe",
    "another_encryption_tool.exe",
    "ransomware_tool.exe"  # Add more known encryption tools here
]

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.encryption_detected = False
        self.suspicious_folder = ""

    def on_modified(self, event):
        if not event.is_directory:
            # Placeholder for actual encryption detection logic
            if self.is_encrypted(event.src_path):
                self.encryption_detected = True
                self.suspicious_folder = os.path.dirname(event.src_path)
                self.block_ransomware()
                self.show_warning_popup(self.suspicious_folder)

    def is_encrypted(self, file_path):
        # Placeholder for actual encryption detection logic
        return file_path.endswith(".encrypted")

    def block_ransomware(self):
        # Detect and terminate suspicious processes
        print("Blocking ransomware processes...")
        self.prevent_suspicious_file_execution()
        
        # You can add additional logic here to block ransomware in other ways
        print(f"Blocking ransomware in folder: {self.suspicious_folder}")

    def prevent_suspicious_file_execution(self):
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                process_name = process.info['name']
                cmdline = process.info['cmdline']
                # Convert cmdline to a string
                cmdline_str = ' '.join(cmdline) if cmdline else ""
                for tool in KNOWN_ENCRYPTION_TOOLS:
                    if tool in cmdline_str:
                        print(f"Suspicious process detected: {cmdline_str}")
                        process.terminate()
                        print(f"Terminated process: {cmdline_str}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def show_warning_popup(self, folder_path):
        ctypes.windll.user32.MessageBoxW(0, f"Ransomware activity detected in folder: {folder_path}", "Ransomware Alert", 1)

if __name__ == "__main__":
    path_to_monitor = "C:\\"  # Change to the path you want to monitor
    event_handler = RansomwareDetector()
    print("Started monitoring for ransomware activities.")
    observer = Observer()
    observer.schedule(event_handler, path_to_monitor, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

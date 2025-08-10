from datetime import datetime

def log_event(message: str, filename: str = "scanner.log"):
    """Append a log entry with timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(filename, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

if __name__ == "__main__":
    log_event("Test log entry")
    print("Test log written!")
from pathlib import Path

def path_data():
    current_dir = Path(__file__).parent
    file_path = current_dir.parent / 'data' / 'sites.txt'
    return file_path

POISONED_PREFIXES = ("10.", "127.", "0.0.0.", "169.254.", "192.168.", "172.16.")
DEFAULT_TIMEOUT   = 3.0
PORT_SCAN_THREADS = 100
import configparser
import requests
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import pytz
import time
from requests.auth import HTTPBasicAuth
from typing import List, Optional, Set
import hashlib
import os
import socket

# --- Constants ---
audit_filename = '/opt/sap/logs/audit.txt'
backup_filename = '/opt/sap/logs/audit.txt.1'
log_filename = '/opt/sap/logs/fetch_audit.log'
MAX_AUDIT_FILESIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_MAX_AGE_SECS = 3600  # 1 hour in seconds
MAX_RETRIES = 5
BASE_TIMEOUT = 60  # seconds
TCP_HOST = '127.0.0.1'
TCP_PORT = 12225

# --- Logging Setup ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
console_handler.setFormatter(console_formatter)

file_handler = RotatingFileHandler(log_filename, maxBytes=10*1024, backupCount=1, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
file_handler.setFormatter(file_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# --- Config load ---
config = configparser.ConfigParser()
if not config.read('credentials.conf'):
    logger.critical('Missing credentials.conf file; cannot continue.')
    exit(1)


def get_config_value(section: str, key: str, default: Optional[str] = None) -> str:
    try:
        return config[section][key]
    except KeyError:
        if default is not None:
            logger.warning(f"Config [{section}] '{key}' missing, using default: {default}")
            return default
        else:
            logger.critical(f"Config [{section}] '{key}' missing, aborting.")
            exit(1)


username = get_config_value('SAP', 'username')
password = get_config_value('SAP', 'password')
base_url = get_config_value('SAP', 'url')
timezone_str = get_config_value('SAP', 'timezone', 'Asia/Dubai')

try:
    tz = pytz.timezone(timezone_str)
except pytz.exceptions.UnknownTimeZoneError:
    logger.warning(f"Invalid timezone '{timezone_str}', defaulting to Asia/Dubai.")
    tz = pytz.timezone('Asia/Dubai')


# --- TCP Sender Class ---
class TcpLogSender:
    def __init__(self, host: str = TCP_HOST, port: int = TCP_PORT):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.connect()

    def connect(self) -> None:
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=10)
            logger.info(f"Connected to TCP {self.host}:{self.port} for log sending")
        except Exception as e:
            logger.error(f"Failed to connect to TCP {self.host}:{self.port}: {e}")
            self.sock = None

    def send(self, data: str) -> None:
        if not self.sock:
            self.connect()
        if self.sock:
            try:
                self.sock.sendall(data.encode('utf-8') + b'\n')
            except Exception as e:
                logger.error(f"Error sending log to TCP: {e}")
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# Instantiate global TCP sender
tcp_sender = TcpLogSender()


# --- Utility functions ---
def time_window(hours: int = 24) -> tuple[datetime, datetime]:
    now = datetime.now(tz)
    return now - timedelta(hours=hours), now


def format_window(dt: datetime) -> tuple[str, str]:
    return dt.strftime('%d.%m.%Y'), dt.strftime('%H:%M:%S')


def fetch_logs(start_dt: datetime, end_dt: datetime) -> Optional[List[dict]]:
    start_date, start_time = format_window(start_dt)
    end_date, end_time = format_window(end_dt)
    params = {
        'startdate': start_date,
        'enddate': end_date,
        'starttime': start_time,
        'endtime': end_time,
    }
    url = f"{base_url}&" + "&".join(f"{k}={v}" for k, v in params.items())

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=BASE_TIMEOUT,
                verify=False  # Set True with CA certs in production
            )
            response.raise_for_status()

            if not response.content.strip():
                logger.info("No logs returned in this window.")
                return []

            logs = response.json()
            if not isinstance(logs, list):
                logger.warning("Unexpected response format: expected list")
                return []

            return logs
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on attempt {attempt}/{MAX_RETRIES} for URL: {url}")
        except requests.RequestException as e:
            logger.error(f"HTTP error on attempt {attempt}/{MAX_RETRIES}: {e}")
            if attempt == MAX_RETRIES:
                return None
        except json.JSONDecodeError:
            logger.error("JSON decode error from response.")
            return None

        backoff = 2 ** attempt
        logger.debug(f"Sleeping {backoff}s before retrying...")
        time.sleep(backoff)

    logger.error(f"Exceeded max retries ({MAX_RETRIES}).")
    return None


def rotate_audit_file() -> None:
    try:
        if os.path.exists(backup_filename):
            backup_age = time.time() - os.path.getmtime(backup_filename)
            if backup_age > BACKUP_MAX_AGE_SECS:
                os.remove(backup_filename)
                logger.info(f"Removed old backup {backup_filename} (older than 1 hour)")

        if os.path.exists(audit_filename) and os.path.getsize(audit_filename) >= MAX_AUDIT_FILESIZE:
            if os.path.exists(backup_filename):
                os.remove(backup_filename)
            os.rename(audit_filename, backup_filename)
            logger.info(f"Rotated {audit_filename} to {backup_filename}")
    except Exception as e:
        logger.error(f"Error rotating audit file: {e}")


def load_existing_event_hashes(filename: str = audit_filename) -> Set[str]:
    seen_hashes = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                seen_hashes.add(hashlib.sha256(line.encode('utf-8')).hexdigest())
    except FileNotFoundError:
        pass
    return seen_hashes


def write_unique_logs(logs: List[dict], seen_hashes: Set[str], filename: str = audit_filename) -> None:
    rotate_audit_file()

    new_events = []
    for log in logs:
        json_line = json.dumps(log, ensure_ascii=False)
        event_hash = hashlib.sha256(json_line.encode('utf-8')).hexdigest()
        if event_hash not in seen_hashes:
            seen_hashes.add(event_hash)
            tcp_sender.send(json_line)
            new_events.append(json_line + '\n')

    if new_events:
        with open(filename, 'a', encoding='utf-8') as f:
            f.writelines(new_events)
        logger.info(f"Wrote and sent {len(new_events)} unique new logs")
    else:
        logger.info("No new unique logs to write or send")


def main() -> None:
    seen_hashes = load_existing_event_hashes()
    start_dt, end_dt = time_window(24)
    logs = fetch_logs(start_dt, end_dt)

    if logs is None:
        logger.error("Initial fetch failed.")
    else:
        write_unique_logs(logs, seen_hashes)
        logger.info(f"Initial fetch complete. Unique events tracked: {len(seen_hashes)}")

    last_end_dt = end_dt

    try:
        while True:
            time.sleep(60)
            now = datetime.now(tz)
            logs_new = fetch_logs(last_end_dt, now)
            if logs_new is None:
                logger.error("Failed to fetch new log window.")
            elif logs_new:
                write_unique_logs(logs_new, seen_hashes)
                logger.info(f"Fetched and sent {len(logs_new)} new logs at {now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
            else:
                logger.info(f"No new logs between {last_end_dt} and {now}")
            last_end_dt = now

    except KeyboardInterrupt:
        logger.info("Process terminated by user.")
        tcp_sender.close()


if __name__ == "__main__":
    main()

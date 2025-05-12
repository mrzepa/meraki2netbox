import logging
import json
import os
import threading
from datetime import datetime, timedelta
from icecream import ic
from typing import Dict, Any, Optional, Tuple, List
import time
import requests
import ipaddress
import urllib3
import config

logger = logging.getLogger(__name__)
filelock = threading.Lock()
site_data_lock = threading.Lock()
nominatim_lock = threading.Lock()
last_nominatim_request_time = 0.0

def setup_logging(min_log_level=logging.INFO):
    """
    Sets up logging to separate files for each log level.
    Only logs from the specified `min_log_level` and above are saved in their respective files.
    Includes console logging for the same log levels.

    :param min_log_level: Minimum log level to log. Defaults to logging.INFO.
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    if not os.access(logs_dir, os.W_OK):
        raise PermissionError(f"Cannot write to log directory: {logs_dir}")

    # Log files for each level
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Define a log format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set up file handlers for each log level
    for level_name, level_value in log_levels.items():
        if level_value >= min_log_level:
            log_file = os.path.join(logs_dir, f"{level_name.lower()}.log")
            handler = logging.FileHandler(log_file)
            handler.setLevel(level_value)
            handler.setFormatter(log_format)

            # Add a filter so only logs of this specific level are captured
            handler.addFilter(lambda record, lv=level_value: record.levelno == lv)
            logger.addHandler(handler)

    # Set up console handler for logs at `min_log_level` and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_log_level)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    logging.info(f"Logging is set up. Minimum log level: {logging.getLevelName(min_log_level)}")

def reverse_geocode(lat: float, lng: float) -> Optional[str]:
    """
    Perform reverse geocoding to get an address from latitude and longitude,
    ensuring no more than one request per second is made to Nominatim.

    Args:
        lat (float): Latitude.
        lng (float): Longitude.

    Returns:
        Optional[str]: The physical address or None if not found.
    """
    url = 'https://nominatim.openstreetmap.org/reverse'
    params = {
        'format': 'jsonv2',
        'lat': lat,
        'lon': lng,
        'addressdetails': 1,
    }
    global last_nominatim_request_time
    with nominatim_lock:
        current_time = time.time()
        time_since_last_request = current_time - last_nominatim_request_time
        if time_since_last_request < 1.0:
            # Need to wait for the remaining time
            time_to_wait = 1.0 - time_since_last_request
            logger.debug(f"Rate limiting in effect. Sleeping for {time_to_wait:.2f} seconds.")
            time.sleep(time_to_wait)
        # Update the last request time
        last_nominatim_request_time = time.time()
    # Make the request outside the lock to allow other threads to proceed
    try:
        response = requests.get(url, params=params, timeout=10, verify=False)
        response.raise_for_status()
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        data = response.json()
        address = data.get('display_name')
        return address
    except requests.RequestException as e:
        logger.error(f'Reverse geocoding failed: {e}')
        return None
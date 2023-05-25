import json
import os
import re
from scapy.all import ARP, Ether, srp
from datetime import datetime, timedelta

data_file = "scan_results.json"

# List of IP addresses or ranges to scan
ip_addresses = [
    "192.168.10.0/24",
    "192.168.20.0/24",
    "10.0.10.0/24",
    "10.0.20.0/24",
    "10.0.30.0/24",
    "10.0.40.0/24",
    "10.0.50.0/24",
    "10.0.60.0/24",
    "10.0.70.0/24",
    "10.0.80.0/24",
    "10.0.90.0/24",
]

# Add your custom MAC addresses and descriptions here
custom_mac_dict = {
    "e0:46:ee:20:69:aa": "Netgear Switch",
    "e0:46:ee:20:69:ab": "Netgear Switch",
}


def save_scan_results(scan_results, ip_range):
    if os.path.exists(data_file):
        with open(data_file, "r") as f:
            data = json.load(f)
    else:
        data = {}

    today = datetime.now().strftime("%Y-%m-%d")

    if today not in data:
        data[today] = {}

    if ip_range not in data[today]:
        data[today][ip_range] = []

    for result in scan_results:
        if result["mac"] not in [entry["mac"] for entry in data[today][ip_range]]:
            data[today][ip_range].append(result)

    # Remove data older than 14 days
    oldest_date = datetime.now() - timedelta(days=14)
    keys_to_remove = []
    for date_str in data:
        if datetime.strptime(date_str, "%Y-%m-%d") < oldest_date:
            keys_to_remove.append(date_str)

    for key in keys_to_remove:
        del data[key]

    with open(data_file, "w") as f:
        json.dump(data, f)

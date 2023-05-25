import json
import os
import re
from scapy.all import ARP, Ether, srp
from datetime import datetime, timedelta
from manuf import manuf

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


def scan_ip_range(ip_range):
    p = manuf.MacParser()
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    ans, _ = srp(arp_request, timeout=2, verbose=0)

    scan_results = []

    for sent, received in ans:
        mac = received[Ether].src
        ip = received[ARP].psrc

        if mac in custom_mac_dict:
            vendor = custom_mac_dict[mac]
        else:
            vendor = p.get_manuf(mac) or "None"

        scan_results.append({"ip": ip, "mac": mac, "vendor": vendor})

    return scan_results


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


def network_scan():
    for ip_range in ip_addresses:
        print(f"Scanning: {ip_range}")
        scan_results = scan_ip_range(ip_range)
        save_scan_results(scan_results, ip_range)
        unique_devices = len(set(result["mac"] for result in scan_results))
        print(f"Unique devices found in {ip_range}: {unique_devices}")


# Report function
def network_report(num_days=3):
    if os.path.exists(data_file):
        with open(data_file, "r") as f:
            data = json.load(f)
    else:
        print("No data found")
        return

    report_data = {}

    # Get the dates for the last num_days scans
    dates = sorted(data.keys(), reverse=True)[:num_days]

    # Build the report data
    for date in dates:
        report_data[date] = {}
        for ip_range, results in data[date].items():
            report_data[date][ip_range] = {
                "total_devices": len(results),
                "devices": results,
            }

    return report_data


if __name__ == "__main__":
    # Test the network_scan function
    print("Testing network_scan function...")
    network_scan()

    # Test the network_report function
    print("Testing network_report function...")
    report = network_report(3)
    print(json.dumps(report, indent=2))

"""Network scan tool with scapy"""
import scapy.all as scapy
import re
import manuf

# Add first 6 of mac for devices that often return None
vendor_mac = {
    "e0:46:rr": "Netgear",
}


def netscan(ip, subnet=24):
    """Scans the network and returns the devices"""
    # Verify valid IP address
    ip_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
    devices = []

    if ip:
        if ip_pattern.search(ip):
            ip_base = ".".join(ip.split(".")[:-1])
            ip_add_range = f"{ip_base}.0/{subnet}"
        else:
            return devices  # Empty list when invalid IP is given

    print(f"Scanning Network: {ip_add_range}")
    arp_result = scapy.arping(ip_add_range, verbose=False)

    m = manuf.MacParser()
    for result in arp_result[0]:
        ip = result[1].psrc
        mac = result[1].hwsrc
        vendor = m.get_manuf(mac)
        if vendor is None:
            if mac.startswith(tuple(vendor_mac.keys())):
                vendor = vendor_mac[mac[:8]]
            else:
                vendor = "None"
        devices.append({"ip": ip, "mac": mac, "vendor": vendor})

    return devices  # Returns list of devices


# TODO Need a way to handle each subnet, example if user enters 10.0.10.x change IP address to 10.0.10.11 before scan? Or maybe another way around it.

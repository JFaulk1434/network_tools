from scapy.all import ARP, Ether, srp, IP, TCP, sr1, ICMP
import manuf
import psutil
import socket
import speedtest
import time
import netifaces
from rich.pretty import pprint

m = manuf.MacParser()


def to_cidr(subnet_mask):
    return sum(bin(int(x)).count("1") for x in subnet_mask.split("."))


class Network_tools:
    def __init__(self, verbose=False) -> None:
        """Network tool class to help with a handful of useful network tools

        Args:
        verbose: default=False
            if True will print out information during each function that is ran."""
        self.verbose = verbose

    def net_scan(self, ip=None, subnet=24, verbose=None):
        """Scans the network and returns a list of devices that responded
        as a list of dictionaries

        Args:
        ip: default=None
            None will attempt to detect your IP address and Subnet to use
        subnet: default=24
        verbose: default=False
            if True will print results instead of returning
        """
        print("Scanning Network...")
        if verbose is None:
            verbose = self.verbose
        ip_range = f"{ip}/{subnet}"

        if ip == None:
            try:
                network = Network_tools.get_local_ip_and_subnet()
                ip_range = f"{network[0]}/{network[1]}"
                print("No IP entered... Attemping Auto...")
            except:
                print("Unable to detect network")

        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, verbose=False)
        devices = []

        if verbose:
            for _, rcv in answered:
                print(
                    f"IP: {rcv.psrc} \tMAC: {rcv.hwsrc} \t\tManufacture: {m.get_manuf_long(rcv.hwsrc)}"
                )

        for _, rcv in answered:
            device = {
                "ip": rcv.psrc,
                "mac": rcv.hwsrc,
                "manufacture": m.get_manuf_long(rcv.hwsrc),
            }
            devices.append(device)

        return devices

    def get_local_ip_and_subnet(self, verbose=None):
        """Checks for current LAN IP and returns the IP, Subnet
        example returned: '192.168.1.34', 24
        """
        if verbose is None:
            verbose = self.verbose

        try:
            local_ip = None
            subnet_mask = None
            cidr = None
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]

            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        if addr.address == local_ip:
                            subnet_mask = addr.netmask
                            cidr = to_cidr(subnet_mask)
                            break

            return local_ip, cidr
        except:
            print("Unable to get local IP address and subnet mask.")
            return None, None

    def tcp_port_scan(self, target_ip, start, end, verbose=None):
        print(f"Checking {target_ip} for open ports between {start}-{end}...")
        if verbose is None:
            verbose = self.verbose

        start_time = time.time()
        port_range = range(start, end)
        open_ports = []
        for port in port_range:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        end_time = time.time()
        if verbose:
            print(f"Scanning complete. Took {end_time - start_time:.2f} seconds.")
            print(f"{target_ip} has the following TCP ports open: {open_ports}")

        return open_ports

    def syn_port_scan(self, target_ip, start, end, verbose=None):
        """Use Scapy to do a Half-Open Scan SYN SCAN is less detectable but takes longer.
        Returns a list of open TCP Ports

        Args:
        target_ip: Target IP address
        start: Starting port number
        end: Ending port number
        versose: default=True
            Automatically prints results and returns
        """
        print(f"Checking {target_ip} for open ports between {start}-{end}...")
        if verbose is None:
            verbose = self.verbose

        start_time = time.time()
        port_range = range(start, end)
        open_ports = []
        for port in port_range:
            # Craft an IP packet with the target IP address
            ip_packet = IP(dst=target_ip)

            # Craft a TCP packet with the target port number
            # Flags 'S' for SYN
            tcp_packet = TCP(dport=port, flags="S")

            # Send the packet and receive a reply
            reply = sr1(ip_packet / tcp_packet, timeout=1, verbose=False)

            # Check if the port is open
            if reply is not None and reply.haslayer(TCP):
                if reply[TCP].flags == "SA":  # SYN-ACK indicates the port is open
                    open_ports.append(port)
        end_time = time.time()
        if verbose:
            print(f"Scanning complete. Took {end_time - start_time:.2f} seconds.")
            print(f"{target_ip} has the following TCP ports open: {open_ports}")
        return open_ports

    def grab_banner(self, target_ip, port, verbose=None):
        """Grab the Banner of a port on an IP address.
        Returns banner or None from IP/Port.

        Args:
        target_ip: Target IP address
        port: port to grab banner from
        """
        if verbose is None:
            verbose = self.verbose

        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target_ip, port))
            banner = s.recv(1024)
            return banner.decode().strip()
        except:
            return None

    def trace_route(self, target_ip, max_hops=30, timeout=2, verbose=None):
        """Runs a trace route to the target IP address
        Returns a dictionary of the hops and the time taken for each

        Args:
        target_ip: IP address you want to trace the route too
        max_hops: default=30
            max amount of hops to target_ip
        timeout: default=2
            seconds until timeout between hops
        verbose: default=True
            if True will print out the results
        """
        if verbose is None:
            verbose = self.verbose
        hop_dict = {}
        total_time = 0

        if verbose:
            print(f"Tracing route to {target_ip} with a maximum of {max_hops} hops.\n")

        for ttl in range(1, max_hops + 1):
            # Craft an IP packet with the target IP address and TTL value
            ip_packet = IP(dst=target_ip, ttl=ttl)

            # Craft an ICMP packet
            icmp_packet = ICMP()

            # Combine the IP and ICMP packets
            packet = ip_packet / icmp_packet

            # Record start time
            start_time = time.time()

            # Send the packet and receive the reply
            reply = sr1(packet, timeout=timeout, verbose=False)

            # Record end time
            end_time = time.time()

            # Calculate the time difference
            elapsed_time = round(end_time - start_time, 2)
            total_time += elapsed_time

            if reply is None:
                hop_info = "*"
            elif reply.haslayer(ICMP):
                if reply[ICMP].type == 11 and reply[ICMP].code == 0:
                    hop_info = reply.src
                elif reply[ICMP].type == 0:
                    hop_info = reply.src
                    if verbose:
                        print(f"{ttl}:\t{hop_info} in {elapsed_time}s\nTrace complete.")
                    hop_dict[ttl] = {"ip": hop_info, "time": elapsed_time}
                    break

            hop_dict[ttl] = {"ip": hop_info, "time": elapsed_time}

            if verbose:
                print(f"{ttl}:\t{hop_info} in {elapsed_time}s")

        hop_dict["total_time"] = round(total_time, 2)
        return hop_dict

    def speed_test(self, verbose=None):
        """Runs an Internet speedtest and returns a dictionary of the results

        Args:
        verbose: default=False
            if verbose=True will print results
        """
        if verbose is None:
            verbose = self.verbose

        s = speedtest.Speedtest()
        s.get_best_server()

        if verbose:
            print("Testing download speed...")
        download_speed = s.download() / 1_000_000

        if verbose:
            print("Testing upload speed...")
        upload_speed = s.upload() / 1_000_000

        ping_time = s.results.ping

        # Get the server information
        server_name = s.results.server.get("name", "Unknown")
        server_host = s.results.server.get("host", "Unknown")
        server_country = s.results.server.get("country", "Unknown")
        server_id = s.results.server.get("id", "Unknown")

        # Get the client information
        client_ip = s.results.client.get("ip", "Unknown")
        client_isp = s.results.client.get("isp", "Unknown")
        client_isp_rating = s.results.client.get("isprating", "Unknown")
        client_country = s.results.client.get("country", "Unknown")

        results = {
            "download_speed": f"{download_speed:.2f} Mbps",
            "upload_speed": f"{upload_speed:.2f} Mbps",
            "ping": f"{ping_time:.2f}ms ",
            "server_name": server_name,
            "server_host": server_host,
            "server_country": server_country,
            "server_id": server_id,
            "client_ip": client_ip,
            "client_isp": client_isp,
            "client_isp_rating": client_isp_rating,
            "client_country": client_country,
        }

        if verbose:
            pprint(results)
        return results

    def get_network_info(self, verbose=None):
        """Gets your computers networking interfaces information.
        Returns a dictionary of all of the interfaces

        Args:
        verbose: default=True
            if verbose=True will print out the interfaces
        """
        if verbose is None:
            verbose = self.verbose

        network_info = {}
        for interface, addrs in psutil.net_if_addrs().items():
            if_info = {}
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    if_info["IPv4"] = addr.address
                    if_info["Netmask"] = addr.netmask
                elif addr.family == socket.AF_INET6:  # IPv6
                    if_info["IPv6"] = addr.address
                elif addr.family == psutil.AF_LINK:  # MAC Address
                    if_info["MAC"] = addr.address

            if "IPv4" in if_info:
                network_info[interface] = if_info

                if verbose:
                    message = f"""
        Interface: {interface}:
            IPv4:    {if_info.get("IPv4")}
            Netmask: {if_info.get("Netmask")}
            IPv6:    {if_info.get("IPv6").split('%')[0]}
            MAC:     {if_info.get("MAC")}
        """
                    print(message)

        gws = netifaces.gateways()
        default_gateway = gws.get("default")
        if default_gateway:
            ipv4_gw = default_gateway.get(netifaces.AF_INET)
            if ipv4_gw:
                network_info["Gateway"] = ipv4_gw[0]

        return network_info


if __name__ == "__main__":
    net = Network_tools(
        verbose=True
    )  # Set verbose=True to print when running methods. False to only return the values.
    # devices = net.net_scan(verbose=True)
    # print(net.tcp_port_scan("192.168.50.200", 0, 5000))
    # print(net.syn_port_scan("192.168.50.200", 0, 5000))
    # print(net.trace_route("8.8.8.8", verbose=False))
    # net.speed_test(verbose=True)
    # net.get_network_info()

    # Get Network Information
    net.get_network_info()

    # Get local IP and scan network
    ip, subnet = net.get_local_ip_and_subnet()
    online_devices = net.net_scan(ip, subnet)

    # Scan ports on 5th device from net_scan
    open_ports = net.tcp_port_scan(online_devices[4]["ip"], 1, 100)

    # Check for banners on each port
    for port in open_ports:
        banner = net.grab_banner(online_devices[4]["ip"], port)
        print(f"Banner: {banner} Port: {port}")

    # Trace route
    net.trace_route("8.8.8.8")

    # Speed Test
    net.speed_test()

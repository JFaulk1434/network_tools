import logging


# Suppresses Scapy no address on IPv4 on MacOS for interfaces not being used.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


from scapy.all import ARP, Ether, srp, IP, TCP, sr1, ICMP
import manuf
import psutil
import socket
import speedtest
import time
import platform
import subprocess

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

    def net_scan(self, ip=None, subnet=24, verbose=None) -> list:
        """Scans the network and returns a list of devices that responded
        as a list of dictionaries

        Args:
        ip: default=None
            None will attempt to detect your IP address and Subnet to use
        subnet: default=24
        verbose: default=False
            if True will print results instead of returning
        """
        print("Scanning Network...\n")
        if verbose is None:
            verbose = self.verbose
        ip_range = f"{ip}/{subnet}"

        if ip == None:
            try:
                print("No IP entered... Attemping Auto...")
                network = self.get_local_ip_and_subnet()
                print(f"Network detected: {network[0]}/{network[1]}\n")

                ip_range = f"{network[0]}/{network[1]}"

            except:
                print("Unable to detect network")
                ip_range = input(
                    "Please enter network with subnet example: 192.168.1.1/24"
                )

        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, verbose=False)
        devices = []

        if verbose:
            for _, rcv in answered:
                print(
                    f"IP: {rcv.psrc:<15} MAC: {rcv.hwsrc:<20} Manufacture: {m.get_manuf_long(rcv.hwsrc)}"
                )
            print("\n\n")

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

    def tcp_port_scan(self, target_ip, start=1, end=500, verbose=None) -> list:
        """Scans TCP ports on target ip using standard TCP Discovery.


        Args:
        ip: IP address you want to scan
        start: default=1
            Starting port
        end: default=2
            Ending port
        verbose: default=True
            if True will print out the results
        """
        print(f"Checking {target_ip} for open ports between {start}-{end}...\n")
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
            print(f"{target_ip} has the following TCP ports open: {open_ports}\n\n")

        return open_ports

    def syn_port_scan(self, target_ip, start, end, verbose=None) -> list:
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

    def grab_banner(self, target_ip, ports, verbose=None) -> dict:
        """Grab the Banner of a port on an IP address.
        Returns a dictionary of port-banner pairs from IP/Port(s).

        Args:
        target_ip: Target IP address
        ports: port or list of ports to grab banner from
        """
        if verbose is None:
            verbose = self.verbose

        banners = {}

        if not isinstance(ports, list):
            ports = [ports]

        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect((target_ip, port))
                banner = s.recv(1024)
                banners[port] = banner.decode().strip()
            except:
                banners[port] = None

        if verbose:
            print("Banners:\n")
            pprint(banners)
            print("\n\n")

        return banners

    def trace_route(self, target_ip, max_hops=15, timeout=2, verbose=None) -> dict:
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
            ip_packet = IP(dst=target_ip, ttl=ttl)
            icmp_packet = ICMP()
            packet = ip_packet / icmp_packet

            start_time = time.time()
            reply = sr1(packet, timeout=timeout, verbose=False)
            end_time = time.time()

            elapsed_time = round(end_time - start_time, 2)
            total_time += elapsed_time

            hop_info = "*"
            if reply is not None and reply.haslayer(ICMP):
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

        if verbose:
            print(f"Total Time: {round(total_time, 2)}s\n")

        hop_dict["total_time"] = round(total_time, 2)

        return hop_dict

    def speed_test(self, verbose=None) -> dict:
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

        # Get the client information
        client_ip = s.results.client.get("ip", "Unknown")
        client_isp = s.results.client.get("isp", "Unknown")
        client_country = s.results.client.get("country", "Unknown")

        results = {
            "download_speed": f"{download_speed:.2f} Mbps",
            "upload_speed": f"{upload_speed:.2f} Mbps",
            "ping": f"{ping_time:.2f}ms ",
            "server_name": server_name,
            "server_host": server_host,
            "server_country": server_country,
            "client_ip": client_ip,
            "client_isp": client_isp,
            "client_country": client_country,
        }

        if verbose:
            pprint(results)
        return results

    def get_default_gateway(self):
        try:
            system = platform.system().lower()
            default_gateway = None

            if system == "linux":
                proc = subprocess.Popen(
                    ["ip", "route", "show", "default"], stdout=subprocess.PIPE
                )
                stdout, _ = proc.communicate()
                default_route_line = stdout.decode("utf-8").strip().split("\n")[0]
                default_gateway = default_route_line.split(" ")[2]

            elif system == "windows":
                proc = subprocess.Popen(["ipconfig"], stdout=subprocess.PIPE)
                stdout, _ = proc.communicate()
                lines = stdout.decode("utf-8").strip().split("\n")
                for line in lines:
                    if "Default Gateway" in line:
                        default_gateway = line.split(":")[1].strip()

            elif system == "darwin":  # macOS
                proc = subprocess.Popen(["netstat", "-nr"], stdout=subprocess.PIPE)
                stdout, _ = proc.communicate()
                lines = stdout.decode("utf-8").strip().split("\n")
                for line in lines:
                    if "default" in line:
                        default_gateway = line.split()[1]

            return default_gateway

        except Exception as e:
            print(f"An error occurred: {e}")
            return None

    def get_network_info(self, verbose=None) -> dict:
        """Gets your computers networking interfaces information.
        Returns a dictionary of all of the interfaces

        Args:
        verbose: default=True
            if verbose=True will print out the interfaces
        """
        print("Checking Network Interfaces...\n")
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

        default_gateway = self.get_default_gateway()
        if default_gateway:
            network_info["Gateway"] = default_gateway

        return network_info

    @staticmethod
    def demo():
        print("This is a demo of network tools")
        print("You can create the class with net = Network_tools(verbose=True)")
        print(
            "with verbose=True will printout all information, verbose=False will only print minimal"
        )
        print("Creating object using: net = Network_tools(verbose=True)")
        net = Network_tools(verbose=True)

        print("Running net.get_network_info()")
        net.get_network_info()

        print("Getting IP / Subnet with: ip, subnet = net.get_local_ip_and_subnet()")
        ip, subnet = net.get_local_ip_and_subnet()

        print(
            "Getting devices online in network with: online_devices = net.net_scan(ip, subnet)"
        )
        online_devices = net.net_scan(ip, subnet)

        print(
            "Checking 2nd device for open ports: open_ports = net.tcp_port_scan(online_devices[1], open_ports)"
        )
        open_ports = net.tcp_port_scan(online_devices[1]["ip"], 1, 100)

        print(
            'Checking for banners on each port: net.grab_banner(online_devices[1]["ip"], open_ports)'
        )
        net.grab_banner(online_devices[1]["ip"], open_ports)

        print('Run a traceroute: net.trace_route("8.8.8.8")')
        net.trace_route("8.8.8.8")

        print("Run a bandwidth speed test: net.speed_test()")
        net.speed_test()

        print("Demo Complete...")


if __name__ == "__main__":
    net = Network_tools(verbose=True)

    net.get_network_info()

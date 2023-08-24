import scapy.all as scapy


def port_scan(target_ip, min_port=1, max_port=100):
    target_ports = range(int(min_port), int(max_port) + 1)
    open_ports = []

    for port in target_ports:
        tcp_scan = scapy.TCP(sport=scapy.RandShort(), dport=port, flags="S")
        ip_packet = scapy.IP(dst=target_ip) / tcp_scan
        response = scapy.sr1(ip_packet, timeout=2, verbose=0)

        if response is not None and response.haslayer(scapy.TCP):
            if response[scapy.TCP].flags == 18:  # 18 represents SYN-ACK
                open_ports.append(port)

    return open_ports

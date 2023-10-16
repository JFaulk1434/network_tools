import argparse
from network_tools import Network_tools  # Make sure to import your class properly


def main():
    parser = argparse.ArgumentParser(description="Network tools CLI.")

    parser.add_argument(
        "--scan", action="store_true", help="Scan the network for devices."
    )
    parser.add_argument(
        "--local", action="store_true", help="Get the local IP and subnet."
    )
    parser.add_argument(
        "--tcp-scan",
        nargs=3,
        metavar=("IP", "START", "END"),
        help="TCP port scan on given IP from START to END port.",
    )
    # ... add more args for other methods

    args = parser.parse_args()
    net_tools = Network_tools(verbose=True)

    if args.scan:
        net_tools.net_scan()

    if args.local:
        net_tools.get_local_ip_and_subnet()

    if args.tcp_scan:
        ip, start, end = args.tcp_scan
        net_tools.tcp_port_scan(ip, int(start), int(end))

    # ... handle other args


if __name__ == "__main__":
    main()

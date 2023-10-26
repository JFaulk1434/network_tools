from nettools.network_tools import Network_tools
from nettools.network_tools import PortScanner
import click

net = Network_tools(verbose=True)
scanner = PortScanner()


def print_header(text, total_length=60, symbol="-"):
    remaining_space = total_length - len(text)
    num_symbols = remaining_space // 2

    # Create the box borders
    border = symbol * total_length

    # Create the header with the text
    header = f"{symbol * num_symbols}{text}{symbol * num_symbols}"

    # Add an extra symbol if the total_length is odd
    if remaining_space % 2 == 1:
        header += symbol

    print(border)
    print(header)
    print(border)


@click.group()
def cli():
    """Version:1.1
    This CLI tool is a Swiss Army knife for network tasks. It offers a range of utilities,
    from scanning local networks and checking open ports to running speed tests and
    tracing routes to a specific IP. It's designed to be a one-stop-shop for
    basic network diagnostics and information gathering."""


@cli.command()
@click.option(
    "--ip", "-i", default=None, help="IP address, left blank will try to auto detect"
)
@click.option("--subnet", "-s", default="24", help="Subnet to scan")
def net_scan(ip, subnet):
    """Scans the network and shows all devices found"""
    net.net_scan(ip, subnet)


@cli.command()
@click.argument("ip")
@click.argument("start", default=1)
@click.argument("end", default=500)
def port_scan(ip, start, end):
    """Scans TCP ports on target ip using standard TCP Discovery"""
    ports = scanner.tcp_port_scan(ip, start, end)
    net.grab_banner(ip, ports)


@cli.command()
@click.argument("ip")
@click.option("--hops", "-h", default=15, help="Max amount of hops to try")
@click.option(
    "--timeout", "-t", default=2, help="Amount of time before timeout on each hop"
)
def trace_route(ip, hops=15, timeout=2):
    """Runs a trace route to the target IP address"""
    net.trace_route(ip, hops, timeout)


@cli.command()
def speed_test():
    """Runs an Internet speedtest"""

    net.speed_test()


@cli.command()
def network_info():
    """Gets your computers networking interfaces information."""
    net.get_network_info()


@cli.command()
def demo():
    """Runs a demo of all the network tools"""
    print_header("net-scan")
    devices = net.net_scan()

    print_header("network-info")
    net.get_network_info()

    print_header("port-scan")
    try:
        ip = devices[1].get("ip")
        ports = scanner.tcp_port_scan(ip, 1, 500)
    except:
        print(f"{ip} has no open ports")

    print_header("speed-test")
    net.speed_test()

    print_header("synport-scan")
    scanner.syn_port_scan(ip, 1, 500)

    print_header("trace-route")
    net.trace_route("8.8.8.8")

    print_header("Demo Complete")


@cli.command()
@click.argument("ip")
@click.argument("start", default=1)
@click.argument("end", default=500)
def synport_scan(ip, start, end):
    """Half-Open Scan SYN is less detectable but slower"""
    ports = scanner.syn_port_scan(ip, start, end)
    net.grab_banner(ip, ports)


if __name__ == "__main__":
    cli()

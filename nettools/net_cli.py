from nettools.network_tools import Network_tools
from nettools.network_tools import PortScanner
import click

net = Network_tools(verbose=True)
scanner = PortScanner()


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
    try:
        net.speed_test()
    except:
        print("Servers are busy try again in a few mins...")


@cli.command()
def network_info():
    """Gets your computers networking interfaces information."""
    net.get_network_info()


@cli.command()
def demo():
    """Runs a demo of all the network tools"""
    net.demo()


@cli.command()
@click.argument("ip")
@click.option("--start", "-s", default=1, help="Starting port")
@click.option("--end", "-e", default=500, help="Ending port to scan")
def synport_scan(ip, start, end):
    """Half-Open Scan SYN is less detectable but slower"""
    ports = scanner.syn_port_scan(ip, start, end)
    net.grab_banner(ip, ports)


if __name__ == "__main__":
    cli()

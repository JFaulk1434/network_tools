from nettools.network_tools import Network_tools
import click

net = Network_tools(verbose=True)


@click.group()
def cli():
    """A handful of network tools"""


@cli.command()
@click.option(
    "--ip", "-i", default=None, help="IP address, left blank will try to auto detect"
)
@click.option("--subnet", "-s", default="24", help="Subnet to scan")
@click.option(
    "--verbose",
    "-v",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def net_scan(ip, subnet, verbose):
    """Scans the network and shows all devices found"""
    net.net_scan(ip, subnet, verbose)


@cli.command()
@click.argument("ip")
@click.argument("start", default=1)
@click.argument("end", default=100)
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def port_scan(ip, start, end, verbose=True):
    """Scans TCP ports on target ip using standard TCP Discovery"""
    net.tcp_port_scan(ip, start, end, verbose)


@cli.command()
@click.argument("ip")
@click.option("--hops", "-h", default=15, help="Max amount of hops to try")
@click.option(
    "--timeout", "-t", default=2, help="Amount of time before timeout on each hop"
)
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def trace_route(ip, hops=15, timeout=2, verbose=True):
    """Runs a trace route to the target IP address"""
    net.trace_route(ip, hops, timeout, verbose)


@cli.command()
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def speed_test(verbose=True):
    """Runs an Internet speedtest and returns a dictionary of the results

    Args:
    verbose: default=False
        if verbose=True will print results
    """
    try:
        net.speed_test(verbose)
    except:
        print("Servers are busy try again in a few mins...")


@cli.command()
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def network_info(verbose=True):
    """Gets your computers networking interfaces information."""
    net.get_network_info(verbose)


@cli.command()
def demo():
    """Runs a demo of all the network tools"""
    net.demo()


if __name__ == "__main__":
    cli()

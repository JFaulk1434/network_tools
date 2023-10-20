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
    """Scans the network and returns a list of devices that responded
    as a list of dictionaries

    Args:
    ip: default=None
        None will attempt to detect your IP address and Subnet to use
    subnet: default=24
    verbose: default=False
        if True will print results instead of returning
    """
    net.net_scan(ip, subnet, verbose)


@cli.command()
@click.argument("ip")
@click.option("--start", "-s", default=1, help="Starting port number")
@click.option("--end", "-e", default=500, help="Ending port number")
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def port_scan(ip, start, end, verbose=True):
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
    net.tcp_port_scan(ip, start, end, verbose)


@cli.command()
@click.option("--ip", default=None, help="IPv4 address of device to scan")
@click.option("--hops", default=15, help="Max amount of hops to try")
@click.option("--timeout", default=2, help="Amount of time before timeout on each hop")
@click.option(
    "--verbose",
    default=True,
    is_flag=True,
    help="Verbose Mode, True will print out more information",
)
def trace_route(ip, hops=15, timeout=2, verbose=True):
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
    """Gets your computers networking interfaces information.
    Returns a dictionary of all of the interfaces

    Args:
    verbose: default=True
        if verbose=True will print out the interfaces
    """
    net.get_network_info(verbose)


@cli.command()
def demo():
    """Runs a demo of all the network tools"""
    net.demo()


if __name__ == "__main__":
    cli()

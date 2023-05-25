from django.http import HttpResponse
from django.shortcuts import render
import speedtest_cli as st
from rich.style import Style
from rich.table import Table
from rich.console import Console
from rich import print

header_style = Style(color="cyan")


def bandwidth_test(request):
    """
    Test the download and upload speeds of the network connection.
    """

    servers = []

    threads = None

    s = st.Speedtest()
    s.get_servers(servers)
    s.get_best_server()

    # Run the download and upload speed tests
    console = Console()
    console.print(f"[green]Testing Download Speed...[/green]")
    download_speed = s.download() / 1_000_000
    console.print(f"[green]Testing Upload Speed...[/green]")
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

    # Pack the results into dictionaries
    results_dict = {
        "Download": f"{download_speed:.2f} Mbps",
        "Upload": f"{upload_speed:.2f} Mbps",
        "Ping": f"{ping_time:.2f} ms",
    }

    server_dict = {
        "Name": server_name,
        "Host": server_host,
        "Country": server_country,
    }
    client_dict = {
        "IP": client_ip,
        "ISP": client_isp,
        "ISP Rating": client_isp_rating,
        "Country": client_country,
    }

    # Create the results table
    results = Table(title="Results", header_style=header_style)
    results.add_column("Download", justify="left")
    results.add_column("Upload", justify="left")
    results.add_column("Ping", justify="left")
    results.add_row(
        f"{download_speed:.2f} Mbps", f"{upload_speed:.2f} Mbps", f"{ping_time:.2f} ms"
    )

    # Create the Client Info table
    client = Table(title="Client Info", header_style=header_style)
    client.add_column("IP Address")
    client.add_column("ISP")
    client.add_column("Rating")
    client.add_row(client_ip, client_isp, client_isp_rating)

    # Create the Server Info table
    server = Table(title="Server Info", header_style=header_style)
    server.add_column("Name")
    server.add_column("Host")
    server.add_column("Country")
    server.add_row(server_name, server_host, server_country)

    context = {
        "results_table": results,
        "client_table": client,
        "server_table": server,
    }

    return render(request, "bandwidth_test.html", context)


if __name__ == "__main__":
    s = st.Speedtest()
    download = s.download()
    print(download)
# You may need to adjust the template name and route to match your Django project.
# Also, make sure you have the appropriate template file in your Django templates directory.

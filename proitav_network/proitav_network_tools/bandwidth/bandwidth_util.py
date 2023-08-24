import speedtest_cli as st


def bandwidth_test():
    """
    Test the download and upload speeds of the network connection.
    """

    s = st.Speedtest()
    s.get_best_server()

    # Run the download and upload speed tests
    download_speed = s.download() / 1_000_000
    upload_speed = s.upload() / 1_000_000
    ping_time = s.results.ping

    # Get the server information
    server_name = s.results.server.get("name", "Unknown")
    server_host = s.results.server.get("host", "Unknown")
    server_country = s.results.server.get("country", "Unknown")

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
        "ISPRating": client_isp_rating,
        "Country": client_country,
    }

    context = {
        "results": results_dict,
        "server": server_dict,
        "client": client_dict,
    }

    return context

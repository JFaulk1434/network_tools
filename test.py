import subprocess


def scan_wifi_channels():
    try:
        # Wi-Fi interface name
        interface_name = "en0"

        # Get the Wi-Fi information including channels
        wifi_info = subprocess.run(
            ["networksetup", "-getairportnetwork", interface_name],
            capture_output=True,
            text=True,
        )
        wifi_output = wifi_info.stdout

        # Print the Wi-Fi information
        print(wifi_output)
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    scan_wifi_channels()

import os


def scan_wifi_channels():
    try:
        # Run the airport command to scan for Wi-Fi networks and store the output in a file
        os.system(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s > wifi_scan.txt"
        )

        # Read the output from the file
        with open("wifi_scan.txt", "r") as file:
            output = file.read()

        # Check if the command was successful
        if "error" not in output.lower():
            lines = output.splitlines()

            # Create a dictionary to store channel information
            channel_info = {}

            for line in lines[1:]:  # Skip the header line
                fields = line.split()
                channel_str = fields[0]
                ssid = " ".join(
                    fields[4:]
                )  # Join all fields after the fourth one as the SSID

                try:
                    channel = int(channel_str)
                except ValueError:
                    # Skip lines with non-numeric channel values
                    continue

                if channel not in channel_info:
                    channel_info[channel] = []

                channel_info[channel].append(ssid)

            # Print channel information
            for channel, networks in channel_info.items():
                print(f"Channel {channel}:")
                for ssid in networks:
                    print(f"  SSID: {ssid}")
        else:
            print("Error: Unable to run airport command.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    scan_wifi_channels()

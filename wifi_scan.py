import os
import re


def scan_wifi_channels():
    try:
        os.system(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s > wifi_scan.txt"
        )

        with open("wifi_scan.txt", "r") as file:
            output = file.readlines()

        channel_info = {}

        pattern = re.compile(r"([^\s]+)\s+(-\d+)\s+(\d+)(?:,\+1)?\s+")

        for line in output[1:]:
            match = pattern.search(line)
            if match:
                ssid, rssi, channel_str = match.groups()
                channel = int(channel_str)
                rssi = int(rssi)

                if channel not in channel_info:
                    channel_info[channel] = []

                channel_info[channel].append((ssid, rssi))

        for channel, networks in channel_info.items():
            print(f"Channel {channel}:")
            for ssid, rssi in networks:
                print(f"  SSID: {ssid}, RSSI: {rssi}")

    except Exception as e:
        print(f"An error occurred: {e}")

    channel_strength_24GHz = {}
    channel_strength_5GHz = {}

    for channel, networks in channel_info.items():
        total_rssi = sum(rssi for _, rssi in networks)

        if channel <= 14:
            channel_strength_24GHz[channel] = total_rssi
        else:
            channel_strength_5GHz[channel] = total_rssi

    # Sort and pick the cleanest for each band
    cleanest_channel_24GHz = sorted(channel_strength_24GHz.items(), key=lambda x: x[1])[
        0
    ][0]
    cleanest_channel_5GHz = sorted(channel_strength_5GHz.items(), key=lambda x: x[1])[
        0
    ][0]
    # Sort and pick the top 3 cleanest channels for 5GHz
    top_3_channels_5GHz = sorted(channel_strength_5GHz.items(), key=lambda x: x[1])[:3]
    top_3_channels_5GHz = [channel for channel, _ in top_3_channels_5GHz]

    print(f"The cleanest 2.4GHz channel is: {cleanest_channel_24GHz}")
    print(f"The cleanest 5GHz channel is: {cleanest_channel_5GHz}")
    print(f"The top 3 cleanest 5GHz channels are: {top_3_channels_5GHz}")


if __name__ == "__main__":
    scan_wifi_channels()

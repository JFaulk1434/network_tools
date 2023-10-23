import os
import subprocess


def scan_wifi_channels_windows():
    try:
        output = subprocess.check_output(
            "netsh wlan show networks mode=bssid", shell=True, text=True
        )

        if "error" not in output.lower():
            lines = output.splitlines()
            channel_info = {}

            for i, line in enumerate(lines):
                if "Channel" in line:
                    channel = int(line.split(":")[1].strip())
                    ssid_line = lines[i - 3].split(":")[1].strip()
                    if channel not in channel_info:
                        channel_info[channel] = []
                    channel_info[channel].append(ssid_line)

            for channel, networks in channel_info.items():
                print(f"Channel {channel}:")
                for ssid in networks:
                    print(f"  SSID: {ssid}")
        else:
            print("Error: Unable to run netsh command.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    scan_wifi_channels_windows()

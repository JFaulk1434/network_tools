from network_scanner import data_file
import json
import os


def run(days):
    days = int(days)
    if not os.path.exists(data_file):
        return "No data available."

    with open(data_file, "r") as f:
        data = json.load(f)

    report = ""
    dates = sorted(data.keys(), reverse=True)[:days]
    for date in dates:
        report += f"\nReport for {date}:\n"
        for ip_range, results in data[date].items():
            report += f"  {ip_range}\n"
            for result in results:
                report += f"    {result}\n"
    return report

from setuptools import setup, find_packages

setup(
    name="nettools",
    version="1.1",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "NT=nettools.net_cli:cli",
        ],
    },
    install_requires=[
        "click",
        "scapy",
        "manuf",
        "psutil",
        "speedtest-cli",
    ],
)

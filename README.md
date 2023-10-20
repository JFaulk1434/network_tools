# Network Tools

A Python-based utility class for various network-related tasks, powered by Scapy, psutil, speedtest, and more.

## Features

- Network Scanning
- TCP Port Scanning
- SYN Port Scanning
- Banner Grabbing
- Trace Route
- Speed Test
- Local Network Info

## Dependencies

- scapy
- manuf
- psutil
- socket
- speedtest
- time
- netifaces
- rich

Install all required packages using pip:

```bash
pip install scapy manuf psutil speedtest-cli netifaces rich
```

Package:

```bash
python3 setup.py sdist bdist_wheel
pip3 install ./dist/nettools-0.1-py3-none-any.whl
```

## Usage

### Initialization

```python
from your_module import Network_tools

# Prints results on all methods
tools = Network_tools(verbose=True)

# Printing of only important information
tools = Network_tools()
```

### Network Scanning

```python
devices = tools.net_scan(ip="192.168.0.1", subnet=24)
```

### TCP Port Scanning

```python
open_ports = tools.tcp_port_scan(target_ip="192.168.0.1", start=1, end=100)
```

### SYN Port Scanning

```python
open_ports = tools.syn_port_scan(target_ip="192.168.0.1", start=1, end=100)
```

### Banner Grabbing

```python
banner = tools.grab_banner(target_ip="192.168.0.1", port=80)
```

### Trace Route

```python
route = tools.trace_route(target_ip="8.8.8.8")
```

### Speed Test

```python
speed = tools.speed_test()
```

### Get Network Info

```python
info = tools.get_network_info()
```

## Contributing

Feel free to dive in! Open an issue or submit PRs.

## License

MIT © Justin Faulk

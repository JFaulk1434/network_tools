# nettools: A CLI Tool for Network Operations

## Installation

To install `nettools`, simply run:

```bash
pip install /path/to/nettools-0.1-py3-none-any.whl
```

## Usage

### Base Command

The base command is `nettools`. It contains various sub-commands for different networking tasks.

```bash
nettools --help
```

### net_scan

Scans the local network and lists devices.

```bash
nettools net_scan --ip [your_ip] --subnet [subnet] --verbose
```

- `--ip`: IP address to start scanning from. If left blank, it tries to auto-detect.
- `--subnet`: Subnet to scan. Default is 24.
- `--verbose`: Verbose mode. Provides additional information.

### port_scan

Performs a TCP port scan on a given IP.

```bash
nettools port_scan --ip [target_ip] --start [starting_port] --end [ending_port] --verbose
```

- `--ip`: Target IP address to scan.
- `--start`: Starting port number. Default is 1.
- `--end`: Ending port number. Default is 500.
- `--verbose`: Verbose mode. Provides additional information.

### trace_route

Traces the route to a target IP address.

```bash
nettools trace_route --ip [target_ip] --hops [max_hops] --time [timeout] --verbose
```

- `--ip`: Target IP address.
- `--hops`: Maximum hops to try. Default is 15.
- `--time`: Time before each hop times out. Default is 2 seconds.
- `--verbose`: Verbose mode. Provides additional information.

### speed_test

Runs an internet speed test.

```bash
nettools speed_test --verbose
```

- `--verbose`: Verbose mode. Provides additional information.

### network_info

Retrieves network interface information.

```bash
nettools network_info --verbose
```

- `--verbose`: Verbose mode. Provides additional information.

### demo

Runs a demo of all the network tools.

```bash
nettools demo
```

---

## Examples

To run a network scan:

```bash
nettools net_scan
```

To perform a port scan between ports 1 and 100 on IP `192.168.1.1`:

```bash
nettools port_scan --ip 192.168.1.1 --start 1 --end 100
```

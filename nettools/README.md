# NetTools CLI

NetTools is a command-line interface that provides a collection of network utilities. With this tool, you can scan networks, perform port scans, trace routes, and more.

## Installation

If you have received a wheel file for this package, you can install it using pip:

```bash
pip install /path/to/nettools-0.3-py3-none-any.whl
```

## Commands

### Base Command

The base command is `NT`. It contains various sub-commands for different networking tasks.

```bash
NT --help
```

### net-scan

Scans the network and shows all devices found.

Usage:

```bash
NT net-scan [--ip, -i IP_ADDRESS] [--subnet, -s SUBNET] [--verbose, -v]
```

`NT net-scan` will attempt to autodetect your network connection and scan that network.
`NT net-scan 192.168.0.1 24` would scan the 192.168.0.x network with a 255.255.255.0 subnet

### port-scan

Scans TCP ports on a target IP using standard TCP Discovery.

Usage:

```bash
NT port-scan IP START END [--verbose, -v]
```

`NT port-scan 192.168.0.1` will scan ports 1-100 by default
`NT port-scan 192.168.0.1 1000 1300` would scan ports 1000 to 1300

### trace-route

Runs a trace route to the target IP address.

Usage:

```bash
NT trace-route IP [--hops, -h HOPS] [--timeout, -t TIMEOUT] [--verbose, -v]
```

### speed-test

Runs an Internet speed test.

Usage:

```bash
NT speed-test [--verbose, -v]
```

### network-info

Gets your computer's networking interfaces information.

Usage:

```bash
NT network-info [--verbose, -v]
```

### demo

Runs a demo of all the network tools.

Usage:

```bash
NT demo
```

## Examples

```bash
# Scan the network
NT net-scan

# Perform a port scan from port 1 to 100 on 192.168.1.1
NT port-scan 192.168.1.1 1 100

# Trace the route to 8.8.8.8
NT trace-route 8.8.8.8

# Run a speed test
NT speed-test

# Get network info
NT network-info
```

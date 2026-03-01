# aioairctrl

Python library and CLI for controlling Philips air purifiers over the local network using the encrypted CoAP protocol.

[![PyPI](https://img.shields.io/pypi/v/aioairctrl)](https://pypi.org/project/aioairctrl/)
[![CI](https://github.com/kongo09/aioairctrl/actions/workflows/ci.yml/badge.svg)](https://github.com/kongo09/aioairctrl/actions/workflows/ci.yml)

## Overview

Philips air purifiers (AC series) expose a CoAP endpoint on port 5683 of your local network. This library communicates with that endpoint using an AES-128/CBC encryption scheme reverse-engineered from the Philips app. No cloud connection or account is required.

Supported operations:
- Read the current device status (all sensor readings and settings)
- Observe live status updates as the device pushes them
- Send control commands to change settings

> **Home Assistant integration**
> If you want to control your Philips air purifier from Home Assistant, see the companion integration: [kongo09/philips_airpurifier_coap](https://github.com/kongo09/philips_airpurifier_coap). It is built on top of this library.

## Requirements

- Python 3.12 or newer
- The air purifier must be on the same local network (or otherwise reachable by IP)

## Installation

```bash
pip install aioairctrl
```

## Command-line usage

All commands require the `-H`/`--host` flag with the IP address of your purifier. Find it in your router's DHCP table or the Philips app.

### Get current status

```bash
aioairctrl -H 192.168.1.100 status
```

Add `--json` to get machine-readable output:

```bash
aioairctrl -H 192.168.1.100 status --json
```

### Watch for live updates

Stays connected and prints a new line each time the device reports a change (e.g. sensor readings, mode changes):

```bash
aioairctrl -H 192.168.1.100 status-observe
aioairctrl -H 192.168.1.100 status-observe --json
```

Press `Ctrl+C` to stop.

### Set a value

String values:
```bash
aioairctrl -H 192.168.1.100 set mode=AG
```

Boolean values (`true`/`false` are handled automatically):
```bash
aioairctrl -H 192.168.1.100 set pwr=true
aioairctrl -H 192.168.1.100 set pwr=false
```

Integer values (use `-I`/`--int`):
```bash
aioairctrl -H 192.168.1.100 set -I om=2
```

Multiple values at once:
```bash
aioairctrl -H 192.168.1.100 set -I pwr=true om=2
```

### Debug output

Add `-D`/`--debug` to any command to see the raw CoAP traffic:

```bash
aioairctrl -H 192.168.1.100 --debug status
```

## Python API

```python
import asyncio
from aioairctrl import CoAPClient

async def main():
    client = await CoAPClient.create(host="192.168.1.100")
    try:
        # Read status once
        status, max_age = await client.get_status()
        print(status)

        # Stream live updates
        async for status in client.observe_status():
            print(status)
            break  # stop after first update

        # Send a command
        await client.set_control_value("pwr", True)

        # Send multiple values at once
        await client.set_control_values({"om": 2, "rhset": 50})
    finally:
        await client.shutdown()

asyncio.run(main())
```

## License

MIT

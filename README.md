# APP BGP INFO

A Python script to audit and back up relevant BGP configurations from Cisco routers (IOS/IOS-XE) via SSH.

It connects to a device, executes a set of `show run | s ...` commands, filters out noise from each section, and automatically groups `route-map` and `prefix-list` entries by BGP neighbor (following the naming convention `RMv{4|6}|Desde_X-Hacia_Y` / `PLv{4|6}|PL0N|Desde_X-Hacia_Y`), rather than leaving them in the random order returned by the router. The output is saved to a timestamped `.txt` file, ready for review or version control.

## What does it solve?

Before this script, reviewing a device's BGP configuration to make changes involved manually connecting, running commands one by one, and then manually reordering route-maps and prefix-lists to make them readable by neighbor. This script automates that entire process.

## Requirements

- Python 3.9+
- [netmiko](https://github.com/ktbyers/netmiko)

## Installation

It is recommended to use a virtual environment to avoid installing dependencies at the system level:

```bash
python3 -m venv venv
source venv/bin/activate
pip install netmiko
```

## How to use it?

```bash
python3 "APP BGP Info.py"
```

The script will interactively prompt for:

- Device type (Netmiko `device_type`, e.g., `cisco_ios`)
- IP address
- Username and password

If the connection fails, it offers the option to retry, change the details, or exit.

**Note:** The script does not store or hardcode credentials on disk and uses `getpass` to avoid exposing the password in the console.

## What information is collected?

| Section | Command | Filter/Processing |
|---|---|---|
| Interfaces | `show run \| s interface` | Removes noise lines (`load-interval`, `negotiation`, etc.) |
| IP SLA | `show run \| s sla` | Unfiltered |
| Static Routes | `show run \| s route` | Removes anything other than `ip route` (BGP and route-maps can appear in this section) |
| BGP | `show run \| s bgp` | Removes route-map lines (`permit`/`deny`) |
| Route-Map | `show run \| s route-map` | Automatically grouped by neighbor; IN before OUT |
| Prefix-List | `show run \| s prefix-list` | Automatically grouped by neighbor and list number (PL01, PL02...) |

Objects that do not follow the naming convention (`From_X-To_RTs`) are not lost; they are listed separately in an "Automatically ungrouped" section at the end of each block.

## Output

A `{hostname}_{date}_{time}.txt` file in the same directory, with each section separated and the content raw or grouped as appropriate.

## Project status?

Under development; tested on Cisco ISR 4331 routers and Cisco Modeling Labs (CML) routers. `development` branch for new features.

## Known limitations

- Designed for Cisco IOS/IOS-XE; not tested with other vendors.
- Automatic grouping relies on the `Desde_X-Hacia_RTs` naming convention (Spanish keywords, matching the script's internal naming); names that do not follow this convention are placed in the "Ungrouped" section.
- The device must support the "sector" filter modifier.

## License

Distributed under the **MIT** license.

**Note:** The script executes read-only commands (`show`) via SSH; however, the use of the software on network equipment is the operator's responsibility. The author assumes no liability for misuse or failures in production environments.

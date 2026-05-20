#!/usr/bin/env python3
"""
Network Discovery Tool
----------------------
Discovers network topology via SSH using CDP/LLDP neighbor data,
presents results in tabular form, generates Mermaid diagrams,
and optionally exports to CSV.

Requirements:
    pip install netmiko tabulate
"""

import re
import csv
import json
import logging
import argparse
from typing import Optional
from dataclasses import dataclass, field, asdict
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False
    print("[WARN] tabulate not installed — table output will be plain text.")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Neighbor:
    """Represents a single CDP/LLDP neighbor relationship."""
    local_device: str
    local_interface: str
    neighbor_device: str
    neighbor_interface: str
    platform: str = ""
    capabilities: str = ""
    protocol: str = "CDP"   # CDP | LLDP

    def edge_key(self) -> frozenset:
        """Canonical key used to deduplicate bidirectional edges."""
        return frozenset([
            f"{self.local_device}:{self.local_interface}",
            f"{self.neighbor_device}:{self.neighbor_interface}",
        ])


# ---------------------------------------------------------------------------
# Interface normalisation
# ---------------------------------------------------------------------------
IFACE_ABBREVS = [
    ("GigabitEthernet", "Gi"),
    ("FastEthernet",    "Fa"),
    ("TenGigabitEthernet", "Te"),
    ("HundredGigE",     "Hu"),
    ("FortyGigabitEthernet", "Fo"),
    ("TwentyFiveGigE",  "Twe"),
    ("Ethernet",        "Et"),
    ("Serial",          "Se"),
    ("Loopback",        "Lo"),
    ("Tunnel",          "Tu"),
    ("Vlan",            "Vl"),
    ("Port-channel",    "Po"),
    ("Management",      "Mg"),
]

def shorten_interface(iface: str) -> str:
    """Shorten a long interface name to its common abbreviation."""
    for long, short in IFACE_ABBREVS:
        if iface.lower().startswith(long.lower()):
            return short + iface[len(long):]
    return iface


def normalize_device_id(device_id: str) -> str:
    """
    Strip FQDN suffix and trailing serial numbers from CDP device-id strings.
    E.g. 'switch1.corp.example.com' -> 'switch1'
         'switch1(SN12345)'          -> 'switch1'
    """
    # Remove parenthesised serial numbers
    device_id = re.sub(r"\(.*?\)", "", device_id)
    # Keep only the hostname portion of an FQDN
    device_id = device_id.split(".")[0]
    return device_id.strip()


# ---------------------------------------------------------------------------
# SSH / Netmiko helpers
# ---------------------------------------------------------------------------
def build_device(host: str, username: str, password: str,
                 secret: str = "", device_type: str = "cisco_ios") -> dict:
    return {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret or password,
        "timeout": 30,
        "session_log": None,
    }


def connect(device: dict):
    """Return an active Netmiko connection or None on failure."""
    try:
        log.info("Connecting to %s …", device["host"])
        conn = ConnectHandler(**device)
        conn.enable()
        return conn
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", device["host"])
    except NetmikoTimeoutException:
        log.error("Timeout connecting to %s", device["host"])
    except Exception as exc:
        log.error("Error connecting to %s: %s", device["host"], exc)
    return None


# ---------------------------------------------------------------------------
# CDP discovery
# ---------------------------------------------------------------------------
def get_cdp_neighbors(conn, local_hostname: str) -> list[Neighbor]:
    """
    Parse 'show cdp neighbors detail' output into Neighbor objects.
    Works for Cisco IOS / IOS-XE / NX-OS.
    """
    neighbors = []
    try:
        output = conn.send_command("show cdp neighbors detail")
    except Exception as exc:
        log.warning("Could not run CDP command: %s", exc)
        return neighbors

    # Split into per-neighbor blocks
    blocks = re.split(r"-{10,}", output)

    for block in blocks:
        if "Device ID" not in block:
            continue

        def extract(pattern, text, default=""):
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1).strip() if m else default

        neighbor_id   = extract(r"Device ID\s*:\s*(.+)",       block)
        local_iface   = extract(r"Interface\s*:\s*(\S+)",       block)
        remote_iface  = extract(r"Port ID.*?:\s*(\S+)",         block)
        platform      = extract(r"Platform\s*:\s*([^,\n]+)",    block)
        capabilities  = extract(r"Capabilities\s*:\s*(.+)",     block)

        if not (neighbor_id and local_iface and remote_iface):
            continue

        neighbors.append(Neighbor(
            local_device=local_hostname,
            local_interface=shorten_interface(local_iface),
            neighbor_device=normalize_device_id(neighbor_id),
            neighbor_interface=shorten_interface(remote_iface),
            platform=platform.strip(",").strip(),
            capabilities=capabilities,
            protocol="CDP",
        ))

    log.info("  Found %d CDP neighbor(s) on %s", len(neighbors), local_hostname)
    return neighbors


# ---------------------------------------------------------------------------
# LLDP discovery
# ---------------------------------------------------------------------------
def get_lldp_neighbors(conn, local_hostname: str) -> list[Neighbor]:
    """
    Parse 'show lldp neighbors detail' output into Neighbor objects.
    """
    neighbors = []
    try:
        output = conn.send_command("show lldp neighbors detail")
    except Exception as exc:
        log.warning("Could not run LLDP command: %s", exc)
        return neighbors

    blocks = re.split(r"-{10,}", output)

    for block in blocks:
        if "System Name" not in block and "Port Description" not in block:
            continue

        def extract(pattern, text, default=""):
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1).strip() if m else default

        neighbor_id  = extract(r"System Name\s*:\s*(.+)",         block)
        local_iface  = extract(r"Local Intf\s*:\s*(\S+)",         block)
        remote_iface = extract(r"Port id\s*:\s*(\S+)",            block)
        platform     = extract(r"System Description\s*:\s*(.+)",  block)
        capabilities = extract(r"System Capabilities\s*:\s*(.+)", block)

        if not (neighbor_id and local_iface and remote_iface):
            continue

        neighbors.append(Neighbor(
            local_device=local_hostname,
            local_interface=shorten_interface(local_iface),
            neighbor_device=normalize_device_id(neighbor_id),
            neighbor_interface=shorten_interface(remote_iface),
            platform=platform[:60],
            capabilities=capabilities,
            protocol="LLDP",
        ))

    log.info("  Found %d LLDP neighbor(s) on %s", len(neighbors), local_hostname)
    return neighbors


def get_hostname(conn) -> str:
    """Retrieve the device hostname from the running config."""
    try:
        out = conn.send_command("show running-config | include hostname")
        m = re.search(r"hostname\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return conn.host   # Fall back to IP


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
def deduplicate(neighbors: list[Neighbor]) -> list[Neighbor]:
    """Remove bidirectional duplicates (A→B and B→A are the same link)."""
    seen: set[frozenset] = set()
    unique: list[Neighbor] = []
    for n in neighbors:
        key = n.edge_key()
        if key not in seen:
            seen.add(key)
            unique.append(n)
    log.info("Deduplicated: %d → %d unique link(s)", len(neighbors), len(unique))
    return unique


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def print_table(neighbors: list[Neighbor]) -> None:
    headers = ["Local Device", "Local Intf", "Neighbor", "Neighbor Intf",
               "Platform", "Protocol"]
    rows = [
        [n.local_device, n.local_interface, n.neighbor_device,
         n.neighbor_interface, n.platform[:30], n.protocol]
        for n in neighbors
    ]
    if HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    else:
        print("  ".join(headers))
        for row in rows:
            print("  ".join(str(c) for c in row))


def export_csv(neighbors: list[Neighbor], path: str) -> None:
    fieldnames = ["local_device", "local_interface", "neighbor_device",
                  "neighbor_interface", "platform", "capabilities", "protocol"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for n in neighbors:
            writer.writerow(asdict(n))
    log.info("CSV exported → %s", path)


def generate_mermaid(neighbors: list[Neighbor]) -> str:
    """
    Build a Mermaid graph LR diagram from the neighbor list.
    Each link is labelled with the interface pair.
    """
    lines = ["graph LR"]
    node_ids: dict[str, str] = {}

    def node_id(name: str) -> str:
        if name not in node_ids:
            safe = re.sub(r"[^A-Za-z0-9]", "_", name)
            node_ids[name] = f"{safe}[{name}]"
        return node_ids[name]

    for n in neighbors:
        src = node_id(n.local_device)
        dst = node_id(n.neighbor_device)
        label = f"{n.local_interface} — {n.neighbor_interface}"
        lines.append(f'    {src} -- "{label}" --> {dst}')

    return "\n".join(lines)


def save_mermaid(diagram: str, path: str) -> None:
    with open(path, "w") as f:
        f.write(diagram)
    log.info("Mermaid diagram saved → %s", path)


# ---------------------------------------------------------------------------
# Main discovery loop
# ---------------------------------------------------------------------------
def discover(
    seed_hosts: list[str],
    username: str,
    password: str,
    secret: str = "",
    device_type: str = "cisco_ios",
    use_cdp: bool = True,
    use_lldp: bool = False,
    csv_path: Optional[str] = None,
    mermaid_path: Optional[str] = None,
    recursive: bool = False,
) -> list[Neighbor]:
    """
    Connect to each seed host, collect CDP/LLDP data, optionally recurse
    into discovered neighbors, deduplicate, and return the full neighbor list.
    """
    all_neighbors: list[Neighbor] = []
    visited: set[str] = set()
    queue: list[str] = list(seed_hosts)

    while queue:
        host = queue.pop(0)
        if host in visited:
            continue
        visited.add(host)

        device = build_device(host, username, password, secret, device_type)
        conn = connect(device)
        if conn is None:
            continue

        hostname = get_hostname(conn)
        log.info("Discovered hostname: %s", hostname)

        batch: list[Neighbor] = []
        if use_cdp:
            batch.extend(get_cdp_neighbors(conn, hostname))
        if use_lldp:
            batch.extend(get_lldp_neighbors(conn, hostname))

        conn.disconnect()
        all_neighbors.extend(batch)

        if recursive:
            for n in batch:
                if n.neighbor_device not in visited:
                    queue.append(n.neighbor_device)

    unique = deduplicate(all_neighbors)

    print("\n=== Network Topology ===\n")
    print_table(unique)

    diagram = generate_mermaid(unique)
    print("\n=== Mermaid Diagram ===\n")
    print(diagram)

    if csv_path:
        export_csv(unique, csv_path)

    if mermaid_path:
        save_mermaid(diagram, mermaid_path)

    return unique


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Network topology discovery via CDP/LLDP over SSH"
    )
    p.add_argument("hosts", nargs="+", help="Seed device IPs or hostnames")
    p.add_argument("-u", "--username", required=True,  help="SSH username")
    p.add_argument("-p", "--password", required=True,  help="SSH password")
    p.add_argument("-s", "--secret",   default="",     help="Enable secret (defaults to password)")
    p.add_argument("-t", "--type",     default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--cdp",  action="store_true", default=True,  help="Use CDP (default: on)")
    p.add_argument("--lldp", action="store_true", default=False, help="Use LLDP (default: off)")
    p.add_argument("--no-cdp", dest="cdp",  action="store_false")
    p.add_argument("--recursive", "-r", action="store_true",
                   help="Recurse into discovered neighbors")
    p.add_argument("--csv",     metavar="FILE", help="Export results to CSV")
    p.add_argument("--mermaid", metavar="FILE", help="Save Mermaid diagram to file")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    discover(
        seed_hosts=args.hosts,
        username=args.username,
        password=args.password,
        secret=args.secret,
        device_type=args.type,
        use_cdp=args.cdp,
        use_lldp=args.lldp,
        csv_path=args.csv,
        mermaid_path=args.mermaid,
        recursive=args.recursive,
    )

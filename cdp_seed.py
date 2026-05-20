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
import getpass
from typing import Optional
from dataclasses import dataclass, field, asdict
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from netmiko.ssh_autodetect import SSHDetect

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
# Device-type autodetection
# ---------------------------------------------------------------------------

# Ordered list of (regex_pattern, netmiko_device_type).
# Checked against the output of 'show version' (or equivalent).
VERSION_FINGERPRINTS: list[tuple[str, str]] = [
    (r"NX-OS",                          "cisco_nxos"),
    (r"IOS[-\s]XR",                     "cisco_xr"),
    (r"IOS[-\s]XE",                     "cisco_iosxe"),
    (r"Cisco IOS Software.*Catalyst",   "cisco_ios"),
    (r"Cisco IOS Software",             "cisco_ios"),
    (r"Arista",                         "arista_eos"),
    (r"EOS",                            "arista_eos"),
    (r"Juniper|JUNOS",                  "juniper_junos"),
    (r"HP.*Comware|H3C",               "hp_comware"),
    (r"FortiOS|FortiGate",              "fortinet"),
    (r"PAN-OS",                         "paloalto_panos"),
]

# Platforms where 'show version' doesn't work — use alternatives
SHOW_VERSION_CMD: dict[str, str] = {
    "default":      "show version",
    "arista_eos":   "show version",
    "juniper_junos":"show version",
}


def fingerprint_version_output(output: str) -> Optional[str]:
    """Match version string output against known OS fingerprints."""
    for pattern, device_type in VERSION_FINGERPRINTS:
        if re.search(pattern, output, re.IGNORECASE):
            return device_type
    return None


def autodetect_device_type(host: str, username: str, password: str,
                            secret: str = "") -> str:
    """
    Determine the Netmiko device_type for a host using a two-stage strategy:

    Stage 1 — Version fingerprinting (fast, single connection):
        Connect with device_type='autodetect', send 'show version',
        and pattern-match the output. This avoids a dedicated probe
        connection and adds no extra latency.

    Stage 2 — SSHDetect fallback (reliable, slower):
        If stage 1 yields no match, SSHDetect sends a series of probe
        commands and scores the responses. Used as a safety net for
        uncommon or ambiguous platforms.

    Returns a valid Netmiko device_type string, defaulting to
    'cisco_ios' if both stages fail.
    """
    base = {
        "host": host,
        "username": username,
        "password": password,
        "secret": secret or password,
        "timeout": 20,
    }

    # ------------------------------------------------------------------
    # Stage 1: version fingerprinting
    # ------------------------------------------------------------------
    log.info("  [autodetect] Stage 1 — version fingerprint for %s", host)
    try:
        conn = ConnectHandler(**{**base, "device_type": "autodetect"})
        try:
            version_out = conn.send_command("show version", read_timeout=15)
        except Exception:
            version_out = ""
        conn.disconnect()

        detected = fingerprint_version_output(version_out)
        if detected:
            log.info("  [autodetect] Fingerprint matched: %s → %s", host, detected)
            return detected
    except Exception as exc:
        log.debug("  [autodetect] Stage 1 connection failed for %s: %s", host, exc)

    # ------------------------------------------------------------------
    # Stage 2: SSHDetect fallback
    # ------------------------------------------------------------------
    log.info("  [autodetect] Stage 2 — SSHDetect fallback for %s", host)
    try:
        guesser = SSHDetect(**{**base, "device_type": "autodetect"})
        result = guesser.autodetect()
        guesser.connection.disconnect()
        if result:
            log.info("  [autodetect] SSHDetect result: %s → %s", host, result)
            return result
    except Exception as exc:
        log.warning("  [autodetect] SSHDetect failed for %s: %s", host, exc)

    log.warning("  [autodetect] Could not detect type for %s — defaulting to cisco_ios", host)
    return "cisco_ios"


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
        log.info("Connecting to %s as %s …", device["host"], device["device_type"])
        conn = ConnectHandler(**device)
        # enable() is only meaningful on IOS-family devices; skip for others
        if device["device_type"] in ("cisco_ios", "cisco_iosxe", "cisco_nxos"):
            try:
                conn.enable()
            except Exception:
                pass   # already privileged or not supported
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



# ---------------------------------------------------------------------------
# Core: poll a single host, return (resolved_hostname, neighbors)
# ---------------------------------------------------------------------------
def poll_device(
    host: str,
    username: str,
    password: str,
    secret: str,
    device_type: str,
    type_cache: dict,
    use_cdp: bool,
    use_lldp: bool,
) -> tuple[Optional[str], list[Neighbor]]:
    """
    Connect to one host, run CDP/LLDP, and return its hostname plus
    the neighbors found. Returns (None, []) if the connection fails.
    """
    if device_type == "auto":
        if host not in type_cache:
            type_cache[host] = autodetect_device_type(host, username, password, secret)
        resolved_type = type_cache[host]
    else:
        resolved_type = device_type

    device = build_device(host, username, password, secret, resolved_type)
    conn = connect(device)
    if conn is None:
        return None, []

    hostname = get_hostname(conn)
    log.info("Polled: %s  (type: %s)", hostname, resolved_type)

    neighbors: list[Neighbor] = []
    if use_cdp:
        neighbors.extend(get_cdp_neighbors(conn, hostname))
    if use_lldp:
        neighbors.extend(get_lldp_neighbors(conn, hostname))

    conn.disconnect()
    return hostname, neighbors


# ---------------------------------------------------------------------------
# Main discovery loop
# ---------------------------------------------------------------------------
def discover(
    seed_hosts: list[str],
    username: str,
    password: str,
    secret: str = "",
    device_type: str = "auto",
    use_cdp: bool = True,
    use_lldp: bool = False,
    csv_path: Optional[str] = None,
) -> list[Neighbor]:
    """
    Two-phase discovery:

    Phase 1 — Seeds:
        Poll every seed host and collect their direct CDP/LLDP neighbors.

    Phase 2 — One hop out:
        For each neighbor discovered in phase 1, connect to that device
        and run the same CDP/LLDP commands to reveal what is connected
        beyond the seed's immediate view.

    Discovery stops after this second hop. Devices already polled in
    phase 1 are skipped in phase 2 to avoid redundant connections.
    """
    all_neighbors: list[Neighbor] = []
    type_cache: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Phase 1: seed devices
    # ------------------------------------------------------------------
    log.info("=== Phase 1: polling %d seed device(s) ===", len(seed_hosts))
    polled: set[str] = set()          # tracks hostnames already queried
    seed_neighbor_hosts: set[str] = set()  # IPs/hostnames to visit in phase 2

    for host in seed_hosts:
        hostname, neighbors = poll_device(
            host, username, password, secret,
            device_type, type_cache, use_cdp, use_lldp,
        )
        if hostname is None:
            continue
        polled.add(hostname)
        all_neighbors.extend(neighbors)

        # Queue the neighbor device IDs for phase 2
        for n in neighbors:
            if n.neighbor_device not in polled:
                seed_neighbor_hosts.add(n.neighbor_device)

    # ------------------------------------------------------------------
    # Phase 2: devices directly connected to the seeds
    # ------------------------------------------------------------------
    log.info(
        "=== Phase 2: polling %d neighbor device(s) discovered from seeds ===",
        len(seed_neighbor_hosts),
    )
    for host in seed_neighbor_hosts:
        if host in polled:
            log.info("  Skipping %s (already polled in phase 1)", host)
            continue

        hostname, neighbors = poll_device(
            host, username, password, secret,
            device_type, type_cache, use_cdp, use_lldp,
        )
        if hostname is None:
            continue
        polled.add(hostname)
        all_neighbors.extend(neighbors)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    unique = deduplicate(all_neighbors)

    print("\n=== Network Topology ===\n")
    print_table(unique)

    if csv_path:
        export_csv(unique, csv_path)

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
    p.add_argument("-s", "--secret",   default="",     help="Enable secret (prompted separately if omitted)")
    p.add_argument("-t", "--type",     default="auto",
                   help="Netmiko device type, or 'auto' to detect per host (default: auto)")
    p.add_argument("--cdp",  action="store_true", default=True,  help="Use CDP (default: on)")
    p.add_argument("--lldp", action="store_true", default=False, help="Use LLDP (default: off)")
    p.add_argument("--no-cdp", dest="cdp",  action="store_false")
    p.add_argument("--recursive", "-r", action="store_true",
                   help="Recurse into discovered neighbors")
    p.add_argument("--csv", metavar="FILE", help="Export results to CSV")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = getpass.getpass(f"SSH password for {args.username}: ")
    secret = args.secret or getpass.getpass("Enable secret (press Enter to use same as password): ") or password

    discover(
        seed_hosts=args.hosts,
        username=args.username,
        password=password,
        secret=secret,
        device_type=args.type,
        use_cdp=args.cdp,
        use_lldp=args.lldp,
        csv_path=args.csv,
        recursive=args.recursive,
    )

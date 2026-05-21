#!/usr/bin/env python3
"""
Network Discovery Tool
----------------------
Discovers network topology via SSH using CDP/LLDP neighbor data,
presents results in tabular form, exports to CSV, and generates
an interactive pyvis HTML topology diagram.

Requirements:
    pip install netmiko tabulate pyvis
"""

import re
import csv
import json
import logging
import argparse
import getpass
import os
import webbrowser
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

try:
    from pyvis.network import Network as PyvisNetwork
    HAS_PYVIS = True
except ImportError:
    HAS_PYVIS = False
    print("[WARN] pyvis not installed — HTML diagram will be skipped. Run: pip install pyvis")

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
    neighbor_ip: str = ""   # Management/interface IP used to SSH in phase 2
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
        # CDP advertises the neighbour's IP under "IP address" or "IPv4 Address"
        neighbor_ip   = extract(r"IP(?:v4)?\s+[Aa]ddress\s*:\s*(\S+)", block)

        if not (neighbor_id and local_iface and remote_iface):
            continue

        neighbors.append(Neighbor(
            local_device=local_hostname,
            local_interface=shorten_interface(local_iface),
            neighbor_device=normalize_device_id(neighbor_id),
            neighbor_interface=shorten_interface(remote_iface),
            neighbor_ip=neighbor_ip,
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
        neighbor_ip  = extract(r"Management Addresses.*?IP:\s*(\S+)", block)
        if not neighbor_ip:
            neighbor_ip = extract(r"IP:\s*(\S+)", block)

        if not (neighbor_id and local_iface and remote_iface):
            continue

        neighbors.append(Neighbor(
            local_device=local_hostname,
            local_interface=shorten_interface(local_iface),
            neighbor_device=normalize_device_id(neighbor_id),
            neighbor_interface=shorten_interface(remote_iface),
            neighbor_ip=neighbor_ip,
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
    headers = [
        "#",
        "Local Device",
        "Local Intf",
        "Neighbor Device",
        "Neighbor IP",
        "Neighbor Intf",
        "Platform",
        "Capabilities",
        "Proto",
    ]
    rows = [
        [
            i + 1,
            n.local_device,
            n.local_interface,
            n.neighbor_device,
            n.neighbor_ip or "—",
            n.neighbor_interface,
            n.platform[:35] or "—",
            n.capabilities[:25] or "—",
            n.protocol,
        ]
        for i, n in enumerate(neighbors)
    ]
    if HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="rounded_outline",
                       colalign=("right",) + ("left",) * (len(headers) - 1)))
    else:
        widths = [max(len(str(r[c])) for r in ([headers] + rows)) for c in range(len(headers))]
        sep = "  ".join("-" * w for w in widths)
        fmt = "  ".join(f"{{:<{w}}}" for w in widths)
        print(fmt.format(*headers))
        print(sep)
        for row in rows:
            print(fmt.format(*row))
    print(f"\n  {len(neighbors)} link(s) found.\n")


def export_csv(neighbors: list[Neighbor], path: str) -> None:
    fieldnames = ["local_device", "local_interface", "neighbor_device",
                  "neighbor_ip", "neighbor_interface", "platform",
                  "capabilities", "protocol"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for n in neighbors:
            writer.writerow(asdict(n))
    log.info("CSV exported → %s", path)


# ---------------------------------------------------------------------------
# pyvis visualisation
# ---------------------------------------------------------------------------

# Group definitions — each maps to a hierarchy level and visual style.
# Level 0 = top of diagram, higher numbers = further down.
DEVICE_GROUPS = [
    {
        "name":      "firewall",
        "level":     0,
        "prefixes":  ("fw", "asa", "palo", "ftd", "firewall"),
        "color":     {"border": "#6c3483", "background": "#8e44ad",
                      "highlight": {"border": "#a569bd", "background": "#a569bd"},
                      "hover":     {"border": "#a569bd", "background": "#a569bd"}},
        "shape":     "diamond",
        "size":      32,
        "borderWidth": 3,
    },
    {
        "name":      "core",
        "level":     1,
        "prefixes":  ("core",),
        "color":     {"border": "#a93226", "background": "#e74c3c",
                      "highlight": {"border": "#ff6b6b", "background": "#ff6b6b"},
                      "hover":     {"border": "#ff6b6b", "background": "#ff6b6b"}},
        "shape":     "box",
        "size":      36,
        "borderWidth": 3,
    },
    {
        "name":      "router",
        "level":     1,
        "prefixes":  ("rtr", "router", "gw", "gateway"),
        "color":     {"border": "#b7770d", "background": "#f39c12",
                      "highlight": {"border": "#f8c471", "background": "#f8c471"},
                      "hover":     {"border": "#f8c471", "background": "#f8c471"}},
        "shape":     "box",
        "size":      30,
        "borderWidth": 2,
    },
    {
        "name":      "distribution",
        "level":     2,
        "prefixes":  ("dist", "agg", "aggr"),
        "color":     {"border": "#b7770d", "background": "#e67e22",
                      "highlight": {"border": "#f0a500", "background": "#f0a500"},
                      "hover":     {"border": "#f0a500", "background": "#f0a500"}},
        "shape":     "box",
        "size":      26,
        "borderWidth": 2,
    },
    {
        "name":      "access",
        "level":     3,
        "prefixes":  ("access", "acc", "sw", "switch"),
        "color":     {"border": "#1a6fa8", "background": "#3498db",
                      "highlight": {"border": "#5dade2", "background": "#5dade2"},
                      "hover":     {"border": "#5dade2", "background": "#5dade2"}},
        "shape":     "box",
        "size":      20,
        "borderWidth": 2,
    },
    {
        "name":      "ap",
        "level":     4,
        "prefixes":  ("ap", "wap", "air", "wifi"),
        "color":     {"border": "#1e8449", "background": "#27ae60",
                      "highlight": {"border": "#58d68d", "background": "#58d68d"},
                      "hover":     {"border": "#58d68d", "background": "#58d68d"}},
        "shape":     "dot",
        "size":      16,
        "borderWidth": 2,
    },
]

# Fallback for unrecognised devices
_FALLBACK_GROUP = {
    "name":      "unknown",
    "level":     3,
    "color":     {"border": "#616a6b", "background": "#7f8c8d",
                  "highlight": {"border": "#aab7b8", "background": "#aab7b8"},
                  "hover":     {"border": "#aab7b8", "background": "#aab7b8"}},
    "shape":     "ellipse",
    "size":      20,
    "borderWidth": 2,
}


def _get_group(hostname: str) -> dict:
    h = hostname.lower()
    for g in DEVICE_GROUPS:
        if any(h.startswith(p) for p in g["prefixes"]):
            return g
    return _FALLBACK_GROUP


def generate_pyvis(
    neighbors: list[Neighbor],
    output_file: str = "topology.html",
    auto_open: bool = True,
) -> None:
    """
    Build an interactive pyvis topology diagram with:
    - Hierarchical top-down layout (firewall → core → dist → access → APs)
    - Group-based colour coding and node shapes
    - Per-node hover tooltips (IP, platform, connections)
    - Styled edges with interface-pair labels
    - Physics and layout control panel in the browser
    """
    if not HAS_PYVIS:
        log.warning("pyvis not available — skipping HTML diagram.")
        return

    net = PyvisNetwork(
        height="100vh",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="#ecf0f1",
        directed=False,
        notebook=False,
    )


    # Collect metadata for tooltips — track connections per device too
    node_meta:  dict[str, dict] = {}
    node_conns: dict[str, list] = {}
    for n in neighbors:
        node_meta.setdefault(n.local_device,    {"ip": "",            "platform": ""})
        node_meta.setdefault(n.neighbor_device, {"ip": n.neighbor_ip, "platform": n.platform})
        node_conns.setdefault(n.local_device,   []).append(f"{n.local_interface} → {n.neighbor_device}")
        node_conns.setdefault(n.neighbor_device,[]).append(f"{n.neighbor_interface} → {n.local_device}")

    added: set[str] = set()

    for n in neighbors:
        for device in (n.local_device, n.neighbor_device):
            if device in added:
                continue

            group     = _get_group(device)
            meta      = node_meta.get(device, {})
            conns     = node_conns.get(device, [])
            conn_html = "".join(f"<br>&nbsp;&nbsp;• {c}" for c in conns)
            tip = (
                f"<b>{device}</b><br>"
                f"IP: {meta.get('ip') or '—'}<br>"
                f"Platform: {meta.get('platform') or '—'}<br>"
                f"Links ({len(conns)}):{conn_html}"
            )

            net.add_node(
                device,
                label=device,
                title=tip,
                level=group["level"],
                color=group["color"],
                shape=group["shape"],
                size=group["size"],
                borderWidth=group["borderWidth"],
            )
            added.add(device)

        edge_label = f"{n.local_interface} ↔ {n.neighbor_interface}"
        net.add_edge(
            n.local_device,
            n.neighbor_device,
            label=edge_label,
            title=f"{n.protocol}: {edge_label}",
        )

    # Generate base HTML — avoid set_options()/options API which triggers
    # AttributeError on many pyvis versions. Instead inject vis.js options
    # directly into the generated HTML after the fact.
    net.write_html(output_file)

    vis_options = """
    network.setOptions({
      layout: {
        hierarchical: {
          enabled: true, direction: "UD", sortMethod: "directed",
          levelSeparation: 160, nodeSpacing: 140, treeSpacing: 200,
          blockShifting: true, edgeMinimization: true, parentCentralization: true
        }
      },
      physics: {
        solver: "hierarchicalRepulsion",
        hierarchicalRepulsion: {
          nodeDistance: 160, springLength: 120, springConstant: 0.01,
          damping: 0.09, avoidOverlap: 1
        },
        stabilization: { enabled: true, iterations: 200 }
      },
      edges: {
        smooth: { type: "cubicBezier", forceDirection: "vertical", roundness: 0.4 },
        font:   { size: 9, color: "#7fb3d3", align: "middle", strokeWidth: 0 },
        color:  { color: "#4a90d9", highlight: "#ffffff", hover: "#aad4f5" },
        width: 2, selectionWidth: 3
      },
      nodes: {
        font:   { size: 12, color: "#ecf0f1", face: "monospace" },
        shadow: { enabled: true, color: "rgba(0,0,0,0.5)", size: 8, x: 3, y: 3 }
      },
      interaction: {
        hover: true, tooltipDelay: 100,
        navigationButtons: true, keyboard: true
      }
    });
    """

    with open(output_file, "r") as f:
        html = f.read()
    # Inject setOptions() call just before the first </script> closing tag,
    # which appears after the network instantiation block in pyvis output
    html = html.replace("</script>", f"{vis_options}\n</script>", 1)
    with open(output_file, "w") as f:
        f.write(html)

    log.info("Topology diagram saved → %s", output_file)
    if auto_open:
        webbrowser.open(f"file://{os.path.abspath(output_file)}")



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
    max_depth: int = 1,
    csv_path: Optional[str] = None,
    html_path: Optional[str] = "topology.html",
) -> list[Neighbor]:
    """
    BFS discovery up to max_depth hops from the seed devices.

    Depth 0 — seeds only (no recursion into neighbors)
    Depth 1 — seeds + their direct neighbors          (default)
    Depth N — seeds + N hops outward

    Each device is polled at most once. Connections use the IP address
    advertised in CDP/LLDP output, falling back to the device hostname.
    """
    all_neighbors: list[Neighbor] = []
    type_cache:    dict[str, str] = {}
    polled:        set[str]       = set()   # hostnames already queried
    # {device_name: connect_address} — populated as neighbors are discovered
    ip_map:        dict[str, str] = {}

    # Seed the BFS queue as depth-0 entries
    # Each queue entry: (connect_address, device_name, current_depth)
    queue: list[tuple[str, str, int]] = [
        (h, h, 0) for h in seed_hosts
    ]

    while queue:
        connect_addr, device_name, depth = queue.pop(0)

        # Skip if we've already polled this device
        if device_name in polled or connect_addr in polled:
            continue

        log.info(
            "=== Depth %d — polling %s (via %s) ===",
            depth, device_name, connect_addr,
        )

        hostname, neighbors = poll_device(
            connect_addr, username, password, secret,
            device_type, type_cache, use_cdp, use_lldp,
        )
        if hostname is None:
            continue

        polled.add(hostname)
        polled.add(device_name)
        polled.add(connect_addr)
        all_neighbors.extend(neighbors)

        # Enqueue neighbors for the next depth level (if within limit)
        if depth < max_depth:
            for n in neighbors:
                if n.neighbor_device in polled:
                    continue
                # Resolve the best address to connect to
                addr = n.neighbor_ip or n.neighbor_device
                if not n.neighbor_ip:
                    log.warning(
                        "  No IP for %s — will try by hostname", n.neighbor_device
                    )
                ip_map[n.neighbor_device] = addr
                queue.append((addr, n.neighbor_device, depth + 1))

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    unique = deduplicate(all_neighbors)

    print("\n=== Network Topology ===\n")
    print_table(unique)

    if csv_path:
        export_csv(unique, csv_path)

    if html_path:
        generate_pyvis(unique, output_file=html_path, auto_open=True)

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
    p.add_argument("--depth", "-d", type=int, default=None,
                   help="Recursion depth (0=seeds only, 1=+neighbors, etc). Prompted if omitted.")
    p.add_argument("--csv", metavar="FILE", default=None,
                   help="Export results to CSV. Prompted if omitted.")
    p.add_argument("--html", metavar="FILE", default=None,
                   help="Save pyvis HTML diagram (default: topology.html). Use --no-html to skip.")
    p.add_argument("--no-html", dest="html", action="store_false",
                   help="Disable HTML diagram generation.")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    password = getpass.getpass(f"SSH password for {args.username}: ")
    secret = args.secret or getpass.getpass("Enable secret (press Enter to use same as password): ") or password

    # Recursion depth
    if args.depth is not None:
        max_depth = args.depth
    else:
        raw = input("Recursion depth — how many hops to follow? [1]: ").strip()
        try:
            max_depth = int(raw) if raw else 1
        except ValueError:
            print("Invalid input, defaulting to 1.")
            max_depth = 1

    # CSV export
    csv_path = args.csv
    if csv_path is None:
        raw = input("Export results to CSV? Enter filename or press Enter to skip: ").strip()
        csv_path = raw or None

    # HTML diagram
    if args.html is False:
        html_path = None   # --no-html explicitly passed
    elif isinstance(args.html, str):
        html_path = args.html
    else:
        html_path = "topology.html"   # default filename

    discover(
        seed_hosts=args.hosts,
        username=args.username,
        password=password,
        secret=secret,
        device_type=args.type,
        use_cdp=args.cdp,
        use_lldp=args.lldp,
        max_depth=max_depth,
        csv_path=csv_path,
        html_path=html_path,
    )

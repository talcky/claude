#!/usr/bin/env python3
"""
switch_rename_prep.py

Prepare (but DO NOT apply) the configuration changes needed on CDP neighbours
when a switch is renamed.

Flow
  1. Prompt for old name, new name, seed address, username, password (hidden).
  2. SSH to the seed (the old switch) and read 'show cdp neighbors detail'.
  3. SSH to each neighbour (Router/Switch capable only), pull the running config.
  4. Find every case-insensitive, whole-word instance of the old name and record:
       device, current line, replacement line, config section (full hierarchy).
  5. Write per-device apply / rollback / review files plus a CSV report.

Nothing is pushed to any device. Read-only commands only.

Requires: netmiko >= 4  (pip install netmiko)
"""

import csv
import getpass
import re
import sys
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, SSHDetect
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
MAX_WORKERS = 5                       # parallel SSH sessions to neighbours
CDP_CAPS_INCLUDE = ("Router", "Switch")  # skip phones, APs, hosts
READ_TIMEOUT = 120                    # seconds for 'show running-config'

# Lines where the name sits inside free text and can safely be overwritten
SAFE_KEYWORDS = re.compile(r"\b(description|remark)\b", re.I)


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass
class Neighbour:
    name: str
    ip: str
    platform: str
    capabilities: str
    links: list = field(default_factory=list)  # [(local_intf, remote_intf)]


@dataclass
class Match:
    device: str
    ip: str
    os_type: str
    line_no: int
    parents: list
    old_line: str
    new_line: str
    status: str = ""   # OK / CHECK / REVIEW
    note: str = ""

    @property
    def section(self) -> str:
        return " > ".join(p.strip() for p in self.parents) or "(global)"


# --------------------------------------------------------------------------- #
# CDP parsing (IOS / IOS-XE / NX-OS / IOS-XR)
# --------------------------------------------------------------------------- #
def _grab(pattern, text, default=""):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else default


def parse_cdp_detail(output: str) -> list:
    """Return a de-duplicated list of Neighbour objects."""
    neighbours = OrderedDict()
    blocks = re.split(r"^-{5,}\s*$", output, flags=re.M)

    for block in blocks:
        dev_id = _grab(r"Device ID:\s*(\S+)", block)
        if not dev_id:
            continue
        name = re.sub(r"\(.*\)$", "", dev_id)          # NX-OS: NAME(SERIAL)

        platform = _grab(r"Platform:\s*([^,\n]+)", block)
        caps = _grab(r"Capabilities:\s*([^\n]+)", block)
        local_if = _grab(r"Interface:\s*([^,\n]+)", block)
        remote_if = _grab(r"Port ID \(outgoing port\):\s*(\S+)", block) or \
            _grab(r"Port ID:\s*(\S+)", block)

        # Prefer the management address; fall back to the first interface IP
        ips = [(m.start(), m.group(1)) for m in re.finditer(
            r"(?:IPv4 [Aa]ddress|IP address)\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
            block)]
        mgmt = re.search(r"M(?:gmt|anagement) address", block, re.I)
        ip = ""
        if mgmt:
            after = [a for pos, a in ips if pos > mgmt.start()]
            ip = after[0] if after else ""
        if not ip and ips:
            ip = ips[0][1]

        key = name.lower()
        if key not in neighbours:
            neighbours[key] = Neighbour(name, ip, platform, caps)
        elif not neighbours[key].ip and ip:
            neighbours[key].ip = ip
        neighbours[key].links.append((local_if, remote_if))

    return list(neighbours.values())


def guess_device_type(platform: str):
    """Map CDP platform string to a Netmiko device_type (None = autodetect)."""
    p = platform.upper()
    if re.search(r"N\d+K|NEXUS", p):
        return "cisco_nxos"
    if re.search(r"ASR9|NCS|XRV|IOS[- ]?XR|CISCO 8\d{3}", p):
        return "cisco_xr"
    if re.search(r"WS-C|C9\d{3}|ISR|ASR1|CSR|C8\d{3}|IE-|CAT", p):
        return "cisco_ios"
    return None


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
def connect(host, username, password, device_type=None):
    base = dict(host=host, username=username, password=password)
    if not device_type:
        try:
            device_type = SSHDetect(device_type="autodetect", **base).autodetect()
        except Exception:
            device_type = None
        device_type = device_type or "cisco_ios"
    conn = ConnectHandler(device_type=device_type, conn_timeout=20, **base)
    return conn, device_type


# --------------------------------------------------------------------------- #
# Config search
# --------------------------------------------------------------------------- #
def build_pattern(old_name: str):
    """Case-insensitive, whole-name match. 'SW01' will not match 'SW010' or
    'XSW01', but will match 'to-SW01', 'SW01.corp.local', 'SW01:Eth1/1'
    and 'SW01-Eth1/1'. Hyphens count as separators, so 'SW01-B' also
    matches - check the report if you have names like that."""
    return re.compile(
        r"(?<![A-Za-z0-9_])" + re.escape(old_name) + r"(?![A-Za-z0-9_])",
        re.I,
    )


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_noise(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("!")


def classify(m: Match, has_children: bool, pattern):
    if has_children:
        m.status = "REVIEW"
        m.note = ("Name is part of a section header. Re-entering creates a "
                  "new object; the old section and any references to it "
                  "need manual handling.")
        return
    kw = SAFE_KEYWORDS.search(m.old_line)
    hit = pattern.search(m.old_line)
    if kw and hit and hit.start() > kw.end():
        m.status = "OK"
        m.note = "Free-text field - re-entering overwrites the old value."
        return
    m.status = "CHECK"
    m.note = ("Name is a command argument. Re-entering may ADD a new entry "
              "rather than replace the old one - the old line may need "
              "removing with 'no'.")


def find_matches(config, pattern, new_name, device, ip, os_type) -> list:
    lines = config.splitlines()
    results = []
    stack = []                 # [(indent, line)] - current parent chain
    banner_delim = None
    banner_head = None

    for idx, raw in enumerate(lines):
        line = raw.rstrip()

        # ---- inside a multi-line banner -------------------------------
        if banner_delim:
            if pattern.search(line):
                m = Match(device, ip, os_type, idx + 1, [banner_head], line,
                          pattern.sub(new_name, line), "REVIEW",
                          "Banner text - the whole banner must be re-entered.")
                results.append(m)
            if banner_delim in line:
                banner_delim = None
            continue

        bm = re.match(r"^banner\s+\S+\s+(\^C|\S)(.*)$", line)
        if bm:
            delim, rest = bm.group(1), bm.group(2)
            if pattern.search(line):
                results.append(Match(
                    device, ip, os_type, idx + 1, [], line,
                    pattern.sub(new_name, line), "REVIEW",
                    "Banner text - the whole banner must be re-entered."))
            if delim not in rest:
                banner_delim, banner_head = delim, line
            stack = []
            continue

        if _is_noise(line):
            continue

        ind = _indent(line)
        while stack and stack[-1][0] >= ind:
            stack.pop()
        parents = [l for _, l in stack]

        if pattern.search(line):
            # Does this line open a section? (next real line is deeper)
            has_children = False
            for nxt in lines[idx + 1:]:
                if _is_noise(nxt):
                    continue
                has_children = _indent(nxt.rstrip()) > ind
                break
            m = Match(device, ip, os_type, idx + 1, parents, line,
                      pattern.sub(new_name, line))
            classify(m, has_children, pattern)
            results.append(m)

        stack.append((ind, line))

    return results


# --------------------------------------------------------------------------- #
# Output builders
# --------------------------------------------------------------------------- #
def render_tree(matches, use_new: bool) -> list:
    """Rebuild the minimum config hierarchy for the given matches, merging
    shared parents and closing each sub-mode with 'exit'."""
    tree = OrderedDict()
    for m in matches:
        node = tree
        for p in m.parents:
            node = node.setdefault(p, OrderedDict())
        node.setdefault(m.new_line if use_new else m.old_line, OrderedDict())

    out = []

    def walk(node):
        for line, kids in node.items():
            out.append(line)
            if kids:
                walk(kids)
                out.append(" " * (_indent(line) + 1) + "exit")

    walk(tree)
    return out


def config_block(matches, use_new, os_type) -> str:
    body = render_tree(matches, use_new)
    tail = ["commit", "end"] if os_type == "cisco_xr" else ["end"]
    return "\n".join(["configure terminal", *body, *tail]) + "\n"


def review_text(matches) -> str:
    out = []
    for m in matches:
        out += [
            f"[{m.status}] line {m.line_no}",
            f"  Section : {m.section}",
            f"  Current : {m.old_line.strip()}",
            f"  New     : {m.new_line.strip()}",
            f"  Note    : {m.note}",
            "",
        ]
    return "\n".join(out)


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


# --------------------------------------------------------------------------- #
# Per-neighbour worker
# --------------------------------------------------------------------------- #
def process_neighbour(nbr, username, password, pattern, new_name, outdir):
    dtype = guess_device_type(nbr.platform)
    conn, dtype = connect(nbr.ip, username, password, dtype)
    try:
        config = conn.send_command("show running-config",
                                   read_timeout=READ_TIMEOUT)
    finally:
        conn.disconnect()

    base = safe_name(nbr.name)
    (outdir / "backups").mkdir(exist_ok=True)
    (outdir / "backups" / f"{base}_running.cfg").write_text(config)

    matches = find_matches(config, pattern, new_name, nbr.name, nbr.ip, dtype)

    ok = [m for m in matches if m.status == "OK"]
    other = [m for m in matches if m.status != "OK"]

    if ok:
        (outdir / f"{base}_apply.txt").write_text(
            config_block(ok, True, dtype))
        (outdir / f"{base}_rollback.txt").write_text(
            config_block(ok, False, dtype))
    if other:
        (outdir / f"{base}_review.txt").write_text(review_text(other))

    return dtype, matches


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def ask(prompt, default=None):
    while True:
        val = input(prompt).strip()
        if val:
            return val
        if default is not None:
            return default


def main():
    print("Switch rename - neighbour config preparation (no changes applied)\n")
    old_name = ask("Old switch name : ")
    new_name = ask("New switch name : ")
    if old_name.lower() == new_name.lower():
        sys.exit("Old and new names are the same - nothing to do.")
    seed = ask(f"Seed IP/hostname of the old switch [{old_name}]: ", old_name)
    username = ask("Username        : ")
    password = getpass.getpass("Password        : ")

    pattern = build_pattern(old_name)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(f"rename_{safe_name(old_name)}_to_{safe_name(new_name)}_{stamp}")
    outdir.mkdir()

    # ---- seed -----------------------------------------------------------
    print(f"\nConnecting to seed {seed} ...")
    try:
        conn, seed_type = connect(seed, username, password)
        prompt = conn.find_prompt()
        cdp = conn.send_command("show cdp neighbors detail", read_timeout=60)
        conn.disconnect()
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        sys.exit(f"Seed connection failed: {e}")

    seed_host = prompt.split(":")[-1].strip("#> ")
    if seed_host.lower() != old_name.lower():
        print(f"  WARNING: seed prompt is '{seed_host}', expected '{old_name}'")

    neighbours = parse_cdp_detail(cdp)
    targets, skipped = [], []
    for n in neighbours:
        if not any(c in n.capabilities for c in CDP_CAPS_INCLUDE):
            skipped.append((n.name, f"capabilities '{n.capabilities}'"))
        elif not n.ip:
            skipped.append((n.name, "no IP address in CDP"))
        else:
            targets.append(n)

    print(f"  {len(neighbours)} CDP neighbour(s), {len(targets)} to check")
    for name, why in skipped:
        print(f"  skip {name}: {why}")

    # ---- neighbours -----------------------------------------------------
    all_matches, errors = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(process_neighbour, n, username, password,
                        pattern, new_name, outdir): n
            for n in targets
        }
        for fut in as_completed(futures):
            n = futures[fut]
            try:
                dtype, matches = fut.result()
                all_matches.extend(matches)
                counts = {s: sum(m.status == s for m in matches)
                          for s in ("OK", "CHECK", "REVIEW")}
                print(f"  {n.name:<30} {n.ip:<16} {dtype:<11} "
                      f"OK={counts['OK']} CHECK={counts['CHECK']} "
                      f"REVIEW={counts['REVIEW']}")
            except Exception as e:  # noqa: BLE001 - report and carry on
                errors.append((n.name, n.ip, str(e).splitlines()[0]))
                print(f"  {n.name:<30} {n.ip:<16} ERROR: {errors[-1][2]}")

    # ---- report ---------------------------------------------------------
    report = outdir / "report.csv"
    with report.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["device", "ip", "os", "line", "section",
                    "current", "new", "status", "note"])
        for m in sorted(all_matches, key=lambda x: (x.device, x.line_no)):
            w.writerow([m.device, m.ip, m.os_type, m.line_no, m.section,
                        m.old_line.strip(), m.new_line.strip(),
                        m.status, m.note])
        for name, ip, err in errors:
            w.writerow([name, ip, "", "", "", "", "", "ERROR", err])

    print(f"\n{len(all_matches)} instance(s) found. Output in ./{outdir}/")
    print("  *_apply.txt     safe changes, ready to paste (NOT applied)")
    print("  *_rollback.txt  reverses *_apply.txt")
    print("  *_review.txt    items needing a manual decision")
    print("  report.csv      every instance found")
    print("  backups/        running configs captured")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nAborted.")

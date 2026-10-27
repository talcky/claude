[README (1).md](https://github.com/user-attachments/files/34027527/README.1.md)
# switch_rename_prep.py

Prepares the configuration changes needed on neighbouring devices when a
Cisco switch is renamed. It finds every reference to the old switch name on
its CDP neighbours (interface descriptions, BGP neighbour descriptions,
VRF sections and anything else) and writes ready-to-review config with the
new name.

**It does not change any device.** It only runs `show cdp neighbors detail`
and `show running-config`. All output is written to local files for you to
review and apply yourself.

## Supported platforms

- Cisco NX-OS
- Cisco IOS / IOS-XE
- Cisco IOS-XR

The platform is identified from the CDP platform string. If it is not
recognised, Netmiko autodetect is used, falling back to IOS.

## Requirements

- Python 3.8 or later
- Netmiko 4 or later

```bash
pip install netmiko
```

- SSH access to the old switch and its neighbours from the machine running
  the script, using one username and password for all devices.

## How to run

```bash
python3 switch_rename_prep.py
```

You are prompted for:

| Prompt | Notes |
|---|---|
| Old switch name | Matching ignores case |
| New switch name | Written exactly as typed |
| Seed IP/hostname of the old switch | Defaults to the old name (needs DNS) |
| Username | Used for every device |
| Password | Hidden, not shown on screen |

Example session:

```
Switch rename - neighbour config preparation (no changes applied)

Old switch name : CORE-SW01
New switch name : DC1-CORE-01
Seed IP/hostname of the old switch [CORE-SW01]: 192.168.0.1
Username        : netadmin
Password        :

Connecting to seed 192.168.0.1 ...
  3 CDP neighbour(s), 2 to check
  skip SEP001122334455: capabilities 'Host Phone'
  LEAF1                          192.168.0.11     cisco_nxos  OK=3 CHECK=1 REVIEW=1
  ACC1                           192.168.0.21     cisco_ios   OK=1 CHECK=0 REVIEW=1

7 instance(s) found. Output in ./CORE-SW01_to_DC1-CORE-01_20261006_1715/
```

## What it does

1. Connects to the seed (the old switch) and reads its CDP neighbours.
2. Skips neighbours that are not routers or switches (phones, APs, hosts)
   and any with no IP address in CDP. The management address is used where
   CDP gives one.
3. Connects to up to 5 neighbours at a time and captures each running config.
4. Searches each config for the old name as a whole name, ignoring case:
   - `CORE-SW01`, `core-sw01`, `to-CORE-SW01`, `CORE-SW01:Eth1/1` and
     `CORE-SW01.corp.local` all match.
   - `CORE-SW010` and `XCORE-SW01` do not match.
5. Records the full config hierarchy for each match, for example
   `router bgp 65001 > vrf PROD > neighbor 10.1.0.1`, so the change is
   applied in the correct place.
6. Sorts every match into one of three groups:

| Status | Meaning | Where it goes |
|---|---|---|
| OK | Name is in free text (`description`, `remark`) or a banner. Re-entering overwrites the old value. Banners are rebuilt in full (see below). | `_apply.txt` |
| CHECK | Name is a command argument, e.g. `ip host CORE-SW01 10.0.0.1`. Re-entering may add a second entry, so the old line may need removing with `no`. | `_review.txt` |
| REVIEW | Name is in a section header (route-map, prefix-list, VRF name). Renaming creates a new object, so references and the old section need manual handling. | `_review.txt` |

### Banners

If the old name appears in a banner (`motd`, `login`, `exec` and so on), the
whole banner is rebuilt as one paste-ready block. Re-entering `banner <type>`
replaces the existing banner, so this is safe to apply.

- `banner motd ^CCC` means different things by platform, and both are
  handled:
  - IOS / IOS-XE / XR: `^C` is the delimiter, the banner ends at `^C`.
  - NX-OS: `^` is the delimiter, the banner ends at a bare `^`.
  The script tries the platform's own reading first, then the other.
- The delimiter is replaced with the first of `# % @ ~ | $ & *` not in the
  banner text, because a typed `^C` does not work as a delimiter when pasted.
- Characters after the delimiter on the first line (the `CC`/`CCC` in
  `^CCC`) are kept as banner text, as that is what the device holds. Delete
  that line from the new banner if you do not want it.
- If the end of a banner cannot be found within 60 lines, the banner is
  listed as REVIEW and the rest of the config is still checked normally.
- If the banner text contains every candidate delimiter, it is listed as
  REVIEW.

## Output

Each run creates a timestamped folder:
`<old>_to_<new>_<YYYYMMDD_HHMM>/`

If you run it twice in the same minute, the second folder gets `_2` added.

| File | Contents |
|---|---|
| `<device>_apply.txt` | OK changes with their parent hierarchy, wrapped in `configure terminal` ... `end`. IOS-XR files also include `commit`. |
| `<device>_rollback.txt` | The same changes with the old names, to reverse `_apply.txt`. |
| `<device>_review.txt` | CHECK and REVIEW items, each with section, current line, proposed line and a note. |
| `report.txt` | Plain-text report grouped by device. Each change shows the full current block and the full new block, ready to copy and paste. CHECK and REVIEW items include their note. |
| `report.csv` | Every instance found, plus any devices that could not be reached. One config line per row: each change is split across rows (parent lines, then the changed line) in the `current_config` and `new_config` columns, with a shared `change` number. Select those cells in Excel and copy to get paste-ready config. |
| `backups/<device>_running.cfg` | The running config captured from each neighbour. |

Example `report.txt` entry:

```
[OK] line 2 - interface Ethernet1/49

--- Current ---
interface Ethernet1/49
  description to-core-sw01:Eth1/1

--- New ---
interface Ethernet1/49
  description to-DC1-CORE-01:Eth1/1
```

Example `report.csv` rows (columns ip, os and note omitted here):

| device | change | line | section | current_config | new_config | status |
|---|---|---|---|---|---|---|
| LEAF1 | 1 | 2 | interface Ethernet1/49 | interface Ethernet1/49 | interface Ethernet1/49 | OK |
| LEAF1 | 1 | 2 | interface Ethernet1/49 | &nbsp;&nbsp;description to-core-sw01:Eth1/1 | &nbsp;&nbsp;description to-DC1-CORE-01:Eth1/1 | OK |
| LEAF1 | 2 | 6 | router bgp 65001 > vrf PROD > neighbor 10.1.0.1 | router bgp 65001 | router bgp 65001 | OK |
| LEAF1 | 2 | 6 | router bgp 65001 > vrf PROD > neighbor 10.1.0.1 | &nbsp;&nbsp;vrf PROD | &nbsp;&nbsp;vrf PROD | OK |
| LEAF1 | 2 | 6 | router bgp 65001 > vrf PROD > neighbor 10.1.0.1 | &nbsp;&nbsp;&nbsp;&nbsp;neighbor 10.1.0.1 | &nbsp;&nbsp;&nbsp;&nbsp;neighbor 10.1.0.1 | OK |
| LEAF1 | 2 | 6 | router bgp 65001 > vrf PROD > neighbor 10.1.0.1 | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;description CORE-SW01 PROD | &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;description DC1-CORE-01 PROD | OK |
| LEAF1 | 3 | 7 | (global) | ip host CORE-SW01 10.0.0.1 | ip host DC1-CORE-01 10.0.0.1 | CHECK |

The device, section and status repeat on every row, so filtering by device or
status keeps each block whole. The note is only on the first row of each
change.

Example `_apply.txt` (NX-OS):

```
configure terminal
interface Ethernet1/49
  description to-DC1-CORE-01:Eth1/1
 exit
router bgp 65001
  vrf PROD
    neighbor 10.1.0.1
      description DC1-CORE-01 PROD
     exit
   exit
 exit
end
```

## Applying the changes

1. Read `report.csv` and every `_review.txt` file.
2. Apply `_apply.txt` to each device in a change window.
3. Handle CHECK and REVIEW items manually.
4. Keep `_rollback.txt` ready in case you need to back out.

## Security

- The password is never shown or written to disk.
- The `backups/` folder and the output files contain device configuration
  and may include secrets (SNMP communities, keys, password hashes). Store
  them according to your security policy and do not commit them to Git.
  Add this to the repository's `.gitignore`:

  ```
  *_to_*_????????_????*/
  ```

## Limitations

- Only direct CDP neighbours of the seed are checked. The seed's own
  `hostname` is not changed.
- Hyphens count as separators, so an old name of `SW01` also matches
  `SW01-B`. Check `report.csv` if you have names like that.
- Devices are reached on the IP address CDP advertises. If that address is
  not reachable from where the script runs (for example it sits in a VRF
  your host cannot reach), the device is listed as ERROR in `report.csv`
  and the run continues.
- The `exit` lines in IOS-XR apply files have not been tested on a live XR
  device. Check one before using them widely.

## Settings

These can be changed at the top of the script:

| Setting | Default | Purpose |
|---|---|---|
| `MAX_WORKERS` | 5 | Number of neighbours connected to at once |
| `CDP_CAPS_INCLUDE` | Router, Switch | CDP capabilities that are checked |
| `READ_TIMEOUT` | 120 | Seconds allowed for `show running-config` |

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

7 instance(s) found. Output in ./rename_CORE-SW01_to_DC1-CORE-01_20261006_171500/
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
| OK | Name is in free text (`description`, `remark`). Re-entering the line overwrites the old value. | `_apply.txt` |
| CHECK | Name is a command argument, e.g. `ip host CORE-SW01 10.0.0.1`. Re-entering may add a second entry, so the old line may need removing with `no`. | `_review.txt` |
| REVIEW | Name is in a section header (route-map, prefix-list, VRF name) or a banner. Renaming creates a new object, so references and the old section need manual handling. | `_review.txt` |

## Output

Each run creates a timestamped folder:
`rename_<old>_to_<new>_<YYYYMMDD_HHMMSS>/`

| File | Contents |
|---|---|
| `<device>_apply.txt` | OK changes with their parent hierarchy, wrapped in `configure terminal` ... `end`. IOS-XR files also include `commit`. |
| `<device>_rollback.txt` | The same changes with the old names, to reverse `_apply.txt`. |
| `<device>_review.txt` | CHECK and REVIEW items, each with section, current line, proposed line and a note. |
| `report.csv` | Every instance found, plus any devices that could not be reached. |
| `backups/<device>_running.cfg` | The running config captured from each neighbour. |

Example `report.csv` rows:

| status | section | current | new |
|---|---|---|---|
| OK | interface Ethernet1/49 | description to-core-sw01:Eth1/1 | description to-DC1-CORE-01:Eth1/1 |
| OK | router bgp 65001 > vrf PROD > neighbor 10.1.0.1 | description CORE-SW01 PROD | description DC1-CORE-01 PROD |
| CHECK | (global) | ip host CORE-SW01 10.0.0.1 | ip host DC1-CORE-01 10.0.0.1 |
| REVIEW | (global) | route-map TO-CORE-SW01 permit 10 | route-map TO-DC1-CORE-01 permit 10 |

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
  rename_*/
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

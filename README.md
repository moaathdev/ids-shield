# IDS Shield

**A lightweight, dependency-free Intrusion Detection System for Windows, built on raw sockets.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

IDS Shield passively inspects IPv4 traffic on a Windows host and raises an alert when it
recognises the network-layer fingerprints of well-known reconnaissance techniques: TCP
stealth scans, UDP sweeps, and ICMP ping scans.

It is a single file, uses only the Python standard library, and is written to be **read** as
much as run — the detection logic is deliberately small and explicit.

---

## Detections

| Attack | Signal | Default threshold | Window |
| --- | --- | --- | --- |
| **SYN scan** | `SYN` set, `ACK` clear | > 8 distinct ports | 3 s |
| **FIN scan** | `FIN` set, no `SYN`/`ACK`/`RST` | > 8 distinct ports | 3 s |
| **XMAS scan** | `FIN` + `PSH` + `URG` | > 8 distinct ports | 3 s |
| **NULL scan** | no flags set | > 8 distinct ports | 3 s |
| **UDP scan** | distinct destination ports | > 15 distinct ports | 3 s |
| **ICMP sweep** | `Echo Request` (type 8) | > 8 packets | 3 s |

TCP and UDP share a port window; ICMP uses its own independent counter. UDP is deliberately
given a higher bar than TCP because ordinary traffic (mDNS, SSDP, NBNS, QUIC) generates
plenty of scattered UDP packets and would otherwise cause constant false positives.

---

## Design notes

Version 3 is a rewrite driven by the failure modes of a naive implementation. Each of these
is a real correctness bug, not a cosmetic change:

- **Separate windows per protocol family.** A shared counter let ICMP traffic reset the TCP
  state and vice versa, silently masking slow scans.
- **True sliding window** anchored at the *first* packet of a burst, instead of resetting the
  clock on every packet — which let an attacker evade detection forever by pacing packets.
- **UDP is rate-based, not per-packet.** A single UDP datagram is not an attack.
- **File logging instead of per-packet prints.** Console I/O in the capture loop stalled the
  socket and caused kernel buffer overruns, i.e. dropped evidence.
- **Two-stage alarm cooldown** (per-attacker + global) so a single noisy host cannot produce an
  unbounded alert storm.
- **Idle-source reaping.** The per-source table is pruned every 60 s, fixing an unbounded
  memory growth that eventually killed long-running captures.
- **Fragment-aware parsing.** Non-first IPv4 fragments have no L4 header; parsing them as TCP
  produced garbage ports and phantom detections.

---

## How it works

```
     raw socket (SIO_RCVALL)
              │
              ▼
    ┌──────────────────┐
    │  IP header parse │── malformed ──▶ drop
    └────────┬─────────┘
             │  skip non-first fragments, skip own traffic
             ▼
      ┌──────┴───────┬──────────────┐
      ▼              ▼              ▼
   TCP handler   UDP handler    ICMP handler
      │              │              │
      └──────────────┴──────────────┘
                     ▼
        per-source sliding window
                     ▼
      threshold crossed ──▶ alert (log + optional sound)
```

State is held per source IP in `SourceState` and guarded by a single lock, so the capture
thread and the housekeeping thread cannot corrupt each other.

---

## Requirements

- Windows (uses `SIO_RCVALL`; unavailable elsewhere)
- Python 3.8+
- **Administrator privileges** (raw sockets)
- No third-party packages

---

## Usage

```bash
git clone https://github.com/gghhjjll/ids-shield.git
cd ids-shield
```

Run from an **elevated** prompt:

```bash
python ids_shield.py
```

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--iface <ip>` | auto-detect | Local interface IP to bind and sniff on |
| `--log <path>` | `ids.log` | Alert log file |
| `--sound <path>` | `$IDS_SOUND` | `.wav` played on alert; falls back to a beep |
| `--verbose` | off | Also print a line per captured packet |

```bash
python ids_shield.py --iface 192.168.1.10 --verbose
python ids_shield.py --sound "C:\sounds\siren.wav" --log lab.log
```

### Alert output

```
**********************************************************************
 [!!!] CRITICAL SECURITY EVENT DETECTED
 [>] ATTACKER IP : 192.168.1.66
 [>] METHOD      : TCP Port Scan (SYN Scan)
 [>] DETAILS     : distinct_ports=9 ports=[21, 22, 23, 25, 80, 110, 139, 443, 445]
**********************************************************************
```

The same event is written to the log file as a single structured line:

```
2026-10-25 14:22:31,114 CRITICAL ALERT attacker=192.168.1.66 method=TCP Port Scan (SYN Scan) details=distinct_ports=9 ...
```

---

## Tuning

Thresholds live at the top of the file, in one block, so they are easy to audit:

```python
TCP_PORT_THRESHOLD  = 8
UDP_PORT_THRESHOLD  = 15
ICMP_THRESHOLD      = 8
TIME_WINDOW         = 3.0
SOURCE_TTL          = 300.0
```

For a noisy LAN, raise `UDP_PORT_THRESHOLD` first. To catch slower, stealthier scans, increase
`TIME_WINDOW` rather than lowering the port threshold — it costs fewer false positives.

---

## Limitations

- IPv4 only; IPv6 traffic is ignored.
- Detects reconnaissance, not exploitation. No payload inspection or signature matching.
- Threshold-based: a slow scan spread over minutes will not trip the window.
- Alerts are local (log + sound). There is no SIEM forwarder or webhook.
- Tested on Windows 10/11 only.

### Roadmap

- [ ] Optional syslog / webhook alert sink
- [ ] Config file instead of constants
- [ ] IPv6 support
- [ ] Unit tests for the packet parsers and scan classifier

---

## Disclaimer

This tool is provided for **education and authorised lab use only**. Capture traffic solely on
networks you own or have explicit written permission to monitor. Running it on a network you
do not control may violate law and policy. The author accepts no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).

#!/usr/bin/env python3
"""
IDS Shield v3.0
===============
Windows raw-socket Intrusion Detection System (educational / lab use only).

Detects:
  * TCP SYN / FIN / XMAS / NULL port scans
  * UDP port scans (port-rate based, NOT "every UDP packet")
  * ICMP ping sweeps

Fixes over v2.0:
  - Separate time-windows for ICMP vs TCP/UDP (removes shared-counter bug)
  - TRUE sliding window anchored at the first packet of the burst
  - FIN / XMAS / NULL scan detection
  - UDP is no longer flagged by a single packet; uses its own higher threshold
  - File logging instead of printing every packet (no capture stall / packet loss)
  - Per-attacker alarm cooldown + a global minimum
  - Periodic cleanup of idle sources (fixes the unbounded-growth memory leak)
  - Fragment-aware L4 parsing (skips non-first fragments)
  - Auto interface detection + CLI override
  - Configurable alarm sound (CLI / env) with graceful fallback
  - Robust error handling around recvfrom and socket setup

Requirements:
  - Windows, run as Administrator (raw sockets + SIO_RCVALL)
  - Python 3.8+

Usage:
  python ids_shield.py
  python ids_shield.py --iface 192.168.1.10
  python ids_shield.py --verbose
  python ids_shield.py --sound "C:\\sounds\\siren.wav"
  python ids_shield.py --log ids.log
"""

import argparse
import logging
import os
import socket
import struct
import sys
import threading
import time
from collections import defaultdict

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
TCP_PORT_THRESHOLD = 8        # distinct TCP ports / window -> scan
UDP_PORT_THRESHOLD = 15       # UDP is noisier -> higher bar
ICMP_THRESHOLD = 8            # echo-requests / window -> sweep
TIME_WINDOW = 3.0             # sliding window length (seconds)
SOURCE_TTL = 300.0            # forget idle sources after 5 minutes
CLEANUP_INTERVAL = 60.0       # housekeeping period (seconds)
ALARM_COOLDOWN_PER_IP = 15.0  # min seconds between sounds for one attacker
ALARM_COOLDOWN_GLOBAL = 3.0   # min seconds between any two sounds

DEFAULT_SOUND = os.environ.get("IDS_SOUND", "")  # e.g. "C:\\sounds\\siren.wav"

# TCP flag bits
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

log = logging.getLogger("ids")


# ----------------------------------------------------------------------------
# Per-source state
# ----------------------------------------------------------------------------
class SourceState:
    __slots__ = (
        "tcp_ports",       # scan_type -> set(ports)
        "udp_ports",       # set(ports)
        "port_win_start",  # window anchor for TCP/UDP
        "icmp_count",
        "icmp_win_start",  # separate window anchor for ICMP
        "last_seen",
        "last_alarm",
    )

    def __init__(self, now):
        self.tcp_ports = defaultdict(set)
        self.udp_ports = set()
        self.port_win_start = now
        self.icmp_count = 0
        self.icmp_win_start = now
        self.last_seen = now
        self.last_alarm = 0.0


sources = {}
sources_lock = threading.Lock()
last_global_alarm = 0.0


def _get_state_locked(ip, now):
    st = sources.get(ip)
    if st is None:
        st = SourceState(now)
        sources[ip] = st
    st.last_seen = now
    return st


# ----------------------------------------------------------------------------
# Alarm / sound
# ----------------------------------------------------------------------------
def play_alarm_sound(sound_path):
    if os.name != "nt":
        return
    try:
        import winsound
    except ImportError:
        return
    if sound_path and os.path.isfile(sound_path):
        try:
            winsound.PlaySound(
                sound_path, winsound.SND_FILENAME | winsound.SND_ASYNC
            )
            return
        except Exception:
            pass
    try:
        winsound.Beep(2000, 500)
    except Exception:
        pass


def trigger_alarm(attacker_ip, attack_type, detail="", sound_path=""):
    global last_global_alarm
    now = time.time()

    with sources_lock:
        st = _get_state_locked(attacker_ip, now)
        per_ip_ok = (now - st.last_alarm) >= ALARM_COOLDOWN_PER_IP
        if per_ip_ok:
            st.last_alarm = now
        global_ok = (now - last_global_alarm) >= ALARM_COOLDOWN_GLOBAL
        if per_ip_ok and global_ok:
            last_global_alarm = now
            should_play = True
        else:
            should_play = False

    line = "*" * 70
    msg = (
        f"\n{line}\n"
        f" [!!!] CRITICAL SECURITY EVENT DETECTED\n"
        f" [>] ATTACKER IP : {attacker_ip}\n"
        f" [>] METHOD      : {attack_type}\n"
        f" [>] DETAILS     : {detail}\n"
        f"{line}\n"
    )
    log.critical(
        "ALERT attacker=%s method=%s details=%s", attacker_ip, attack_type, detail
    )
    print(msg)

    if should_play:
        play_alarm_sound(sound_path)
    else:
        log.info("Alarm sound suppressed (cooldown) for %s", attacker_ip)


# ----------------------------------------------------------------------------
# Packet parsing
# ----------------------------------------------------------------------------
def parse_ip_header(raw):
    """Return a dict of IP header fields, or None if malformed/unsupported."""
    if len(raw) < 20:
        return None

    iph = struct.unpack("!BBHHHBBH4s4s", raw[:20])
    version = iph[0] >> 4
    ihl = (iph[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(raw) < ihl:
        return None

    total_len = iph[2]
    frag_field = iph[4]
    mf = (frag_field & 0x2000) != 0
    frag_offset = frag_field & 0x1FFF

    if 0 < total_len <= len(raw):
        payload = raw[ihl:total_len]
    else:
        payload = raw[ihl:]

    return {
        "protocol": iph[6],
        "src": socket.inet_ntoa(iph[8]),
        "dst": socket.inet_ntoa(iph[9]),
        "payload": payload,
        "mf": mf,
        "frag_offset": frag_offset,
    }


def classify_tcp_scan(flags):
    """Return the scan type name, or None if it looks like normal traffic."""
    if flags == 0:
        return "NULL Scan"
    if flags & TCP_FIN and flags & TCP_PSH and flags & TCP_URG:
        return "XMAS Scan"
    if flags & TCP_FIN and not (flags & (TCP_SYN | TCP_ACK | TCP_RST)):
        return "FIN Scan"
    if flags & TCP_SYN and not (flags & TCP_ACK):
        return "SYN Scan"
    return None


def handle_tcp(ip, now, sound_path):
    payload = ip["payload"]
    if len(payload) < 20:
        return
    tcph = struct.unpack("!HHLLBBHHH", payload[:20])
    dst_port = tcph[1]
    flags = tcph[5]

    scan = classify_tcp_scan(flags)
    if not scan:
        return

    with sources_lock:
        st = _get_state_locked(ip["src"], now)
        # TRUE sliding window anchored at the first packet of the burst.
        if now - st.port_win_start > TIME_WINDOW:
            st.tcp_ports.clear()
            st.udp_ports.clear()
            st.port_win_start = now
        st.tcp_ports[scan].add(dst_port)
        total = sum(len(v) for v in st.tcp_ports.values())
        seen_ports = sorted(set().union(*st.tcp_ports.values()))
        fire = total > TCP_PORT_THRESHOLD
        if fire:
            st.tcp_ports.clear()
            st.udp_ports.clear()

    if fire:
        trigger_alarm(
            ip["src"],
            f"TCP Port Scan ({scan})",
            f"distinct_ports={total} ports={seen_ports}",
            sound_path,
        )


def handle_udp(ip, now, sound_path):
    payload = ip["payload"]
    if len(payload) < 8:
        return
    udph = struct.unpack("!HHHH", payload[:8])
    dst_port = udph[1]

    with sources_lock:
        st = _get_state_locked(ip["src"], now)
        if now - st.port_win_start > TIME_WINDOW:
            st.tcp_ports.clear()
            st.udp_ports.clear()
            st.port_win_start = now
        st.udp_ports.add(dst_port)
        total = len(st.udp_ports)
        seen_ports = sorted(st.udp_ports)
        fire = total > UDP_PORT_THRESHOLD
        if fire:
            st.udp_ports.clear()
            st.tcp_ports.clear()

    if fire:
        trigger_alarm(
            ip["src"],
            "UDP Port Scan",
            f"distinct_ports={total} ports={seen_ports}",
            sound_path,
        )


def handle_icmp(ip, now, sound_path):
    payload = ip["payload"]
    if len(payload) < 1:
        return
    icmp_type = payload[0]
    if icmp_type != 8:  # only Echo Request (ping)
        return

    with sources_lock:
        st = _get_state_locked(ip["src"], now)
        if now - st.icmp_win_start > TIME_WINDOW:
            st.icmp_count = 0
            st.icmp_win_start = now
        st.icmp_count += 1
        count = st.icmp_count
        fire = count > ICMP_THRESHOLD
        if fire:
            st.icmp_count = 0

    if fire:
        trigger_alarm(
            ip["src"],
            "ICMP Ping Sweep / OS Discovery",
            f"echo_requests={count}",
            sound_path,
        )


# ----------------------------------------------------------------------------
# Housekeeping
# ----------------------------------------------------------------------------
def cleanup_loop(stop_event):
    while not stop_event.wait(CLEANUP_INTERVAL):
        now = time.time()
        with sources_lock:
            dead = [k for k, v in sources.items() if now - v.last_seen > SOURCE_TTL]
            for k in dead:
                del sources[k]
        if dead:
            log.info("Cleaned up %d idle source(s)", len(dead))


# ----------------------------------------------------------------------------
# Setup helpers
# ----------------------------------------------------------------------------
def detect_local_ip():
    """Best-effort detection of the primary interface IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets are actually sent for a UDP connect.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        s.close()


def setup_logging(logfile, verbose):
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.handlers.clear()

    fh = logging.FileHandler(logfile, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))
    log.addHandler(fh)

    if verbose:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(ch)


def parse_args():
    p = argparse.ArgumentParser(description="IDS Shield v3.0")
    p.add_argument("--iface", default="", help="Local IP to bind / sniff on")
    p.add_argument("--sound", default=DEFAULT_SOUND, help="Path to alarm .wav")
    p.add_argument("--log", default="ids.log", help="Log file path")
    p.add_argument("--verbose", action="store_true", help="Print every packet")
    return p.parse_args()


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    args = parse_args()
    setup_logging(args.log, args.verbose)

    if os.name != "nt":
        print("[!] This tool relies on Windows SIO_RCVALL and will not work here.")
        sys.exit(1)

    local_ip = args.iface or detect_local_ip()

    print("=" * 70)
    print(" IDS Shield v3.0")
    print(f" Listening on interface : {local_ip}")
    print(f" Log file               : {args.log}")
    print(f" TCP/UDP window         : {TIME_WINDOW}s "
          f"(TCP>{TCP_PORT_THRESHOLD}, UDP>{UDP_PORT_THRESHOLD} ports)")
    print(f" ICMP threshold         : >{ICMP_THRESHOLD} echo-requests / {TIME_WINDOW}s")
    print("=" * 70)

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    except PermissionError:
        print("[!] Raw sockets require Administrator privileges. Run as Admin.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Could not open raw socket: {e}. Run as Administrator.")
        sys.exit(1)

    try:
        sniffer.bind((local_ip, 0))
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except OSError as e:
        print(f"[!] Failed to bind/enable capture on {local_ip}: {e}")
        sniffer.close()
        sys.exit(1)

    stop_event = threading.Event()
    cleaner = threading.Thread(target=cleanup_loop, args=(stop_event,), daemon=True)
    cleaner.start()

    log.info("Capture started on %s", local_ip)

    try:
        while True:
            try:
                raw_data, _ = sniffer.recvfrom(65535)
            except OSError as e:
                log.warning("recvfrom failed: %s", e)
                continue

            now = time.time()
            ip = parse_ip_header(raw_data)
            if ip is None:
                continue
            if ip["src"] == local_ip:
                continue
            if ip["frag_offset"] != 0:
                # Non-first fragment: L4 header isn't present. Skip.
                continue

            proto = ip["protocol"]
            if proto == socket.IPPROTO_TCP:
                handle_tcp(ip, now, args.sound)
            elif proto == socket.IPPROTO_UDP:
                handle_udp(ip, now, args.sound)
            elif proto == socket.IPPROTO_ICMP:
                handle_icmp(ip, now, args.sound)

            if args.verbose:
                log.debug("pkt %s -> %s proto=%s len=%d",
                          ip["src"], ip["dst"], proto, len(raw_data))

    except KeyboardInterrupt:
        print("\n[-] Shutting down securely...")
    finally:
        stop_event.set()
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
        sniffer.close()
        log.info("Capture stopped.")


if __name__ == "__main__":
    main()

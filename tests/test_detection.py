"""Unit tests for the stateless parts of IDS Shield.

Run with:  python -m unittest discover -s tests -v
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ids_shield as ids  # noqa: E402


def build_ipv4(protocol=6, src="10.0.0.1", dst="10.0.0.2",
               flags_frag=0, total_len=40, payload=b"\x00" * 20):
    """Assemble a minimal but valid IPv4 header + payload."""
    import socket

    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,             # version 4, IHL 5
        0,                # DSCP/ECN
        total_len,        # total length
        0,                # identification
        flags_frag,       # flags + fragment offset
        64,               # TTL
        protocol,
        0,                # checksum (not validated by the parser)
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


class TestParseIpHeader(unittest.TestCase):
    def test_parses_valid_packet(self):
        pkt = build_ipv4(src="192.168.1.5", dst="192.168.1.9")
        ip = ids.parse_ip_header(pkt)
        self.assertIsNotNone(ip)
        self.assertEqual(ip["src"], "192.168.1.5")
        self.assertEqual(ip["dst"], "192.168.1.9")
        self.assertEqual(ip["protocol"], 6)
        self.assertEqual(ip["frag_offset"], 0)
        self.assertFalse(ip["mf"])

    def test_rejects_truncated_header(self):
        self.assertIsNone(ids.parse_ip_header(b"\x45\x00"))

    def test_rejects_ipv6_version_bits(self):
        pkt = bytearray(build_ipv4())
        pkt[0] = 0x65  # version 6
        self.assertIsNone(ids.parse_ip_header(bytes(pkt)))

    def test_rejects_bogus_ihl(self):
        pkt = bytearray(build_ipv4())
        pkt[0] = 0x43  # IHL = 3 words (12 bytes) -> invalid
        self.assertIsNone(ids.parse_ip_header(bytes(pkt)))

    def test_detects_more_fragments_flag(self):
        # MF bit set, offset 0 -> first fragment
        pkt = build_ipv4(flags_frag=0x2000)
        ip = ids.parse_ip_header(pkt)
        self.assertTrue(ip["mf"])
        self.assertEqual(ip["frag_offset"], 0)

    def test_detects_fragment_offset(self):
        # offset 185 * 8 = 1480 bytes
        pkt = build_ipv4(flags_frag=185)
        ip = ids.parse_ip_header(pkt)
        self.assertEqual(ip["frag_offset"], 185)
        self.assertFalse(ip["mf"])

    def test_payload_truncated_by_total_length(self):
        # total_len claims 24 bytes (20 header + 4 payload); we hand it 20 bytes of payload
        pkt = build_ipv4(total_len=24, payload=b"\xAA" * 20)
        ip = ids.parse_ip_header(pkt)
        self.assertEqual(len(ip["payload"]), 4)


class TestClassifyTcpScan(unittest.TestCase):
    def test_syn_scan(self):
        self.assertEqual(ids.classify_tcp_scan(ids.TCP_SYN), "SYN Scan")

    def test_fin_scan(self):
        self.assertEqual(ids.classify_tcp_scan(ids.TCP_FIN), "FIN Scan")

    def test_xmas_scan(self):
        flags = ids.TCP_FIN | ids.TCP_PSH | ids.TCP_URG
        self.assertEqual(ids.classify_tcp_scan(flags), "XMAS Scan")

    def test_null_scan(self):
        self.assertEqual(ids.classify_tcp_scan(0), "NULL Scan")

    def test_syn_ack_is_normal_traffic(self):
        self.assertIsNone(ids.classify_tcp_scan(ids.TCP_SYN | ids.TCP_ACK))

    def test_plain_ack_is_normal_traffic(self):
        self.assertIsNone(ids.classify_tcp_scan(ids.TCP_ACK))

    def test_psh_ack_is_normal_traffic(self):
        self.assertIsNone(ids.classify_tcp_scan(ids.TCP_PSH | ids.TCP_ACK))


class TestSourceState(unittest.TestCase):
    def test_state_initialised_per_source(self):
        st = ids.SourceState(100.0)
        self.assertEqual(st.icmp_count, 0)
        self.assertEqual(st.port_win_start, 100.0)
        self.assertEqual(st.last_alarm, 0.0)
        self.assertEqual(len(st.udp_ports), 0)

    def test_tcp_ports_grouped_by_scan_type(self):
        st = ids.SourceState(0.0)
        st.tcp_ports["SYN Scan"].add(80)
        st.tcp_ports["FIN Scan"].add(443)
        total = sum(len(v) for v in st.tcp_ports.values())
        self.assertEqual(total, 2)


if __name__ == "__main__":
    unittest.main()

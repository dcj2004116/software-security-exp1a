"""parser.py 协议解析单元测试（标准库 unittest，零第三方依赖）。

运行方式（在 EX1A 目录下）：
    python -m unittest discover -s tests -v
"""
import os
import struct
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parser as P


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def eth(etype, data):
    return mac("aabbccddeeff") + mac("112233445566") + struct.pack("!H", etype) + data


def ipv4(proto, payload, src="192.168.1.100", dst="192.168.1.1"):
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0, src_b, dst_b) + payload


def tcp(sport, dport, payload, seq=1000, ack=2000, flags=0x18):
    return struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


class TestEthernet(unittest.TestCase):
    def test_plain(self):
        layer, rest, etype = P.parse_ethernet(eth(0x0800, b"payload"))
        self.assertEqual(etype, 0x0800)
        self.assertEqual(layer["fields"]["Source"], "11:22:33:44:55:66")

    def test_vlan(self):
        # 802.1Q：VLAN 头 + 内层 EtherType
        frame = mac("aabbccddeeff") + mac("112233445566") + struct.pack("!HHH", 0x8100, 100, 0x0800) + b"x"
        layer, rest, etype = P.parse_ethernet(frame)
        self.assertEqual(etype, 0x0800)
        self.assertEqual(layer["fields"]["802.1Q VLAN ID"], "100")


class TestIPv4(unittest.TestCase):
    def test_parse(self):
        layer, rest, proto = P.parse_ipv4(ipv4(6, b"abc"))
        self.assertEqual(proto, 6)
        self.assertEqual(layer["fields"]["Source"], "192.168.1.100")
        self.assertEqual(layer["fields"]["TTL"], 64)


class TestTCP(unittest.TestCase):
    def test_parse(self):
        layer, rest, ports = P.parse_tcp(tcp(12345, 8080, b"hi"))
        self.assertEqual(ports, (12345, 8080))
        self.assertEqual(layer["fields"]["Sequence Number"], 1000)
        self.assertIn("ACK", layer["fields"]["Flags"])
        self.assertEqual(rest, b"hi")


class TestUDP(unittest.TestCase):
    def test_parse(self):
        layer, rest, ports = P.parse_udp(udp(5353, 53, b"dns"))
        self.assertEqual(ports, (5353, 53))
        self.assertEqual(rest, b"dns")


class TestHTTP(unittest.TestCase):
    def test_request(self):
        layer, _ = P.parse_http(b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(layer["name"], "HTTP")
        self.assertEqual(layer["fields"]["Method"], "POST")

    def test_response_status(self):
        layer, _ = P.parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(layer["fields"]["Status Code"], 200)


class TestDNS(unittest.TestCase):
    def test_query(self):
        q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        q += b"\x03www\x06google\x03com\x00" + struct.pack("!HH", 1, 1)
        layer, _ = P.parse_dns(q)
        self.assertEqual(layer["fields"]["Query"], "www.google.com")
        self.assertEqual(layer["fields"]["Query Type"], 1)


def _dhcp(msg_type=1, hostname=b"testhost"):
    op = struct.pack("!BBBB", 1, 1, 6, 0)           # op/htype/hlen/hops
    xid = struct.pack("!I", 0x12345678)
    secs_flags = struct.pack("!HH", 0, 0)
    zeros4 = b"\x00" * 4                             # ciaddr/yiaddr/siaddr/giaddr
    chaddr = mac("aabbccddeeff") + b"\x00" * 10
    sname = b"\x00" * 64
    fname = b"\x00" * 128
    magic = b"\x63\x82\x53\x63"
    opts = b"\x35\x01" + bytes([msg_type])           # option 53 Message Type
    opts += b"\x0c" + bytes([len(hostname)]) + hostname  # option 12 Host Name
    opts += b"\xff"
    return op + xid + secs_flags + zeros4 * 4 + chaddr + sname + fname + magic + opts


class TestDHCP(unittest.TestCase):
    def test_parse(self):
        layer, _ = P.parse_dhcp(_dhcp(msg_type=1, hostname=b"testhost"))
        self.assertEqual(layer["name"], "DHCP")
        self.assertIn("DISCOVER", layer["fields"]["Message Type"])
        self.assertEqual(layer["fields"]["Host Name"], "testhost")
        self.assertEqual(layer["fields"]["Client MAC"], "aa:bb:cc:dd:ee:ff")

    def test_full_pipeline(self):
        p = P.parse(eth(0x0800, ipv4(17, udp(68, 67, _dhcp(msg_type=3, hostname=b"pc1")))), 1.0, 1, 1)
        self.assertEqual(p["proto"], "DHCP")
        self.assertIn("REQUEST", p["summary"])


class TestTLS(unittest.TestCase):
    def _clienthello(self, sni=None):
        body = b"\x03\x03"                       # client_version
        body += bytes(range(32))                  # random
        body += b"\x00"                           # session_id 长度 0
        body += b"\x00\x02\x00\x2f"               # 1 个密码套件 TLS_RSA_WITH_AES_128_CBC_SHA
        body += b"\x01\x00"                       # 1 个压缩方法 null
        if sni:
            name = sni.encode()
            ext_data = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
            ext = struct.pack("!HH", 0, len(ext_data)) + ext_data   # type 0 = server_name
            body += struct.pack("!H", len(ext)) + ext
        else:
            body += b"\x00\x00"                   # 无扩展
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        return record

    def test_clienthello_sni(self):
        layer, _ = P.parse_tls(self._clienthello(sni="example.com"))
        self.assertEqual(layer["fields"]["Handshake Type"], "1 (ClientHello)")
        self.assertEqual(layer["fields"]["Server Name (SNI)"], "example.com")

    def test_no_sni(self):
        layer, _ = P.parse_tls(self._clienthello())
        self.assertNotIn("Server Name (SNI)", layer["fields"])


class TestParsePipeline(unittest.TestCase):
    def test_http_full(self):
        p = P.parse(eth(0x0800, ipv4(6, tcp(12345, 8080, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))), 1.0, 1, 1)
        self.assertEqual(p["proto"], "HTTP")
        self.assertEqual(p["summary"], "GET / HTTP/1.1")
        self.assertEqual([l["name"] for l in p["layers"]], ["Ethernet II", "IPv4", "TCP", "HTTP"])

    def test_dns_full(self):
        q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x01a\x03biz\x00" + struct.pack("!HH", 1, 1)
        p = P.parse(eth(0x0800, ipv4(17, udp(5353, 53, q))), 1.0, 1, 1)
        self.assertEqual(p["proto"], "DNS")
        self.assertIn("a.biz", p["summary"])

    def test_arp_full(self):
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                          mac("112233445566"), socket.inet_aton("192.168.1.100"),
                          mac("000000000000"), socket.inet_aton("192.168.1.1"))
        p = P.parse(eth(0x0806, arp), 1.0, 1, 1)
        self.assertEqual(p["proto"], "ARP")
        self.assertIn("Who has 192.168.1.1", p["summary"])

    def test_icmp_full(self):
        icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"abcdefgh"
        p = P.parse(eth(0x0800, ipv4(1, icmp)), 1.0, 1, 1)
        self.assertEqual(p["proto"], "ICMP")
        self.assertIn("Echo Request", p["summary"])

    def test_tls_sni_summary(self):
        # 构造带 SNI 的 ClientHello，走完整 TCP 解析，验证 summary 提取 SNI
        body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
        name = b"secure.example.org"
        ext_data = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
        ext = struct.pack("!HH", 0, len(ext_data)) + ext_data
        body += struct.pack("!H", len(ext)) + ext
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
        p = P.parse(eth(0x0800, ipv4(6, tcp(50000, 443, record))), 1.0, 1, 1)
        self.assertEqual(p["proto"], "TLS")
        self.assertIn("secure.example.org", p["summary"])


if __name__ == "__main__":
    unittest.main()

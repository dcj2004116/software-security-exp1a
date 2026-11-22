"""flow.py 流追踪与进程映射单元测试（标准库 unittest）。"""
import os
import struct
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parser as P
import flow as F


def mac(s):
    return bytes.fromhex(s.replace(":", ""))


def eth(etype, data):
    return mac("aabbccddeeff") + mac("112233445566") + struct.pack("!H", etype) + data


def ipv4(proto, payload, src="192.168.1.100", dst="192.168.1.1"):
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total = 20 + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0, src_b, dst_b) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


class TestFlowTracker(unittest.TestCase):
    def test_bidirectional_reassembly(self):
        tracker = F.FlowTracker()
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        p1 = P.parse(eth(0x0800, ipv4(6, tcp(40000, 8080, req, seq=1))), 10.0, 1, 1)
        tracker.add(p1)
        # 第二个正向段：seq 续上，应无缝重组
        p2 = P.parse(eth(0x0800, ipv4(6, tcp(40000, 8080, b"tail", seq=1 + len(req)))), 10.1, 1, 2)
        tracker.add(p2)
        # 反向段
        resp = b"HTTP/1.1 200 OK\r\n\r\n"
        p3 = P.parse(eth(0x0800, ipv4(6, tcp(8080, 40000, resp, seq=5000),
                                       src="192.168.1.1", dst="192.168.1.100")), 10.2, 1, 3)
        tracker.add(p3)

        flows = tracker.list()
        self.assertEqual(len(flows), 1)
        f = flows[0]
        self.assertEqual(f["packets"], 3)
        self.assertEqual(f["bytes"], len(req) + len(b"tail") + len(resp))

        res = tracker.follow(p1["flowkey"])
        self.assertEqual(res["packets"], 3)
        self.assertEqual(len(res["directions"]), 2)
        # 正向流应把两段顺序重组
        fwd = [d for d in res["directions"] if "40000" in d["direction"]][0]
        self.assertEqual(fwd["bytes"], req + b"tail")

    def test_retransmission_dedup(self):
        tracker = F.FlowTracker()
        payload = b"hello world"
        p1 = P.parse(eth(0x0800, ipv4(6, tcp(1, 2, payload, seq=100))), 1.0, 1, 1)
        tracker.add(p1)
        # 重传同一段（seq 相同），不应重复追加
        p2 = P.parse(eth(0x0800, ipv4(6, tcp(1, 2, payload, seq=100))), 1.1, 1, 2)
        tracker.add(p2)
        res = tracker.follow(p1["flowkey"])
        fwd = res["directions"][0]["bytes"]
        self.assertEqual(fwd, payload)   # 只出现一次


class TestProcessMap(unittest.TestCase):
    def test_get_process_map_returns_dict(self):
        # 只验证返回类型与结构，不校验具体内容（依赖本机环境）
        m = F.get_process_map()
        self.assertIsInstance(m, dict)
        for (ip, port), (pid, name) in list(m.items())[:3]:
            self.assertIsInstance(ip, str)
            self.assertIsInstance(port, int)
            self.assertIsInstance(pid, int)
            self.assertIsInstance(name, str)

    def test_get_process_connections_returns_list(self):
        conns = F.get_process_connections()
        self.assertIsInstance(conns, list)
        for c in conns[:3]:
            for k in ("pid", "name", "proto", "local_ip", "local_port",
                      "remote_ip", "remote_port"):
                self.assertIn(k, c)


class TestFlowsForConnections(unittest.TestCase):
    def test_match_by_endpoint(self):
        tracker = F.FlowTracker()
        req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        p1 = P.parse(eth(0x0800, ipv4(6, tcp(40000, 8080, req, seq=1))), 1.0, 1, 1)
        tracker.add(p1)
        # 模拟进程的一条连接：本地 192.168.1.100:40000 -> 远端 192.168.1.1:8080
        conns = [{"pid": 123, "name": "app", "proto": "TCP",
                  "local_ip": "192.168.1.100", "local_port": 40000,
                  "remote_ip": "192.168.1.1", "remote_port": 8080}]
        keys = tracker.flows_for_connections(conns)
        self.assertEqual(keys, {p1["flowkey"]})


if __name__ == "__main__":
    unittest.main()

"""
flow.py —— TCP 流追踪(Follow TCP Stream) + 进程→连接映射(Linux /proc)
"""
import os
import re
import socket


class FlowTracker:
    """按 (IP, Port) 四元组(双向归一化) 聚合 TCP 流，支持按 seq 重组"""
    def __init__(self):
        self.flows = {}

    def reset(self):
        self.flows.clear()

    def add(self, pkt):
        key = pkt.get("flowkey")
        if not key:
            return
        if pkt.get("proto") not in ("TCP", "HTTP", "TLS"):
            return
        sport = pkt.get("sport")
        dport = pkt.get("dport")
        if sport is None or dport is None:
            return
        if key not in self.flows:
            self.flows[key] = {"label": pkt.get("flowlabel", key), "n": 0, "dirs": {}}
        flow = self.flows[key]
        flow["n"] += 1

        direction = (pkt.get("src_ip", ""), sport, pkt.get("dst_ip", ""), dport)
        seq = pkt.get("seq")
        payload = pkt.get("payload") or b""
        d = flow["dirs"].setdefault(direction, {"segments": []})
        if seq is not None and payload:
            d["segments"].append((seq, payload))

    def follow(self, key):
        """返回按 seq 重组的双向流内容"""
        flow = self.flows.get(key)
        if not flow:
            return None
        out = []
        for direction, d in flow["dirs"].items():
            src_ip, src_port, dst_ip, dst_port = direction
            segs = sorted(d["segments"])
            reassembled = bytearray()
            expected = None
            for seq, payload in segs:
                if expected is None:
                    reassembled.extend(payload)
                    expected = seq + len(payload)
                elif seq < expected:
                    skip = expected - seq
                    if skip < len(payload):
                        reassembled.extend(payload[skip:])
                        expected = seq + len(payload)
                elif seq == expected:
                    reassembled.extend(payload)
                    expected += len(payload)
                else:
                    reassembled.extend(b"\n[...gap...]\n")
                    reassembled.extend(payload)
                    expected = seq + len(payload)
            out.append({"direction": f"{src_ip}:{src_port} → {dst_ip}:{dst_port}",
                        "bytes": bytes(reassembled)})
        return {"label": flow["label"], "packets": flow["n"], "directions": out}


# ---------- 进程 → 连接映射（Linux） ----------
def _ipv4_from_hex(h):
    return socket.inet_ntoa(bytes.fromhex(h)[::-1])


def _ipv6_from_hex(h):
    parts = [bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8)]
    return socket.inet_ntop(socket.AF_INET6, b"".join(parts))


def _parse_net_file(content, family):
    mapping = {}
    for line in content.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        if ":" not in local:
            continue
        ip_hex, port_hex = local.rsplit(":", 1)
        try:
            ip = _ipv4_from_hex(ip_hex) if family == 4 else _ipv6_from_hex(ip_hex)
            port = int(port_hex, 16)
            inode = int(parts[9])
        except Exception:
            continue
        mapping[(ip, port)] = inode
    return mapping


def get_process_map():
    """返回 {(ip, port): (pid, 进程名)}，通过 /proc/net/tcp{,6} + /proc/*/fd 关联"""
    inode_to_proc = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = os.path.join("/proc", pid, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        try:
            with open(os.path.join("/proc", pid, "comm")) as f:
                name = f.read().strip() or f"pid{pid}"
        except OSError:
            name = f"pid{pid}"
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            m = re.match(r"socket:\[(\d+)\]", target)
            if m:
                inode_to_proc[int(m.group(1))] = (int(pid), name)

    result = {}
    for family, path in ((4, "/proc/net/tcp"), (6, "/proc/net/tcp6")):
        try:
            with open(path) as f:
                content = f.read()
        except OSError:
            continue
        for (ip, port), inode in _parse_net_file(content, family).items():
            proc = inode_to_proc.get(inode)
            if proc:
                result[(ip, port)] = proc
    return result

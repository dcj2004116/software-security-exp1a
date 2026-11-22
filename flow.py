"""
flow.py —— TCP 流追踪(Follow TCP Stream + 流时序) + 进程→连接映射(Linux /proc)
"""
import os
import re
import socket


class FlowTracker:
    """按 (IP, Port) 四元组(双向归一化) 聚合 TCP 流，支持 seq 重组 + 时序段记录"""
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
            self.flows[key] = {
                "label": pkt.get("flowlabel", key), "n": 0, "bytes": 0,
                "first_ts": pkt.get("ts", 0.0), "last_ts": pkt.get("ts", 0.0),
                "a": (pkt.get("src_ip", ""), sport),
                "b": (pkt.get("dst_ip", ""), dport),
                "dirs": {},
            }
        flow = self.flows[key]
        flow["n"] += 1
        flow["bytes"] += len(pkt.get("payload") or b"")
        ts = pkt.get("ts", 0.0)
        if ts < flow["first_ts"]:
            flow["first_ts"] = ts
        if ts > flow["last_ts"]:
            flow["last_ts"] = ts
        direction = (pkt.get("src_ip", ""), sport, pkt.get("dst_ip", ""), dport)
        d = flow["dirs"].setdefault(direction, {"segments": []})
        d["segments"].append({
            "seq": pkt.get("seq"),
            "ack": pkt.get("ack"),
            "flags": pkt.get("flags", ""),
            "payload": pkt.get("payload") or b"",
            "ts": pkt.get("ts", 0),
        })

    def follow(self, key):
        """返回重组后的双向流内容 + 时序段列表"""
        flow = self.flows.get(key)
        if not flow:
            return None
        A, B = flow["a"], flow["b"]
        out_dirs = []
        segments = []
        for direction, d in flow["dirs"].items():
            sip, sport, dip, dport = direction
            # ---- 按 seq 重组（去重传/重叠） ----
            ordered = sorted([s for s in d["segments"] if s["seq"] is not None],
                             key=lambda s: s["seq"])
            reassembled = bytearray()
            expected = None
            for s in ordered:
                seq, payload = s["seq"], s["payload"]
                if not payload:
                    continue
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
            out_dirs.append({"direction": f"{sip}:{sport} → {dip}:{dport}",
                             "bytes": bytes(reassembled)})
            # ---- 时序段 ----
            forward = (sip, sport) == A and (dip, dport) == B
            for s in d["segments"]:
                segments.append({
                    "forward": forward,
                    "ts": s["ts"],
                    "seq": s["seq"],
                    "ack": s["ack"],
                    "flags": s["flags"],
                    "len": len(s["payload"]),
                })
        segments.sort(key=lambda s: s["ts"])
        return {"label": flow["label"], "packets": flow["n"],
                "directions": out_dirs, "segments": segments}

    def list(self):
        """返回所有流的摘要，供前端「会话」面板展示。"""
        out = []
        for key, f in self.flows.items():
            a_ip, a_port = f["a"]
            b_ip, b_port = f["b"]
            out.append({
                "key": key,
                "label": f["label"],
                "src": f"{a_ip}:{a_port}",
                "dst": f"{b_ip}:{b_port}",
                "packets": f["n"],
                "bytes": f["bytes"],
                "first_ts": f["first_ts"],
                "last_ts": f["last_ts"],
            })
        out.sort(key=lambda x: x["first_ts"])
        return out


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
    """返回 {(ip, port): (pid, 进程名)}；Linux 用 /proc，Windows 用 netstat+tasklist"""
    if os.path.isdir("/proc"):
        return _get_process_map_linux()
    if os.name == "nt":
        return _get_process_map_windows()
    return {}


def _get_process_map_linux():
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


def _get_process_map_windows():
    import subprocess
    result = {}
    try:
        pid_name = {}
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            parts = line.split('","')
            if len(parts) < 2:
                continue
            name = parts[0].lstrip('"').strip()
            try:
                pid = int(parts[1].strip())
            except ValueError:
                continue
            pid_name[pid] = name

        out = subprocess.run(["netstat", "-ano"],
                             capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            if "TCP" not in line and "UDP" not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[1]
            try:
                pid = int(parts[-1])
            except ValueError:
                continue
            if ":" not in local:
                continue
            if local.startswith("["):
                ip, port = local.rsplit("]:", 1)
                ip = ip[1:]
            else:
                ip, port = local.rsplit(":", 1)
            try:
                port = int(port)
            except ValueError:
                continue
            result[(ip, port)] = (pid, pid_name.get(pid, f"pid{pid}"))
    except Exception:
        pass
    return result

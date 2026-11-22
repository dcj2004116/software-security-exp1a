"""
capture.py —— 抓包封装

优先用 libpcap（ctypes 直调）；若主机没有 libpcap，自动回退到
原始套接字 AF_PACKET（纯标准库，Linux 上等价于 libpcap 底层机制）。

抓包需要 root / CAP_NET_RAW 权限（sudo 运行）。
"""
import ctypes
import os
import re
import socket
import struct
import threading
import time
from ctypes import (c_void_p, c_char_p, c_int, c_uint, c_uint32, c_long,
                    POINTER, Structure, byref, create_string_buffer,
                    string_at, c_ubyte)


# ---------- libpcap 相关结构体 ----------
class timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class pcap_pkthdr(Structure):
    _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]


class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [
    ("next", POINTER(pcap_addr)), ("addr", c_void_p), ("netmask", c_void_p),
    ("broadaddr", c_void_p), ("dstaddr", c_void_p),
]


class pcap_if(Structure):
    pass
pcap_if._fields_ = [
    ("next", POINTER(pcap_if)), ("name", c_char_p), ("description", c_char_p),
    ("addresses", POINTER(pcap_addr)), ("flags", c_uint32),
]


class bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class pcap_stat(Structure):
    _fields_ = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]


# ---------- 加载 libpcap（可能失败） ----------
def _load_libpcap():
    # Linux 用 libpcap.so，Windows 用 Npcap 的 wpcap.dll
    for name in ("libpcap.so", "libpcap.so.1", "libpcap.so.0.8", "libpcap.so.0.9",
                 "wpcap.dll", "npcap.dll"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


_lib = _load_libpcap()
HAS_LIBPCAP = _lib is not None

if HAS_LIBPCAP:
    _lib.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
    _lib.pcap_findalldevs.restype = c_int
    _lib.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
    _lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    _lib.pcap_open_live.restype = c_void_p
    _lib.pcap_close.argtypes = [c_void_p]
    _lib.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)),
                                  POINTER(POINTER(c_ubyte))]
    _lib.pcap_next_ex.restype = c_int
    _lib.pcap_compile.argtypes = [c_void_p, POINTER(bpf_program), c_char_p, c_int, c_uint32]
    _lib.pcap_compile.restype = c_int
    _lib.pcap_setfilter.argtypes = [c_void_p, POINTER(bpf_program)]
    _lib.pcap_setfilter.restype = c_int
    _lib.pcap_freecode.argtypes = [POINTER(bpf_program)]
    _lib.pcap_datalink.argtypes = [c_void_p]
    _lib.pcap_datalink.restype = c_int
    _lib.pcap_geterr.argtypes = [c_void_p]
    _lib.pcap_geterr.restype = c_char_p
    _lib.pcap_dump_open.argtypes = [c_void_p, c_char_p]
    _lib.pcap_dump_open.restype = c_void_p
    _lib.pcap_dump.argtypes = [c_void_p, POINTER(pcap_pkthdr), POINTER(c_ubyte)]
    _lib.pcap_dump_close.argtypes = [c_void_p]
    _lib.pcap_stats.argtypes = [c_void_p, POINTER(pcap_stat)]
    _lib.pcap_stats.restype = c_int


class CaptureError(Exception):
    pass


def list_devices():
    """枚举网卡"""
    if HAS_LIBPCAP:
        alldevs = POINTER(pcap_if)()
        errbuf = create_string_buffer(256)
        if _lib.pcap_findalldevs(byref(alldevs), errbuf) == -1:
            raise CaptureError(errbuf.value.decode(errors="replace"))
        devs = []
        p = alldevs
        while p:
            d = p.contents
            devs.append({"name": d.name.decode(errors="replace") if d.name else "",
                         "description": d.description.decode(errors="replace") if d.description else ""})
            p = d.next
        _lib.pcap_freealldevs(alldevs)
        return devs
    else:
        if os.name == "nt":
            raise CaptureError("未找到 Npcap/wpcap.dll，请先安装 Npcap（安装时勾选 WinPcap 兼容模式）")
        if not os.path.isdir("/sys/class/net"):
            raise CaptureError("无法枚举网卡（无 libpcap 且 /sys/class/net 不存在）")
        return [{"name": n, "description": ""} for n in sorted(os.listdir("/sys/class/net"))]


def filter_match(expr, pkt):
    """简单的用户态过滤，仅在无 libpcap（原始套接字）时使用。
    支持 tcp / udp / icmp / ip / ip6 / port N 等关键字。"""
    if not expr:
        return True
    e = expr.lower()
    transport = (pkt.get("transport") or "").lower()
    sport = pkt.get("sport")
    dport = pkt.get("dport")
    if "tcp" in e and "tcp" not in transport:
        return False
    if "udp" in e and "udp" not in transport:
        return False
    if "icmp" in e and "icmp" not in transport:
        return False
    m = re.search(r"port\s+(\d+)", e)
    if m:
        want = int(m.group(1))
        if sport != want and dport != want:
            return False
    return True


class Capture:
    def __init__(self):
        self._handle = None       # pcap_t*（libpcap）或 None
        self._raw_sock = None     # 无 libpcap 时的原始套接字
        self._running = False
        self._thread = None
        self.datalink = 1         # DLT_EN10MB
        self.filter = ""
        self._packets = []        # (sec, usec, caplen, len, raw)

    @property
    def running(self):
        return self._running

    @property
    def using_libpcap(self):
        return HAS_LIBPCAP

    def open(self, device, filter_str="", promisc=1, snaplen=65536, timeout=1000):
        self.filter = filter_str
        if HAS_LIBPCAP:
            errbuf = create_string_buffer(256)
            self._handle = _lib.pcap_open_live(device.encode(), snaplen, promisc,
                                               timeout, errbuf)
            if not self._handle:
                raise CaptureError(errbuf.value.decode(errors="replace"))
            self.datalink = _lib.pcap_datalink(self._handle)
            if filter_str:
                self.set_filter(filter_str)
        else:
            # 原始套接字：抓所有以太网帧（ETH_P_ALL）
            self._raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                           socket.htons(0x0003))
            self._raw_sock.bind((device, 0))
            self._raw_sock.settimeout(0.5)
            try:
                # SOL_PACKET=263, PACKET_IGNORE_OUTGOING=23：忽略本机发出方向，
                # 避免回环接口抓到重复包
                self._raw_sock.setsockopt(263, 23, 1)
            except OSError:
                pass
            self.datalink = 1

    def set_filter(self, expr):
        self.filter = expr
        if HAS_LIBPCAP:
            fp = bpf_program()
            if _lib.pcap_compile(self._handle, byref(fp), expr.encode(), 1, 0) != 0:
                raise CaptureError(self._err())
            if _lib.pcap_setfilter(self._handle, byref(fp)) != 0:
                _lib.pcap_freecode(byref(fp))
                raise CaptureError(self._err())
            _lib.pcap_freecode(byref(fp))

    def _err(self):
        e = _lib.pcap_geterr(self._handle)
        return e.decode(errors="replace") if e else "unknown pcap error"

    def start(self, callback):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(callback,), daemon=True)
        self._thread.start()

    def _loop(self, callback):
        if HAS_LIBPCAP:
            self._loop_libpcap(callback)
        else:
            self._loop_raw(callback)

    def _loop_libpcap(self, callback):
        hdr = POINTER(pcap_pkthdr)()
        data = POINTER(c_ubyte)()
        while self._running and self._handle:
            r = _lib.pcap_next_ex(self._handle, byref(hdr), byref(data))
            if r == 1:
                caplen = hdr.contents.caplen
                length = hdr.contents.len
                raw = string_at(data, caplen)
                ts = hdr.contents.ts.tv_sec + hdr.contents.ts.tv_usec / 1e6
                self._append_packet(hdr.contents.ts.tv_sec, hdr.contents.ts.tv_usec,
                                    caplen, length, raw)
                callback(raw, ts, caplen, length)
            elif r in (-1, -2):
                break

    def _loop_raw(self, callback):
        while self._running and self._raw_sock:
            try:
                raw = self._raw_sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            ts = time.time()
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            caplen = len(raw)
            self._append_packet(sec, usec, caplen, caplen, raw)
            callback(raw, ts, caplen, caplen)

    def _append_packet(self, sec, usec, caplen, length, raw):
        self._packets.append((sec, usec, caplen, length, raw))
        if len(self._packets) > 20000:
            self._packets.pop(0)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def close(self):
        self.stop()
        if HAS_LIBPCAP and self._handle:
            _lib.pcap_close(self._handle)
            self._handle = None
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except OSError:
                pass
            self._raw_sock = None

    def stats(self):
        """返回抓包统计 (received/dropped/if_dropped)；无 libpcap 或未打开时返回 None。"""
        if not HAS_LIBPCAP or not self._handle:
            return None
        st = pcap_stat()
        if _lib.pcap_stats(self._handle, byref(st)) != 0:
            return None
        return {"received": st.ps_recv, "dropped": st.ps_drop,
                "if_dropped": st.ps_ifdrop}

    def save_pcap(self, path):
        """把本次会话已抓到的包导出成标准 pcap 文件"""
        snap = list(self._packets)
        if HAS_LIBPCAP:
            if not self._handle:
                raise CaptureError("尚未打开设备，无法导出 pcap")
            dumper = _lib.pcap_dump_open(self._handle, path.encode())
            if not dumper:
                raise CaptureError(self._err())
            try:
                for sec, usec, caplen, length, raw in snap:
                    hdr = pcap_pkthdr()
                    hdr.ts.tv_sec = sec
                    hdr.ts.tv_usec = usec
                    hdr.caplen = caplen
                    hdr.len = length
                    buf = (c_ubyte * caplen).from_buffer_copy(raw)
                    _lib.pcap_dump(dumper, byref(hdr), buf)
            finally:
                _lib.pcap_dump_close(dumper)
        else:
            self._save_pcap_manual(path, snap)

    @staticmethod
    def _save_pcap_manual(path, packets):
        with open(path, "wb") as f:
            # 全局头：小端、微秒时间戳、链路类型 Ethernet(1)
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for sec, usec, caplen, length, raw in packets:
                f.write(struct.pack("<IIII", sec, usec, caplen, length))
                f.write(raw)

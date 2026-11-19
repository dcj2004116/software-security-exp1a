"""
capture.py —— libpcap 的 ctypes 封装（直调 libpcap.so，无额外依赖）

功能：枚举网卡 / 打开设备(混杂模式) / BPF 过滤 / 后台线程抓包 / 导出 pcap
抓包需要 root 或 CAP_NET_RAW，建议用 run.sh 里的 setcap 做最小权限授权。
"""
import ctypes
import threading
from ctypes import (c_void_p, c_char_p, c_int, c_uint, c_uint32, c_long,
                    POINTER, Structure, byref, create_string_buffer,
                    string_at, c_ubyte)


# ---------- 结构体 ----------
class timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class pcap_pkthdr(Structure):
    _fields_ = [("ts", timeval), ("caplen", c_uint32), ("len", c_uint32)]


class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [
    ("next", POINTER(pcap_addr)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
]


class pcap_if(Structure):
    pass
pcap_if._fields_ = [
    ("next", POINTER(pcap_if)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(pcap_addr)),
    ("flags", c_uint32),
]


class bpf_program(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


# ---------- 加载 libpcap ----------
def _load_libpcap():
    for name in ("libpcap.so", "libpcap.so.1", "libpcap.so.0.8", "libpcap.so.0.9"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise OSError("找不到 libpcap，请先安装：sudo apt install libpcap-dev")


_lib = _load_libpcap()

# ---------- 函数原型 ----------
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


class CaptureError(Exception):
    pass


def list_devices():
    """枚举所有网卡，返回 [{"name":.., "description":..}]"""
    alldevs = POINTER(pcap_if)()
    errbuf = create_string_buffer(256)
    if _lib.pcap_findalldevs(byref(alldevs), errbuf) == -1:
        raise CaptureError(errbuf.value.decode(errors="replace"))
    devs = []
    p = alldevs
    while p:
        d = p.contents
        devs.append({
            "name": d.name.decode() if d.name else "",
            "description": d.description.decode() if d.description else "",
        })
        p = d.next
    _lib.pcap_freealldevs(alldevs)
    return devs


class Capture:
    def __init__(self):
        self._handle = None
        self._running = False
        self._thread = None
        self.datalink = 1          # 默认 DLT_EN10MB（以太网）
        self._packets = []         # (sec, usec, caplen, len, raw) 用于导出 pcap

    @property
    def running(self):
        return self._running

    def open(self, device, filter_str="", promisc=1, snaplen=65536, timeout=1000):
        errbuf = create_string_buffer(256)
        self._handle = _lib.pcap_open_live(device.encode(), snaplen, promisc,
                                           timeout, errbuf)
        if not self._handle:
            raise CaptureError(errbuf.value.decode(errors="replace"))
        self.datalink = _lib.pcap_datalink(self._handle)
        if filter_str:
            self.set_filter(filter_str)

    def set_filter(self, expr):
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
        """启动后台抓包线程，每抓到一个包调用 callback(raw, ts, caplen, length)"""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(callback,), daemon=True)
        self._thread.start()

    def _loop(self, callback):
        hdr = POINTER(pcap_pkthdr)()
        data = POINTER(c_ubyte)()
        while self._running and self._handle:
            r = _lib.pcap_next_ex(self._handle, byref(hdr), byref(data))
            if r == 1:
                caplen = hdr.contents.caplen
                length = hdr.contents.len
                raw = string_at(data, caplen)
                ts = hdr.contents.ts.tv_sec + hdr.contents.ts.tv_usec / 1e6
                self._packets.append((hdr.contents.ts.tv_sec, hdr.contents.ts.tv_usec,
                                      caplen, length, raw))
                if len(self._packets) > 20000:
                    self._packets.pop(0)
                callback(raw, ts, caplen, length)
            elif r in (-1, -2):
                break

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def close(self):
        self.stop()
        if self._handle:
            _lib.pcap_close(self._handle)
            self._handle = None

    def save_pcap(self, path):
        """把本次会话已抓到的包导出成 pcap 文件"""
        if not self._handle:
            raise CaptureError("尚未打开设备，无法导出 pcap")
        snap = list(self._packets)
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

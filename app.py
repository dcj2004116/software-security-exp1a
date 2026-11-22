"""
app.py —— 纯标准库实现的嗅探器后端（零第三方依赖，适配无外网实验室主机）

HTTP 接口：
  GET  /            网页界面
  GET  /devices     网卡列表
  POST /start       开始抓包 {device, filter}
  POST /stop        停止
  POST /save        导出 pcap {path}
  GET  /follow/KEY  查看 TCP 流（KEY 需 URL 编码）
  GET  /processes   进程→连接映射
  GET  /stream      SSE 实时推送抓包结果

运行：sudo python3 app.py   （抓包需要 root / CAP_NET_RAW）
"""
import json
import os
import time
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import capture
import parser as P
import flow as F

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

capture_obj = capture.Capture()
tracker = F.FlowTracker()
counter = {"n": 0}
# 服务端全局统计（供 /stats 与前端图表使用，随 /start 重置）
_stats = {"total": 0, "bytes": 0, "protos": {}, "src": {}, "dst": {}}

# SSE 客户端队列列表
_clients = []
_clients_lock = threading.Lock()
_process_cache = {"data": {}, "t": 0.0}
_raw_cache = {}          # 包编号 -> 原始字节，供 /raw/{no} 按需取原始数据
RAW_CACHE_MAX = 10000


def to_json(pkt):
    """去掉 payload，保留原始字节前 256 字节的 hex 供前端直接显示"""
    d = {k: v for k, v in pkt.items() if k not in ("payload", "raw")}
    raw = pkt.get("raw", b"")
    d["raw_hex"] = raw[:256].hex()
    d["raw_truncated"] = len(raw) > 256
    return d


def on_packet(raw, ts, caplen, length):
    counter["n"] += 1
    no = counter["n"]
    pkt = P.parse(raw, ts, capture_obj.datalink, no, length)
    # 用户态过滤仅用于「无 libpcap、原始套接字回退」的场景；
    # 使用 libpcap 时内核已按 BPF 过滤，叠加用户态过滤会误伤复合表达式。
    if capture_obj.filter and not capture_obj.using_libpcap:
        if not capture.filter_match(capture_obj.filter, pkt):
            return
    _raw_cache[no] = raw
    if len(_raw_cache) > RAW_CACHE_MAX:
        _raw_cache.pop(next(iter(_raw_cache)))
    tracker.add(pkt)
    # 更新服务端统计
    _stats["total"] += 1
    _stats["bytes"] += length
    proto = pkt.get("proto", "Unknown")
    _stats["protos"][proto] = _stats["protos"].get(proto, 0) + 1
    if pkt.get("src"):
        _stats["src"][pkt["src"]] = _stats["src"].get(pkt["src"], 0) + 1
    if pkt.get("dst"):
        _stats["dst"][pkt["dst"]] = _stats["dst"].get(pkt["dst"], 0) + 1
    j = json.dumps(to_json(pkt))
    with _clients_lock:
        snapshot = list(_clients)
    for q in snapshot:
        try:
            q.put_nowait(j)
        except queue.Full:
            pass


def _render_text(b):
    return "".join(chr(c) if (32 <= c < 127) else ("\n" if c in (10, 13) else ".")
                   for c in b)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # 静默访问日志

    # ---- 通用响应 ----
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        return self.rfile.read(n) if n else b""

    # ---- GET ----
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(BASE_DIR, "static", "index.html"), "rb") as f:
                self._html(f.read())
        elif path == "/devices":
            try:
                self._json({"devices": capture.list_devices()})
            except capture.CaptureError as e:
                self._json({"error": str(e)}, 500)
        elif path == "/status":
            st = capture_obj.stats()
            self._json({"running": capture_obj.running, "count": counter["n"],
                        "received": st.get("received", 0) if st else None,
                        "dropped": st.get("dropped", 0) if st else None})
        elif path == "/stats":
            self._json(dict(_stats))
        elif path == "/flows":
            self._json({"flows": tracker.list()})
        elif path.startswith("/raw/"):
            try:
                no = int(path[len("/raw/"):])
            except ValueError:
                self._json({"error": "bad packet number"}, 400)
                return
            raw = _raw_cache.get(no)
            if raw is None:
                self._json({"error": "packet not in cache"}, 404)
            else:
                self._json({"no": no, "len": len(raw),
                            "raw_hex": raw[:1024].hex(),
                            "truncated": len(raw) > 1024})
        elif path.startswith("/follow/"):
            key = unquote(path[len("/follow/"):])
            res = tracker.follow(key)
            if res is None:
                self._json({"error": "flow not found"}, 404)
            else:
                self._json({"label": res["label"], "packets": res["packets"],
                            "directions": [{"direction": d["direction"],
                                            "text": _render_text(d["bytes"])}
                                           for d in res["directions"]],
                            "segments": res["segments"]})
        elif path.startswith("/export_flow/"):
            key = unquote(path[len("/export_flow/"):])
            res = tracker.follow(key)
            if res is None:
                self._json({"error": "flow not found"}, 404)
            else:
                lines = [f"# Follow TCP Stream: {res['label']}",
                         f"# packets: {res['packets']}", ""]
                for d in res["directions"]:
                    lines.append(f"===== {d['direction']} =====")
                    lines.append(_render_text(d["bytes"]))
                    lines.append("")
                body = "\n".join(lines).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition",
                                 'attachment; filename="flow.txt"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        elif path == "/processes":
            now = time.time()
            if now - _process_cache["t"] > 3 or not _process_cache["data"]:
                _process_cache["data"] = F.get_process_map()
                _process_cache["t"] = now
            conns = [{"ip": ip, "port": port, "pid": pid, "name": name}
                     for (ip, port), (pid, name) in _process_cache["data"].items()]
            self._json({"connections": conns})
        elif path == "/stream":
            self._stream()
        else:
            self._json({"error": "not found"}, 404)

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = queue.Queue(maxsize=10000)
        with _clients_lock:
            _clients.append(q)
        try:
            while True:
                try:
                    item = q.get(timeout=15)
                    self.wfile.write(("data: " + item + "\n\n").encode("utf-8"))
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _clients_lock:
                if q in _clients:
                    _clients.remove(q)

    # ---- POST ----
    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            data = json.loads(self._read_body() or b"{}")
        except json.JSONDecodeError:
            data = {}
        if path == "/start":
            try:
                capture_obj.close()
                tracker.reset()
                _raw_cache.clear()
                _stats.update({"total": 0, "bytes": 0, "protos": {},
                               "src": {}, "dst": {}})
                device = data.get("device", "")
                capture_obj.open(device, data.get("filter", ""))
                print(f"[capture] 设备={device} 链路类型DLT={capture_obj.datalink} 过滤={data.get('filter', '') or '无'}")
                capture_obj.start(on_packet)
                self._json({"ok": True, "device": device,
                            "filter": data.get("filter", "")})
            except capture.CaptureError as e:
                self._json({"error": str(e)}, 500)
        elif path == "/stop":
            capture_obj.stop()
            self._json({"ok": True, "count": counter["n"]})
        elif path == "/save":
            try:
                capture_obj.save_pcap(data.get("path", "/tmp/sniffer_capture.pcap"))
                self._json({"ok": True, "path": data.get("path", "")})
            except capture.CaptureError as e:
                self._json({"error": str(e)}, 500)
        else:
            self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    port = 8000
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"嗅探器已启动，浏览器打开 http://localhost:{port}")
    if os.name == "nt":
        print("提示：抓包需要管理员权限（请以管理员身份运行）。")
    else:
        print("提示：抓包需要 root / CAP_NET_RAW 权限，请用 sudo 运行。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

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

# SSE 客户端队列列表
_clients = []
_clients_lock = threading.Lock()
_process_cache = {"data": {}, "t": 0.0}


def to_json(pkt):
    """去掉不可 JSON 序列化的 payload/raw，只保留前端需要的字段"""
    d = {k: v for k, v in pkt.items() if k not in ("payload", "raw")}
    raw = pkt.get("raw", b"")
    d["raw_hex"] = raw[:1024].hex()
    d["raw_truncated"] = len(raw) > 1024
    return d


def on_packet(raw, ts, caplen, length):
    counter["n"] += 1
    pkt = P.parse(raw, ts, capture_obj.datalink, counter["n"], length)
    if not capture_obj.using_libpcap and capture_obj.filter:
        if not capture.filter_match(capture_obj.filter, pkt):
            return
    tracker.add(pkt)
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
        self.end_headers()
        self.wfile.write(body)

    def _html(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
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
            self._json({"running": capture_obj.running, "count": counter["n"]})
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
                counter["n"] = 0
                tracker.reset()
                capture_obj.open(data.get("device", ""), data.get("filter", ""))
                capture_obj.start(on_packet)
                self._json({"ok": True, "device": data.get("device", ""),
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
    print("提示：抓包需要 root / CAP_NET_RAW 权限，请用 sudo 运行。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

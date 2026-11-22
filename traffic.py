"""
traffic.py —— 生成测试流量（实验室无外网也能演示）

启动本地 HTTP 服务并制造 HTTP/TCP 流量，可在 lo 网卡上抓到。
用法：先开一个终端运行 `python3 traffic.py`，再开另一个终端运行嗅探器，
      嗅探器里选择 lo 网卡开始抓包。
"""
import http.server
import threading
import time
import socket


def _serve():
    httpd = http.server.HTTPServer(("127.0.0.1", 8080),
                                   http.server.SimpleHTTPRequestHandler)
    httpd.serve_forever()


def _http_request():
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        s.recv(4096)
        s.close()
    except OSError:
        pass


def main():
    threading.Thread(target=_serve, daemon=True).start()
    time.sleep(0.5)
    print("开始持续生成 HTTP 测试流量（127.0.0.1:8080，每秒 1 次，Ctrl+C 停止）...")
    try:
        while True:
            _http_request()
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

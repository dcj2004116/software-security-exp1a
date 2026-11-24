"""
traffic.py —— 生成多协议测试流量（实验室无外网也能演示）

在回环网卡(127.0.0.1)上同时生成多种协议流量，便于在 lo / NPF_Loopback
上抓包并演示 NPA 协议解析：
    TCP  + HTTP   （127.0.0.1:8080）
    UDP  + DNS    （127.0.0.1:53）
    TCP  + TLS    （127.0.0.1:443，自签名证书）
    ICMP          （ping 127.0.0.1）
    UDP           （127.0.0.1:9999 回显）

用法：先开一个终端运行 `python traffic.py`，再开另一个终端运行嗅探器，
      嗅探器里选择回环网卡开始抓包（抓包过滤可留空，看全部协议）。
"""
import http.server
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

CERT_FILE = os.path.join(tempfile.gettempdir(), "sniffer_tls_cert.pem")
KEY_FILE = os.path.join(tempfile.gettempdir(), "sniffer_tls_key.pem")


def _ensure_cert() -> bool:
    """若证书不存在，用 openssl 生成自签名证书。"""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", KEY_FILE, "-out", CERT_FILE, "-days", "365",
             "-nodes", "-subj", "/CN=localhost"],
            check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        print("警告：无法生成 TLS 证书，跳过 HTTPS 流量")
        return False


class _HTTPServer6(http.server.HTTPServer):
    address_family = socket.AF_INET6


def _serve_http() -> None:
    httpd = http.server.HTTPServer(("127.0.0.1", 8080),
                                   http.server.SimpleHTTPRequestHandler)
    httpd.serve_forever()


def _serve_http6() -> None:
    """IPv6 回环 HTTP 服务（::1:8081），用于演示 IPv6 解析。"""
    try:
        httpd = _HTTPServer6(("::1", 8081), http.server.SimpleHTTPRequestHandler)
        httpd.serve_forever()
    except OSError:
        print("[HTTP6] 无法监听 ::1:8081", flush=True)


def _serve_https() -> None:
    if not _ensure_cert():
        return
    httpd = http.server.HTTPServer(("127.0.0.1", 443),
                                   http.server.SimpleHTTPRequestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def _serve_dns() -> None:
    """极简 DNS 应答：对任意 A 查询返回 1.2.3.4。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 53))
    except OSError as e:
        print(f"[DNS] 无法监听 53 端口: {e}", flush=True)
        return
    print("[DNS] 已监听 127.0.0.1:53", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            break
        if len(data) < 12:
            continue
        txid, qdcount, query = data[:2], data[4:6], data[12:]
        resp = (txid + b"\x81\x80" + qdcount + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
                + query + b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01"
                + b"\x00\x00\x00\x3c" + b"\x00\x04" + b"\x01\x02\x03\x04")
        try:
            sock.sendto(resp, addr)
        except OSError:
            pass


def _udp_echo() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 9999))
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            sock.sendto(data, addr)
        except OSError:
            break


def _http_request() -> None:
    try:
        s = socket.create_connection(("127.0.0.1", 8080), timeout=2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        s.recv(4096)
        s.close()
    except OSError:
        pass


def _http6_request() -> None:
    try:
        s = socket.create_connection(("::1", 8081), timeout=2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        s.recv(4096)
        s.close()
    except OSError:
        pass


def _dns_query() -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        q += b"\x03www\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        s.sendto(q, ("127.0.0.1", 53))
        s.recvfrom(512)
        s.close()
    except OSError:
        pass


def _https_request() -> None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(socket.socket(), server_hostname="secure.example.com")
        s.settimeout(2)
        s.connect(("127.0.0.1", 443))
        s.sendall(b"GET / HTTP/1.1\r\nHost: secure.example.com\r\n\r\n")
        s.recv(1024)
        s.close()
    except OSError:
        pass


def _udp_chatter() -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"hello udp", ("127.0.0.1", 9999))
        s.recvfrom(1024)
        s.close()
    except OSError:
        pass


def _ping() -> None:
    flag = "-n" if os.name == "nt" else "-c"
    subprocess.run(["ping", flag, "1", "127.0.0.1"], capture_output=True)


def main() -> None:
    threading.Thread(target=_serve_http, daemon=True).start()
    threading.Thread(target=_serve_http6, daemon=True).start()
    threading.Thread(target=_serve_https, daemon=True).start()
    threading.Thread(target=_serve_dns, daemon=True).start()
    threading.Thread(target=_udp_echo, daemon=True).start()
    time.sleep(1)
    print("开始持续生成多协议测试流量（DNS/UDP/ICMP 高频，HTTP/TLS/IPv6 低频，Ctrl+C 停止）...")
    try:
        counter = 0
        while True:
            counter += 1
            # 无连接协议，每轮多次（DNS/UDP/ICMP 只产生 2 个包，靠数量拉高比例）
            _dns_query()
            _dns_query()
            _udp_chatter()
            _udp_chatter()
            _ping()
            # 有连接协议，低频（每次连接有握手+挥手，TCP 包多，所以少做）
            if counter % 4 == 0:
                _http_request()
            if counter % 6 == 0:
                _https_request()
            if counter % 8 == 0:
                _http6_request()
            time.sleep(0.4)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

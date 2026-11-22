"""
parser.py —— 手动逐层协议解析（不依赖第三方协议库）

支持：Ethernet(含802.1Q) / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / HTTP / DNS / TLS
思路：链路层 → 网络层 → 传输层 → 应用层 逐层剥离，每层输出字段字典供前端树形展示，
      并提炼 src/dst/proto/summary 等摘要信息。
"""
import struct
import socket

DLT_EN10MB = 1
DLT_NULL = 0
DLT_LOOP = 108
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


# ---------- 格式化 ----------
def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _ipv4(b):
    return socket.inet_ntoa(b)


def _ipv6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


# ---------- 链路层 ----------
def parse_ethernet(data):
    if len(data) < 14:
        return None, b"", None
    dst, src, etype = struct.unpack("!6s6sH", data[:14])
    rest = data[14:]
    fields = {"Destination": _mac(dst), "Source": _mac(src)}
    if etype == 0x8100 and len(rest) >= 4:      # 802.1Q VLAN
        tci, etype = struct.unpack("!HH", rest[:4])
        fields["802.1Q VLAN ID"] = str(tci & 0x0FFF)
        rest = rest[4:]
    fields["Type"] = f"0x{etype:04x}"
    return {"name": "Ethernet II", "fields": fields}, rest, etype


def parse_arp(data):
    if len(data) < 28:
        return None, b""
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack(
        "!HHBBH6s4s6s4s", data[:28])
    opname = {1: "Request", 2: "Reply"}.get(op, str(op))
    return {"name": "ARP", "fields": {
        "Hardware Type": htype, "Protocol Type": f"0x{ptype:04x}",
        "Operation": f"{op} ({opname})",
        "Sender MAC": _mac(sha), "Sender IP": _ipv4(spa),
        "Target MAC": _mac(tha), "Target IP": _ipv4(tpa)}}, data[28:]


# ---------- 网络层 ----------
def parse_ipv4(data):
    if len(data) < 20:
        return None, b"", None
    vihl, tos, tot, ident, frag, ttl, proto, csum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", data[:20])
    ver = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    flags = (frag >> 13) & 0x7
    frag_off = frag & 0x1FFF
    rest = data[ihl:]
    layer = {"name": "IPv4", "fields": {
        "Version": ver, "Header Length": f"{ihl} bytes",
        "Total Length": tot, "Identification": f"0x{ident:04x}",
        "Flags": f"0x{flags:x}", "Fragment Offset": frag_off,
        "TTL": ttl, "Protocol": proto, "Checksum": f"0x{csum:04x}",
        "Source": _ipv4(src), "Destination": _ipv4(dst)}}
    return layer, rest, proto


def parse_ipv6(data):
    if len(data) < 40:
        return None, b"", None
    vtc, plen, nh, hop, src, dst = struct.unpack("!IHBB16s16s", data[:40])
    ver = vtc >> 28
    rest = data[40:]
    layer = {"name": "IPv6", "fields": {
        "Version": ver, "Payload Length": plen, "Next Header": nh,
        "Hop Limit": hop, "Source": _ipv6(src), "Destination": _ipv6(dst)}}
    # 尽力跳过扩展头（逐跳0/路由43/分片44/目的选项60/AH51）
    seen = 0
    while nh in (0, 43, 44, 60, 51) and seen < 4:
        seen += 1
        if len(rest) < 2:
            break
        if nh == 44:                       # Fragment：8 字节定长
            if len(rest) < 8:
                break
            nh = rest[0]
            rest = rest[8:]
        elif nh == 51:                     # AH：长度 = (payload_len + 2) * 4 字节
            ext_len = (rest[1] + 2) * 4
            nh = rest[0]
            if len(rest) < ext_len:
                break
            rest = rest[ext_len:]
        else:                              # 逐跳0/路由43/目的选项60：单位 8 字节组
            ext_len = (rest[1] + 1) * 8
            nh = rest[0]
            if len(rest) < ext_len:
                break
            rest = rest[ext_len:]
    return layer, rest, nh


# ---------- 传输层 ----------
def parse_tcp(data):
    if len(data) < 20:
        return None, b"", None
    sport, dport, seq, ack, off_res, flags, win, csum, urg = struct.unpack(
        "!HHLLBBHHH", data[:20])
    off = (off_res >> 4) * 4
    ns = off_res & 0x01
    flags9 = (ns << 8) | flags
    names = []
    for bit, nm in [(0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"), (0x20, "URG"),
                    (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"),
                    (0x01, "FIN")]:
        if flags9 & bit:
            names.append(nm)
    layer = {"name": "TCP", "fields": {
        "Source Port": sport, "Destination Port": dport,
        "Sequence Number": seq, "Acknowledgment": ack,
        "Header Length": f"{off} bytes",
        "Flags": " ".join(names) or "None",
        "Window": win, "Checksum": f"0x{csum:04x}", "Urgent Pointer": urg}}
    return layer, data[off:], (sport, dport)


def parse_udp(data):
    if len(data) < 8:
        return None, b"", None
    sport, dport, ulen, csum = struct.unpack("!HHHH", data[:8])
    layer = {"name": "UDP", "fields": {
        "Source Port": sport, "Destination Port": dport,
        "Length": ulen, "Checksum": f"0x{csum:04x}"}}
    return layer, data[8:], (sport, dport)


def parse_icmp(data):
    if len(data) < 4:
        return None, b""
    itype, code, csum = struct.unpack("!BBH", data[:4])
    names = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable",
             11: "Time Exceeded", 5: "Redirect"}
    fields = {"Type": f"{itype} ({names.get(itype, '')})", "Code": code,
              "Checksum": f"0x{csum:04x}"}
    if itype in (0, 8) and len(data) >= 8:
        ident, seq = struct.unpack("!HH", data[4:8])
        fields["Identifier"] = ident
        fields["Sequence"] = seq
    return {"name": "ICMP", "fields": fields}, data[8:]


# ---------- 应用层 ----------
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")


def _first_line(data):
    e = data.find(b"\r\n")
    if e < 0:
        e = data.find(b"\n")
    if e <= 0:
        return "", data
    return data[:e].decode(errors="replace"), data[e + 2:]


def parse_http(data):
    if data.startswith(b"HTTP/"):
        line, rest = _first_line(data)
        hdr_end = rest.find(b"\r\n\r\n")
        headers = rest[:hdr_end].decode(errors="replace") if hdr_end >= 0 else ""
        fields = {"Response": line, "Headers": headers}
        parts = line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            fields["Status Code"] = int(parts[1])
        return {"name": "HTTP", "fields": fields}, data
    for m in HTTP_METHODS:
        if data.startswith(m):
            line, rest = _first_line(data)
            hdr_end = rest.find(b"\r\n\r\n")
            headers = rest[:hdr_end].decode(errors="replace") if hdr_end >= 0 else ""
            method = m.decode().strip()
            return {"name": "HTTP", "fields": {"Request": line, "Method": method,
                                               "Headers": headers}}, data
    return None, data


def parse_dns(data):
    if len(data) < 12:
        return None, data
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    fields = {"Transaction ID": f"0x{txid:04x}", "Questions": qd,
              "Answers": an, "Authority": ns, "Additional": ar}
    try:
        off = 12
        labels = []
        while off < len(data):
            l = data[off]
            off += 1
            if l == 0:
                break
            labels.append(data[off:off + l].decode(errors="replace"))
            off += l
        if off + 4 <= len(data):
            qtype, qclass = struct.unpack("!HH", data[off:off + 4])
            fields["Query"] = ".".join(labels)
            fields["Query Type"] = qtype
            fields["Query Class"] = qclass
    except Exception:
        pass
    return {"name": "DNS", "fields": fields}, data[12:]


def _tls_sni(data):
    """从 TLS ClientHello 报文里提取 SNI 域名（Server Name Indication）。

    data 以 TLS Record 头（ContentType=22 Handshake）开始。逐字段解析
    ClientHello：跳过版本/随机数/会话ID/密码套件/压缩方法，进入扩展区，
    找到 type=0(server_name) 的扩展，读出 host_name 类型的域名。
    只处理单条 Record 内的情况（覆盖绝大多数真实流量）。
    """
    try:
        if len(data) < 9 or data[0] != 22:
            return None
        pos = 5                          # 跳过 Record 头：type(1)+version(2)+length(2)
        if data[pos] != 1:               # 必须为 ClientHello
            return None
        pos += 4                         # 跳过 Handshake 头：type(1)+length(3)
        if pos + 34 > len(data):
            return None
        pos += 2                         # client_version
        pos += 32                        # random
        slen = data[pos]                 # session_id 长度
        pos += 1 + slen
        if pos + 2 > len(data):
            return None
        clen = int.from_bytes(data[pos:pos + 2], "big")   # cipher_suites 长度
        pos += 2 + clen
        if pos + 1 > len(data):
            return None
        mlen = data[pos]                 # compression_methods 长度
        pos += 1 + mlen
        if pos + 2 > len(data):
            return None
        elen = int.from_bytes(data[pos:pos + 2], "big")   # extensions 总长
        pos += 2
        end = min(pos + elen, len(data))
        while pos + 4 <= end:
            etype = int.from_bytes(data[pos:pos + 2], "big")
            extlen = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if etype == 0 and pos + 5 <= end:             # server_name 扩展
                npos = pos + 2                            # 跳过 list 总长(2)
                if npos < end and data[npos] == 0:        # 0 = host_name
                    nlen = int.from_bytes(data[npos + 1:npos + 3], "big")
                    name = data[npos + 3:npos + 3 + nlen]
                    return name.decode("utf-8", errors="replace") or None
            pos += extlen
        return None
    except Exception:
        return None


def parse_tls(data):
    if len(data) < 3:
        return None, data
    ctype, ver = struct.unpack("!BH", data[:3])
    ctype_names = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake",
                   23: "Application Data"}
    if ctype not in ctype_names:
        return None, data
    fields = {"Content Type": f"{ctype} ({ctype_names[ctype]})",
              "Version": f"0x{ver:04x}"}
    if ctype == 22 and len(data) >= 6:
        htype = data[5]
        hn = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
              12: "ServerKeyExchange", 13: "CertificateRequest",
              14: "ServerHelloDone", 15: "CertificateVerify",
              16: "ClientKeyExchange", 20: "Finished"}
        fields["Handshake Type"] = f"{htype} ({hn.get(htype, '')})"
        if htype == 1:                   # ClientHello：尝试提取 SNI
            sni = _tls_sni(data)
            if sni:
                fields["Server Name (SNI)"] = sni
    return {"name": "TLS", "fields": fields}, data


# ---------- 应用层识别 ----------
def _detect_app(sport, dport, payload):
    if sport in (80, 8080) or dport in (80, 8080):
        layer, _ = parse_http(payload)
        if layer:
            return "HTTP", layer
    if sport == 443 or dport == 443:
        layer, _ = parse_tls(payload)
        if layer:
            return "TLS", layer
    if sport == 53 or dport == 53:
        layer, _ = parse_dns(payload)
        if layer:
            return "DNS", layer
    layer, _ = parse_http(payload)
    if layer:
        return "HTTP", layer
    return None, None


def _flow_key(src_ip, dst_ip, sport, dport):
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            a = socket.inet_pton(fam, src_ip)
            b = socket.inet_pton(fam, dst_ip)
            break
        except OSError:
            continue
    else:
        a, b = src_ip.encode(), dst_ip.encode()
    sa = a + bytes([sport >> 8, sport & 0xFF])
    sb = b + bytes([dport >> 8, dport & 0xFF])
    return (f"{sa.hex()}|{sb.hex()}" if sa <= sb else f"{sb.hex()}|{sa.hex()}")


# ---------- 内部：传输层之后的处理 ----------
def _handle_transport(layer, rest, ports, layers, pkt, is_tcp):
    layers.append(layer)
    sport, dport = ports
    pkt["sport"], pkt["dport"] = sport, dport
    pkt["transport"] = "TCP" if is_tcp else "UDP"
    pkt["src"] = f"{pkt['src_ip']}:{sport}"
    pkt["dst"] = f"{pkt['dst_ip']}:{dport}"
    pkt["payload"] = rest
    pkt["flowkey"] = _flow_key(pkt["src_ip"], pkt["dst_ip"], sport, dport)
    pkt["flowlabel"] = f"{pkt['src_ip']}:{sport} ↔ {pkt['dst_ip']}:{dport}"

    if is_tcp:
        pkt["proto"] = "TCP"
        pkt["seq"] = layer["fields"]["Sequence Number"]
        pkt["ack"] = layer["fields"]["Acknowledgment"]
        pkt["flags"] = layer["fields"].get("Flags", "")
        app, app_layer = _detect_app(sport, dport, rest)
        if app_layer:
            layers.append(app_layer)
            pkt["proto"] = app
        fl = layer["fields"].get("Flags", "")
        if app == "HTTP":
            pkt["summary"] = (app_layer["fields"].get("Request")
                              or app_layer["fields"].get("Response") or "HTTP")
        elif app == "TLS":
            sni = app_layer["fields"].get("Server Name (SNI)")
            if sni:
                pkt["summary"] = f"TLS ClientHello → {sni}"
            else:
                pkt["summary"] = (f"{sport} → {dport} [{fl}] "
                                  f"Seq={pkt['seq']} Ack={pkt['ack']} Len={len(rest)}")
        else:
            pkt["summary"] = (f"{sport} → {dport} [{fl}] "
                              f"Seq={pkt['seq']} Ack={pkt['ack']} Len={len(rest)}")
    else:
        pkt["proto"] = "UDP"
        app, app_layer = _detect_app(sport, dport, rest)
        if app_layer:
            layers.append(app_layer)
            pkt["proto"] = app
        if app == "DNS":
            q = app_layer["fields"].get("Query")
            pkt["summary"] = f"DNS query {q}" if q else "DNS"
        else:
            pkt["summary"] = f"{sport} → {dport} Len={len(rest)}"


def _parse_ip(data, layers, pkt, v6):
    if v6:
        layer, rest, nh = parse_ipv6(data)
        if layer is None:
            return
        layers.append(layer)
        pkt["src_ip"] = layer["fields"]["Source"]
        pkt["dst_ip"] = layer["fields"]["Destination"]
        pkt["src"], pkt["dst"] = pkt["src_ip"], pkt["dst_ip"]
        if nh == 6:
            l2, r2, ports = parse_tcp(rest)
            if l2:
                _handle_transport(l2, r2, ports, layers, pkt, is_tcp=True)
        elif nh == 17:
            l2, r2, ports = parse_udp(rest)
            if l2:
                _handle_transport(l2, r2, ports, layers, pkt, is_tcp=False)
        elif nh == 58:
            l2, _ = parse_icmp(rest)
            if l2:
                layers.append(l2)
                pkt["proto"] = "ICMPv6"
                pkt["transport"] = "ICMPv6"
                pkt["summary"] = f"ICMPv6 {l2['fields'].get('Type')}"
        else:
            pkt["proto"] = "IPv6"
            pkt["summary"] = f"{pkt['src']} → {pkt['dst']} (next header {nh})"
    else:
        layer, rest, proto = parse_ipv4(data)
        if layer is None:
            return
        layers.append(layer)
        pkt["src_ip"] = layer["fields"]["Source"]
        pkt["dst_ip"] = layer["fields"]["Destination"]
        pkt["src"], pkt["dst"] = pkt["src_ip"], pkt["dst_ip"]
        if proto == 6:
            l2, r2, ports = parse_tcp(rest)
            if l2:
                _handle_transport(l2, r2, ports, layers, pkt, is_tcp=True)
        elif proto == 17:
            l2, r2, ports = parse_udp(rest)
            if l2:
                _handle_transport(l2, r2, ports, layers, pkt, is_tcp=False)
        elif proto == 1:
            l2, _ = parse_icmp(rest)
            if l2:
                layers.append(l2)
                pkt["proto"] = "ICMP"
                pkt["transport"] = "ICMP"
                pkt["summary"] = f"ICMP {l2['fields'].get('Type')}"
        else:
            pkt["proto"] = f"IP-{proto}"
            pkt["summary"] = f"{pkt['src']} → {pkt['dst']} (proto {proto})"


# ---------- 主入口 ----------
def parse(raw, ts, linktype=DLT_EN10MB, no=0, length=None):
    length = length if length is not None else len(raw)
    pkt = {
        "no": no, "ts": ts, "len": length, "caplen": len(raw),
        "proto": "Unknown", "src": "", "dst": "",
        "sport": None, "dport": None,
        "src_ip": "", "dst_ip": "",
        "seq": None, "ack": None,
        "transport": "",
        "flags": "",
        "flowkey": None, "flowlabel": "",
        "summary": "", "payload": b"", "raw": raw,
        "layers": [],
    }
    layers = []
    data = raw

    if linktype == DLT_EN10MB:
        layer, data, etype = parse_ethernet(data)
        if layer is None:
            pkt["summary"] = f"Ethernet caplen={len(raw)}"
            return pkt
        layers.append(layer)
        if etype == 0x0806:
            l2, _ = parse_arp(data)
            if l2:
                layers.append(l2)
                pkt["proto"] = "ARP"
                pkt["src"] = l2["fields"].get("Sender IP", "")
                pkt["dst"] = l2["fields"].get("Target IP", "")
                op = l2["fields"]["Operation"]
                pkt["summary"] = (f"Who has {pkt['dst']}? Tell {pkt['src']}"
                                  if "Request" in op else
                                  f"{pkt['src']} is at {l2['fields'].get('Sender MAC')}")
        elif etype == 0x0800:
            _parse_ip(data, layers, pkt, v6=False)
        elif etype == 0x86DD:
            _parse_ip(data, layers, pkt, v6=True)
        else:
            pkt["summary"] = f"EtherType 0x{etype:04x}"
    elif linktype in (DLT_NULL, DLT_LOOP):
        if len(data) >= 4:
            fam = struct.unpack("=I", data[:4])[0]
            data = data[4:]
            if fam == 2:
                _parse_ip(data, layers, pkt, v6=False)
            elif fam in (10, 23, 24, 28, 30):   # IPv6: Linux=10 / Windows=23 / macOS=30
                _parse_ip(data, layers, pkt, v6=True)
    elif linktype in (DLT_RAW, DLT_LINUX_SLL, DLT_LINUX_SLL2):
        if linktype in (DLT_LINUX_SLL, DLT_LINUX_SLL2) and len(data) >= 16:
            data = data[16:]
        if data:
            ver = data[0] >> 4
            if ver == 4:
                _parse_ip(data, layers, pkt, v6=False)
            elif ver == 6:
                _parse_ip(data, layers, pkt, v6=True)

    pkt["layers"] = layers
    return pkt

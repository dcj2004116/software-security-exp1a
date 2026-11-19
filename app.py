"""
app.py —— FastAPI 后端：WebSocket 推送抓包结果 + REST 控制接口

运行：
    bash run.sh            # 自动装依赖 + setcap 授权 + 启动
    # 或手动：
    sudo python3 -m uvicorn app:app --host 0.0.0.0 --port 8000

浏览器访问 http://localhost:8000
"""
import os
import time
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

import capture
import parser as P
import flow as F

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

capture_obj = capture.Capture()
tracker = F.FlowTracker()

packet_queue = None          # asyncio.Queue，lifespan 里初始化
main_loop = None
counter = {"n": 0}

_process_cache = {"data": {}, "t": 0.0}


class StartReq(BaseModel):
    device: str = ""
    filter: str = ""


class SaveReq(BaseModel):
    path: str = "/tmp/sniffer_capture.pcap"


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
    tracker.add(pkt)
    if main_loop is not None and packet_queue is not None:
        try:
            main_loop.call_soon_threadsafe(packet_queue.put_nowait, to_json(pkt))
        except asyncio.QueueFull:
            pass


@asynccontextmanager
async def lifespan(app):
    global main_loop, packet_queue
    main_loop = asyncio.get_running_loop()
    packet_queue = asyncio.Queue(maxsize=20000)
    yield
    capture_obj.close()


app = FastAPI(title="Network Sniffer (Exp 1A)", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(os.path.join(BASE_DIR, "static", "index.html"))


@app.get("/devices")
def devices():
    try:
        return {"devices": capture.list_devices()}
    except capture.CaptureError as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/start")
def start(req: StartReq):
    global counter
    try:
        capture_obj.close()
        counter["n"] = 0
        tracker.reset()
        capture_obj.open(req.device, req.filter)
        capture_obj.start(on_packet)
        return {"ok": True, "device": req.device, "filter": req.filter}
    except capture.CaptureError as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/stop")
def stop():
    capture_obj.stop()
    return {"ok": True, "count": counter["n"]}


@app.get("/status")
def status():
    return {"running": capture_obj.running, "count": counter["n"]}


@app.post("/save")
def save(req: SaveReq):
    try:
        capture_obj.save_pcap(req.path)
        return {"ok": True, "path": req.path}
    except capture.CaptureError as e:
        return JSONResponse({"error": str(e)}, status_code=500)


def _render_text(b):
    return "".join(chr(c) if (32 <= c < 127) else ("\n" if c in (10, 13) else ".")
                   for c in b)


@app.get("/follow/{key}")
def follow(key: str):
    res = tracker.follow(key)
    if res is None:
        return JSONResponse({"error": "flow not found"}, status_code=404)
    return {"label": res["label"], "packets": res["packets"],
            "directions": [{"direction": d["direction"],
                            "text": _render_text(d["bytes"])}
                           for d in res["directions"]]}


@app.get("/processes")
def processes():
    now = time.time()
    if now - _process_cache["t"] > 3 or not _process_cache["data"]:
        try:
            _process_cache["data"] = F.get_process_map()
            _process_cache["t"] = now
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    conns = [{"ip": ip, "port": port, "pid": pid, "name": name}
             for (ip, port), (pid, name) in _process_cache["data"].items()]
    return {"connections": conns}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            pkt = await packet_queue.get()
            await websocket.send_json(pkt)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass

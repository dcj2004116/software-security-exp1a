#!/usr/bin/env bash
# 一键启动嗅探器（零第三方依赖，抓包需要 root 权限）
cd "$(dirname "$0")"
echo "启动嗅探器 http://0.0.0.0:8000"
echo "提示：抓包需要 root / CAP_NET_RAW 权限"
exec sudo python3 app.py

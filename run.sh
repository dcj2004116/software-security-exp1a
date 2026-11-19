#!/usr/bin/env bash
# 一键启动嗅探器：安装依赖 + 最小权限授权(CAP_NET_RAW) + 启动服务
set -e
cd "$(dirname "$0")"

echo "==> [1/3] 安装 Python 依赖"
pip3 install -r requirements.txt -q

echo "==> [2/3] 配置抓包能力（CAP_NET_RAW，最小权限，免 root）"
PYBIN="$(command -v python3)"
if [ ! -f ./sniffpy ]; then
    cp "$PYBIN" ./sniffpy
fi

if command -v sudo >/dev/null 2>&1; then
    if sudo setcap cap_net_raw,cap_net_admin=eip ./sniffpy 2>/dev/null; then
        echo "    capability 已设置（./sniffpy）"
    else
        echo "!! setcap 失败（可能无 sudo，或文件系统不支持 xattr，如 NFS 家目录）"
        echo "   请改用 root 运行：sudo python3 -m uvicorn app:app --host 0.0.0.0 --port 8000"
    fi
else
    echo "!! 没有 sudo，请以 root 运行：sudo python3 -m uvicorn app:app --host 0.0.0.0 --port 8000"
fi

echo "==> [3/3] 启动服务 http://localhost:8000"
exec ./sniffpy -m uvicorn app:app --host 0.0.0.0 --port 8000

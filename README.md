# 实验 1A：带 Web 界面的网络嗅探器

基于 **libpcap + Python 标准库 + 网页前端** 实现的网络嗅探器（NPS + NPA + 流追踪）。

**零第三方依赖**：后端用纯标准库（`http.server` + SSE），无需 `pip install`，
适配无外网的实验室主机。

> 此 README 仅供自己参考，提交时不需要（作业要求"无需 README，把想说的写进 report 文档，Git 链接必须写进文档"）。

## 功能

- **抓包（NPS）**：枚举网卡、混杂模式、libpcap 抓包
- **协议解析（NPA）**：Ethernet / 802.1Q / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / HTTP / DNS / TLS，逐层手动解析
- **过滤**：libpcap BPF 抓包过滤 + 前端显示过滤
- **Follow TCP Stream**：按 (IP, Port) 四元组 + seq 重组流
- **进程 → 连接映射**：通过 Linux `/proc` 关联
- **导出 pcap**：把抓到的包保存成标准 pcap 文件
- **网页三栏界面**：包列表 / 包详情 / 原始字节

## 环境要求（Linux）

- Python 3.x（Ubuntu 自带）
- libpcap 运行库（`ldconfig -p | grep pcap` 能看到 `libpcap.so.x` 即可，一般已装）
- 抓包权限：root（用 sudo 运行）

## 快速开始

```bash
sudo python3 app.py
```

然后本机浏览器（VS Code 端口转发后）打开 http://localhost:8000

## 演示测试流量（无外网也能演示）

```bash
# 终端1：造 HTTP 流量（起本地服务并请求 10 次）
python3 traffic.py

# 终端2：启动嗅探器，网页里选 lo 网卡开始抓包
```

## 目录结构

```
EX1A/
├── app.py          # 纯标准库 HTTP 后端 + SSE 推送
├── capture.py      # libpcap ctypes 封装
├── parser.py       # 协议解析
├── flow.py         # 流追踪 + 进程映射
├── traffic.py      # 测试流量生成
├── run.sh          # 一键启动（sudo）
├── static/index.html  # 前端
└── requirements.txt   # （空，无第三方依赖）
```

# 实验 1A：带 Web 界面的网络嗅探器（Sniffer v5）

基于 **libpcap / Npcap + Python 标准库 + 原生网页前端** 实现的网络嗅探器
（NPS 抓包 + NPA 协议解析 + 流追踪 + 进程映射）。

**零第三方依赖**：抓包用 ctypes 直调 libpcap/Npcap，后端用标准库 `http.server` + SSE，
前端原生 HTML/CSS/JS（SVG 手绘图表）。这使判卷者无需任何环境准备即可 `python app.py`
一键复现；同时更直接地体现了对 libpcap 与各层协议格式的底层掌握，而非依赖高层封装。
Linux / Windows（Npcap）均可运行。

> 此 README 仅供自己参考，提交时不需要（作业要求"无需 README，把想说的写进 report 文档，Git 链接必须写进文档"）。

## 功能

- **抓包（NPS）**：枚举网卡、混杂模式、libpcap / Npcap 抓包，无 libpcap 时自动回退原始套接字（AF_PACKET）
- **协议解析（NPA）**：Ethernet / 802.1Q / ARP / IPv4 / IPv6（含扩展头）/ TCP / UDP / ICMP / ICMPv6 / HTTP / DNS / TLS / DHCP，逐层手动解析；TLS 提取 SNI 域名，HTTP 提取状态码
- **过滤**：libpcap BPF 抓包过滤 + 前端显示过滤 + 关键字搜索
- **Follow TCP Stream**：按 (IP, Port) 四元组 + seq 重组流，含时序图
- **会话面板**：列出所有 TCP 会话（源/目的/包数/字节/时长），一键查看流或导出流内容
- **实时统计**：协议分布饼图 + 抓包速率曲线（原生 SVG）
- **进程 → 连接 → 流**：Linux `/proc`（fd inode 关联），Windows `netstat + tasklist`；支持查看某进程产生的所有 TCP 流（加分项）
- **导出**：pcap 文件导出、流内容导出为 txt
- **丢包统计**：libpcap `pcap_stats`（received/dropped/if_dropped）
- **网页界面**：可拖拽三栏（包列表 / 包详情 / 原始字节）、亮/暗主题、字号缩放、键盘快捷键、网卡与过滤条件持久化

## 环境要求

- Python 3.x（3.10+，标准库）
- Linux：libpcap 运行库；抓包需 root / CAP_NET_RAW（`sudo`）
- Windows：安装 [Npcap](https://npcap.com/)（安装时勾选 WinPcap 兼容模式）；回环网卡无需管理员，真实网卡需管理员

## 快速开始

```bash
# Linux
sudo python3 app.py
# Windows
python app.py        # 或右键 run.bat 以管理员身份运行
```

然后浏览器打开 http://localhost:8000

## 演示测试流量（无外网也能演示）

```bash
# 终端 1：生成多协议流量（HTTP/DNS/TLS/ICMP/UDP，每秒一轮）
python traffic.py

# 终端 2：启动嗅探器，网页里选回环网卡开始抓包
#   Linux 选 lo；Windows 选 \Device\NPF_Loopback
#   抓包过滤可留空，一次看到 TCP/HTTP/TLS/DNS/ICMP/UDP 六种协议
```

## 运行测试

```bash
python -m unittest discover -s tests -v
```

## 目录结构

```
EX1A/
├── app.py          # 纯标准库 HTTP 后端 + SSE 推送 + 统计/会话/导出接口
├── capture.py      # libpcap/Npcap ctypes 封装 + 原始套接字回退 + pcap 导出
├── parser.py       # 逐层协议解析（含 TLS SNI、IPv6 扩展头）
├── flow.py         # 流追踪 + 进程映射
├── traffic.py      # 多协议测试流量生成（HTTP/DNS/TLS/ICMP/UDP）
├── run.sh / run.bat# 一键启动
├── static/index.html  # 前端（三栏可拖拽、会话面板、统计图表、快捷键）
├── tests/          # 单元测试（unittest）
└── requirements.txt   # （空，无第三方依赖）
```

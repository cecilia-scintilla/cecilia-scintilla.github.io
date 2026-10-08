---
layout: post
title: Wireshark 抓包与流量分析入门（附 telnet 题目实战）
date: 2026-10-04 20:00:00 +0800
categories: CTF
---

Wireshark 抓包与流量分析入门（附 telnet 题目实战）

这篇笔记解决三个问题：**抓包是什么**、**怎么用 Wireshark 抓**、**拿到 pcap 之后怎么分析**。最后用 Bugku「telnet」那题完整走一遍流程。

一、抓包到底是什么

```text
你的电脑 ────网卡────> 路由器 ────> 互联网
              ↑
         抓包就在这里"把经过的数据录下来"
```

- 录下来的文件就是 **`.pcap`**（或较新的 `.pcapng`）—— 也就是流量分析题附件的形式。
- 关键点：**很多协议是明文传输的**（telnet、ftp、http…），所以只要抓到包，内容就能直接看到。这就是为什么"telnet 那道题"能在数据包里搜到 flag。

二、安装 Wireshark（Windows）

- 官网：`https://www.wireshark.org/download.html`
- 版本：Windows x64 Installer（写作时最新稳定版是 4.6.9）

安装时的**关键一步**：

```text
中途会弹出 Npcap 的安装提示 —— 必须勾选安装！
Npcap 是抓包驱动，不装的话 Wireshark 只能打开现成 pcap，
无法抓实时流量（网卡列表会是空的）。
```

装完可能提示重启，一般直接打开也能用。

三、Wireshark 界面（四个区域）

```text
┌──────────────────────────────────────────────────────┐
│ ① 过滤栏  输入 telnet / http / ip.addr==1.2.3.4 等     │
├──────────────────────────────────────────────────────┤
│ ② 数据包列表  一行一个包：序号 | 时间 | 源 | 目的 | 协议 | 长度 | 信息 │
├──────────────────────────────────────────────────────┤
│ ③ 包详情  把选中的包逐层展开（以太网 → IP → TCP → 数据）│
├──────────────────────────────────────────────────────┤
│ ④ 十六进制视图  这个包的原始字节（左十六进制、右 ASCII）│
└──────────────────────────────────────────────────────┘
```

**做 CTF 题时你主要看 ② 和 ④**：②找出可疑的包，④看里面的原始内容。

四、怎么抓包（操作步骤）

1. 打开 Wireshark，主界面会列出**所有网卡**（每块网卡后面有流量波动曲线）
2. **双击你要抓的网卡**开始抓包（一般选"以太网"或"WLAN"，看哪个有波动）
3. 这时去**复现你要分析的操作**（比如用 telnet 连服务器、打开某个网页）
4. 回到 Wireshark，点左上角的**红色方块（Stop）**停止抓包
5. `File → Save As` 保存成 `.pcap` 文件

**常用过滤命令**（第 ① 区输入，输完按回车）：

```text
telnet                      只看 telnet 流量
http                        只看 HTTP
ftp                         只看 FTP
icmp                        只看 ping 的包
tcp.port == 23              只看 23 端口（telnet 默认端口）
ip.addr == 10.0.0.2         只看跟某个 IP 的通信
ip.src == 10.0.0.2          只看来自某个 IP 的包
tcp contains "flag"         只看载荷里含 flag 的包（很实用！）
frame contains "flag"       同上，在整帧里找
```

> 提示：过滤栏输错会变红，按 `Ctrl+Z` 撤销。

五、⭐ 最重要的一招：追踪 TCP 流（Follow TCP Stream）

**这是流量分析里最核心的功能**，一定要掌握：

```text
右键任意一个包 → Follow（追踪）→ TCP Stream（TCP 流）
```

它会弹出一个窗口，把**同一个 TCP 连接的所有数据包按顺序拼接**起来显示：

- 默认会用**红蓝两色**区分两个方向（谁发给谁一目了然）
- 找到内容后可以直接 `Save as` 导出

**为什么必须用它**：像 telnet 这种协议是**逐字符发送**的，一个 flag 很可能被拆成好几个数据包。如果只在"原始字节"里搜 `flag{`，会因为中间夹着包头而搜不到 —— **必须先把流拼起来才能看到完整内容**。

六、其它必备功能

| 功能 | 位置 | 用途 |
|---|---|---|
| 协议层次统计 | Statistics → Protocol Hierarchy | 一眼看出这包里有哪些协议 |
| 会话统计 | Statistics → Conversations | 看哪些 IP 通信最多 |
| 导出对象 | File → Export Objects → HTTP | 把 HTTP 传输的文件导出来 |
| 查找 | Ctrl + F（可选"分组字节流/分组详情"） | 搜 flag、password 等关键字 |
| 追踪 UDP 流 | 右键 → Follow → UDP Stream | 分析 DNS 等多播/无连接协议 |

**`Ctrl + F` 查找的三种类型**（很多人搜不到就是因为选错）：

```text
分组列表   —— 只搜列表里显示的信息
分组详情   —— 搜展开后的协议字段（推荐）
分组字节流 —— 搜原始字节（找 flag 用这个，最容易命中）
```

七、实战：Bugku「telnet」这道题

题目：附件是一个 pcap，提示 `flag{xxxxxxxxxxxxxxxxxxxxxxxxxxx}`。

```text
① Wireshark 打开这个 pcap
② 过滤栏输入 telnet 回车，看到一堆 telnet 包
③ 右键任意 telnet 包 → Follow → TCP Stream
④ 弹窗里就是完整的 telnet 会话：
      Welcome to the server
      login: admin          <- 明文用户名！
      Password: admin123    <- 明文密码！
      $ cat /home/flag.txt
      flag{xxxxxxxxxxxxxxxxxxxxxxxxxxx}
⑤ 直接复制 flag 提交
```

**顺便学到的道理**：telnet/ftp/http 这些老协议都是**明文**的，抓包就等于看到了对方屏幕。所以现在都用 SSH、HTTPS 替代它们。

八、没有 Wireshark 怎么办（替代方案）

| 需求 | 方案 |
|---|---|
| 分析现成的 pcap | 纯 Python 解析：`python pcapfind.py 流量.pcap --dump` |
| 自己抓包 | Windows 自带 **pktmon**（Win10 1809+ 都有） |
| 一键分析 | 「随波逐流」工具箱里有 pcap 数据查看 |
| 只看 HTTP | 浏览器 `F12` → Network 面板（不用抓包） |

**pktmon 抓包命令**（要管理员权限的 PowerShell）：

```powershell
pktmon start --capture --pkt-size 0 -f C:\Users\你\capture.etl
# ...去复现你要分析的操作...
pktmon stop
pktmon etl2pcap C:\Users\你\capture.etl -o C:\Users\你\capture.pcapng
```

> `--pkt-size 0` 表示记录完整数据包；不加的话只记录包头，看不到内容。

九、常见问题排查

| 现象 | 原因 / 解决 |
|---|---|
| 网卡列表是空的 | Npcap 没装成功 → 重装 Wireshark 并勾选 Npcap |
| 抓到一堆包但没自己要的 | 关掉 VPN/加速器（它们会走虚拟网卡），或改抓虚拟网卡 |
| 抓包开着但一个包都没有 | 选错网卡了 → 换另一块网卡试；或网卡没流量 |
| 搜 `flag` 搜不到 | 内容被拆成多个包了 → 改用 **Follow TCP Stream** 拼起来看 |
| 提示没有权限 | 用**管理员身份**运行 Wireshark（抓包需要管理员权限） |
| pcap 打不开 | 可能是 pcapng 格式，Wireshark 两种都支持；或文件损坏 |

十、总结

- 抓包 = **把经过网卡的数据录下来**；分析 pcap = **在录下来的数据里找线索**。
- Wireshark 三招走天下：**过滤（只看关心的协议）→ 追踪流（把会话拼起来）→ 查找（搜关键字）**。
- 记住流量分析的排查顺序：

```text
① 协议层次统计  —— 这包里有什么协议？
② 过滤可疑协议  —— telnet / ftp / http / dns / icmp
③ 追踪 TCP/UDP 流 —— 把会话内容拼出来看（最重要！）
④ 搜关键字      —— flag{ / key{ / password / admin
⑤ 导出对象      —— HTTP 传的文件可以导出来
```

- CTF 里**大多数流量分析题都是直接给你 pcap 文件**，你不需要自己抓包 —— 所以先把"分析"这一半练熟，抓包等你需要时再练。

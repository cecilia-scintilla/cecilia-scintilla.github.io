---
layout: post
title: Bugku CTF - linux Writeup
date: 2026-10-05 20:00:00 +0800
categories: CTF
---

Bugku CTF - linux Writeup

一、题目信息

- 题型：MISC
- 题目：linux
- 考点：文件类型识别（file）、套娃式压缩包解压、strings 提取可打印字符串、grep 过滤

二、题目分析

- 题目描述只有一句"linux基础问题"，提示给的 flag 格式是 `key{}`（**不是 flag{}**，这点要注意）。
- 下载附件后解压，得到一个**没有后缀名**的文件，用十六进制工具打开会发现里面大片空白，中间夹着少量可读文本，并且能看到 `flag.txt` 这样的文件名 —— 这说明它是一个 **Linux 磁盘/分区镜像**（ext3 文件系统）。
- 也就是说，这道题的结构是"套娃"：

```text
linux.zip  →  linux.tar（其实是 gzip 压缩的 tar）  →  磁盘镜像（ext3）  →  flag.txt
```

- 题解里说的"两次解压"就是这个意思：压缩包解开还有一层压缩，第二层解完才是真正的镜像文件。
- 而 flag 就写在镜像里的 `flag.txt` 中，是**明文存储**的，所以不需要真的把镜像挂载起来，用 `strings` 把里面的字符串全倒出来就能看到。

三、解题步骤

- 第一步：先用 `file` 命令确认文件真实类型（不要靠后缀名猜）。

```bash
file linux            # 输出显示是 Linux 磁盘/分区镜像（ext3 文件系统）
```

- 第二步：把压缩包解压到底。附件是两层压缩，解压两次才能拿到镜像文件。

```bash
unzip linux.zip       # 解出 linux.tar
tar -zxvf linux.tar   # 它实际是 tar.gz，再解一次得到镜像文件
```

- 第三步：用 `strings` 把镜像里的可打印字符串全部输出，配合 `grep` 过滤出 flag。

```bash
strings 镜像文件 | grep -i "key{"
```

- 得到 flag：

```text
key{feb81d3834e2423c9903f4755464060b}
```

- 补充几种等价做法：

```bash
# 直接全文件搜索（grep 加 -a 把二进制当文本处理）
grep -a "key" 镜像文件

# 想按文件系统的方式做，就挂载镜像再读文件（更"正规"，但 CTF 里没必要）
sudo mount -o loop 镜像文件 /mnt && cat /mnt/flag.txt
```

四、Windows 环境下的做法

没有 Kali / Linux 也能做，思路完全一样，只是换工具：

- 第一步：把 `linux.zip` 解压，得到 `linux.tar`；再把它解压一次（7-Zip 可以直接识别 gzip），得到那个无后缀的镜像文件。
- 第二步：用支持"搜索明文"的工具打开**镜像文件**（不是压缩包！），搜索 `key{`：
  - WinHex / 010 Editor：搜索时选 **ASCII / Text 模式**，关键字带上花括号写 `key{`，避免命中大量无关内容；
  - Notepad++ / VS Code：直接打开（或改后缀为 `.txt`）后 `Ctrl+F` 搜 `key{`；
  - 命令行等价写法（PowerShell 调 Python 模拟 strings）：

```powershell
python -c "
import re
d = open('镜像文件','rb').read()
for m in re.finditer(rb'[ -~]{4,}', d):
    s = m.group().decode()
    if 'key{' in s: print(s)
"
```

> 一个常见踩坑点：**不要在压缩包上直接搜 `key`**。压缩包里的数据是压缩过的二进制，`key{}` 早已不是明文，搜不到是必然的，必须先解压到最里面那层镜像文件再搜。

五、总结

- 这道题的核心考点只有一个：**`strings` 命令**（提取文件中的可打印字符串），它是 MISC 类题目最常用的"第一把梭"，配合 `grep` 几乎能解决一大半隐写/镜像类题目。
- 通用套路：拿到附件先 `file` 看类型 → `strings xxx | grep 关键字` 梭一遍 → 不行再考虑挂载、binwalk、foremost 等更重的工具。
- 别忘了提交格式：本题提示明确写了 `key{}`，解析出来的字符串本身已带 `key{}`，直接提交即可。

---
layout: post
title: Bugku CTF - 黄道十二宫 Writeup
date: 2026-09-28 20:00:00 +0800
categories: CTF
---

Bugku CTF - 黄道十二宫 Writeup

一、题目信息

- 题型：Crypto（密码学）
- 题目：黄道十二宫
- 考点：黄道十二宫杀手（Zodiac Killer）340 密码——把图片符号转成文本、按特定走法读取，
  再用 AZdecrypt 做同音替换求解。属于"真实事件改编"的密码题

二、题目分析

- 下载附件得到一张图片，上面画满了各种奇怪符号（圆圈加十字、字母变形、几何图形等）。
- 图片本身没有隐写，题目名字"黄道十二宫"就是全部提示 —— 指的是 1969 年美国**黄道十二宫杀手**寄给报社的密码信（著名的 340 密码）。
- 这题考的不是某一个编码，而是要**复刻真实事件的破解流程**：

```text
第 1 步：把图片里的符号逐个敲成文本（本题是 9 行 × 15 个符号）
第 2 步：按特定走法把二维的符号读成一维字符串
第 3 步：把字符串丢进 AZdecrypt，做同音替换（homophonic substitution）求解
```

- 第 2 步的走法是本题最"反直觉"的地方：**不是简单地按行读**，而是

```text
从左上角开始，每读一个字符就「往下走一行、往右走两列」；
走到最下面一行回到第一行继续；
每读满 9 个字符，整体起点向右挪一格。
```

- 关于 AZdecrypt：它是目前破解黄道十二宫 340 密码最有效的免费工具（作者 Jarl Van Eycke），下载地址 `http://scz.bplaced.net/azdecrypt.html`。

三、解题步骤

- **第一步：把图片上的符号敲成文本**
  按行敲，每行 15 个符号，一共 9 行。用任意字符代表符号就行（同一个符号用同一个字符表示即可），例如：

```text
%,,@_>@?==%88%5
,@%#@@90-7$^=_@
17,(>()1@##-$40
~,_6?#%#8#=75+1
(_@_1%#>,0@5)%?
%_^=)&>=1%,+7&#
8681(+8_@@(,@@@
#_=#$3_#%,#%%,3
,_+7,7+@===+)61
```

- **第二步：按走法读出线性字符串**（用 Python 实现，这段逻辑是本题的核心）：

```python
# -*- coding: utf-8 -*-
ROWS, COLS = 9, 15

def read_zigzag(lines):
    """每步 下移一行、右移两列；行尾回卷；每读满 9 个字符，起点右移一格"""
    res, i, j, m = '', 0, 0, 1
    while len(res) < ROWS * COLS:
        if i > COLS - 1:
            i -= COLS
        if j >= len(lines):
            j = 0
        res += lines[j][i]
        i += 2
        j += 1
        if len(res) % ROWS == 0:
            i = m % ROWS + m // ROWS
            j = 0
            m += 1
    return res

lines = [l.strip() for l in open('hd.txt', encoding='utf-8') if l.strip()]
res = read_zigzag(lines)
print(len(res), res)                      # 135 个字符

with open('solve.txt', 'w', encoding='utf-8') as f:
    for i in range(0, len(res) - COLS + 1, COLS):
        f.write(res[i:i + COLS] + '\n')   # 按 15 字符一行写出
```

- **第三步：用 AZdecrypt 求解**
  1. 下载并打开 AZdecrypt（`http://scz.bplaced.net/azdecrypt.html`）；
  2. `New` 新建，把上一步生成的 `solve.txt` 内容粘贴进去；
  3. 选择同音替换（Homophonic substitution）相关的求解模式，点 `Solve`；
  4. 让它多跑一会儿（这类求解是启发式的，可能要跑几轮、或者多点几次 Solve 取最好的结果）。
- **第四步：在解出的英文里找 flag**
  解出的文本是英文片段，其中能看到 `alpha nanke` 这样的词，拼起来就是：

```text
flag{alphananke}
```

- 也可以参考现成的题解和视频
  - 视频讲解：`https://www.bilibili.com/video/av585626175/`
  - 文字题解：搜索 "bugku 黄道十二宫 AZdecrypt"

四、总结

- 这题属于 CTF 里的"**背景知识题**"：考的是你知不知道黄道十二宫杀手的 340 密码这件事，以及配套的破解工具 AZdecrypt。技术上不难，但**不知道背景就完全无从下手**。
- 通用经验：
  1. 拿到一张**满是奇怪符号**的图片，先去查"这是什么密码体系"，而不是对着图片硬猜；
  2. 遇到"真实事件改编"的密码题（例如黄道十二宫、克里普托斯雕塑、玛丽女王的信），直接搜事件名 + "密码/破解"，通常能找到现成的工具和思路；
  3. 这类题往往需要**先手工把图形转录成文本**（本题的 9×15 符号矩阵），转录时要仔细，漏一个符号结果就跑偏。
- 关于 AZdecrypt：它是专门为这类"同音替换密码"设计的求解器，本质是用语言模型（n-gram）去搜索最可能的替换表。类似的思路也可用于其他古典替换密码。

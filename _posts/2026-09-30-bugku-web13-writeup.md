---
layout: post
title: Bugku CTF - ok Writeup
date: 2026-09-17 20:00:00 +0800
categories: CTF
---

Bugku CTF - ok Writeup

一、题目信息

- 题型：Crypto（密码学）
- 题目：ok
- 考点：Ook! 语言（Brainfuck 的变形）识别与解码

二、题目分析

- 题目描述只有一个词 `Ook.`，附件里是一大段由 `Ook.` `Ook?` `Ook!` 三种记号两两组合而成的文本。

```text
Ook. Ook? Ook! Ook! Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. …
```

- `Ook!` 是一种"入门级"的深奥编程语言（esolang），它其实就是 **Brainfuck 的马甲**：把 Brainfuck 的 8 个符号换成 8 组 Ook 词组，两种语言的程序可以一一对应互相翻译。

三、解题步骤

- 先认识 Ook! 与 Brainfuck 的对照表（每组是两个 Ook 记号）：

```text
Ook. Ook?  →  >        Ook? Ook.  →  <
Ook. Ook.  →  +        Ook! Ook!  →  -
Ook! Ook.  →  .        Ook. Ook!  →  ,
Ook! Ook?  →  [        Ook? Ook!  →  ]
```

- 最简单的方法：把附件内容整段复制到 Ook! 在线解码工具里（例如 `https://www.splitbrain.org/services/ook`），选择 "Ook! to text"，直接就能看到 flag。
- 也可以用"随波逐流"这类一键解码工具，选择 Ook 解码。
- 如果想自己动手，就按上面的对照表把 Ook 文本翻译成 Brainfuck 代码，再用 Brainfuck 解释器跑一遍。Python 脚本（先翻译，再解释执行）：

```python
# -*- coding: utf-8 -*-
import re

P = {('Ook.', 'Ook?'): '>', ('Ook?', 'Ook.'): '<',
     ('Ook.', 'Ook.'): '+', ('Ook!', 'Ook!'): '-',
     ('Ook!', 'Ook.'): '.', ('Ook.', 'Ook!'): ',',
     ('Ook!', 'Ook?'): '[', ('Ook?', 'Ook!'): ']'}

ook = open('ook.txt').read()          # 附件内容
t = ook.split()
bf = ''.join(P.get((t[i], t[i + 1]), '') for i in range(0, len(t) - 1, 2))

# ---- 以下是 Brainfuck 解释器 ----
tape = [0] * 30000
p = i = 0
out = []
stack = []
br = {}
for j, c in enumerate(bf):
    if c == '[':
        stack.append(j)
    elif c == ']':
        k = stack.pop()
        br[k] = j
        br[j] = k
while i < len(bf):
    c = bf[i]
    if c == '>':
        p += 1
    elif c == '<':
        p -= 1
    elif c == '+':
        tape[p] = (tape[p] + 1) & 0xFF
    elif c == '-':
        tape[p] = (tape[p] - 1) & 0xFF
    elif c == '.':
        out.append(chr(tape[p]))
    elif c == '[' and tape[p] == 0:
        i = br[i]
    elif c == ']' and tape[p] != 0:
        i = br[i]
    i += 1

print(''.join(out))
```

- 注意：附件里可能存在多余的空格或换行，翻译前保证每组 Ook 记号之间用空格分隔、两两成对即可（`split()` 会自动处理多余空白）。
- 解出来的结果就是 flag：

```text
flag{0a394df55312c51a}
```

四、总结

- 看到满屏 `Ook.` `Ook?` `Ook!`，可以确定是 Ook! 语言；同类"换皮"语言还有 `Brainfuck`、`JSFuck`、`AAencode`、`jother` 等，思路都是"认出语言 → 找对应解码器"。
- Ook! 和 Brainfuck 是等价的，如果找不到 Ook 解码器，也可以先手动翻译成 Brainfuck 再解码（本题就是通过这种方式还原出 flag 的）。

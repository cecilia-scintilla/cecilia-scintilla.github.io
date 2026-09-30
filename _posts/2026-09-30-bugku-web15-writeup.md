---
layout: post
title: Bugku CTF - 入门逆向 Writeup
date: 2026-09-19 20:00:00 +0800
categories: CTF
---

Bugku CTF - 入门逆向 Writeup

一、题目信息

- 题型：Reverse（逆向工程）
- 题目：入门逆向（来源：XJNU）
- 金币：1　　分数：10
- 考点：PE 文件基本分析、IDA 静态分析、flag 以明文字节硬编码

二、题目分析

- 下载附件得到一个可执行文件，先看文件类型和位数，再决定用哪个工具打开：

```bash
file reverse.exe        # PE32 executable (console) Intel 80386 → 32 位程序
strings reverse.exe     # 先碰碰运气，有时 flag 会直接以明文字符串出现
```

- 如果 `strings` 没直接看到完整 flag，就用 IDA Pro（32-bit）打开，找到 `_main` 函数。
- 打开后发现 `_main` 里是一长串 `mov` 指令，把一个个字节写进栈上的局部变量，而这些字节拼起来正好是一段可见字符——也就是说 flag 被**硬编码**在程序里了。

三、解题步骤

- 在 IDA 里定位 `_main`（左侧 Functions window 搜索 main，或直接看 entry 之后的第一个函数），能看到类似下面的代码（字节以十六进制立即数形式出现）：

```asm
mov     [ebp+var_40], 66h   ; f
mov     [ebp+var_3F], 6Ch   ; l
mov     [ebp+var_3E], 61h   ; a
mov     [ebp+var_3D], 67h   ; g
mov     [ebp+var_3C], 7Bh   ; {
...
mov     [ebp+var_2C], 7Dh   ; }
```

- 按顺序把十六进制字节读出来：

```text
66 6C 61 67 7B 52 65 5F 31 73 5F 53 30 5F 43 30 4F 4C 7D
```

- 转成字符就是 flag，用 Python 验证一下：

```python
# -*- coding: utf-8 -*-
# 注意：flag 里的字符都是单字节 ASCII，用 latin-1 解码不会出乱码
data = '66 6C 61 67 7B 52 65 5F 31 73 5F 53 30 5F 43 30 4F 4C 7D'.replace(' ', '')
print(bytes.fromhex(data).decode('latin-1'))
# 输出：flag{Re_1s_S0_C0OL}
```

- 也可以直接**在 IDA 里操作**：选中第一个字节（66h），按 `R` 键把它转成字符，依次把后面的字节都转成字符，就能在反汇编窗口里直接看到明文 `flag{Re_1s_S0_C0OL}`。
- 最终 flag：

```text
flag{Re_1s_S0_C0OL}
```

（小提示：解析出的字符串本身已带 `flag{}`，提交时注意与平台提示的格式保持一致。）

四、总结

- 逆向入门题的常见套路就是：**先 `file` 看类型 → 再 `strings` 捞字符串 → 最后上 IDA 看 `_main`**，绝大多数"入门"级别的题在这三步之内就能出结果。
- 如果 `strings` 没有结果，说明 flag 被拆成了单个字节（就像本题这样），此时在反汇编里找连续的 `mov [ebp-xx], 立即数`，把立即数按顺序拼起来即可。
- 小技巧：IDA 里处理这种"逐字节赋值"的代码时，注意栈变量的布局（`var_40` 到 `var_2C` 是连续地址），按地址从低到高读取就不会把顺序弄反。

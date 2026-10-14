---
layout: post
title: CTFHub - 目录遍历 Writeup（Apache 目录列表实战）
platform: ctfhub
date: 2026-10-14 16:01:00 +0800
categories: CTF
---

CTFHub - 目录遍历 Writeup（Apache 目录列表实战）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → **目录遍历**）
- 题型：Web
- 考点：**Apache 目录列表（Directory Listing）**、链接爬取、排序参数陷阱


```text
真实结构     : 3 层目录，每层 4 个分支（1/ 2/ 3/ 4/）
flag 位置    : /flag_in_here/3/2/flag.txt
正确请求     : GET http://challenge-xxx:10800/flag_in_here/3/2/flag.txt
flag         : ctfhub{c157989040f8d75ce296af49}
爬取耗时     : 21 个请求，3 层就撞到了（很快）
```

二、题目分析

**① 题目现象**

打开环境首页：

```html
<h1>目录遍历</h1>
<a href="flag_in_here/" class="btn btn-success">点击开始寻找flag</a>
```

点那个按钮进去，看到的是 **Apache 的目录列表页**：

```text
Index of /flag_in_here
  [DIR]  1/
  [DIR]  2/
  [DIR]  3/
  [DIR]  4/
  [PARENTDIR] Parent Directory
```

再点进 `1/`，里面又是 4 个子目录 —— **层层嵌套，跟迷宫一样**。

**② 真实结构（实测）**

```text
/                                   首页（一个按钮）
└── /flag_in_here/                  4 个子目录
    ├── /1/  /2/  /3/  /4/          每层再 4 个
    │   └── /1/ /2/ /3/ /4/         flag 就在这一层的某个目录里
    └── ...                        /3/2/flag.txt  ← ★ 实测在这里
```

**总路径数**：4 × 4 = 16 条（第 2 层就找到了），最多也就是 4³ = 64 条 —— **比想象的少，很快能扫完**。

**③ 这题在考什么**

```text
"目录遍历"有两层含义：

① Directory Listing（目录列表泄露）← 本题
   Apache 配置了 Options +Indexes，把目录下的文件/子目录直接列出来。
   这本身就是信息泄露：你能看到服务器上有什么文件。

② Path Traversal（路径穿越）
   用 ../ 跳出网站根目录读任意文件（比如 ?file=../../../../etc/passwd）
```

三、解题步骤

**方法一：手工点击（能过，但累）**

```text
① 打开环境 → 点【点击开始寻找flag】
② 看到 1/ 2/ 3/ 4/ → 随便点一个进去
③ 一直点到底，看到 flag.txt 就点它 → 显示 flag
④ 没找到就退回上一层换分支
```

**方法二：用脚本自动爬（推荐）**

```powershell
python crawl_ctfhub_dir.py "http://challenge-xxx.sandbox.ctfhub.com:10800" --path flag_in_here --depth 5
```

**实测输出**：

```text
起点: .../flag_in_here/
--- 第 0 层：1 个目录 ---
    [200] .../flag_in_here/   子目录 4 个, 文件 0 个
    → 下一层 4 个目录

--- 第 1 层：4 个目录 ---
    [200] .../flag_in_here/1/   子目录 5 个, 文件 0 个
    [200] .../flag_in_here/2/   子目录 5 个, 文件 0 个
    [200] .../flag_in_here/3/   子目录 5 个, 文件 0 个
    [200] .../flag_in_here/4/   子目录 5 个, 文件 0 个
    → 下一层 16 个目录

--- 第 2 层：16 个目录 ---
    [200] .../flag_in_here/3/2/   子目录 1 个, 文件 1 个
      ☆ 发现 flag 文件: .../flag_in_here/3/2/flag.txt
      ★★★ 找到 flag: ctfhub{c157989040f8d75ce296af49}

共请求 21 个 URL
```

四、⭐ 两个必须知道的"坑"（本题最有价值的经验）

这题看起来简单（就是点目录），但**自己写脚本时会连续踩两个坑**，我实际都踩了：

**坑① 目录必须以 `/` 结尾，请求 `index.html` 会 404**

```text
✅ GET /flag_in_here/1/             → 200 返回目录列表
⚠️ GET /flag_in_here/1              → 301 跳转（Apache 自动补斜杠）
❌ GET /flag_in_here/1/index.html   → 404 ！！！（Apache 不会生成这个文件）

直觉上你会以为"目录里应该有 index.html"，但 Apache 的目录列表是
【动态生成】的，磁盘上并不存在这个文件 → 请求它必然 404。
```

**我第一版脚本就栽在这里**：我按常识去请求 `/flag_in_here/1/index.html`，256 个请求全部 404。

**坑② 目录列表里的"排序链接"是陷阱，跟着爬会无限打转**

Apache 目录列表顶部有这样几个链接：

```html
<tr>
  <th><a href="?C=N;O=D">Name</a></th>
  <th><a href="?C=M;O=A">Last modified</a></th>
  <th><a href="?C=S;O=A">Size</a></th>
  <th><a href="?C=D;O=A">Description</a></th>
</tr>
```

**它们不是子目录！** 只是"按什么排序"的查询参数（C=Column, O=Order）。点它们会**重新渲染同一个目录**，只是排序变了。

```text
如果通用爬虫无脑跟着所有 <a href> 爬：
    /flag_in_here/1/
    → /flag_in_here/1/?C=N;O=D
    → /flag_in_here/1/?C=M;O=A
    → ...无限在同一个页面打转
    → 还会因为请求太多触发服务器【503 限速】
```

**我第一版通用爬虫就这样**：输出里全是 `?C=N;O=A`、`?C=S;O=D` 这种 URL，一层都没往下走。你如果看到爬虫刷出一堆带 `?C=` 的地址，就是这个原因。

**解决办法**：解析链接时**跳过所有带 `?` 的链接**：

```python
for m in re.finditer(r'<a href="([^"]+)"', html):
    href = m.group(1)
    if '?' in href:        # ★ 排序参数，跳过
        continue
    if href.startswith(('/icons/', 'http://', 'https://', '#')):
        continue
    ...
```

> **顺带一个经验**：爬任何"目录列表"页（Apache、Nginx autoindex、Python http.server、IIS），都要注意区分**真实条目**和**界面控件链接**（排序、分页、返回上级）。只看"链接文字 + 形状"有时不够，要看 URL 的特征（带查询参数、指向 /icons/ 等）。

五、延伸知识：目录遍历漏洞

**① Directory Listing（本题）**

```text
成因：Apache 配了 Options Indexes / Nginx 配了 autoindex on / IIS 开了目录浏览
危害：暴露备份文件、源码、数据库导出、配置文件、隐藏目录
（看到 db.sql、www.zip、.git/ 这类东西，往往能直接拿到源码）
防护：Nginx  autoindex off;
      Apache Options -Indexes
      敏感文件不要放在 web 根目录
```

**② Path Traversal（另一种常见考点）**

```text
原理：程序用用户输入拼文件路径，但没过滤 ../
   正常：  /download?file=report.pdf
   攻击：  /download?file=../../../../etc/passwd

常见绕过（当过滤了 ../ 时）：
    ....//          → 过滤掉 ../ 后剩下的还是 ../
    ..%2f           → URL 编码的 /
    %2e%2e%2f       → URL 编码的 ../
    ..\             → Windows 路径分隔符
    绝对路径         → 直接写 /etc/passwd 或 C:\Windows\win.ini
    ....\/          → 混合

防护：不用用户输入直接拼路径 / 用白名单 / basename() 去路径
      / 规范化后检查是否还在允许目录内（realpath 对比）
```

六、总结

- **本题核心：Apache 目录列表把目录结构暴露了，顺着爬到底就能找到 `flag.txt`。**
- **两个实战坑（比题目本身更有价值）**：

```text
① 目录要以 / 结尾请求，别去请求 index.html（动态生成的，磁盘上不存在）
② 目录列表里的 ?C=N;O=D 是排序参数不是子目录，爬虫必须跳过带 ? 的链接
```

- 分清三个容易混的概念：

```text
目录遍历 / Directory Listing  = 服务器列出了目录内容，你顺着看（本题）
路径穿越 / Path Traversal     = 用 ../ 跳出根目录读任意文件
目录爆破 / Directory Bruteforce = 用字典猜隐藏路径名（dirsearch）
```

**配套文件**（都在工作区）：

```text
crawl_ctfhub_dir.py   专治本题的爬取脚本（处理了上面两个坑）
dirtree_crawl.py      通用目录树爬虫（适合"纯链接、无排序参数"的题）
demo_dirtree.py       本地复刻靶场（监听 8889，可自己练手）
run-demo-dirtree.bat  双击启动靶场
crawl-target.bat      双击后粘贴地址即可扫任意题目
```

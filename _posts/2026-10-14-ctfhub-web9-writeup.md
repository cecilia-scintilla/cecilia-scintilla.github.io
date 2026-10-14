---
layout: post
title: CTFHub - bak 文件 Writeup（备份文件下载）
platform: ctfhub
date: 2026-10-14 21:44:00 +0800
categories: CTF
---

CTFHub - bak 文件 Writeup（备份文件下载）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → 备份文件下载 → **bak 文件**）
- 题型：Web
- 考点：**单个文件的备份泄露**（`.bak` 后缀）、备份命名规律


```text
首页提示原文 : Flag in index.php source code.
              （意思是 flag 在 index.php 的源码里）

备份文件     : /index.php.bak                    ← 就试了这一个，直接命中
状态码       : 200
Content-Type : application/x-trash               ← nginx 对 .bak 的默认类型
响应内容     : index.php 的源码

    <!DOCTYPE html>
    <html><head><title>CTFHub 备份文件下载 - bak</title></head>
    <body>
    <?php
    // FLAG: ctfhub{2d72838d5e9cbf3669e1803e}
    echo "Flag in index.php source code.";
    ?>
    </body></html>

flag         : ctfhub{2d72838d5e9cbf3669e1803e}
```

> 💡 因为 `Content-Type` 是 `application/x-trash`，浏览器点开会**直接下载文件**而不是显示。
> 想直接看内容，用命令行更省事：
> ```powershell
> curl.exe -s "http://challenge-xxx:10800/index.php.bak"
> ```

二、题目分析

**① 题目现象**

打开环境首页，页面给了一句提示：

```text
当开发人员在线上环境中对源代码进行了备份操作，
并且将备份文件放在了 web 目录下，就会引起网站源码泄露。
```

页面里还提到了一个文件名（不同环境可能提示 `index.php` 之类）。

**② 原理：和"网站源码"那题一个道理，只是粒度不同**

```text
"网站源码"题 → 泄露的是【整个站的打包】  www.zip / web.rar
"bak 文件"题 → 泄露的是【单个文件的备份】 index.php.bak

共同点：
    这些后缀（.zip / .bak / .old / ~）服务器都【不认识】，
    所以当成普通静态文件原样返回 → 源码可读。

为什么会有 .bak 文件？
    开发者改代码前的习惯动作：
        cp index.php index.php.bak      ← 先备份一份
        改 index.php
        ★ 改完忘了删 index.php.bak
```

**③ 破题思路**

```text
题目已经告诉你文件名了（比如 index.php），
那就给它加上常见的"备份后缀"试一遍：
    index.php.bak       ← 最常见
    index.php~          ← vim / emacs 习惯
    index.php.old
    index.php.orig
    index.php.save
    .index.php.swp      ← vim 交换文件（下一题就是它）
    index.php.bak1 / .bak2
    index.php.txt
    index.php.1 / .2
```

三、解题步骤

**方法一：直接访问（最快，题目提示了文件名）**

```text
假设提示的文件是 index.php，就在地址栏试：
    http://目标地址/index.php.bak       ← ★ 通常就是它
    http://目标地址/index.php~
    http://目标地址/index.php.old
    http://目标地址/index.php.save
```

访问 `.bak` 后，浏览器会**下载一个文件**（或者直接显示源码）—— 打开就能看到 PHP 源码。

**方法二：用我写的工具（自动试 43 种变体）**

```powershell
python find_bak.py http://challenge-xxx:10800 index.php
```

**或者双击 `find-bak.bat`** → 输入地址 → 输入文件名（默认 `index.php`）。

它会自动生成这个文件名的各种备份变体并逐个请求，**发现后直接打印内容并提取 flag**。

**实测效果**（我用模拟的同款站点验证）：

```text
目标: http://127.0.0.1:8892
原始文件: index.php
尝试 43 种备份变体
======================================================================
  ★ [200] /index.php.bak      151 字节

★ 找到 1 个可访问的备份文件
URL: http://127.0.0.1:8892/index.php.bak
内容:
   <?php
   // 备份文件：服务器当成普通文本返回，源码泄露
   $flag = "ctfhub{demo_bak_flag_999}";
   echo "Hello, this is index.php";
   ?>
   ★★★ 发现 flag: ctfhub{demo_bak_flag_999}
```

**方法三：dirsearch 扫（不知道文件名时用）**

```powershell
.\run-dirsearch.bat -u http://challenge-xxx:10800/ -e bak,old,save,swp,txt -t 5 -q
```

> 用 `-e` 指定后缀，dirsearch 会拿字典里的每个名字去组合这些后缀。
> 本题文件名已知，用方法一/二更快。

四、延伸知识：备份文件命名规律速查表

**① 一个文件名的 N 种备份形态**

以 `index.php` 为例：

| 变体 | 由来 | 说明 |
|---|---|---|
| `index.php.bak` | 手动备份 | ★ 最常见 |
| `index.php.bak1` / `.bak2` | 多次备份 | 数字递增 |
| `index.php~` | vim / emacs | 编辑器自动备份 |
| `index.php.old` / `.orig` / `.save` | 手动命名 | 老版本 |
| `.index.php.swp` | **vim 交换文件** | 崩溃恢复用（下一题） |
| `.index.php.swo` / `.swn` | vim 多次崩溃 | swp → swo → swn 递增 |
| `index.php.txt` | 改扩展名伪装 | 有些服务器只解析 .php |
| `index.php.1` / `.001` | 下载工具重命名 | 少见 |
| `backup/index.php` | 备份目录 | 整个目录挪走 |

**② 更全的"备份后缀"清单（爆破时用）**

```text
.bak  .bak1  .bak2  .backup  .old  .orig  .save  .sav
.swp  .swo  .swn  .tmp  .temp  .copy  .txt  .1  .2  .001
~     （波浪号结尾）
.phps （有些配置下会显示 PHP 源码）
```

**③ 为什么 `.phps` 也值得试**

```text
.phps 是 PHP 的一个"显示高亮源码"的扩展名：
    如果服务器配置了 AddType application/x-httpd-php-source .phps
    那么 index.phps 会把源码【高亮显示】出来
（这是配置不当导致的另一种源码泄露，实战中也常见）
```

**④ 拿到源码后看什么**（和上一题一样）

```text
· 硬编码的 flag / 密钥 / 数据库密码
· 后台入口、默认账号
· 权限校验逻辑（哪里能绕过）
· 其它漏洞点（文件包含、命令执行、SQL 注入）
· 服务器路径
```

**⑤ 防护**

```text
· 备份文件放 web 目录之外（或专门的备份服务器）
· 编辑器配置：把 .bak / .swp 写到临时目录，不要留在源码目录
· 服务器禁止访问敏感后缀：
      Nginx:  location ~* \.(bak|old|orig|save|swp|swo|phps)$ { deny all; }
      Apache: <FilesMatch "\.(bak|old|orig|save|swp|phps)$"> Require all denied </FilesMatch>
· 用 git 管理代码（有版本历史就不需要手动 .bak 了）
```

五、总结

- **本题核心：开发者把 `index.php` 备份成 `index.php.bak` 忘了删，而服务器把 `.bak` 当普通文件返回 → 源码泄露。**
- 操作只有一步：**在已知文件名后面加上备份后缀试一遍**，最常用的是 `.bak`，其次是 `~`。
- 和上一题（网站源码）的对比，记住这个"梯度"：

```text
网站源码题  → 泄露【整个站的打包】  www.zip / web.rar   → 猜"包名"
bak 文件题  → 泄露【单个文件备份】  index.php.bak        → 变"后缀"（本题）
vim 缓存题  → 泄露【单个文件快照】  .index.php.swp       → 复用编辑器的临时文件
```

```text
find_bak.py      单文件备份变体爆破（43 种变体，自动提取 flag）
find-bak.bat     双击启动器
find_backup.py   整站打包备份爆破（www.zip 那题用）
```

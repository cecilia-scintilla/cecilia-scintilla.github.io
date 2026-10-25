---
layout: post
title: Pikachu - CSRF Token Writeup（防护有效的一次完整验证）
platform: pikachu
date: 2026-10-25 22:36:00 +0800
categories: CTF
---

Pikachu - CSRF Token Writeup（防护有效的一次完整验证）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：CSRF → CSRF Token
- 入口：`http://localhost/pikachu/vul/csrf/csrftoken/token_get_login.php`
- 题型：Web
- 考点：**CSRF Token 防护是否有效**、同源策略、token 设计原则

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**测试账号**：

```text
vince / allen / kobe / grady / kevin / lucy / lili
密码全部是 123456
```

**✅ 实测结果（7 项体检，全部失败）**

| # | 测试项 | 结果 | 说明 |
|---|---|---|---|
| 1 | 不传 token | ❌ 失败 | 资料没变 |
| 2 | 传错 token（abc123）| ❌ 失败 | 资料没变 |
| 3 | 传**正确** token | ✅ 成功 | 正常功能，说明接口本身可用 |
| 4 | 复用同一个 token | ❌ 失败 | token 用一次就作废 |
| 5 | 刷新页面后 token | ✅ 每次都变 | 每次重新生成 |
| 6 | 类型混淆（`0` / 空 / 数组）| ❌ 全部失败 | 无宽松比较漏洞 |
| 7 | token 是否可预测 | ❌ 约 9×10¹⁷ 种 | 无法暴力猜 |

**★ 结论：这一关的 CSRF 打不通 —— 它是 pikachu 里少有的"防护正确"的关卡。**

```text
攻击前: boy / 18626545453 / chain / vince@pikachu.com
攻击后: boy / 18626545453 / chain / vince@pikachu.com      ← 没变

★ 对比前两关（CSRF get / CSRF post）都能改成功
★ 这一关加了 token 之后，所有攻击方式全部失效
```

二、题目分析

**① 后端代码（和前两关的差别）**

```php
<?php
// token_get_edit.php

if(!check_csrf_login($link)){                    // ① 登录检查（和前两关一样）
    header("location:token_get_login.php");
}

$html1 = '';
if(isset($_GET['submit'])){
    // ★★★ 关键：多了一个 token 校验
    if($_GET['sex']!=null && $_GET['phonenum']!=null && $_GET['add']!=null
       && $_GET['email']!=null
       && $_GET['token']==$_SESSION['token']){

        $getdata = escape($link, $_GET);

        $query = "update member set
                    sex='{$getdata['sex']}',
                    phonenum='{$getdata['phonenum']}',
                    address='{$getdata['add']}',
                    email='{$getdata['email']}'
                  where username='{$_SESSION['csrf']['username']}'";

        $result = execute($link, $query);
        if(mysqli_affected_rows($link)==1 || mysqli_affected_rows($link)==0){
            header("location:token_get.php");
        }
    }
}

// ★★★ 每次请求后都重新生成 token
set_token();
?>
```

**★ 和 CSRF(post) 相比，只多了两个东西**：

```text
① if 条件里加了 $_GET['token'] == $_SESSION['token']
② 页面末尾加了 set_token()
```

**就这两行，攻击就完全失效了。**

**② 表单（token 藏在 hidden input 里）**

```html
<form method="get">
    <p>性别:<input type="text" name="sex"      value="{$sex}"/></p>
    <p>手机:<input type="text" name="phonenum" value="{$phonenum}"/></p>
    <p>住址:<input type="text" name="add"      value="{$add}"/></p>
    <p>邮箱:<input type="text" name="email"    value="{$email}"/></p>

    <!-- ★ 就是这一行 -->
    <input type="hidden" name="token" value="{$_SESSION['token']}" />

    <input type="submit" name="submit" value="submit"/>
</form>
```

**★ 提交时 token 会被带进 URL**（因为表单是 `method="get"`）：

```
token_get_edit.php?sex=xxx&phonenum=xxx&add=xxx&email=xxx&token=598766ade13c48...&submit=submit
```

**③ token 是怎么生成的**

```php
// inc/function.php
function set_token(){
    if(isset($_SESSION['token'])){
       unset($_SESSION['token']);          // 先销毁旧的
    }
    $_SESSION['token'] = str_replace('.', '', uniqid(mt_rand(10000,99999), true));
}
```

**结构拆解**：

```text
598766 ade13c48 4bf3002000512
└─┬──┘ └──┬───┘ └─────┬──────┘
5位随机  8位hex     5位微秒 + 8位随机
mt_rand  时间戳     （uniqid 的 more_entropy）
```

**实测的三个 token 对比**：

```text
598766ade13c484bf3002000512
560006ade13c48c694108594684     ← 中段 ade13c48 相同（同一秒）
307706ade13c49171f166822224     ← 中段变成 ade13c49（过了一秒）
```

**★ 可以观察到时间关联**：

```
uniqid 的第二段是"当前时间的十六进制"
→ 相邻两次生成的 token，这一段会相同或递增
→ 这是 uniqid 的固有特性
```

**★ 但整体仍然不可预测**：

```text
5 位随机前缀（mt_rand 10000~99999）  → 90,000 种
5 位微秒（00000~99999）              → 100,000 种
8 位随机尾串                         → 100,000,000 种

合计 ≈ 9 × 10^17 种可能
→ 即使用 localhost 的低延迟，也不可能在线暴力猜中
```

**④ 为什么攻击者拿不到 token（核心）**

**这是本题最重要的原理。**

```text
┌─────────────────────────────────────────────────────────────┐
│ 攻击者的页面                                                    │
│   http://evil.com/attack.html                                │
│                                                              │
│   想要读取：http://localhost/pikachu/.../token_get_edit.php    │
│           里的 <input name="token" value="598766...">         │
│                                                              │
│   尝试方式：                                                   │
│     ① fetch / XMLHttpRequest                                 │
│        → 被 CORS 拦住，读不到响应内容                           │
│                                                              │
│     ② <iframe src="..."> 然后读 contentDocument              │
│        → 被同源策略拦住（跨域 iframe 无法读 DOM）               │
│                                                              │
│     ③ <script src="..."> 把页面当 JS 加载                     │
│        → HTML 不是合法 JS，解析报错；且拿不到内容                │
│                                                              │
│   ★ 所有读取路径都被浏览器的【同源策略】堵死                     │
└─────────────────────────────────────────────────────────────┘
```

**★ 一句话**：

```
token 之所以有效
    = 因为它藏在"攻击者读不到的地方"
    = 而这块地方由【同源策略】保护
```

**⑤ 为什么"发送请求"能成功，"读取内容"却不行**

**这是很多人搞混的地方**：

```text
跨域请求：
    发出去 ✅（简单请求可以直接发，如 <img>、<form>、<a>）
    读响应 ❌（响应被浏览器拦截，除非服务器给 CORS 头）

★ 所以 CSRF 的本质是：
   "我可以让你的浏览器替我发请求"
   "但我读不到你页面里的任何东西"

★ CSRF token 就是利用了这个不对称：
   把"必须知道才能发请求"的东西，放进"攻击者读不到"的地方
```

三、解题步骤

**说明**：这一关的目标不是"打进"，而是"验证防护是否有效"。

**所以"解题"= 系统性地测试 token 的 7 个可能破绽，并给出结论。**

**第 1 步：登录并观察 token**

```text
① 登录：
   http://localhost/pikachu/vul/csrf/csrftoken/token_get_login.php?username=vince&password=123456&submit=submit

② 点"修改个人信息" → 进入 token_get_edit.php

③ F12 → 【元素】→ Ctrl+F 搜 "token"
   → 看到：
     <input type="hidden" name="token" value="598766ade13c484bf3002000512" />

④ F12 → 【网络】→ 正常提交一次
   → 看到请求 URL 里带着 &token=598766...
```

**★ 三个观察点**：

```text
· token 在 HTML 的 hidden input 里（不在 Cookie）
· 表单是 GET，token 会出现在 URL
· token 长约 27 字符
```

**第 2 步：体检 1 —— 不传 token 会怎样**

**用"编辑并重发"**：

```text
① F12 → 网络 → 找那条 token_get_edit.php 请求
② 右键 → 【编辑并重发】
③ 把 &token=598766... 整段删掉
④ 发送
⑤ 回会员中心 F5 看资料
```

**结果**：

```
资料没变 ❌
```

**★ 说明：服务器强制要求 token，不传就拒绝。**

**第 3 步：体检 2 —— 传错 token**

```text
① 编辑并重发
② 把 token 的值改成 abc123
③ 发送
```

**结果**：

```
资料没变 ❌
```

**第 4 步：体检 3 —— 用正确的 token（对照组）**

```text
① 正常提交一次（用页面里的真 token）
```

**结果**：

```
资料变成你填的值 ✅

★ 这一步很重要：证明接口本身是可用的
★ 排除了"接口坏了"这种干扰因素
```

**第 5 步：体检 4 —— 复用同一个 token**

```text
① 记下刚才用过的 token（假设是 A）
② 编辑并重发 → 改成 sex=reuse_test → 发送（还是用 A）
```

**结果**：

```
资料没变 ❌

★ 原因：set_token() 在每次请求结束时都会执行
        → 你提交成功后，session 里的 token 已经换成 B 了
        → 再用 A 就不匹配
```

**★ 这是"一次性凭证"的正确实现（对比暴力破解第 3 关的反面教材）。**

**第 6 步：体检 5 —— 刷新页面 token 变吗**

```text
① 记下当前 token = A
② F5 刷新页面
③ 再看 token = B
```

**结果**：

```
A ≠ B，每次都变 ✅（正确）

实测三个连续的 token：
    598766ade13c484bf3002000512
    560006ade13c48c694108594684
    307706ade13c49171f166822224
```

**第 7 步：体检 6 —— 类型混淆**

**PHP 的 `==` 是宽松比较，历史上有很多绕过案例**：

```php
"0e123456" == "0e999999"   // true（都被当科学计数法的 0）
"0"        == "0e123"      // true
```

**尝试三种畸形输入**：

```text
① token=0
② token=（空值）
③ token[]=x（数组）
```

**结果**：

```
三种全部失败 ❌

★ 原因：这关的 token 是 27 位、含字母的字符串
        → 不是纯数字，不会触发"数值比较"
        → 数组和字符串比较在 PHP 7 里恒为 false
```

**★ 结论：没有类型混淆漏洞。**

**第 8 步：体检 7 —— token 可预测吗**

**看源码（`inc/function.php`）**：

```php
$_SESSION['token'] = str_replace('.', '', uniqid(mt_rand(10000,99999), true));
```

**分析**：

```text
① mt_rand(10000, 99999)         → 5 位随机，90,000 种
② uniqid 的 hex 时间戳           → 可推算（如果知道服务器时间）
③ uniqid 的微秒部分              → 100,000 种
④ uniqid 的 8 位随机尾串         → 100,000,000 种

要猜中一个 token ≈ 9 × 10^17 次尝试
★ 即使本地测试（0 延迟），也不可能在线暴力
```

**★ 结论：不可预测（虽然有时间关联，但不足以缩减搜索空间到可行范围）。**

**第 9 步：最终结论**

```text
┌──────────────────────────────────────────────────────────┐
│ 7 项体检全部失败                                            │
│                                                          │
│  → CSRF 攻击在这一关【打不通】                              │
│  → 这关的防护是【正确实现】的                               │
│                                                          │
│  ★ 和前两关（CSRF get / post）形成鲜明对比                  │
│  ★ 两行代码的差别：                                        │
│      ① if 条件加 && $_GET['token'] == $_SESSION['token']   │
│      ② 末尾加 set_token()                                  │
└──────────────────────────────────────────────────────────┘
```

四、延伸知识

**① CSRF 三关的完整对比**

| | CSRF(get) | CSRF(post) | **CSRF Token** |
|---|---|---|---|
| **提交方式** | GET | POST | GET |
| **有没有 token** | ❌ | ❌ | ✅ |
| **token 是否一次性** | — | — | ✅ 用后即换 |
| **能不能打通** | ✅（同站）| ✅（同站）| ❌ **打不通** |
| **攻击成本** | 1 行 `<img>` | 6 行 `<form>` + JS | 不可能 |
| **失败原因** | — | — | 同源策略保护 token |

**★ 三关连起来看，才是完整的认知**：

```text
第 1 关：没防护          → 能打
第 2 关：改了方法        → 能打（改 POST 不算防护）
第 3 关：加 token        → 打不通（这才是有效防护）
```

**② 为什么 token 能防住 CSRF（三个不等式）**

```text
① 攻击者能"发请求"  ≠  能"读响应"
   → CSRF 只能借用浏览器发请求，读不到任何响应内容

② 攻击者能"构造参数"  ≠  能"知道 token"
   → token 在受害者的页面里，跨域读不到

③ 攻击者能"打开你的页面"  ≠  能"看到页面的 DOM"
   → 跨域 iframe / fetch 都被同源策略拦住
```

**★ token 的巧妙之处**：

```
把"必须先知道才能发请求"的信息
放进"攻击者读不到的地方"
→ 攻击者永远差这一步
```

**③ 正确实现 CSRF Token 的 6 个要点**

```php
<?php
// ① 随机生成（用密码学安全的随机源，不要用 rand/uniqid）
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));   // 64 位十六进制
}

// ② 和用户绑定（存在 session 里，天然绑定）

// ③ 嵌进表单（用 htmlspecialchars 防 XSS）
?>
<form method="post">
    <input type="hidden" name="csrf_token"
           value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
    ...
</form>
<?php
// ④ 校验（用 hash_equals 防时序攻击，用 === 不用 ==）
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    die("CSRF token invalid");
}

// ⑤ 用完销毁（防重放）
unset($_SESSION['csrf_token']);

// ⑥ 或者按请求生成（每次 AJAX 请求都换一个）
```

**★ 对照本关的实现**：

| 要点 | 本关做到没 | 说明 |
|---|---|---|
| 随机生成 | ⚠️ 用了 `uniqid`（不是密码学安全）| 但配合 mt_rand 前缀，实际够用 |
| 和用户绑定 | ✅ 存在 session | |
| 嵌进表单 | ⚠️ 没做 `htmlspecialchars` | token 是服务端生成，无 XSS 风险 |
| 用 `===` 比较 | ❌ 用了 `==` | 但 token 非纯数字，无法利用 |
| 用完销毁 | ✅ `set_token()` 每次换 | |
| 一次性 | ✅ | |

**★ 所以这关是"基本正确但有小瑕疵"的实现。**

**④ 更现代的方案：SameSite Cookie**

**其实不用 token，光靠 SameSite 就能防住大部分 CSRF**：

```php
<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,        // JS 读不到 cookie（防 XSS 偷 cookie）
    'secure'   => true,        // 只在 HTTPS 传输
    'samesite' => 'Strict',    // ★ 跨站请求不带 cookie
]);
session_start();
?>
```

**★ SameSite 和 Token 的对比**：

| | CSRF Token | SameSite=Strict |
|---|---|---|
| **防护层** | 应用层（代码）| 浏览器层 |
| **要改代码吗** | 要（每个表单）| 一行配置 |
| **是否影响体验** | 不影响 | 从外站点链接过来会掉登录态 |
| **老浏览器支持** | ✅ | ⚠️ 2016 年前的不支持 |
| **推荐** | ✅ 用 | ✅ 用 |

**★ 最佳实践：两个都上**（纵深防御）。

**⑤ 唯一能突破 token 的情况：XSS + CSRF 组合**

```text
步骤：
① 网站有 XSS 漏洞（比如留言板能注入 <script>）
② 攻击者注入的 JS 在受害者浏览器里执行
③ 这段 JS 是"同源"的 → 能读页面里的 token
④ 读取 token → 构造请求 → 攻击成功

★ 但这时候根本原因已经是 XSS，不是 CSRF 了
★ 这就是为什么说："XSS 能击穿几乎所有前端防护"
```

**★ 防御链的启示**：

```text
任何"依赖浏览器隔离"的防护
都会被 XSS 从内部瓦解

→ 所以 XSS 的危害等级通常比 CSRF 更高
→ 所以 CSP（内容安全策略）很重要
```

**⑥ token 设计的三条铁律**

```text
① 不可预测
   → 用 random_bytes / random_int（密码学安全）
   → 不要用 rand() / mt_rand() / uniqid() / 时间戳 / 自增 ID

② 不可复用
   → 用一次就销毁（不管成功失败）
   → 或者加时间戳 + HMAC 签名

③ 不可跨站读取
   → 放在页面里（同源策略保护）
   → 不要放在 URL 里（会被 Referer 泄露、浏览器历史记录）
   → 不要放在 Cookie 里（CSRF 场景下 cookie 会被自动发送，起不到防护作用）
```

**★ 第 ③ 条最容易搞错**：

```
把 token 放 Cookie 里 → 完全无效
    ★ 因为 CSRF 的核心就是"浏览器自动带 cookie"
    ★ 你放在 cookie 里的 token，攻击者的请求也会自动带上
    ★ 必须放在【请求体/URL参数】里，且值来自【页面内容】
```

**⑦ 这一关的教学价值**

```text
安全学习最容易犯的错：
    "只学怎么打，不学怎么防"

    打了 CSRF(get) → "哦，img 就能改资料，好玩"
    打了 CSRF(post) → "哦，表单也能改，好玩"
    打了 CSRF Token → "打不通？这关是不是坏了？"
    
★ 但真正学到东西的，恰恰是第三关：
    · 你验证了什么防护是有效的
    · 你理解了同源策略为什么是关键
    · 以后写代码时你知道该怎么防
```

五、总结

- **本题核心：这一关的 CSRF token 是正确实现的，攻击全部失败。**

- **7 项体检结果**：

```text
① 不传 token        → ❌ 失败
② 传错 token        → ❌ 失败
③ 传正确 token      → ✅ 成功（正常功能）
④ 复用 token        → ❌ 失败（一次性）
⑤ 刷新后 token      → ✅ 变化（每次重新生成）
⑥ 类型混淆（0/空/数组）→ ❌ 失败
⑦ token 可预测吗    → ❌ 9×10^17 种，无法暴力
```

- **和前两关的两行差别**：

```php
// ① if 条件里加 token 校验
&& $_GET['token'] == $_SESSION['token']

// ② 页面末尾重新生成 token
set_token();
```

**★ 就这两行，攻击完全失效。**

- **为什么 token 有效（一句话）**：

```text
token 藏在"攻击者读不到的地方"
而那块地方，由【同源策略】保护

攻击者能让你"发请求"，但读不到"页面内容"
token 就是利用这个不对称
```

- **⭐ 最重要的认知**：

```
┌────────────────────────────────────────────────────────────┐
│  CSRF 的攻击面 = "浏览器自动带 cookie"                        │
│                                                            │
│  防不住的原因：                                             │
│      · 没有 token                                          │
│      · token 可复用                                        │
│      · token 可预测                                        │
│      · token 放在 Cookie 里（无效）                          │
│                                                            │
│  能防住的原因：                                             │
│      · token 随机、一次性、只在页面里                         │
│      · 同源策略让攻击者读不到                                 │
│      · 再加 SameSite=Strict（浏览器层）                       │
└────────────────────────────────────────────────────────────┘
```

- **CSRF 模块进度**：**全部完成 🎉**

```text
✅ CSRF(get)    —— 无 token，<img> 就能打（同站可通）
✅ CSRF(post)   —— 无 token，<form>+JS 能打（同站可通）
✅ CSRF Token   —— 有 token，打不通（本题，防护有效）
```

- **三关连起来的收获**：

```text
第 1 关教你：不设防会怎样
第 2 关教你：改方法不等于防护
第 3 关教你：什么样的防护才是对的

★ 只会打第 1、2 关的人：知道 CSRF 危险
★ 打通第 3 关（验证防护有效）的人：知道怎么防
```

**手工复现要点**：

```text
· 登录：token_get_login.php?username=vince&password=123456&submit=submit
· F12 元素搜 token → 记下值
· 不传 token 提交 → 失败
· 传错 token 提交 → 失败
· 传对 token 提交 → 成功（对照）
· 复用 token 提交 → 失败
· 刷新页面 → token 变了
· 传 token=0 / 空 / 数组 → 全部失败
· 下载源码看 set_token() → 分析可预测性
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  CSRF Token 不是"加个参数"就算防护                            │
│                                                            │
│  三个必须：                                                  │
│      ① 随机（猜不到）                                        │
│      ② 一次性（用不了第二次）                                 │
│      ③ 只在页面里（攻击者读不到）                              │
│                                                            │
│  ★ 三条缺任何一条，防护就破                                   │
│  ★ 这关三条都做到了 → 所以打不通                              │
└────────────────────────────────────────────────────────────┘
```

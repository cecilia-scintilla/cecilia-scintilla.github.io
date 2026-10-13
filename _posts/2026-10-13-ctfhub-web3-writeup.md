---
layout: post
title: CTFHub - Cookie 伪造 Writeup
platform: ctfhub
date: 2026-10-13 20:00:00 +0800
categories: CTF
---

CTFHub - Cookie 伪造 Writeup

一、题目信息

- 平台：CTFHub
- 题型：Web
- 考点：Cookie 的作用、**客户端可任意修改 Cookie**、身份伪造
- flag 格式：`ctfhub{...}`

二、题目分析

**① 题目现象**

打开页面，显示类似这样的提示：

```text
只有 admin 才能看到 flag
```

页面上可能会有个按钮或链接。

**② 核心知识点：Cookie 是存在"你这边"的**

```text
Cookie 是服务器发给浏览器、让浏览器存起来的一小段数据。
之后每次请求，浏览器都会自动把它带上，服务器靠它"认出"你（维持登录状态）。

关键点：Cookie 存在客户端（你的浏览器里），你能随便改！
        很多初学者以为 Cookie 是服务器说了算，其实服务器只是"读取"它 ——
        你改了什么，服务器就看到什么。
```

**③ 破题思路**

服务器发下来的 Cookie 里通常是这样的：

```http
Set-Cookie: admin=0        ← 服务器认为：你不是管理员
```

它靠这个 `admin=0` 判断你的身份。那我们只要：

```http
Cookie: admin=1            ← 改成 1，服务器就以为你是管理员了
```

**就这么简单** —— 服务器"信任"了客户端传来的身份标识，这是典型的**信任客户端数据**漏洞。

三、解题步骤

**方法一：Burp Suite（推荐，你刚学的正好用上）**

```text
① Burp → Proxy → Intercept on
② 用 Burp 内置浏览器打开题目地址
③ 请求被拦下 → 在请求头里找到 Cookie 那一行：
       Cookie: admin=0
④ 把 0 改成 1（或者整行改成 Cookie: admin=1）
⑤ 点 Forward 放行
⑥ 浏览器里就会显示 flag —— 因为服务器认为你是管理员了
⑦ 关掉 Intercept
```

> 更省事的做法（用 Repeater）：
> ```
> ① Intercept 关着，浏览器正常访问一次
> ② Burp → Proxy → HTTP history 里找到那个请求
> ③ 右键 → Send to Repeater（Ctrl+R）
> ④ Repeater 左侧把 Cookie 的 0 改成 1 → 点 Send
> ⑤ 右侧 Response 里就是 flag
> ```

**方法二：浏览器 F12 直接改（最快，不用 Burp）**

```text
① 打开题目页面 → 按 F12 → 切到 "应用程序 / Application" 标签
② 左侧找到 "Cookie" → 展开题目域名
③ 找到 admin 那一项，双击值，把 0 改成 1
④ 回到页面按 F5 刷新 → flag 就出来了
```

四、延伸知识：Cookie 与身份认证

**① Cookie 长什么样**

```http
Set-Cookie: admin=0; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax
             ↑值      ↑路径  ↑有效期       ↑JS不可读  ↑仅HTTPS  ↑跨站限制
```

常见的安全属性：

| 属性 | 作用 | 少了它会怎样 |
|---|---|---|
| `HttpOnly` | 禁止 JS 读取该 Cookie | XSS 能直接偷走你的 Cookie |
| `Secure` | 只在 HTTPS 下发送 | 明文传输，可能被中间人窃取 |
| `SameSite` | 限制跨站携带 | 容易被 CSRF 攻击 |
| `Max-Age` / `Expires` | 过期时间 | 长期有效，被盗后危害更久 |

**② 为什么"改 Cookie 就能伪造身份"是真实漏洞**

```text
CTF 里是故意做成漏洞给你玩，但现实中这类问题真实存在：
  · 把身份信息（role=admin、isAdmin=1）直接存在 Cookie 里，且不加签名
  · 只做 Base64 编码就当"加密"（Base64 是可逆的，不是加密！）
  · 用可预测的 ID（user_id=1001 → 改成 1002 就能看别人的数据）
  · JWT 用了弱密钥或 none 算法，能自己签发 token
```

**③ 正确做法是什么**

```text
· 身份信息放服务端（Session），Cookie 里只放一个随机、不可猜的 Session ID
· 或者用签名机制（如 JWT + 强密钥），客户端改了签名就对不上
· 敏感 Cookie 加上 HttpOnly、Secure、SameSite
```

**④ 顺带分清这几组概念（容易混）**

| 名词 | 存在哪 | 举例 |
|---|---|---|
| **Cookie** | 客户端（浏览器） | `admin=1`、`sessionid=xxx` |
| **Session** | 服务端 | 服务器上存着 `sessionid → {user: admin}` |
| **Token / JWT** | 客户端（但带签名） | `eyJhbGci...`（改了就验签失败） |

记住一句话：**Cookie 是客户端的东西，永远不能无条件信任。**

五、总结

- **本题核心：Cookie 存在客户端，可以任意修改；服务器如果直接信任 Cookie 里的身份信息，就能被伪造。**
- 操作上就一步：**把 `admin=0` 改成 `admin=1`**。三种工具任选（Burp / F12 / curl）。
- 一条实用经验：**做 Web 题时永远先看一眼 Cookie** —— 很多题的突破口就在里面（isAdmin、role、user_id、hash 之类的字段）。
- ⚠️ **关于 flag**：CTFHub 的 flag 是**每个沙盒环境独立生成**的（形如 `ctfhub{一串十六进制}`），而且**环境有过期时间**（几十分钟到几小时）。所以别人的题解里贴的 flag 是**不能用的**，必须用你自己环境里显示的那个。环境过期了就回平台重新「启动环境」，地址会变，重新做一遍即可。

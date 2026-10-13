---
layout: post
title: CTFHub - 基础认证 Writeup（Basic Auth 爆破）
platform: ctfhub
date: 2026-10-14 00:08:00 +0800
categories: CTF
---

CTFHub - 基础认证 Writeup（Basic Auth 爆破）

一、题目信息

- 平台：CTFHub（技能树 → Web → HTTP 协议 → **基础认证**）
- 题型：Web
- 考点：HTTP 基本认证（Basic Authentication）、Base64 编码、字典爆破
- 附件：一个密码字典（常见密码 top100）

** 实测结果（本题已通关）**

```text
受保护的页面 : /flag.html        （注意不是 /flag，那个是 404）
正确凭据     : admin : batman
请求头       : Authorization: Basic YWRtaW46YmF0bWFu
flag        : ctfhub{e096a34d34e568dd4596e06e}

验证方式：带着上面那个请求头请求 /flag.html，返回 200 且响应体就是 flag
```

二、题目分析

**① 题目现象**

打开页面有个按钮（写着 Click 之类），点进去浏览器**弹出登录框**，要求输入用户名和密码。随便输一个 → 拒绝访问。

题目还给了个附件：**一份常见密码字典** —— 这个信号非常明确：**用户名可以猜，密码要爆破**。

**② 先搞懂什么是 HTTP 基本认证（Basic Auth）**

```text
浏览器弹的那个登录框，走的就是 HTTP 基本认证（Basic Authentication）。

工作原理：
    ① 浏览器第一次请求 → 服务器返回 401 Unauthorized + 一个响应头：
           WWW-Authenticate: Basic realm="xxx"
    ② 浏览器弹出登录框，用户输入用户名密码
    ③ 浏览器把「用户名:密码」用 Base64 编码，放进请求头再发一次：
           Authorization: Basic YWRtaW46YWRtaW4=
                                    └─ Base64 解码 → admin:admin

核心问题：Base64 只是【编码】，不是【加密】！
         任何人都能解码还原出明文账号密码。
```

**③ 破题思路**

```text
第一步：随便输个账号密码（比如 aaa / bbb），抓包看响应
        → 响应里通常会提示用户名（比如 "do u konw admin ?"）→ 猜出用户名是 admin
第二步：用户名已知，只剩密码 → 拿题目给的字典爆破
        对字典里每个密码，构造 Authorization: Basic base64("admin:密码") 去请求
        哪个返回 200（而不是 401），就是正确密码
第三步：用爆破出的密码登录 → 得到 flag
```

三、解题步骤

**方法一：Burp Suite Intruder 爆破（官方推荐）**

```text
① 挂 Burp 代理，浏览器打开题目，随便输账号密码（比如 admin / admin）
② 在 Proxy → HTTP history 里找到那个请求，看请求头：
       Authorization: Basic YWRtaW46YWRtaW4=
   顺便看响应 → 会得到用户名提示（比如 "do u konw admin ?"）

③ 右键那个请求 → Send to Intruder（发送到入侵者）

④ 切到 Intruder → Positions 标签：
   - 点 "Clear §" 清掉自动标记
   - 手动选中 Authorization: Basic 后面那串 Base64 内容
   - 点 "Add §" 把它标记为 payload 位置：
         Authorization: Basic §YWRtaW46YWRtaW4=§

⑤ 切到 Payloads 标签：
   - Payload type 选 Simple list
   - Payload Options → Load → 加载题目附件的密码字典

⑥ ★ 关键：Payload processing → Add：
   - 先加 "Add prefix"，填  admin:
   - 再加 "Encode"，选 Base64-encode
     （这样每个密码都会自动变成 base64("admin:密码")）

⑦ 切到 Settings → 找 Payload encoding（或请求头编码）：
   - ★ 取消勾选 "URL-encode these characters"
   - 否则 Base64 里的 = 会被编码成 %3d，爆破一辈子也出不来！

⑧ 点 Start attack
   - 结果按 Status 或 Length 排序
   - 找到状态码 200（其它都是 401）的那一行 → 就是正确密码
   - 看它的 Response，里面有 flag
```

> ⚠️ **第 ⑦ 步是这道题最大的坑**。Base64 结尾常有 `=`，Burp 默认会把它 URL 编码成 `%3d`，导致解出来的凭据是错的，怎么爆都爆不出来。

**方法二：用 Python 脚本爆破（更快，不用配 Burp）**

我写了个脚本（见文末工具），一条命令搞定：

```powershell
python basic_auth_brute.py "http://challenge-xxx.sandbox.ctfhub.com:10800/flag" 字典.txt
```

它会：
1. 先不带认证请求一次，看基线响应（通常是 401）
2. 对字典里每个密码，构造 `Basic base64("admin:密码")` 发请求
3. 自动识别状态码/长度异常的那一条，并从中提取 flag


四、延伸知识：HTTP 基本认证的安全问题

**① 为什么现在几乎没人用 Basic Auth**

```text
· 凭据就是 base64(用户名:密码)，等于【明文传输】—— 抓包就能看到
· 没有登录失败次数限制（本题就是靠这个爆破成功的）
· 没有登出机制（浏览器关了才失效）
· 每个请求都要带凭据，暴露面大

所以现在都用：
    · 表单登录 + 服务端 Session
    · Token（JWT / OAuth）
    · 至少也要套 HTTPS（但 HTTPS 只保护传输，服务器端仍是明文比对）
```

**② 但它在这些地方还在用**

```text
· 路由器的管理后台（192.168.1.1 弹的那个框）
· 内网设备、摄像头的 Web 管理界面
· API 的基础鉴权（有些老 API 还在用）
· CI/CD、Jenkins、Git 的 HTTP 方式拉取
→ 这些都是渗透测试的常见突破口：默认密码 + 无锁定 = 直接爆破
```

**③ 相关的几个知识点**

| 概念 | 说明 |
|---|---|
| `WWW-Authenticate` | 服务器要求认证时返回的响应头（带 `realm`） |
| `Authorization: Basic xxx` | 客户端提交凭据的请求头 |
| **Base64 ≠ 加密** | 它只是编码，可逆，没有任何保密性 |
| 401 vs 403 | 401 = 没认证（该登录）；403 = 认证了但没权限 |
| `Digest` 认证 | Basic 的改进版（不明文传密码），但现在也基本不用了 |

**④ 顺带记住这个"爆破思路"的通用套路**

```text
凡是遇到"已知用户名、需要密码"的题，都可以用同一套思路：
    ① 找到一个"成功 vs 失败"响应有差异的请求
    ② 把密码位置标记为可变（Burp 的 §，或脚本里的循环）
    ③ 加载字典，批量发送
    ④ 按【状态码 / 响应长度 / 响应内容】的差异找出成功那一条
```

五、总结

- **本题核心：HTTP 基本认证把凭据用 Base64 放在请求头里 —— Base64 是可逆的编码，不是加密；再加上没有失败锁定，所以能爆破。**
- 记住 Authorization 头的格式：

```http
Authorization: Basic base64(用户名:密码)
```

- **最大的坑**：Burp 的 Intruder 默认会 URL 编码 payload，会把 Base64 的 `=` 变成 `%3d`，**必须取消**，否则永远爆不出来。


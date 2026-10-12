[2026-10-06-ctfhub-http-method-writeup.md](https://github.com/user-attachments/files/33327685/2026-10-06-ctfhub-http-method-writeup.md)
---
layout: post
title: CTFHub - HTTP Method（请求方式）Writeup
date: 2026-10-12 20:00:00 +0800
categories: CTF
platform: ctfhub
---

CTFHub - HTTP Method（请求方式）Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → HTTP 协议 → **请求方式**）
- 题型：Web
- 考点：HTTP 请求方法（Request Method）、自定义请求方法、405 Method Not Allowed
- 
二、题目分析

- 打开题目地址，页面显示三行提示：

```text
HTTP Method is GET
Use CTF**B Method, I will give you flag.
Hint: If you got [HTTP Method Not Allowed] Error, you should request index.php.
```

逐句解读：

| 页面内容 | 含义 |
|---|---|
| `HTTP Method is GET` | 服务器识别出你当前用的是 **GET** 方法（它会把你用的方法回显出来） |
| `Use CTF**B Method, I will give you flag.` | 要用 **`CTFHUB`** 这个方法请求（`**` 是打码，CTF\*\*B = CTFHub） |
| `Hint: If you got [HTTP Method Not Allowed] Error, you should request index.php.` | 如果报 **405** 错误，说明请求的路径不对，要写全 `index.php` |

- 这题的关键知识点：**HTTP 请求方法不限于 GET / POST**。

```text
按 HTTP 规范，请求方法是"一个记号（token）"，理论上可以是任意字符串。
服务器可以自己定义并识别自定义方法 —— 本题的服务器就只认 CTFHUB。
浏览器地址栏只会发 GET，所以要改方法必须用工具（curl / Burp / 脚本）。
```

三、解题步骤

**先看原始请求长什么样**

HTTP 请求的第一行就是"方法 + 路径 + 版本"：

```http
GET /index.php HTTP/1.1          <- 普通浏览器请求（方法 GET）
Host: challenge-xxx.sandbox.ctfhub.com:10800
User-Agent: Mozilla/5.0
```

要过关，只要把第一行的 `GET` 换成 `CTFHUB` 就行：

```http
CTFHUB /index.php HTTP/1.1       <- ★ 改成自定义方法
Host: challenge-xxx.sandbox.ctfhub.com:10800
User-Agent: Mozilla/5.0
```

**方法一：curl（最省事，Windows 自带）**

```powershell
curl.exe -X CTFHUB "http://challenge-xxx.sandbox.ctfhub.com:10800/index.php"
```

- `-X` 用来**指定请求方法**，后面跟方法名
- 服务器会返回：

```html
good job! ctfhub{xxxxxxxxxxxxxxxxxxxxxxxx}
```

**方法二：Burp Suite（最直观）**

```text
① 浏览器设置 Burp 为代理，打开题目页面（或在 Burp 里点开内置浏览器）
② 在 Proxy → HTTP history 里找到这个请求，右键 → Send to Repeater
③ 在 Repeater 里把第一行的 GET 改成 CTFHUB：
       GET /index.php HTTP/1.1     →     CTFHUB /index.php HTTP/1.1
④ 点 Send，右侧 Response 里就能看到 flag
```

**实测对比（同一个地址，四种方法）**

| 请求方法 | 服务器响应 |
|---|---|
| `GET` | `HTTP Method is GET` + 让你用 CTF**B |
| `POST` | `HTTP Method is POST` + 让你用 CTF**B** |
| `PUT` | `HTTP Method is PUT` + 让你用 CTF**B** |
| **`CTFHUB`** | ✅ `good job! ctfhub{...}` |

可以看到**服务器会把你的请求方法原样回显**，唯独 `CTFHUB` 能拿到 flag。

四、延伸知识：HTTP 请求方法有哪些

**① 标准方法（RFC 定义）**

| 方法 | 作用 | 常见场景 |
|---|---|---|
| `GET` | 获取资源 | 打开网页（浏览器默认） |
| `POST` | 提交数据 | 表单提交、登录、上传 |
| `PUT` | 上传/替换资源 | RESTful API 更新 |
| `DELETE` | 删除资源 | RESTful API 删除 |
| `HEAD` | 只要响应头，不要正文 | 检查资源是否存在 |
| `OPTIONS` | 询问服务器支持哪些方法 | 跨域预检（CORS） |
| `PATCH` | 局部更新资源 | API 部分修改 |
| `TRACE` / `CONNECT` | 诊断 / 建立隧道 | 一般不开放，属于安全隐患 |

**② 自定义方法**

除标准方法外，服务器**可以识别任意自定义方法**。在 CTF 里这是常见考点（本题），在真实渗透里也有价值 —— 比如某些 WAF 只检查 GET/POST，用自定义方法可能绕过；某些接口只对特定方法做了鉴权。

**③ 405 Method Not Allowed 是什么**

```text
405 = 服务器认识这个路径，但不支持你用的这个请求方法。
```

所以本题提示里那句"If you got 405, you should request index.php"的意思是：**不是方法错了，而是路径错了** —— 直接请求根目录 `/` 时，服务器可能没有把方法判断逻辑挂上去，返回 405；请求完整的 `/index.php` 才对。

**④ 相关的其它状态码（顺带记住）**

```text
200 OK                    正常
301 / 302                 重定向
400 Bad Request           请求格式有问题
401 Unauthorized          未认证
403 Forbidden             认证了但没权限
404 Not Found             路径不存在
405 Method Not Allowed    方法不被允许（本题的排查点）
500 Internal Server Error 服务器内部错误
```

五、总结

- **本题核心：HTTP 请求方法可以自定义，且必须用工具（curl / Burp / 脚本）才能改。** 浏览器地址栏只会发 GET，所以做这类题必须离开浏览器。
- 记住改方法的最快方式：

```powershell
curl.exe -X 方法名 "URL"      # -X 指定请求方法
```

- 报 **405** 时的排查思路：**先确认方法和路径哪个错了** —— 换个方法试（GET/POST），或者把路径写全（指向具体脚本文件而不是目录）。
- CTFHub 这类平台的特点是**一道题一个知识点**，很适合系统地刷。这题属于"HTTP 协议"系列，同系列还有：请求方式（本题）、302 跳转、Cookie 伪造、基础认证（Authorization）、UA 伪造、Referer 伪造、XFF 伪造等 —— 都是围绕"HTTP 请求/响应的各个字段可以做手脚"设计的。

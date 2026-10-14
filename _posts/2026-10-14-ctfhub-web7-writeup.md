---
layout: post
title: CTFHub - PHPINFO Writeup（信息泄露）
platform: ctfhub
date: 2026-10-14 20:00:00 +0800
categories: CTF
---

CTFHub - PHPINFO Writeup（信息泄露）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → **PHPINFO**）
- 题型：Web
- 考点：`phpinfo()` 信息泄露、页面搜索

二、题目分析

**① 题目现象**

打开环境，页面显示类似：

```text
phpinfo
点击查看
```

点进去之后，是一个**信息量巨大的页面** —— 这就是 `phpinfo()` 的输出：

```text
PHP Version 7.4.33
System  Linux xxx
Configuration
  allow_url_fopen  On
  display_errors   On
  ...
Environment
  USER      www-data
  HOME      /var/www
  ...
PHP Variables
HTTP Headers Information
```

**几百上千行配置**，一眼看过去全是技术参数。

**② 这题在考什么**

```text
phpinfo() 是 PHP 的一个函数，作用是【输出 PHP 运行环境的全部信息】：
    · PHP 版本、编译参数
    · 所有配置项（php.ini 的内容）
    · 环境变量（Environment）
    · 请求头（HTTP_* 变量）
    · 已加载的模块、扩展
    · 文件路径、服务器信息

开发时用它来排查环境问题很方便 —— 但如果【生产环境里留着它】，
就等于把服务器的底牌全部摊开给攻击者看。

★ 这题就是把 flag 塞进了这个页面里（藏在某个配置项的值里）。
```

**③ 破题思路**

```text
页面太长，人眼翻会很累 —— 但 flag 就在里面，所以【搜】就行了。

最简单：浏览器打开页面 → Ctrl+F → 搜 flag
```

三、解题步骤

**方法一：浏览器 Ctrl+F（30 秒）**

```text
① 打开题目环境 → 点进 phpinfo 页面
② 按 Ctrl+F（浏览器查找）
③ 输入 flag  回车
④ 页面上会高亮显示命中处 —— flag 就在那儿
⑤ 或者搜 ctfhub（本题 flag 前缀）
```

> 💡 **小技巧**：如果搜 `flag` 找不到，试试搜：
> ```text
> ctfhub        （平台前缀）
> CTF           （有些环境变量名里带 CTF）
> {             （带大括号的内容）
> ```
> 有些题会把 flag 当成"环境变量的值"，变量名可能是 `FLAG`、`CTFHUB_FLAG`、`GZCTF_FLAG` 等。

**方法二：用脚本自动搜（推荐，还能告诉你 flag 藏在哪）**

```powershell
python phpinfo_find.py "http://challenge-xxx.sandbox.ctfhub.com:10800/phpinfo.php"
```

**实测效果**（我用模拟的同款靶场验证）：

```text
目标: http://127.0.0.1:8890/
状态码: 200   页面大小: 2274 字符
✔ 确认是 phpinfo 页面   PHP 版本: 7.4.33

① 搜索 flag 形式的内容
  ★ 命中: ctfhub{demo_phpinfo_flag_123456}
    上下文: ...HOME /var/www PATH /usr/local/sbin:... LANG C.UTF-8
            CTFHUB_FLAG ctfhub{demo_phpinfo_flag_123456} PHP Variables...

④ 提示：phpinfo 页面上常藏 flag 的位置
  · 有这个段落: Environment
  · 有这个段落: PHP Variables
  · 有这个段落: HTTP Headers Information
  · 有这个段落: Configuration
```

它会打印**命中内容的上下文**，这样你能看出 flag 是**哪个配置项的值**。

**方法三：curl + findstr（命令行一行）**

```powershell
curl.exe -s "http://challenge-xxx:10800/phpinfo.php" | findstr /i "flag"
```

四、实用技能：平时怎么检查一个网站有没有暴露 phpinfo

这是信息收集的基本功。有四种由浅到深的方法：

**① 手工猜（最快，试几个最常见的名字）**

在浏览器地址栏挨个试：

```text
https://目标站/phpinfo.php
https://目标站/info.php
https://目标站/test.php
https://目标站/phpinfo
https://目标站/i.php
```

看到那个"配置表格"页面就成了。**试 5 个只要 10 秒**，很多站就是因为这种低级疏忽中招。

**② 用我写的小工具（自动试 37 个常见名字）**

```powershell
python check_phpinfo.py https://example.com
```

**或者双击 `check-phpinfo.bat`** → 粘贴网址 → 回车。

它会挨个试这些路径，并且**用两道关判断是不是真的 phpinfo**：

```text
① 状态码 200（页面存在）
② 内容里有 phpinfo 特征（"PHP Credits"、"Configuration File (php.ini) Path"、
   具体配置项如 allow_url_fopen 等），且不是"文档页"
```

**实测效果**：

```text
★★★ 发现 phpinfo 页面！ http://127.0.0.1:8890/phpinfo.php
     命中特征: allow_url_fopen
     PHP 版本: 7.4.33
     ★ 这是【高危】发现：服务器配置信息全部暴露
```

> ⚠️ **顺便记一个踩坑经验（关于误报）**：
> 我第一版工具用 `phpinfo()` 当特征，结果拿 php.net 一试，
> 它把官方的**函数手册页**（讲 phpinfo 怎么用的教程页）全报成漏洞了。
> **教训**：写检测工具时，特征词要选"只有目标才有"的 ——
> `phpinfo` 这个词在文档、教程、博客里到处都是，
> 而 `PHP Credits`、`Configuration File (php.ini) Path` 这种才只在真实输出里出现。

**③ 用目录爆破工具扫大字典（最全面）**

```powershell
.\run-dirsearch.bat -u https://example.com/ -e php,html,txt,bak -t 5 --timeout=8 -q
```

字典里像 `phpinfo`、`info`、`test`、`debug`、`phpinfo.php.bak` 这些词都带着，扫一遍就知道有没有留东西。

**用 dirsearch 和上面小工具的区别**：

| | check_phpinfo.py | dirsearch |
|---|---|---|
| 速度 | 几秒（只试 37 个名字） | 几分钟（试几千个） |
| 覆盖面 | 只查 phpinfo/调试页 | 所有常见路径 |
| 判定 | 会判断"是不是真 phpinfo" | 只报状态码，需人工看 |
| 适合 | 专项快速检查 | 全面信息收集 |

**④ 在线空间测绘引擎（查别人扫过的数据）**

```text
FOFA      https://fofa.info      语法: body="phpinfo()" && country="CN"
Shodan    https://shodan.io      语法: http.title:"phpinfo()"
ZoomEye   https://www.zoomeye.org
Quake     https://quake.360.net
```

这些引擎**已经扫描过全网**，你搜语法就能直接列出"暴露了 phpinfo 的站点"。
真实渗透测试里，这是**最快找到攻击目标**的方式（但要注意：**只能查你自己的资产，扫别人的站是违法的**）。

**⑤ 顺手再记几个常一起暴露的"调试残留"**

```text
/phpinfo.php         PHP 环境信息
/.env                环境变量文件（★ 常有数据库密码、API 密钥 —— 比 phpinfo 还致命）
/composer.json       依赖清单（能推出用了哪些框架/库）
/.git/config         版本控制泄露（能拿到全部源码）
/server-status       Apache 服务器状态（能看到正在处理的请求、客户端 IP）
/test.php /debug.php 开发者留下的测试页
```

五、延伸知识：phpinfo 泄露了什么（为什么它是漏洞）

**① 一个 phpinfo 页面能告诉攻击者什么**

| 信息 | 危害 |
|---|---|
| **PHP 版本** | 直接查这个版本有没有已知 CVE，精准打击 |
| **disable_functions** | 知道哪些危险函数被禁用 → 找别的绕过路径 |
| **allow_url_fopen / allow_url_include** | 是否允许远程包含 → 判断能不能打远程文件包含（RFI） |
| **open_basedir** | 知道网站根目录限制 → 规划路径穿越的边界 |
| **upload_max_filesize / post_max_size** | 知道上传限制 → 决定 webshell 能多大 |
| **环境变量（Environment）** | ★ 常有部署时注入的密钥、数据库密码、**flag** |
| **文件路径 / DOCUMENT_ROOT** | 知道服务器目录结构，方便路径穿越 |
| **已加载扩展** | 有 Redis/MySQL 扩展 → 可以打 SSRF 或反序列化 |
| **`_SERVER` 变量** | 服务器 IP、端口、协议 |
| **HTTP_* 变量** | 反映请求头，能判断有没有 CDN/WAF |

**② 为什么 flag 常藏在这里**

```text
CTF 出题时，往容器里注入 flag 最方便的方式就是【设个环境变量】：
    docker run -e CTFHUB_FLAG=ctfhub{xxx} ...

而 phpinfo() 会把所有环境变量原样打出来 →
所以 flag 就"顺带"泄露了。

（同样的道理：真实环境里 DATABASE_URL、AWS_SECRET_KEY 这类环境变量
  如果被 phpinfo 打印出来，就是严重的信息泄露）
```

**③ 正确做法**

```text
· 生产环境绝不部署 phpinfo.php（开发完就删）
· 用 phpinfo() 排查完问题立刻移除
· 或者限制访问：只在 /admin 后台、只允许内网 IP、加认证
· 环境变量里的敏感值要用专门的密钥管理服务，不要图省事塞 env
```

**④ 找 phpinfo 的常见路径（打真实站点时的信息收集）**

```text
/phpinfo.php     /info.php      /test.php
/php.php         /i.php         /pi.php
/phpinfo/        /debug.php     /1.php
（这些也是"目录爆破"时字典里必带的词）
```

六、总结

- **本题核心：`phpinfo()` 页面输出海量服务器信息，flag 就藏在里面 —— 用 `Ctrl+F` 搜一下就出来了。**
- 记住这个"搜索优先"的思路：

```text
遇到"页面很长、信息很多"的题，第一反应不是一行行读，而是：
    ① Ctrl+F 搜 flag / ctfhub / {
    ② 搜不到就看看有哪些【段落标题】（Environment、PHP Variables…）
    ③ 重点关注"值"里带特殊格式的内容（看起来像 flag 的字符串）
```

- 一条实用经验：**phpinfo 是真实渗透测试中很有价值的信息泄露点** —— 它不只是"看到 flag"这么简单，而是能让你摸清整个 PHP 环境，为后续攻击做决策。
- CTFHub「信息泄露」系列进度：

```

**配套文件**（都在工作区）：

```text
phpinfo_find.py       自动搜 phpinfo 页面里的 flag（含上下文定位）
demo_phpinfo.py       本地模拟靶场（监听 8890，可自己练手）
```

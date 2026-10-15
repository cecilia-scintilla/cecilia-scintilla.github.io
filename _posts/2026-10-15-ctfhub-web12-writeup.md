---
layout: post
title: CTFHub - Git 泄露 Stash Writeup
platform: ctfhub
date: 2026-10-15 14:32:00 +0800
categories: CTF
---

CTFHub - Git 泄露 Stash Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → Git 泄露 → **Stash**）
- 题型：Web
- 考点：**`.git` 泄露 + `git stash` 暂存内容恢复**
- 题目提示原文：

```text
当前大量开发人员使用 git 进行版本控制，对站点自动部署。
如果配置不当，可能会将 .git 文件夹直接部署到线上环境。
这就引起了 git 泄露漏洞。
请尝试使用 BugScanTeam 的 GitHack 完成本题
```

```text
首页提示     : CTFHub .git leakage —— "Where is flag?"
探测结果     : /.git/HEAD          → 200
              /.git/refs/stash    → 200  ← ★ 这就是本题的入口（Stash 题的特征）
              /.git/logs/HEAD     → 200

① 读 /.git/refs/stash：
      dd62518c1d753a637401b727e78cfd55b1fc3a17

② 读 /.git/logs/refs/stash：
      00000000 → dd62518c   「WIP on master: ce9cf7a add flag」

③ 解析 stash 对象：
      类型: commit
      tree: fc6a5f791a530720623a8ae7e9596f0b21d075fb
      说明: WIP on master: ce9cf7a add flag

④ 遍历 tree，发现三个文件：
      159042095323352.txt      ← ★ flag 在这个文件里
      50x.html
      index.html

⑤ 取文件内容：
      ctfhub{4895f1a33f191ca5b104a891}

★ 验证对比（很能说明问题）:
      直接访问 /159042095323352.txt  →  404（服务器上根本没这个文件！）
      从 .git 对象里取                →  ctfhub{4895f1a33f191ca5b104a891}
      ↑ 说明 stash 的内容【从未被提交】，网站目录里不存在，
        只能从 .git 的对象库里挖出来 —— 这就是 Stash 题的特点

flag         : ctfhub{4895f1a33f191ca5b104a891}
```

二、题目分析

**① 先搞懂 `git stash` 是什么**

```text
场景：你正在写代码，改了三个文件，改到一半，突然要切去修另一个 bug。
     但不想把"改到一半的东西"提交上去（因为没写完）。

这时就可以用：
    git stash            ← "把我现在没提交的改动【临时存起来】"
    （工作区被还原成干净状态）

修完别的，想继续：
    git stash pop        ← "把刚才存起来的东西【拿回来】"

★ 关键点：stash 存的内容【也在 .git 目录里】！
     存在哪：.git/refs/stash      （最新一次 stash 指向哪个提交）
             .git/logs/refs/stash （stash 栈的历史）
             .git/objects/...     （实际的 stash 对象）
```

**② 为什么 stash 泄露也是信息泄露**

```text
开发者心态：
    "我又没 git commit，只是 stash 暂存了一下 —— 应该不会被看到吧？"

真相：
    ★ stash 本质上就是【特殊的 commit 对象】，落在 .git/objects/ 里
    ★ 只要 .git 目录泄露，stash 里的内容就能被完整恢复出来

    而且 stash 里往往藏着【最敏感的东西】——
    因为它是"还没准备好提交"的中间状态：
        · 调试用的测试账号密码
        · 临时打开的调试开关
        · 写到一半、还没删的 flag / 密钥
```

**③ 破题思路**

```text
① 确认 /.git/ 可访问
② ★ 读 /.git/refs/stash —— 拿到最新 stash 的 SHA（本题的入口）
③ 按 SHA 去 .git/objects/ 下载那个对象，解压 → 是个 commit
④ commit 里的 tree 就是【当时工作区的完整快照】
⑤ 遍历这个 tree，看里面的文件内容 → flag 就在里面
```

三、解题步骤

**方法一：用 GitHack（题目推荐，需要 Python 2）**

```bash
git clone https://github.com/BugScanTeam/GitHack.git
cd GitHack
python2 GitHack.py http://challenge-xxx:10800/.git/

# 它会恢复出完整仓库，然后：
cd challenge-xxx_10800/
git stash list          # 看有哪些 stash
git stash pop           # ★ 把 stash 的内容弹出来（flag 就在出来的文件里）
```

> 如果 `git stash show` 没显示东西，用下面的方法二。

**方法二：手工挖（不需要装工具）**

**第 1 步：确认 `.git` 泄露**

浏览器访问：
```text
http://challenge-xxx:10800/.git/HEAD
```
看到 `ref: refs/heads/master` → 泄露了。

**第 2 步：★ 读 `.git/refs/stash`（本题的关键入口）**

浏览器访问：
```text
http://challenge-xxx:10800/.git/refs/stash
```

**返回的是一串 40 位 SHA**，比如：
```text
e71ada5b3c8f2e1d9a4b6c7d8e9f0a1b2c3d4e5f
```

**这就是最新 stash 的 SHA** —— 记住它（官方的解法二就是要你 `git diff e71ada`）。

**第 3 步：看 stash 的历史（可选，但建议看）**

```text
http://challenge-xxx:10800/.git/logs/refs/stash
```

能看到每次 stash 的操作记录：
```text
0000...0000  e71ada5b...  CTFHub <...>  <时间>   stash: WIP on master: xxxxxxx init
                                                          └──── 说明文字 ────┘
```

> 💡 `WIP on master` 是 git 自动生成的说明（WIP = Work In Progress，进行中的工作）。

**第 4 步：按 SHA 下载 stash 对象**

```text
http://challenge-xxx:10800/.git/objects/e7/1ada5b3c8f2e1d9a4b6c7d8e9f0a1b2c3d4e5f
                                                      └┬┘└──────────┬──────────┘
                                                   前2位        后38位
```

**浏览器会显示乱码**（zlib 压缩的），**这是正常的** —— 需要用工具解压。

**第 5 步：解压后继续顺藤摸瓜**

```
stash 对象（commit）
    ↓ 里面写着 tree <目录树SHA>
目录树（tree）
    ↓ 列出当时工作区里的所有文件 + 每个文件的 SHA
文件（blob）
    ↓ 解压 = 文件内容 → ★ flag 在这里
```

**这条链和上一题（Log）完全一样**，只是起点从 `.git/logs/HEAD` 换成了 `.git/refs/stash`。

**方法三：用我写的工具（纯 Python，双击就行）**

```text
双击 dump-git-stash.bat
→ 粘贴题目根地址（结尾是 :10800 那一串，不要带 /.git/...）
→ 回车
```

**实测效果**（我用 Python 构造了一个真实的 stash 仓库来验证）：

```text
① 读 .git/refs/stash
   ✔ 服务器返回: 112df1ccb021962b39642db7405d5028807c38e0
      ↑ 这就是最新 stash 的 SHA

② 读 .git/logs/refs/stash
   00000000 → 112df1cc   「stash: WIP on master: 2fb2328 init」

③ 解析 stash 的内容
   stash 提交: 112df1ccb021962b39642db7405d5028807c38e0
   对象类型: commit
   tree: 27bf953ea9e0f161646998201b1e9f8297d27921
   说明: WIP on master: 2fb2328 init

   ── stash 的工作区快照 ──
         index.html      c9da3a0d60
         new_file.txt    1ba20df968
         ★★★ flag: ctfhub{demo_stash_flag_xyz789}
              文件: index.html

★ 找到 flag：
   ctfhub{demo_stash_flag_xyz789}
      （来自 stash 的工作区快照 的 index.html）
```

四、延伸知识

**① Git 泄露三兄弟的区别（CTFHub 就是这么分的）**

| 子题 | 敏感内容在哪 | 入口文件 | 对应命令 |
|---|---|---|---|
| **Log** | 历史提交里的文件 | `.git/logs/HEAD` | `git log` / `git show` |
| **Stash** | **被 stash 暂存的改动** | **`.git/refs/stash`** | `git stash list` / `git stash pop` |
| **Index** | 暂存区（add 了但没 commit） | `.git/index` | `git diff --cached` |

**② stash 的对象结构（为什么它是"特殊 commit"）**

```text
一次 git stash 实际会创建【两个或三个 commit 对象】：

    stash@{0}  ← 这个 commit 有【两个 parent】：
        parent 1: 当前分支的 HEAD（你 stash 时所在的那个提交）
        parent 2: 暂存区（index）的内容

    它的 tree 记录的是【工作区里所有文件的当前状态】
    （包括你改了还没 add 的、和已经 add 了的）

所以解析 stash 时要看：
    · 主 tree        → 工作区快照
    · 第 2 个 parent 的 tree → 暂存区快照
```

**③ Git 内部还有哪些"藏东西"的地方（信息收集清单）**

```text
.git/refs/stash             stash 栈（本题）
.git/logs/HEAD              所有操作日志（Log 题）
.git/logs/refs/stash        stash 操作历史
.git/index                  暂存区（Index 题）
.git/ORIG_HEAD              危险操作前的备份指针（merge/rebase 前的状态）
.git/FETCH_HEAD             最后一次 fetch 的信息
.git/objects/               所有对象（含被删除的）
.git/packed-refs            打包的引用
.git/config                 仓库配置（可能有远程地址、用户名）
```

**④ 实战里最有价值的一招：找"悬空对象"**

```bash
git fsck --lost-found
```

它会列出所有**没有任何引用指向的对象**（dangling blob / commit）——
那些往往是**被删除、被 reset 掉、被 stash 后丢弃**的内容。
这是挖 Git 泄露的"最后一招"，能翻出很多常规方法看不到的东西。

**⑤ 防护**

```text
· 部署时不要把 .git 传到 web 目录（用 git archive 导出干净副本）
· 服务器拒绝访问：
      Nginx:  location ~ /\.git { deny all; }
· ★ 别把敏感信息放进 stash 就不管了 —— 它和 commit 一样会留在仓库里
      （很多人以为"没提交就安全"，这是误区）
```

五、总结

- **本题核心：`.git` 泄露 → 读 `.git/refs/stash` 拿到 stash 的 SHA → 顺着对象链挖出被暂存的改动 → flag 在改动里。**
- 和上一题（Log）的对比，记住这个"起点差异"：

```text
Log 题    → 起点是 .git/logs/HEAD     看【提交历史】
Stash 题  → 起点是 .git/refs/stash    看【暂存的内容】（本题）
Index 题  → 起点是 .git/index         看【暂存区】
三者的"顺藤摸瓜"过程完全一样：commit → tree → blob
```

- 一个重要的认知：

```text
★ "没提交" ≠ "不会被看到"
  git stash 的内容一样落在 .git/objects/ 里，
  只要 .git 泄露，暂存的东西全都能被恢复出来。
```


**配套文件**（都在工作区）：

```text
git_stash_dump.py     纯 Python 的 stash 挖掘工具（读 refs/stash + 解析对象链 + 搜 flag）
dump-git-stash.bat    双击启动器
git_leak_dump.py      上一个工具（挖提交历史，Log 题用）
git_leak_step_by_step.py  教学版（一步一步讲解，每步告诉你在浏览器访问什么）
```

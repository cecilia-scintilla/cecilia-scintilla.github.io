---
layout: post
title: Pikachu - 敏感信息泄露 Writeup（注释、枚举、Cookie）
platform: pikachu
date: 2026-10-29 20:43:00 +0800
categories: CTF
---

Pikachu - 敏感信息泄露 Writeup（注释、枚举、Cookie）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：敏感信息泄露 → IcanseeyourABC
- 地址：`http://localhost/pikachu/vul/infoleak/findabc.php`
- 题型：Web
- 考点：**敏感信息泄露**、用户枚举、Cookie 安全

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
模块目录：D:\phpstudy_pro\WWW\pikachu\vul\infoleak\
```

**页面形态**：

```text
Please Enter Your Information

[Username]
[Password]
[Login]
```

**作者提示**：

```html
data-content="找找看,很多地方都漏点了..."
```

**★ "很多地方都漏点了" —— 确实不止一处。**

**✅ 实测结果（四种泄露点）**

| # | 泄露点 | 内容 | 危害 |
|---|---|---|---|
| 1 | **HTML 注释** | `<!-- 测试账号:lili/123456-->` | **直接拿到可用账号** ✅ |
| 2 | **用户枚举** | `lili`+错密码 → "密码错误"<br>`nobody`+错密码 → "账号错误" | 能枚举用户名 ✅ |
| 3 | **Cookie 明文** | `abc[uname]=lili`<br>`abc[pw]=e10adc3949ba59abbe56e057f20f883e` | 暴露密码哈希 ✅ |
| 4 | **SQL 报错** | `execute()` 直接打印 `mysqli_error()` | 泄露数据库结构（前几关已见）|

**★ 第 3 行的哈希**：

```
e10adc3949ba59abbe56e057f20f883e  =  md5('123456')
★ 无盐 md5 + 弱口令 → 秒破
```

**★ 登录后的页面（`abc.php`）**：

```
退出登陆

那一天我二十一岁，在我一生的黄金时代
我有好多奢望。我想爱，想吃，还想在一瞬间变成天上半明半暗的云
后来我才知道，生活就是个缓慢受锤的过程，人一天天老下去，奢望也一天天消失，
最后变得像挨了锤的牛一样
可是我过二十一岁生日时没有预见到这一点。我觉得自己会永远生猛下去，什么也锤不了我
                                                            -----王小波《黄金时代》
```

**★ 所以本关的"目标"不是"拿到什么秘密"，而是"证明你能登录进去"。**

二、题目分析

**① 泄露点 1：HTML 注释里写测试账号（最经典）**

**★ `findabc.php` 第 109 行**：

```html
        </div><!-- 测试账号:lili/123456-->

    </div><!-- /.widget-body -->
```

**★ 这是开发时留下的"方便自己测试"的注释**：

```html
<!-- 测试账号:lili/123456-->
```

**★ 为什么会被浏览器"发出去"？**

```
HTML 注释（<!-- ... -->）是【HTML 源码的一部分】
→ 服务器原样发给浏览器
→ 浏览器"不显示"它，但它就在 HTML 里
★ 按 Ctrl+U（查看源码）或 F12（元素）就能看到
```

**★ 一个常见的误解**：

```
"注释用户看不见" → 错
"用户看不见"只是"不渲染"，不是"不发送"
★ 只要在 HTTP 响应里，就等于"公开"
```

**★ 实际危害**：

```
· 直接拿到可用账号 → 登录后台
· 如果注释里是"内网地址 / API key / 数据库密码" → 更严重
★ 这是渗透测试里"看源码"的第一步
```

**② 泄露点 2：用户枚举（不同提示暴露"用户是否存在"）**

**★ 源码（`findabc.php` 第 38-48 行）**：

```php
<?php
}else{
    $query_username = "select * from member where username='$username'";
    $res_user = execute($link, $query_username);
    if(mysqli_num_rows($res_user) == 1){
        $html .= "<p class='notice'>您输入的密码错误</p>";     // ★ 用户存在
    }else{
        $html .= "<p class='notice'>您输入的账号错误</p>";     // ★ 用户不存在
    }
}
?>
```

**★ 实测对比**：

| 输入 | 提示 |
|---|---|
| `lili` / `wrongpass` | **您输入的密码错误** |
| `nobody_xyz` / `wrongpass` | **您输入的账号错误** |

**★ 两种提示 → 两个信息**：

```
"密码错误" → 这个用户名【存在】
"账号错误" → 这个用户名【不存在】
```

**★ 危害（这是"信息泄露"里最隐蔽的一种）**：

```
① 攻击者拿一个字典（常见用户名/工号/邮箱前缀）
② 逐个试 → 得到"有效用户名列表"
③ 再针对这些用户名做密码爆破
   ★ 成功率从 "1/字典大小" 提升到 "接近 100%"
★ 这叫"用户枚举漏洞"（User Enumeration）
```

**★ 正确的做法（统一提示）**：

```php
// ❌ 两种提示
if (user_exists($u)) { echo "密码错误"; } else { echo "账号错误"; }

// ✅ 统一提示
if (login_ok($u, $p)) { ... } else { echo "用户名或密码错误"; }
```

**★ 但"统一提示"还不够**：

```
还要统一"响应时间"和"HTTP 状态码"
★ 否则攻击者能通过"耗时差异"（time-based）判断用户是否存在
```

**③ 泄露点 3：Cookie 里存明文用户名 + 密码哈希**

**★ 源码（`findabc.php` 第 34-35 行）**：

```php
<?php
setcookie('abc[uname]', $_GET['username'], time()+36000);      // ★ 明文用户名
setcookie('abc[pw]', md5($_GET['password']), time()+36000);   // ★ md5 密码
?>
```

**★ 实测拿到的 cookie**：

```
PHPSESSID  = n58pe7sa5vvoglsalri8larvni
abc[uname] = lili
abc[pw]    = e10adc3949ba59abbe56e057f20f883e
```

**★ 三个问题**：

```
① cookie 里存了"密码的哈希" → 等于把"半个密码"发给客户端
② md5 无盐 → 可以离线暴力破解（弱口令秒出）
③ cookie 不是 HttpOnly（可被 JS 读取）→ 一旦有 XSS，cookie 全泄露
```

**★ 危害链条**：

```
cookie 泄露 → 拿到 md5 哈希 → 离线破解 → 拿到明文密码
    ↓
或者直接"Pass-the-Hash"：
    伪造 abc[uname] / abc[pw] cookie → 不需要知道明文密码就能登录
★ 这就是 CSRF 那关学过的技巧
```

**★ 一个"实测"的小细节**：

```
在 Python 里打开这个页面，收到的 Cookie 头是：
    Set-Cookie: abc[uname]=lili; expires=...
    Set-Cookie: abc[pw]=e10adc...; expires=...
★ 连 "HttpOnly" 标志都没有 → document.cookie 能直接读到
```

**④ 泄露点 4：SQL 错误信息（本模块前面几关都见过）**

**★ `execute()` 的实现**：

```php
function execute($link, $query){
    $result = mysqli_query($link, $query);
    if(mysqli_errno($link)){
        exit(mysqli_error($link));       // ★ 直接把 MySQL 错误打印给用户
    }
    return $result;
}
```

**★ 这会泄露什么**：

```
· 数据库类型和版本（MySQL 5.7.26）
· 表名、列名（Unknown column 'xxx'）
· 绝对路径（load_file 报错时）
· 甚至能"报错注入"读数据（第 22 关做过）
```

**★ 生产环境的正确配置**：

```ini
; php.ini
display_errors = Off
log_errors = On
```

**⑤ ⭐ 为什么"小泄露"能串成"大攻击"**

**★ 本关的四种泄露，单独看都是"小问题"**：

```
· 一行注释
· 两种提示文案
· 一个 cookie
· 一条报错
```

**★ 但串起来就是完整的攻击链**：

```
① 看源码 → 找到测试账号 lili/123456
② 登录 → 拿到 cookie（含 md5）
③ 破解 md5 → 确认密码规律（123456）
④ 用"用户枚举"扩展用户名列表
⑤ 用"密码规律"（都是 123456）批量试 → 拿下所有账号
⑥ 如果其中有管理员 → 提权
```

**★ 这就是"信息收集"的价值**：

```
渗透测试里 80% 的工作是"信息收集"
★ 一个不起眼的注释，可能就是"入口"
★ 一个"提示文案的差异"，可能就是"用户名列表"
★ 一个 cookie 里的哈希，可能就是"密码"
```

三、解题步骤

**第 1 步：⭐ 看源码找注释（最快的一步）**

**★ 方式 A：Ctrl+U（查看页面源码）**

```text
① 打开 http://localhost/pikachu/vul/infoleak/findabc.php
② 按 Ctrl+U
③ Ctrl+F 搜 "测试" 或 "账号" 或 "lili"
④ 往下翻，会看到：
    </div><!-- 测试账号:lili/123456-->
```

**★ 方式 B：F12 → 元素**

```text
① F12 → 元素
② Ctrl+F 搜 "测试账号"
③ 找到注释节点
```

**★ 方式 C：直接看我写的源码分析（第 109 行）**

**★ 拿到账号**：

```
用户名：lili
密码：  123456
```

**第 2 步：登录**

```text
① 用户名填 lili
② 密码填 123456
③ 点 Login
④ 跳到 abc.php → 看到王小波那段话
★ 登录成功
```

**第 3 步：⭐ 体验用户枚举**

**★ 地址栏构造（或者用表单）**：

```
# 正确的用户名 + 错密码
http://localhost/pikachu/vul/infoleak/findabc.php?username=lili&password=wrong&submit=Login
→ "您输入的密码错误"

# 不存在的用户名 + 任意密码
http://localhost/pikachu/vul/infoleak/findabc.php?username=nobody&password=123&submit=Login
→ "您输入的账号错误"
```

**★ 两种提示不同 → 能判断"用户名是否存在"。**

**★ 顺手枚举一下 member 表的 7 个用户**：

```
vince / allen / kobe / grady / kevin / lucy / lili
★ 全部会返回"密码错误"（说明都存在）
★ 随便编一个 → "账号错误"
```

**第 4 步：⭐ 看 Cookie**

**★ 登录后**：

```
① F12 → 应用程序（Application）→ Cookie
② 看到：
   abc[uname] = lili
   abc[pw]    = e10adc3949ba59abbe56e057f20f883e
```

**★ 破解 md5**：

```python
import hashlib
target = "e10adc3949ba59abbe56e057f20f883e"
for pwd in ["123456","000000","abc123","password","admin","111111","888888"]:
    if hashlib.md5(pwd.encode()).hexdigest() == target:
        print("明文:", pwd)
        break
```

**★ 输出**：

```
明文: 123456
```

**★ 或者用"Pass-the-Hash"直接伪造 cookie**：

```
abc[uname]=vince
abc[pw]=e10adc3949ba59abbe56e057f20f883e    ← 所有用户都是 123456，哈希相同
★ 这样不用知道明文，也能"变成别人"
```

**第 5 步：完整 payload 汇总**

```
// ========== 泄露点 1：HTML 注释 ==========
<!-- 测试账号:lili/123456-->

// ========== 泄露点 2：用户枚举 ==========
?username=lili&password=wrong&submit=Login        → 密码错误（用户存在）
?username=nobody&password=wrong&submit=Login      → 账号错误（用户不存在）

// ========== 泄露点 3：Cookie ==========
abc[uname]=lili
abc[pw]=e10adc3949ba59abbe56e057f20f883e          → md5('123456')

// ========== 泄露点 4：SQL 报错 ==========
?username=lili'&submit=Login                      → SQL syntax error（泄露报错）
```

四、延伸知识

**① 敏感信息泄露的"完整地图"**

**★ 泄露发生在哪里？**

| 类别 | 具体位置 | 例子 |
|---|---|---|
| **源码注释** | HTML / JS / PHP 注释 | **本关的 `<!-- 测试账号 -->`** |
| **备份文件** | `.bak` / `.zip` / `.sql` / `www.zip` | `index.php.bak` 能下载到源码 |
| **版本控制** | `.git/` / `.svn/` | `.git/config` 泄露仓库地址 |
| **配置文件** | `.env` / `config.php` | 数据库密码、API key |
| **错误信息** | SQL / 异常堆栈 | 表名、路径、版本 |
| **响应头** | `Server:` / `X-Powered-By:` | Apache 2.4.39 / PHP 7.3.4 |
| **Cookie** | 明文身份/哈希 | **本关的 `abc[pw]`** |
| **URL 参数** | `?debug=1` / `?test=1` | 调试模式开启 |
| **目录浏览** | Autoindex 开启 | 看到文件列表 |
| **用户枚举** | 登录/注册/找回密码的提示差异 | **本关的"账号错误"vs"密码错误"** |
| **JS 文件** | 前端硬编码 | API 地址、密钥、测试账号 |
| **注释掉的代码** | `<!-- <a href="/admin">管理</a> -->` | 泄露隐藏功能/路径 |
| **robots.txt** | 声明了不允许爬的路径 | 反而告诉攻击者"这些路径存在" |
| **sitemap.xml** | 网站地图 | 泄露所有页面 |
| **.DS_Store / Thumbs.db** | Mac/Windows 自动生成 | 泄露目录里的文件名 |

**★ 本环境有哪些？**

```
· HTML 注释（本关）
· SQL 报错（execute 打印）
· Cookie（abc[pw]）
· robots.txt？  → 可以试试 http://localhost/pikachu/robots.txt
· .git？        → 可以试试 http://localhost/pikachu/.git/config
· 备份文件？    → 可以试试 www.zip / pikachu.zip / index.php.bak
```

**② 用户枚举的三种"侧信道"**

**★ 除了"提示文案"，还有两种**：

**侧信道 1：响应时间**

```
用户存在 → 走"查密码"的逻辑（多一次查询）→ 慢几毫秒
用户不存在 → 直接返回 → 快几毫秒
★ 用脚本统计 100 次的时间差，能判断出来
```

**侧信道 2：HTTP 状态码**

```
用户存在 + 密码错 → 200
用户不存在       → 404 / 403
★ 有些系统会这样（虽然少见）
```

**侧信道 3：重定向**

```
用户存在 → 302 到"密码错误页"
用户不存在 → 200 直接渲染错误
★ 看 Location 头就能区分
```

**★ 防御"用户枚举"的完整做法**：

```php
// ① 统一提示
echo "用户名或密码错误";

// ② 统一响应时间（对不存在的用户也做一次假查询）
if (!user_exists($u)) {
    usleep(random_int(50000, 200000));   // 模拟耗时
}

// ③ 统一状态码和响应体长度
http_response_code(200);
```

**③ Cookie 安全的三件套**

**★ 一个"安全"的 cookie 应该长这样**：

```http
Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```

**★ 四个属性的作用**：

| 属性 | 作用 | 不加的后果 |
|---|---|---|
| **`HttpOnly`** | JS 读不到（`document.cookie` 拿不到）| XSS 能偷 cookie |
| **`Secure`** | 只在 HTTPS 下发送 | 明文传输，能被中间人截获 |
| **`SameSite`** | 跨站请求不带 cookie | CSRF 风险 |
| **`Max-Age` / `Expires`** | 有效期 | 永久 cookie，泄露后长期有效 |

**★ 本关的 cookie 问题**：

```
abc[uname]=lili                                  → 明文身份
abc[pw]=e10adc...                                → 密码哈希
（没有 HttpOnly / Secure / SameSite）             → 全裸
★ 这不是"会话标识"，而是"把密码塞给客户端"
```

**★ 正确做法**：

```
cookie 里只放"随机的 session id"
→ 身份信息存服务端（session 文件 / Redis）
→ 客户端拿到的那串 id，即使泄露，也能"服务端失效"
```

**④ 信息收集在渗透测试中的地位**

**★ 一个"经验比例"**：

```
渗透测试的时间分配：
    信息收集    60% ~ 80%
    漏洞验证    10% ~ 20%
    写报告      10%
★ 信息越全，攻击路径越清晰
```

**★ 本模块（敏感信息泄露）的意义**：

```
它教你的不是"某个漏洞怎么打"
而是"养成'看源码、看响应头、看 cookie、看报错'的习惯"
★ 这些习惯决定了你能不能发现"别人发现不了的东西"
```

**★ 一个实用的"信息收集 checklist"（针对单个站点）**：

```
□ 看 HTML 源码（注释、隐藏字段、JS 里的接口）
□ 看响应头（Server / X-Powered-By / Set-Cookie）
□ 看 cookie（有没有明文/哈希/角色字段）
□ 看报错（随便输点特殊字符，看有没有堆栈）
□ 试 robots.txt / sitemap.xml
□ 试 .git/config / .svn/entries / .DS_Store
□ 试常见备份：www.zip / backup.zip / index.php.bak / .env
□ 试目录浏览：/uploads/ /backup/ /admin/
□ 试用户枚举：登录/注册/找回密码处
□ 看前端 JS 文件（有没有硬编码 key / 内网地址）
```

**⑤ 真实世界的敏感信息泄露案例**

**案例 1：GitHub 上泄露 API Key**

```
开发把 .env 或 config.js 推到公开仓库
→ 里面是 AWS / 阿里云 / 数据库的密钥
→ 攻击者直接接管云资源
★ 这类事件每年都有大量
```

**案例 2：`.git` 目录可访问**

```
http://target/.git/config 能下载
→ 用 GitHack 之类的工具恢复整个源码
→ 从源码里找 SQL 注入 / 后门
★ 很多站点忘了在部署时排除 .git
```

**案例 3：JS 里硬编码测试账号**

```javascript
// 前端 JS
const ADMIN = { user: "admin", pass: "Admin@123" };
```
```
★ F12 一看就看到
★ 本关的"HTML 注释"是同一类问题
```

**案例 4：报错泄露内网信息**

```
Fatal error: Uncaught PDOException: SQLSTATE[HY000] [2002]
Connection refused ... in /var/www/html/config/db.php:12
```
```
★ 泄露了：框架（PDO）、路径、数据库端口
★ 攻击者据此判断"内网数据库"的存在
```

**⑥ 防御（五层）**

**❌ 本关的问题**：

```html
<!-- 测试账号:lili/123456-->                              ← 注释泄露
```
```php
if(user_exists($u)){ echo "密码错误"; } else { echo "账号错误"; }   ← 枚举
```
```php
setcookie('abc[pw]', md5($password), ...);                ← cookie 放哈希
```
```php
if(mysqli_errno($link)) exit(mysqli_error($link));        ← 报错直出
```

**✅ 第 1 层：代码审查（发布前删注释）**

```text
· 上线前搜一遍 "TODO" / "测试" / "test" / "admin" / "密码" / "password"
· 用构建工具（webpack 等）压缩时自动去掉注释
· ★ 但 HTML 注释通常不会被压缩工具处理 → 要人工检查
```

**✅ 第 2 层：统一错误提示（防枚举）**

```php
// 登录失败
echo "用户名或密码错误";

// 找回密码
echo "如果该邮箱存在，我们已发送邮件";
★ 都是"模糊提示"，不暴露"存在性"
```

**✅ 第 3 层：Cookie 安全（只放 session id）**

```php
session_start();
setcookie(session_name(), session_id(), [
    'httponly' => true,      // ★ JS 读不到
    'secure'   => true,      // ★ 只走 HTTPS
    'samesite' => 'Lax',     // ★ 防 CSRF
    'path'     => '/',
]);
```

**✅ 第 4 层：关闭错误显示**

```ini
; php.ini（生产环境）
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

```php
// 或者代码里
ini_set('display_errors', 0);
```

**✅ 第 5 层：部署时清理（最容易忘）**

```bash
# 删除版本控制
rm -rf .git .svn .hg

# 删除备份/临时文件
rm -f *.bak *.zip *.sql *.log

# 删除编辑器文件
rm -f .DS_Store Thumbs.db .idea .vscode

# 配置 Web 服务器禁止访问敏感文件
```

```nginx
# nginx：禁止访问 .git / .env / 备份文件
location ~ /\.(git|svn|env|DS_Store) { deny all; }
location ~ \.(bak|sql|zip|log|old)$ { deny all; }
```

**★ 一条"上线前检查"的口诀**：

```
"注释删掉、报错关掉、cookie 收紧、备份清掉"
```

五、总结

- **本题核心：`findabc.php` 的 HTML 注释里写着 `<!-- 测试账号:lili/123456-->` → 直接拿到账号密码登录。**

- **四处泄露点汇总**：

```html
<!-- ① 注释泄露（第 109 行）-->
</div><!-- 测试账号:lili/123456-->
```

```php
// ② 用户枚举（第 41-46 行）
if(mysqli_num_rows($res_user) == 1){ echo "密码错误"; }   // 用户存在
else                               { echo "账号错误"; }   // 用户不存在
```

```php
// ③ Cookie 明文（第 34-35 行）
setcookie('abc[uname]', $_GET['username'], time()+36000);
setcookie('abc[pw]', md5($_GET['password']), time()+36000);   // md5 可破
```

```php
// ④ SQL 报错（execute 函数）
if(mysqli_errno($link)) exit(mysqli_error($link));            // 报错直出
```

- **⭐ 八个必记要点**：

```text
① HTML 注释是"发出去的"，不是"藏起来的"
   Ctrl+U / F12 就能看到
   ★ "用户看不见" ≠ "不在响应里"

② 用户枚举靠"提示差异"
   "密码错误" vs "账号错误" → 能判断用户名是否存在
   ★ 还有"响应时间 / 状态码 / 重定向"三种侧信道

③ Cookie 里不能放密码（哪怕哈希）
   md5 无盐 → 离线秒破
   而且没有 HttpOnly → XSS 能偷

④ 报错信息是最容易被忽略的泄露
   SQL 报错 → 表名/列名/路径
   ★ 生产环境必须 display_errors = Off

⑤ 小泄露能串成大攻击链
   注释 → 测试账号 → 登录 → cookie 哈希 → 破解 → 密码规律 → 批量试

⑥ 信息收集占渗透工作量的 60%~80%
   看源码、看响应头、看 cookie、看报错、试备份文件

⑦ 高频泄露点：.git / .env / *.bak / robots.txt / .DS_Store / JS 硬编码
   ★ 上线前必须清理

⑧ 防御口诀：注释删掉、报错关掉、cookie 收紧、备份清掉
```

- **实测数据**：

```text
【注释泄露】
    findabc.php 第 109 行：<!-- 测试账号:lili/123456-->

【用户枚举】
    lili       / wrongpass  → "您输入的密码错误"    （用户存在）
    nobody_xyz / wrongpass  → "您输入的账号错误"    （用户不存在）

【Cookie 泄露】
    abc[uname] = lili
    abc[pw]    = e10adc3949ba59abbe56e057f20f883e  = md5('123456')

【登录成功】
    lili / 123456 → HTTP 302 → abc.php
    abc.php 内容：王小波《黄金时代》节选（本关无额外秘密）

【md5 破解】
    e10adc3949ba59abbe56e057f20f883e → 123456
```

- **进度**：

```text
platform: pikachu   38 篇

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
└── 敏感信息泄露        1/1    ✅  ← 刚完成
```

**手工复现要点**：

```text
· 打开 findabc.php → Ctrl+U → Ctrl+F 搜 "测试账号"
  → 看到 <!-- 测试账号:lili/123456-->
· 用 lili / 123456 登录 → 成功
· 试 ?username=nobody&password=x → "账号错误"
· 试 ?username=lili&password=x   → "密码错误"  ★ 枚举成功
· 登录后 F12 → Cookie → 看到 abc[pw] 是 md5
· 破解 md5 → 123456
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  敏感信息泄露 = "开发时的小方便，变成了攻击者的入口"              │
│                                                            │
│  四种典型泄露点：                                             │
│      ① HTML 注释里的测试账号                                  │
│      ② 登录提示的差异（用户枚举）                              │
│      ③ Cookie 里的密码哈希                                    │
│      ④ 报错信息里的表名/路径                                   │
│                                                            │
│  ★ "用户看不见" ≠ "不在响应里"（注释会被发出去）                 │
│  ★ 小泄露能串成大攻击链                                        │
│  ★ 防御口诀：注释删掉、报错关掉、cookie 收紧、备份清掉            │
└────────────────────────────────────────────────────────────┘
```

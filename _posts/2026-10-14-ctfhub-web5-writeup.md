---
layout: post
title: CTFHub - 响应包源代码 Writeup
platform: ctfhub
date: 2026-10-14 00:29:00 +0800
categories: CTF
---

CTFHub - 响应包源代码 Writeup

一、题目信息

- 平台：CTFHub（技能树 → Web → HTTP 协议 → **响应包源代码**）
- 题型：Web
- 考点：**查看 HTTP 响应包源码**、网页源码里的隐藏信息
  
二、题目分析

**① 题目现象**

打开题目地址，页面上是一个**网页版的"贪吃蛇"小游戏**。

```
陷阱：你会开始玩这个游戏，想"通关拿 flag"
真相：flag 跟游戏没有半点关系 —— 它一直就在网页的源代码里
```

**② 核心知识点：什么是"响应包源代码"**

```text
你访问一个网页，实际发生的事：
    浏览器发请求  →  服务器返回【响应包】  →  浏览器解析后画出页面

响应包里包含：
    · 响应头（状态码、Content-Type、Cookie…）
    · 响应体（HTML 源码 + CSS + JS）

★ 浏览器"画页面"时，会按 HTML/CSS 的规则决定【什么显示、什么不显示】：
    · HTML 注释 <!-- 这里的内容 -->   → 不显示
    · <input type="hidden">           → 不显示
    · CSS 的 display:none / 透明色     → 不显示

但不管你显示不显示，【源码就在那儿】—— 直接看源码就能看到全部内容。
```

**③ 破题思路**

```text
题目名直接叫"响应包源代码" —— 出题人在明示：
    "别玩那个游戏了，去看网页的源代码"

flag 通常藏在：
    ① HTML 注释里        <!-- flag{...} -->
    ② 隐藏的表单字段里    <input type="hidden" value="flag{...}">
    ③ 被 CSS 隐藏的元素里 <div style="display:none">flag{...}</div>
    ④ JS 代码的变量里     var flag = "ctfhub{...}";
```

三、解题步骤

**方法一：Ctrl + U 查看网页源代码（最快）**

```text
① 打开题目页面
② 按 Ctrl + U（或右键页面 → "查看网页源代码"）
③ 会打开一个新标签页，显示完整的 HTML 源码
④ 按 Ctrl + F 搜 flag  →  直接定位
```

**方法二：F12 开发者工具**

```text
① 按 F12 打开开发者工具
② 切到 Elements（元素）标签 → 看到完整 HTML 结构
③ 按 Ctrl + F 在 Elements 里搜 flag
④ 或者用 Ctrl + Shift + F 全局搜（能搜到 JS 文件里的内容）
```

> ⚠️ **注意 Ctrl+U 和 Elements 的区别**（前面 F12 指南里详细讲过）：
> ```text
> Ctrl+U    → 服务器返回的【原始源码】（未经 JS 处理）
> Elements  → 浏览器解析后的【渲染结果 DOM】（可能被 JS 增删改过）
>
> 如果 flag 在被 JS 删掉的标签里，Elements 里就找不到了，必须用 Ctrl+U
> ```


四、延伸知识：源码里的隐藏信息都藏在哪

**① 常见的位置清单（做题时挨个检查）**

| 位置 | 长什么样 | 怎么看到 |
|---|---|---|
| **HTML 注释** | `<!-- flag{...} -->` | Ctrl+U / 响应源码 |
| **隐藏表单字段** | `<input type="hidden" name="x" value="flag{...}">` | Ctrl+U / F12 |
| **CSS 隐藏元素** | `<div style="display:none">`、`color:#fff`（白字白底） | F12 看元素属性 |
| **JS 变量** | `var flag = "ctfhub{...}"` | Sources 标签 / Ctrl+Shift+F |
| **JS 注释** | `// TODO: 记得删掉 flag{...}` | 同上 |
| **响应头** | `X-Flag: ctfhub{...}` | F12 Network / Burp |
| **Cookie** | `Set-Cookie: flag=...` | F12 Application / Burp |
| **HTML 属性** | `<a href="/x" data-flag="...">` | Ctrl+U |
| **页面底部** | 大量空行之后再写内容 | 拉到源码最底部 |

**② "白字白底"这种隐藏方式**

```html
<div style="color: white; background: white;">flag{...}</div>
```

页面上**完全看不见**（白字写在白底上），但你一按 **`Ctrl+A` 全选**，被选中的文字会高亮 → **flag 就现形了**。

> 这是个很实用的小技巧：**遇到"页面上什么都没有"的题，先 `Ctrl+A` 全选看看** —— 能发现白字、透明字、被遮挡的内容。

**③ 为什么响应源码里会残留敏感信息（真实场景）**

```text
· 开发时调试留下的注释没删（// 测试账号 admin/123456）
· 把配置写在前端 JS 里（API key、内网地址、数据库信息）
· 隐藏字段里放了"不该给用户看"的数据，以为隐藏就安全
  （其实用户一改就能提交回去 —— 典型的"信任客户端"）

→ 这也是为什么"前端隐藏"永远不算保护措施
→ 真实渗透测试中，看源码（Ctrl+U）是信息收集的第一步
```

**④ 一条通用经验：页面看不到 ≠ 不存在**

```text
浏览器只"画"出符合规则的内容，但源码里可能还有一大堆东西。
做 Web 题的第一反应应该是：先看源码，再看响应头，最后才看页面。

顺序建议：
    ① Ctrl+U 看源码（找注释、隐藏字段、JS）
    ② F12 Network 看请求/响应头（找 Cookie、Location、自定义头）
    ③ 抓包用 Burp（找请求方法、参数、Authorization）
```

五、总结

- **本题核心：flag 就在 HTTP 响应包的 HTML 源码里，跟页面上的游戏毫无关系。** 按 `Ctrl+U` 或去 Burp 的 Response 里就能看到。
- 记住这条：**页面看不见的东西，去"响应包"里找** —— 注释、隐藏字段、被 CSS 藏起来的元素，全都在源码里明摆着。
- 三个顺手的技巧：
  ```text
  ① Ctrl+U        → 看原始源码（最快）
  ② Ctrl+F        → 在源码里搜 flag / key / pass
  ③ Ctrl+A 全选   → 发现"白字白底"这类视觉隐藏的内容
  ```
- CTFHub「HTTP 协议」系列**全部通关** 🎉


- 这五题串起来其实就是一句话：**HTTP 请求和响应的每个部分（方法、路径、头、Cookie、正文）都可能藏信息，也都可能被动手脚。** 而 Burp 和 F12 就是让你能"看见"和"改动"这些部分的两个工具。

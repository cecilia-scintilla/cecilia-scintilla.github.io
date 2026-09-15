---
layout: post
title: Bugku CTF - POST Writeup
date: 2026-09-12 16:17:00 +0800
categories: CTF
---

Bugku CTF - POST Writeup

一、题目信息

· 题型：web

· 题目：POST

· 考点：HTTP POST 请求传参、PHP POST 变量接收与判断

二、题目分析

· 点进去后页面通常只显示一段提示信息或 PHP 源码。

· 源码中通常包含类似 `$what=$_POST['what'];` 和 `if($what=='flag')` 的代码，要求通过 POST 方式传入一个名为 `what` 的参数，且该参数的值必须等于 `flag`。

· 与 GET 关卡不同，直接用浏览器地址栏输入 URL?what=flag 是无法通过的，因为浏览器地址栏默认发起的是 GET 请求，必须构造 POST 请求提交数据。

三、解题步骤

· 使用 curl 命令行（快捷方法）
· 打开终端或命令行，输入：
· `curl -X POST -d "what=flag" http://题目URL`
· 其中 `-X POST` 指定请求方法为 POST，`-d` 指定提交的参数数据。
· 页面响应中即可直接看到 flag。

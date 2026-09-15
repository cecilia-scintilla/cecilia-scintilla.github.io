---
layout: post
title: Bugku CTF - GET Writeup
date: 2026-09-12 16:17:00 +0800
categories: CTF
---

Bugku CTF - GET Writeup

一、题目信息

· 题型：web

· 题目：GET

· 考点：HTTP GET 请求传参、PHP 变量接收与判断

二、题目分析

· 点进去后页面通常只显示一段 PHP 源码或提示信息。

· 源码中通常包含类似 `$what=$_GET['what'];` 和 `if($what=='flag')` 的代码，要求通过 GET 方式传入一个名为 `what` 的参数，且该参数的值必须等于 `flag`。

三、解题步骤

· 直接在 URL 中构造参数
· 在浏览器地址栏中，在题目 URL 后面加上 `?what=flag`。
· 例如：`http://题目URL/?what=flag`
· 按回车访问，页面即可直接返回 flag。

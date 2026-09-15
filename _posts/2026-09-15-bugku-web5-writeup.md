---
layout: post
title: Bugku CTF - 头等舱 Writeup
date: 2026-09-12 16:17:00 +0800
categories: CTF
---

Bugku CTF - 头等舱 Writeup

一、题目信息

· 题型：web

· 题目：头等舱

· 考点：HTTP 响应头（Response Headers）信息查看

二、题目分析

· 点进去后页面什么也没有显示，查看网页源代码（F12 或右键查看源代码）也没有任何多余信息。

· 题目名称“头等舱”是明显的提示，暗示我们要往“头”部（即 HTTP 头）去思考，因此需要重点关注 HTTP 响应头是否隐藏了 flag。

三、解题步骤

· 方法一：F12 开发者工具查看
· 打开题目页面，按 F12 打开开发者工具。
· 切换到 Network（网络）面板，刷新一下页面。
· 点击列表中的第一个请求（通常是题目 URL 或 index.php）。
· 在右侧选择 Headers（标头），向下滚动找到 Response Headers（响应标头），即可看到 flag。

---
layout: post
title: Bugku CTF - Source Writeup
date: 2026-09-12 16:17:00 +0800
categories: CTF
---

Bugku CTF - Source Writeup

一、题目信息

· 题型：web

· 题目：Source（源代码）

· 考点：网页源代码查看、源码泄露（Git 泄露、备份文件泄露等）

二、题目分析

· 点进去后页面通常会显示一句提示“Flag 在源代码里”。

· 这道题考察的是获取网站源码的常见方式。很多时候，开发者会将网站的源码或备份文件直接放在 Web 目录下，导致源码泄露。

· 查看网页源码、常见备份文件、或者利用 `.git`、`.svn` 等版本控制泄露来获取 flag。

三、解题步骤

· 利用 Git 源码泄露
· 如果服务器存在 `.git` 目录泄露，可以使用工具如 GitHack 或 dirsearch 进行扫描。
· 常用命令：`python2 GitHack.py http://题目URL/.git/`
· 下载完成后，在生成的文件夹中查找源码或 flag 文件。

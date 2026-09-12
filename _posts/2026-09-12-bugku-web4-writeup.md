---
layout: post
title: "Bugku CTF - WEB4 Writeup"
date: 2026-09-12 16:17:00 +0800
categories: CTF
---
Bugku CTF -WEB4 Writeup

一、题目信息

·  题型：web

二、题目分析

·  点进去后看到图片一直在来回闪动只有当图片停下才可获得flag，图片闪动由js决定把js禁用即可获得flag

三、解题步骤

·  F12点开开发者工具ctrl+shift+p运行disable JavaScript的指令

·此时图片停下即可在元素中查看flag

四、心得总结

·  html负责结构（内容）css负责外观js负责行为（弹窗，刷新页面）

·  在CTF WEB题中用来前端验证flag

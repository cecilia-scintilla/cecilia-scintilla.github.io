---
layout: default
title: 我的博客
---

<div style="text-align: center; padding: 40px 0;">
  <h1>cecilia-scintilla</h1>
  <p>欢迎来到我的个人空间！</p >
</div>

<hr>

<h2>最新文章</h2>
<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 20px;">
      <h3 style="margin-bottom: 5px;">
        <a href=" " style="text-decoration: none; color: #0366d6;">{{ post.title }}</a >
      </h3>
      <small style="color: #666;">{{ post.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>

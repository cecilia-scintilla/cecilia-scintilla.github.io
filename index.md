---
layout: default
title: cecilia-scintilla的博客
---

# cecilia-scintilla

共同进步！

---

## 最新文章

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 15px;">
      <!-- 核心修复：必须把 post.url 放进来 -->
      <a href="{{ post.url }} " style="font-size: 18px; color: #0366d6; text-decoration: none;">{{ post.title }}</a >
      <br>
      <small style="color: #888;">{{ post.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>

<style>
  /* 覆盖顶部绿色背景为图片 */
  body > header, .header, .hero, header, .banner {
      background-image: url('/bg.jpg') !important; 
      background-size: cover !important;
      background-position: center !important;
      background-repeat: no-repeat !important;
      padding-top: 60px !important; 
      padding-bottom: 60px !important;
  }
  
  /* 因为图1是浅色，白字看不清，这里强制改成深色字 */
  body > header *, .header *, .hero *, header *, .banner * {
      color: #333333 !important; /* 深灰色 */
  }
</style>

# cecilia-scintilla

共同进步！

## 最新文章

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 15px;">
      <a href="{{ post.url }} " style="font-size: 18px; color: #0366d6; text-decoration: none;">{{ post.title }}</a ><br>
      <small style="color: #888;">{{ post.date | date: "%Y-%m-%d" }}</small>
    </li>
  {% endfor %}
</ul>

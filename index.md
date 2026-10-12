---
layout: default
---

{% comment %}
  注意：顶部横幅由主题自带的 .page-header 渲染（标题取 _config.yml 的 site.title），
  所以这里不要再写 page-header，否则会出现两条横幅。
{% endcomment %}

<div class="main-content">

  <h2 class="section-title">关于我 🤍</h2>
  <p>允许一切发生 然后 做个勇敢的人</p>

  {% for module in site.data.modules %}

    {% assign module_posts = site.emptyArray %}
    {% if module.layout == "category" %}
      {% assign module_posts = site.categories[module.category] %}
    {% endif %}

    <h2 class="section-title">{{ module.icon }} {{ module.title }}</h2>
    {% if module.desc %}<p class="section-desc">{{ module.desc }}</p>{% endif %}

    {% comment %} ① 分类型模块（内部再分平台子模块） {% endcomment %}
    {% if module.layout == "category" %}

      {% for grp in module.groups %}
        {% assign group_posts = site.posts | where: "platform", grp.platform %}
        <div class="module-card">
          <h3>{{ grp.title }}</h3>
          {% if grp.desc %}<p class="module-desc">{{ grp.desc }}</p>{% endif %}
          <p class="module-count">共 {{ group_posts.size }} 篇</p>
          {% if grp.url %}
            <a class="module-more" href="{{ grp.url | relative_url }}">查看全部 writeup →</a>
          {% endif %}
        </div>
      {% endfor %}

      {% if module.url %}
        <p><a class="module-more" href="{{ module.url | relative_url }}">查看全部 {{ module.title }} →</a></p>
      {% endif %}

    {% comment %} ② 普通模块（直接用 platform 收集文章） {% endcomment %}
    {% else %}
      {% assign module_posts = site.posts | where: "platform", module.platform %}
      <div class="module-card">
        {% if module.desc %}<p class="module-desc">{{ module.desc }}</p>{% endif %}
        <p class="module-count">共 {{ module_posts.size }} 篇</p>
        {% if module_posts.size > 0 %}
          <ul class="post-list">
            {% for post in module_posts limit: 10 %}
              <li>
                <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
                <span class="post-date">{{ post.date | date: "%Y-%m-%d" }}</span>
              </li>
            {% endfor %}
          </ul>
        {% endif %}
        {% if module.url %}
          <p><a class="module-more" href="{{ module.url | relative_url }}">查看全部 →</a></p>
        {% endif %}
      </div>
    {% endif %}

  {% endfor %}

  <h2 class="section-title">📮 最新文章</h2>
  <p class="section-desc">不管哪个模块，最近写的都会出现在这里。</p>
  <ul class="post-list">
    {% for post in site.posts limit: 8 %}
      <li>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        <span class="post-date">{{ post.date | date: "%Y-%m-%d" }}</span>
      </li>
    {% endfor %}
  </ul>

</div>

---
layout: default
title: Bugs
---

<h1>Random bugs</h1>
<ul class="bugs">
    {% for bug in site.data.bugs.bugs %}
    <li><span>{{ bug.package }}</span>: <a href="{{ bug.url }}" title="{{ bug.title }}">{{ bug.title }}</a></li>
    {% endfor %}
</ul>
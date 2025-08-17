---
title: _index
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# _index

> Индекс раздела **nebula-resource** (Dataview).

```dataview
TABLE file.name AS "Page", file.folder AS "Folder", file.mtime AS "Updated"
FROM "02-Crates/nebula-resource"
WHERE file.name != "_index.md"
SORT file.folder ASC, file.name ASC
```

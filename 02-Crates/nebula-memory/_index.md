---
title: _index
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

# _index

> Индекс для Dataview

```dataview
TABLE file.name AS Page, file.folder AS Folder, file.mtime AS Updated
FROM "02-Crates/nebula-memory"
WHERE file.name != "_index.md"
SORT file.folder, file.name
```

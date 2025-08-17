---
title: _Index
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# _Index

> Master index for **nebula-action** (deep docs).

```dataview
TABLE file.name AS "Page", file.folder AS "Folder", file.mtime AS "Updated"
FROM "02-Crates/nebula-action"
WHERE file.name != "_Index.md"
SORT file.folder ASC, file.name ASC
```

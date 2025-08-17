---
title: _Index
tags: [nebula, moc]
status: draft
created: 2025-08-17
---

# _Index

> This is the index (MOC) for **Overview**.

## Contents
```dataview
TABLE file.name AS "Page", file.mtime AS "Updated"
WHERE file.folder = this.file.folder AND file.name != "_Index.md"
SORT file.name ASC
```

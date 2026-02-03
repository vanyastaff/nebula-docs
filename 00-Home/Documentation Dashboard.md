---
title: Documentation Dashboard
tags: [meta, dashboard, tracking]
status: published
lang: ru
created: 2026-02-03
last_updated: 2026-02-03
---

# 📊 Nebula Documentation Dashboard

Центральная панель для отслеживания прогресса документации.

---

## 🚧 В работе (Draft Pages)

```dataview
TABLE WITHOUT ID
  file.link as "Страница",
  tags as "Теги",
  last_updated as "Обновлено"
FROM ""
WHERE status = "draft"
SORT last_updated DESC
LIMIT 15
```

---

## ✅ Недавно опубликовано

```dataview
TABLE WITHOUT ID
  file.link as "Страница",
  tags as "Теги",
  last_updated as "Опубликовано"
FROM ""
WHERE status = "published"
SORT last_updated DESC
LIMIT 10
```

---

## ⚠️ Требуют обновления (Outdated)

```dataview
TABLE WITHOUT ID
  file.link as "Страница",
  last_updated as "Последнее обновление",
  tags as "Теги"
FROM ""
WHERE status = "outdated"
SORT last_updated ASC
```

> [!WARNING] Эти страницы помечены как устаревшие
> Проверьте и обновите информацию или поменяйте статус на `published`

---

## 📦 Статус документации Crates

```dataview
TABLE WITHOUT ID
  file.link as "Crate",
  status as "Статус",
  version as "Версия",
  last_updated as "Обновлено"
FROM "02-Crates"
WHERE file.name != "_Index" AND file.name != "Crates Overview"
SORT file.name ASC
```

---

## 🎯 Документация по концепциям

```dataview
TABLE WITHOUT ID
  file.link as "Концепция",
  status as "Статус",
  audience as "Уровень",
  estimated_reading as "Время чтения"
FROM "03-Concepts"
WHERE file.name != "_Index"
SORT status ASC, file.name ASC
```

---

## 📚 API Reference Coverage

```dataview
TABLE WITHOUT ID
  file.link as "API",
  status as "Статус",
  last_updated as "Обновлено"
FROM "05-API-Reference"
WHERE file.name != "_Index"
SORT file.name ASC
```

---

## 💡 Примеры кода (Examples)

```dataview
TABLE WITHOUT ID
  file.link as "Пример",
  tags as "Категории",
  status as "Статус"
FROM "06-Examples"
WHERE file.name != "_Index"
SORT file.name ASC
```

---

## 📈 Статистика документации

### По статусам

```dataview
TABLE WITHOUT ID
  length(rows) as "Количество"
FROM ""
WHERE status != null
GROUP BY status
SORT length(rows) DESC
```

### По языкам

```dataview
TABLE WITHOUT ID
  length(rows) as "Страниц"
FROM ""
WHERE lang != null
GROUP BY lang
```

### По тегам (топ-10)

```dataview
TABLE WITHOUT ID
  length(rows) as "Использований"
FROM ""
FLATTEN tags
WHERE tags != null
GROUP BY tags
SORT length(rows) DESC
LIMIT 10
```

---

## 🔗 Страницы без backlinks (Orphans)

```dataview
TABLE WITHOUT ID
  file.link as "Потенциально осиротевшая страница",
  file.inlinks as "Входящих ссылок",
  last_updated as "Обновлено"
FROM ""
WHERE length(file.inlinks) = 0
  AND file.name != "Documentation Dashboard"
  AND file.name != "_Index"
  AND !contains(file.path, "_templates")
SORT last_updated DESC
LIMIT 10
```

> [!TIP] Добавьте ссылки на эти страницы
> Страницы без входящих ссылок трудно найти через навигацию

---

## 📅 Активность за последние 7 дней

```dataview
TABLE WITHOUT ID
  file.link as "Страница",
  status as "Статус",
  last_updated as "Дата"
FROM ""
WHERE last_updated >= date(today) - dur(7 days)
SORT last_updated DESC
```

---

## 🎯 Action Items

### Высокоприоритетные задачи

```dataview
TASK
WHERE !completed AND priority = 1
SORT due ASC
```

### Просроченные задачи

```dataview
TASK
WHERE !completed AND due < date(today)
SORT due ASC
```

---

## 🚀 Быстрая навигация

### По категориям

- [[00-Home/_Index|🏠 Home]] - Главная страница
- [[01-Overview/_Index|📖 Overview]] - Обзор проекта
- [[02-Crates/_Index|📦 Crates]] - Документация crates
- [[03-Concepts/_Index|💡 Concepts]] - Концепции
- [[04-Development/_Index|🔨 Development]] - Руководства разработчика
- [[05-API-Reference/_Index|📚 API Reference]] - Справочник API
- [[06-Examples/_Index|💻 Examples]] - Примеры кода
- [[07-Advanced/_Index|🚀 Advanced]] - Продвинутые темы
- [[08-Reference/_Index|📋 Reference]] - Справочники и FAQ

### Ключевые страницы

- [[What is Nebula]] - Что такое Nebula
- [[Getting Started]] - Быстрый старт
- [[Architecture Overview]] - Архитектура
- [[API Reference]] - API документация
- [[Obsidian Plugins Guide]] - Руководство по плагинам

---

## 🔧 Инструменты

- [[Documentation Kanban]] - Kanban доска задач
- [[Obsidian Plugins Guide]] - Гид по плагинам
- [[Constitution]] - Принципы документации
- [[Tag Glossary]] - Глоссарий тегов

---

## 📝 Заметки

> [!NOTE] Как пользоваться Dashboard
> 1. Начинайте день с проверки "В работе" и "Требуют обновления"
> 2. Обновляйте `status` по мере завершения страниц
> 3. Следите за orphan pages - добавляйте ссылки на них
> 4. Проверяйте статистику раз в неделю

---

*Обновляется автоматически через Dataview*  
*Последний просмотр: {{date:YYYY-MM-DD HH:mm}}*

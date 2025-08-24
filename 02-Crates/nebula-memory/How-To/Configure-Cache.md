---
title: Configure Cache
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

# Configure Cache

**Цель.** Пошаговая инструкция, чек-листы, грабли.


```rust
pub struct LruCache<K: Eq + std::hash::Hash, V> {
    // segmented LRU for better scan resistance
    budget_bytes: usize, used_bytes: usize,
    // internal maps/lists omitted
}
impl<K: Eq + std::hash::Hash, V> LruCache<K,V> {
    pub fn with_budget(b: usize) -> Self { Self { budget_bytes: b, used_bytes: 0 } }
    pub fn put(&mut self, _k: K, _v: V, sz: usize) { self.used_bytes += sz; /* evict until <= budget */ }
    pub fn get(&mut self, _k: &K) -> Option<&V> { None }
    pub fn used(&self) -> usize { self.used_bytes }
}
```


Рекомендации — пункт 1. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 2. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 3. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 4. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 5. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 6. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

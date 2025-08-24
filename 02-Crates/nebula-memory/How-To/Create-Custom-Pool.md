---
title: Create Custom Pool
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

# Create Custom Pool

**Цель.** Пошаговая инструкция, чек-листы, грабли.


```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use crossbeam_queue::SegQueue;

pub struct FixedBufferPool {
    chunk: usize,
    free: SegQueue<Box<[u8]>>,
    total: AtomicUsize,
}

pub struct Lease {
    buf: Option<Box<[u8]>>,
    back: *const SegQueue<Box<[u8]>>,
}

impl FixedBufferPool {
    pub fn new(chunk: usize, prealloc: usize) -> Self {
        let q = SegQueue::new();
        for _ in 0..prealloc { q.push(vec![0u8; chunk].into_boxed_slice()); }
        Self { chunk, free: q, total: AtomicUsize::new(prealloc) }
    }
    pub fn lease(&self) -> Lease {
        if let Some(b) = self.free.pop() { Lease{ buf: Some(b), back: &self.free } }
        else { self.total.fetch_add(1, Ordering::Relaxed); Lease{ buf: Some(vec![0u8; self.chunk].into_boxed_slice()), back: &self.free } }
    }
}
impl Drop for Lease {
    fn drop(&mut self) { unsafe { (&*self.back).push(self.buf.take().unwrap()); } }
}
```


Рекомендации — пункт 1. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 2. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 3. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 4. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 5. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

Рекомендации — пункт 6. Детально: мотивация, алгоритмы, контроль границ, эксплуатация, метрики и грабли.

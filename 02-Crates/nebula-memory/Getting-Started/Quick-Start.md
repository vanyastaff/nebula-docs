---
title: Quick Start
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

# Quick Start

## Открываем scope и аллоцируем в арену

```rust
/// Simplified bump arena
pub struct BumpArena { start: *mut u8, ptr: *mut u8, end: *mut u8 }

impl BumpArena {
    pub fn with_capacity(cap: usize) -> Self { /* mmap/Vec reserve; set pointers */ unimplemented!() }
    #[inline] pub fn alloc(&mut self, n: usize) -> &mut [u8] {
        // check capacity then bump the pointer
        unimplemented!()
    }
    #[inline] pub fn reset(&mut self) { /* ptr = start */ }
    pub fn used(&self) -> usize { (self.ptr as usize) - (self.start as usize) }
    pub fn capacity(&self) -> usize { (self.end as usize) - (self.start as usize) }
}
```


## Пул фиксированных буферов

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


## Byte-budget кэша

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

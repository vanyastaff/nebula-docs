---
title: Hierarchical Pools
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---


## Overview

Hierarchical pools organize memory pools in parent-child relationships, enabling scoped resource management, automatic cleanup, and resource limits at different levels of your application.

## Problem

Complex applications need:

- Resource isolation between components
- Automatic cleanup when components terminate
- Resource limits and quotas per subsystem
- Efficient resource sharing within boundaries
- Prevention of resource leaks across boundaries

## Solution

Create a tree structure of memory pools where child pools borrow from parent pools:

```rust
use nebula_memory::pool::HierarchicalPool;

pub struct ApplicationMemory {
    root_pool: HierarchicalPool<Buffer>,
}

impl ApplicationMemory {
    pub fn new() -> Self {
        // Root pool with global limit
        let root = HierarchicalPool::new()
            .with_capacity(10000)
            .with_name("root");
        
        Self { root_pool: root }
    }
    
    pub fn create_service_pool(&self, name: &str) -> HierarchicalPool<Buffer> {
        self.root_pool.create_child()
            .with_capacity(1000)
            .with_borrow_limit(100)
            .with_name(name)
            .build()
    }
}

// Service gets its own pool
let service_pool = app.create_service_pool("api-service");

// Requests get pools from service
let request_pool = service_pool.create_child()
    .with_capacity(100)
    .build();
```

## Implementation

### Basic Hierarchical Pool

```rust
pub struct HierarchicalPool<T> {
    name: String,
    parent: Option<Weak<RwLock<HierarchicalPool<T>>>>,
    children: Vec<Arc<RwLock<HierarchicalPool<T>>>>,
    
    // Local resources
    local_objects: Vec<T>,
    available: VecDeque<T>,
    in_use: HashMap<usize, T>,
    
    // Limits and quotas
    max_capacity: usize,
    borrow_limit: usize,
    current_borrowed: AtomicUsize,
    
    // Statistics
    stats: PoolStats,
}

impl<T: Poolable> HierarchicalPool<T> {
    pub fn acquire(&self) -> Result<PooledObject<T>> {
        // Try local pool first
        if let Some(obj) = self.available.pop_front() {
            self.stats.local_hit();
            return Ok(PooledObject::new(obj, self.clone()));
        }
        
        // Try borrowing from parent
        if let Some(parent) = &self.parent {
            if self.can_borrow() {
                if let Ok(obj) = parent.acquire() {
                    self.current_borrowed.fetch_add(1, Ordering::Relaxed);
                    self.stats.parent_borrow();
                    return Ok(PooledObject::new(obj, self.clone()));
                }
            }
        }
        
        // Create new if under capacity
        if self.local_objects.len() < self.max_capacity {
            let obj = T::default();
            self.local_objects.push(obj.clone());
            self.stats.allocation();
            return Ok(PooledObject::new(obj, self.clone()));
        }
        
        Err(PoolError::Exhausted)
    }
    
    pub fn release(&self, obj: T) {
        obj.reset();
        
        // Return to parent if borrowed
        if self.is_borrowed(&obj) {
            if let Some(parent) = &self.parent {
                parent.release(obj);
                self.current_borrowed.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }
        
        // Return to local pool
        self.available.push_back(obj);
        self.stats.release();
    }
}
```

### Child Pool Creation

```rust
pub struct ChildPoolBuilder<T> {
    parent: Arc<RwLock<HierarchicalPool<T>>>,
    name: Option<String>,
    capacity: Option<usize>,
    borrow_limit: Option<usize>,
    auto_grow: bool,
}

impl<T> ChildPoolBuilder<T> {
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = Some(capacity);
        self
    }
    
    pub fn with_borrow_limit(mut self, limit: usize) -> Self {
        self.borrow_limit = Some(limit);
        self
    }
    
    pub fn with_auto_grow(mut self) -> Self {
        self.auto_grow = true;
        self
    }
    
    pub fn build(self) -> Arc<RwLock<HierarchicalPool<T>>> {
        let child = HierarchicalPool {
            name: self.name.unwrap_or_else(|| "child".to_string()),
            parent: Some(Arc::downgrade(&self.parent)),
            children: Vec::new(),
            local_objects: Vec::new(),
            available: VecDeque::new(),
            in_use: HashMap::new(),
            max_capacity: self.capacity.unwrap_or(100),
            borrow_limit: self.borrow_limit.unwrap_or(10),
            current_borrowed: AtomicUsize::new(0),
            stats: PoolStats::default(),
        };
        
        let child_arc = Arc::new(RwLock::new(child));
        
        // Register with parent
        self.parent.write().unwrap().children.push(child_arc.clone());
        
        child_arc
    }
}
```

### Resource Propagation

```rust
impl<T: Poolable> HierarchicalPool<T> {
    /// Propagate resources down to children
    pub fn distribute_resources(&self, count: usize) {
        let children_count = self.children.len();
        if children_count == 0 {
            return;
        }
        
        let per_child = count / children_count;
        let remainder = count % children_count;
        
        for (i, child) in self.children.iter().enumerate() {
            let child_count = if i < remainder {
                per_child + 1
            } else {
                per_child
            };
            
            for _ in 0..child_count {
                if let Some(obj) = self.available.pop_front() {
                    child.write().unwrap().available.push_back(obj);
                }
            }
        }
    }
    
    /// Reclaim resources from children
    pub fn reclaim_resources(&mut self) -> usize {
        let mut reclaimed = 0;
        
        for child in &self.children {
            let mut child_pool = child.write().unwrap();
            
            while let Some(obj) = child_pool.available.pop_front() {
                self.available.push_back(obj);
                reclaimed += 1;
            }
        }
        
        reclaimed
    }
}
```

## Advanced Features

### Priority-Based Allocation

```rust
pub struct PriorityHierarchicalPool<T> {
    base: HierarchicalPool<T>,
    child_priorities: HashMap<String, Priority>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

impl<T: Poolable> PriorityHierarchicalPool<T> {
    pub fn acquire_with_priority(&self, priority: Priority) -> Result<T> {
        // Critical priority can steal from children
        if priority == Priority::Critical {
            if let Some(obj) = self.steal_from_children() {
                return Ok(obj);
            }
        }
        
        // Try normal acquisition
        self.base.acquire()
    }
    
    fn steal_from_children(&self) -> Option<T> {
        // Sort children by priority (lowest first)
        let mut children: Vec<_> = self.base.children.iter()
            .map(|c| {
                let priority = self.child_priorities
                    .get(&c.read().unwrap().name)
                    .copied()
                    .unwrap_or(Priority::Normal);
                (priority, c.clone())
            })
            .collect();
        
        children.sort_by_key(|(p, _)| *p);
        
        // Try to steal from lowest priority children
        for (_, child) in children {
            let mut child_pool = child.write().unwrap();
            if let Some(obj) = child_pool.available.pop_front() {
                return Some(obj);
            }
        }
        
        None
    }
}
```

### Automatic Rebalancing

```rust
pub struct RebalancingPool<T> {
    pools: Vec<Arc<RwLock<HierarchicalPool<T>>>>,
    rebalance_threshold: f32,
    rebalance_interval: Duration,
    last_rebalance: Instant,
}

impl<T: Poolable> RebalancingPool<T> {
    pub fn maybe_rebalance(&mut self) {
        if self.last_rebalance.elapsed() < self.rebalance_interval {
            return;
        }
        
        let stats: Vec<_> = self.pools.iter()
            .map(|p| {
                let pool = p.read().unwrap();
                (pool.available.len(), pool.in_use.len())
            })
            .collect();
        
        let total_available: usize = stats.iter().map(|(a, _)| a).sum();
        let total_in_use: usize = stats.iter().map(|(_, u)| u).sum();
        
        if total_available == 0 {
            return;
        }
        
        let utilization = total_in_use as f32 / (total_available + total_in_use) as f32;
        
        if utilization > self.rebalance_threshold {
            self.rebalance(stats);
        }
        
        self.last_rebalance = Instant::now();
    }
    
    fn rebalance(&mut self, stats: Vec<(usize, usize)>) {
        // Calculate target distribution
        let total: usize = stats.iter().map(|(a, u)| a + u).sum();
        let target_per_pool = total / self.pools.len();
        
        let mut surplus_pools = Vec::new();
        let mut deficit_pools = Vec::new();
        
        for (i, (available, in_use)) in stats.iter().enumerate() {
            let current = available + in_use;
            if current > target_per_pool {
                surplus_pools.push((i, current - target_per_pool));
            } else if current < target_per_pool {
                deficit_pools.push((i, target_per_pool - current));
            }
        }
        
        // Transfer resources
        for (surplus_idx, surplus_count) in surplus_pools {
            for (deficit_idx, deficit_count) in &mut deficit_pools {
                if *deficit_count == 0 {
                    continue;
                }
                
                let transfer_count = surplus_count.min(*deficit_count);
                self.transfer_resources(surplus_idx, *deficit_idx, transfer_count);
                *deficit_count -= transfer_count;
            }
        }
    }
}
```

### Pool Lifecycle Management

```rust
pub struct ManagedHierarchicalPool<T> {
    pool: Arc<RwLock<HierarchicalPool<T>>>,
    lifecycle: PoolLifecycle,
    health_checker: Box<dyn Fn(&HierarchicalPool<T>) -> Health>,
}

pub enum PoolLifecycle {
    Starting,
    Warming,
    Active,
    Draining,
    Stopped,
}

impl<T: Poolable> ManagedHierarchicalPool<T> {
    pub async fn start(&mut self) {
        self.lifecycle = PoolLifecycle::Starting;
        
        // Pre-warm pool
        self.lifecycle = PoolLifecycle::Warming;
        self.pre_warm().await;
        
        self.lifecycle = PoolLifecycle::Active;
    }
    
    async fn pre_warm(&self) {
        let pool = self.pool.write().unwrap();
        let warm_count = pool.max_capacity / 2;
        
        for _ in 0..warm_count {
            pool.available.push_back(T::default());
        }
    }
    
    pub async fn drain(&mut self) {
        self.lifecycle = PoolLifecycle::Draining;
        
        // Stop accepting new acquisitions
        // Wait for in-use objects to be released
        while self.pool.read().unwrap().in_use.len() > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        self.lifecycle = PoolLifecycle::Stopped;
    }
}
```

## Usage Examples

### Web Application

```rust
struct WebApplication {
    memory: Arc<HierarchicalPool<Buffer>>,
}

impl WebApplication {
    pub fn new() -> Self {
        let memory = HierarchicalPool::new()
            .with_capacity(10000)
            .with_name("web-app")
            .build();
            
        Self { memory }
    }
    
    pub fn create_service(&self, name: &str) -> Service {
        let service_pool = self.memory.create_child()
            .with_name(name)
            .with_capacity(1000)
            .with_borrow_limit(100)
            .build();
            
        Service::new(service_pool)
    }
}

struct Service {
    memory: Arc<HierarchicalPool<Buffer>>,
}

impl Service {
    pub async fn handle_request(&self, req: Request) -> Response {
        // Each request gets its own pool
        let request_pool = self.memory.create_child()
            .with_capacity(10)
            .with_auto_grow()
            .build();
        
        let buffer = request_pool.acquire()?;
        // Process request...
        
        // Request pool automatically cleaned up
        drop(request_pool);
        
        response
    }
}
```

### Game Engine Subsystems

```rust
struct GameEngine {
    memory: Arc<HierarchicalPool<GameObject>>,
    physics: PhysicsSystem,
    rendering: RenderSystem,
    ai: AISystem,
}

impl GameEngine {
    pub fn new() -> Self {
        let root = HierarchicalPool::new()
            .with_capacity(100000)
            .build();
        
        let physics = PhysicsSystem::new(
            root.create_child()
                .with_name("physics")
                .with_capacity(30000)
                .build()
        );
        
        let rendering = RenderSystem::new(
            root.create_child()
                .with_name("rendering")
                .with_capacity(40000)
                .build()
        );
        
        let ai = AISystem::new(
            root.create_child()
                .with_name("ai")
                .with_capacity(20000)
                .build()
        );
        
        Self {
            memory: root,
            physics,
            rendering,
            ai,
        }
    }
}
```

## Best Practices

1. **Set appropriate borrow limits**:
    
    ```rust
    let child = parent.create_child()
        .with_borrow_limit(parent_capacity * 0.1) // Max 10% from parent
        .build();
    ```
    
2. **Monitor pool health**:
    
    ```rust
    fn check_pool_health(pool: &HierarchicalPool<T>) -> Health {
        let utilization = pool.utilization();
        
        match utilization {
            u if u < 0.5 => Health::Good,
            u if u < 0.8 => Health::Warning,
            _ => Health::Critical,
        }
    }
    ```
    
3. **Implement cleanup strategies**:
    
    ```rust
    impl Drop for ServicePool {
        fn drop(&mut self) {
            // Return borrowed resources to parent
            self.pool.return_all_to_parent();
            
            // Clear local resources
            self.pool.clear();
        }
    }
    ```
    

## See Also

- [Request-Scoped-Memory](https://claude.ai/chat/Request-Scoped-Memory.md)
- [Memory-Isolation](https://claude.ai/chat/Memory-Isolation.md)
- [Resource-Pooling](https://claude.ai/Advanced/Resource-Pooling.md)

---
title: Request Scoped Memory
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

## Overview

Request-scoped memory management ensures each request has isolated memory resources that are automatically cleaned up when the request completes. This pattern is essential for web servers, API services, and any request-response systems.

## Problem

Traditional memory management in request handlers leads to:

- Memory leaks from forgotten deallocations
- Memory fragmentation from many small allocations
- Unpredictable latency from garbage collection
- Cross-request memory pollution

## Solution

Use hierarchical memory pools with request-scoped lifetime:

```rust
use nebula_memory::prelude::*;
use nebula_memory::patterns::RequestScope;

pub struct RequestHandler {
    global_pool: HierarchicalPool<Vec<u8>>,
    global_arena: Arena,
}

impl RequestHandler {
    pub async fn handle_request(&self, req: Request) -> Result<Response> {
        // Create request-scoped memory context
        let scope = RequestScope::new()
            .with_pool(self.global_pool.create_child(100))
            .with_arena(self.global_arena.create_sub_arena(1024 * 1024))
            .with_timeout(Duration::from_secs(30));
        
        // All allocations within scope
        let parsed = scope.alloc(parse_request(&req));
        let validated = scope.alloc(validate_data(parsed));
        let processed = scope.alloc(process_business_logic(validated));
        let response = build_response(processed);
        
        // Automatic cleanup when scope drops
        Ok(response)
    }
}
```

## Implementation

### Basic Request Scope

```rust
pub struct RequestScope {
    id: Uuid,
    pool: LocalPool<Vec<u8>>,
    arena: LocalArena,
    started_at: Instant,
    memory_limit: usize,
    allocations: AtomicUsize,
}

impl RequestScope {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            pool: LocalPool::new(50),
            arena: LocalArena::new(512 * 1024),
            started_at: Instant::now(),
            memory_limit: 10 * 1024 * 1024, // 10MB per request
            allocations: AtomicUsize::new(0),
        }
    }
    
    pub fn alloc<T>(&self, value: T) -> &T {
        self.check_limits();
        self.allocations.fetch_add(
            std::mem::size_of::<T>(),
            Ordering::Relaxed
        );
        self.arena.alloc(value)
    }
    
    fn check_limits(&self) {
        let used = self.allocations.load(Ordering::Relaxed);
        if used > self.memory_limit {
            panic!("Request memory limit exceeded");
        }
        
        if self.started_at.elapsed() > Duration::from_secs(30) {
            panic!("Request timeout");
        }
    }
}
```

### With Async Support

```rust
pub struct AsyncRequestScope {
    inner: Arc<RequestScopeInner>,
    _guard: ScopeGuard,
}

impl AsyncRequestScope {
    pub async fn with<F, Fut, R>(&self, f: F) -> R
    where
        F: FnOnce(ScopeHandle) -> Fut,
        Fut: Future<Output = R>,
    {
        let handle = ScopeHandle::new(self.inner.clone());
        
        // Set task-local scope
        CURRENT_SCOPE.scope(handle.clone(), async move {
            f(handle).await
        }).await
    }
}

// Task-local storage for current scope
task_local! {
    static CURRENT_SCOPE: ScopeHandle;
}

// Use in handlers
async fn process_data() -> Result<Data> {
    let scope = CURRENT_SCOPE.get();
    let buffer = scope.alloc_buffer(1024);
    // Process with scoped memory...
}
```

## Advanced Features

### Memory Pressure Handling

```rust
impl RequestScope {
    pub fn with_pressure_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(MemoryPressure) + Send + Sync + 'static,
    {
        self.pressure_handler = Some(Box::new(handler));
        self
    }
    
    fn handle_pressure(&self) {
        let pressure = self.calculate_pressure();
        
        match pressure {
            MemoryPressure::Low => {},
            MemoryPressure::Medium => {
                self.pool.shrink_to_fit();
            },
            MemoryPressure::High => {
                self.pool.clear();
                if let Some(handler) = &self.pressure_handler {
                    handler(pressure);
                }
            },
            MemoryPressure::Critical => {
                panic!("Critical memory pressure in request");
            }
        }
    }
}
```

### Nested Scopes

```rust
pub struct NestedScope<'parent> {
    parent: &'parent RequestScope,
    local_arena: LocalArena,
    allocations: Vec<*mut u8>,
}

impl RequestScope {
    pub fn create_nested(&self) -> NestedScope {
        NestedScope {
            parent: self,
            local_arena: LocalArena::new(64 * 1024),
            allocations: Vec::new(),
        }
    }
}

// Usage
let request_scope = RequestScope::new();

// Nested scope for validation
{
    let validation_scope = request_scope.create_nested();
    let temp_data = validation_scope.alloc(validate_input(&input));
    // Validation scope cleaned up here
}

// Continue with request scope
let processed = request_scope.alloc(process_data(&input));
```

## Integration Examples

### With Web Framework (Axum)

```rust
use axum::{Extension, extract::Request};
use nebula_memory::patterns::RequestScope;

async fn handler(
    Extension(memory): Extension<Arc<MemorySystem>>,
    request: Request,
) -> Response {
    let scope = memory.create_request_scope();
    
    REQUEST_SCOPE.scope(scope.clone(), async move {
        // Handler logic with scoped memory
        process_request(request).await
    }).await
}

// Middleware to inject scope
async fn memory_middleware(
    req: Request,
    next: Next,
) -> Response {
    let scope = RequestScope::new();
    req.extensions_mut().insert(scope);
    next.run(req).await
}
```

### With gRPC

```rust
impl MyService for MyServiceImpl {
    async fn process(
        &self,
        request: Request<Input>,
    ) -> Result<Response<Output>, Status> {
        let scope = self.memory.create_request_scope()
            .with_memory_limit(5 * 1024 * 1024); // 5MB
        
        let input = scope.alloc(request.into_inner());
        let result = scope.alloc(process_business_logic(input).await?);
        
        Ok(Response::new(result.clone()))
    }
}
```

## Best Practices

1. **Set appropriate limits**:
    
    ```rust
    let scope = RequestScope::new()
        .with_memory_limit(10 * 1024 * 1024)  // 10MB
        .with_timeout(Duration::from_secs(30))
        .with_max_allocations(10000);
    ```
    
2. **Use metrics**:
    
    ```rust
    impl Drop for RequestScope {
        fn drop(&mut self) {
            metrics::record_histogram(
                "request.memory.used",
                self.allocations.load(Ordering::Relaxed) as f64
            );
            metrics::record_histogram(
                "request.duration",
                self.started_at.elapsed().as_secs_f64()
            );
        }
    }
    ```
    
3. **Handle errors gracefully**:
    
    ```rust
    match scope.try_alloc(large_data) {
        Ok(data) => process(data),
        Err(MemoryError::LimitExceeded) => {
            return Err(Response::payload_too_large());
        }
    }
    ```
    
4. **Pre-warm pools**:
    
    ```rust
    // On server startup
    let global_pool = HierarchicalPool::new(1000)
        .with_pre_warming(100); // Pre-create 100 objects
    ```
    

## Performance Characteristics

|Aspect|Performance|Notes|
|---|---|---|
|Allocation|O(1)|Arena bump allocation|
|Deallocation|O(1)|Bulk deallocation on scope drop|
|Memory overhead|Low|~1KB per scope|
|Thread safety|Optional|Use Arc for shared scopes|
|Fragmentation|None|Arena reset removes all fragmentation|

## Monitoring

```rust
pub struct ScopeMetrics {
    requests_total: Counter,
    memory_used_bytes: Histogram,
    allocation_count: Histogram,
    scope_duration_seconds: Histogram,
    memory_limit_exceeded: Counter,
}

impl RequestScope {
    pub fn with_metrics(mut self, metrics: Arc<ScopeMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}
```

## Common Pitfalls

1. **Escaping references**:
    
    ```rust
    // ❌ Wrong - reference escapes scope
    let data = {
        let scope = RequestScope::new();
        scope.alloc(compute_data()) // Reference invalid after scope
    };
    
    // ✅ Correct - clone if needed outside
    let data = {
        let scope = RequestScope::new();
        scope.alloc(compute_data()).clone()
    };
    ```
    
2. **Unbounded growth**:
    
    ```rust
    // ❌ Wrong - no limits
    let scope = RequestScope::new();
    
    // ✅ Correct - set limits
    let scope = RequestScope::new()
        .with_memory_limit(10 * 1024 * 1024);
    ```
    
3. **Forgetting cleanup**:
    
    ```rust
    // ❌ Wrong - manual management
    let scope = RequestScope::new();
    process(scope);
    // Forgot to cleanup!
    
    // ✅ Correct - RAII
    {
        let scope = RequestScope::new();
        process(scope);
    } // Automatic cleanup
    ```
    

## See Also

- [Hierarchical-Pools](https://claude.ai/chat/Hierarchical-Pools.md)
- [Memory-Isolation](https://claude.ai/chat/Memory-Isolation.md)
- [Zero-Copy-Patterns](https://claude.ai/chat/Zero-Copy-Patterns.md)
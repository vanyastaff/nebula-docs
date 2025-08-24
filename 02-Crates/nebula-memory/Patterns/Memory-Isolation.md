---
title: Memory Isolation
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---


## Overview

Memory isolation ensures that different components, modules, or execution contexts have separated memory spaces that cannot interfere with each other. This pattern is crucial for security, stability, and predictable resource usage.

## Problem

Applications need:

- Prevention of memory corruption between components
- Resource limit enforcement per component
- Protection against memory leaks affecting other parts
- Security boundaries between untrusted code
- Predictable memory behavior in multi-tenant systems

## Solution

Create isolated memory contexts with strict boundaries and controlled communication:

```rust
use nebula_memory::isolation::{MemoryIsolation, IsolatedContext};

pub struct IsolatedApplication {
    isolation: MemoryIsolation,
    contexts: HashMap<ContextId, IsolatedContext>,
}

impl IsolatedApplication {
    pub fn create_isolated_context(&mut self, config: ContextConfig) -> ContextId {
        let context = self.isolation.create_context()
            .with_memory_limit(config.memory_limit)
            .with_permissions(config.permissions)
            .with_timeout(config.timeout)
            .build();
        
        let id = ContextId::new();
        self.contexts.insert(id, context);
        id
    }
    
    pub fn execute_in_context<F, R>(&self, id: ContextId, f: F) -> Result<R>
    where
        F: FnOnce(&IsolatedContext) -> R,
    {
        let context = self.contexts.get(&id)
            .ok_or(IsolationError::ContextNotFound)?;
        
        context.execute(f)
    }
}
```

## Implementation

### Basic Memory Isolation

```rust
pub struct IsolatedContext {
    id: ContextId,
    memory_region: MemoryRegion,
    limits: ResourceLimits,
    permissions: MemoryPermissions,
    parent: Option<Weak<IsolatedContext>>,
    stats: IsolationStats,
}

pub struct MemoryRegion {
    base: *mut u8,
    size: usize,
    used: AtomicUsize,
    protection: Protection,
}

pub struct ResourceLimits {
    max_memory: usize,
    max_allocations: usize,
    max_cpu_time: Duration,
    max_io_operations: usize,
}

impl IsolatedContext {
    pub fn allocate(&self, size: usize) -> Result<*mut u8> {
        // Check limits
        if !self.check_limits(size) {
            return Err(IsolationError::LimitExceeded);
        }
        
        // Check permissions
        if !self.permissions.can_allocate {
            return Err(IsolationError::PermissionDenied);
        }
        
        // Allocate within region
        let offset = self.memory_region.used.fetch_add(size, Ordering::SeqCst);
        
        if offset + size > self.memory_region.size {
            self.memory_region.used.fetch_sub(size, Ordering::SeqCst);
            return Err(IsolationError::OutOfMemory);
        }
        
        unsafe {
            Ok(self.memory_region.base.add(offset))
        }
    }
    
    fn check_limits(&self, size: usize) -> bool {
        let current_used = self.memory_region.used.load(Ordering::Relaxed);
        current_used + size <= self.limits.max_memory
    }
}
```

### Process-Level Isolation

```rust
#[cfg(unix)]
pub struct ProcessIsolation {
    contexts: HashMap<ContextId, ProcessContext>,
}

#[cfg(unix)]
pub struct ProcessContext {
    pid: Pid,
    memory_map: MemoryMap,
    communication: IpcChannel,
}

#[cfg(unix)]
impl ProcessIsolation {
    pub fn create_isolated_process(&mut self) -> Result<ContextId> {
        use nix::unistd::{fork, ForkResult};
        use nix::sys::mman::{mmap, ProtFlags, MapFlags};
        
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                let context = ProcessContext {
                    pid: child,
                    memory_map: MemoryMap::new(child)?,
                    communication: IpcChannel::new()?,
                };
                
                let id = ContextId::new();
                self.contexts.insert(id, context);
                Ok(id)
            }
            ForkResult::Child => {
                // Set up child process isolation
                self.setup_child_isolation()?;
                
                // Child process main loop
                self.child_main_loop();
                
                std::process::exit(0);
            }
        }
    }
    
    fn setup_child_isolation(&self) -> Result<()> {
        // Set resource limits
        use nix::sys::resource::{setrlimit, Resource, Rlimit};
        
        setrlimit(
            Resource::RLIMIT_AS,
            &Rlimit {
                rlim_cur: 100 * 1024 * 1024, // 100MB
                rlim_max: 100 * 1024 * 1024,
            }
        )?;
        
        // Drop privileges
        self.drop_privileges()?;
        
        Ok(())
    }
}
```

### WASM-Based Isolation

```rust
#[cfg(feature = "wasm")]
pub struct WasmIsolation {
    engine: wasmtime::Engine,
    contexts: HashMap<ContextId, WasmContext>,
}

#[cfg(feature = "wasm")]
pub struct WasmContext {
    store: wasmtime::Store<ContextData>,
    instance: wasmtime::Instance,
    memory: wasmtime::Memory,
    limits: wasmtime::StoreLimits,
}

#[cfg(feature = "wasm")]
impl WasmIsolation {
    pub fn create_wasm_context(&mut self, wasm_module: &[u8]) -> Result<ContextId> {
        let module = wasmtime::Module::new(&self.engine, wasm_module)?;
        
        // Configure limits
        let mut config = wasmtime::Config::new();
        config.wasm_reference_types(false);
        config.wasm_bulk_memory(false);
        config.memory_init_cow(false);
        
        let engine = wasmtime::Engine::new(&config)?;
        let mut store = wasmtime::Store::new(&engine, ContextData::default());
        
        // Set memory limits
        store.limiter(|data| &mut data.limits);
        store.data_mut().limits = wasmtime::StoreLimits::new(
            Some(10 * 1024 * 1024), // 10MB memory limit
            Some(1000000),           // 1M instructions
            Some(100),               // 100 instances
            Some(10),                // 10 tables
            Some(1000),              // 1000 table elements
            Some(10 * 1024 * 1024),  // 10MB memories
        );
        
        let instance = wasmtime::Instance::new(&mut store, &module, &[])?;
        let memory = instance.get_memory(&mut store, "memory")
            .ok_or(IsolationError::NoMemoryExport)?;
        
        let context = WasmContext {
            store,
            instance,
            memory,
            limits: Default::default(),
        };
        
        let id = ContextId::new();
        self.contexts.insert(id, context);
        Ok(id)
    }
    
    pub fn execute_in_wasm<F, R>(&mut self, id: ContextId, f: F) -> Result<R>
    where
        F: FnOnce(&mut WasmContext) -> R,
    {
        let context = self.contexts.get_mut(&id)
            .ok_or(IsolationError::ContextNotFound)?;
        
        Ok(f(context))
    }
}
```

### Thread-Level Isolation

```rust
pub struct ThreadIsolation {
    thread_locals: ThreadLocal<IsolatedContext>,
    global_limits: GlobalLimits,
}

thread_local! {
    static CURRENT_CONTEXT: RefCell<Option<Arc<IsolatedContext>>> = RefCell::new(None);
}

impl ThreadIsolation {
    pub fn run_isolated<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        std::thread::spawn(move || {
            // Create thread-local isolated context
            let context = Arc::new(IsolatedContext::new_thread_local());
            
            CURRENT_CONTEXT.with(|c| {
                *c.borrow_mut() = Some(context.clone());
            });
            
            // Set thread priority and affinity
            Self::configure_thread();
            
            // Execute function in isolated context
            let result = f();
            
            // Cleanup
            CURRENT_CONTEXT.with(|c| {
                *c.borrow_mut() = None;
            });
            
            result
        }).join().map_err(|_| IsolationError::ThreadPanicked)
    }
    
    #[cfg(unix)]
    fn configure_thread() {
        use nix::sched::{setaffinity, CpuSet};
        use nix::unistd::Pid;
        
        // Pin to specific CPU
        let mut cpu_set = CpuSet::new();
        cpu_set.set(0).unwrap();
        setaffinity(Pid::from_raw(0), &cpu_set).ok();
        
        // Set thread priority
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
        }
    }
}
```

## Advanced Features

### Memory Sandbox

```rust
pub struct MemorySandbox {
    regions: Vec<SandboxRegion>,
    page_table: PageTable,
    violation_handler: Box<dyn Fn(ViolationInfo)>,
}

pub struct SandboxRegion {
    start: usize,
    end: usize,
    permissions: Permissions,
    owner: ContextId,
}

impl MemorySandbox {
    pub fn create_region(&mut self, size: usize, perms: Permissions) -> SandboxRegion {
        let region = self.allocate_region(size);
        
        // Set page permissions
        self.page_table.set_permissions(
            region.start,
            region.end,
            perms,
        );
        
        // Install guard pages
        self.install_guard_pages(&region);
        
        region
    }
    
    fn install_guard_pages(&mut self, region: &SandboxRegion) {
        // Guard page before region
        self.page_table.set_permissions(
            region.start - PAGE_SIZE,
            region.start,
            Permissions::NONE,
        );
        
        // Guard page after region
        self.page_table.set_permissions(
            region.end,
            region.end + PAGE_SIZE,
            Permissions::NONE,
        );
    }
    
    pub fn check_access(&self, ptr: *const u8, size: usize) -> Result<()> {
        let addr = ptr as usize;
        
        for region in &self.regions {
            if addr >= region.start && addr + size <= region.end {
                return Ok(());
            }
        }
        
        let violation = ViolationInfo {
            address: addr,
            size,
            context: self.current_context(),
            timestamp: Instant::now(),
        };
        
        (self.violation_handler)(violation);
        Err(IsolationError::AccessViolation)
    }
}
```

### Cross-Context Communication

```rust
pub struct IsolatedChannel<T> {
    sender: ContextId,
    receiver: ContextId,
    buffer: Arc<Mutex<VecDeque<Message<T>>>>,
    capacity: usize,
}

pub struct Message<T> {
    data: T,
    sender: ContextId,
    timestamp: Instant,
}

impl<T: Clone> IsolatedChannel<T> {
    pub fn send(&self, data: T) -> Result<()> {
        // Verify sender context
        if self.current_context() != self.sender {
            return Err(IsolationError::UnauthorizedSender);
        }
        
        let mut buffer = self.buffer.lock().unwrap();
        
        if buffer.len() >= self.capacity {
            return Err(IsolationError::ChannelFull);
        }
        
        // Deep copy data for isolation
        let isolated_data = self.deep_copy(data)?;
        
        buffer.push_back(Message {
            data: isolated_data,
            sender: self.sender,
            timestamp: Instant::now(),
        });
        
        Ok(())
    }
    
    pub fn receive(&self) -> Result<T> {
        // Verify receiver context
        if self.current_context() != self.receiver {
            return Err(IsolationError::UnauthorizedReceiver);
        }
        
        let mut buffer = self.buffer.lock().unwrap();
        
        buffer.pop_front()
            .map(|msg| msg.data)
            .ok_or(IsolationError::ChannelEmpty)
    }
    
    fn deep_copy(&self, data: T) -> Result<T> {
        // Serialize and deserialize to ensure complete isolation
        let bytes = bincode::serialize(&data)?;
        Ok(bincode::deserialize(&bytes)?)
    }
}
```

### Capability-Based Security

```rust
pub struct Capability {
    id: CapabilityId,
    resource: ResourceId,
    permissions: Permissions,
    expiry: Option<Instant>,
    uses_remaining: Option<usize>,
}

pub struct CapabilitySystem {
    capabilities: HashMap<CapabilityId, Capability>,
    contexts: HashMap<ContextId, HashSet<CapabilityId>>,
}

impl CapabilitySystem {
    pub fn grant_capability(
        &mut self,
        context: ContextId,
        resource: ResourceId,
        permissions: Permissions,
    ) -> CapabilityId {
        let cap = Capability {
            id: CapabilityId::new(),
            resource,
            permissions,
            expiry: Some(Instant::now() + Duration::from_secs(3600)),
            uses_remaining: Some(100),
        };
        
        let id = cap.id;
        self.capabilities.insert(id, cap);
        self.contexts.entry(context)
            .or_insert_with(HashSet::new)
            .insert(id);
        
        id
    }
    
    pub fn check_capability(
        &self,
        context: ContextId,
        capability: CapabilityId,
        requested: Permissions,
    ) -> Result<()> {
        // Check if context has capability
        let context_caps = self.contexts.get(&context)
            .ok_or(IsolationError::ContextNotFound)?;
        
        if !context_caps.contains(&capability) {
            return Err(IsolationError::CapabilityNotOwned);
        }
        
        // Check capability details
        let cap = self.capabilities.get(&capability)
            .ok_or(IsolationError::CapabilityNotFound)?;
        
        // Check expiry
        if let Some(expiry) = cap.expiry {
            if Instant::now() > expiry {
                return Err(IsolationError::CapabilityExpired);
            }
        }
        
        // Check uses
        if let Some(uses) = cap.uses_remaining {
            if uses == 0 {
                return Err(IsolationError::CapabilityExhausted);
            }
        }
        
        // Check permissions
        if !cap.permissions.contains(requested) {
            return Err(IsolationError::InsufficientPermissions);
        }
        
        Ok(())
    }
}
```

## Usage Examples

### Multi-Tenant Application

```rust
pub struct MultiTenantApp {
    isolation: MemoryIsolation,
    tenants: HashMap<TenantId, TenantContext>,
}

impl MultiTenantApp {
    pub fn create_tenant(&mut self, config: TenantConfig) -> TenantId {
        let context = self.isolation.create_context()
            .with_memory_limit(config.memory_limit)
            .with_cpu_limit(config.cpu_limit)
            .with_io_limit(config.io_limit)
            .build();
        
        let tenant = TenantContext {
            id: TenantId::new(),
            context,
            data: TenantData::new(),
        };
        
        let id = tenant.id;
        self.tenants.insert(id, tenant);
        id
    }
    
    pub fn execute_tenant_code<F, R>(
        &self,
        tenant: TenantId,
        code: F,
    ) -> Result<R>
    where
        F: FnOnce() -> R,
    {
        let tenant_ctx = self.tenants.get(&tenant)
            .ok_or(IsolationError::TenantNotFound)?;
        
        tenant_ctx.context.execute(|| {
            // Set current tenant context
            CURRENT_TENANT.with(|t| {
                *t.borrow_mut() = Some(tenant);
            });
            
            // Execute with monitoring
            let start = Instant::now();
            let result = code();
            let duration = start.elapsed();
            
            // Record metrics
            self.record_tenant_metrics(tenant, duration);
            
            result
        })
    }
}
```

## Best Practices

1. **Use appropriate isolation level**:
    
    ```rust
    match security_requirements {
        SecurityLevel::Low => ThreadIsolation::new(),
        SecurityLevel::Medium => ProcessIsolation::new(),
        SecurityLevel::High => WasmIsolation::new(),
        SecurityLevel::Critical => HardwareIsolation::new(),
    }
    ```
    
2. **Monitor resource usage**:
    
    ```rust
    context.set_monitor(|stats| {
        if stats.memory_used > stats.memory_limit * 0.9 {
            log::warn!("Context {} approaching memory limit", stats.context_id);
        }
    });
    ```
    
3. **Handle violations gracefully**:
    
    ```rust
    sandbox.set_violation_handler(|violation| {
        log::error!("Memory violation: {:?}", violation);
        
        // Terminate offending context
        isolation.terminate_context(violation.context);
        
        // Alert administrators
        alert_system.send_alert(Alert::SecurityViolation(violation));
    });
    ```
    

## See Also

- [Request-Scoped-Memory](https://claude.ai/chat/Request-Scoped-Memory.md)
- [Hierarchical-Pools](https://claude.ai/chat/Hierarchical-Pools.md)
- [Security Best Practices](https://claude.ai/Advanced/Security.md)

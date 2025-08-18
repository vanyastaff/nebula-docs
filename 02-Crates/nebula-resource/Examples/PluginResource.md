---
title: Example: PluginResource
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Example: PluginResource

> Динамическая загрузка ресурсов через plugin систему с hot-reload и sandboxing

## Overview

PluginResource позволяет расширять nebula-resource во время выполнения через динамически загружаемые плагины. Поддерживает hot-reload, версионирование, dependency resolution и безопасное выполнение в sandbox.

## Implementation

```rust
use nebula_resource::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use libloading::{Library, Symbol};
use notify::{Watcher, RecursiveMode, DebouncedEvent};
use std::time::{Duration, SystemTime};
use semver::{Version, VersionReq};

/// Plugin Resource - динамически загружаемые ресурсы
#[derive(Resource)]
#[resource(
    id = "plugin_manager",
    name = "Plugin Resource Manager",
    singleton = true
)]
pub struct PluginResource;

/// Plugin manager configuration
#[derive(ResourceConfig, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    /// Directory containing plugins
    pub plugin_dir: PathBuf,
    
    /// Enable hot reload
    #[serde(default = "default_true")]
    pub hot_reload: bool,
    
    /// Plugin discovery strategy
    #[serde(default)]
    pub discovery: DiscoveryStrategy,
    
    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,
    
    /// Plugin loading strategy
    #[serde(default)]
    pub loading: LoadingStrategy,
    
    /// Global plugin configuration
    #[serde(default)]
    pub global_config: HashMap<String, serde_json::Value>,
    
    /// Plugin timeout
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    
    /// Maximum memory per plugin (bytes)
    #[serde(default = "default_memory_limit")]
    pub memory_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryStrategy {
    /// Scan directory for .so/.dll/.dylib files
    FileSystem { 
        pattern: String,
        recursive: bool,
    },
    
    /// Load from manifest file
    Manifest { 
        path: PathBuf 
    },
    
    /// Discover from registry service
    Registry { 
        url: String,
        auth: Option<String>,
    },
    
    /// Explicit list of plugins
    Explicit { 
        plugins: Vec<PluginDescriptor> 
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable signature verification
    pub verify_signature: bool,
    
    /// Trusted signing keys
    pub trusted_keys: Vec<String>,
    
    /// Sandbox mode
    pub sandbox: SandboxMode,
    
    /// Allowed capabilities
    pub capabilities: Vec<PluginCapability>,
    
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxMode {
    /// No sandboxing
    None,
    
    /// Basic process isolation
    Process,
    
    /// WebAssembly sandbox
    Wasm,
    
    /// Container-based isolation
    Container { runtime: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    Network,
    FileSystem,
    ProcessSpawn,
    MemoryAllocation,
    SystemCalls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory: usize,
    pub max_cpu_percent: f32,
    pub max_file_handles: usize,
    pub max_threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoadingStrategy {
    /// Load all plugins at startup
    Eager,
    
    /// Load plugins on first use
    Lazy,
    
    /// Load based on priority
    Priority { threshold: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDescriptor {
    pub id: String,
    pub name: String,
    pub version: Version,
    pub path: PathBuf,
    pub dependencies: Vec<PluginDependency>,
    pub metadata: PluginMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub plugin_id: String,
    pub version_req: VersionReq,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub author: String,
    pub description: String,
    pub license: String,
    pub homepage: Option<String>,
    pub tags: Vec<String>,
    pub min_nebula_version: Option<Version>,
    pub max_nebula_version: Option<Version>,
}

/// Plugin instance manager
pub struct PluginInstance {
    config: PluginConfig,
    plugins: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
    registry: Arc<RwLock<PluginRegistry>>,
    file_watcher: Option<notify::RecommendedWatcher>,
    metrics: Arc<PluginMetrics>,
    shutdown: Arc<RwLock<bool>>,
}

/// Loaded plugin
struct LoadedPlugin {
    descriptor: PluginDescriptor,
    library: Arc<Library>,
    instance: Arc<dyn DynamicResource>,
    state: PluginState,
    loaded_at: SystemTime,
    reload_count: u32,
    last_used: SystemTime,
    metrics: PluginInstanceMetrics,
}

/// Plugin state
#[derive(Debug, Clone)]
enum PluginState {
    Loaded,
    Active,
    Suspended,
    Failed(String),
    Unloading,
}

/// Plugin registry
struct PluginRegistry {
    plugins: HashMap<String, PluginDescriptor>,
    dependencies: HashMap<String, Vec<String>>,
    load_order: Vec<String>,
}

/// Dynamic resource trait that plugins must implement
pub trait DynamicResource: Send + Sync {
    /// Initialize the resource
    fn initialize(&self, config: &serde_json::Value) -> Result<(), PluginError>;
    
    /// Get resource metadata
    fn metadata(&self) -> ResourceMetadata;
    
    /// Execute resource operation
    fn execute(&self, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, PluginError>;
    
    /// Health check
    fn health_check(&self) -> Result<HealthStatus, PluginError>;
    
    /// Cleanup resource
    fn cleanup(&self) -> Result<(), PluginError>;
}

/// Plugin API version
pub const PLUGIN_API_VERSION: u32 = 1;

/// Plugin entry point type
pub type PluginEntryPoint = unsafe extern "C" fn() -> *mut dyn DynamicResource;

/// Resource implementation
#[async_trait]
impl Resource for PluginResource {
    type Config = PluginConfig;
    type Instance = PluginInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        let instance = PluginInstance {
            config: config.clone(),
            plugins: Arc::new(RwLock::new(HashMap::new())),
            registry: Arc::new(RwLock::new(PluginRegistry::new())),
            file_watcher: None,
            metrics: Arc::new(PluginMetrics::new()),
            shutdown: Arc::new(RwLock::new(false)),
        };
        
        // Discover plugins
        instance.discover_plugins().await?;
        
        // Load plugins based on strategy
        match &config.loading {
            LoadingStrategy::Eager => {
                instance.load_all_plugins().await?;
            }
            LoadingStrategy::Priority { threshold } => {
                instance.load_priority_plugins(*threshold).await?;
            }
            LoadingStrategy::Lazy => {
                // Plugins will be loaded on first use
            }
        }
        
        // Setup hot reload if enabled
        if config.hot_reload {
            instance.setup_file_watcher()?;
        }
        
        Ok(instance)
    }
}

impl PluginInstance {
    /// Discover available plugins
    async fn discover_plugins(&self) -> Result<(), PluginError> {
        let descriptors = match &self.config.discovery {
            DiscoveryStrategy::FileSystem { pattern, recursive } => {
                self.discover_filesystem(pattern, *recursive).await?
            }
            DiscoveryStrategy::Manifest { path } => {
                self.load_manifest(path).await?
            }
            DiscoveryStrategy::Registry { url, auth } => {
                self.fetch_from_registry(url, auth.as_ref()).await?
            }
            DiscoveryStrategy::Explicit { plugins } => {
                plugins.clone()
            }
        };
        
        // Register discovered plugins
        let mut registry = self.registry.write().await;
        for descriptor in descriptors {
            registry.register(descriptor)?;
        }
        
        // Resolve dependencies and determine load order
        registry.resolve_dependencies()?;
        
        Ok(())
    }
    
    /// Discover plugins from filesystem
    async fn discover_filesystem(
        &self,
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<PluginDescriptor>, PluginError> {
        let mut descriptors = Vec::new();
        
        let walker = if recursive {
            walkdir::WalkDir::new(&self.config.plugin_dir)
        } else {
            walkdir::WalkDir::new(&self.config.plugin_dir).max_depth(1)
        };
        
        for entry in walker {
            let entry = entry.map_err(|e| PluginError::Discovery(e.to_string()))?;
            let path = entry.path();
            
            // Check if file matches pattern
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if glob::Pattern::new(pattern)
                    .map_err(|e| PluginError::Discovery(e.to_string()))?
                    .matches(&name_str)
                {
                    // Load plugin metadata
                    if let Ok(descriptor) = self.load_plugin_metadata(path).await {
                        descriptors.push(descriptor);
                    }
                }
            }
        }
        
        Ok(descriptors)
    }
    
    /// Load plugin metadata
    async fn load_plugin_metadata(&self, path: &Path) -> Result<PluginDescriptor, PluginError> {
        // Look for metadata file (plugin.toml or plugin.json)
        let metadata_path = path.with_extension("toml");
        
        if metadata_path.exists() {
            let content = tokio::fs::read_to_string(&metadata_path).await
                .map_err(|e| PluginError::MetadataLoad(e.to_string()))?;
            
            toml::from_str(&content)
                .map_err(|e| PluginError::MetadataLoad(e.to_string()))
        } else {
            // Try to extract metadata from the plugin itself
            self.extract_embedded_metadata(path).await
        }
    }
    
    /// Extract embedded metadata from plugin
    async fn extract_embedded_metadata(&self, path: &Path) -> Result<PluginDescriptor, PluginError> {
        // Temporarily load the library to extract metadata
        unsafe {
            let lib = Library::new(path)
                .map_err(|e| PluginError::LoadFailed(e.to_string()))?;
            
            let metadata_fn: Symbol<unsafe extern "C" fn() -> *const u8> = 
                lib.get(b"plugin_metadata")
                    .map_err(|e| PluginError::SymbolNotFound("plugin_metadata".to_string()))?;
            
            let metadata_ptr = metadata_fn();
            let metadata_cstr = std::ffi::CStr::from_ptr(metadata_ptr as *const i8);
            let metadata_str = metadata_cstr.to_str()
                .map_err(|e| PluginError::MetadataLoad(e.to_string()))?;
            
            serde_json::from_str(metadata_str)
                .map_err(|e| PluginError::MetadataLoad(e.to_string()))
        }
    }
    
    /// Load all plugins
    async fn load_all_plugins(&self) -> Result<(), PluginError> {
        let registry = self.registry.read().await;
        let load_order = registry.load_order.clone();
        drop(registry);
        
        for plugin_id in load_order {
            self.load_plugin(&plugin_id).await?;
        }
        
        Ok(())
    }
    
    /// Load priority plugins
    async fn load_priority_plugins(&self, threshold: u32) -> Result<(), PluginError> {
        let registry = self.registry.read().await;
        
        for (plugin_id, descriptor) in &registry.plugins {
            // Check priority in metadata
            if let Some(priority) = descriptor.metadata.tags.iter()
                .find(|t| t.starts_with("priority:"))
                .and_then(|t| t.strip_prefix("priority:"))
                .and_then(|p| p.parse::<u32>().ok())
            {
                if priority >= threshold {
                    drop(registry);
                    self.load_plugin(plugin_id).await?;
                    return Ok(());
                }
            }
        }
        
        Ok(())
    }
    
    /// Load a specific plugin
    pub async fn load_plugin(&self, plugin_id: &str) -> Result<(), PluginError> {
        // Check if already loaded
        {
            let plugins = self.plugins.read().await;
            if plugins.contains_key(plugin_id) {
                return Ok(());
            }
        }
        
        // Get plugin descriptor
        let descriptor = {
            let registry = self.registry.read().await;
            registry.plugins.get(plugin_id)
                .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?
                .clone()
        };
        
        // Verify signature if required
        if self.config.security.verify_signature {
            self.verify_plugin_signature(&descriptor).await?;
        }
        
        // Load the dynamic library
        let library = unsafe {
            Library::new(&descriptor.path)
                .map_err(|e| PluginError::LoadFailed(e.to_string()))?
        };
        
        // Get entry point
        let entry_point: Symbol<PluginEntryPoint> = unsafe {
            library.get(b"plugin_entry")
                .map_err(|e| PluginError::SymbolNotFound("plugin_entry".to_string()))?
        };
        
        // Create plugin instance
        let instance = unsafe {
            let raw_instance = entry_point();
            Arc::from_raw(raw_instance)
        };
        
        // Initialize plugin with config
        let plugin_config = self.config.global_config.get(plugin_id)
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
        
        instance.initialize(&plugin_config)?;
        
        // Create loaded plugin entry
        let loaded = LoadedPlugin {
            descriptor: descriptor.clone(),
            library: Arc::new(library),
            instance,
            state: PluginState::Loaded,
            loaded_at: SystemTime::now(),
            reload_count: 0,
            last_used: SystemTime::now(),
            metrics: PluginInstanceMetrics::new(),
        };
        
        // Store loaded plugin
        let mut plugins = self.plugins.write().await;
        plugins.insert(plugin_id.to_string(), loaded);
        
        self.metrics.record_load(plugin_id);
        info!("Loaded plugin: {}", plugin_id);
        
        Ok(())
    }
    
    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_id: &str) -> Result<(), PluginError> {
        let mut plugins = self.plugins.write().await;
        
        if let Some(mut plugin) = plugins.remove(plugin_id) {
            // Mark as unloading
            plugin.state = PluginState::Unloading;
            
            // Cleanup plugin
            plugin.instance.cleanup()?;
            
            // Drop the instance and library
            drop(plugin.instance);
            drop(plugin.library);
            
            self.metrics.record_unload(plugin_id);
            info!("Unloaded plugin: {}", plugin_id);
        }
        
        Ok(())
    }
    
    /// Reload a plugin (hot reload)
    pub async fn reload_plugin(&self, plugin_id: &str) -> Result<(), PluginError> {
        info!("Reloading plugin: {}", plugin_id);
        
        // Save current state if needed
        let state = self.save_plugin_state(plugin_id).await?;
        
        // Unload the plugin
        self.unload_plugin(plugin_id).await?;
        
        // Reload with new version
        self.load_plugin(plugin_id).await?;
        
        // Restore state if applicable
        self.restore_plugin_state(plugin_id, state).await?;
        
        // Update reload count
        let mut plugins = self.plugins.write().await;
        if let Some(plugin) = plugins.get_mut(plugin_id) {
            plugin.reload_count += 1;
        }
        
        Ok(())
    }
    
    /// Execute plugin operation
    pub async fn execute(
        &self,
        plugin_id: &str,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, PluginError> {
        // Load plugin if needed (lazy loading)
        if !self.plugins.read().await.contains_key(plugin_id) {
            self.load_plugin(plugin_id).await?;
        }
        
        // Get plugin
        let plugins = self.plugins.read().await;
        let plugin = plugins.get(plugin_id)
            .ok_or_else(|| PluginError::NotFound(plugin_id.to_string()))?;
        
        // Check plugin state
        match &plugin.state {
            PluginState::Failed(err) => {
                return Err(PluginError::ExecutionFailed(err.clone()));
            }
            PluginState::Unloading => {
                return Err(PluginError::ExecutionFailed("Plugin is unloading".to_string()));
            }
            _ => {}
        }
        
        // Execute in sandbox if configured
        let result = match &self.config.security.sandbox {
            SandboxMode::None => {
                // Direct execution
                plugin.instance.execute(operation, params)
            }
            SandboxMode::Process => {
                // Execute in separate process
                self.execute_in_process(plugin, operation, params).await
            }
            SandboxMode::Wasm => {
                // Execute in WASM runtime
                self.execute_in_wasm(plugin, operation, params).await
            }
            SandboxMode::Container { runtime } => {
                // Execute in container
                self.execute_in_container(plugin, operation, params, runtime).await
            }
        };
        
        // Update metrics
        plugin.metrics.record_execution(operation, result.is_ok());
        
        result
    }
    
    /// Setup file watcher for hot reload
    fn setup_file_watcher(&mut self) -> Result<(), PluginError> {
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut watcher = notify::watcher(tx, Duration::from_secs(2))
            .map_err(|e| PluginError::WatcherFailed(e.to_string()))?;
        
        watcher.watch(&self.config.plugin_dir, RecursiveMode::Recursive)
            .map_err(|e| PluginError::WatcherFailed(e.to_string()))?;
        
        let plugins = self.plugins.clone();
        let registry = self.registry.clone();
        
        // Spawn watcher thread
        tokio::spawn(async move {
            loop {
                match rx.recv() {
                    Ok(DebouncedEvent::Write(path)) | 
                    Ok(DebouncedEvent::Create(path)) => {
                        // Check if it's a plugin file
                        if let Some(plugin_id) = Self::path_to_plugin_id(&path).await {
                            info!("Plugin file changed: {:?}", path);
                            
                            // Trigger reload
                            // Note: In real implementation, this would call reload_plugin
                        }
                    }
                    Ok(DebouncedEvent::Remove(path)) => {
                        if let Some(plugin_id) = Self::path_to_plugin_id(&path).await {
                            info!("Plugin file removed: {:?}", path);
                            
                            // Trigger unload
                            // Note: In real implementation, this would call unload_plugin
                        }
                    }
                    _ => {}
                }
            }
        });
        
        self.file_watcher = Some(watcher);
        Ok(())
    }
    
    /// Map file path to plugin ID
    async fn path_to_plugin_id(path: &Path) -> Option<String> {
        // Extract plugin ID from filename
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    }
    
    /// Verify plugin signature
    async fn verify_plugin_signature(&self, descriptor: &PluginDescriptor) -> Result<(), PluginError> {
        // Implementation would verify digital signature
        // using trusted keys from config
        Ok(())
    }
    
    /// Save plugin state before reload
    async fn save_plugin_state(&self, plugin_id: &str) -> Result<serde_json::Value, PluginError> {
        let plugins = self.plugins.read().await;
        
        if let Some(plugin) = plugins.get(plugin_id) {
            plugin.instance.execute("save_state", &serde_json::Value::Null)
        } else {
            Ok(serde_json::Value::Null)
        }
    }
    
    /// Restore plugin state after reload
    async fn restore_plugin_state(
        &self,
        plugin_id: &str,
        state: serde_json::Value,
    ) -> Result<(), PluginError> {
        let plugins = self.plugins.read().await;
        
        if let Some(plugin) = plugins.get(plugin_id) {
            plugin.instance.execute("restore_state", &state)?;
        }
        
        Ok(())
    }
    
    /// Execute in separate process
    async fn execute_in_process(
        &self,
        plugin: &LoadedPlugin,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, PluginError> {
        // Spawn process with limited resources
        let output = tokio::process::Command::new("nebula-plugin-runner")
            .arg(&plugin.descriptor.path)
            .arg(operation)
            .arg(params.to_string())
            .output()
            .await
            .map_err(|e| PluginError::ExecutionFailed(e.to_string()))?;
        
        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            serde_json::from_str(&result)
                .map_err(|e| PluginError::ExecutionFailed(e.to_string()))
        } else {
            let error = String::from_utf8_lossy(&output.stderr);
            Err(PluginError::ExecutionFailed(error.to_string()))
        }
    }
    
    /// Execute in WASM runtime
    async fn execute_in_wasm(
        &self,
        plugin: &LoadedPlugin,
        operation: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, PluginError> {
        // Would use wasmtime or wasmer for execution
        todo!("WASM execution not implemented")
    }
    
    /// Execute in container
    async fn execute_in_container(
        &self,
        plugin: &LoadedPlugin,
        operation: &str,
        params: &serde_json::Value,
        runtime: &str,
    ) -> Result<serde_json::Value, PluginError> {
        // Would use Docker/Podman API for execution
        todo!("Container execution not implemented")
    }
    
    /// List loaded plugins
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        
        plugins.values().map(|plugin| PluginInfo {
            id: plugin.descriptor.id.clone(),
            name: plugin.descriptor.name.clone(),
            version: plugin.descriptor.version.clone(),
            state: format!("{:?}", plugin.state),
            loaded_at: plugin.loaded_at,
            reload_count: plugin.reload_count,
            last_used: plugin.last_used,
        }).collect()
    }
    
    /// Get plugin health status
    pub async fn plugin_health(&self, plugin_id: &str) -> Result<HealthStatus, PluginError> {
        let plugins = self.plugins.read().await;
        
        if let Some(plugin) = plugins.get(plugin_id) {
            plugin.instance.health_check()
        } else {
            Err(PluginError::NotFound(plugin_id.to_string()))
        }
    }
}

/// Plugin registry implementation
impl PluginRegistry {
    fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            dependencies: HashMap::new(),
            load_order: Vec::new(),
        }
    }
    
    fn register(&mut self, descriptor: PluginDescriptor) -> Result<(), PluginError> {
        // Check for conflicts
        if let Some(existing) = self.plugins.get(&descriptor.id) {
            if existing.version != descriptor.version {
                return Err(PluginError::VersionConflict {
                    plugin: descriptor.id.clone(),
                    existing: existing.version.clone(),
                    requested: descriptor.version.clone(),
                });
            }
        }
        
        // Register dependencies
        for dep in &descriptor.dependencies {
            self.dependencies.entry(descriptor.id.clone())
                .or_insert_with(Vec::new)
                .push(dep.plugin_id.clone());
        }
        
        self.plugins.insert(descriptor.id.clone(), descriptor);
        Ok(())
    }
    
    fn resolve_dependencies(&mut self) -> Result<(), PluginError> {
        // Topological sort for load order
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        
        for plugin_id in self.plugins.keys() {
            if !visited.contains(plugin_id) {
                self.visit(plugin_id, &mut visited, &mut stack)?;
            }
        }
        
        self.load_order = stack;
        Ok(())
    }
    
    fn visit(
        &self,
        plugin_id: &str,
        visited: &mut HashSet<String>,
        stack: &mut Vec<String>,
    ) -> Result<(), PluginError> {
        visited.insert(plugin_id.to_string());
        
        if let Some(deps) = self.dependencies.get(plugin_id) {
            for dep in deps {
                if !visited.contains(dep) {
                    self.visit(dep, visited, stack)?;
                }
            }
        }
        
        stack.push(plugin_id.to_string());
        Ok(())
    }
}

/// Plugin metrics
struct PluginMetrics {
    loads_total: AtomicU64,
    unloads_total: AtomicU64,
    reloads_total: AtomicU64,
    executions_total: AtomicU64,
    failures_total: AtomicU64,
}

impl PluginMetrics {
    fn new() -> Self {
        Self {
            loads_total: AtomicU64::new(0),
            unloads_total: AtomicU64::new(0),
            reloads_total: AtomicU64::new(0),
            executions_total: AtomicU64::new(0),
            failures_total: AtomicU64::new(0),
        }
    }
    
    fn record_load(&self, _plugin_id: &str) {
        self.loads_total.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_unload(&self, _plugin_id: &str) {
        self.unloads_total.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-plugin metrics
struct PluginInstanceMetrics {
    executions: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    total_duration: AtomicU64,
}

impl PluginInstanceMetrics {
    fn new() -> Self {
        Self {
            executions: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            total_duration: AtomicU64::new(0),
        }
    }
    
    fn record_execution(&self, _operation: &str, success: bool) {
        self.executions.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Plugin info for listing
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: Version,
    pub state: String,
    pub loaded_at: SystemTime,
    pub reload_count: u32,
    pub last_used: SystemTime,
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),
    
    #[error("Plugin load failed: {0}")]
    LoadFailed(String),
    
    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),
    
    #[error("Version conflict for {plugin}: existing {existing}, requested {requested}")]
    VersionConflict {
        plugin: String,
        existing: Version,
        requested: Version,
    },
    
    #[error("Discovery failed: {0}")]
    Discovery(String),
    
    #[error("Metadata load failed: {0}")]
    MetadataLoad(String),
    
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Watcher failed: {0}")]
    WatcherFailed(String),
}

// Default implementations
fn default_true() -> bool { true }
fn default_timeout() -> Duration { Duration::from_secs(30) }
fn default_memory_limit() -> usize { 100 * 1024 * 1024 } // 100MB

impl Default for DiscoveryStrategy {
    fn default() -> Self {
        DiscoveryStrategy::FileSystem {
            pattern: "*.so".to_string(),
            recursive: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            verify_signature: false,
            trusted_keys: Vec::new(),
            sandbox: SandboxMode::None,
            capabilities: vec![
                PluginCapability::Network,
                PluginCapability::FileSystem,
                PluginCapability::MemoryAllocation,
            ],
            resource_limits: ResourceLimits {
                max_memory: 100 * 1024 * 1024,
                max_cpu_percent: 50.0,
                max_file_handles: 100,
                max_threads: 10,
            },
        }
    }
}

impl Default for LoadingStrategy {
    fn default() -> Self {
        LoadingStrategy::Lazy
    }
}
```

## Plugin Development

### Example Plugin Implementation

```rust
// my_plugin.rs - компилируется в shared library

use nebula_resource::plugin::*;
use serde_json::{json, Value};

pub struct MyCustomResource {
    config: Value,
    connection_pool: Option<Pool>,
}

impl DynamicResource for MyCustomResource {
    fn initialize(&self, config: &Value) -> Result<(), PluginError> {
        // Initialize resource with config
        self.config = config.clone();
        
        // Setup connection pool or other resources
        if let Some(url) = config.get("database_url").and_then(|v| v.as_str()) {
            self.connection_pool = Some(create_pool(url)?);
        }
        
        Ok(())
    }
    
    fn metadata(&self) -> ResourceMetadata {
        ResourceMetadata {
            id: "my_custom_resource".to_string(),
            name: "My Custom Resource".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["database", "cache"],
        }
    }
    
    fn execute(&self, operation: &str, params: &Value) -> Result<Value, PluginError> {
        match operation {
            "query" => self.execute_query(params),
            "insert" => self.execute_insert(params),
            "delete" => self.execute_delete(params),
            "save_state" => Ok(self.save_state()),
            "restore_state" => self.restore_state(params),
            _ => Err(PluginError::ExecutionFailed(
                format!("Unknown operation: {}", operation)
            )),
        }
    }
    
    fn health_check(&self) -> Result<HealthStatus, PluginError> {
        if let Some(pool) = &self.connection_pool {
            if pool.is_healthy() {
                Ok(HealthStatus::Healthy)
            } else {
                Ok(HealthStatus::Unhealthy("Pool degraded".to_string()))
            }
        } else {
            Ok(HealthStatus::Healthy)
        }
    }
    
    fn cleanup(&self) -> Result<(), PluginError> {
        // Cleanup resources
        if let Some(pool) = &self.connection_pool {
            pool.close()?;
        }
        Ok(())
    }
}

// Plugin entry point - MUST be present
#[no_mangle]
pub extern "C" fn plugin_entry() -> *mut dyn DynamicResource {
    Box::into_raw(Box::new(MyCustomResource::new()))
}

// Plugin metadata - optional but recommended
#[no_mangle]
pub extern "C" fn plugin_metadata() -> *const u8 {
    let metadata = json!({
        "id": "my_custom_resource",
        "name": "My Custom Resource",
        "version": "1.0.0",
        "author": "Your Name",
        "description": "Custom resource for special operations",
        "license": "MIT",
        "dependencies": [
            {
                "plugin_id": "base_resource",
                "version_req": ">=1.0.0",
                "optional": false
            }
        ],
        "tags": ["database", "priority:10"]
    });
    
    metadata.to_string().as_ptr()
}

// API version - MUST match
#[no_mangle]
pub static PLUGIN_API_VERSION: u32 = 1;
```

## Usage Examples

### Basic Plugin Usage

```rust
async fn use_plugins(ctx: &ExecutionContext) -> Result<()> {
    let plugin_manager = ctx.get_resource::<PluginInstance>().await?;
    
    // List available plugins
    let plugins = plugin_manager.list_plugins().await;
    for plugin in plugins {
        println!("Plugin: {} v{} - {}", plugin.name, plugin.version, plugin.state);
    }
    
    // Execute plugin operation
    let result = plugin_manager.execute(
        "my_custom_resource",
        "query",
        &json!({
            "sql": "SELECT * FROM users WHERE active = true",
            "limit": 100
        })
    ).await?;
    
    println!("Query result: {}", result);
    
    // Check plugin health
    let health = plugin_manager.plugin_health("my_custom_resource").await?;
    println!("Plugin health: {:?}", health);
    
    Ok(())
}
```

### Configuration

```yaml
# plugin_resource.yaml
type: plugin_manager
config:
  plugin_dir: /usr/lib/nebula/plugins
  hot_reload: true
  
  discovery:
    type: FileSystem
    pattern: "*.so"
    recursive: true
  
  security:
    verify_signature: true
    trusted_keys:
      - "AAAAB3NzaC1yc2EA..."
    sandbox: Process
    capabilities:
      - Network
      - FileSystem
      - MemoryAllocation
    resource_limits:
      max_memory: 104857600  # 100MB
      max_cpu_percent: 50.0
      max_file_handles: 100
      max_threads: 10
  
  loading: Lazy
  
  global_config:
    my_custom_resource:
      database_url: "postgresql://localhost/mydb"
      cache_size: 1000
  
  timeout: 30s
  memory_limit: 104857600
```

### Plugin Manifest

```toml
# my_plugin.toml
id = "my_custom_resource"
name = "My Custom Resource"
version = "1.0.0"
path = "./my_plugin.so"

[metadata]
author = "Your Name"
description = "Custom resource for special operations"
license = "MIT"
homepage = "https://github.com/yourusername/my-plugin"
tags = ["database", "cache", "priority:10"]
min_nebula_version = "0.2.0"
max_nebula_version = "1.0.0"

[[dependencies]]
plugin_id = "base_resource"
version_req = ">=1.0.0, <2.0.0"
optional = false

[[dependencies]]
plugin_id = "logger"
version_req = ">=0.5.0"
optional = true
```

### Hot Reload Example

```rust
async fn hot_reload_example(plugin_manager: &PluginInstance) -> Result<()> {
    // Initial load
    plugin_manager.load_plugin("my_plugin").await?;
    
    // Use plugin
    let v1_result = plugin_manager.execute(
        "my_plugin",
        "version",
        &json!({})
    ).await?;
    println!("Version 1: {}", v1_result);
    
    // Plugin file is updated externally...
    // Hot reload triggers automatically or manually:
    plugin_manager.reload_plugin("my_plugin").await?;
    
    // Use updated plugin
    let v2_result = plugin_manager.execute(
        "my_plugin",
        "version",
        &json!({})
    ).await?;
    println!("Version 2: {}", v2_result);
    
    Ok(())
}
```

## Benefits

1. **Extensibility** - Добавление функциональности без перекомпиляции
2. **Hot Reload** - Обновление плагинов без остановки системы
3. **Isolation** - Sandboxing для безопасности
4. **Version Management** - Поддержка версий и зависимостей
5. **Discovery** - Автоматическое обнаружение плагинов
6. **Resource Limits** - Контроль ресурсов плагинов
7. **Metrics** - Мониторинг производительности плагинов

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_plugin_loading() {
        let config = PluginConfig {
            plugin_dir: PathBuf::from("./test_plugins"),
            hot_reload: false,
            discovery: DiscoveryStrategy::Explicit {
                plugins: vec![
                    PluginDescriptor {
                        id: "test_plugin".to_string(),
                        name: "Test Plugin".to_string(),
                        version: Version::parse("1.0.0").unwrap(),
                        path: PathBuf::from("./test_plugins/test.so"),
                        dependencies: vec![],
                        metadata: PluginMetadata {
                            author: "Test".to_string(),
                            description: "Test plugin".to_string(),
                            license: "MIT".to_string(),
                            homepage: None,
                            tags: vec![],
                            min_nebula_version: None,
                            max_nebula_version: None,
                        },
                    },
                ],
            },
            ..Default::default()
        };
        
        let plugin_manager = PluginResource.create(&config, &mock_context()).await.unwrap();
        
        // Load plugin
        plugin_manager.load_plugin("test_plugin").await.unwrap();
        
        // Execute operation
        let result = plugin_manager.execute(
            "test_plugin",
            "test",
            &json!({"input": "hello"})
        ).await.unwrap();
        
        assert_eq!(result, json!({"output": "hello world"}));
    }
}
```
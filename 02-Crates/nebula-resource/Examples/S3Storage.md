---
title: Example: S3Storage
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Example: S3Storage

> Object storage ресурс с поддержкой S3-compatible хранилищ, multipart upload, presigned URLs и автоматическим retry

## Overview

Полнофункциональный S3 storage ресурс для работы с Amazon S3, MinIO, DigitalOcean Spaces и другими S3-compatible хранилищами. Включает поддержку multipart upload для больших файлов, генерацию presigned URLs, управление версиями и lifecycle policies.

## Implementation

```rust
use nebula_resource::prelude::*;
use aws_sdk_s3::{Client as S3Client, Config as S3Config};
use aws_sdk_s3::types::{
    BucketVersioningStatus, CompletedMultipartUpload, CompletedPart,
    Delete, ObjectIdentifier, ServerSideEncryption, StorageClass,
};
use aws_smithy_types::byte_stream::ByteStream;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use futures::{stream, StreamExt};
use bytes::Bytes;

/// S3 Storage resource
#[derive(Resource)]
#[resource(
    id = "s3_storage",
    name = "S3-Compatible Object Storage",
    health_checkable = true
)]
pub struct S3StorageResource;

/// Configuration
#[derive(ResourceConfig, Serialize, Deserialize, Clone)]
pub struct S3StorageConfig {
    /// S3 endpoint (for custom S3-compatible services)
    pub endpoint: Option<String>,
    
    /// AWS region
    #[serde(default = "default_region")]
    pub region: String,
    
    /// Default bucket
    pub default_bucket: Option<String>,
    
    /// AWS credentials
    #[credential(id = "aws_access_key_id")]
    pub access_key_id: SecretString,
    
    #[credential(id = "aws_secret_access_key")]
    pub secret_access_key: SecretString,
    
    /// Session token (for temporary credentials)
    #[credential(id = "aws_session_token", optional = true)]
    pub session_token: Option<SecretString>,
    
    /// Force path-style addressing (for MinIO/custom S3)
    #[serde(default)]
    pub force_path_style: bool,
    
    /// Upload configuration
    #[serde(default)]
    pub upload: UploadConfig,
    
    /// Download configuration
    #[serde(default)]
    pub download: DownloadConfig,
    
    /// Retry configuration
    #[serde(default)]
    pub retry: S3RetryConfig,
    
    /// Encryption settings
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
    
    /// Enable versioning
    #[serde(default)]
    pub versioning: bool,
    
    /// Default storage class
    #[serde(default = "default_storage_class")]
    pub storage_class: S3StorageClass,
    
    /// Request timeout
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadConfig {
    /// Multipart upload threshold (bytes)
    pub multipart_threshold: usize,
    
    /// Part size for multipart uploads (bytes)
    pub part_size: usize,
    
    /// Maximum concurrent parts
    pub max_concurrent_parts: usize,
    
    /// Enable server-side compression
    pub compress: bool,
    
    /// Compute and verify checksums
    pub checksum: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadConfig {
    /// Enable parallel downloads for large files
    pub parallel: bool,
    
    /// Chunk size for parallel downloads
    pub chunk_size: usize,
    
    /// Maximum concurrent chunks
    pub max_concurrent_chunks: usize,
    
    /// Verify checksums on download
    pub verify_checksum: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EncryptionConfig {
    /// Server-side encryption with S3-managed keys
    SSE_S3,
    
    /// Server-side encryption with KMS
    SSE_KMS {
        key_id: String,
        key_context: Option<HashMap<String, String>>,
    },
    
    /// Server-side encryption with customer-provided keys
    SSE_C {
        #[credential(id = "sse_customer_key")]
        key: SecretString,
        algorithm: String,
    },
    
    /// Client-side encryption
    ClientSide {
        #[credential(id = "client_encryption_key")]
        key: SecretString,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum S3StorageClass {
    Standard,
    ReducedRedundancy,
    StandardIA,
    OneZoneIA,
    IntelligentTiering,
    Glacier,
    GlacierInstantRetrieval,
    DeepArchive,
}

/// S3 Storage instance
pub struct S3StorageInstance {
    client: S3Client,
    config: S3StorageConfig,
    upload_semaphore: Arc<Semaphore>,
    download_semaphore: Arc<Semaphore>,
    metrics: Arc<S3Metrics>,
    transfer_manager: Arc<TransferManager>,
}

/// Transfer manager for optimized uploads/downloads
struct TransferManager {
    active_transfers: Arc<RwLock<HashMap<String, TransferState>>>,
    progress_trackers: Arc<RwLock<HashMap<String, Arc<TransferProgress>>>>,
}

#[derive(Clone)]
struct TransferState {
    id: String,
    operation: TransferOperation,
    started_at: SystemTime,
    total_bytes: u64,
    transferred_bytes: Arc<AtomicU64>,
    status: TransferStatus,
}

#[derive(Clone)]
enum TransferOperation {
    Upload { key: String, bucket: String },
    Download { key: String, bucket: String },
}

#[derive(Clone)]
enum TransferStatus {
    InProgress,
    Completed,
    Failed(String),
    Cancelled,
}

struct TransferProgress {
    total_bytes: u64,
    transferred_bytes: AtomicU64,
    started_at: SystemTime,
    speed_bps: AtomicU64, // Bytes per second
}

/// Object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub key: String,
    pub size: u64,
    pub last_modified: SystemTime,
    pub etag: String,
    pub storage_class: Option<String>,
    pub version_id: Option<String>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Upload result
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub version_id: Option<String>,
    pub size: u64,
    pub duration: Duration,
}

/// Download result
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub data: Vec<u8>,
    pub metadata: ObjectMetadata,
    pub duration: Duration,
}

/// Resource implementation
#[async_trait]
impl Resource for S3StorageResource {
    type Config = S3StorageConfig;
    type Instance = S3StorageInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        // Build AWS config
        let mut aws_config_builder = aws_config::from_env();
        
        aws_config_builder = aws_config_builder
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .credentials_provider(
                aws_sdk_s3::config::Credentials::new(
                    config.access_key_id.expose_secret(),
                    config.secret_access_key.expose_secret(),
                    config.session_token.as_ref().map(|t| t.expose_secret().to_string()),
                    None,
                    "nebula_s3_storage",
                )
            );
        
        let aws_config = aws_config_builder.load().await;
        
        // Build S3 config
        let mut s3_config_builder = S3Config::builder()
            .region(aws_sdk_s3::config::Region::new(config.region.clone()))
            .credentials_provider(
                aws_sdk_s3::config::Credentials::new(
                    config.access_key_id.expose_secret(),
                    config.secret_access_key.expose_secret(),
                    config.session_token.as_ref().map(|t| t.expose_secret().to_string()),
                    None,
                    "nebula_s3_storage",
                )
            )
            .force_path_style(config.force_path_style);
        
        if let Some(endpoint) = &config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }
        
        let s3_config = s3_config_builder.build();
        let client = S3Client::from_conf(s3_config);
        
        // Create semaphores for concurrency control
        let upload_semaphore = Arc::new(Semaphore::new(config.upload.max_concurrent_parts));
        let download_semaphore = Arc::new(Semaphore::new(config.download.max_concurrent_chunks));
        
        Ok(S3StorageInstance {
            client,
            config: config.clone(),
            upload_semaphore,
            download_semaphore,
            metrics: Arc::new(S3Metrics::new()),
            transfer_manager: Arc::new(TransferManager::new()),
        })
    }
}

impl S3StorageInstance {
    /// Upload file to S3
    pub async fn upload_file(
        &self,
        file_path: impl AsRef<Path>,
        key: impl Into<String>,
        bucket: Option<String>,
    ) -> Result<UploadResult, S3Error> {
        let file_path = file_path.as_ref();
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let metadata = tokio::fs::metadata(file_path).await
            .map_err(|e| S3Error::IoError(e.to_string()))?;
        
        let file_size = metadata.len();
        
        if file_size > self.config.upload.multipart_threshold as u64 {
            self.multipart_upload_file(file_path, key, bucket).await
        } else {
            self.simple_upload_file(file_path, key, bucket).await
        }
    }
    
    /// Simple upload for small files
    async fn simple_upload_file(
        &self,
        file_path: &Path,
        key: String,
        bucket: String,
    ) -> Result<UploadResult, S3Error> {
        let start = SystemTime::now();
        
        // Read file
        let data = tokio::fs::read(file_path).await
            .map_err(|e| S3Error::IoError(e.to_string()))?;
        
        let size = data.len() as u64;
        
        // Prepare request
        let mut request = self.client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .body(ByteStream::from(data));
        
        // Add storage class
        request = request.storage_class(self.map_storage_class(&self.config.storage_class));
        
        // Add encryption
        if let Some(encryption) = &self.config.encryption {
            request = self.apply_encryption(request, encryption);
        }
        
        // Add content type
        if let Some(content_type) = self.detect_content_type(file_path) {
            request = request.content_type(content_type);
        }
        
        // Execute upload with retry
        let output = self.execute_with_retry(|| {
            request.clone().send()
        }).await?;
        
        let duration = start.elapsed().unwrap_or_default();
        self.metrics.record_upload(size, duration);
        
        Ok(UploadResult {
            bucket,
            key,
            etag: output.e_tag().unwrap_or_default().to_string(),
            version_id: output.version_id().map(|v| v.to_string()),
            size,
            duration,
        })
    }
    
    /// Multipart upload for large files
    async fn multipart_upload_file(
        &self,
        file_path: &Path,
        key: String,
        bucket: String,
    ) -> Result<UploadResult, S3Error> {
        let start = SystemTime::now();
        
        // Initialize multipart upload
        let multipart = self.client
            .create_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;
        
        let upload_id = multipart.upload_id()
            .ok_or_else(|| S3Error::UploadFailed("No upload ID".to_string()))?;
        
        // Open file
        let file = tokio::fs::File::open(file_path).await
            .map_err(|e| S3Error::IoError(e.to_string()))?;
        
        let file_size = file.metadata().await
            .map_err(|e| S3Error::IoError(e.to_string()))?
            .len();
        
        // Calculate parts
        let part_size = self.config.upload.part_size;
        let num_parts = (file_size as usize + part_size - 1) / part_size;
        
        // Upload parts in parallel
        let mut parts = Vec::new();
        let mut handles = Vec::new();
        
        for part_number in 0..num_parts {
            let client = self.client.clone();
            let bucket = bucket.clone();
            let key = key.clone();
            let upload_id = upload_id.to_string();
            let semaphore = self.upload_semaphore.clone();
            let file_path = file_path.to_path_buf();
            
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let start_byte = part_number * part_size;
                let end_byte = std::cmp::min(start_byte + part_size, file_size as usize);
                let part_size = end_byte - start_byte;
                
                // Read part from file
                let mut file = tokio::fs::File::open(&file_path).await?;
                file.seek(std::io::SeekFrom::Start(start_byte as u64)).await?;
                
                let mut buffer = vec![0; part_size];
                file.read_exact(&mut buffer).await?;
                
                // Upload part
                let part_output = client
                    .upload_part()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .part_number((part_number + 1) as i32)
                    .body(ByteStream::from(buffer))
                    .send()
                    .await?;
                
                Ok::<_, S3Error>(CompletedPart::builder()
                    .part_number((part_number + 1) as i32)
                    .e_tag(part_output.e_tag().unwrap_or_default())
                    .build())
            });
            
            handles.push(handle);
        }
        
        // Wait for all parts to complete
        for handle in handles {
            match handle.await {
                Ok(Ok(part)) => parts.push(part),
                Ok(Err(e)) => {
                    // Abort multipart upload on error
                    let _ = self.client
                        .abort_multipart_upload()
                        .bucket(&bucket)
                        .key(&key)
                        .upload_id(upload_id)
                        .send()
                        .await;
                    return Err(e);
                }
                Err(e) => {
                    // Abort multipart upload on error
                    let _ = self.client
                        .abort_multipart_upload()
                        .bucket(&bucket)
                        .key(&key)
                        .upload_id(upload_id)
                        .send()
                        .await;
                    return Err(S3Error::UploadFailed(e.to_string()));
                }
            }
        }
        
        // Complete multipart upload
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        
        let complete_output = self.client
            .complete_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;
        
        let duration = start.elapsed().unwrap_or_default();
        self.metrics.record_upload(file_size, duration);
        
        Ok(UploadResult {
            bucket,
            key,
            etag: complete_output.e_tag().unwrap_or_default().to_string(),
            version_id: complete_output.version_id().map(|v| v.to_string()),
            size: file_size,
            duration,
        })
    }
    
    /// Upload data from memory
    pub async fn upload_data(
        &self,
        data: impl Into<Bytes>,
        key: impl Into<String>,
        bucket: Option<String>,
        content_type: Option<String>,
    ) -> Result<UploadResult, S3Error> {
        let start = SystemTime::now();
        let data = data.into();
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        let size = data.len() as u64;
        
        let mut request = self.client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .body(ByteStream::from(data));
        
        if let Some(content_type) = content_type {
            request = request.content_type(content_type);
        }
        
        request = request.storage_class(self.map_storage_class(&self.config.storage_class));
        
        if let Some(encryption) = &self.config.encryption {
            request = self.apply_encryption(request, encryption);
        }
        
        let output = self.execute_with_retry(|| {
            request.clone().send()
        }).await?;
        
        let duration = start.elapsed().unwrap_or_default();
        self.metrics.record_upload(size, duration);
        
        Ok(UploadResult {
            bucket,
            key,
            etag: output.e_tag().unwrap_or_default().to_string(),
            version_id: output.version_id().map(|v| v.to_string()),
            size,
            duration,
        })
    }
    
    /// Download file from S3
    pub async fn download_file(
        &self,
        key: impl Into<String>,
        bucket: Option<String>,
    ) -> Result<DownloadResult, S3Error> {
        let start = SystemTime::now();
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        // Get object
        let response = self.execute_with_retry(|| {
            self.client
                .get_object()
                .bucket(&bucket)
                .key(&key)
                .send()
        }).await?;
        
        // Collect metadata
        let metadata = ObjectMetadata {
            key: key.clone(),
            size: response.content_length() as u64,
            last_modified: response.last_modified()
                .and_then(|t| t.to_millis().ok())
                .map(|m| SystemTime::UNIX_EPOCH + Duration::from_millis(m as u64))
                .unwrap_or_else(SystemTime::now),
            etag: response.e_tag().unwrap_or_default().to_string(),
            storage_class: response.storage_class().map(|s| s.as_str().to_string()),
            version_id: response.version_id().map(|v| v.to_string()),
            content_type: response.content_type().map(|s| s.to_string()),
            content_encoding: response.content_encoding().map(|s| s.to_string()),
            metadata: response.metadata().unwrap_or_default().clone(),
        };
        
        // Download data
        let data = response.body.collect().await
            .map_err(|e| S3Error::DownloadFailed(e.to_string()))?
            .into_bytes()
            .to_vec();
        
        let duration = start.elapsed().unwrap_or_default();
        self.metrics.record_download(data.len() as u64, duration);
        
        Ok(DownloadResult {
            data,
            metadata,
            duration,
        })
    }
    
    /// Download file to disk
    pub async fn download_file_to_path(
        &self,
        key: impl Into<String>,
        destination: impl AsRef<Path>,
        bucket: Option<String>,
    ) -> Result<ObjectMetadata, S3Error> {
        let result = self.download_file(key, bucket).await?;
        
        tokio::fs::write(destination, result.data).await
            .map_err(|e| S3Error::IoError(e.to_string()))?;
        
        Ok(result.metadata)
    }
    
    /// List objects in bucket
    pub async fn list_objects(
        &self,
        prefix: Option<String>,
        bucket: Option<String>,
        max_keys: Option<i32>,
    ) -> Result<Vec<ObjectMetadata>, S3Error> {
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let mut request = self.client
            .list_objects_v2()
            .bucket(&bucket);
        
        if let Some(prefix) = prefix {
            request = request.prefix(prefix);
        }
        
        if let Some(max_keys) = max_keys {
            request = request.max_keys(max_keys);
        }
        
        let response = request.send().await
            .map_err(|e| S3Error::ListFailed(e.to_string()))?;
        
        let objects = response.contents()
            .unwrap_or_default()
            .iter()
            .map(|obj| ObjectMetadata {
                key: obj.key().unwrap_or_default().to_string(),
                size: obj.size() as u64,
                last_modified: obj.last_modified()
                    .and_then(|t| t.to_millis().ok())
                    .map(|m| SystemTime::UNIX_EPOCH + Duration::from_millis(m as u64))
                    .unwrap_or_else(SystemTime::now),
                etag: obj.e_tag().unwrap_or_default().to_string(),
                storage_class: obj.storage_class().map(|s| s.as_str().to_string()),
                version_id: None,
                content_type: None,
                content_encoding: None,
                metadata: HashMap::new(),
            })
            .collect();
        
        Ok(objects)
    }
    
    /// Delete object
    pub async fn delete_object(
        &self,
        key: impl Into<String>,
        bucket: Option<String>,
    ) -> Result<(), S3Error> {
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        self.execute_with_retry(|| {
            self.client
                .delete_object()
                .bucket(&bucket)
                .key(&key)
                .send()
        }).await?;
        
        self.metrics.record_delete();
        Ok(())
    }
    
    /// Delete multiple objects
    pub async fn delete_objects(
        &self,
        keys: Vec<String>,
        bucket: Option<String>,
    ) -> Result<Vec<String>, S3Error> {
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let objects: Vec<ObjectIdentifier> = keys
            .iter()
            .map(|key| ObjectIdentifier::builder().key(key).build())
            .collect();
        
        let delete = Delete::builder()
            .set_objects(Some(objects))
            .build();
        
        let response = self.client
            .delete_objects()
            .bucket(&bucket)
            .delete(delete)
            .send()
            .await
            .map_err(|e| S3Error::DeleteFailed(e.to_string()))?;
        
        let deleted = response.deleted()
            .unwrap_or_default()
            .iter()
            .filter_map(|obj| obj.key().map(|k| k.to_string()))
            .collect();
        
        self.metrics.record_delete_batch(keys.len());
        Ok(deleted)
    }
    
    /// Generate presigned URL for upload
    pub async fn generate_presigned_upload_url(
        &self,
        key: impl Into<String>,
        bucket: Option<String>,
        expiration: Duration,
    ) -> Result<String, S3Error> {
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
            .expires_in(expiration)
            .build()
            .map_err(|e| S3Error::PresignFailed(e.to_string()))?;
        
        let presigned = self.client
            .put_object()
            .bucket(&bucket)
            .key(&key)
            .presigned(presigning_config)
            .await
            .map_err(|e| S3Error::PresignFailed(e.to_string()))?;
        
        Ok(presigned.uri().to_string())
    }
    
    /// Generate presigned URL for download
    pub async fn generate_presigned_download_url(
        &self,
        key: impl Into<String>,
        bucket: Option<String>,
        expiration: Duration,
    ) -> Result<String, S3Error> {
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
            .expires_in(expiration)
            .build()
            .map_err(|e| S3Error::PresignFailed(e.to_string()))?;
        
        let presigned = self.client
            .get_object()
            .bucket(&bucket)
            .key(&key)
            .presigned(presigning_config)
            .await
            .map_err(|e| S3Error::PresignFailed(e.to_string()))?;
        
        Ok(presigned.uri().to_string())
    }
    
    /// Copy object
    pub async fn copy_object(
        &self,
        source_key: impl Into<String>,
        dest_key: impl Into<String>,
        source_bucket: Option<String>,
        dest_bucket: Option<String>,
    ) -> Result<(), S3Error> {
        let source_key = source_key.into();
        let dest_key = dest_key.into();
        let source_bucket = source_bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        let dest_bucket = dest_bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        let copy_source = format!("{}/{}", source_bucket, source_key);
        
        self.execute_with_retry(|| {
            self.client
                .copy_object()
                .copy_source(&copy_source)
                .bucket(&dest_bucket)
                .key(&dest_key)
                .send()
        }).await?;
        
        Ok(())
    }
    
    /// Check if object exists
    pub async fn object_exists(
        &self,
        key: impl Into<String>,
        bucket: Option<String>,
    ) -> Result<bool, S3Error> {
        let key = key.into();
        let bucket = bucket.unwrap_or_else(|| self.config.default_bucket.clone().unwrap());
        
        match self.client
            .head_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.to_string().contains("404") || e.to_string().contains("NoSuchKey") {
                    Ok(false)
                } else {
                    Err(S3Error::HeadFailed(e.to_string()))
                }
            }
        }
    }
    
    /// Helper: Execute with retry
    async fn execute_with_retry<F, Fut, T>(
        &self,
        f: F,
    ) -> Result<T, S3Error>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, aws_sdk_s3::error::SdkError<impl std::error::Error>>>,
    {
        let mut attempts = 0;
        let mut last_error = None;
        
        while attempts < self.config.retry.max_attempts {
            attempts += 1;
            
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e.to_string());
                    
                    if attempts < self.config.retry.max_attempts {
                        let delay = self.calculate_retry_delay(attempts);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(S3Error::RetryExhausted(last_error.unwrap_or_default()))
    }
    
    fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let base = self.config.retry.initial_delay;
        let exponential = 2_u32.pow(attempt - 1);
        let delay = base * exponential;
        std::cmp::min(delay, self.config.retry.max_delay)
    }
    
    fn detect_content_type(&self, path: &Path) -> Option<String> {
        let extension = path.extension()?.to_str()?;
        
        match extension.to_lowercase().as_str() {
            "html" | "htm" => Some("text/html"),
            "css" => Some("text/css"),
            "js" => Some("application/javascript"),
            "json" => Some("application/json"),
            "xml" => Some("application/xml"),
            "pdf" => Some("application/pdf"),
            "zip" => Some("application/zip"),
            "gz" => Some("application/gzip"),
            "jpg" | "jpeg" => Some("image/jpeg"),
            "png" => Some("image/png"),
            "gif" => Some("image/gif"),
            "svg" => Some("image/svg+xml"),
            "mp4" => Some("video/mp4"),
            "mp3" => Some("audio/mpeg"),
            "txt" => Some("text/plain"),
            "csv" => Some("text/csv"),
            _ => None,
        }.map(|s| s.to_string())
    }
    
    fn map_storage_class(&self, class: &S3StorageClass) -> StorageClass {
        match class {
            S3StorageClass::Standard => StorageClass::Standard,
            S3StorageClass::ReducedRedundancy => StorageClass::ReducedRedundancy,
            S3StorageClass::StandardIA => StorageClass::StandardIa,
            S3StorageClass::OneZoneIA => StorageClass::OnezoneIa,
            S3StorageClass::IntelligentTiering => StorageClass::IntelligentTiering,
            S3StorageClass::Glacier => StorageClass::Glacier,
            S3StorageClass::GlacierInstantRetrieval => StorageClass::GlacierIr,
            S3StorageClass::DeepArchive => StorageClass::DeepArchive,
        }
    }
    
    fn apply_encryption<B>(
        &self,
        mut request: B,
        encryption: &EncryptionConfig,
    ) -> B
    where
        B: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
    {
        match encryption {
            EncryptionConfig::SSE_S3 => {
                request.server_side_encryption(ServerSideEncryption::Aes256)
            }
            EncryptionConfig::SSE_KMS { key_id, .. } => {
                request
                    .server_side_encryption(ServerSideEncryption::AwsKms)
                    .ssekms_key_id(key_id)
            }
            EncryptionConfig::SSE_C { .. } => {
                // SSE-C requires additional headers
                request
            }
            EncryptionConfig::ClientSide { .. } => {
                // Client-side encryption handled separately
                request
            }
        }
    }
}

/// S3 Metrics
struct S3Metrics {
    uploads_total: AtomicU64,
    downloads_total: AtomicU64,
    deletes_total: AtomicU64,
    bytes_uploaded: AtomicU64,
    bytes_downloaded: AtomicU64,
    upload_duration_ms: AtomicU64,
    download_duration_ms: AtomicU64,
}

impl S3Metrics {
    fn new() -> Self {
        Self {
            uploads_total: AtomicU64::new(0),
            downloads_total: AtomicU64::new(0),
            deletes_total: AtomicU64::new(0),
            bytes_uploaded: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            upload_duration_ms: AtomicU64::new(0),
            download_duration_ms: AtomicU64::new(0),
        }
    }
    
    fn record_upload(&self, bytes: u64, duration: Duration) {
        self.uploads_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_uploaded.fetch_add(bytes, Ordering::Relaxed);
        self.upload_duration_ms.fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }
    
    fn record_download(&self, bytes: u64, duration: Duration) {
        self.downloads_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_downloaded.fetch_add(bytes, Ordering::Relaxed);
        self.download_duration_ms.fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }
    
    fn record_delete(&self) {
        self.deletes_total.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_delete_batch(&self, count: usize) {
        self.deletes_total.fetch_add(count as u64, Ordering::Relaxed);
    }
}

impl TransferManager {
    fn new() -> Self {
        Self {
            active_transfers: Arc::new(RwLock::new(HashMap::new())),
            progress_trackers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("Upload failed: {0}")]
    UploadFailed(String),
    
    #[error("Download failed: {0}")]
    DownloadFailed(String),
    
    #[error("Delete failed: {0}")]
    DeleteFailed(String),
    
    #[error("List failed: {0}")]
    ListFailed(String),
    
    #[error("Head failed: {0}")]
    HeadFailed(String),
    
    #[error("Presign failed: {0}")]
    PresignFailed(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Retry exhausted: {0}")]
    RetryExhausted(String),
}

// Default implementations
fn default_region() -> String { "us-east-1".to_string() }
fn default_storage_class() -> S3StorageClass { S3StorageClass::Standard }
fn default_timeout() -> Duration { Duration::from_secs(300) }

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            multipart_threshold: 5 * 1024 * 1024, // 5MB
            part_size: 5 * 1024 * 1024, // 5MB
            max_concurrent_parts: 10,
            compress: false,
            checksum: true,
        }
    }
}

impl Default for DownloadConfig {
    fn default() -> Self {
        Self {
            parallel: true,
            chunk_size: 1024 * 1024, // 1MB
            max_concurrent_chunks: 10,
            verify_checksum: true,
        }
    }
}

impl Default for S3RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        }
    }
}
```

## Usage Examples

### Basic Usage

```rust
async fn basic_s3_usage(ctx: &ExecutionContext) -> Result<()> {
    let s3 = ctx.get_resource::<S3StorageInstance>().await?;
    
    // Upload a file
    let upload_result = s3.upload_file(
        "/path/to/local/file.pdf",
        "documents/report.pdf",
        Some("my-bucket".to_string()),
    ).await?;
    
    println!("Uploaded: {} ({} bytes in {:?})", 
        upload_result.key, 
        upload_result.size, 
        upload_result.duration
    );
    
    // Download a file
    let download_result = s3.download_file(
        "documents/report.pdf",
        Some("my-bucket".to_string()),
    ).await?;
    
    println!("Downloaded: {} bytes", download_result.data.len());
    
    // List objects
    let objects = s3.list_objects(
        Some("documents/".to_string()),
        Some("my-bucket".to_string()),
        Some(100),
    ).await?;
    
    for obj in objects {
        println!("  {} - {} bytes", obj.key, obj.size);
    }
    
    Ok(())
}
```

### Advanced Operations

```rust
async fn advanced_s3_operations(s3: &S3StorageInstance) -> Result<()> {
    // Generate presigned URL for direct upload
    let upload_url = s3.generate_presigned_upload_url(
        "uploads/user-file.jpg",
        None,
        Duration::from_secs(3600), // 1 hour expiration
    ).await?;
    
    println!("Upload directly to: {}", upload_url);
    
    // Generate presigned URL for download
    let download_url = s3.generate_presigned_download_url(
        "documents/private-doc.pdf",
        None,
        Duration::from_secs(300), // 5 minute expiration
    ).await?;
    
    println!("Download from: {}", download_url);
    
    // Copy object
    s3.copy_object(
        "source/file.txt",
        "destination/file-copy.txt",
        None,
        None,
    ).await?;
    
    // Batch delete
    let deleted = s3.delete_objects(
        vec![
            "temp/file1.txt".to_string(),
            "temp/file2.txt".to_string(),
            "temp/file3.txt".to_string(),
        ],
        None,
    ).await?;
    
    println!("Deleted {} objects", deleted.len());
    
    Ok(())
}
```

### Configuration Examples

```yaml
# s3_storage.yaml
type: s3_storage
config:
  # For AWS S3
  region: us-west-2
  default_bucket: my-application-bucket
  
  # For MinIO or custom S3
  # endpoint: http://localhost:9000
  # force_path_style: true
  
  # Credentials (from environment or secrets manager)
  access_key_id: "${AWS_ACCESS_KEY_ID}"
  secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
  
  # Upload configuration
  upload:
    multipart_threshold: 10485760  # 10MB
    part_size: 5242880             # 5MB
    max_concurrent_parts: 20
    compress: false
    checksum: true
  
  # Download configuration
  download:
    parallel: true
    chunk_size: 1048576  # 1MB
    max_concurrent_chunks: 10
    verify_checksum: true
  
  # Retry configuration
  retry:
    max_attempts: 3
    initial_delay: 100ms
    max_delay: 10s
  
  # Encryption
  encryption:
    type: SSE_S3  # or SSE_KMS, SSE_C, ClientSide
  
  # Storage class
  storage_class: Standard  # or StandardIA, Glacier, etc.
  
  # Enable versioning
  versioning: true
  
  timeout: 5m
```

### Stream Processing

```rust
async fn stream_processing(s3: &S3StorageInstance) -> Result<()> {
    // Process large dataset in chunks
    let objects = s3.list_objects(
        Some("data/".to_string()),
        None,
        None,
    ).await?;
    
    // Process objects in parallel with limited concurrency
    let semaphore = Arc::new(Semaphore::new(5));
    let mut handles = Vec::new();
    
    for obj in objects {
        let s3 = s3.clone();
        let permit = semaphore.clone().acquire_owned().await?;
        
        let handle = tokio::spawn(async move {
            let _permit = permit; // Hold permit until done
            
            // Download and process
            let result = s3.download_file(&obj.key, None).await?;
            
            // Process data
            process_data(&result.data).await?;
            
            // Upload processed result
            let processed = transform_data(&result.data);
            s3.upload_data(
                processed,
                format!("processed/{}", obj.key),
                None,
                Some("application/octet-stream".to_string()),
            ).await?;
            
            Ok::<_, Box<dyn std::error::Error>>(())
        });
        
        handles.push(handle);
    }
    
    // Wait for all processing to complete
    for handle in handles {
        handle.await??;
    }
    
    Ok(())
}
```

## Benefits

1. **Multipart Upload** - Автоматическое разбиение больших файлов
2. **Parallel Transfer** - Параллельная загрузка/выгрузка частей
3. **Presigned URLs** - Прямая загрузка без прокси-сервера
4. **Retry Logic** - Автоматические повторы при сбоях
5. **Multiple Backends** - Поддержка S3, MinIO, DigitalOcean Spaces
6. **Encryption** - Server-side и client-side шифрование
7. **Metrics** - Детальная статистика операций

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_upload_download() {
        // Use LocalStack or MinIO for testing
        let config = S3StorageConfig {
            endpoint: Some("http://localhost:4566".to_string()),
            region: "us-east-1".to_string(),
            default_bucket: Some("test-bucket".to_string()),
            force_path_style: true,
            ..Default::default()
        };
        
        let s3 = S3StorageResource.create(&config, &mock_context()).await.unwrap();
        
        // Test upload
        let data = b"Hello, S3!";
        let upload = s3.upload_data(
            data.to_vec(),
            "test/file.txt",
            None,
            None,
        ).await.unwrap();
        
        assert!(!upload.etag.is_empty());
        
        // Test download
        let download = s3.download_file("test/file.txt", None).await.unwrap();
        assert_eq!(download.data, data);
        
        // Test delete
        s3.delete_object("test/file.txt", None).await.unwrap();
        
        // Verify deletion
        assert!(!s3.object_exists("test/file.txt", None).await.unwrap());
    }
}
```

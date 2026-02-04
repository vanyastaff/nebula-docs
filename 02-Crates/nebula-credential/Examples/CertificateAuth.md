---
title: CertificateAuth
tags: [nebula, nebula-credential, docs, mtls, certificates, tls]
status: ready
created: 2025-08-24
---

# Certificate Authentication

Certificate Authentication — аутентификация с использованием X.509 certificates, включая mutual TLS (mTLS), client certificates, certificate rotation и управление certificate chains.

## Определение

Certificate authentication использует asymmetric cryptography (public/private key pairs) для проверки идентичности:

1. **Client Certificate (mTLS)** — клиент предоставляет сертификат серверу для mutual authentication
2. **Server Certificate (TLS/SSL)** — сервер предоставляет сертификат клиенту
3. **Certificate Chain** — цепочка сертификатов от leaf до root CA
4. **Self-Signed vs CA-Signed** — самоподписанные vs подписанные Certificate Authority

```rust
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use x509_parser::prelude::*;

/// Client certificate credential
#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateCredential {
    pub credential_id: String,
    pub name: String,

    // Certificate в PEM формате (публичная информация)
    pub certificate_pem: String,

    // Certificate chain в PEM формате (если есть intermediate CAs)
    pub certificate_chain_pem: Option<String>,

    // Private key в PEM формате (СЕКРЕТНАЯ информация)
    #[serde(serialize_with = "serialize_secret")]
    pub private_key_pem: SecretString,

    // CA certificate для верификации server certificates
    pub ca_cert_pem: Option<String>,

    pub subject: String,  // CN=example.com, O=My Company
    pub issuer: String,   // CN=My CA, O=My Company
    pub serial_number: String,

    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,

    pub fingerprint_sha256: String,  // SHA256 fingerprint для идентификации

    pub created_at: DateTime<Utc>,
    pub last_rotated: Option<DateTime<Utc>>,
}

impl CertificateCredential {
    pub fn new(
        name: String,
        certificate_pem: String,
        private_key_pem: String,
    ) -> Result<Self, CertificateError> {
        // Parse certificate для извлечения metadata
        let cert_info = Self::parse_certificate(&certificate_pem)?;

        Ok(Self {
            credential_id: Uuid::new_v4().to_string(),
            name,
            certificate_pem: certificate_pem.clone(),
            certificate_chain_pem: None,
            private_key_pem: SecretString::new(private_key_pem),
            ca_cert_pem: None,
            subject: cert_info.subject,
            issuer: cert_info.issuer,
            serial_number: cert_info.serial_number,
            not_before: cert_info.not_before,
            not_after: cert_info.not_after,
            fingerprint_sha256: cert_info.fingerprint_sha256,
            created_at: Utc::now(),
            last_rotated: None,
        })
    }

    pub fn with_chain(mut self, chain_pem: String) -> Self {
        self.certificate_chain_pem = Some(chain_pem);
        self
    }

    pub fn with_ca_cert(mut self, ca_cert_pem: String) -> Self {
        self.ca_cert_pem = Some(ca_cert_pem);
        self
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    pub fn expires_soon(&self, days: i64) -> bool {
        let threshold = Utc::now() + chrono::Duration::days(days);
        self.not_after < threshold
    }

    fn parse_certificate(pem: &str) -> Result<CertificateInfo, CertificateError> {
        // Удалить PEM headers/footers
        let pem_data = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        let der = base64::decode(&pem_data)
            .map_err(|e| CertificateError::ParseError(e.to_string()))?;

        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|e| CertificateError::ParseError(e.to_string()))?;

        // Extract subject
        let subject = cert.subject().to_string();

        // Extract issuer
        let issuer = cert.issuer().to_string();

        // Extract serial number
        let serial_number = cert.serial.to_string();

        // Extract validity period
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        // Calculate SHA256 fingerprint
        let fingerprint_sha256 = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&der);
            format!("{:x}", hasher.finalize())
        };

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            not_before: DateTime::from_timestamp(not_before, 0)
                .ok_or_else(|| CertificateError::ParseError("Invalid timestamp".to_string()))?,
            not_after: DateTime::from_timestamp(not_after, 0)
                .ok_or_else(|| CertificateError::ParseError("Invalid timestamp".to_string()))?,
            fingerprint_sha256,
        })
    }
}

struct CertificateInfo {
    subject: String,
    issuer: String,
    serial_number: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    fingerprint_sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("Certificate parse error: {0}")]
    ParseError(String),

    #[error("Certificate expired at {0}")]
    Expired(DateTime<Utc>),

    #[error("Certificate not yet valid until {0}")]
    NotYetValid(DateTime<Utc>),

    #[error("Certificate verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid certificate chain")]
    InvalidChain,
}

fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str("***REDACTED***")
}
```

## Зачем это нужно?

Certificate authentication используется для:

1. **Mutual TLS (mTLS)** — двусторонняя аутентификация client ↔ server
2. **Service-to-Service Auth** — аутентификация между microservices без passwords
3. **Zero-Trust Networks** — каждый service должен доказать свою идентичность
4. **API Gateway** — client certificates для доступа к защищенным APIs
5. **Database Connections** — PostgreSQL, MongoDB, MySQL поддерживают certificate auth

## Базовое использование

### mTLS Client с Reqwest

```rust
use nebula_credential::{CredentialManager, Scope, CredentialId};
use reqwest::{Client, Certificate, Identity};
use std::sync::Arc;
use anyhow::Result;

pub struct MtlsClient {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
    client: Option<Client>,
}

impl MtlsClient {
    pub fn new(credential_manager: Arc<CredentialManager>, credential_id: CredentialId) -> Self {
        Self {
            credential_manager,
            credential_id,
            client: None,
        }
    }

    async fn get_certificate(&self) -> Result<CertificateCredential> {
        let credential = self.credential_manager
            .get_credential(&self.credential_id, &Scope::Global)
            .await?;

        let cert_cred: CertificateCredential = serde_json::from_value(credential.data)?;

        // Проверить expiration
        if cert_cred.is_expired() {
            return Err(anyhow::anyhow!(
                "Certificate expired at {}",
                cert_cred.not_after
            ));
        }

        // Предупредить если истекает скоро (30 дней)
        if cert_cred.expires_soon(30) {
            warn!("Certificate expires soon: {}", cert_cred.not_after);
        }

        Ok(cert_cred)
    }

    async fn build_client(&mut self) -> Result<&Client> {
        if self.client.is_some() {
            return Ok(self.client.as_ref().unwrap());
        }

        let cert_cred = self.get_certificate().await?;

        // Создать Identity из certificate + private key
        let identity = {
            // Combine certificate + private key в PEM format
            let mut pem = cert_cred.certificate_pem.clone();
            pem.push('\n');
            pem.push_str(cert_cred.private_key_pem.expose_secret());

            // Если есть chain, добавить его
            if let Some(chain) = &cert_cred.certificate_chain_pem {
                pem.push('\n');
                pem.push_str(chain);
            }

            Identity::from_pem(pem.as_bytes())?
        };

        // Создать reqwest Client с client certificate
        let mut client_builder = Client::builder()
            .identity(identity)
            .use_rustls_tls();  // Использовать rustls

        // Если есть CA certificate для server verification
        if let Some(ca_cert_pem) = &cert_cred.ca_cert_pem {
            let ca_cert = Certificate::from_pem(ca_cert_pem.as_bytes())?;
            client_builder = client_builder.add_root_certificate(ca_cert);
        }

        let client = client_builder.build()?;
        self.client = Some(client);

        Ok(self.client.as_ref().unwrap())
    }

    pub async fn get(&mut self, url: &str) -> Result<String> {
        let client = self.build_client().await?;

        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Request failed with status: {}",
                response.status()
            ));
        }

        let body = response.text().await?;
        Ok(body)
    }

    pub async fn post(&mut self, url: &str, body: &impl Serialize) -> Result<String> {
        let client = self.build_client().await?;

        let response = client.post(url).json(body).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Request failed with status: {}",
                response.status()
            ));
        }

        let response_body = response.text().await?;
        Ok(response_body)
    }

    /// Invalidate кеш client (после ротации certificate)
    pub fn invalidate_cache(&mut self) {
        self.client = None;
    }
}
```

### mTLS Server с Axum + Rustls

```rust
use axum::{
    Router,
    routing::get,
    extract::State,
    http::StatusCode,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;

pub struct MtlsServer {
    credential_manager: Arc<CredentialManager>,
    server_cert_id: CredentialId,
    client_ca_cert_id: CredentialId,
}

impl MtlsServer {
    pub async fn start(&self, addr: SocketAddr) -> Result<()> {
        // Получить server certificate
        let server_cert = self.get_server_certificate().await?;

        // Получить CA certificate для client verification
        let client_ca = self.get_client_ca_certificate().await?;

        // Создать RustlsConfig для mTLS
        let config = self.build_mtls_config(&server_cert, &client_ca)?;

        // Создать Axum router
        let app = Router::new()
            .route("/", get(root_handler))
            .route("/api/data", get(data_handler))
            .with_state(self.credential_manager.clone());

        info!("Starting mTLS server on {}", addr);

        // Запустить HTTPS server с client certificate verification
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }

    async fn get_server_certificate(&self) -> Result<CertificateCredential> {
        let credential = self.credential_manager
            .get_credential(&self.server_cert_id, &Scope::Global)
            .await?;

        let cert_cred: CertificateCredential = serde_json::from_value(credential.data)?;

        if cert_cred.is_expired() {
            return Err(anyhow::anyhow!("Server certificate expired"));
        }

        Ok(cert_cred)
    }

    async fn get_client_ca_certificate(&self) -> Result<String> {
        let credential = self.credential_manager
            .get_credential(&self.client_ca_cert_id, &Scope::Global)
            .await?;

        let ca_pem: String = serde_json::from_value(credential.data["ca_cert_pem"].clone())?;
        Ok(ca_pem)
    }

    fn build_mtls_config(
        &self,
        server_cert: &CertificateCredential,
        client_ca_pem: &str,
    ) -> Result<RustlsConfig> {
        // Parse server certificate chain
        let cert_chain = rustls_pemfile::certs(&mut server_cert.certificate_pem.as_bytes())?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        // Parse private key
        let private_key = {
            let mut key_reader = server_cert.private_key_pem.expose_secret().as_bytes();
            let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?;

            if keys.is_empty() {
                return Err(anyhow::anyhow!("No private key found"));
            }

            rustls::PrivateKey(keys[0].clone())
        };

        // Parse client CA certificate
        let client_ca_cert = {
            let mut ca_reader = client_ca_pem.as_bytes();
            let certs = rustls_pemfile::certs(&mut ca_reader)?;

            if certs.is_empty() {
                return Err(anyhow::anyhow!("No CA certificate found"));
            }

            rustls::Certificate(certs[0].clone())
        };

        // Create root cert store для client verification
        let mut client_auth_roots = rustls::RootCertStore::empty();
        client_auth_roots.add(&client_ca_cert)?;

        // Client certificate verifier
        let client_verifier = AllowAnyAuthenticatedClient::new(client_auth_roots);

        // Server config с client certificate verification
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(client_verifier))
            .with_single_cert(cert_chain, private_key)?;

        Ok(RustlsConfig::from_config(Arc::new(config)))
    }
}

async fn root_handler() -> &'static str {
    "mTLS server is running"
}

async fn data_handler(State(cred_mgr): State<Arc<CredentialManager>>) -> Result<String, StatusCode> {
    // Handler logic
    Ok("Secure data".to_string())
}
```

## Certificate Rotation

### Zero-Downtime Certificate Rotation

```rust
use tokio::sync::RwLock;

pub struct CertificateRotator {
    credential_manager: Arc<CredentialManager>,
    // Cache для текущих активных certificates
    active_certificates: Arc<RwLock<HashMap<CredentialId, CertificateCredential>>>,
}

impl CertificateRotator {
    /// Ротация certificate с zero downtime
    ///
    /// Процесс:
    /// 1. Проверить что новый certificate валидный
    /// 2. Проверить что новый certificate + private key match
    /// 3. Сохранить новый certificate в storage
    /// 4. Обновить кеш с новым certificate
    /// 5. Старый certificate остается валидным до expiration (grace period)
    pub async fn rotate_certificate(
        &self,
        credential_id: &CredentialId,
        new_certificate_pem: String,
        new_private_key_pem: String,
        new_chain_pem: Option<String>,
    ) -> Result<()> {
        info!("Starting certificate rotation for credential: {}", credential_id);

        // STAGE 1: Получить текущий certificate
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_cert: CertificateCredential = serde_json::from_value(old_credential.data)?;

        info!("Old certificate expires at: {}", old_cert.not_after);

        // STAGE 2: Создать новый CertificateCredential
        let mut new_cert = CertificateCredential::new(
            old_cert.name.clone(),
            new_certificate_pem,
            new_private_key_pem,
        )?;

        if let Some(chain) = new_chain_pem {
            new_cert = new_cert.with_chain(chain);
        }

        if let Some(ca_cert) = old_cert.ca_cert_pem {
            new_cert = new_cert.with_ca_cert(ca_cert);
        }

        new_cert.last_rotated = Some(Utc::now());

        info!("New certificate valid until: {}", new_cert.not_after);

        // STAGE 3: Verify новый certificate
        self.verify_certificate(&new_cert).await?;

        // STAGE 4: Verify что certificate + private key match
        self.verify_key_pair(&new_cert)?;

        // STAGE 5: Сохранить новый certificate
        let new_credential_data = serde_json::to_value(&new_cert)?;

        self.credential_manager.update_credential(
            credential_id,
            new_credential_data,
        ).await?;

        info!("Updated certificate storage");

        // STAGE 6: Обновить кеш
        let mut cache = self.active_certificates.write().await;
        cache.insert(credential_id.clone(), new_cert.clone());

        info!("Certificate rotation completed successfully");

        Ok(())
    }

    /// Проверка что certificate валидный
    async fn verify_certificate(&self, cert: &CertificateCredential) -> Result<()> {
        // Проверить expiration
        if cert.is_expired() {
            return Err(anyhow::anyhow!("New certificate is already expired"));
        }

        // Проверить что certificate еще валиден (not_before)
        if Utc::now() < cert.not_before {
            return Err(anyhow::anyhow!(
                "New certificate is not yet valid (not_before: {})",
                cert.not_before
            ));
        }

        // Проверить minimum validity period (например, минимум 7 дней)
        if cert.expires_soon(7) {
            warn!("New certificate expires soon (within 7 days)");
        }

        Ok(())
    }

    /// Проверка что certificate и private key соответствуют друг другу
    fn verify_key_pair(&self, cert: &CertificateCredential) -> Result<()> {
        use openssl::x509::X509;
        use openssl::pkey::PKey;

        // Parse certificate
        let x509 = X509::from_pem(cert.certificate_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

        // Parse private key
        let private_key = PKey::private_key_from_pem(cert.private_key_pem.expose_secret().as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?;

        // Get public key from certificate
        let public_key = x509.public_key()
            .map_err(|e| anyhow::anyhow!("Failed to extract public key: {}", e))?;

        // Verify that private key matches public key
        if !public_key.public_eq(&private_key) {
            return Err(anyhow::anyhow!("Private key does not match certificate public key"));
        }

        info!("Certificate and private key match verified successfully");
        Ok(())
    }

    /// Автоматическая ротация expiring certificates
    pub async fn auto_rotate_expiring_certificates(&self, days_before_expiry: i64) -> Result<()> {
        let credentials = self.credential_manager.list_credentials().await?;

        for cred_id in credentials {
            let credential = self.credential_manager
                .get_credential(&cred_id, &Scope::Global)
                .await?;

            if let Ok(cert_cred) = serde_json::from_value::<CertificateCredential>(credential.data) {
                if cert_cred.expires_soon(days_before_expiry) && !cert_cred.is_expired() {
                    warn!(
                        "Certificate {} expires soon ({}), triggering rotation",
                        cred_id, cert_cred.not_after
                    );

                    // Здесь должна быть интеграция с ACME (Let's Encrypt) или другим CA
                    // для автоматического получения нового certificate
                    // self.request_new_certificate(&cred_id).await?;
                }
            }
        }

        Ok(())
    }
}
```

## Service-Specific Examples

### PostgreSQL с Client Certificates

```rust
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::path::Path;
use tokio::fs;

pub struct PostgresMtlsClient {
    credential_manager: Arc<CredentialManager>,
    cert_credential_id: CredentialId,
    pool: Option<PgPool>,
}

impl PostgresMtlsClient {
    pub async fn connect(
        &mut self,
        host: &str,
        port: u16,
        database: &str,
        user: &str,
    ) -> Result<&PgPool> {
        if self.pool.is_some() {
            return Ok(self.pool.as_ref().unwrap());
        }

        let cert_cred = self.get_certificate().await?;

        // Сохранить certificate files во временную директорию
        let temp_dir = std::env::temp_dir().join(format!("pg-certs-{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).await?;

        let cert_path = temp_dir.join("client-cert.pem");
        let key_path = temp_dir.join("client-key.pem");
        let ca_path = temp_dir.join("ca-cert.pem");

        // Записать files
        fs::write(&cert_path, &cert_cred.certificate_pem).await?;
        fs::write(&key_path, cert_cred.private_key_pem.expose_secret()).await?;

        if let Some(ca_cert) = &cert_cred.ca_cert_pem {
            fs::write(&ca_path, ca_cert).await?;
        }

        // Построить connection string с SSL параметрами
        let connection_string = format!(
            "postgresql://{}@{}:{}/{}?sslmode=verify-full&sslcert={}&sslkey={}&sslrootcert={}",
            user,
            host,
            port,
            database,
            cert_path.display(),
            key_path.display(),
            ca_path.display(),
        );

        // Создать connection pool
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&connection_string)
            .await?;

        info!("Connected to PostgreSQL with mTLS");

        self.pool = Some(pool);
        Ok(self.pool.as_ref().unwrap())
    }

    async fn get_certificate(&self) -> Result<CertificateCredential> {
        let credential = self.credential_manager
            .get_credential(&self.cert_credential_id, &Scope::Global)
            .await?;

        let cert_cred: CertificateCredential = serde_json::from_value(credential.data)?;

        if cert_cred.is_expired() {
            return Err(anyhow::anyhow!("Certificate expired"));
        }

        Ok(cert_cred)
    }
}
```

### Kubernetes Service-to-Service mTLS

```rust
use kube::{Client, Config};
use k8s_openapi::api::core::v1::Secret;

pub struct KubernetesMtlsClient {
    credential_manager: Arc<CredentialManager>,
    cert_credential_id: CredentialId,
}

impl KubernetesMtlsClient {
    /// Create Kubernetes client с custom certificate для service-to-service auth
    pub async fn build_client(&self) -> Result<Client> {
        let cert_cred = self.get_certificate().await?;

        // Load default config
        let mut config = Config::infer().await?;

        // Override с custom certificate
        config.identity = Some({
            let mut pem = cert_cred.certificate_pem.clone();
            pem.push('\n');
            pem.push_str(cert_cred.private_key_pem.expose_secret());

            kube::config::Identity::from_pem(pem.as_bytes())?
        });

        // CA certificate
        if let Some(ca_cert) = cert_cred.ca_cert_pem {
            config.root_cert = Some(ca_cert.into_bytes());
        }

        let client = Client::try_from(config)?;
        Ok(client)
    }

    async fn get_certificate(&self) -> Result<CertificateCredential> {
        let credential = self.credential_manager
            .get_credential(&self.cert_credential_id, &Scope::Global)
            .await?;

        let cert_cred: CertificateCredential = serde_json::from_value(credential.data)?;

        if cert_cred.is_expired() {
            return Err(anyhow::anyhow!("Certificate expired"));
        }

        Ok(cert_cred)
    }

    /// Store certificate в Kubernetes Secret для использования другими pods
    pub async fn store_in_k8s_secret(
        &self,
        client: &Client,
        namespace: &str,
        secret_name: &str,
    ) -> Result<()> {
        use k8s_openapi::api::core::v1::Secret;
        use kube::api::{Api, PostParams};
        use std::collections::BTreeMap;

        let cert_cred = self.get_certificate().await?;

        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), cert_cred.certificate_pem.into_bytes());
        data.insert(
            "tls.key".to_string(),
            cert_cred.private_key_pem.expose_secret().as_bytes().to_vec(),
        );

        if let Some(ca_cert) = cert_cred.ca_cert_pem {
            data.insert("ca.crt".to_string(), ca_cert.into_bytes());
        }

        let secret = Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(secret_name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(data.into_iter().map(|(k, v)| (k, k8s_openapi::ByteString(v))).collect()),
            type_: Some("kubernetes.io/tls".to_string()),
            ..Default::default()
        };

        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        secrets.create(&PostParams::default(), &secret).await?;

        info!("Certificate stored in Kubernetes secret: {}/{}", namespace, secret_name);
        Ok(())
    }
}
```

## Best Practices

### ✅ Правильные практики

```rust
// ✅ ПРАВИЛЬНО: Хранить private key в SecretString
pub struct CertificateCredential {
    pub certificate_pem: String,  // Public — можно логировать
    pub private_key_pem: SecretString,  // Secret — не попадет в логи
}

// ✅ ПРАВИЛЬНО: Проверять expiration перед использованием
if cert.is_expired() {
    return Err(anyhow::anyhow!("Certificate expired"));
}

// ✅ ПРАВИЛЬНО: Предупреждать о скором истечении (30 дней)
if cert.expires_soon(30) {
    warn!("Certificate expires soon: {}", cert.not_after);
}

// ✅ ПРАВИЛЬНО: Verify certificate + private key match перед ротацией
self.verify_key_pair(&new_cert)?;

// ✅ ПРАВИЛЬНО: Использовать certificate chains для CA-signed certificates
let mut cert_cred = CertificateCredential::new(name, cert_pem, key_pem)?;
cert_cred = cert_cred.with_chain(intermediate_ca_pem);

// ✅ ПРАВИЛЬНО: Verify server certificates с CA cert
let ca_cert = Certificate::from_pem(ca_cert_pem.as_bytes())?;
let client = Client::builder()
    .add_root_certificate(ca_cert)
    .build()?;

// ✅ ПРАВИЛЬНО: Использовать separate credentials для different environments
let prod_cert_id = credential_manager.store_credential("mtls-prod", ...);
let staging_cert_id = credential_manager.store_credential("mtls-staging", ...);

// ✅ ПРАВИЛЬНО: Логировать fingerprint вместо всего certificate
info!("Using certificate with fingerprint: {}", cert.fingerprint_sha256);

// ✅ ПРАВИЛЬНО: Автоматическая ротация expiring certificates
rotator.auto_rotate_expiring_certificates(30).await?;  // 30 дней до expiry

// ✅ ПРАВИЛЬНО: Использовать временные файлы с правильными permissions
use std::os::unix::fs::PermissionsExt;
fs::write(&key_path, private_key_pem).await?;
fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).await?;  // Owner read/write only
```

### ❌ Неправильные практики

```rust
// ❌ НЕПРАВИЛЬНО: Private key в обычной String (попадет в логи)
pub struct BadCertificateCredential {
    pub certificate_pem: String,
    pub private_key_pem: String,  // ОПАСНО!
}

// ❌ НЕПРАВИЛЬНО: Не проверять expiration
let client = build_mtls_client(&cert).await?;  // Может быть expired!

// ❌ НЕПРАВИЛЬНО: Логировать private key
error!("Failed with key: {}", cert.private_key_pem);  // УТЕЧКА!

// ❌ НЕПРАВИЛЬНО: Hardcode certificates в коде
let cert_pem = "-----BEGIN CERTIFICATE-----\nMIID...";  // Не делать так!

// ❌ НЕПРАВИЛЬНО: Не проверять что certificate + private key match
credential_manager.update_credential(id, new_cert)?;  // Может не работать!

// ❌ НЕПРАВИЛЬНО: Игнорировать certificate chain для CA-signed certs
// Server может отклонить certificate без intermediate CA в chain

// ❌ НЕПРАВИЛЬНО: Не verify server certificates
let client = Client::builder()
    .danger_accept_invalid_certs(true)  // ОПАСНО в production!
    .build()?;

// ❌ НЕПРАВИЛЬНО: Использовать self-signed certificates в production без pinning
// Self-signed certificates должны использоваться только для testing

// ❌ НЕПРАВИЛЬНО: Хранить private keys в plain text files
fs::write("/tmp/private-key.pem", private_key)?;  // Плохая идея!

// ❌ НЕПРАВИЛЬНО: Использовать один certificate для всех environments
// Production, staging, development должны иметь separate certificates

// ❌ НЕПРАВИЛЬНО: Игнорировать ошибки ротации
let _ = rotator.rotate_certificate(&cert_id, new_cert).await;  // Молча провалилось!

// ❌ НЕПРАВИЛЬНО: Не использовать certificate для sensitive операций
let password = "hardcoded-password";  // Использовать mTLS вместо passwords!
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("Certificate parse error: {0}")]
    ParseError(String),

    #[error("Certificate expired at {0}")]
    Expired(DateTime<Utc>),

    #[error("Certificate not yet valid until {0}")]
    NotYetValid(DateTime<Utc>),

    #[error("Certificate verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid certificate chain")]
    InvalidChain,

    #[error("Private key does not match certificate")]
    KeyMismatch,

    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),

    #[error("Certificate revoked")]
    Revoked,
}

impl MtlsClient {
    pub async fn get_with_retry(
        &mut self,
        url: &str,
        max_retries: u32,
    ) -> Result<String> {
        let mut retries = 0;

        loop {
            match self.get(url).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    if retries >= max_retries {
                        return Err(e);
                    }

                    // Проверить тип ошибки
                    if self.is_retryable_error(&e) {
                        retries += 1;
                        let backoff = Duration::from_secs(2u64.pow(retries));
                        warn!("Request failed, retrying in {:?}: {}", backoff, e);
                        tokio::time::sleep(backoff.to_std()?).await;

                        // Invalidate client cache (может быть certificate rotation)
                        self.invalidate_cache();
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn is_retryable_error(&self, error: &anyhow::Error) -> bool {
        let error_string = error.to_string().to_lowercase();

        // TLS handshake failures могут быть из-за certificate rotation
        error_string.contains("tls") || error_string.contains("ssl") ||
        error_string.contains("certificate") || error_string.contains("timeout")
    }

    async fn handle_certificate_error(&self, error: CertificateError) -> Result<()> {
        match error {
            CertificateError::Expired(expiry) => {
                error!("Certificate expired at {}, triggering rotation", expiry);
                // Trigger automatic rotation
                // self.rotator.rotate_certificate(...).await?;
                Err(error.into())
            }
            CertificateError::NotYetValid(not_before) => {
                warn!("Certificate not yet valid until {}, waiting...", not_before);
                // Wait until valid
                let wait_duration = (not_before - Utc::now()).to_std()?;
                tokio::time::sleep(wait_duration).await;
                Ok(())
            }
            _ => Err(error.into()),
        }
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Generate self-signed certificate для testing
    fn generate_self_signed_cert() -> (String, String) {
        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::hash::MessageDigest;
        use openssl::pkey::{PKey, Private};
        use openssl::rsa::Rsa;
        use openssl::x509::{X509NameBuilder, X509};

        // Generate RSA key pair
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa).unwrap();

        // Create X509 name
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("C", "US").unwrap();
        name_builder.append_entry_by_text("ST", "CA").unwrap();
        name_builder.append_entry_by_text("O", "Test Org").unwrap();
        name_builder.append_entry_by_text("CN", "localhost").unwrap();
        let name = name_builder.build();

        // Create certificate
        let mut cert_builder = X509::builder().unwrap();
        cert_builder.set_version(2).unwrap();

        let serial_number = BigNum::from_u32(1).unwrap();
        cert_builder.set_serial_number(&serial_number.to_asn1_integer().unwrap()).unwrap();

        cert_builder.set_subject_name(&name).unwrap();
        cert_builder.set_issuer_name(&name).unwrap();

        cert_builder.set_pubkey(&private_key).unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        cert_builder.set_not_before(&not_before).unwrap();
        cert_builder.set_not_after(&not_after).unwrap();

        cert_builder.sign(&private_key, MessageDigest::sha256()).unwrap();

        let cert = cert_builder.build();

        let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
        let key_pem = String::from_utf8(private_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

        (cert_pem, key_pem)
    }

    #[test]
    fn test_certificate_parsing() {
        let (cert_pem, key_pem) = generate_self_signed_cert();

        let cert_cred = CertificateCredential::new(
            "test-cert".to_string(),
            cert_pem,
            key_pem,
        ).unwrap();

        assert_eq!(cert_cred.subject.contains("CN=localhost"), true);
        assert!(!cert_cred.is_expired());
    }

    #[test]
    fn test_certificate_expiration() {
        let (cert_pem, key_pem) = generate_self_signed_cert();

        let mut cert_cred = CertificateCredential::new(
            "test-cert".to_string(),
            cert_pem,
            key_pem,
        ).unwrap();

        // Override expiration для теста
        cert_cred.not_after = Utc::now() - chrono::Duration::days(1);

        assert!(cert_cred.is_expired());
    }

    #[test]
    fn test_certificate_expires_soon() {
        let (cert_pem, key_pem) = generate_self_signed_cert();

        let mut cert_cred = CertificateCredential::new(
            "test-cert".to_string(),
            cert_pem,
            key_pem,
        ).unwrap();

        // Override expiration — через 20 дней
        cert_cred.not_after = Utc::now() + chrono::Duration::days(20);

        assert!(cert_cred.expires_soon(30));  // Expires within 30 days
        assert!(!cert_cred.expires_soon(10));  // Does not expire within 10 days
    }

    #[tokio::test]
    async fn test_mtls_client_server() {
        // Generate certificates
        let (server_cert_pem, server_key_pem) = generate_self_signed_cert();
        let (client_cert_pem, client_key_pem) = generate_self_signed_cert();

        // Test mTLS handshake
        // (Полный integration test требует запущенных server/client)
    }
}
```

## Complete Example: mTLS Service Communication

```rust
use nebula_credential::{CredentialManager, CredentialId, Scope};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

/// Complete example: Service A ↔ Service B с mTLS authentication
pub struct MtlsServiceManager {
    credential_manager: Arc<CredentialManager>,
    rotator: Arc<CertificateRotator>,

    // Service identities
    service_a_cert_id: CredentialId,
    service_b_cert_id: CredentialId,

    // Cached clients
    clients: Arc<RwLock<HashMap<String, MtlsClient>>>,
}

impl MtlsServiceManager {
    pub async fn new(
        credential_manager: Arc<CredentialManager>,
        service_a_cert_id: CredentialId,
        service_b_cert_id: CredentialId,
    ) -> Self {
        Self {
            credential_manager: credential_manager.clone(),
            rotator: Arc::new(CertificateRotator {
                credential_manager,
                active_certificates: Arc::new(RwLock::new(HashMap::new())),
            }),
            service_a_cert_id,
            service_b_cert_id,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Service A вызывает Service B через mTLS
    pub async fn service_a_call_service_b(&self, endpoint: &str) -> Result<String> {
        let mut client = self.get_or_create_client("service-a", &self.service_a_cert_id).await?;

        let service_b_url = format!("https://service-b.example.com{}", endpoint);

        client.get(&service_b_url).await
    }

    /// Service B вызывает Service A через mTLS
    pub async fn service_b_call_service_a(&self, endpoint: &str) -> Result<String> {
        let mut client = self.get_or_create_client("service-b", &self.service_b_cert_id).await?;

        let service_a_url = format!("https://service-a.example.com{}", endpoint);

        client.get(&service_a_url).await
    }

    async fn get_or_create_client(
        &self,
        service_name: &str,
        cert_id: &CredentialId,
    ) -> Result<MtlsClient> {
        let clients = self.clients.read().await;

        if let Some(client) = clients.get(service_name) {
            return Ok(client.clone());
        }

        drop(clients);

        // Create new client
        let client = MtlsClient::new(
            self.credential_manager.clone(),
            cert_id.clone(),
        );

        let mut clients = self.clients.write().await;
        clients.insert(service_name.to_string(), client.clone());

        Ok(client)
    }

    /// Ротация certificates для всех services
    pub async fn rotate_all_certificates(&self) -> Result<()> {
        info!("Starting certificate rotation for all services");

        // Rotate Service A certificate
        // let (new_cert_a, new_key_a) = self.request_new_certificate("service-a").await?;
        // self.rotator.rotate_certificate(&self.service_a_cert_id, new_cert_a, new_key_a, None).await?;

        // Rotate Service B certificate
        // let (new_cert_b, new_key_b) = self.request_new_certificate("service-b").await?;
        // self.rotator.rotate_certificate(&self.service_b_cert_id, new_cert_b, new_key_b, None).await?;

        // Invalidate cached clients
        let mut clients = self.clients.write().await;
        clients.clear();

        info!("Certificate rotation completed for all services");
        Ok(())
    }

    /// Background task для автоматической ротации expiring certificates
    pub async fn start_auto_rotation_task(&self) {
        let rotator = self.rotator.clone();

        tokio::spawn(async move {
            loop {
                // Проверять каждые 24 часа
                tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;

                info!("Running automatic certificate expiration check");

                if let Err(e) = rotator.auto_rotate_expiring_certificates(30).await {
                    error!("Auto-rotation failed: {}", e);
                }
            }
        });
    }
}

// Пример использования
#[tokio::main]
async fn main() -> Result<()> {
    let credential_manager = Arc::new(CredentialManager::new(/* ... */));

    // Создать certificates для Service A и Service B
    let (service_a_cert, service_a_key) = generate_certificate("service-a")?;
    let (service_b_cert, service_b_key) = generate_certificate("service-b")?;

    let service_a_cert_cred = CertificateCredential::new(
        "service-a".to_string(),
        service_a_cert,
        service_a_key,
    )?;

    let service_b_cert_cred = CertificateCredential::new(
        "service-b".to_string(),
        service_b_cert,
        service_b_key,
    )?;

    let service_a_id = credential_manager.store_credential(
        "mtls-service-a",
        serde_json::to_value(&service_a_cert_cred)?,
        &Scope::Global,
    ).await?;

    let service_b_id = credential_manager.store_credential(
        "mtls-service-b",
        serde_json::to_value(&service_b_cert_cred)?,
        &Scope::Global,
    ).await?;

    // Создать service manager
    let manager = MtlsServiceManager::new(
        credential_manager,
        service_a_id,
        service_b_id,
    ).await;

    // Запустить auto-rotation task
    manager.start_auto_rotation_task().await;

    // Service A → Service B communication
    let response = manager.service_a_call_service_b("/api/data").await?;
    println!("Service B response: {}", response);

    // Service B → Service A communication
    let response = manager.service_b_call_service_a("/api/status").await?;
    println!("Service A response: {}", response);

    Ok(())
}

fn generate_certificate(service_name: &str) -> Result<(String, String)> {
    // Integration с CA или self-signed для testing
    todo!("Implement certificate generation")
}
```

## Links

Related documentation:

- [[02-Crates/nebula-credential/README|nebula-credential]] — основная документация по управлению credentials
- [[02-Crates/nebula-credential/Architecture|Architecture]] — архитектура credential management system
- [[02-Crates/nebula-credential/Encryption|Encryption]] — шифрование credentials в storage
- [[02-Crates/nebula-credential/RotateCredentials|RotateCredentials]] — стратегии ротации credentials
- [[02-Crates/nebula-credential/Examples/BasicApiKey|BasicApiKey]] — simple API key authentication
- [[02-Crates/nebula-credential/Examples/AWSCredentials|AWSCredentials]] — AWS IAM credentials

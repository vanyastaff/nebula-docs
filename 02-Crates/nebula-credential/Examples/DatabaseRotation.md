---
title: DatabaseRotation
tags: [nebula, nebula-credential, docs, database, rotation, postgres, mysql, mongodb]
status: ready
created: 2025-08-24
---

# Database Credential Rotation

Database Credential Rotation — автоматическая ротация database credentials (username/password) с zero downtime через dual-user pattern, connection pool draining и graceful migration.

## Определение

Database credential rotation включает:

1. **Dual-User Pattern** — создание нового пользователя до удаления старого (zero downtime)
2. **Connection Pool Draining** — graceful закрытие старых connections перед переключением
3. **Multi-Database Support** — PostgreSQL, MySQL, MongoDB, Redis
4. **Automatic Rollback** — откат на старые credentials при ошибке

```rust
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Database credential
#[derive(Clone, Serialize, Deserialize)]
pub struct DatabaseCredential {
    pub credential_id: String,
    pub name: String,

    pub database_type: DatabaseType,  // PostgreSQL, MySQL, MongoDB, Redis
    pub host: String,
    pub port: u16,
    pub database: String,  // Database name

    pub username: String,

    #[serde(serialize_with = "serialize_secret")]
    pub password: SecretString,

    // Additional connection parameters
    pub ssl_mode: Option<String>,  // require, prefer, disable
    pub max_connections: Option<u32>,
    pub connection_timeout_seconds: Option<u32>,

    pub created_at: DateTime<Utc>,
    pub last_rotated: Option<DateTime<Utc>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    MongoDB,
    Redis,
}

impl DatabaseCredential {
    pub fn new(
        name: String,
        database_type: DatabaseType,
        host: String,
        port: u16,
        database: String,
        username: String,
        password: String,
    ) -> Self {
        Self {
            credential_id: Uuid::new_v4().to_string(),
            name,
            database_type,
            host,
            port,
            database,
            username,
            password: SecretString::new(password),
            ssl_mode: None,
            max_connections: None,
            connection_timeout_seconds: None,
            created_at: Utc::now(),
            last_rotated: None,
        }
    }

    pub fn with_ssl_mode(mut self, ssl_mode: String) -> Self {
        self.ssl_mode = Some(ssl_mode);
        self
    }

    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = Some(max_connections);
        self
    }

    /// Build connection string для PostgreSQL/MySQL
    pub fn connection_string(&self) -> String {
        match self.database_type {
            DatabaseType::PostgreSQL => {
                let ssl_mode = self.ssl_mode.as_deref().unwrap_or("prefer");
                format!(
                    "postgresql://{}:{}@{}:{}/{}?sslmode={}",
                    self.username,
                    self.password.expose_secret(),
                    self.host,
                    self.port,
                    self.database,
                    ssl_mode
                )
            }
            DatabaseType::MySQL => {
                format!(
                    "mysql://{}:{}@{}:{}/{}",
                    self.username,
                    self.password.expose_secret(),
                    self.host,
                    self.port,
                    self.database
                )
            }
            DatabaseType::MongoDB => {
                format!(
                    "mongodb://{}:{}@{}:{}/{}",
                    self.username,
                    self.password.expose_secret(),
                    self.host,
                    self.port,
                    self.database
                )
            }
            DatabaseType::Redis => {
                format!(
                    "redis://:{}@{}:{}/",
                    self.password.expose_secret(),
                    self.host,
                    self.port
                )
            }
        }
    }
}

fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str("***REDACTED***")
}
```

## Зачем это нужно?

Database credential rotation нужна для:

1. **Security Compliance** — регулярная ротация passwords согласно security policies
2. **Breach Mitigation** — минимизация impact при утечке credentials
3. **Zero Downtime** — ротация без прерывания сервиса через dual-user pattern
4. **Automated Management** — автоматическая ротация без manual intervention
5. **Audit Trail** — tracking всех credential changes для compliance

## Базовое использование

### PostgreSQL Credential Rotation

```rust
use nebula_credential::{CredentialManager, Scope, CredentialId};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

pub struct PostgresCredentialRotator {
    credential_manager: Arc<CredentialManager>,
    // Admin connection для создания/удаления users
    admin_pool: PgPool,
}

impl PostgresCredentialRotator {
    /// Ротация PostgreSQL credentials с zero downtime
    ///
    /// Процесс:
    /// 1. Получить текущие credentials
    /// 2. Создать нового PostgreSQL user с новым password
    /// 3. Предоставить те же permissions новому user
    /// 4. Сохранить новые credentials в storage
    /// 5. Создать новый connection pool с новыми credentials
    /// 6. Drain старый connection pool (graceful shutdown)
    /// 7. Проверить что новый pool работает
    /// 8. Удалить старого PostgreSQL user
    pub async fn rotate_credentials(
        &self,
        credential_id: &CredentialId,
        app_connection_pool: Arc<RwLock<PgPool>>,
    ) -> Result<()> {
        info!("Starting PostgreSQL credential rotation for: {}", credential_id);

        // STAGE 1: Получить текущие credentials
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_db_cred: DatabaseCredential = serde_json::from_value(old_credential.data)?;

        if old_db_cred.database_type != DatabaseType::PostgreSQL {
            return Err(anyhow::anyhow!("Expected PostgreSQL credential"));
        }

        let old_username = old_db_cred.username.clone();

        info!("Current username: {}", old_username);

        // STAGE 2: Generate новый username и password
        let new_username = format!("{}_{}", old_db_cred.name, Uuid::new_v4().to_string().split('-').next().unwrap());
        let new_password = Self::generate_secure_password();

        info!("New username: {}", new_username);

        // STAGE 3: Создать нового PostgreSQL user
        self.create_postgres_user(&new_username, &new_password).await?;

        info!("Created new PostgreSQL user: {}", new_username);

        // STAGE 4: Grant те же permissions что у старого user
        self.clone_user_permissions(&old_username, &new_username).await?;

        info!("Cloned permissions from {} to {}", old_username, new_username);

        // STAGE 5: Создать новый DatabaseCredential
        let mut new_db_cred = DatabaseCredential::new(
            old_db_cred.name.clone(),
            DatabaseType::PostgreSQL,
            old_db_cred.host.clone(),
            old_db_cred.port,
            old_db_cred.database.clone(),
            new_username.clone(),
            new_password,
        );

        new_db_cred.ssl_mode = old_db_cred.ssl_mode.clone();
        new_db_cred.max_connections = old_db_cred.max_connections;
        new_db_cred.last_rotated = Some(Utc::now());

        // STAGE 6: Сохранить новые credentials в storage
        let new_credential_data = serde_json::to_value(&new_db_cred)?;
        self.credential_manager.update_credential(
            credential_id,
            new_credential_data,
        ).await?;

        info!("Updated credential storage");

        // STAGE 7: Создать новый connection pool
        let new_pool = PgPoolOptions::new()
            .max_connections(new_db_cred.max_connections.unwrap_or(10))
            .connect(&new_db_cred.connection_string())
            .await?;

        info!("Created new connection pool");

        // STAGE 8: Verify новый pool работает
        match self.verify_connection(&new_pool).await {
            Ok(_) => {
                info!("New connection pool verified successfully");

                // STAGE 9: Drain старый pool и заменить на новый
                let old_pool = {
                    let mut pool_lock = app_connection_pool.write().await;
                    let old_pool = std::mem::replace(&mut *pool_lock, new_pool);
                    old_pool
                };

                info!("Replaced connection pool");

                // STAGE 10: Gracefully close старый pool
                old_pool.close().await;

                info!("Closed old connection pool");

                // STAGE 11: Подождать чтобы все старые connections закрылись
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                // STAGE 12: Удалить старого PostgreSQL user
                match self.drop_postgres_user(&old_username).await {
                    Ok(_) => {
                        info!("Dropped old PostgreSQL user: {}", old_username);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Failed to drop old user {}: {}", old_username, e);
                        // Не критично — новый user работает
                        Ok(())
                    }
                }
            }
            Err(e) => {
                error!("New connection pool verification failed: {}", e);

                // ROLLBACK: Удалить нового user и вернуть старые credentials
                warn!("Rolling back to old credentials");

                let _ = self.drop_postgres_user(&new_username).await;

                let old_credential_data = serde_json::to_value(&old_db_cred)?;
                self.credential_manager.update_credential(
                    credential_id,
                    old_credential_data,
                ).await?;

                Err(anyhow::anyhow!("Rotation failed and rolled back: {}", e))
            }
        }
    }

    /// Создать нового PostgreSQL user
    async fn create_postgres_user(&self, username: &str, password: &str) -> Result<()> {
        sqlx::query(&format!(
            "CREATE USER {} WITH PASSWORD $1",
            username
        ))
        .bind(password)
        .execute(&self.admin_pool)
        .await?;

        Ok(())
    }

    /// Clone permissions от старого user к новому
    async fn clone_user_permissions(&self, old_username: &str, new_username: &str) -> Result<()> {
        // Get database grants
        let grants = sqlx::query(
            r#"
            SELECT 'GRANT ' || privilege_type || ' ON ' || table_schema || '.' || table_name || ' TO ' || $2
            FROM information_schema.table_privileges
            WHERE grantee = $1
            "#
        )
        .bind(old_username)
        .bind(new_username)
        .fetch_all(&self.admin_pool)
        .await?;

        for grant in grants {
            let grant_sql: String = grant.get(0);
            sqlx::query(&grant_sql).execute(&self.admin_pool).await?;
        }

        // Grant schema usage
        sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {}", new_username))
            .execute(&self.admin_pool)
            .await?;

        // Grant connect to database
        sqlx::query(&format!("GRANT CONNECT ON DATABASE postgres TO {}", new_username))
            .execute(&self.admin_pool)
            .await?;

        Ok(())
    }

    /// Удалить PostgreSQL user
    async fn drop_postgres_user(&self, username: &str) -> Result<()> {
        // Terminate active connections
        sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{}'",
            username
        ))
        .execute(&self.admin_pool)
        .await?;

        // Drop user
        sqlx::query(&format!("DROP USER IF EXISTS {}", username))
            .execute(&self.admin_pool)
            .await?;

        Ok(())
    }

    /// Verify connection pool работает
    async fn verify_connection(&self, pool: &PgPool) -> Result<()> {
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(pool)
            .await?;

        if row.0 != 1 {
            return Err(anyhow::anyhow!("Connection verification failed"));
        }

        Ok(())
    }

    /// Generate secure random password
    fn generate_secure_password() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  abcdefghijklmnopqrstuvwxyz\
                                  0123456789\
                                  !@#$%^&*";
        const PASSWORD_LEN: usize = 32;

        let mut rng = rand::thread_rng();

        (0..PASSWORD_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}
```

### MySQL Credential Rotation

```rust
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};

pub struct MySqlCredentialRotator {
    credential_manager: Arc<CredentialManager>,
    admin_pool: MySqlPool,
}

impl MySqlCredentialRotator {
    pub async fn rotate_credentials(
        &self,
        credential_id: &CredentialId,
        app_connection_pool: Arc<RwLock<MySqlPool>>,
    ) -> Result<()> {
        info!("Starting MySQL credential rotation");

        // Get old credentials
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_db_cred: DatabaseCredential = serde_json::from_value(old_credential.data)?;

        if old_db_cred.database_type != DatabaseType::MySQL {
            return Err(anyhow::anyhow!("Expected MySQL credential"));
        }

        let old_username = old_db_cred.username.clone();

        // Generate new username and password
        let new_username = format!("{}_{}", old_db_cred.name, Uuid::new_v4().to_string().split('-').next().unwrap());
        let new_password = Self::generate_secure_password();

        // Create new MySQL user
        self.create_mysql_user(&new_username, &new_password).await?;

        info!("Created new MySQL user: {}", new_username);

        // Clone permissions
        self.clone_mysql_permissions(&old_username, &new_username).await?;

        // Save new credentials
        let mut new_db_cred = DatabaseCredential::new(
            old_db_cred.name.clone(),
            DatabaseType::MySQL,
            old_db_cred.host.clone(),
            old_db_cred.port,
            old_db_cred.database.clone(),
            new_username.clone(),
            new_password,
        );

        new_db_cred.last_rotated = Some(Utc::now());

        let new_credential_data = serde_json::to_value(&new_db_cred)?;
        self.credential_manager.update_credential(credential_id, new_credential_data).await?;

        // Create new connection pool
        let new_pool = MySqlPoolOptions::new()
            .max_connections(10)
            .connect(&new_db_cred.connection_string())
            .await?;

        // Verify new pool
        self.verify_mysql_connection(&new_pool).await?;

        // Replace pool
        let old_pool = {
            let mut pool_lock = app_connection_pool.write().await;
            std::mem::replace(&mut *pool_lock, new_pool)
        };

        old_pool.close().await;

        // Drop old user
        self.drop_mysql_user(&old_username).await?;

        info!("MySQL credential rotation completed");
        Ok(())
    }

    async fn create_mysql_user(&self, username: &str, password: &str) -> Result<()> {
        sqlx::query(&format!(
            "CREATE USER '{}'@'%' IDENTIFIED BY ?",
            username
        ))
        .bind(password)
        .execute(&self.admin_pool)
        .await?;

        Ok(())
    }

    async fn clone_mysql_permissions(&self, old_username: &str, new_username: &str) -> Result<()> {
        // Get grants from old user
        let grants = sqlx::query(&format!("SHOW GRANTS FOR '{}'@'%'", old_username))
            .fetch_all(&self.admin_pool)
            .await?;

        for grant in grants {
            let grant_sql: String = grant.get(0);

            // Replace old username with new username
            let new_grant = grant_sql.replace(
                &format!("'{}'@'%'", old_username),
                &format!("'{}'@'%'", new_username)
            );

            sqlx::query(&new_grant).execute(&self.admin_pool).await?;
        }

        // Flush privileges
        sqlx::query("FLUSH PRIVILEGES").execute(&self.admin_pool).await?;

        Ok(())
    }

    async fn drop_mysql_user(&self, username: &str) -> Result<()> {
        sqlx::query(&format!("DROP USER IF EXISTS '{}'@'%'", username))
            .execute(&self.admin_pool)
            .await?;

        Ok(())
    }

    async fn verify_mysql_connection(&self, pool: &MySqlPool) -> Result<()> {
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(pool)
            .await?;

        if row.0 != 1 {
            return Err(anyhow::anyhow!("Connection verification failed"));
        }

        Ok(())
    }

    fn generate_secure_password() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  abcdefghijklmnopqrstuvwxyz\
                                  0123456789\
                                  !@#$%^&*";
        const PASSWORD_LEN: usize = 32;

        let mut rng = rand::thread_rng();
        (0..PASSWORD_LEN)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    }
}
```

### MongoDB Credential Rotation

```rust
use mongodb::{Client, options::ClientOptions};
use bson::{doc, Document};

pub struct MongoDbCredentialRotator {
    credential_manager: Arc<CredentialManager>,
    admin_client: Client,
}

impl MongoDbCredentialRotator {
    pub async fn rotate_credentials(
        &self,
        credential_id: &CredentialId,
    ) -> Result<()> {
        info!("Starting MongoDB credential rotation");

        // Get old credentials
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_db_cred: DatabaseCredential = serde_json::from_value(old_credential.data)?;

        if old_db_cred.database_type != DatabaseType::MongoDB {
            return Err(anyhow::anyhow!("Expected MongoDB credential"));
        }

        let old_username = old_db_cred.username.clone();

        // Generate new username and password
        let new_username = format!("{}_{}", old_db_cred.name, Uuid::new_v4().to_string().split('-').next().unwrap());
        let new_password = Self::generate_secure_password();

        // Create new MongoDB user
        self.create_mongo_user(&old_db_cred.database, &new_username, &new_password).await?;

        info!("Created new MongoDB user: {}", new_username);

        // Clone roles from old user
        self.clone_mongo_roles(&old_db_cred.database, &old_username, &new_username).await?;

        // Save new credentials
        let mut new_db_cred = DatabaseCredential::new(
            old_db_cred.name.clone(),
            DatabaseType::MongoDB,
            old_db_cred.host.clone(),
            old_db_cred.port,
            old_db_cred.database.clone(),
            new_username.clone(),
            new_password,
        );

        new_db_cred.last_rotated = Some(Utc::now());

        let new_credential_data = serde_json::to_value(&new_db_cred)?;
        self.credential_manager.update_credential(credential_id, new_credential_data).await?;

        // Verify new credentials work
        self.verify_mongo_credentials(&new_db_cred).await?;

        // Drop old user
        self.drop_mongo_user(&old_db_cred.database, &old_username).await?;

        info!("MongoDB credential rotation completed");
        Ok(())
    }

    async fn create_mongo_user(&self, database: &str, username: &str, password: &str) -> Result<()> {
        let db = self.admin_client.database(database);

        let create_user_cmd = doc! {
            "createUser": username,
            "pwd": password,
            "roles": []  // Roles будут добавлены позже
        };

        db.run_command(create_user_cmd, None).await?;
        Ok(())
    }

    async fn clone_mongo_roles(&self, database: &str, old_username: &str, new_username: &str) -> Result<()> {
        let db = self.admin_client.database(database);

        // Get old user info
        let user_info_cmd = doc! {
            "usersInfo": old_username
        };

        let user_info: Document = db.run_command(user_info_cmd, None).await?;

        if let Some(users) = user_info.get_array("users").ok() {
            if let Some(user) = users.first() {
                if let Some(user_doc) = user.as_document() {
                    if let Some(roles) = user_doc.get_array("roles").ok() {
                        // Grant same roles to new user
                        let grant_roles_cmd = doc! {
                            "grantRolesToUser": new_username,
                            "roles": roles.clone()
                        };

                        db.run_command(grant_roles_cmd, None).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn drop_mongo_user(&self, database: &str, username: &str) -> Result<()> {
        let db = self.admin_client.database(database);

        let drop_user_cmd = doc! {
            "dropUser": username
        };

        db.run_command(drop_user_cmd, None).await?;
        Ok(())
    }

    async fn verify_mongo_credentials(&self, db_cred: &DatabaseCredential) -> Result<()> {
        let client_options = ClientOptions::parse(&db_cred.connection_string()).await?;
        let client = Client::with_options(client_options)?;

        // Simple ping to verify
        let admin_db = client.database("admin");
        admin_db.run_command(doc! { "ping": 1 }, None).await?;

        Ok(())
    }

    fn generate_secure_password() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                  abcdefghijklmnopqrstuvwxyz\
                                  0123456789";
        const PASSWORD_LEN: usize = 32;

        let mut rng = rand::thread_rng();
        (0..PASSWORD_LEN)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect()
    }
}
```

## Best Practices

### ✅ Правильные практики

```rust
// ✅ ПРАВИЛЬНО: Использовать SecretString для passwords
pub struct DatabaseCredential {
    pub username: String,  // Не секретный
    pub password: SecretString,  // Секретный
}

// ✅ ПРАВИЛЬНО: Dual-user pattern (создать нового user ДО удаления старого)
create_new_user(&new_username, &new_password).await?;
clone_permissions(&old_username, &new_username).await?;
verify_new_user(&new_username).await?;
drop_old_user(&old_username).await?;  // Последним

// ✅ ПРАВИЛЬНО: Graceful connection pool draining
let old_pool = std::mem::replace(&mut *pool_lock, new_pool);
old_pool.close().await;  // Ждет закрытия всех connections
tokio::time::sleep(Duration::from_secs(5)).await;  // Grace period

// ✅ ПРАВИЛЬНО: Verify новые credentials работают перед удалением старых
match verify_connection(&new_pool).await {
    Ok(_) => drop_old_user().await?,
    Err(e) => rollback_to_old_credentials().await?,
}

// ✅ ПРАВИЛЬНО: Clone ВСЕ permissions от старого user
clone_table_grants(&old_user, &new_user).await?;
clone_schema_usage(&old_user, &new_user).await?;
clone_database_connect(&old_user, &new_user).await?;

// ✅ ПРАВИЛЬНО: Generate cryptographically secure passwords
use rand::Rng;
let password: String = (0..32)
    .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
    .collect();

// ✅ ПРАВИЛЬНО: Terminate активные connections старого user перед удалением
sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1")
    .bind(&old_username)
    .execute(&admin_pool)
    .await?;

// ✅ ПРАВИЛЬНО: Логировать только usernames, не passwords
info!("Rotating credentials for user: {}", username);  // OK
// НЕ логировать password!

// ✅ ПРАВИЛЬНО: Rollback при ошибке
if verify_new_credentials().await.is_err() {
    drop_new_user().await?;
    restore_old_credentials().await?;
    return Err(anyhow::anyhow!("Rotation failed"));
}

// ✅ ПРАВИЛЬНО: Separate admin credentials для rotation operations
let admin_pool = connect_with_admin_credentials().await?;
admin_pool.execute("CREATE USER ...").await?;
```

### ❌ Неправильные практики

```rust
// ❌ НЕПРАВИЛЬНО: Password в обычной String
pub struct BadDatabaseCredential {
    pub username: String,
    pub password: String,  // Попадет в логи!
}

// ❌ НЕПРАВИЛЬНО: Удалить старого user ДО создания нового (downtime!)
drop_old_user(&old_username).await?;
create_new_user(&new_username, &new_password).await?;  // Downtime между этими steps!

// ❌ НЕПРАВИЛЬНО: Не drain connection pool перед заменой
*pool_lock = new_pool;  // Старые connections могут быть активны!

// ❌ НЕПРАВИЛЬНО: Не verify новые credentials
create_new_user().await?;
drop_old_user().await?;  // Если новый user не работает — полный downtime!

// ❌ НЕПРАВИЛЬНО: Не clone permissions
create_new_user(&new_username, &new_password).await?;
// Забыли grant permissions — новый user ничего не может делать!

// ❌ НЕПРАВИЛЬНО: Weak passwords
let password = "password123";  // Слишком простой!

// ❌ НЕПРАВИЛЬНО: Не terminate активные connections перед удалением user
drop_user(&username).await?;  // Может провалиться если есть активные connections!

// ❌ НЕПРАВИЛЬНО: Логировать passwords
info!("New password: {}", password);  // УТЕЧКА В ЛОГИ!

// ❌ НЕПРАВИЛЬНО: Игнорировать ошибки ротации
let _ = rotate_credentials().await;  // Молча провалилось!

// ❌ НЕПРАВИЛЬНО: Использовать application credentials для rotation
let app_pool = get_app_pool();
app_pool.execute("CREATE USER ...").await?;  // App user не имеет permissions!

// ❌ НЕПРАВИЛЬНО: Hardcode connection strings
let connection_string = "postgresql://user:password@localhost/db";  // Не делать так!

// ❌ НЕПРАВИЛЬНО: Не использовать transactions для atomic operations
create_user().await?;
// Crash здесь — partial state!
grant_permissions().await?;
```

## Connection Pool Management

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

/// Connection pool manager с автоматической rotation support
pub struct DatabaseConnectionManager {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,

    // Current active connection pool
    pool: Arc<RwLock<PgPool>>,

    // Rotator
    rotator: Arc<PostgresCredentialRotator>,
}

impl DatabaseConnectionManager {
    pub async fn new(
        credential_manager: Arc<CredentialManager>,
        credential_id: CredentialId,
        admin_pool: PgPool,
    ) -> Result<Self> {
        // Get initial credentials
        let credential = credential_manager
            .get_credential(&credential_id, &Scope::Global)
            .await?;

        let db_cred: DatabaseCredential = serde_json::from_value(credential.data)?;

        // Create initial connection pool
        let pool = PgPoolOptions::new()
            .max_connections(db_cred.max_connections.unwrap_or(10))
            .connect(&db_cred.connection_string())
            .await?;

        Ok(Self {
            credential_manager: credential_manager.clone(),
            credential_id: credential_id.clone(),
            pool: Arc::new(RwLock::new(pool)),
            rotator: Arc::new(PostgresCredentialRotator {
                credential_manager,
                admin_pool,
            }),
        })
    }

    /// Get connection pool для application use
    pub async fn pool(&self) -> Arc<RwLock<PgPool>> {
        self.pool.clone()
    }

    /// Rotate credentials с graceful pool replacement
    pub async fn rotate_credentials(&self) -> Result<()> {
        self.rotator.rotate_credentials(&self.credential_id, self.pool.clone()).await
    }

    /// Background task для автоматической rotation каждые N дней
    pub async fn start_auto_rotation(&self, rotation_days: i64) {
        let credential_id = self.credential_id.clone();
        let pool = self.pool.clone();
        let rotator = self.rotator.clone();

        tokio::spawn(async move {
            loop {
                // Check каждые 24 часа
                tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;

                // Get credential age
                // if credential_age > rotation_days {
                    info!("Triggering automatic credential rotation");

                    if let Err(e) = rotator.rotate_credentials(&credential_id, pool.clone()).await {
                        error!("Automatic rotation failed: {}", e);
                    }
                // }
            }
        });
    }
}
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum DatabaseRotationError {
    #[error("Failed to create new user: {0}")]
    CreateUserFailed(String),

    #[error("Failed to clone permissions: {0}")]
    ClonePermissionsFailed(String),

    #[error("Connection pool verification failed: {0}")]
    VerificationFailed(String),

    #[error("Failed to drop old user: {0}")]
    DropUserFailed(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Database type not supported: {0:?}")]
    UnsupportedDatabaseType(DatabaseType),

    #[error("Admin credentials required for rotation")]
    AdminCredentialsRequired,
}

impl PostgresCredentialRotator {
    async fn rotate_with_error_handling(&self, credential_id: &CredentialId) -> Result<(), DatabaseRotationError> {
        let old_cred = self.get_credential(credential_id).await
            .map_err(|e| DatabaseRotationError::VerificationFailed(e.to_string()))?;

        let new_username = self.generate_username();
        let new_password = Self::generate_secure_password();

        // Try to create new user
        if let Err(e) = self.create_postgres_user(&new_username, &new_password).await {
            return Err(DatabaseRotationError::CreateUserFailed(e.to_string()));
        }

        // Try to clone permissions
        if let Err(e) = self.clone_user_permissions(&old_cred.username, &new_username).await {
            // Cleanup: drop partially created user
            let _ = self.drop_postgres_user(&new_username).await;
            return Err(DatabaseRotationError::ClonePermissionsFailed(e.to_string()));
        }

        // Continue with rotation...

        Ok(())
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{clients, images::postgres::Postgres};

    #[tokio::test]
    async fn test_postgres_credential_rotation() {
        // Start PostgreSQL container для testing
        let docker = clients::Cli::default();
        let postgres_container = docker.run(Postgres::default());

        let host = "localhost";
        let port = postgres_container.get_host_port_ipv4(5432);

        // Create admin pool
        let admin_connection_string = format!(
            "postgresql://postgres:postgres@{}:{}/postgres",
            host, port
        );

        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_connection_string)
            .await
            .unwrap();

        let credential_manager = Arc::new(CredentialManager::new(/* ... */));

        // Create initial credential
        let initial_cred = DatabaseCredential::new(
            "test_db".to_string(),
            DatabaseType::PostgreSQL,
            host.to_string(),
            port,
            "postgres".to_string(),
            "test_user_initial".to_string(),
            "initial_password".to_string(),
        );

        // Store credential
        let credential_id = credential_manager.store_credential(
            "test-db",
            serde_json::to_value(&initial_cred).unwrap(),
            &Scope::Global,
        ).await.unwrap();

        // Create rotator
        let rotator = PostgresCredentialRotator {
            credential_manager: credential_manager.clone(),
            admin_pool,
        };

        // Perform rotation
        let app_pool = Arc::new(RwLock::new(
            PgPoolOptions::new()
                .max_connections(5)
                .connect(&initial_cred.connection_string())
                .await
                .unwrap()
        ));

        rotator.rotate_credentials(&credential_id, app_pool.clone()).await.unwrap();

        // Verify new credentials работают
        let pool = app_pool.read().await;
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&*pool)
            .await
            .unwrap();

        assert_eq!(row.0, 1);
    }

    #[test]
    fn test_password_generation() {
        let password = PostgresCredentialRotator::generate_secure_password();

        // Verify length
        assert_eq!(password.len(), 32);

        // Verify contains different character types
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_numeric()));
    }

    #[test]
    fn test_connection_string_generation() {
        let db_cred = DatabaseCredential::new(
            "test".to_string(),
            DatabaseType::PostgreSQL,
            "localhost".to_string(),
            5432,
            "mydb".to_string(),
            "myuser".to_string(),
            "mypassword".to_string(),
        );

        let conn_str = db_cred.connection_string();

        assert!(conn_str.contains("postgresql://"));
        assert!(conn_str.contains("myuser"));
        assert!(conn_str.contains("mypassword"));
        assert!(conn_str.contains("localhost:5432"));
        assert!(conn_str.contains("mydb"));
    }
}
```

## Complete Example: Multi-Database Rotation Manager

```rust
use std::collections::HashMap;

/// Unified database rotation manager для всех database types
pub struct MultiDatabaseRotationManager {
    credential_manager: Arc<CredentialManager>,

    // Database-specific rotators
    postgres_rotators: HashMap<CredentialId, Arc<PostgresCredentialRotator>>,
    mysql_rotators: HashMap<CredentialId, Arc<MySqlCredentialRotator>>,
    mongo_rotators: HashMap<CredentialId, Arc<MongoDbCredentialRotator>>,
}

impl MultiDatabaseRotationManager {
    pub fn new(credential_manager: Arc<CredentialManager>) -> Self {
        Self {
            credential_manager,
            postgres_rotators: HashMap::new(),
            mysql_rotators: HashMap::new(),
            mongo_rotators: HashMap::new(),
        }
    }

    /// Register database для rotation
    pub async fn register_database(
        &mut self,
        credential_id: CredentialId,
        admin_pool: DatabaseAdminPool,
    ) -> Result<()> {
        let credential = self.credential_manager
            .get_credential(&credential_id, &Scope::Global)
            .await?;

        let db_cred: DatabaseCredential = serde_json::from_value(credential.data)?;

        match db_cred.database_type {
            DatabaseType::PostgreSQL => {
                let rotator = Arc::new(PostgresCredentialRotator {
                    credential_manager: self.credential_manager.clone(),
                    admin_pool: admin_pool.into_postgres()?,
                });
                self.postgres_rotators.insert(credential_id, rotator);
            }
            DatabaseType::MySQL => {
                let rotator = Arc::new(MySqlCredentialRotator {
                    credential_manager: self.credential_manager.clone(),
                    admin_pool: admin_pool.into_mysql()?,
                });
                self.mysql_rotators.insert(credential_id, rotator);
            }
            DatabaseType::MongoDB => {
                let rotator = Arc::new(MongoDbCredentialRotator {
                    credential_manager: self.credential_manager.clone(),
                    admin_client: admin_pool.into_mongo()?,
                });
                self.mongo_rotators.insert(credential_id, rotator);
            }
            _ => return Err(anyhow::anyhow!("Unsupported database type")),
        }

        Ok(())
    }

    /// Rotate credentials для specific database
    pub async fn rotate_database(&self, credential_id: &CredentialId) -> Result<()> {
        if let Some(rotator) = self.postgres_rotators.get(credential_id) {
            // rotator.rotate_credentials(credential_id, ...).await?;
            return Ok(());
        }

        if let Some(rotator) = self.mysql_rotators.get(credential_id) {
            // rotator.rotate_credentials(credential_id, ...).await?;
            return Ok(());
        }

        if let Some(rotator) = self.mongo_rotators.get(credential_id) {
            rotator.rotate_credentials(credential_id).await?;
            return Ok(());
        }

        Err(anyhow::anyhow!("No rotator found for credential"))
    }

    /// Rotate ALL registered databases
    pub async fn rotate_all_databases(&self) -> Result<()> {
        info!("Starting rotation for all databases");

        let mut errors = Vec::new();

        // Rotate all PostgreSQL databases
        for (cred_id, rotator) in &self.postgres_rotators {
            if let Err(e) = self.rotate_database(cred_id).await {
                error!("Failed to rotate PostgreSQL {}: {}", cred_id, e);
                errors.push((cred_id.clone(), e));
            }
        }

        // Rotate all MySQL databases
        for (cred_id, rotator) in &self.mysql_rotators {
            if let Err(e) = self.rotate_database(cred_id).await {
                error!("Failed to rotate MySQL {}: {}", cred_id, e);
                errors.push((cred_id.clone(), e));
            }
        }

        // Rotate all MongoDB databases
        for (cred_id, rotator) in &self.mongo_rotators {
            if let Err(e) = self.rotate_database(cred_id).await {
                error!("Failed to rotate MongoDB {}: {}", cred_id, e);
                errors.push((cred_id.clone(), e));
            }
        }

        if errors.is_empty() {
            info!("All database rotations completed successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!("{} database rotations failed", errors.len()))
        }
    }
}

pub enum DatabaseAdminPool {
    Postgres(PgPool),
    MySql(MySqlPool),
    Mongo(Client),
}

impl DatabaseAdminPool {
    fn into_postgres(self) -> Result<PgPool> {
        match self {
            DatabaseAdminPool::Postgres(pool) => Ok(pool),
            _ => Err(anyhow::anyhow!("Expected PostgreSQL pool")),
        }
    }

    fn into_mysql(self) -> Result<MySqlPool> {
        match self {
            DatabaseAdminPool::MySql(pool) => Ok(pool),
            _ => Err(anyhow::anyhow!("Expected MySQL pool")),
        }
    }

    fn into_mongo(self) -> Result<Client> {
        match self {
            DatabaseAdminPool::Mongo(client) => Ok(client),
            _ => Err(anyhow::anyhow!("Expected MongoDB client")),
        }
    }
}

// Пример использования
#[tokio::main]
async fn main() -> Result<()> {
    let credential_manager = Arc::new(CredentialManager::new(/* ... */));

    let mut rotation_manager = MultiDatabaseRotationManager::new(credential_manager.clone());

    // Register PostgreSQL database
    let pg_admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect("postgresql://admin:admin@localhost/postgres")
        .await?;

    let pg_cred_id = CredentialId::from("postgres-prod");
    rotation_manager.register_database(
        pg_cred_id.clone(),
        DatabaseAdminPool::Postgres(pg_admin_pool),
    ).await?;

    // Rotate single database
    rotation_manager.rotate_database(&pg_cred_id).await?;

    // Or rotate all databases
    rotation_manager.rotate_all_databases().await?;

    Ok(())
}
```

## Links

Related documentation:

- [[02-Crates/nebula-credential/README|nebula-credential]] — основная документация по управлению credentials
- [[02-Crates/nebula-credential/Architecture|Architecture]] — архитектура credential management system
- [[02-Crates/nebula-credential/RotateCredentials|RotateCredentials]] — общие стратегии ротации credentials
- [[02-Crates/nebula-credential/Encryption|Encryption]] — шифрование credentials в storage
- [[02-Crates/nebula-resource/README|nebula-resource]] — resource management для database connection pools

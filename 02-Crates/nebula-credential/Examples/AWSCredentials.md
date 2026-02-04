---
title: AWSCredentials
tags: [nebula, nebula-credential, docs, aws, iam, sts]
status: ready
created: 2025-08-24
---

# AWS Credentials

AWS Credentials — управление учетными данными для AWS (Amazon Web Services), включая Access Keys, Secret Keys, Session Tokens, AssumeRole и автоматическую ротацию через IAM API.

## Определение

AWS использует несколько типов credentials для аутентификации:

1. **Access Key + Secret Key** — долгосрочные статические ключи IAM пользователя
2. **Session Token** — временные credentials от AWS STS (Security Token Service)
3. **AssumeRole** — временные credentials для доступа к другому AWS аккаунту или роли
4. **Instance Profile** — credentials для EC2 инстансов (автоматически обновляются)

```rust
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

/// AWS IAM Access Key credentials
#[derive(Clone, Serialize, Deserialize)]
pub struct AwsCredential {
    pub credential_id: String,
    pub access_key_id: String,  // Не секретный, но идентифицирует ключ

    #[serde(serialize_with = "serialize_secret")]
    pub secret_access_key: SecretString,  // Секретный ключ, никогда не логируется

    #[serde(serialize_with = "serialize_option_secret")]
    pub session_token: Option<SecretString>,  // Для STS temporary credentials

    pub region: String,  // us-east-1, eu-west-1, etc.
    pub account_id: Option<String>,
    pub user_arn: Option<String>,  // arn:aws:iam::123456789012:user/alice

    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,  // Для STS credentials
    pub last_rotated: Option<DateTime<Utc>>,
}

/// AWS STS AssumeRole credentials
#[derive(Clone, Serialize, Deserialize)]
pub struct AwsAssumeRoleCredential {
    pub role_arn: String,  // arn:aws:iam::123456789012:role/MyRole
    pub role_session_name: String,  // Имя сессии для логов CloudTrail
    pub external_id: Option<String>,  // Для cross-account access
    pub duration_seconds: i32,  // 900-43200 (15 минут - 12 часов)
    pub mfa_serial: Option<String>,  // arn:aws:iam::123456789012:mfa/alice
    pub mfa_token: Option<String>,  // Текущий MFA token

    // Base credentials для AssumeRole вызова
    pub base_credential_id: String,
}

impl AwsCredential {
    pub fn new(access_key_id: String, secret_access_key: String, region: String) -> Self {
        Self {
            credential_id: Uuid::new_v4().to_string(),
            access_key_id,
            secret_access_key: SecretString::new(secret_access_key),
            session_token: None,
            region,
            account_id: None,
            user_arn: None,
            created_at: Utc::now(),
            expires_at: None,
            last_rotated: None,
        }
    }

    pub fn with_session_token(mut self, token: String, expires_at: DateTime<Utc>) -> Self {
        self.session_token = Some(SecretString::new(token));
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn needs_rotation(&self, rotation_days: i64) -> bool {
        if let Some(last_rotated) = self.last_rotated {
            Utc::now() > last_rotated + Duration::days(rotation_days)
        } else {
            // Никогда не ротировался — нужна ротация
            true
        }
    }
}

// Вспомогательные функции для сериализации SecretString
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str("***REDACTED***")
}

fn serialize_option_secret<S>(secret: &Option<SecretString>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match secret {
        Some(_) => serializer.serialize_str("***REDACTED***"),
        None => serializer.serialize_none(),
    }
}
```

## Зачем это нужно?

AWS Credentials используются для:

1. **Аутентификация в AWS Services** — S3, DynamoDB, Lambda, SQS, SNS, etc.
2. **Cross-Account Access** — доступ к ресурсам в других AWS аккаунтах через AssumeRole
3. **Temporary Credentials** — минимизация risk через короткоживущие STS credentials
4. **Automated Rotation** — регулярная ротация access keys через IAM API для безопасности
5. **Multi-Region Operations** — работа с ресурсами в разных AWS регионах

## Базовое использование

### Статические AWS Credentials

```rust
use nebula_credential::{CredentialManager, Scope, CredentialId};
use aws_sdk_s3::Client as S3Client;
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use std::sync::Arc;
use anyhow::Result;

pub struct AwsS3Service {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
}

impl AwsS3Service {
    pub fn new(credential_manager: Arc<CredentialManager>, credential_id: CredentialId) -> Self {
        Self {
            credential_manager,
            credential_id,
        }
    }

    async fn get_aws_credential(&self) -> Result<AwsCredential> {
        let credential = self.credential_manager
            .get_credential(&self.credential_id, &Scope::Global)
            .await?;

        let aws_cred: AwsCredential = serde_json::from_value(credential.data)?;

        if aws_cred.is_expired() {
            return Err(anyhow::anyhow!("AWS credential expired"));
        }

        Ok(aws_cred)
    }

    async fn build_s3_client(&self) -> Result<S3Client> {
        let aws_cred = self.get_aws_credential().await?;

        // Создаем AWS SDK Credentials
        let credentials = if let Some(session_token) = &aws_cred.session_token {
            Credentials::new(
                &aws_cred.access_key_id,
                aws_cred.secret_access_key.expose_secret(),
                Some(session_token.expose_secret().to_string()),
                None,  // expiration
                "nebula-credential",
            )
        } else {
            Credentials::new(
                &aws_cred.access_key_id,
                aws_cred.secret_access_key.expose_secret(),
                None,
                None,
                "nebula-credential",
            )
        };

        // Конфигурируем AWS SDK
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        Ok(S3Client::new(&config))
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        let client = self.build_s3_client().await?;

        let response = client.list_buckets().send().await?;

        let buckets = response.buckets()
            .iter()
            .filter_map(|b| b.name().map(|n| n.to_string()))
            .collect();

        Ok(buckets)
    }

    pub async fn upload_file(&self, bucket: &str, key: &str, content: Vec<u8>) -> Result<()> {
        let client = self.build_s3_client().await?;

        client.put_object()
            .bucket(bucket)
            .key(key)
            .body(content.into())
            .send()
            .await?;

        Ok(())
    }
}
```

### AWS STS AssumeRole

```rust
use aws_sdk_sts::Client as StsClient;
use aws_sdk_sts::config::Region;

pub struct AwsAssumeRoleService {
    credential_manager: Arc<CredentialManager>,
}

impl AwsAssumeRoleService {
    /// AssumeRole для получения temporary credentials
    pub async fn assume_role(
        &self,
        base_credential_id: &CredentialId,
        role_config: &AwsAssumeRoleCredential,
    ) -> Result<AwsCredential> {
        // Получаем базовые credentials для AssumeRole вызова
        let base_cred = self.credential_manager
            .get_credential(base_credential_id, &Scope::Global)
            .await?;
        let base_aws: AwsCredential = serde_json::from_value(base_cred.data)?;

        // Создаем STS client с базовыми credentials
        let credentials = Credentials::new(
            &base_aws.access_key_id,
            base_aws.secret_access_key.expose_secret(),
            None,
            None,
            "nebula-sts",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(base_aws.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        let sts_client = StsClient::new(&config);

        // AssumeRole request
        let mut request = sts_client.assume_role()
            .role_arn(&role_config.role_arn)
            .role_session_name(&role_config.role_session_name)
            .duration_seconds(role_config.duration_seconds);

        if let Some(external_id) = &role_config.external_id {
            request = request.external_id(external_id);
        }

        if let (Some(mfa_serial), Some(mfa_token)) = (&role_config.mfa_serial, &role_config.mfa_token) {
            request = request.serial_number(mfa_serial).token_code(mfa_token);
        }

        let response = request.send().await?;

        let creds = response.credentials()
            .ok_or_else(|| anyhow::anyhow!("No credentials in AssumeRole response"))?;

        // Создаем temporary AWS credential
        let temp_credential = AwsCredential {
            credential_id: Uuid::new_v4().to_string(),
            access_key_id: creds.access_key_id().to_string(),
            secret_access_key: SecretString::new(creds.secret_access_key().to_string()),
            session_token: Some(SecretString::new(creds.session_token().to_string())),
            region: base_aws.region.clone(),
            account_id: None,
            user_arn: Some(role_config.role_arn.clone()),
            created_at: Utc::now(),
            expires_at: Some(creds.expiration().clone().try_into()?),
            last_rotated: None,
        };

        Ok(temp_credential)
    }
}
```

## AWS IAM Access Key Rotation

### Multi-Stage Zero-Downtime Rotation

```rust
use aws_sdk_iam::Client as IamClient;
use aws_sdk_iam::types::AccessKey;

pub struct AwsCredentialRotator {
    credential_manager: Arc<CredentialManager>,
}

impl AwsCredentialRotator {
    /// Ротация AWS IAM Access Key с zero downtime
    ///
    /// Процесс:
    /// 1. Создать новый access key через IAM API (у пользователя может быть макс 2 ключа)
    /// 2. Сохранить новый ключ в credential storage
    /// 3. Подождать propagation (30 сек)
    /// 4. Проверить что новый ключ работает
    /// 5. Если новый ключ работает — удалить старый ключ
    /// 6. Если новый ключ НЕ работает — откатиться на старый и удалить новый
    pub async fn rotate_access_key(&self, credential_id: &CredentialId) -> Result<()> {
        // STAGE 1: Получить текущий credential
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_aws: AwsCredential = serde_json::from_value(old_credential.data.clone())?;

        info!("Starting AWS credential rotation for access key: {}", old_aws.access_key_id);

        // STAGE 2: Создать IAM client с текущими credentials
        let credentials = Credentials::new(
            &old_aws.access_key_id,
            old_aws.secret_access_key.expose_secret(),
            None,
            None,
            "nebula-rotation",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(old_aws.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        let iam_client = IamClient::new(&config);

        // STAGE 3: Получить текущего IAM user
        let current_user = iam_client.get_user().send().await?;
        let user_name = current_user.user()
            .and_then(|u| u.user_name())
            .ok_or_else(|| anyhow::anyhow!("Cannot determine IAM user name"))?;

        info!("Rotating access key for IAM user: {}", user_name);

        // STAGE 4: Создать новый access key
        let new_key_response = iam_client
            .create_access_key()
            .user_name(user_name)
            .send()
            .await?;

        let new_key = new_key_response.access_key()
            .ok_or_else(|| anyhow::anyhow!("No access key in CreateAccessKey response"))?;

        info!("Created new access key: {}", new_key.access_key_id());

        // STAGE 5: Создать новый AwsCredential с новым ключом
        let new_aws = AwsCredential {
            credential_id: old_aws.credential_id.clone(),
            access_key_id: new_key.access_key_id().to_string(),
            secret_access_key: SecretString::new(
                new_key.secret_access_key()
                    .ok_or_else(|| anyhow::anyhow!("No secret in new access key"))?
                    .to_string()
            ),
            session_token: None,
            region: old_aws.region.clone(),
            account_id: old_aws.account_id.clone(),
            user_arn: old_aws.user_arn.clone(),
            created_at: Utc::now(),
            expires_at: None,
            last_rotated: Some(Utc::now()),
        };

        // STAGE 6: Сохранить новый credential
        let new_credential_data = serde_json::to_value(&new_aws)?;

        self.credential_manager.update_credential(
            credential_id,
            new_credential_data,
        ).await?;

        info!("Updated credential storage with new access key");

        // STAGE 7: Подождать AWS propagation (30 секунд)
        info!("Waiting 30 seconds for AWS credential propagation...");
        tokio::time::sleep(Duration::from_secs(30)).await;

        // STAGE 8: Проверить что новый ключ работает
        match self.verify_aws_credential(credential_id).await {
            Ok(_) => {
                info!("New access key verified successfully");

                // STAGE 9: Удалить старый access key
                let delete_result = iam_client
                    .delete_access_key()
                    .user_name(user_name)
                    .access_key_id(&old_aws.access_key_id)
                    .send()
                    .await;

                match delete_result {
                    Ok(_) => {
                        info!("Deleted old access key: {}", old_aws.access_key_id);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("Failed to delete old access key {}: {}", old_aws.access_key_id, e);
                        // Новый ключ работает, старый не удалился — не критично
                        Ok(())
                    }
                }
            }
            Err(e) => {
                error!("New access key verification failed: {}", e);

                // STAGE 10: Rollback — вернуть старый ключ
                warn!("Rolling back to old access key");

                let old_credential_data = serde_json::to_value(&old_aws)?;
                self.credential_manager.update_credential(
                    credential_id,
                    old_credential_data,
                ).await?;

                // Удалить новый (неработающий) ключ
                let _ = iam_client
                    .delete_access_key()
                    .user_name(user_name)
                    .access_key_id(new_key.access_key_id())
                    .send()
                    .await;

                Err(anyhow::anyhow!("Rotation failed and rolled back: {}", e))
            }
        }
    }

    /// Проверка что AWS credential работает
    async fn verify_aws_credential(&self, credential_id: &CredentialId) -> Result<()> {
        let credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let aws_cred: AwsCredential = serde_json::from_value(credential.data)?;

        let credentials = Credentials::new(
            &aws_cred.access_key_id,
            aws_cred.secret_access_key.expose_secret(),
            None,
            None,
            "nebula-verify",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        // Простой вызов для проверки — GetCallerIdentity
        let sts_client = StsClient::new(&config);
        let identity = sts_client.get_caller_identity().send().await?;

        info!("Verified AWS credential - Account: {}, ARN: {}",
            identity.account().unwrap_or("unknown"),
            identity.arn().unwrap_or("unknown")
        );

        Ok(())
    }
}
```

## Service-Specific Examples

### S3 File Operations

```rust
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::operation::get_object::GetObjectOutput;

pub struct S3FileManager {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
}

impl S3FileManager {
    pub async fn upload_large_file(
        &self,
        bucket: &str,
        key: &str,
        file_path: &Path,
    ) -> Result<()> {
        let client = self.build_s3_client().await?;

        // Multipart upload для больших файлов
        let file = tokio::fs::File::open(file_path).await?;
        let file_size = file.metadata().await?.len();

        if file_size > 5 * 1024 * 1024 {  // > 5MB
            info!("Using multipart upload for large file: {} bytes", file_size);
            self.multipart_upload(&client, bucket, key, file_path).await?;
        } else {
            let body = ByteStream::from_path(file_path).await?;
            client.put_object()
                .bucket(bucket)
                .key(key)
                .body(body)
                .send()
                .await?;
        }

        Ok(())
    }

    pub async fn download_file(
        &self,
        bucket: &str,
        key: &str,
        output_path: &Path,
    ) -> Result<()> {
        let client = self.build_s3_client().await?;

        let response = client.get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await?;

        let body = response.body.collect().await?;
        tokio::fs::write(output_path, body.into_bytes()).await?;

        Ok(())
    }

    pub async fn generate_presigned_url(
        &self,
        bucket: &str,
        key: &str,
        expires_in: Duration,
    ) -> Result<String> {
        let client = self.build_s3_client().await?;

        let presigned = client.get_object()
            .bucket(bucket)
            .key(key)
            .presigned(
                aws_sdk_s3::presigning::PresigningConfig::expires_in(
                    expires_in.to_std()?
                )?
            )
            .await?;

        Ok(presigned.uri().to_string())
    }
}
```

### DynamoDB Operations

```rust
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_dynamodb::types::AttributeValue;
use std::collections::HashMap;

pub struct DynamoDbService {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
    table_name: String,
}

impl DynamoDbService {
    async fn build_dynamodb_client(&self) -> Result<DynamoDbClient> {
        let aws_cred = self.get_aws_credential().await?;

        let credentials = Credentials::new(
            &aws_cred.access_key_id,
            aws_cred.secret_access_key.expose_secret(),
            aws_cred.session_token.as_ref().map(|t| t.expose_secret().to_string()),
            None,
            "nebula-dynamodb",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        Ok(DynamoDbClient::new(&config))
    }

    pub async fn put_item(&self, item: HashMap<String, AttributeValue>) -> Result<()> {
        let client = self.build_dynamodb_client().await?;

        client.put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await?;

        Ok(())
    }

    pub async fn get_item(&self, key: HashMap<String, AttributeValue>) -> Result<Option<HashMap<String, AttributeValue>>> {
        let client = self.build_dynamodb_client().await?;

        let response = client.get_item()
            .table_name(&self.table_name)
            .set_key(Some(key))
            .send()
            .await?;

        Ok(response.item)
    }

    pub async fn query_by_partition_key(&self, partition_key: String) -> Result<Vec<HashMap<String, AttributeValue>>> {
        let client = self.build_dynamodb_client().await?;

        let response = client.query()
            .table_name(&self.table_name)
            .key_condition_expression("PK = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(partition_key))
            .send()
            .await?;

        Ok(response.items.unwrap_or_default())
    }
}
```

### Lambda Invocation

```rust
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_lambda::primitives::Blob;

pub struct LambdaInvoker {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
}

impl LambdaInvoker {
    async fn build_lambda_client(&self) -> Result<LambdaClient> {
        let aws_cred = self.get_aws_credential().await?;

        let credentials = Credentials::new(
            &aws_cred.access_key_id,
            aws_cred.secret_access_key.expose_secret(),
            aws_cred.session_token.as_ref().map(|t| t.expose_secret().to_string()),
            None,
            "nebula-lambda",
        );

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        Ok(LambdaClient::new(&config))
    }

    pub async fn invoke_function<T: Serialize, R: DeserializeOwned>(
        &self,
        function_name: &str,
        payload: &T,
    ) -> Result<R> {
        let client = self.build_lambda_client().await?;

        let payload_json = serde_json::to_string(payload)?;

        let response = client.invoke()
            .function_name(function_name)
            .payload(Blob::new(payload_json.as_bytes()))
            .send()
            .await?;

        if let Some(error) = response.function_error() {
            return Err(anyhow::anyhow!("Lambda function error: {}", error));
        }

        let result_blob = response.payload()
            .ok_or_else(|| anyhow::anyhow!("No payload in Lambda response"))?;

        let result: R = serde_json::from_slice(result_blob.as_ref())?;
        Ok(result)
    }

    pub async fn invoke_async(&self, function_name: &str, payload: &impl Serialize) -> Result<()> {
        let client = self.build_lambda_client().await?;

        let payload_json = serde_json::to_string(payload)?;

        client.invoke()
            .function_name(function_name)
            .invocation_type(aws_sdk_lambda::types::InvocationType::Event)  // Async
            .payload(Blob::new(payload_json.as_bytes()))
            .send()
            .await?;

        Ok(())
    }
}
```

## Best Practices

### ✅ Правильные практики

```rust
// ✅ ПРАВИЛЬНО: Использовать SecretString для secret_access_key
pub struct AwsCredential {
    pub access_key_id: String,
    pub secret_access_key: SecretString,  // Не попадет в логи
}

// ✅ ПРАВИЛЬНО: Проверять expiration для STS credentials
if aws_cred.is_expired() {
    return Err(anyhow::anyhow!("AWS credential expired"));
}

// ✅ ПРАВИЛЬНО: Использовать temporary STS credentials вместо long-term keys
let temp_cred = assume_role_service.assume_role(&base_cred_id, &role_config).await?;

// ✅ ПРАВИЛЬНО: Ротация access keys каждые 90 дней
if aws_cred.needs_rotation(90) {
    rotator.rotate_access_key(&credential_id).await?;
}

// ✅ ПРАВИЛЬНО: Проверять новый ключ перед удалением старого (zero-downtime)
match verify_aws_credential(&new_cred_id).await {
    Ok(_) => delete_old_access_key().await?,
    Err(e) => rollback_to_old_key().await?,
}

// ✅ ПРАВИЛЬНО: Использовать least privilege IAM policies
// Политика только для чтения S3 bucket
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"
    ]
  }]
}

// ✅ ПРАВИЛЬНО: Логировать только access_key_id (не secret)
info!("Using AWS access key: {}", aws_cred.access_key_id);

// ✅ ПРАВИЛЬНО: Использовать external_id для cross-account AssumeRole
let role_config = AwsAssumeRoleCredential {
    role_arn: "arn:aws:iam::123456789012:role/CrossAccountRole".to_string(),
    external_id: Some("unique-external-id-12345".to_string()),
    // ...
};

// ✅ ПРАВИЛЬНО: Короткий session duration для sensitive operations
let role_config = AwsAssumeRoleCredential {
    duration_seconds: 900,  // 15 минут
    // ...
};
```

### ❌ Неправильные практики

```rust
// ❌ НЕПРАВИЛЬНО: Secret key в обычной String (попадет в логи)
pub struct BadAwsCredential {
    pub access_key_id: String,
    pub secret_access_key: String,  // ОПАСНО!
}

// ❌ НЕПРАВИЛЬНО: Логировать secret_access_key
error!("Failed with key: {}", aws_cred.secret_access_key.expose_secret());

// ❌ НЕПРАВИЛЬНО: Не проверять expiration для STS credentials
let client = build_client(&aws_cred).await?;  // Может быть expired!

// ❌ НЕПРАВИЛЬНО: Никогда не ротировать long-term access keys
// Access keys должны ротироваться каждые 90 дней максимум

// ❌ НЕПРАВИЛЬНО: Удалять старый ключ до проверки нового
delete_access_key(&old_key_id).await?;
// Если новый ключ не работает — downtime!

// ❌ НЕПРАВИЛЬНО: Hardcode credentials в коде
let aws_cred = AwsCredential::new(
    "AKIAIOSFODNN7EXAMPLE".to_string(),
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
    "us-east-1".to_string(),
);

// ❌ НЕПРАВИЛЬНО: Использовать root account credentials
// Всегда создавать IAM users с минимальными permissions

// ❌ НЕПРАВИЛЬНО: Широкие IAM permissions
{
  "Effect": "Allow",
  "Action": "*",  // ВСЕ действия
  "Resource": "*"  // НА ВСЕХ ресурсах
}

// ❌ НЕПРАВИЛЬНО: Передавать credentials через URL parameters
let url = format!("https://api.example.com?access_key={}&secret={}",
    access_key, secret_key);  // Попадет в логи!

// ❌ НЕПРАВИЛЬНО: Длинный session duration для AssumeRole
let role_config = AwsAssumeRoleCredential {
    duration_seconds: 43200,  // 12 часов — слишком долго
    // ...
};

// ❌ НЕПРАВИЛЬНО: Игнорировать ошибки ротации
let _ = rotator.rotate_access_key(&cred_id).await;  // Молча провалилось!
```

## Error Handling

```rust
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;

#[derive(Debug, thiserror::Error)]
pub enum AwsCredentialError {
    #[error("AWS credential expired at {0}")]
    CredentialExpired(DateTime<Utc>),

    #[error("AWS access denied: {0}")]
    AccessDenied(String),

    #[error("AWS service error: {0}")]
    ServiceError(String),

    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("Invalid AWS region: {0}")]
    InvalidRegion(String),

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("STS AssumeRole failed: {0}")]
    AssumeRoleFailed(String),
}

impl S3FileManager {
    pub async fn download_with_retry(
        &self,
        bucket: &str,
        key: &str,
        max_retries: u32,
    ) -> Result<Vec<u8>> {
        let mut retries = 0;

        loop {
            match self.download_file_once(bucket, key).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    if retries >= max_retries {
                        return Err(e);
                    }

                    // Проверить тип ошибки
                    if self.is_retryable_error(&e) {
                        retries += 1;
                        let backoff = Duration::from_secs(2u64.pow(retries));
                        warn!("S3 download failed, retrying in {:?}: {}", backoff, e);
                        tokio::time::sleep(backoff.to_std()?).await;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn is_retryable_error(&self, error: &anyhow::Error) -> bool {
        // Проверить является ли ошибка temporary (network, throttling, etc)
        if let Some(sdk_err) = error.downcast_ref::<SdkError<GetObjectError>>() {
            match sdk_err {
                SdkError::TimeoutError(_) => true,
                SdkError::ServiceError(ctx) => {
                    // Throttling — retryable
                    matches!(ctx.err(), GetObjectError::Unhandled(_))
                }
                _ => false,
            }
        } else {
            false
        }
    }

    async fn handle_s3_error(&self, error: SdkError<GetObjectError>) -> AwsCredentialError {
        match error {
            SdkError::ServiceError(ctx) => match ctx.err() {
                GetObjectError::NoSuchKey(_) => {
                    AwsCredentialError::NotFound("S3 object not found".to_string())
                }
                _ => AwsCredentialError::ServiceError(ctx.err().to_string()),
            },
            SdkError::TimeoutError(_) => {
                AwsCredentialError::ServiceError("Request timeout".to_string())
            }
            _ => AwsCredentialError::ServiceError(error.to_string()),
        }
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::mock;

    mock! {
        AwsCredentialProvider {}

        impl AwsCredentialProvider for AwsCredentialProvider {
            async fn get_credential(&self, id: &CredentialId) -> Result<AwsCredential>;
        }
    }

    #[tokio::test]
    async fn test_aws_credential_expiration() {
        let expired_cred = AwsCredential {
            credential_id: "test-1".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::new("secret".to_string()),
            session_token: None,
            region: "us-east-1".to_string(),
            account_id: None,
            user_arn: None,
            created_at: Utc::now() - Duration::hours(2),
            expires_at: Some(Utc::now() - Duration::hours(1)),  // Expired 1 hour ago
            last_rotated: None,
        };

        assert!(expired_cred.is_expired());
    }

    #[tokio::test]
    async fn test_credential_needs_rotation() {
        let old_cred = AwsCredential {
            credential_id: "test-2".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: SecretString::new("secret".to_string()),
            session_token: None,
            region: "us-east-1".to_string(),
            account_id: None,
            user_arn: None,
            created_at: Utc::now() - Duration::days(100),
            expires_at: None,
            last_rotated: Some(Utc::now() - Duration::days(100)),
        };

        assert!(old_cred.needs_rotation(90));  // 90 дней policy
        assert!(!old_cred.needs_rotation(180));
    }

    #[tokio::test]
    async fn test_assume_role_credential() {
        let role_config = AwsAssumeRoleCredential {
            role_arn: "arn:aws:iam::123456789012:role/TestRole".to_string(),
            role_session_name: "test-session".to_string(),
            external_id: Some("ext-123".to_string()),
            duration_seconds: 3600,
            mfa_serial: None,
            mfa_token: None,
            base_credential_id: "base-cred-1".to_string(),
        };

        assert_eq!(role_config.duration_seconds, 3600);
        assert_eq!(role_config.external_id, Some("ext-123".to_string()));
    }
}

// Integration tests с LocalStack
#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Требует запущенный LocalStack: docker run -p 4566:4566 localstack/localstack
    #[tokio::test]
    #[ignore]  // Запускать только когда LocalStack доступен
    async fn test_s3_operations_with_localstack() {
        let aws_cred = AwsCredential::new(
            "test".to_string(),
            "test".to_string(),
            "us-east-1".to_string(),
        );

        // LocalStack endpoint
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url("http://localhost:4566")
            .load()
            .await;

        let s3_client = aws_sdk_s3::Client::new(&config);

        // Создать bucket
        let bucket_name = "test-bucket";
        s3_client.create_bucket()
            .bucket(bucket_name)
            .send()
            .await
            .unwrap();

        // Upload file
        s3_client.put_object()
            .bucket(bucket_name)
            .key("test-file.txt")
            .body("Hello LocalStack".as_bytes().to_vec().into())
            .send()
            .await
            .unwrap();

        // Download file
        let response = s3_client.get_object()
            .bucket(bucket_name)
            .key("test-file.txt")
            .send()
            .await
            .unwrap();

        let body = response.body.collect().await.unwrap();
        assert_eq!(body.into_bytes(), b"Hello LocalStack");
    }
}
```

## Complete Example: Multi-Service AWS Client

```rust
use nebula_credential::{CredentialManager, CredentialId, Scope};
use aws_config::{BehaviorVersion, Region};
use aws_credential_types::Credentials;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_sqs::Client as SqsClient;
use std::sync::Arc;
use tokio::sync::RwLock;
use anyhow::Result;

/// Multi-service AWS client с автоматической ротацией credentials
pub struct AwsServiceClient {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,

    // Cached clients
    s3_client: Arc<RwLock<Option<S3Client>>>,
    dynamodb_client: Arc<RwLock<Option<DynamoDbClient>>>,
    sqs_client: Arc<RwLock<Option<SqsClient>>>,

    // Credential rotator
    rotator: Arc<AwsCredentialRotator>,
}

impl AwsServiceClient {
    pub fn new(
        credential_manager: Arc<CredentialManager>,
        credential_id: CredentialId,
    ) -> Self {
        Self {
            credential_manager: credential_manager.clone(),
            credential_id: credential_id.clone(),
            s3_client: Arc::new(RwLock::new(None)),
            dynamodb_client: Arc::new(RwLock::new(None)),
            sqs_client: Arc::new(RwLock::new(None)),
            rotator: Arc::new(AwsCredentialRotator {
                credential_manager,
            }),
        }
    }

    /// Получить текущий AWS credential с проверкой expiration
    async fn get_credential(&self) -> Result<AwsCredential> {
        let credential = self.credential_manager
            .get_credential(&self.credential_id, &Scope::Global)
            .await?;

        let aws_cred: AwsCredential = serde_json::from_value(credential.data)?;

        // Проверить expiration (для STS credentials)
        if aws_cred.is_expired() {
            return Err(anyhow::anyhow!("AWS credential expired"));
        }

        // Проверить needs rotation (для IAM access keys)
        if aws_cred.needs_rotation(90) {
            warn!("AWS credential needs rotation (90+ days old)");
            // Запустить ротацию в фоне
            let rotator = self.rotator.clone();
            let cred_id = self.credential_id.clone();
            tokio::spawn(async move {
                if let Err(e) = rotator.rotate_access_key(&cred_id).await {
                    error!("Background credential rotation failed: {}", e);
                }
            });
        }

        Ok(aws_cred)
    }

    /// Создать AWS Credentials для SDK
    async fn build_aws_credentials(&self) -> Result<Credentials> {
        let aws_cred = self.get_credential().await?;

        let credentials = if let Some(session_token) = &aws_cred.session_token {
            Credentials::new(
                &aws_cred.access_key_id,
                aws_cred.secret_access_key.expose_secret(),
                Some(session_token.expose_secret().to_string()),
                aws_cred.expires_at.map(|dt| dt.into()),
                "nebula-aws-client",
            )
        } else {
            Credentials::new(
                &aws_cred.access_key_id,
                aws_cred.secret_access_key.expose_secret(),
                None,
                None,
                "nebula-aws-client",
            )
        };

        Ok(credentials)
    }

    /// Получить S3 client (с кешированием)
    pub async fn s3(&self) -> Result<S3Client> {
        {
            let reader = self.s3_client.read().await;
            if let Some(client) = reader.as_ref() {
                return Ok(client.clone());
            }
        }

        // Создать новый client
        let aws_cred = self.get_credential().await?;
        let credentials = self.build_aws_credentials().await?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        let client = S3Client::new(&config);

        // Кешировать
        let mut writer = self.s3_client.write().await;
        *writer = Some(client.clone());

        Ok(client)
    }

    /// Получить DynamoDB client (с кешированием)
    pub async fn dynamodb(&self) -> Result<DynamoDbClient> {
        {
            let reader = self.dynamodb_client.read().await;
            if let Some(client) = reader.as_ref() {
                return Ok(client.clone());
            }
        }

        let aws_cred = self.get_credential().await?;
        let credentials = self.build_aws_credentials().await?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        let client = DynamoDbClient::new(&config);

        let mut writer = self.dynamodb_client.write().await;
        *writer = Some(client.clone());

        Ok(client)
    }

    /// Получить SQS client (с кешированием)
    pub async fn sqs(&self) -> Result<SqsClient> {
        {
            let reader = self.sqs_client.read().await;
            if let Some(client) = reader.as_ref() {
                return Ok(client.clone());
            }
        }

        let aws_cred = self.get_credential().await?;
        let credentials = self.build_aws_credentials().await?;

        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(aws_cred.region.clone()))
            .credentials_provider(credentials)
            .load()
            .await;

        let client = SqsClient::new(&config);

        let mut writer = self.sqs_client.write().await;
        *writer = Some(client.clone());

        Ok(client)
    }

    /// Invalidate кеш clients (после ротации credentials)
    pub async fn invalidate_cache(&self) {
        *self.s3_client.write().await = None;
        *self.dynamodb_client.write().await = None;
        *self.sqs_client.write().await = None;
    }

    /// Ротация credentials с автоматическим invalidation кеша
    pub async fn rotate_credential(&self) -> Result<()> {
        self.rotator.rotate_access_key(&self.credential_id).await?;
        self.invalidate_cache().await;
        Ok(())
    }
}

// Пример использования
#[tokio::main]
async fn main() -> Result<()> {
    let credential_manager = Arc::new(CredentialManager::new(/* ... */));

    // Создать AWS credential
    let aws_cred = AwsCredential::new(
        std::env::var("AWS_ACCESS_KEY_ID")?,
        std::env::var("AWS_SECRET_ACCESS_KEY")?,
        "us-east-1".to_string(),
    );

    let credential_id = credential_manager.store_credential(
        "aws-production",
        serde_json::to_value(&aws_cred)?,
        &Scope::Global,
    ).await?;

    // Создать multi-service client
    let aws_client = AwsServiceClient::new(credential_manager, credential_id);

    // Использовать S3
    let s3 = aws_client.s3().await?;
    let buckets = s3.list_buckets().send().await?;
    for bucket in buckets.buckets() {
        println!("Bucket: {}", bucket.name().unwrap_or("unknown"));
    }

    // Использовать DynamoDB
    let dynamodb = aws_client.dynamodb().await?;
    let tables = dynamodb.list_tables().send().await?;
    for table in tables.table_names() {
        println!("Table: {}", table);
    }

    // Использовать SQS
    let sqs = aws_client.sqs().await?;
    let queues = sqs.list_queues().send().await?;
    for queue_url in queues.queue_urls() {
        println!("Queue: {}", queue_url);
    }

    // Ротация credentials (автоматически invalidate кеш)
    aws_client.rotate_credential().await?;

    Ok(())
}
```

## Links

Related documentation:

- [[02-Crates/nebula-credential/README|nebula-credential]] — основная документация по управлению credentials
- [[02-Crates/nebula-credential/Architecture|Architecture]] — архитектура credential management system
- [[02-Crates/nebula-credential/Encryption|Encryption]] — шифрование credentials в storage
- [[02-Crates/nebula-credential/RotateCredentials|RotateCredentials]] — стратегии ротации credentials
- [[02-Crates/nebula-credential/Examples/BasicApiKey|BasicApiKey]] — simple API key authentication
- [[02-Crates/nebula-resource/README|nebula-resource]] — resource management для AWS services (S3, DynamoDB pools)

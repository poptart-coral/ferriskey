use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::domain::common::{generate_timestamp, generate_uuid_v7};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, ToSchema)]
pub struct RealmId(Uuid);

impl RealmId {
    pub fn new(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for RealmId {
    fn default() -> Self {
        Self::new(generate_uuid_v7())
    }
}

impl From<Uuid> for RealmId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<RealmId> for Uuid {
    fn from(id: RealmId) -> Self {
        id.0
    }
}

impl PartialEq<Uuid> for RealmId {
    fn eq(&self, other: &Uuid) -> bool {
        self.0.eq(other)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, ToSchema)]
pub struct Realm {
    pub id: RealmId,
    pub name: String,
    pub settings: Option<RealmSetting>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, ToSchema)]
pub struct RealmSetting {
    pub id: Uuid,
    pub realm_id: RealmId,
    pub default_signing_algorithm: Option<String>,
    pub user_registration_enabled: bool,
    pub forgot_password_enabled: bool,
    pub remember_me_enabled: bool,
    pub magic_link_enabled: Option<bool>,
    pub magic_link_ttl_minutes: Option<u32>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd, ToSchema)]
pub struct RealmLoginSetting {
    pub user_registration_enabled: bool,
    pub forgot_password_enabled: bool,
    pub remember_me_enabled: bool,
    pub magic_link_enabled: bool,
    pub magic_link_ttl_minutes: u32,
}

impl From<RealmSetting> for RealmLoginSetting {
    fn from(value: RealmSetting) -> Self {
        Self {
            forgot_password_enabled: value.forgot_password_enabled,
            remember_me_enabled: value.remember_me_enabled,
            user_registration_enabled: value.user_registration_enabled,
            magic_link_enabled: value.magic_link_enabled.unwrap_or(false),
            magic_link_ttl_minutes: value.magic_link_ttl_minutes.unwrap_or(60), // Default 1 hour
        }
    }
}

impl RealmSetting {
    pub fn new(realm_id: RealmId, default_signing_algorithm: Option<String>) -> Self {
        let (now, timestamp) = generate_timestamp();

        Self {
            id: Uuid::new_v7(timestamp),
            realm_id,
            default_signing_algorithm,
            forgot_password_enabled: false,
            remember_me_enabled: false,
            user_registration_enabled: false,
            magic_link_enabled: Some(false),  // Default disabled
            magic_link_ttl_minutes: Some(60), // Default 1 hour
            updated_at: now,
        }
    }
}

impl Realm {
    pub fn new(name: String) -> Self {
        let now = Utc::now();

        Self {
            id: RealmId::default(),
            name,
            settings: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn can_delete(&self) -> bool {
        self.name != "master"
    }
}

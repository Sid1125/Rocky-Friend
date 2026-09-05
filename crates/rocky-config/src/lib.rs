//! Strict loading for ROCKY's small local configuration surface.
//!
//! Unknown keys and malformed values are rejected so configuration cannot silently widen
//! security boundaries. This intentionally supports only the project's current scalar schema.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RockyConfig {
    pub runtime: RuntimeConfig,
    pub resources: ResourceConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub max_subagents: usize,
    pub max_agent_depth: u8,
    pub idle_background_work: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceConfig {
    pub mode: ResourceStrategy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceStrategy {
    Adaptive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityConfig {
    pub default_permission: DefaultPermission,
    pub cloud_models_enabled: bool,
    pub arbitrary_shell_enabled: bool,
    pub admin_execution_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultPermission {
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageConfig {
    pub database: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    Io(String),
    InvalidLine { line: usize },
    UnknownSection { line: usize, section: String },
    UnknownKey { line: usize, key: String },
    DuplicateKey { key: String },
    MissingKey { key: &'static str },
    InvalidValue { key: String },
    UnsafeConfiguration { key: &'static str },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "configuration error: {self:?}")
    }
}

impl std::error::Error for ConfigError {}

impl RockyConfig {
    /// Loads a configuration file from a caller-selected path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
        Self::parse(&text)
    }

    /// Parses the project's supported TOML-like scalar configuration format.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let values = parse_values(input)?;
        let config = Self {
            runtime: RuntimeConfig {
                max_subagents: required_usize(&values, "runtime.max_subagents")?,
                max_agent_depth: required_u8(&values, "runtime.max_agent_depth")?,
                idle_background_work: required_bool(&values, "runtime.idle_background_work")?,
            },
            resources: ResourceConfig {
                mode: match required_string(&values, "resources.mode")?.as_str() {
                    "adaptive" => ResourceStrategy::Adaptive,
                    _ => {
                        return Err(ConfigError::InvalidValue {
                            key: "resources.mode".into(),
                        });
                    }
                },
            },
            security: SecurityConfig {
                default_permission: match required_string(&values, "security.default_permission")?
                    .as_str()
                {
                    "deny" => DefaultPermission::Deny,
                    _ => {
                        return Err(ConfigError::UnsafeConfiguration {
                            key: "security.default_permission",
                        });
                    }
                },
                cloud_models_enabled: required_bool(&values, "security.cloud_models_enabled")?,
                arbitrary_shell_enabled: required_bool(
                    &values,
                    "security.arbitrary_shell_enabled",
                )?,
                admin_execution_enabled: required_bool(
                    &values,
                    "security.admin_execution_enabled",
                )?,
            },
            storage: StorageConfig {
                database: required_string(&values, "storage.database")?,
            },
        };
        if config.runtime.max_subagents == 0 {
            return Err(ConfigError::InvalidValue {
                key: "runtime.max_subagents".into(),
            });
        }
        if config.security.arbitrary_shell_enabled || config.security.admin_execution_enabled {
            return Err(ConfigError::UnsafeConfiguration {
                key: "security elevated execution",
            });
        }
        Ok(config)
    }
}

fn parse_values(input: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut section = None::<String>;
    let mut values = BTreeMap::new();
    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let candidate = &line[1..line.len() - 1];
            if !matches!(candidate, "runtime" | "resources" | "security" | "storage") {
                return Err(ConfigError::UnknownSection {
                    line: line_number,
                    section: candidate.into(),
                });
            }
            section = Some(candidate.into());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(ConfigError::InvalidLine { line: line_number })?;
        let section = section
            .as_ref()
            .ok_or(ConfigError::InvalidLine { line: line_number })?;
        let key = key.trim();
        let full_key = format!("{section}.{key}");
        if !known_key(&full_key) {
            return Err(ConfigError::UnknownKey {
                line: line_number,
                key: full_key,
            });
        }
        if values
            .insert(full_key.clone(), value.trim().into())
            .is_some()
        {
            return Err(ConfigError::DuplicateKey { key: full_key });
        }
    }
    Ok(values)
}

fn known_key(key: &str) -> bool {
    matches!(
        key,
        "runtime.max_subagents"
            | "runtime.max_agent_depth"
            | "runtime.idle_background_work"
            | "resources.mode"
            | "security.default_permission"
            | "security.cloud_models_enabled"
            | "security.arbitrary_shell_enabled"
            | "security.admin_execution_enabled"
            | "storage.database"
    )
}

fn required<'a>(
    values: &'a BTreeMap<String, String>,
    key: &'static str,
) -> Result<&'a str, ConfigError> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or(ConfigError::MissingKey { key })
}

fn required_usize(
    values: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<usize, ConfigError> {
    required(values, key)?
        .parse()
        .map_err(|_| ConfigError::InvalidValue { key: key.into() })
}

fn required_u8(values: &BTreeMap<String, String>, key: &'static str) -> Result<u8, ConfigError> {
    required(values, key)?
        .parse()
        .map_err(|_| ConfigError::InvalidValue { key: key.into() })
}

fn required_bool(
    values: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<bool, ConfigError> {
    required(values, key)?
        .parse()
        .map_err(|_| ConfigError::InvalidValue { key: key.into() })
}

fn required_string(
    values: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<String, ConfigError> {
    let value = required(values, key)?;
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(ConfigError::InvalidValue { key: key.into() });
    }
    Ok(value[1..value.len() - 1].into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_CONFIG: &str = include_str!("../../../config/default.toml");

    #[test]
    fn parses_the_checked_in_secure_defaults() {
        let config = RockyConfig::parse(DEFAULT_CONFIG).expect("checked-in config is valid");
        assert_eq!(config.runtime.max_subagents, 3);
        assert_eq!(config.security.default_permission, DefaultPermission::Deny);
        assert!(!config.security.arbitrary_shell_enabled);
    }

    #[test]
    fn rejects_unknown_security_keys() {
        let invalid = DEFAULT_CONFIG.replace(
            "admin_execution_enabled = false",
            "admin_execution_enabled = false\nallow_everything = true",
        );
        assert!(matches!(
            RockyConfig::parse(&invalid),
            Err(ConfigError::UnknownKey { .. })
        ));
    }

    #[test]
    fn rejects_configuration_that_enables_an_arbitrary_shell() {
        let unsafe_config = DEFAULT_CONFIG.replace(
            "arbitrary_shell_enabled = false",
            "arbitrary_shell_enabled = true",
        );
        assert_eq!(
            RockyConfig::parse(&unsafe_config),
            Err(ConfigError::UnsafeConfiguration {
                key: "security elevated execution"
            })
        );
    }
}

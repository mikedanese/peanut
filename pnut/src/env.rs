//! Environment policy configuration and setup.

use std::collections::HashMap;

/// Environment handling for the sandboxed process.
#[derive(Debug, Default)]
pub struct Config {
    /// Clear all environment variables before applying `set` and `keep`.
    pub clear: bool,

    /// Variables to set or override inside the sandbox.
    pub set: HashMap<String, String>,

    /// Host variables to preserve when `clear = true`.
    pub keep: Vec<String>,
}

impl Config {
    /// Control whether the host environment is cleared before applying this policy.
    pub fn clear(&mut self, clear: bool) -> &mut Self {
        self.clear = clear;
        self
    }

    /// Set or override one environment variable inside the sandbox.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.set.insert(key.into(), value.into());
        self
    }

    /// Preserve one host environment variable when `clear = true`.
    pub fn keep(&mut self, key: impl Into<String>) -> &mut Self {
        self.keep.push(key.into());
        self
    }
}

/// Set up the process environment according to the config.
pub(crate) fn setup_environment(env_config: &Config) {
    unsafe {
        if env_config.clear {
            let kept: Vec<(String, String)> = env_config
                .keep
                .iter()
                .filter_map(|name| std::env::var(name).ok().map(|val| (name.clone(), val)))
                .collect();

            let all_vars: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
            for key in &all_vars {
                std::env::remove_var(key);
            }

            for (key, val) in &kept {
                std::env::set_var(key, val);
            }
        }

        for (key, val) in &env_config.set {
            std::env::set_var(key, val);
        }
    }
}

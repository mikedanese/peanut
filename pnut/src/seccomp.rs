//! Seccomp policy compilation for the sandbox.

use std::path::Path;

use crate::error::BuildError;
use crate::sandbox::SeccompSource;

pub(crate) fn prepare_program(
    source: Option<&SeccompSource>,
) -> std::result::Result<Option<kafel::BpfProgram>, BuildError> {
    match source {
        Some(SeccompSource::Inline(policy_text)) => compile_policy(policy_text, None),
        Some(SeccompSource::File(policy_path)) => {
            let contents =
                std::fs::read_to_string(policy_path).map_err(|e| BuildError::SeccompFileRead {
                    path: policy_path.display().to_string(),
                    source: e,
                })?;
            let base_dir = policy_path.parent().unwrap_or(Path::new("."));
            compile_policy(&contents, Some(base_dir))
        }
        None => Ok(None),
    }
}

fn compile_policy(
    policy_text: &str,
    base_dir: Option<&Path>,
) -> std::result::Result<Option<kafel::BpfProgram>, BuildError> {
    let mut options = kafel::CompileOptions::new().with_prelude(kafel::BUILTIN_PRELUDE);

    if let Some(dir) = base_dir {
        let resolver = kafel::FilesystemResolver::new(dir);
        options = options.with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));
    }

    let mut policy = kafel::parse_policy(policy_text, &options)
        .map_err(|e| BuildError::SeccompCompile(e.to_string()))?;

    // pnut installs the seccomp filter before execve, so execve must always
    // be allowed. Runtime startup syscalls (set_tid_address, mprotect, etc.)
    // are the user's responsibility via allow_static_startup or
    // allow_dynamic_startup in the policy.
    for name in ["execve", "execveat"] {
        let nr =
            kafel::resolve_syscall(name).map_err(|e| BuildError::SeccompCompile(e.to_string()))?;
        policy.add_entry(kafel::PolicyEntry {
            syscall_number: nr,
            action: kafel::Action::Allow,
            filter: None,
        });
    }

    policy
        .codegen()
        .map(Some)
        .map_err(|e| BuildError::SeccompCompile(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_inline_policy_with_typed_api() {
        let policy_text = "POLICY p { ALLOW { read, write } }\nUSE p DEFAULT KILL\n";
        let result = compile_policy(policy_text, None);
        assert!(result.is_ok(), "compile_policy failed: {result:?}");
        assert!(result.unwrap().is_some());
    }
}

use std::collections::BTreeSet;
use std::path::Path;

use podbay_core::{PodId, Role, ScopeId};

use crate::authority::{CredentialRef, HostError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceSelection {
    pub scope_id: ScopeId,
    pub basis_ref: String,
    pub relative_cwd: String,
    pub access: WorkspaceAccess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSelection {
    pub profile_ref: String,
    pub profile_generation: u64,
    pub model_id: Option<String>,
    pub reasoning_effort: Option<String>,
    pub fallback_approved: bool,
    pub workspace: WorkspaceSelection,
    pub arguments: Vec<String>,
    pub tool_bundle_refs: Vec<String>,
    pub authority_ref: String,
    pub wall_seconds: u64,
    pub max_children: u32,
    pub parent_run_id: Option<String>,
}

/// Protected policy input. No request can set the executable or environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLaunchProfileInput {
    pub profile_ref: String,
    pub profile_generation: u64,
    pub executable: String,
    pub binary_generation: String,
    pub fixed_arguments: Vec<String>,
    pub permitted_extra_arguments: BTreeSet<String>,
    pub default_model: String,
    pub allowed_models: BTreeSet<String>,
    pub default_effort: String,
    pub allowed_efforts: BTreeSet<String>,
    pub workspace_scope: ScopeId,
    pub workspace_basis_ref: String,
    pub allowed_cwd_prefix: String,
    pub allow_write: bool,
    pub allowed_tool_bundle_refs: BTreeSet<String>,
    pub environment_refs: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub max_wall_seconds: u64,
    pub max_children: u32,
    pub allow_fallback: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredLaunchProfile {
    input: TrustedLaunchProfileInput,
}

impl RegisteredLaunchProfile {
    pub fn from_trusted_policy(input: TrustedLaunchProfileInput) -> Result<Self, HostError> {
        if !valid_label(&input.profile_ref)
            || input.profile_generation == 0
            || input.executable.len() < 2
            || input.executable.len() > 4096
            || !Path::new(&input.executable).is_absolute()
            || input.executable.chars().any(char::is_control)
            || !valid_label(&input.binary_generation)
            || !valid_label(&input.default_model)
            || !valid_label(&input.default_effort)
            || !valid_label(&input.workspace_basis_ref)
            || !valid_relative_cwd(&input.allowed_cwd_prefix)
            || input.max_wall_seconds == 0
            || input.allowed_models.is_empty()
            || input.allowed_efforts.is_empty()
            || input.allowed_models.len() > 64
            || input.allowed_efforts.len() > 32
            || !input.allowed_models.contains(&input.default_model)
            || !input.allowed_efforts.contains(&input.default_effort)
            || input.fixed_arguments.len() > 64
            || input.permitted_extra_arguments.len() > 64
            || input.allowed_tool_bundle_refs.len() > 64
            || input.environment_refs.len() > 64
            || input.credential_refs.len() > 32
        {
            return Err(HostError::InvalidInput);
        }
        for value in input
            .allowed_models
            .iter()
            .chain(input.allowed_efforts.iter())
            .chain(input.allowed_tool_bundle_refs.iter())
            .chain(input.environment_refs.iter())
        {
            if !valid_label(value) {
                return Err(HostError::InvalidInput);
            }
        }
        for argument in input
            .fixed_arguments
            .iter()
            .chain(input.permitted_extra_arguments.iter())
        {
            if !valid_argument(argument) {
                return Err(HostError::InvalidInput);
            }
        }
        if input
            .credential_refs
            .iter()
            .any(|reference| reference.scope_id() != &input.workspace_scope)
        {
            return Err(HostError::Unauthorised);
        }
        Ok(Self { input })
    }

    pub fn profile_ref(&self) -> &str {
        &self.input.profile_ref
    }

    pub fn generation(&self) -> u64 {
        self.input.profile_generation
    }

    pub fn workspace_scope(&self) -> &ScopeId {
        &self.input.workspace_scope
    }

    pub(crate) fn resolve(
        &self,
        pod_id: PodId,
        role: Role,
        grant_id: u64,
        selected_credential: Option<&CredentialRef>,
        selection: &LaunchSelection,
    ) -> Result<EffectiveLaunchSpec, HostError> {
        let profile = &self.input;
        if selection.profile_ref != profile.profile_ref
            || selection.profile_generation != profile.profile_generation
            || selection.workspace.scope_id != profile.workspace_scope
            || selection.workspace.basis_ref != profile.workspace_basis_ref
            || !valid_relative_cwd(&selection.workspace.relative_cwd)
            || !cwd_within_prefix(
                &selection.workspace.relative_cwd,
                &profile.allowed_cwd_prefix,
            )
            || (selection.workspace.access == WorkspaceAccess::ReadWrite && !profile.allow_write)
            || (selection.fallback_approved && !profile.allow_fallback)
            || selection.wall_seconds == 0
            || selection.wall_seconds > profile.max_wall_seconds
            || selection.max_children > profile.max_children
            || selection.arguments.len() > 64
            || selection.tool_bundle_refs.len() > 64
            || selection.authority_ref != format!("grant.{grant_id}")
        {
            return Err(HostError::Unauthorised);
        }
        if let Some(parent) = &selection.parent_run_id {
            if !valid_label(parent) {
                return Err(HostError::InvalidInput);
            }
        }
        let model_id = selection
            .model_id
            .clone()
            .unwrap_or_else(|| profile.default_model.clone());
        let reasoning_effort = selection
            .reasoning_effort
            .clone()
            .unwrap_or_else(|| profile.default_effort.clone());
        if !profile.allowed_models.contains(&model_id)
            || !profile.allowed_efforts.contains(&reasoning_effort)
            || selection
                .arguments
                .iter()
                .any(|arg| !valid_argument(arg) || !profile.permitted_extra_arguments.contains(arg))
            || selection
                .tool_bundle_refs
                .iter()
                .any(|reference| !profile.allowed_tool_bundle_refs.contains(reference))
            || selected_credential
                .is_some_and(|reference| !profile.credential_refs.contains(reference))
        {
            return Err(HostError::Unauthorised);
        }
        let mut arguments = profile.fixed_arguments.clone();
        arguments.extend(selection.arguments.iter().cloned());
        let mut tool_bundle_refs = selection.tool_bundle_refs.clone();
        tool_bundle_refs.sort();
        tool_bundle_refs.dedup();
        let mut environment_refs = profile.environment_refs.clone();
        environment_refs.sort();
        environment_refs.dedup();
        let credential_refs = selected_credential.cloned().into_iter().collect();
        Ok(EffectiveLaunchSpec {
            pod_id,
            role,
            parent_run_id: selection.parent_run_id.clone(),
            profile_ref: profile.profile_ref.clone(),
            profile_generation: profile.profile_generation,
            executable: profile.executable.clone(),
            binary_generation: profile.binary_generation.clone(),
            arguments,
            model_id,
            reasoning_effort,
            fallback_approved: selection.fallback_approved,
            workspace: selection.workspace.clone(),
            tool_bundle_refs,
            authority_grant_id: grant_id,
            wall_seconds: selection.wall_seconds,
            max_children: selection.max_children,
            environment_refs,
            credential_refs,
        })
    }
}

/// Immutable reviewed launch data. Only a registered profile can construct it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveLaunchSpec {
    pod_id: PodId,
    role: Role,
    parent_run_id: Option<String>,
    profile_ref: String,
    profile_generation: u64,
    executable: String,
    binary_generation: String,
    arguments: Vec<String>,
    model_id: String,
    reasoning_effort: String,
    fallback_approved: bool,
    workspace: WorkspaceSelection,
    tool_bundle_refs: Vec<String>,
    authority_grant_id: u64,
    wall_seconds: u64,
    max_children: u32,
    environment_refs: Vec<String>,
    credential_refs: Vec<CredentialRef>,
}

impl EffectiveLaunchSpec {
    pub fn pod_id(&self) -> &PodId {
        &self.pod_id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn binary_generation(&self) -> &str {
        &self.binary_generation
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn reasoning_effort(&self) -> &str {
        &self.reasoning_effort
    }

    pub fn workspace(&self) -> &WorkspaceSelection {
        &self.workspace
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn credential_refs(&self) -> &[CredentialRef] {
        &self.credential_refs
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, HostError> {
        let mut output = b"podbay.effective-launch/1\0".to_vec();
        append_string(&mut output, self.pod_id.as_str())?;
        append_string(
            &mut output,
            match self.role {
                Role::Coordinator => "coordinator",
                Role::Worker => "worker",
                Role::Advisor => "advisor",
            },
        )?;
        append_optional(&mut output, self.parent_run_id.as_deref())?;
        append_string(&mut output, &self.profile_ref)?;
        output.extend_from_slice(&self.profile_generation.to_be_bytes());
        append_string(&mut output, &self.executable)?;
        append_string(&mut output, &self.binary_generation)?;
        append_list(&mut output, &self.arguments)?;
        append_string(&mut output, &self.model_id)?;
        append_string(&mut output, &self.reasoning_effort)?;
        output.push(u8::from(self.fallback_approved));
        append_string(&mut output, self.workspace.scope_id.as_str())?;
        append_string(&mut output, &self.workspace.basis_ref)?;
        append_string(&mut output, &self.workspace.relative_cwd)?;
        output.push(match self.workspace.access {
            WorkspaceAccess::ReadOnly => 0,
            WorkspaceAccess::ReadWrite => 1,
        });
        append_list(&mut output, &self.tool_bundle_refs)?;
        output.extend_from_slice(&self.authority_grant_id.to_be_bytes());
        output.extend_from_slice(&self.wall_seconds.to_be_bytes());
        output.extend_from_slice(&self.max_children.to_be_bytes());
        append_list(&mut output, &self.environment_refs)?;
        output.extend_from_slice(
            &u32::try_from(self.credential_refs.len())
                .map_err(|_| HostError::InvalidInput)?
                .to_be_bytes(),
        );
        for credential in &self.credential_refs {
            append_string(&mut output, credential.scope_id().as_str())?;
            append_string(&mut output, credential.as_str())?;
        }
        Ok(output)
    }
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), HostError> {
    let length = u32::try_from(value.len()).map_err(|_| HostError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_optional(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), HostError> {
    match value {
        Some(value) => {
            output.push(1);
            append_string(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

fn append_list(output: &mut Vec<u8>, values: &[String]) -> Result<(), HostError> {
    output.extend_from_slice(
        &u32::try_from(values.len())
            .map_err(|_| HostError::InvalidInput)?
            .to_be_bytes(),
    );
    for value in values {
        append_string(output, value)?;
    }
    Ok(())
}

fn valid_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_argument(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

fn valid_relative_cwd(value: &str) -> bool {
    if value == "." {
        return true;
    }
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains(':')
        && value.split('/').all(|part| {
            !part.is_empty() && part != "." && part != ".." && !part.chars().any(char::is_control)
        })
}

fn cwd_within_prefix(cwd: &str, prefix: &str) -> bool {
    prefix == "." || cwd == prefix || cwd.starts_with(&format!("{prefix}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_cwd_rejects_drive_and_parent_segments() {
        assert!(!valid_relative_cwd("C:temp"));
        assert!(!valid_relative_cwd("src/../private"));
        assert!(valid_relative_cwd("src/work"));
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_absolute_executable_is_recognised() {
        assert!(Path::new(r"C:\Program Files\PodBay\agent.exe").is_absolute());
    }
}

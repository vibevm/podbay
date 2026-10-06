use std::collections::{BTreeSet, HashMap};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use podbay_core::{LaunchBinding, PodId, ResourceKind, Role, ScopeId};
use podbay_wire::{
    CodexAppServerPolicyV2, EffectiveLaunchContract, EffectiveLaunchContractV2,
    EffectiveWorkspaceAccess, ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2,
    LifetimeLimit, NativeResourceKind, NativeRole, OPERATOR_PROCESS_PROFILE_REF,
    ResourceDriver, ReviewedNativePolicy, ReviewedResource,
    TargetOs,
};
use sha2::{Digest, Sha256};

use crate::authority::{CredentialRef, HostError};

mod operator_fd3_profile;
pub use operator_fd3_profile::ResolvedOperatorFd3ObserveData;

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

/// Installed by the authenticated host policy boundary, never by a launch
/// request. The first resolver supports the compiled Linux backend only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedNativeHostConfig {
    host_id: String,
    target_os: TargetOs,
    structured_drivers: BTreeSet<(String, String)>,
    auxiliary_drivers: BTreeSet<String>,
}

impl TrustedNativeHostConfig {
    pub fn for_compiled_backend(host_id: String) -> Result<Self, HostError> {
        if !cfg!(target_os = "linux") {
            return Err(HostError::Unsupported);
        }
        if !valid_label(&host_id) {
            return Err(HostError::InvalidInput);
        }
        Ok(Self {
            host_id,
            target_os: TargetOs::Linux,
            structured_drivers: BTreeSet::new(),
            auxiliary_drivers: BTreeSet::new(),
        })
    }

    pub fn with_structured_driver(
        mut self,
        driver_ref: String,
        protocol_ref: String,
    ) -> Result<Self, HostError> {
        if !valid_label(&driver_ref) || !valid_label(&protocol_ref) {
            return Err(HostError::InvalidInput);
        }
        self.structured_drivers.insert((driver_ref, protocol_ref));
        Ok(self)
    }

    pub fn with_auxiliary_driver(mut self, driver_ref: String) -> Result<Self, HostError> {
        if !valid_label(&driver_ref) {
            return Err(HostError::InvalidInput);
        }
        self.auxiliary_drivers.insert(driver_ref);
        Ok(self)
    }

    fn supports_driver(&self, driver: &ResourceDriver) -> bool {
        match driver {
            ResourceDriver::Pty { .. } => true,
            ResourceDriver::Structured {
                driver_ref,
                protocol_ref,
            } => self
                .structured_drivers
                .contains(&(driver_ref.clone(), protocol_ref.clone())),
            ResourceDriver::Auxiliary { driver_ref } => self.auxiliary_drivers.contains(driver_ref),
        }
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }
    pub fn target_os(&self) -> TargetOs {
        self.target_os
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedDriverTemplate {
    pub kind: ResourceKind,
    pub driver: ResourceDriver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    /// Pathname-based Linux execution of dynamic binaries. This is cooperative
    /// local policy, not hostile same-UID or loader/library isolation.
    LinuxCooperative,
}

pub(crate) struct ResolvedNativePaths {
    pub(crate) cwd: PathBuf,
    pub(crate) executable: PathBuf,
    pub(crate) executable_sha256: String,
}

/// Protected policy input. No request can set the executable or environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedLaunchProfileInput {
    pub profile_ref: String,
    pub profile_generation: u64,
    pub executable: String,
    pub binary_generation: String,
    pub executable_sha256: String,
    pub workspace_root: PathBuf,
    pub resource_layout: Vec<TrustedDriverTemplate>,
    pub execution_mode: ExecutionMode,
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
    codex_policy: Option<CodexAppServerPolicyV2>,
    operator_fd3_observe: Option<operator_fd3_profile::Fd3Registration>,
    operator_until_stopped: bool,
    codex_until_stopped: bool,
}

impl RegisteredLaunchProfile {
    pub fn from_trusted_policy(input: TrustedLaunchProfileInput) -> Result<Self, HostError> {
        if operator_fd3_profile::has_fd3_names(&input) {
            return Err(HostError::Unsupported);
        }
        Self::from_common_input(input)
    }

    fn from_common_input(input: TrustedLaunchProfileInput) -> Result<Self, HostError> {
        if !valid_label(&input.profile_ref)
            || input.profile_generation == 0
            || input.executable.len() < 2
            || input.executable.len() > 4096
            || !Path::new(&input.executable).is_absolute()
            || input.executable.chars().any(char::is_control)
            || !valid_label(&input.binary_generation)
            || !valid_sha256(&input.executable_sha256)
            || input.binary_generation != format!("sha256:{}", input.executable_sha256)
            || !input.workspace_root.is_absolute()
            || input.workspace_root.as_os_str().len() > 4096
            || input.resource_layout.is_empty()
            || input.resource_layout.len() > 64
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
        if input
            .resource_layout
            .iter()
            .any(|template| !driver_matches_kind(template))
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
        Ok(Self {
            input,
            codex_policy: None,
            operator_fd3_observe: None,
            operator_until_stopped: false,
            codex_until_stopped: false,
        })
    }

    pub fn with_until_stopped_operator_service(mut self) -> Result<Self, HostError> {
        let input = &self.input;
        if self.requires_fd3_observe() || self.codex_policy.is_some()
            || input.profile_ref != OPERATOR_PROCESS_PROFILE_REF
            || input.resource_layout.len() != 1
            || input.resource_layout[0].kind != ResourceKind::Auxiliary
            || !matches!(&input.resource_layout[0].driver,
                ResourceDriver::Auxiliary { driver_ref } if driver_ref == "process.exec")
            || input.default_model != "none"
            || input.default_effort != "none"
            || input.max_children != 0
            || !input.environment_refs.is_empty()
            || !input.credential_refs.is_empty()
        {
            return Err(HostError::Unauthorised);
        }
        self.operator_until_stopped = true;
        Ok(self)
    }

    pub(crate) fn operator_until_stopped(&self) -> bool {
        self.operator_until_stopped
    }

    pub fn with_until_stopped_codex_service(mut self) -> Result<Self, HostError> {
        if self.requires_fd3_observe() || self.codex_policy.is_none()
            || self.operator_until_stopped
            || self.input.profile_ref == OPERATOR_PROCESS_PROFILE_REF
            || self.input.execution_mode != ExecutionMode::LinuxCooperative
            || self.input.resource_layout.len() != 1
            || self.input.resource_layout[0].kind != ResourceKind::StructuredProvider
            || self.input.credential_refs.len() != 1
        {
            return Err(HostError::Unauthorised);
        }
        self.codex_until_stopped = true;
        Ok(self)
    }

    pub(crate) fn codex_until_stopped(&self) -> bool {
        self.codex_until_stopped
    }

    /// Explicit trusted-policy opt-in for the internal Codex V2 launch shape.
    /// Legacy profiles never infer this policy from a driver name or argv.
    /// Existing V1 launch resolution refuses an opted-in profile until a
    /// separately reviewed V2 admission path exists.
    pub fn with_codex_policy_from_trusted_policy(
        mut self,
        policy: CodexAppServerPolicyV2,
    ) -> Result<Self, HostError> {
        if self.requires_fd3_observe() || self.codex_policy.is_some() || self.operator_until_stopped {
            return Err(HostError::InvalidInput);
        }
        let input = &self.input;
        let canonical = CodexAppServerPolicyV2::new(
            &input.workspace_scope,
            policy.credential_ref().to_owned(),
            policy.driver_ref().to_owned(),
            policy.protocol_ref().to_owned(),
        )
        .map_err(|_| HostError::InvalidInput)?;
        if canonical != policy
            || !input.allow_write
            || input.resource_layout.len() != 1
            || input.credential_refs.len() != 1
            || input.credential_refs[0].scope_id() != &input.workspace_scope
            || input.credential_refs[0].as_str() != policy.credential_ref()
        {
            return Err(HostError::Unauthorised);
        }
        let template = &input.resource_layout[0];
        match (template.kind, &template.driver) {
            (
                ResourceKind::StructuredProvider,
                ResourceDriver::Structured {
                    driver_ref,
                    protocol_ref,
                },
            ) if driver_ref == policy.driver_ref() && protocol_ref == policy.protocol_ref() => {}
            _ => return Err(HostError::Unauthorised),
        }
        self.codex_policy = Some(policy);
        Ok(self)
    }

    pub fn codex_policy(&self) -> Option<&CodexAppServerPolicyV2> {
        self.codex_policy.as_ref()
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

    pub(crate) fn resolve_native_policy(
        &self,
        host: &TrustedNativeHostConfig,
        spec: &EffectiveLaunchSpec,
        binding: &LaunchBinding,
        effective_digest: &str,
    ) -> Result<(ReviewedNativePolicy, ResolvedNativePaths), HostError> {
        if self.requires_fd3_observe() || self.codex_policy.is_some() {
            return Err(HostError::Unsupported);
        }
        self.resolve_native_policy_for_review(host, spec, binding, effective_digest)
    }

    pub(crate) fn resolve_native_policy_codex_v2(
        &self,
        host: &TrustedNativeHostConfig,
        spec: &EffectiveLaunchSpec,
        binding: &LaunchBinding,
        effective_digest: &str,
    ) -> Result<(ReviewedNativePolicy, ResolvedNativePaths), HostError> {
        if self.requires_fd3_observe() {
            return Err(HostError::Unsupported);
        }
        let policy = self.codex_policy.as_ref().ok_or(HostError::Unsupported)?;
        if binding.parent_run_id().is_some()
            || binding.resources().len() != 1
            || binding.resources()[0].kind() != ResourceKind::StructuredProvider
            || spec.credential_refs.len() != 1
            || spec.credential_refs[0].scope_id().as_str() != policy.credential_scope()
            || spec.credential_refs[0].as_str() != policy.credential_ref()
        {
            return Err(HostError::Unauthorised);
        }
        self.resolve_native_policy_for_review(host, spec, binding, effective_digest)
    }

    fn resolve_native_policy_for_review(
        &self,
        host: &TrustedNativeHostConfig,
        spec: &EffectiveLaunchSpec,
        binding: &LaunchBinding,
        effective_digest: &str,
    ) -> Result<(ReviewedNativePolicy, ResolvedNativePaths), HostError> {
        if host.target_os != TargetOs::Linux
            || self.input.execution_mode != ExecutionMode::LinuxCooperative
            || spec.profile_ref != self.input.profile_ref
            || spec.profile_generation != self.input.profile_generation
            || spec.workspace.scope_id != self.input.workspace_scope
            || spec.workspace.basis_ref != self.input.workspace_basis_ref
            || spec.workspace.access != WorkspaceAccess::ReadWrite
            || binding.resources().len() != self.input.resource_layout.len()
        {
            return Err(HostError::Unsupported);
        }
        let paths = self.resolve_native_paths(&spec.workspace.relative_cwd)?;
        let mut resources = Vec::with_capacity(binding.resources().len());
        for (bound, template) in binding.resources().iter().zip(&self.input.resource_layout) {
            if bound.kind() != template.kind {
                return Err(HostError::Unauthorised);
            }
            if !host.supports_driver(&template.driver) {
                return Err(HostError::Unsupported);
            }
            resources.push(ReviewedResource {
                resource_id: bound.id().clone(),
                kind: bound.kind(),
                epoch: bound.epoch(),
                driver: template.driver.clone(),
            });
        }
        let policy = ReviewedNativePolicy {
            target_os: host.target_os,
            host_id: host.host_id.clone(),
            profile_ref: spec.profile_ref.clone(),
            profile_generation: spec.profile_generation,
            model_id: spec.model_id.clone(),
            reasoning_effort: spec.reasoning_effort.clone(),
            executable_generation: spec.binary_generation.clone(),
            effective_spec_digest: effective_digest.to_owned(),
            workspace_basis_ref: spec.workspace.basis_ref.clone(),
            executable: paths.executable.to_string_lossy().into_owned(),
            cwd: paths.cwd.to_string_lossy().into_owned(),
            arguments: spec.arguments.clone(),
            environment_refs: spec.environment_refs.clone(),
            credential_refs: spec
                .credential_refs
                .iter()
                .map(|reference| reference.as_str().to_owned())
                .collect(),
            wall_seconds: spec.wall_seconds,
            max_children: spec.max_children,
            resources,
        };
        Ok((policy, paths))
    }

    pub(crate) fn revalidate_committed_native(
        &self,
        host: &TrustedNativeHostConfig,
        effective: &EffectiveLaunchContract,
        descriptor: &ImmutableLaunchDescriptor,
    ) -> Result<ResolvedNativePaths, HostError> {
        if self.requires_fd3_observe() || self.codex_policy.is_some() {
            return Err(HostError::Unsupported);
        }
        if host.target_os != TargetOs::Linux
            || descriptor.target_os() != host.target_os
            || descriptor.host_id() != host.host_id
            || effective.profile_ref() != self.input.profile_ref
            || effective.profile_generation() != self.input.profile_generation
            || effective.workspace_scope() != &self.input.workspace_scope
            || effective.workspace_basis_ref() != self.input.workspace_basis_ref
            || effective.workspace_access() != EffectiveWorkspaceAccess::ReadWrite
            || !self.input.allow_write
            || descriptor.resources_len() != self.input.resource_layout.len()
            || descriptor.executable_generation() != self.input.binary_generation
            || effective.executable() != self.input.executable
            || matches!(effective.lifetime(), LifetimeLimit::UntilStopped)
                != self.operator_until_stopped
        {
            return Err(HostError::StaleGuard);
        }
        for (index, template) in self.input.resource_layout.iter().enumerate() {
            let native = descriptor.resource(index).ok_or(HostError::StaleGuard)?;
            if native.kind != NativeResourceKind::from(template.kind)
                || native.driver != &template.driver
                || !host.supports_driver(&template.driver)
            {
                return Err(HostError::StaleGuard);
            }
        }
        let paths = self.resolve_native_paths(effective.relative_cwd())?;
        if descriptor.cwd() != paths.cwd.to_string_lossy()
            || descriptor.executable() != paths.executable.to_string_lossy()
        {
            return Err(HostError::StaleGuard);
        }
        Ok(paths)
    }

    /// Rebuilds the complete effective launch from today's trusted policy.
    /// The committed V2 bytes are the only selection source; a caller cannot
    /// supply a replacement descriptor or silently choose profile defaults.
    pub(crate) fn revalidate_committed_codex_v2(
        &self,
        host: &TrustedNativeHostConfig,
        effective: &EffectiveLaunchContractV2,
        descriptor: &ImmutableLaunchDescriptorV2,
    ) -> Result<ResolvedNativePaths, HostError> {
        if self.requires_fd3_observe() {
            return Err(HostError::Unsupported);
        }
        let policy = self.codex_policy.as_ref().ok_or(HostError::StaleGuard)?;
        let base = effective.base();
        if effective.codex_policy() != policy
            || descriptor.codex_policy() != policy
            || base.parent_run_id().is_some()
            || descriptor.parent_run_id().is_some()
            || host.target_os != TargetOs::Linux
            || descriptor.target_os() != host.target_os
            || descriptor.host_id() != host.host_id
            || self.input.execution_mode != ExecutionMode::LinuxCooperative
            || !self.input.allow_write
            || self.input.resource_layout.len() != 1
            || descriptor.resources_len() != 1
            || self.input.credential_refs.len() != 1
            || base.profile_ref() != self.input.profile_ref
            || base.profile_generation() != self.input.profile_generation
            || base.workspace_scope() != &self.input.workspace_scope
            || base.workspace_basis_ref() != self.input.workspace_basis_ref
            || base.workspace_access() != EffectiveWorkspaceAccess::ReadWrite
            || base.credential_refs().len() != 1
            || base.credential_refs()[0].scope_id() != &self.input.workspace_scope
            || base.credential_refs()[0].reference() != policy.credential_ref()
            || self.input.credential_refs[0].as_str() != policy.credential_ref()
        {
            return Err(HostError::StaleGuard);
        }
        let role = match base.role() {
            NativeRole::Coordinator => Role::Coordinator,
            NativeRole::Worker => Role::Worker,
            NativeRole::Advisor => return Err(HostError::StaleGuard),
        };
        let arguments = base
            .arguments()
            .strip_prefix(self.input.fixed_arguments.as_slice())
            .ok_or(HostError::StaleGuard)?
            .to_vec();
        let selection = LaunchSelection {
            profile_ref: base.profile_ref().to_owned(),
            profile_generation: base.profile_generation(),
            model_id: Some(base.model_id().to_owned()),
            reasoning_effort: Some(base.reasoning_effort().to_owned()),
            fallback_approved: base.fallback_approved(),
            workspace: WorkspaceSelection {
                scope_id: base.workspace_scope().clone(),
                basis_ref: base.workspace_basis_ref().to_owned(),
                relative_cwd: base.relative_cwd().to_owned(),
                access: WorkspaceAccess::ReadWrite,
            },
            arguments,
            tool_bundle_refs: base.tool_bundle_refs().to_vec(),
            authority_ref: format!("grant.{}", base.authority_grant_id()),
            wall_seconds: base.wall_seconds().unwrap_or(self.input.max_wall_seconds),
            max_children: base.max_children(),
            parent_run_id: None,
        };
        let spec = self
            .resolve_codex_v2(
                base.pod_id().clone(),
                role,
                base.authority_grant_id(),
                Some(&self.input.credential_refs[0]),
                &selection,
            )
            .map_err(|_| HostError::StaleGuard)?;
        if spec.canonical_bytes()? != base.canonical_bytes() {
            return Err(HostError::StaleGuard);
        }
        let template = &self.input.resource_layout[0];
        let native = descriptor.resource(0).ok_or(HostError::StaleGuard)?;
        if template.kind != ResourceKind::StructuredProvider
            || native.kind != NativeResourceKind::StructuredProvider
            || native.driver != &template.driver
            || !host.supports_driver(&template.driver)
            || descriptor.executable_generation() != self.input.binary_generation
        {
            return Err(HostError::StaleGuard);
        }
        let paths = self.resolve_native_paths(base.relative_cwd())?;
        if descriptor.cwd() != paths.cwd.to_string_lossy()
            || descriptor.executable() != paths.executable.to_string_lossy()
        {
            return Err(HostError::StaleGuard);
        }
        Ok(paths)
    }

    fn resolve_native_paths(&self, relative_cwd: &str) -> Result<ResolvedNativePaths, HostError> {
        if !valid_relative_cwd(relative_cwd) {
            return Err(HostError::Unauthorised);
        }
        resolve_linux_paths(
            &self.input.workspace_root,
            relative_cwd,
            Path::new(&self.input.executable),
            &self.input.executable_sha256,
        )
    }

    pub(crate) fn resolve(
        &self,
        pod_id: PodId,
        role: Role,
        grant_id: u64,
        selected_credential: Option<&CredentialRef>,
        selection: &LaunchSelection,
    ) -> Result<EffectiveLaunchSpec, HostError> {
        if self.requires_fd3_observe() || self.codex_policy.is_some() {
            return Err(HostError::Unsupported);
        }
        self.resolve_selection(pod_id, role, grant_id, selected_credential, selection)
    }

    pub(crate) fn resolve_codex_v2(
        &self,
        pod_id: PodId,
        role: Role,
        grant_id: u64,
        selected_credential: Option<&CredentialRef>,
        selection: &LaunchSelection,
    ) -> Result<EffectiveLaunchSpec, HostError> {
        if self.requires_fd3_observe() {
            return Err(HostError::Unsupported);
        }
        let policy = self.codex_policy.as_ref().ok_or(HostError::Unsupported)?;
        let credential = selected_credential.ok_or(HostError::Unauthorised)?;
        if !matches!(role, Role::Coordinator | Role::Worker)
            || selection.parent_run_id.is_some()
            || selection.model_id.is_none()
            || selection.reasoning_effort.is_none()
            || selection.workspace.access != WorkspaceAccess::ReadWrite
            || selection.fallback_approved
            || credential.scope_id().as_str() != policy.credential_scope()
            || credential.as_str() != policy.credential_ref()
        {
            return Err(HostError::Unauthorised);
        }
        self.resolve_selection(pod_id, role, grant_id, Some(credential), selection)
    }

    fn resolve_selection(
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
            until_stopped: (profile.profile_ref == OPERATOR_PROCESS_PROFILE_REF
                && self.operator_until_stopped)
                || (self.codex_until_stopped && role == Role::Coordinator
                    && selection.parent_run_id.is_none()),
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
    until_stopped: bool,
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
        if self.profile_ref == podbay_wire::OPERATOR_FD3_OBSERVE_PROFILE_REF {
            return Err(HostError::Unsupported);
        }
        let mut output = if self.until_stopped && self.profile_ref == OPERATOR_PROCESS_PROFILE_REF {
            b"podbay.effective-launch/operator-until-stopped/1\0".to_vec()
        } else if self.until_stopped {
            b"podbay.effective-launch/codex-until-stopped/1\0".to_vec()
        } else {
            b"podbay.effective-launch/1\0".to_vec()
        };
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
        if !self.until_stopped {
            output.extend_from_slice(&self.wall_seconds.to_be_bytes());
        }
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

/// Pure registry update shared with DurableAuthority. No store or port effect.
pub(crate) fn register_launch_profile(
    profiles: &mut HashMap<String, RegisteredLaunchProfile>,
    profile: RegisteredLaunchProfile,
) -> Result<(), HostError> {
    if profile.requires_fd3_observe() {
        profile.validate_fd3_registration()?;
    }
    let key = profile.profile_ref().to_owned();
    if let Some(existing) = profiles.get(&key) {
        if existing.generation() > profile.generation()
            || (existing.generation() == profile.generation() && existing != &profile)
        {
            return Err(HostError::StaleGuard);
        }
    }
    profiles.insert(key, profile);
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn driver_matches_kind(template: &TrustedDriverTemplate) -> bool {
    match (template.kind, &template.driver) {
        (
            ResourceKind::Pty,
            ResourceDriver::Pty {
                rows,
                columns,
                retention_events,
            },
        ) => *rows > 0 && *columns > 0 && *retention_events > 0,
        (
            ResourceKind::StructuredProvider,
            ResourceDriver::Structured {
                driver_ref,
                protocol_ref,
            },
        ) => valid_label(driver_ref) && valid_label(protocol_ref),
        (ResourceKind::Auxiliary, ResourceDriver::Auxiliary { driver_ref }) => {
            valid_label(driver_ref)
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn reject_symlink_components(path: &Path) -> Result<(), HostError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            _ => return Err(HostError::InvalidInput),
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| HostError::StaleGuard)?;
        if metadata.file_type().is_symlink() {
            return Err(HostError::Unauthorised);
        }
    }
    Ok(())
}

/// Cooperative pathname checks. A later rename/write or dynamic loader change
/// can still race a pathname-based spawn; this is not hostile same-UID isolation.
#[cfg(target_os = "linux")]
fn resolve_linux_paths(
    workspace_root: &Path,
    relative_cwd: &str,
    executable: &Path,
    expected_sha256: &str,
) -> Result<ResolvedNativePaths, HostError> {
    use std::os::unix::fs::PermissionsExt;

    reject_symlink_components(workspace_root)?;
    let root = std::fs::canonicalize(workspace_root).map_err(|_| HostError::StaleGuard)?;
    if !root.is_dir() {
        return Err(HostError::InvalidInput);
    }
    let requested_cwd = if relative_cwd == "." {
        root.clone()
    } else {
        root.join(relative_cwd)
    };
    reject_symlink_components(&requested_cwd)?;
    let cwd = std::fs::canonicalize(&requested_cwd).map_err(|_| HostError::StaleGuard)?;
    if !cwd.starts_with(&root) || !cwd.is_dir() {
        return Err(HostError::Unauthorised);
    }

    reject_symlink_components(executable)?;
    let executable = std::fs::canonicalize(executable).map_err(|_| HostError::StaleGuard)?;
    let metadata = std::fs::metadata(&executable).map_err(|_| HostError::StaleGuard)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(HostError::InvalidInput);
    }
    let mut file = std::fs::File::open(&executable).map_err(|_| HostError::StaleGuard)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer).map_err(|_| HostError::StaleGuard)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    let actual_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_sha256 != expected_sha256 {
        return Err(HostError::StaleGuard);
    }
    Ok(ResolvedNativePaths {
        cwd,
        executable,
        executable_sha256: actual_sha256,
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_linux_paths(
    _workspace_root: &Path,
    _relative_cwd: &str,
    _executable: &Path,
    _expected_sha256: &str,
) -> Result<ResolvedNativePaths, HostError> {
    Err(HostError::Unsupported)
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

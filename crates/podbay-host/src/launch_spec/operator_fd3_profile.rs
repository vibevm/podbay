//! Trusted registration and bounded data resolution only. This module never
//! opens files, admits a command, constructs ResolvedNativeLaunch, calls an OS
//! port or produces a readiness observation.
use podbay_core::{PlannedRootBinding, WorkKind};
use podbay_wire::{
    EffectiveOperatorFd3ObserveContractV1, ImmutableOperatorFd3ObserveDescriptorV1,
    OPERATOR_FD3_OBSERVE_DRIVER_REF, OPERATOR_FD3_OBSERVE_PROFILE_REF,
    OperatorFd3ObserveEffectiveInputV1, OperatorFd3ObservePolicyV1, OperatorFilePinV1,
};

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Fd3Registration {
    policy: OperatorFd3ObservePolicyV1,
    lifetime: LifetimeLimit,
}

/// Validated wire data from one exact trusted registration and root plan.
/// This is neither an authenticated request nor an admission/dispatch proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedOperatorFd3ObserveData {
    effective: EffectiveOperatorFd3ObserveContractV1,
    descriptor: ImmutableOperatorFd3ObserveDescriptorV1,
}
impl ResolvedOperatorFd3ObserveData {
    pub fn effective(&self) -> &EffectiveOperatorFd3ObserveContractV1 {
        &self.effective
    }
    pub fn descriptor(&self) -> &ImmutableOperatorFd3ObserveDescriptorV1 {
        &self.descriptor
    }
}

impl RegisteredLaunchProfile {
    /// Trusted setup only. Requests cannot supply this policy through
    /// LaunchSelection. Pins remain expectations until a separate trusted
    /// filesystem/launch adapter measures and rechecks them.
    pub fn from_trusted_operator_fd3_observe_policy(
        input: TrustedLaunchProfileInput,
        policy: OperatorFd3ObservePolicyV1,
        lifetime: LifetimeLimit,
    ) -> Result<Self, HostError> {
        let mut profile = Self::from_common_input(input)?;
        profile.operator_fd3_observe = Some(Fd3Registration { policy, lifetime });
        profile.validate_fd3_registration()?;
        Ok(profile)
    }

    pub fn operator_fd3_observe_policy(&self) -> Option<&OperatorFd3ObservePolicyV1> {
        self.operator_fd3_observe
            .as_ref()
            .map(|registered| &registered.policy)
    }

    /// Pure, bounded data resolution. The caller must perform authenticated
    /// admission separately; this method does not consult current authority.
    /// Every execution choice is exact. UntilStopped comes from registration,
    /// never a numeric wall-time sentinel or a request override.
    pub fn resolve_operator_fd3_observe_data(
        &self,
        host: &TrustedNativeHostConfig,
        planned: &PlannedRootBinding,
        grant_id: u64,
        selection: &LaunchSelection,
    ) -> Result<ResolvedOperatorFd3ObserveData, HostError> {
        self.validate_fd3_registration()?;
        let registered = self
            .operator_fd3_observe
            .as_ref()
            .ok_or(HostError::Unsupported)?;
        let binding = planned.identity();
        if host.target_os != TargetOs::Linux
            || !host.supports_driver(&self.input.resource_layout[0].driver)
        {
            return Err(HostError::Unsupported);
        }
        if grant_id == 0
            || binding.scope_id() != &self.input.workspace_scope
            || binding.role() != Role::Coordinator
            || binding.work_kind() != WorkKind::Service
            || binding.parent_run_id().is_some()
            || binding.resources().len() != 1
            || binding.resources()[0].kind() != ResourceKind::Auxiliary
            || selection.workspace.relative_cwd != "."
            || selection.workspace.access != WorkspaceAccess::ReadWrite
            || selection.parent_run_id.is_some()
            || selection.wall_seconds != self.input.max_wall_seconds
            || selection.max_children != 0
            || selection.fallback_approved
            || !selection.arguments.is_empty()
            || !selection.tool_bundle_refs.is_empty()
        {
            return Err(HostError::Unauthorised);
        }
        // Reuse the exact profile/generation/scope/basis/grant selection checks,
        // but never encode the temporary legacy EffectiveLaunchSpec.
        let selected = self.resolve_selection(
            binding.pod_id().clone(),
            Role::Coordinator,
            grant_id,
            None,
            selection,
        )?;
        let effective = EffectiveOperatorFd3ObserveContractV1::new(
            OperatorFd3ObserveEffectiveInputV1 {
                pod_id: binding.pod_id().clone(),
                scope_id: binding.scope_id().clone(),
                host_id: host.host_id.clone(),
                profile_generation: self.input.profile_generation,
                executable: OperatorFilePinV1 {
                    path: self.input.executable.clone(),
                    sha256: self.input.executable_sha256.clone(),
                },
                cwd: registered.policy.artifact().root.clone(),
                arguments: selected.arguments,
                workspace_basis_ref: self.input.workspace_basis_ref.clone(),
                authority_grant_id: grant_id,
                lifetime: registered.lifetime,
            },
            registered.policy.clone(),
        )
        .map_err(|_| HostError::InvalidInput)?;
        let descriptor =
            ImmutableOperatorFd3ObserveDescriptorV1::from_planned_root(planned, &effective)
                .map_err(|_| HostError::Unauthorised)?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| HostError::InvalidInput)?;
        Ok(ResolvedOperatorFd3ObserveData {
            effective,
            descriptor,
        })
    }

    pub(super) fn requires_fd3_observe(&self) -> bool {
        self.operator_fd3_observe.is_some() || has_fd3_names(&self.input)
    }

    pub(super) fn validate_fd3_registration(&self) -> Result<(), HostError> {
        let registered = self
            .operator_fd3_observe
            .as_ref()
            .ok_or(HostError::Unsupported)?;
        let input = &self.input;
        if self.codex_policy.is_some()
            || self.operator_until_stopped
            || self.codex_until_stopped
            || input.profile_ref != OPERATOR_FD3_OBSERVE_PROFILE_REF
            || input.execution_mode != ExecutionMode::LinuxCooperative
            || input.resource_layout.len() != 1
            || input.resource_layout[0].kind != ResourceKind::Auxiliary
            || !matches!(&input.resource_layout[0].driver, ResourceDriver::Auxiliary { driver_ref }
                if driver_ref == OPERATOR_FD3_OBSERVE_DRIVER_REF)
            || input.workspace_root.to_str() != Some(registered.policy.artifact().root.as_str())
            || input.allowed_cwd_prefix != "."
            || !input.allow_write
            || !lexical_linux_executable(&input.executable)
            || input.fixed_arguments.is_empty()
            || !input.permitted_extra_arguments.is_empty()
            || input.default_model != "none"
            || input.allowed_models != BTreeSet::from(["none".into()])
            || input.default_effort != "none"
            || input.allowed_efforts != BTreeSet::from(["none".into()])
            || input.allow_fallback
            || input.max_children != 0
            || !input.allowed_tool_bundle_refs.is_empty()
            || !input.environment_refs.is_empty()
            || !input.credential_refs.is_empty()
            || !(30..=3600).contains(&input.max_wall_seconds)
            || !matches!(
                registered.lifetime,
                LifetimeLimit::UntilStopped | LifetimeLimit::Finite { seconds: 30..=3600 }
            )
            || matches!(registered.lifetime, LifetimeLimit::Finite { seconds } if seconds != input.max_wall_seconds)
        {
            return Err(HostError::Unauthorised);
        }
        Ok(())
    }
}

pub(super) fn has_fd3_names(input: &TrustedLaunchProfileInput) -> bool {
    input.profile_ref == OPERATOR_FD3_OBSERVE_PROFILE_REF
        || input.resource_layout.iter().any(|template| {
            matches!(&template.driver,
                ResourceDriver::Auxiliary { driver_ref }
                    | ResourceDriver::Structured { driver_ref, .. }
                    if driver_ref == OPERATOR_FD3_OBSERVE_DRIVER_REF)
        })
}

fn lexical_linux_executable(value: &str) -> bool {
    value.len() > 1
        && value.len() <= 4096
        && value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(all(test, target_os = "linux"))]
mod tests;

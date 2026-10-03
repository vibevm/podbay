//! Strict decoder for host PB09b `EffectiveLaunchSpec::canonical_bytes`.
//! Parsing and comparison do not prove that a profile or OS path was reviewed.
use std::error::Error;
use std::fmt::{Display, Formatter};

use podbay_core::{PodId, RunId, ScopeId};
use sha2::{Digest, Sha256};

use crate::{ImmutableLaunchDescriptor, MAX_FRAME_BYTES, NativeRole};

pub const EFFECTIVE_LAUNCH_VERSION: &str = "podbay.effective-launch/1";
const PREFIX: &[u8] = b"podbay.effective-launch/1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveLaunchError {
    TooLarge,
    Truncated,
    TrailingBytes,
    InvalidField(&'static str),
    NonCanonical,
    DescriptorMismatch(&'static str),
}
impl Display for EffectiveLaunchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("effective launch bytes exceed the frame bound"),
            Self::Truncated => f.write_str("effective launch bytes end before a field is complete"),
            Self::TrailingBytes => f.write_str("effective launch bytes contain trailing data"),
            Self::InvalidField(field) => write!(f, "invalid effective launch field: {field}"),
            Self::NonCanonical => f.write_str("effective launch bytes are not canonical"),
            Self::DescriptorMismatch(field) => {
                write!(f, "descriptor differs from effective launch: {field}")
            }
        }
    }
}
impl Error for EffectiveLaunchError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveWorkspaceAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLocator {
    scope_id: ScopeId,
    reference: String,
}
impl CredentialLocator {
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveLaunchContract {
    canonical: Vec<u8>,
    digest: String,
    pod_id: PodId,
    role: NativeRole,
    parent_run_id: Option<RunId>,
    profile_ref: String,
    profile_generation: u64,
    executable: String,
    executable_generation: String,
    arguments: Vec<String>,
    model_id: String,
    reasoning_effort: String,
    fallback_approved: bool,
    workspace_scope: ScopeId,
    workspace_basis_ref: String,
    relative_cwd: String,
    workspace_access: EffectiveWorkspaceAccess,
    tool_bundle_refs: Vec<String>,
    authority_grant_id: u64,
    wall_seconds: u64,
    max_children: u32,
    environment_refs: Vec<String>,
    credential_refs: Vec<CredentialLocator>,
}

impl EffectiveLaunchContract {
    pub fn decode(bytes: &[u8]) -> Result<Self, EffectiveLaunchError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(EffectiveLaunchError::TooLarge);
        }
        let mut reader = Reader { bytes, at: 0 };
        if reader.take(PREFIX.len())? != PREFIX {
            return Err(EffectiveLaunchError::InvalidField("version"));
        }
        let pod_id = PodId::try_from(reader.string(256)?.as_str())
            .map_err(|_| EffectiveLaunchError::InvalidField("podId"))?;
        let role = match reader.string(32)?.as_str() {
            "coordinator" => NativeRole::Coordinator,
            "worker" => NativeRole::Worker,
            "advisor" => NativeRole::Advisor,
            _ => return Err(EffectiveLaunchError::InvalidField("role")),
        };
        let parent_run_id = match reader.byte()? {
            0 => None,
            1 => Some(
                RunId::try_from(reader.string(256)?.as_str())
                    .map_err(|_| EffectiveLaunchError::InvalidField("parentRunId"))?,
            ),
            _ => return Err(EffectiveLaunchError::InvalidField("parentRunId marker")),
        };
        let profile_ref = reader.label("profileRef")?;
        let profile_generation = reader.u64()?;
        if profile_generation == 0 {
            return Err(EffectiveLaunchError::InvalidField("profileGeneration"));
        }
        let executable = reader.string(4096)?;
        if executable.len() < 2 || executable.chars().any(char::is_control) {
            return Err(EffectiveLaunchError::InvalidField("executable"));
        }
        let executable_generation = reader.label("binaryGeneration")?;
        let arguments = reader.list(128, 1024, "arguments", valid_argument)?;
        let model_id = reader.label("modelId")?;
        let reasoning_effort = reader.label("reasoningEffort")?;
        let fallback_approved = match reader.byte()? {
            0 => false,
            1 => true,
            _ => return Err(EffectiveLaunchError::InvalidField("fallbackApproved")),
        };
        let workspace_scope = ScopeId::try_from(reader.string(256)?.as_str())
            .map_err(|_| EffectiveLaunchError::InvalidField("workspace.scopeId"))?;
        let workspace_basis_ref = reader.label("workspace.basisRef")?;
        let relative_cwd = reader.string(1024)?;
        if !valid_relative_cwd(&relative_cwd) {
            return Err(EffectiveLaunchError::InvalidField("workspace.relativeCwd"));
        }
        let workspace_access = match reader.byte()? {
            0 => EffectiveWorkspaceAccess::ReadOnly,
            1 => EffectiveWorkspaceAccess::ReadWrite,
            _ => return Err(EffectiveLaunchError::InvalidField("workspace.access")),
        };
        let tool_bundle_refs = reader.list(64, 256, "toolBundleRefs", valid_label)?;
        if !sorted_unique(&tool_bundle_refs) {
            return Err(EffectiveLaunchError::InvalidField("toolBundleRefs order"));
        }
        let authority_grant_id = reader.u64()?;
        if authority_grant_id == 0 {
            return Err(EffectiveLaunchError::InvalidField("authorityGrantId"));
        }
        let wall_seconds = reader.u64()?;
        if wall_seconds == 0 {
            return Err(EffectiveLaunchError::InvalidField("wallSeconds"));
        }
        let max_children = reader.u32()?;
        let environment_refs = reader.list(64, 256, "environmentRefs", valid_label)?;
        if !sorted_unique(&environment_refs) {
            return Err(EffectiveLaunchError::InvalidField("environmentRefs order"));
        }
        let credential_count = reader.u32()? as usize;
        if credential_count > 1 {
            return Err(EffectiveLaunchError::InvalidField("credentialRefs count"));
        }
        let mut credential_refs = Vec::with_capacity(credential_count);
        for _ in 0..credential_count {
            let scope_id = ScopeId::try_from(reader.string(256)?.as_str())
                .map_err(|_| EffectiveLaunchError::InvalidField("credential.scopeId"))?;
            if scope_id != workspace_scope {
                return Err(EffectiveLaunchError::InvalidField("credential scope"));
            }
            let reference = reader.string(160)?;
            if !valid_credential_ref(&reference) {
                return Err(EffectiveLaunchError::InvalidField("credential reference"));
            }
            credential_refs.push(CredentialLocator {
                scope_id,
                reference,
            });
        }
        if reader.at != bytes.len() {
            return Err(EffectiveLaunchError::TrailingBytes);
        }
        let result = Self {
            canonical: bytes.to_vec(),
            digest: digest(bytes),
            pod_id,
            role,
            parent_run_id,
            profile_ref,
            profile_generation,
            executable,
            executable_generation,
            arguments,
            model_id,
            reasoning_effort,
            fallback_approved,
            workspace_scope,
            workspace_basis_ref,
            relative_cwd,
            workspace_access,
            tool_bundle_refs,
            authority_grant_id,
            wall_seconds,
            max_children,
            environment_refs,
            credential_refs,
        };
        if result.reencode() != bytes {
            return Err(EffectiveLaunchError::NonCanonical);
        }
        Ok(result)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn pod_id(&self) -> &PodId {
        &self.pod_id
    }
    pub fn role(&self) -> NativeRole {
        self.role
    }
    pub fn parent_run_id(&self) -> Option<&RunId> {
        self.parent_run_id.as_ref()
    }
    pub fn profile_ref(&self) -> &str {
        &self.profile_ref
    }
    pub fn profile_generation(&self) -> u64 {
        self.profile_generation
    }
    pub fn executable(&self) -> &str {
        &self.executable
    }
    pub fn executable_generation(&self) -> &str {
        &self.executable_generation
    }
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
    pub fn model_id(&self) -> &str {
        &self.model_id
    }
    pub fn reasoning_effort(&self) -> &str {
        &self.reasoning_effort
    }
    pub fn fallback_approved(&self) -> bool {
        self.fallback_approved
    }
    pub fn workspace_scope(&self) -> &ScopeId {
        &self.workspace_scope
    }
    pub fn workspace_basis_ref(&self) -> &str {
        &self.workspace_basis_ref
    }
    pub fn relative_cwd(&self) -> &str {
        &self.relative_cwd
    }
    pub fn workspace_access(&self) -> EffectiveWorkspaceAccess {
        self.workspace_access
    }
    pub fn tool_bundle_refs(&self) -> &[String] {
        &self.tool_bundle_refs
    }
    pub fn authority_grant_id(&self) -> u64 {
        self.authority_grant_id
    }
    pub fn wall_seconds(&self) -> u64 {
        self.wall_seconds
    }
    pub fn max_children(&self) -> u32 {
        self.max_children
    }
    pub fn environment_refs(&self) -> &[String] {
        &self.environment_refs
    }
    pub fn credential_refs(&self) -> &[CredentialLocator] {
        &self.credential_refs
    }

    /// Strictly compares fields present in both formats. The descriptor's
    /// resolved cwd, host and driver inventory need separate trusted checks.
    pub fn compare_with_descriptor(
        &self,
        descriptor: &ImmutableLaunchDescriptor,
    ) -> Result<(), EffectiveLaunchError> {
        let credential_refs = self
            .credential_refs
            .iter()
            .map(|value| value.reference.as_str())
            .collect::<Vec<_>>();
        let checks = [
            (descriptor.pod_id() == self.pod_id.as_str(), "podId"),
            (descriptor.role() == self.role, "role"),
            (
                descriptor.parent_run_id() == self.parent_run_id.as_ref().map(|v| v.as_str()),
                "parentRunId",
            ),
            (descriptor.profile_ref() == self.profile_ref, "profileRef"),
            (
                descriptor.profile_generation() == self.profile_generation,
                "profileGeneration",
            ),
            (descriptor.executable() == self.executable, "executable"),
            (
                descriptor.executable_generation() == self.executable_generation,
                "binaryGeneration",
            ),
            (descriptor.arguments() == self.arguments, "arguments"),
            (descriptor.model_id() == self.model_id, "modelId"),
            (
                descriptor.reasoning_effort() == self.reasoning_effort,
                "reasoningEffort",
            ),
            (
                descriptor.scope_id() == self.workspace_scope.as_str(),
                "workspace.scopeId",
            ),
            (
                descriptor.workspace_basis_ref() == self.workspace_basis_ref,
                "workspace.basisRef",
            ),
            (
                descriptor.wall_seconds() == self.wall_seconds,
                "wallSeconds",
            ),
            (
                descriptor.max_children() == u64::from(self.max_children),
                "maxChildren",
            ),
            (
                descriptor.environment_refs() == self.environment_refs,
                "environmentRefs",
            ),
            (
                descriptor
                    .credential_refs()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    == credential_refs,
                "credentialRefs",
            ),
            (
                descriptor.effective_spec_digest() == self.digest,
                "effectiveSpecDigest",
            ),
        ];
        for (matches, field) in checks {
            if !matches {
                return Err(EffectiveLaunchError::DescriptorMismatch(field));
            }
        }
        Ok(())
    }

    pub fn reencode(&self) -> Vec<u8> {
        let mut output = PREFIX.to_vec();
        append_string(&mut output, self.pod_id.as_str());
        append_string(
            &mut output,
            match self.role {
                NativeRole::Coordinator => "coordinator",
                NativeRole::Worker => "worker",
                NativeRole::Advisor => "advisor",
            },
        );
        match &self.parent_run_id {
            Some(value) => {
                output.push(1);
                append_string(&mut output, value.as_str());
            }
            None => output.push(0),
        }
        append_string(&mut output, &self.profile_ref);
        output.extend_from_slice(&self.profile_generation.to_be_bytes());
        append_string(&mut output, &self.executable);
        append_string(&mut output, &self.executable_generation);
        append_list(&mut output, &self.arguments);
        append_string(&mut output, &self.model_id);
        append_string(&mut output, &self.reasoning_effort);
        output.push(u8::from(self.fallback_approved));
        append_string(&mut output, self.workspace_scope.as_str());
        append_string(&mut output, &self.workspace_basis_ref);
        append_string(&mut output, &self.relative_cwd);
        output.push(match self.workspace_access {
            EffectiveWorkspaceAccess::ReadOnly => 0,
            EffectiveWorkspaceAccess::ReadWrite => 1,
        });
        append_list(&mut output, &self.tool_bundle_refs);
        output.extend_from_slice(&self.authority_grant_id.to_be_bytes());
        output.extend_from_slice(&self.wall_seconds.to_be_bytes());
        output.extend_from_slice(&self.max_children.to_be_bytes());
        append_list(&mut output, &self.environment_refs);
        output.extend_from_slice(&(self.credential_refs.len() as u32).to_be_bytes());
        for credential in &self.credential_refs {
            append_string(&mut output, credential.scope_id.as_str());
            append_string(&mut output, &credential.reference);
        }
        output
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], EffectiveLaunchError> {
        let end = self
            .at
            .checked_add(length)
            .ok_or(EffectiveLaunchError::TooLarge)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(EffectiveLaunchError::Truncated)?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, EffectiveLaunchError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, EffectiveLaunchError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, EffectiveLaunchError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    fn string(&mut self, maximum: usize) -> Result<String, EffectiveLaunchError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(EffectiveLaunchError::InvalidField("string length"));
        }
        let bytes = self.take(length)?;
        let value =
            std::str::from_utf8(bytes).map_err(|_| EffectiveLaunchError::InvalidField("UTF-8"))?;
        Ok(value.to_owned())
    }
    fn label(&mut self, field: &'static str) -> Result<String, EffectiveLaunchError> {
        let value = self.string(256)?;
        if !valid_label(&value) {
            return Err(EffectiveLaunchError::InvalidField(field));
        }
        Ok(value)
    }
    fn list(
        &mut self,
        maximum_count: usize,
        maximum_length: usize,
        field: &'static str,
        valid: fn(&str) -> bool,
    ) -> Result<Vec<String>, EffectiveLaunchError> {
        let count = self.u32()? as usize;
        if count > maximum_count {
            return Err(EffectiveLaunchError::InvalidField(field));
        }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let value = self.string(maximum_length)?;
            if !valid(&value) {
                return Err(EffectiveLaunchError::InvalidField(field));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}
fn append_list(output: &mut Vec<u8>, values: &[String]) {
    output.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        append_string(output, value);
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn valid_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}
fn valid_argument(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}
fn valid_credential_ref(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}
fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
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

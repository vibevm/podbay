//! One strict manager-owned Codex V2 policy. This file holds locators and
//! reviewed launch choices, never actor private keys or credential bytes.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_core::{ActorId, ResourceKind, ScopeId};
use podbay_host::{
    CredentialRef, ExecutionMode, RegisteredLaunchProfile, TrustedDriverTemplate,
    TrustedInitialOwnerPolicy, TrustedLaunchProfileInput, TrustedNativeHostConfig,
};
use podbay_launch_linux::TrustedCodexCredentialSource;
use podbay_wire::{CodexAppServerPolicyV2, LifetimeLimit, ResourceDriver};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_POLICY_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicy {
    schema: String,
    actor_id: String,
    scope_id: String,
    credential_ref: String,
    credential_source: PathBuf,
    profile_ref: String,
    profile_generation: u64,
    executable: PathBuf,
    executable_sha256: String,
    workspace_root: PathBuf,
    workspace_basis_ref: String,
    host_id: String,
    driver_ref: String,
    protocol_ref: String,
    model_id: String,
    reasoning_effort: String,
    approval_policy: String,
    sandbox: String,
    #[serde(default)]
    wall_seconds: Option<u64>,
    #[serde(default)]
    lifetime: Option<LifetimeLimit>,
    max_children: u32,
    result_contract_ref: String,
    launch_deadline_seconds: u64,
    send_deadline_seconds: u64,
    writer_lease_seconds: u64,
}

pub(crate) struct PreparedManagerPolicy {
    pub owner: TrustedInitialOwnerPolicy,
    pub credential_source: Option<TrustedCodexCredentialSource>,
    pub profile: RegisteredLaunchProfile,
    pub native_host: TrustedNativeHostConfig,
    pub result_contract_ref: String,
    pub launch_deadline: Duration,
    pub send_deadline: Duration,
    pub writer_lease_seconds: u64,
}

impl PreparedManagerPolicy {
    pub fn load(path: &Path, state_dir: &Path, uid: u32) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("trusted policy unavailable: {error}"))?;
        if !path.is_absolute()
            || path.parent() != Some(state_dir)
            || !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_POLICY_BYTES
            || fs::canonicalize(path).map_err(|error| error.to_string())? != path
        {
            return Err(
                "trusted manager policy must be a canonical owned 0600 file in --state-dir".into(),
            );
        }
        let file =
            File::open(path).map_err(|error| format!("trusted policy open failed: {error}"))?;
        let opened = file
            .metadata()
            .map_err(|error| format!("trusted policy metadata failed: {error}"))?;
        if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino())
            || !opened.is_file()
            || opened.uid() != uid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
        {
            return Err("trusted policy file identity changed while opening".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("trusted policy read failed: {error}"))?;
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return Err("trusted manager policy exceeds byte bound".into());
        }
        let final_metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("trusted policy path changed: {error}"))?;
        if (final_metadata.dev(), final_metadata.ino()) != (opened.dev(), opened.ino())
            || fs::canonicalize(path).map_err(|error| error.to_string())? != path
        {
            return Err("trusted policy file identity changed while reading".into());
        }
        let raw: RawPolicy = serde_json::from_slice(&bytes)
            .map_err(|error| format!("trusted manager policy is malformed: {error}"))?;
        if raw.schema != "podbay.trusted-manager-policy/1"
            || raw.model_id != "gpt-6-sol"
            || raw.reasoning_effort != "medium"
            || raw.approval_policy != "never"
            || raw.sandbox != "danger_full_access"
            || !(1..=300).contains(&raw.launch_deadline_seconds)
            || !(1..=300).contains(&raw.send_deadline_seconds)
            || !(1..=3600).contains(&raw.writer_lease_seconds)
            || !matches!((raw.wall_seconds, raw.lifetime),
                (Some(1..=604_800), None) | (None, Some(LifetimeLimit::UntilStopped)))
            || raw.max_children == 0
            || !valid_token(&raw.result_contract_ref)
        {
            return Err("trusted manager policy fixed Codex fields or budgets differ".into());
        }
        let actor =
            ActorId::try_from(raw.actor_id.as_str()).map_err(|_| "trusted actor ID is invalid")?;
        let scope =
            ScopeId::try_from(raw.scope_id.as_str()).map_err(|_| "trusted scope ID is invalid")?;
        let credential = CredentialRef::from_trusted_vault(scope.clone(), &raw.credential_ref)
            .map_err(|_| "trusted credential reference is invalid")?;
        let owner = TrustedInitialOwnerPolicy::from_trusted_manager_policy(
            actor,
            scope.clone(),
            credential.clone(),
        )
        .map_err(|_| "trusted owner policy is invalid")?;
        let credential_source = TrustedCodexCredentialSource::from_trusted_policy(
            credential.clone(),
            raw.credential_source,
        )
        .map_err(|error| format!("trusted credential source refused: {error}"))?;
        let executable = canonical_regular_file(&raw.executable)?;
        let digest = digest_file(&executable)?;
        if digest != raw.executable_sha256 {
            return Err("trusted Codex executable SHA-256 differs".into());
        }
        let workspace = fs::canonicalize(&raw.workspace_root)
            .map_err(|error| format!("workspace root unavailable: {error}"))?;
        if workspace != raw.workspace_root
            || !fs::metadata(&workspace).is_ok_and(|value| value.is_dir())
        {
            return Err("workspace root must be a canonical directory".into());
        }
        let profile = TrustedLaunchProfileInput {
            profile_ref: raw.profile_ref,
            profile_generation: raw.profile_generation,
            executable: executable.to_string_lossy().into_owned(),
            binary_generation: format!("sha256:{digest}"),
            executable_sha256: digest,
            workspace_root: workspace,
            resource_layout: vec![TrustedDriverTemplate {
                kind: ResourceKind::StructuredProvider,
                driver: ResourceDriver::Structured {
                    driver_ref: raw.driver_ref.clone(),
                    protocol_ref: raw.protocol_ref.clone(),
                },
            }],
            execution_mode: ExecutionMode::LinuxCooperative,
            fixed_arguments: vec!["app-server".into(), "--listen".into(), "stdio://".into()],
            permitted_extra_arguments: BTreeSet::new(),
            default_model: "gpt-6-sol".into(),
            allowed_models: BTreeSet::from(["gpt-6-sol".into()]),
            default_effort: "medium".into(),
            allowed_efforts: BTreeSet::from(["medium".into()]),
            workspace_scope: scope.clone(),
            workspace_basis_ref: raw.workspace_basis_ref,
            allowed_cwd_prefix: ".".into(),
            allow_write: true,
            allowed_tool_bundle_refs: BTreeSet::new(),
            environment_refs: Vec::new(),
            credential_refs: vec![credential.clone()],
            max_wall_seconds: raw.wall_seconds.unwrap_or(60),
            max_children: raw.max_children,
            allow_fallback: false,
        };
        let codex = CodexAppServerPolicyV2::new(
            &scope,
            credential.as_str().into(),
            raw.driver_ref.clone(),
            raw.protocol_ref.clone(),
        )
        .map_err(|_| "trusted Codex V2 policy is invalid")?;
        let profile = RegisteredLaunchProfile::from_trusted_policy(profile)
            .and_then(|profile| profile.with_codex_policy_from_trusted_policy(codex))
            .and_then(|profile| if raw.lifetime == Some(LifetimeLimit::UntilStopped) {
                profile.with_until_stopped_codex_service()
            } else { Ok(profile) })
            .map_err(|error| format!("trusted launch profile refused: {error:?}"))?;
        let native_host = TrustedNativeHostConfig::for_compiled_backend(raw.host_id)
            .and_then(|host| host.with_structured_driver(raw.driver_ref, raw.protocol_ref))
            .map_err(|error| format!("trusted native host refused: {error:?}"))?;
        Ok(Self {
            owner,
            credential_source: Some(credential_source),
            profile,
            native_host,
            result_contract_ref: raw.result_contract_ref,
            launch_deadline: Duration::from_secs(raw.launch_deadline_seconds),
            send_deadline: Duration::from_secs(raw.send_deadline_seconds),
            writer_lease_seconds: raw.writer_lease_seconds,
        })
    }
}

fn valid_token(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("trusted executable path is not absolute".into());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("trusted executable unavailable: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("trusted executable unavailable: {error}"))?;
    if canonical != path || !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err("trusted executable is not canonical regular executable".into());
    }
    Ok(canonical)
}

fn digest_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("trusted executable open failed: {error}"))?;
    let mut hash = Sha256::new();
    let mut chunk = [0_u8; 16_384];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|error| format!("trusted executable read failed: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

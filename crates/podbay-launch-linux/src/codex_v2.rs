//! Read-only Linux preflight for a host-reviewed, committed Codex V2 root.
//! It does not claim an outbox effect or invoke systemd.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use podbay_host::{CredentialRef, ResolvedNativeCodexLaunch};
use podbay_pod::{LinuxPeerEvidence, PodError, PodPeerBootstrap};
use podbay_store::{BoundLaunchFormat, PodBayStore};
use podbay_wire::{
    CodexApprovalPolicyV2, CodexSandboxV2, NativeResourceKind, NativeRole, NativeWorkKind,
    ResourceDriver, TargetOs,
};
use sha2::{Digest, Sha256};

const MAX_CREDENTIAL_SOURCE_BYTES: u64 = 1_048_576;

/// One scoped vault locator mapped by trusted manager policy to a private
/// source for a future systemd LoadCredential call. It never reads the file.
pub struct TrustedCodexCredentialSource {
    reference: CredentialRef,
    source: PathBuf,
    source_identity: (u64, u64),
    directory_identity: (u64, u64),
}

impl TrustedCodexCredentialSource {
    pub fn from_trusted_policy(
        reference: CredentialRef,
        source: PathBuf,
    ) -> Result<Self, PodError> {
        let (source_identity, directory_identity) = validate_private_source(&source)?;
        Ok(Self {
            reference,
            source,
            source_identity,
            directory_identity,
        })
    }

    pub(crate) fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    pub(crate) fn recheck(&self) -> Result<(), PodError> {
        let (source_identity, directory_identity) = validate_private_source(&self.source)?;
        if source_identity != self.source_identity || directory_identity != self.directory_identity
        {
            return Err(PodError::Refused("credential source identity changed"));
        }
        Ok(())
    }
}

/// A point-in-time read-only result. A later effect path must recheck every
/// fence and credential source immediately before systemd receives the path.
pub struct CodexV2Preflight {
    bootstrap: PodPeerBootstrap,
    credential_source: PathBuf,
    credential_source_identity: (u64, u64),
}

impl CodexV2Preflight {
    pub fn bootstrap(&self) -> &PodPeerBootstrap {
        &self.bootstrap
    }
    pub fn credential_source(&self) -> &Path {
        &self.credential_source
    }
    pub fn credential_source_identity(&self) -> (u64, u64) {
        self.credential_source_identity
    }
}

/// Rechecks a private host proof and one trusted credential locator mapping.
/// No request-built descriptor, credential contents or mutable store operation
/// enters this path.
pub fn preflight_committed_codex_v2(
    launch: &ResolvedNativeCodexLaunch,
    credential: &TrustedCodexCredentialSource,
) -> Result<CodexV2Preflight, PodError> {
    let record = launch.committed_record();
    let wire = launch.descriptor();
    let effective = launch.effective();
    let policy = effective.codex_policy();
    let resource = wire
        .resource(0)
        .ok_or(PodError::Refused("Codex V2 resource is missing"))?;
    let role_pair = matches!(
        (wire.role(), wire.work_kind()),
        (NativeRole::Coordinator, NativeWorkKind::Service)
            | (NativeRole::Worker, NativeWorkKind::Task)
    );
    if record.format != BoundLaunchFormat::CodexV2
        || !role_pair
        || wire.parent_run_id().is_some()
        || wire.target_os() != TargetOs::Linux
        || wire.resources_len() != 1
        || resource.kind != NativeResourceKind::StructuredProvider
        || !matches!(resource.driver, ResourceDriver::Structured { driver_ref, protocol_ref }
            if driver_ref == policy.driver_ref() && protocol_ref == policy.protocol_ref())
        || launch.resource_input_epochs().len() != 1
        || launch
            .resource_input_epochs()
            .get(resource.resource_id)
            .is_none()
        || policy.sandbox() != CodexSandboxV2::DangerFullAccess
        || policy.approval_policy() != CodexApprovalPolicyV2::Never
        || policy.credential_scope() != credential.reference.scope_id().as_str()
        || policy.credential_ref() != credential.reference.as_str()
        || effective.base().credential_refs().len() != 1
        || effective.base().credential_refs()[0].scope_id().as_str()
            != credential.reference.scope_id().as_str()
        || effective.base().credential_refs()[0].reference() != credential.reference.as_str()
        || wire.credential_refs() != [credential.reference.as_str()]
        || wire.executable() != launch.executable().to_string_lossy()
        || wire.cwd() != launch.cwd().to_string_lossy()
        || wire.executable_generation() != format!("sha256:{}", launch.executable_sha256())
        || effective.canonical_bytes() != launch.effective_spec_bytes()
        || wire
            .encode_json()
            .map_err(|_| PodError::Refused("V2 descriptor cannot encode"))?
            != launch.descriptor_bytes()
    {
        return Err(PodError::Refused(
            "Codex V2 proof or credential mapping differs",
        ));
    }
    let peer = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager identity unavailable"))?;
    if peer.attested_peer() != launch.manager_peer() {
        return Err(PodError::Refused("manager process changed"));
    }
    let database = fs::symlink_metadata(launch.store_path())
        .map_err(|_| PodError::Refused("committed store unavailable"))?;
    if !launch.store_path().is_absolute()
        || !database.is_file()
        || (database.dev(), database.ino()) != launch.store_file_identity()
        || fs::canonicalize(launch.store_path())
            .map_err(|_| PodError::Refused("committed store unavailable"))?
            != launch.store_path()
    {
        return Err(PodError::Refused("committed store identity changed"));
    }
    let mut store = PodBayStore::open(launch.store_path())
        .map_err(|_| PodError::Refused("committed store unavailable"))?;
    let claim = store
        .current_manager_credential_claim(launch.owner_epoch())
        .map_err(|_| PodError::Refused("manager claim unavailable"))?;
    if claim.store_lineage() != launch.store_lineage()
        || claim.credential_epoch() != launch.credential_epoch()
        || !store
            .current_manager_peer_matches(&claim, peer.attested_peer())
            .map_err(|_| PodError::Refused("manager peer unavailable"))?
    {
        return Err(PodError::Refused("manager claim changed"));
    }
    let current = store
        .current_bound_pod_snapshot(wire.scope_id(), wire.pod_id())
        .map_err(|_| PodError::Refused("current committed launch unavailable"))?;
    let inputs = current
        .resources()
        .iter()
        .map(|resource| {
            (
                resource.id().as_str().to_owned(),
                resource.input_epoch().get(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if current.store_lineage().as_str() != launch.store_lineage()
        || current.owner_epoch().get() != launch.owner_epoch()
        || current.authority_revision() != launch.authority_revision()
        || current.launch() != record
        || inputs != *launch.resource_input_epochs()
        || current.resources().len() != 1
        || current.resources()[0].id().as_str() != resource.resource_id
        || current.resources()[0].kind() != podbay_core::ResourceKind::StructuredProvider
        || current.resources()[0].epoch().get() != resource.epoch
    {
        return Err(PodError::Refused(
            "Codex V2 authority or resource fence changed",
        ));
    }
    let executable = fs::symlink_metadata(launch.executable())
        .map_err(|_| PodError::Refused("executable unavailable"))?;
    let cwd = fs::symlink_metadata(launch.cwd())
        .map_err(|_| PodError::Refused("workspace unavailable"))?;
    if !executable.is_file()
        || !cwd.is_dir()
        || fs::canonicalize(launch.executable())
            .map_err(|_| PodError::Refused("executable unavailable"))?
            != launch.executable()
        || fs::canonicalize(launch.cwd()).map_err(|_| PodError::Refused("workspace unavailable"))?
            != launch.cwd()
        || sha256_file(launch.executable())? != launch.executable_sha256()
    {
        return Err(PodError::Refused(
            "Codex V2 executable or workspace changed",
        ));
    }
    credential.recheck()?;
    let final_peer = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager identity unavailable"))?;
    let final_database = fs::symlink_metadata(launch.store_path())
        .map_err(|_| PodError::Refused("committed store unavailable"))?;
    let final_claim = store
        .current_manager_credential_claim(launch.owner_epoch())
        .map_err(|_| PodError::Refused("manager claim unavailable"))?;
    let final_current = store
        .current_bound_pod_snapshot(wire.scope_id(), wire.pod_id())
        .map_err(|_| PodError::Refused("current committed launch unavailable"))?;
    let final_inputs = final_current
        .resources()
        .iter()
        .map(|resource| {
            (
                resource.id().as_str().to_owned(),
                resource.input_epoch().get(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if final_peer.attested_peer() != launch.manager_peer()
        || (final_database.dev(), final_database.ino()) != launch.store_file_identity()
        || final_claim != claim
        || !store
            .current_manager_peer_matches(&final_claim, final_peer.attested_peer())
            .map_err(|_| PodError::Refused("manager peer unavailable"))?
        || final_current.store_lineage().as_str() != launch.store_lineage()
        || final_current.owner_epoch().get() != launch.owner_epoch()
        || final_current.authority_revision() != launch.authority_revision()
        || final_current.launch() != record
        || final_inputs != inputs
    {
        return Err(PodError::Refused("Codex V2 preflight fences changed"));
    }
    Ok(CodexV2Preflight {
        bootstrap: PodPeerBootstrap {
            store_path: launch.store_path().to_path_buf(),
            store_lineage: launch.store_lineage().to_owned(),
            owner_epoch: launch.owner_epoch(),
            credential_epoch: launch.credential_epoch(),
            resource_input_epochs: launch.resource_input_epochs().clone(),
            canonical_executable: launch.executable().to_path_buf(),
            executable_sha256: launch.executable_sha256().to_owned(),
            expected_manager_peer: launch.manager_peer().clone(),
        },
        credential_source: credential.source.clone(),
        credential_source_identity: credential.source_identity,
    })
}

fn validate_private_source(path: &Path) -> Result<((u64, u64), (u64, u64)), PodError> {
    let peer = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager identity unavailable"))?;
    let parent = path
        .parent()
        .ok_or(PodError::Refused("credential source has no directory"))?;
    let directory = fs::symlink_metadata(parent)
        .map_err(|_| PodError::Refused("credential directory unavailable"))?;
    let source = fs::symlink_metadata(path)
        .map_err(|_| PodError::Refused("credential source unavailable"))?;
    if !path.is_absolute()
        || !directory.is_dir()
        || directory.uid() != peer.uid()
        || directory.mode() & 0o077 != 0
        || directory.mode() & 0o100 == 0
        || fs::canonicalize(parent)
            .map_err(|_| PodError::Refused("credential directory unavailable"))?
            != parent
        || !source.is_file()
        || source.uid() != peer.uid()
        || source.mode() & 0o077 != 0
        || source.mode() & 0o400 == 0
        || source.nlink() != 1
        || source.len() == 0
        || source.len() > MAX_CREDENTIAL_SOURCE_BYTES
        || fs::canonicalize(path).map_err(|_| PodError::Refused("credential source unavailable"))?
            != path
    {
        return Err(PodError::Refused(
            "credential source is not private and canonical",
        ));
    }
    Ok((
        (source.dev(), source.ino()),
        (directory.dev(), directory.ino()),
    ))
}

fn sha256_file(path: &Path) -> Result<String, PodError> {
    let mut file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(PodError::Refused("executable is not a regular file"));
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 16_384];
    loop {
        let count = file.read(&mut chunk)?;
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

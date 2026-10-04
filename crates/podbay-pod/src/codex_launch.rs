//! Linux V2 Codex pod admission from an exact committed launch record.
//! The manifest is durable before systemd can start; ambiguity never retries.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podbay_store::{
    BoundLaunchFormat, BoundLaunchRecord, EffectState, LaunchDispatchStage, PodBayStore,
};
use podbay_wire::{
    EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2, NativeResourceKind, NativeRole,
    NativeWorkKind, ResourceDriver, TargetOs,
};
use sha2::{Digest, Sha256};

use crate::linux_peer::LinuxPeerEvidence;
use crate::manifest::{
    BoundPeerManifest, BoundPodStatus, CODEX_V2_CAPABILITY, LaunchDescriptor,
    PEER_BINDING_V2_PROTOCOL, PROTOCOL, PodError, PodManifest, PodPeerBootstrap, PodRole, hex,
    manifest_path, private_directory, read_manifest, unit_name, write_manifest,
};
use crate::runtime::PodClient;

const MAX_CREDENTIAL_BYTES: u64 = 1_048_576;
const MAX_STATUS_WAIT_SECONDS: u64 = 300;
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Starts only one already-claimed Codex V2 pod, using the private source
/// reviewed by Linux preflight. It never reads credential bytes. Existing
/// manifest state is inspected or reported uncertain, never launched again.
pub fn launch_bound_codex_v2(
    record: BoundLaunchRecord,
    bootstrap: PodPeerBootstrap,
    expected_authority_revision: u64,
    expected_store_file_identity: (u64, u64),
    directory: impl AsRef<Path>,
    pod_binary: impl AsRef<Path>,
    credential_source: impl AsRef<Path>,
    credential_source_identity: (u64, u64),
) -> Result<PodClient, PodError> {
    let directory = directory.as_ref();
    let pod_binary = pod_binary.as_ref();
    let credential_source = credential_source.as_ref();
    private_directory(directory)?;
    validate_pod_binary(pod_binary)?;

    let wire = ImmutableLaunchDescriptorV2::decode_json(&record.descriptor)
        .map_err(|_| PodError::Invalid("committed Codex V2 descriptor bytes"))?;
    let effective = EffectiveLaunchContractV2::decode(&record.effective_spec)
        .map_err(|_| PodError::Invalid("committed Codex V2 effective bytes"))?;
    effective
        .compare_with_descriptor(&wire)
        .map_err(|_| PodError::Invalid("committed Codex V2 launch differs"))?;
    let resource = wire
        .resource(0)
        .ok_or(PodError::Invalid("Codex V2 resource is missing"))?;
    let role = match (wire.role(), wire.work_kind()) {
        (NativeRole::Coordinator, NativeWorkKind::Service) => PodRole::Coordinator,
        (NativeRole::Worker, NativeWorkKind::Task) => PodRole::Worker,
        _ => return Err(PodError::Unsupported("Codex V2 root role is unavailable")),
    };
    if record.format != BoundLaunchFormat::CodexV2
        || record.scope_id != wire.scope_id()
        || record.session_id != wire.session_id()
        || record.run_id != wire.run_id()
        || record.attempt_id != wire.attempt_id()
        || record.pod_id != wire.pod_id()
        || record.pod_incarnation != wire.pod_incarnation()
        || wire.parent_run_id().is_some()
        || wire.target_os() != TargetOs::Linux
        || wire.resources_len() != 1
        || record.resources.len() != 1
        || record.resources[0].id != resource.resource_id
        || record.resources[0].epoch != resource.epoch
        || resource.kind != NativeResourceKind::StructuredProvider
        || !matches!(resource.driver, ResourceDriver::Structured { driver_ref, protocol_ref }
            if driver_ref == wire.codex_policy().driver_ref()
                && protocol_ref == wire.codex_policy().protocol_ref())
        || wire.arguments() != ["app-server", "--listen", "stdio://"]
        || wire.wall_seconds() == 0
        || bootstrap.resource_input_epochs.len() != 1
        || bootstrap.resource_input_epochs.get(resource.resource_id) != Some(&1)
        || bootstrap.canonical_executable != Path::new(wire.executable())
        || wire.executable_generation() != format!("sha256:{}", bootstrap.executable_sha256)
    {
        return Err(PodError::Unsupported(
            "Codex V2 launch is outside reviewed root shape",
        ));
    }
    let descriptor = LaunchDescriptor {
        protocol: PROTOCOL.into(),
        pod_id: wire.pod_id().into(),
        attempt_id: wire.attempt_id().into(),
        session_id: wire.session_id().into(),
        run_id: wire.run_id().into(),
        scope_id: wire.scope_id().into(),
        role,
        incarnation: wire.pod_incarnation(),
        resource_id: resource.resource_id.into(),
        executable: PathBuf::from(wire.executable()),
        args: wire.arguments().to_vec(),
        cwd: PathBuf::from(wire.cwd()),
        pty: None,
    };
    descriptor.validate()?;
    let manager = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager process identity unavailable"))?;
    let peer = manager.attested_peer();
    if peer != &bootstrap.expected_manager_peer {
        return Err(PodError::Refused(
            "manager peer changed before Codex V2 launch",
        ));
    }
    let mut bound = BoundPeerManifest {
        protocol: PEER_BINDING_V2_PROTOCOL.into(),
        capability: CODEX_V2_CAPABILITY.into(),
        wire_descriptor: record.descriptor.clone(),
        effective_spec: record.effective_spec.clone(),
        descriptor_digest: wire.digest().into(),
        effective_digest: effective.digest().into(),
        resource_epoch: resource.epoch,
        store_path: bootstrap.store_path.clone(),
        store_lineage: bootstrap.store_lineage.clone(),
        owner_epoch: bootstrap.owner_epoch,
        credential_epoch: bootstrap.credential_epoch,
        authority_revision: Some(expected_authority_revision),
        resource_input_epochs: bootstrap.resource_input_epochs.clone(),
        manager_os_identity: peer.os_identity().into(),
        manager_process_id: peer.native_process_id().into(),
        manager_boot_identity: peer.boot_identity().into(),
        manager_birth_identity: peer.birth_identity().into(),
        manager_containment: peer.containment_identity().into(),
        canonical_executable: bootstrap.canonical_executable.clone(),
        executable_sha256: bootstrap.executable_sha256.clone(),
        binding_digest: String::new(),
    };
    bound.binding_digest = bound.digest()?;
    bound.validate(&descriptor, directory)?;
    let expected_status = bound.status(resource.resource_id, wire.scope_id());
    let status_wait = readiness_wait(wire.wall_seconds())?;
    let path = manifest_path(directory, &descriptor)?;
    let source_text = credential_source
        .to_str()
        .filter(|value| {
            value.len() <= 4096 && !value.contains(':') && !value.chars().any(char::is_control)
        })
        .ok_or(PodError::Invalid("systemd credential source path"))?;

    recheck_store_file(&bootstrap.store_path, expected_store_file_identity)?;
    let mut store = PodBayStore::open(&bootstrap.store_path)
        .map_err(|_| PodError::Refused("committed store unavailable"))?;
    recheck_current_binding(
        &mut store,
        &record,
        &bound,
        peer,
        expected_authority_revision,
    )?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let existing = read_manifest(&path)
                .map_err(|_| PodError::Uncertain("existing Codex V2 manifest is unreadable"))?;
            if existing.descriptor != descriptor || existing.peer_binding.as_ref() != Some(&bound) {
                return Err(PodError::Uncertain(
                    "existing Codex V2 manifest differs; no replacement launched",
                ));
            }
            let client = PodClient::from_validated_manifest(&path, existing.clone())
                .map_err(|_| PodError::Uncertain("existing Codex V2 manifest identity changed"))?;
            wait_for_ready(status_wait, STATUS_POLL_INTERVAL, || {
                attest_running(&client, &expected_status)
            })?;
            final_acceptance_guards(
                &client,
                &path,
                &existing,
                &mut store,
                &record,
                &bound,
                peer,
                expected_authority_revision,
                expected_store_file_identity,
                credential_source,
                credential_source_identity,
                &expected_status,
            )
            .map_err(|_| PodError::Uncertain("existing Codex V2 final guards changed"))?;
            return Ok(client);
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(PodError::Uncertain("Codex V2 manifest state is unknown")),
    }

    recheck_credential_source(credential_source, credential_source_identity)?;
    let effect = store
        .load_effect(record.receipt.outbox_id, &record.scope_id, &record.pod_id)
        .map_err(|_| PodError::Refused("Codex V2 outbox unavailable"))?;
    let status = store
        .launch_dispatch_status(record.receipt.outbox_id, &record.scope_id, &record.pod_id)
        .map_err(|_| PodError::Refused("Codex V2 claim status unavailable"))?;
    let expected_claim = format!("claim.{}", record.receipt.command_id);
    if effect.state != EffectState::ClaimedUncertain
        || status.stage != LaunchDispatchStage::ClaimedUncertain
        || effect.kind != "pod.offer"
        || effect.command_id != record.receipt.command_id
        || effect.admission_target_epoch != record.pod_incarnation
        || effect.claim_key.as_deref() != Some(expected_claim.as_str())
        || effect.claim_owner_epoch != Some(bootstrap.owner_epoch)
        || effect.payload != record.descriptor
        || effect.effect_digest != sha256(&record.descriptor)
    {
        return Err(PodError::Refused(
            "Codex V2 outbox did not claim this launch",
        ));
    }
    let mut token = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut token)?;
    let manifest = PodManifest {
        digest: descriptor.digest()?,
        token: hex(&token),
        viewer_token: None,
        socket_path: path.with_extension("sock"),
        unit_name: unit_name(&path)?,
        descriptor,
        peer_binding: Some(bound.clone()),
    };
    if manifest.socket_path.as_os_str().len() > 100 {
        return Err(PodError::Invalid("Codex V2 socket path is too long"));
    }
    if serde_json::to_vec(&manifest)?.len() > 65_536 {
        return Err(PodError::Invalid(
            "Codex V2 manifest exceeds private file bound",
        ));
    }
    // A partial durable write is ambiguous. Never remove or replace the slot.
    write_manifest(&path, &manifest)
        .map_err(|_| PodError::Uncertain("Codex V2 manifest write did not settle"))?;
    // Validate the persisted manifest, including its large executable digest,
    // once. The pinned client checks only exact small file bytes and inode
    // during readiness polling; final acceptance performs one full recheck.
    let persisted = read_manifest(&path)
        .map_err(|_| PodError::Uncertain("Codex V2 persisted manifest is unavailable"))?;
    if serde_json::to_vec(&persisted)
        .map_err(|_| PodError::Uncertain("Codex V2 persisted manifest cannot encode"))?
        != serde_json::to_vec(&manifest)
            .map_err(|_| PodError::Uncertain("Codex V2 manifest cannot encode"))?
    {
        return Err(PodError::Uncertain("Codex V2 persisted manifest differs"));
    }
    let client = PodClient::from_validated_manifest(&path, persisted)
        .map_err(|_| PodError::Uncertain("Codex V2 persisted manifest identity changed"))?;
    recheck_credential_source(credential_source, credential_source_identity)
        .map_err(|_| PodError::Uncertain("Codex V2 credential changed after manifest write"))?;
    recheck_current_binding(
        &mut store,
        &record,
        &bound,
        peer,
        expected_authority_revision,
    )
    .map_err(|_| PodError::Uncertain("Codex V2 authority changed after manifest write"))?;
    recheck_store_file(&bootstrap.store_path, expected_store_file_identity)
        .map_err(|_| PodError::Uncertain("Codex V2 store file changed after manifest write"))?;
    let started = Command::new("systemd-run")
        .args([
            "--user",
            "--no-ask-password",
            "--collect",
            "--service-type=exec",
            "--property=KillMode=control-group",
            "--property=NoNewPrivileges=yes",
        ])
        .arg(format!("--property=RuntimeMaxSec={}s", wire.wall_seconds()))
        .arg(format!("--property=LoadCredential=auth.json:{source_text}"))
        .arg(format!("--unit={}", manifest.unit_name))
        .arg(pod_binary)
        .arg("serve")
        .arg("--manifest")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(started, Ok(status) if status.success()) {
        return Err(PodError::Uncertain(
            "systemd Codex V2 admission not attested; manifest retained",
        ));
    }
    wait_for_ready(status_wait, STATUS_POLL_INTERVAL, || {
        attest_running(&client, &expected_status)
    })?;
    final_acceptance_guards(
        &client,
        &path,
        &manifest,
        &mut store,
        &record,
        &bound,
        peer,
        expected_authority_revision,
        expected_store_file_identity,
        credential_source,
        credential_source_identity,
        &expected_status,
    )
    .map_err(|_| PodError::Uncertain("Codex V2 final guards changed; manifest retained"))?;
    Ok(client)
}

fn readiness_wait(wall_seconds: u64) -> Result<Duration, PodError> {
    if wall_seconds == 0 {
        return Err(PodError::Invalid("Codex V2 wall time is zero"));
    }
    Ok(Duration::from_secs(
        wall_seconds.min(MAX_STATUS_WAIT_SECONDS),
    ))
}

fn transient_readiness_error(error: &PodError) -> bool {
    matches!(error, PodError::Io(io) if matches!(
        io.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
    ))
}

fn wait_for_ready(
    wait: Duration,
    interval: Duration,
    mut probe: impl FnMut() -> Result<(), PodError>,
) -> Result<(), PodError> {
    let deadline = Instant::now() + wait;
    loop {
        match probe() {
            Ok(()) => return Ok(()),
            Err(error) if transient_readiness_error(&error) => {}
            Err(_) => {
                return Err(PodError::Uncertain(
                    "Codex V2 pod status differs; manifest retained",
                ));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(PodError::Uncertain(
                "Codex V2 pod status not attested; manifest retained",
            ));
        }
        std::thread::sleep(interval.min(deadline.saturating_duration_since(now)));
    }
}

#[allow(clippy::too_many_arguments)]
fn final_acceptance_guards(
    client: &PodClient,
    path: &Path,
    expected_manifest: &PodManifest,
    store: &mut PodBayStore,
    record: &BoundLaunchRecord,
    binding: &BoundPeerManifest,
    manager_peer: &podbay_core::AttestedPeer,
    expected_authority_revision: u64,
    expected_store_file_identity: (u64, u64),
    credential_source: &Path,
    credential_source_identity: (u64, u64),
    expected_status: &BoundPodStatus,
) -> Result<(), PodError> {
    let persisted = read_manifest(path)?;
    if serde_json::to_vec(&persisted)? != serde_json::to_vec(expected_manifest)? {
        return Err(PodError::Refused("Codex V2 final manifest differs"));
    }
    recheck_store_file(&binding.store_path, expected_store_file_identity)?;
    recheck_current_binding(
        store,
        record,
        binding,
        manager_peer,
        expected_authority_revision,
    )?;
    recheck_credential_source(credential_source, credential_source_identity)?;
    let manager = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager process identity unavailable"))?;
    if manager.attested_peer() != manager_peer {
        return Err(PodError::Refused("Codex V2 manager process changed"));
    }
    attest_running(client, expected_status)
}

fn recheck_current_binding(
    store: &mut PodBayStore,
    record: &BoundLaunchRecord,
    binding: &BoundPeerManifest,
    peer: &podbay_core::AttestedPeer,
    expected_authority_revision: u64,
) -> Result<(), PodError> {
    let claim = store
        .current_manager_credential_claim(binding.owner_epoch)
        .map_err(|_| PodError::Refused("current Codex V2 manager claim unavailable"))?;
    let current = store
        .current_bound_pod_snapshot(&record.scope_id, &record.pod_id)
        .map_err(|_| PodError::Refused("current Codex V2 launch unavailable"))?;
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
    if claim.store_lineage() != binding.store_lineage
        || claim.credential_epoch() != binding.credential_epoch
        || binding.authority_revision != Some(expected_authority_revision)
        || !store
            .current_manager_peer_matches(&claim, peer)
            .map_err(|_| PodError::Refused("current Codex V2 manager peer unavailable"))?
        || current.store_lineage().as_str() != binding.store_lineage
        || current.owner_epoch().get() != binding.owner_epoch
        || current.authority_revision() != expected_authority_revision
        || current.launch() != record
        || inputs != binding.resource_input_epochs
    {
        return Err(PodError::Refused("current Codex V2 authority changed"));
    }
    Ok(())
}

fn recheck_credential_source(path: &Path, expected: (u64, u64)) -> Result<(), PodError> {
    let peer = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("manager process identity unavailable"))?;
    let parent = path.parent().ok_or(PodError::Refused(
        "Codex V2 credential directory is missing",
    ))?;
    let directory = fs::symlink_metadata(parent)?;
    let source = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !directory.is_dir()
        || directory.uid() != peer.uid()
        || directory.mode() & 0o077 != 0
        || directory.mode() & 0o100 == 0
        || fs::canonicalize(parent)? != parent
        || !source.is_file()
        || source.uid() != peer.uid()
        || source.mode() & 0o077 != 0
        || source.mode() & 0o400 == 0
        || source.nlink() != 1
        || !(1..=MAX_CREDENTIAL_BYTES).contains(&source.len())
        || (source.dev(), source.ino()) != expected
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused("Codex V2 credential source changed"));
    }
    Ok(())
}

fn recheck_store_file(path: &Path, expected: (u64, u64)) -> Result<(), PodError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| PodError::Refused("Codex V2 committed store is unavailable"))?;
    if !path.is_absolute()
        || !metadata.is_file()
        || (metadata.dev(), metadata.ino()) != expected
        || fs::canonicalize(path)
            .map_err(|_| PodError::Refused("Codex V2 committed store is unavailable"))?
            != path
    {
        return Err(PodError::Refused("Codex V2 store file identity changed"));
    }
    Ok(())
}

fn validate_pod_binary(path: &Path) -> Result<(), PodError> {
    let binary = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !binary.is_file()
        || binary.mode() & 0o111 == 0
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Invalid(
            "Codex V2 pod binary is not canonical executable",
        ));
    }
    Ok(())
}

fn attest_running(client: &PodClient, expected: &BoundPodStatus) -> Result<(), PodError> {
    let status = client.attested_status()?;
    let final_status = client.attested_status()?;
    if !status.child_running
        || !final_status.child_running
        || status.bound.as_ref() != Some(expected)
        || final_status.bound.as_ref() != Some(expected)
        || status.supervisor_pid != final_status.supervisor_pid
        || status.supervisor_start_ticks != final_status.supervisor_start_ticks
        || status.child_pid != final_status.child_pid
        || status.child_start_ticks != final_status.child_start_ticks
    {
        return Err(PodError::Uncertain("Codex V2 status identity differs"));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_wait_uses_reviewed_wall_time_with_finite_ceiling() {
        assert_eq!(readiness_wait(120).unwrap(), Duration::from_secs(120));
        assert_eq!(readiness_wait(60).unwrap(), Duration::from_secs(60));
        assert_eq!(readiness_wait(86_400).unwrap(), Duration::from_secs(300));
        assert!(matches!(readiness_wait(0), Err(PodError::Invalid(_))));
    }

    #[test]
    fn slow_readiness_retries_connection_delay_but_refuses_identity_drift() {
        let mut attempts = 0;
        wait_for_ready(Duration::from_millis(250), Duration::from_millis(1), || {
            attempts += 1;
            if attempts < 5 {
                Err(PodError::Io(std::io::Error::from(
                    ErrorKind::ConnectionRefused,
                )))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 5);
        attempts = 0;
        assert!(matches!(
            wait_for_ready(Duration::from_millis(250), Duration::from_millis(1), || {
                attempts += 1;
                Err(PodError::Refused("pinned identity changed"))
            }),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(attempts, 1);
    }
}

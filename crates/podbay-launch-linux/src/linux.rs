use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use podbay_core::{
    AttemptId, CredentialEpoch, Epoch, InputEpoch, OwnerEpoch, PodFenceIdentity, PodId,
    RebindPhase, ResourceId, ScopeId, StoreLineageId,
};
use podbay_host::{
    AuthorisedBoundLaunch, AuthorisedDispatch, BootstrapNativeObservation, BootstrapNativeStage,
    BootstrapObservationError, CredentialRef, HostDispatchPort, PortDispatchError,
    PortDispatchOutcome, PortRebindObservation, PortReceiptRef, PreparedCodexV2Rebind,
    ResolvedClaimedBootstrap, ResolvedClaimedBootstrapInspection, ResolvedNativeCodexLaunch,
    ResolvedNativeLaunch,
};
use podbay_pod::{
    BootstrapControlStage, BoundPeerManifest, BoundPodStatus, CODEX_BOOTSTRAP_INSPECT_PROTOCOL,
    CODEX_V2_CAPABILITY, LinuxPeerEvidence, PodClient, PodError, PodManifest, PodPeerBootstrap,
    PodStatus, RebindInspection,
};
use podbay_store::{
    BootstrapSendSelector, BoundLaunchRecord, DurableRebindPhase, EffectState,
    HostObservedPriorCheckpoint, LaunchDispatchStage, NativeWriterTarget, PodBayStore,
};
use podbay_wire::{
    EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2, NativeResourceKind, NativeRole,
    NativeWorkKind, ResourceDriver, TargetOs,
};
use sha2::{Digest, Sha256};

use crate::codex_v2::{
    TrustedCodexCredentialSource, preflight_committed_codex_v2,
    preflight_committed_codex_v2_read_only,
};

/// Trusted host configuration for local Linux pod admission. Pinning is
/// cooperative and does not provide hostile same-UID isolation.
pub struct TrustedLinuxLaunchConfig {
    pod_binary: PathBuf,
    pod_sha256: String,
    directory: PathBuf,
    directory_identity: (u64, u64),
    binary_identity: (u64, u64),
}

impl TrustedLinuxLaunchConfig {
    pub fn from_trusted_policy(
        pod_binary: PathBuf,
        pod_sha256: String,
        directory: PathBuf,
    ) -> Result<Self, PodError> {
        let dir = fs::symlink_metadata(&directory)?;
        let bin = fs::symlink_metadata(&pod_binary)?;
        let result = Self {
            pod_binary,
            pod_sha256,
            directory,
            directory_identity: (dir.dev(), dir.ino()),
            binary_identity: (bin.dev(), bin.ino()),
        };
        result.recheck()?;
        Ok(result)
    }

    fn recheck(&self) -> Result<(), PodError> {
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("manager identity unavailable"))?;
        let dir = fs::symlink_metadata(&self.directory)?;
        let bin = fs::symlink_metadata(&self.pod_binary)?;
        if !self.directory.is_absolute()
            || fs::canonicalize(&self.directory)? != self.directory
            || !dir.is_dir()
            || dir.mode() & 0o077 != 0
            || dir.uid() != peer.uid()
            || (dir.dev(), dir.ino()) != self.directory_identity
            || !self.pod_binary.is_absolute()
            || fs::canonicalize(&self.pod_binary)? != self.pod_binary
            || !bin.is_file()
            || bin.mode() & 0o111 == 0
            || (bin.dev(), bin.ino()) != self.binary_identity
            || self.pod_sha256.len() != 64
            || !self
                .pod_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || sha256_file(&self.pod_binary)? != self.pod_sha256
        {
            return Err(PodError::Refused(
                "trusted pod executable or private directory changed",
            ));
        }
        Ok(())
    }
}

pub struct LinuxLaunchPort {
    config: TrustedLinuxLaunchConfig,
    codex_credentials: BTreeMap<CredentialRef, TrustedCodexCredentialSource>,
}

impl LinuxLaunchPort {
    pub fn new(config: TrustedLinuxLaunchConfig) -> Self {
        Self {
            config,
            codex_credentials: BTreeMap::new(),
        }
    }

    /// Register a private source under a trusted scope and vault locator.
    /// The resolved launch may select only this already-registered mapping.
    pub fn register_codex_credential_source_from_trusted_policy(
        &mut self,
        source: TrustedCodexCredentialSource,
    ) -> Result<(), PodError> {
        self.config.recheck()?;
        source.recheck()?;
        let reference = source.reference().clone();
        if self.codex_credentials.contains_key(&reference) {
            return Err(PodError::Conflict(
                "Codex credential source is already registered",
            ));
        }
        self.codex_credentials.insert(reference, source);
        Ok(())
    }

    fn preflight(&self, launch: &ResolvedNativeLaunch) -> Result<PodPeerBootstrap, PodError> {
        self.config.recheck()?;
        let committed = launch.committed();
        let wire = committed.descriptor();
        let effective = committed.effective();
        let record = committed.record();
        let resource = wire
            .resource(0)
            .ok_or(PodError::Unsupported("missing process resource"))?;
        if launch.cwd() != self.config.directory
            || wire.cwd() != self.config.directory.to_string_lossy()
            || wire.target_os() != TargetOs::Linux
            || wire.role() != NativeRole::Worker
            || wire.work_kind() != NativeWorkKind::Task
            || wire.parent_run_id().is_some()
            || wire.profile_ref() != "podbay.fixture.process.exec"
            || wire.model_id() != "none"
            || wire.reasoning_effort() != "none"
            || wire.resources_len() != 1
            || resource.kind != NativeResourceKind::Auxiliary
            || !matches!(resource.driver, ResourceDriver::Auxiliary{driver_ref} if driver_ref=="process.exec")
            || resource.epoch != 1
            || !wire.environment_refs().is_empty()
            || !wire.credential_refs().is_empty()
            || !effective.tool_bundle_refs().is_empty()
            || wire.max_children() != 0
            || wire.wall_seconds() != 60
            || wire.arguments() != ["60"]
            || launch.resource_input_epochs().len() != 1
            || launch.resource_input_epochs().get(resource.resource_id) != Some(&1)
            || launch.executable() != Path::new(wire.executable())
            || wire.executable_generation() != format!("sha256:{}", launch.executable_sha256())
            || sha256_file(launch.executable())? != launch.executable_sha256()
            || fs::canonicalize(launch.executable())? != launch.executable()
            || !launch.store_path().is_absolute()
            || fs::canonicalize(launch.store_path())? != launch.store_path()
        {
            return Err(PodError::Unsupported(
                "launch is outside synthetic process.exec policy",
            ));
        }
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("manager identity unavailable"))?;
        if peer.attested_peer() != launch.manager_peer() {
            return Err(PodError::Refused("manager process changed"));
        }
        let mut store = PodBayStore::open(launch.store_path())
            .map_err(|_| PodError::Refused("committed store unavailable"))?;
        let claim = store
            .current_manager_credential_claim(launch.owner_epoch())
            .map_err(|_| PodError::Refused("manager claim unavailable"))?;
        if claim.store_lineage() != launch.store_lineage()
            || claim.credential_epoch() != launch.credential_epoch()
        {
            return Err(PodError::Refused("manager claim changed"));
        }
        let effect = store
            .load_effect(launch.outbox_id(), &record.scope_id, &record.pod_id)
            .map_err(|_| PodError::Refused("committed outbox unavailable"))?;
        let expected_claim = format!("claim.{}", record.receipt.command_id);
        let status = store
            .launch_dispatch_status(launch.outbox_id(), &record.scope_id, &record.pod_id)
            .map_err(|_| PodError::Refused("committed outcome unavailable"))?;
        if effect.state != EffectState::ClaimedUncertain
            || status.stage != LaunchDispatchStage::ClaimedUncertain
            || effect.kind != "pod.offer"
            || effect.command_id != record.receipt.command_id
            || effect.admission_target_epoch != record.pod_incarnation
            || effect.claim_key.as_deref() != Some(expected_claim.as_str())
            || effect.claim_owner_epoch != Some(launch.owner_epoch())
            || effect.payload != launch.descriptor_bytes()
            || effect.effect_digest != sha256(launch.descriptor_bytes())
            || effective.canonical_bytes() != launch.effective_spec_bytes()
            || wire.effective_spec_digest() != sha256(launch.effective_spec_bytes())
        {
            return Err(PodError::Refused(
                "outbox does not authorize this exact claimed launch",
            ));
        }
        let snapshot = store
            .authority_snapshot()
            .map_err(|_| PodError::Refused("authority unavailable"))?;
        let resources = snapshot
            .resources
            .iter()
            .filter(|r| r.pod_id == record.pod_id)
            .collect::<Vec<_>>();
        if snapshot.owner_epoch != launch.owner_epoch()
            || resources.len() != 1
            || resources[0].scope_id != record.scope_id
            || resources[0].pod_incarnation != record.pod_incarnation
            || resources[0].resource_id != resource.resource_id
            || resources[0].resource_epoch != resource.epoch
            || launch
                .resource_input_epochs()
                .get(&resources[0].resource_id)
                != Some(&resources[0].input_epoch)
        {
            return Err(PodError::Refused("resource authority changed"));
        }
        Ok(PodPeerBootstrap {
            store_path: launch.store_path().to_path_buf(),
            store_lineage: launch.store_lineage().into(),
            owner_epoch: launch.owner_epoch(),
            credential_epoch: launch.credential_epoch(),
            resource_input_epochs: launch.resource_input_epochs().clone(),
            canonical_executable: launch.executable().to_path_buf(),
            executable_sha256: launch.executable_sha256().into(),
            expected_manager_peer: launch.manager_peer().clone(),
        })
    }

    fn launch_with(
        &mut self,
        launch: ResolvedNativeLaunch,
        run: impl FnOnce(
            BoundLaunchRecord,
            PodPeerBootstrap,
            &Path,
            &Path,
        ) -> Result<BoundPodStatus, PodError>,
    ) -> Result<PortDispatchOutcome<PortReceiptRef>, PortDispatchError> {
        let bootstrap = self
            .preflight(&launch)
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let wire = launch.committed().descriptor();
        let receipt = PortReceiptRef::from_port(&format!("podbay.launch.{}", wire.digest()))
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        // Once the pod adapter is entered, a manifest/unit may already exist.
        // All failures from that point preserve ambiguity and never retry.
        let status = run(
            launch.committed().record().clone(),
            bootstrap,
            &self.config.directory,
            &self.config.pod_binary,
        )
        .map_err(|_| PortDispatchError::UncertainAfterPossibleEffect {
            receipt_ref: Some(receipt.clone()),
        })?;
        let peer = launch.manager_peer();
        if status.capability != "synthetic_fixture_only"
            || status.descriptor_digest != wire.digest()
            || status.effective_digest != wire.effective_spec_digest()
            || status.resource_id != wire.resource_id(0).unwrap_or("")
            || status.resource_epoch != 1
            || status.scope_id != wire.scope_id()
            || status.store_lineage != launch.store_lineage()
            || status.owner_epoch != launch.owner_epoch()
            || status.credential_epoch != launch.credential_epoch()
            || status.manager_os_identity != peer.os_identity()
            || status.manager_process_id != peer.native_process_id()
            || status.manager_boot_identity != peer.boot_identity()
            || status.manager_birth_identity != peer.birth_identity()
            || status.manager_containment != peer.containment_identity()
        {
            return Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            });
        }
        Ok(PortDispatchOutcome::Accepted(receipt))
    }

    fn launch_codex_v2(
        &mut self,
        launch: ResolvedNativeCodexLaunch,
    ) -> Result<PortDispatchOutcome<PortReceiptRef>, PortDispatchError> {
        self.config
            .recheck()
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let wire = launch.descriptor();
        let policy = launch.effective().codex_policy();
        if policy.credential_scope() != wire.scope_id() {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let scope = ScopeId::try_from(wire.scope_id())
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let reference = CredentialRef::from_trusted_vault(scope, policy.credential_ref())
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let source = self
            .codex_credentials
            .get(&reference)
            .ok_or(PortDispatchError::RefusedBeforeEffect)?;
        let reviewed = preflight_committed_codex_v2(&launch, source)
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        self.config
            .recheck()
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let receipt = PortReceiptRef::from_port(&format!("podbay.launch.{}", wire.digest()))
            .map_err(|_| PortDispatchError::RefusedBeforeEffect)?;
        let expected_resource = wire
            .resource(0)
            .ok_or(PortDispatchError::RefusedBeforeEffect)?;
        let expected_digest = launch.effective().digest();
        let expected_peer = launch.manager_peer().clone();
        // The pod adapter can find an existing manifest or create one. Every
        // failure after entry therefore preserves uncertain admission.
        let client = podbay_pod::launch_bound_codex_v2(
            launch.committed_record().clone(),
            reviewed.bootstrap().clone(),
            launch.authority_revision(),
            launch.store_file_identity(),
            &self.config.directory,
            &self.config.pod_binary,
            reviewed.credential_source(),
            reviewed.credential_source_identity(),
        )
        .map_err(|_| PortDispatchError::UncertainAfterPossibleEffect {
            receipt_ref: Some(receipt.clone()),
        })?;
        let observed = client.attested_status().map_err(|_| {
            PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt.clone()),
            }
        })?;
        let final_observed = client.attested_status().map_err(|_| {
            PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt.clone()),
            }
        })?;
        let bound = observed.bound.as_ref().ok_or_else(|| {
            PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt.clone()),
            }
        })?;
        if !observed.child_running
            || !final_observed.child_running
            || final_observed.bound.as_ref() != Some(bound)
            || observed.supervisor_pid != final_observed.supervisor_pid
            || observed.supervisor_start_ticks != final_observed.supervisor_start_ticks
            || observed.child_pid != final_observed.child_pid
            || observed.child_start_ticks != final_observed.child_start_ticks
            || observed.boot_id != final_observed.boot_id
            || observed.cgroup_path != final_observed.cgroup_path
            || observed.unit_name != final_observed.unit_name
            || bound.capability != CODEX_V2_CAPABILITY
            || bound.descriptor_digest != wire.digest()
            || bound.effective_digest != expected_digest
            || bound.resource_id != expected_resource.resource_id
            || bound.resource_epoch != expected_resource.epoch
            || bound.scope_id != wire.scope_id()
            || bound.store_lineage != launch.store_lineage()
            || bound.owner_epoch != launch.owner_epoch()
            || bound.credential_epoch != launch.credential_epoch()
            || bound.manager_os_identity != expected_peer.os_identity()
            || bound.manager_process_id != expected_peer.native_process_id()
            || bound.manager_boot_identity != expected_peer.boot_identity()
            || bound.manager_birth_identity != expected_peer.birth_identity()
            || bound.manager_containment != expected_peer.containment_identity()
        {
            return Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            });
        }
        Ok(PortDispatchOutcome::Accepted(receipt))
    }

    /// One already-claimed send. Everything before PodClient's selector-only
    /// call is read-only; once that call begins, any ambiguous result keeps
    /// the original command uncertain and the port never retries it.
    fn send_claimed_bootstrap(
        &mut self,
        claimed: ResolvedClaimedBootstrap,
    ) -> Result<PortDispatchOutcome<PortReceiptRef>, PortDispatchError> {
        let selector = claimed.selector();
        let target = &selector.native_target;
        fn refused<E>(_: E) -> PortDispatchError {
            PortDispatchError::RefusedBeforeEffect
        }
        self.config.recheck().map_err(refused)?;
        if selector.scope_id != target.scope_id || claimed.writer_epoch() == 0 {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let receipt = PortReceiptRef::from_port(&format!(
            "podbay.bootstrap.{}",
            selector.command_id.as_str()
        ))
        .map_err(refused)?;
        let uncertain = || PortDispatchError::UncertainAfterPossibleEffect {
            receipt_ref: Some(receipt.clone()),
        };
        let manager = LinuxPeerEvidence::for_current_process().map_err(refused)?;
        let database_identity =
            checked_store_file(claimed.store_path(), manager.uid()).map_err(refused)?;
        if database_identity != claimed.store_file_identity() {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let incarnation = Epoch::new(target.pod_incarnation).map_err(refused)?;
        let manifest_path = podbay_pod::manifest_path_for_identity(
            &self.config.directory,
            &target.pod_id,
            &target.attempt_id,
            incarnation,
        );
        let manifest_meta = fs::symlink_metadata(&manifest_path).map_err(refused)?;
        if !manifest_meta.is_file()
            || manifest_meta.nlink() != 1
            || manifest_meta.uid() != manager.uid()
            || manifest_meta.mode() & 0o077 != 0
            || manifest_meta.len() == 0
            || manifest_meta.len() > 1_048_576
            || fs::canonicalize(&manifest_path).map_err(refused)? != manifest_path
        {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let manifest: PodManifest =
            serde_json::from_slice(&fs::read(&manifest_path).map_err(refused)?).map_err(refused)?;
        let binding = podbay_pod::current_bound_peer_binding(&manifest_path).map_err(refused)?;
        if binding.capability != CODEX_V2_CAPABILITY
            || binding.protocol != "podbay.peer-binding/2"
            || binding.store_path != claimed.store_path()
            || binding.store_lineage != target.store_lineage.as_str()
            || binding.owner_epoch != claimed.owner_epoch()
            || binding.credential_epoch != claimed.manager_credential_epoch()
            || binding.authority_revision != Some(claimed.authority_revision())
            || binding.resource_epoch != target.resource_epoch
            || binding.resource_input_epochs.len() != 1
            || binding
                .resource_input_epochs
                .get(target.resource_id.as_str())
                != Some(&target.resource_input_epoch)
            || manifest.descriptor.scope_id != target.scope_id.as_str()
            || manifest.descriptor.session_id != target.session_id.as_str()
            || manifest.descriptor.run_id != target.run_id.as_str()
            || manifest.descriptor.attempt_id != target.attempt_id.as_str()
            || manifest.descriptor.pod_id != target.pod_id.as_str()
            || manifest.descriptor.incarnation != target.pod_incarnation
            || manifest.descriptor.resource_id != target.resource_id.as_str()
            || manifest.descriptor.pty.is_some()
        {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let mut store =
            PodBayStore::open_existing_read_only(claimed.store_path()).map_err(refused)?;
        let proof = store
            .inspect_claimed_bootstrap_send(selector)
            .map_err(refused)?;
        let lease = store.inspect_native_writer_lease(target).map_err(refused)?;
        let current = store
            .current_bound_pod_snapshot(target.scope_id.as_str(), target.pod_id.as_str())
            .map_err(refused)?;
        let manager_claim = store
            .current_manager_credential_claim(claimed.owner_epoch())
            .map_err(refused)?;
        if proof.receipt().command_id != selector.command_id.as_str()
            || proof.native_target() != target
            || proof.writer_epoch() != claimed.writer_epoch()
            || proof.owner_epoch() != claimed.owner_epoch()
            || proof.manager_credential_epoch() != claimed.manager_credential_epoch()
            || proof.authority_revision() != claimed.authority_revision()
            || lease.writer_epoch() != proof.writer_epoch()
            || lease.target() != target
            || lease.holder_actor_id() != proof.holder_actor_id()
            || lease.holder_credential_generation() != proof.holder_credential_generation()
            || lease.expires_at_unix_seconds() != proof.lease_expires_at_unix_seconds()
            || current.store_lineage() != &target.store_lineage
            || current.owner_epoch().get() != claimed.owner_epoch()
            || current.authority_revision() != claimed.authority_revision()
            || current.launch().session_id != target.session_id.as_str()
            || current.launch().run_id != target.run_id.as_str()
            || current.launch().attempt_id != target.attempt_id.as_str()
            || current.launch().descriptor != binding.wire_descriptor
            || current.launch().effective_spec != binding.effective_spec
            || manager_claim.store_lineage() != target.store_lineage.as_str()
            || manager_claim.credential_epoch() != claimed.manager_credential_epoch()
            || !store
                .current_manager_peer_matches(&manager_claim, manager.attested_peer())
                .map_err(refused)?
            || binding.manager_os_identity != manager.attested_peer().os_identity()
            || binding.manager_process_id != manager.attested_peer().native_process_id()
            || binding.manager_boot_identity != manager.attested_peer().boot_identity()
            || binding.manager_birth_identity != manager.attested_peer().birth_identity()
            || binding.manager_containment != manager.attested_peer().containment_identity()
        {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let client = PodClient::connect(&manifest_path).map_err(refused)?;
        let before = client.attested_status().map_err(refused)?;
        if !bootstrap_status_matches(&before, target, &claimed, &manifest) {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        self.config.recheck().map_err(refused)?;
        if checked_store_file(claimed.store_path(), manager.uid()).map_err(refused)?
            != claimed.store_file_identity()
            || fs::symlink_metadata(&manifest_path).map_err(refused)?.ino() != manifest_meta.ino()
        {
            return Err(PortDispatchError::RefusedBeforeEffect);
        }
        let response = client
            .submit_claimed_codex_bootstrap(&selector.command_id, target, claimed.writer_epoch())
            .map_err(|_| uncertain())?;
        // The pod may have started a native effect even when its reply was
        // Refused or incomplete. Reattest the same supervisor and child before
        // trusting a typed stage, while never making a second send call.
        let after = client.attested_status().map_err(|_| uncertain())?;
        if !bootstrap_status_matches(&after, target, &claimed, &manifest)
            || after.supervisor_pid != before.supervisor_pid
            || after.supervisor_start_ticks != before.supervisor_start_ticks
            || after.child_pid != before.child_pid
            || after.child_start_ticks != before.child_start_ticks
            || after.boot_id != before.boot_id
            || after.cgroup_path != before.cgroup_path
            || self.config.recheck().is_err()
            || !LinuxPeerEvidence::for_current_process()
                .is_ok_and(|peer| peer.attested_peer() == manager.attested_peer())
            || fs::symlink_metadata(&manifest_path)
                .ok()
                .map(|metadata| (metadata.dev(), metadata.ino()))
                != Some((manifest_meta.dev(), manifest_meta.ino()))
            || checked_store_file(claimed.store_path(), manager.uid()).map_err(|_| uncertain())?
                != claimed.store_file_identity()
            || response
                .request_digest
                .as_deref()
                .is_some_and(|digest| digest != proof.receipt().request_digest)
        {
            return Err(uncertain());
        }
        bootstrap_port_stage(response.stage, receipt)
    }

    /// Read one already-claimed command's held pod journal. No claim, native
    /// input, or retry is possible through this path.
    fn inspect_claimed_bootstrap(
        &self,
        inspection: ResolvedClaimedBootstrapInspection,
    ) -> Result<BootstrapNativeObservation, BootstrapObservationError> {
        use BootstrapObservationError::{Invalid, Unavailable};

        self.config.recheck().map_err(|_| Unavailable)?;
        let selector = inspection.selector();
        let target = &selector.native_target;
        if selector.scope_id != target.scope_id || inspection.writer_epoch() == 0 {
            return Err(Invalid);
        }
        let manager = LinuxPeerEvidence::for_current_process().map_err(|_| Unavailable)?;
        if checked_store_file(inspection.store_path(), manager.uid()).map_err(|_| Unavailable)?
            != inspection.store_file_identity()
        {
            return Err(Invalid);
        }
        let incarnation = Epoch::new(target.pod_incarnation).map_err(|_| Invalid)?;
        let manifest_path = podbay_pod::manifest_path_for_identity(
            &self.config.directory,
            &target.pod_id,
            &target.attempt_id,
            incarnation,
        );
        let manifest_meta = fs::symlink_metadata(&manifest_path).map_err(|_| Unavailable)?;
        let manifest_identity = (manifest_meta.dev(), manifest_meta.ino());
        if !manifest_meta.is_file()
            || manifest_meta.nlink() != 1
            || manifest_meta.uid() != manager.uid()
            || manifest_meta.mode() & 0o077 != 0
            || manifest_meta.len() == 0
            || manifest_meta.len() > 1_048_576
            || fs::canonicalize(&manifest_path).map_err(|_| Unavailable)? != manifest_path
        {
            return Err(Invalid);
        }
        let manifest: PodManifest =
            serde_json::from_slice(&fs::read(&manifest_path).map_err(|_| Unavailable)?)
                .map_err(|_| Invalid)?;
        let binding =
            podbay_pod::current_bound_peer_binding(&manifest_path).map_err(|_| Invalid)?;
        let wire = ImmutableLaunchDescriptorV2::decode_json(&binding.wire_descriptor)
            .map_err(|_| Invalid)?;
        let effective =
            EffectiveLaunchContractV2::decode(&binding.effective_spec).map_err(|_| Invalid)?;
        if binding.capability != CODEX_V2_CAPABILITY
            || binding.protocol != "podbay.peer-binding/2"
            || binding.store_path != inspection.store_path()
            || binding.store_lineage != target.store_lineage.as_str()
            || binding.owner_epoch != inspection.owner_epoch()
            || binding.credential_epoch != inspection.manager_credential_epoch()
            || binding.authority_revision != Some(inspection.authority_revision())
            || binding.resource_epoch != target.resource_epoch
            || binding.resource_input_epochs.len() != 1
            || binding
                .resource_input_epochs
                .get(target.resource_id.as_str())
                != Some(&target.resource_input_epoch)
            || manifest.descriptor.scope_id != target.scope_id.as_str()
            || manifest.descriptor.session_id != target.session_id.as_str()
            || manifest.descriptor.run_id != target.run_id.as_str()
            || manifest.descriptor.attempt_id != target.attempt_id.as_str()
            || manifest.descriptor.pod_id != target.pod_id.as_str()
            || manifest.descriptor.incarnation != target.pod_incarnation
            || manifest.descriptor.resource_id != target.resource_id.as_str()
            || manifest.descriptor.pty.is_some()
            || binding.descriptor_digest != wire.digest()
            || binding.effective_digest != effective.digest()
            || binding.manager_os_identity != manager.attested_peer().os_identity()
            || binding.manager_process_id != manager.attested_peer().native_process_id()
            || binding.manager_boot_identity != manager.attested_peer().boot_identity()
            || binding.manager_birth_identity != manager.attested_peer().birth_identity()
            || binding.manager_containment != manager.attested_peer().containment_identity()
        {
            return Err(Invalid);
        }

        let mut store = PodBayStore::open_existing_read_only(inspection.store_path())
            .map_err(|_| Unavailable)?;
        check_inspection_store(&mut store, &inspection, &binding, &manager)?;
        let client = PodClient::connect(&manifest_path).map_err(|_| Unavailable)?;
        let before = client.attested_status().map_err(|_| Unavailable)?;
        if !inspection_status_matches(&before, target, &manifest, &binding) {
            return Err(Invalid);
        }
        self.config.recheck().map_err(|_| Unavailable)?;
        let fresh_manifest_meta = fs::symlink_metadata(&manifest_path).map_err(|_| Unavailable)?;
        if checked_store_file(inspection.store_path(), manager.uid()).map_err(|_| Unavailable)?
            != inspection.store_file_identity()
            || (fresh_manifest_meta.dev(), fresh_manifest_meta.ino()) != manifest_identity
        {
            return Err(Invalid);
        }
        check_inspection_store(&mut store, &inspection, &binding, &manager)?;
        let response = client
            .inspect_claimed_codex_bootstrap(
                &selector.command_id,
                target,
                inspection.writer_epoch(),
            )
            .map_err(|_| Unavailable)?;
        let after = client.attested_status().map_err(|_| Unavailable)?;
        if !inspection_status_matches(&after, target, &manifest, &binding)
            || after.supervisor_pid != before.supervisor_pid
            || after.supervisor_start_ticks != before.supervisor_start_ticks
            || after.child_pid != before.child_pid
            || after.child_start_ticks != before.child_start_ticks
            || after.boot_id != before.boot_id
            || after.cgroup_path != before.cgroup_path
            || after.unit_name != before.unit_name
            || self.config.recheck().is_err()
            || !LinuxPeerEvidence::for_current_process()
                .is_ok_and(|peer| peer.attested_peer() == manager.attested_peer())
            || fs::symlink_metadata(&manifest_path)
                .ok()
                .map(|metadata| (metadata.dev(), metadata.ino()))
                != Some(manifest_identity)
            || checked_store_file(inspection.store_path(), manager.uid())
                .map_err(|_| Unavailable)?
                != inspection.store_file_identity()
        {
            return Err(Invalid);
        }
        check_inspection_store(&mut store, &inspection, &binding, &manager)?;
        if response.request_digest.as_deref() != Some(inspection.expected_request_digest()) {
            return Err(Invalid);
        }
        let stage = match response.stage {
            BootstrapControlStage::ClaimedUnobserved => BootstrapNativeStage::ClaimedUnobserved,
            BootstrapControlStage::ThreadCreateUncertain => {
                BootstrapNativeStage::ThreadCreateUncertain
            }
            BootstrapControlStage::ThreadCreated {
                native_thread_id,
                native_session_id,
            } => BootstrapNativeStage::ThreadCreated {
                native_thread_id,
                native_session_id,
            },
            BootstrapControlStage::BootstrapUncertain {
                native_thread_id,
                native_session_id,
            } => BootstrapNativeStage::BootstrapUncertain {
                native_thread_id,
                native_session_id,
            },
            BootstrapControlStage::Submitted {
                native_thread_id,
                native_session_id,
                native_turn_id,
            } => BootstrapNativeStage::Submitted {
                native_thread_id,
                native_session_id,
                native_turn_id,
            },
            BootstrapControlStage::RefusedBeforeEffect => return Err(Invalid),
        };
        BootstrapNativeObservation::from_attested_pod(
            CODEX_BOOTSTRAP_INSPECT_PROTOCOL,
            selector.clone(),
            inspection.writer_epoch(),
            inspection.expected_request_digest().into(),
            stage,
        )
    }
}

fn bootstrap_port_stage(
    stage: BootstrapControlStage,
    receipt: PortReceiptRef,
) -> Result<PortDispatchOutcome<PortReceiptRef>, PortDispatchError> {
    match stage {
        BootstrapControlStage::Submitted { .. } => Ok(PortDispatchOutcome::Accepted(receipt)),
        BootstrapControlStage::RefusedBeforeEffect => Err(PortDispatchError::RefusedBeforeEffect),
        BootstrapControlStage::ClaimedUnobserved
        | BootstrapControlStage::ThreadCreateUncertain
        | BootstrapControlStage::ThreadCreated { .. }
        | BootstrapControlStage::BootstrapUncertain { .. } => {
            Err(PortDispatchError::UncertainAfterPossibleEffect {
                receipt_ref: Some(receipt),
            })
        }
    }
}

impl HostDispatchPort for LinuxLaunchPort {
    type Receipt = PortReceiptRef;
    fn dispatch(
        &mut self,
        _: AuthorisedDispatch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
    fn launch_bound(
        &mut self,
        _: AuthorisedBoundLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        Err(PortDispatchError::RefusedBeforeEffect)
    }
    fn accepts_resolved_native_launch(&self) -> bool {
        true
    }
    fn launch_resolved(
        &mut self,
        launch: ResolvedNativeLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.launch_with(launch, |record, bootstrap, directory, binary| {
            let client = podbay_pod::launch_bound(record, bootstrap, directory, binary)?;
            client.bound_status()
        })
    }

    fn accepts_resolved_codex_v2(&self) -> bool {
        !self.codex_credentials.is_empty() && self.config.recheck().is_ok()
    }

    fn launch_resolved_codex_v2(
        &mut self,
        launch: ResolvedNativeCodexLaunch,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.launch_codex_v2(launch)
    }

    fn inspect_existing_codex_v2_rebind(
        &self,
        launch: &ResolvedNativeCodexLaunch,
    ) -> Result<PortRebindObservation, podbay_host::HostError> {
        self.inspect_codex_v2_rebind(launch)
            .map_err(|_| podbay_host::HostError::StaleGuard)
    }

    fn prepare_existing_codex_v2_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
    ) -> Result<String, podbay_host::HostError> {
        let path = self
            .recheck_prepared_rebind(prepared, DurableRebindPhase::Pending, None)
            .map_err(|_| podbay_host::HostError::StaleGuard)?;
        let digest = PodClient::prepare_rebind(
            &path,
            prepared.proposal(),
            prepared.prior_checkpoint_digest(),
        )
        .map_err(|_| podbay_host::HostError::UncertainAfterPossibleEffect {
            command_key: prepared.proposal().command_key.as_str().into(),
            receipt_ref: None,
        })?;
        self.recheck_prepared_rebind(prepared, DurableRebindPhase::Pending, None)
            .map_err(|_| podbay_host::HostError::UncertainAfterPossibleEffect {
                command_key: prepared.proposal().command_key.as_str().into(),
                receipt_ref: None,
            })?;
        Ok(digest)
    }

    fn activate_existing_codex_v2_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
        pending_checkpoint_digest: &str,
    ) -> Result<String, podbay_host::HostError> {
        let path = self
            .recheck_prepared_rebind(
                prepared,
                DurableRebindPhase::Activated,
                Some(pending_checkpoint_digest),
            )
            .map_err(|_| podbay_host::HostError::StaleGuard)?;
        let digest = PodClient::activate_rebind(
            &path,
            prepared.proposal(),
            prepared.prior_checkpoint_digest(),
            pending_checkpoint_digest,
        )
        .map_err(|_| podbay_host::HostError::UncertainAfterPossibleEffect {
            command_key: prepared.proposal().command_key.as_str().into(),
            receipt_ref: None,
        })?;
        self.recheck_prepared_rebind(
            prepared,
            DurableRebindPhase::Activated,
            Some(pending_checkpoint_digest),
        )
        .map_err(|_| podbay_host::HostError::UncertainAfterPossibleEffect {
            command_key: prepared.proposal().command_key.as_str().into(),
            receipt_ref: None,
        })?;
        Ok(digest)
    }

    fn accepts_claimed_codex_bootstrap(&self) -> bool {
        self.config.recheck().is_ok()
    }

    fn send_claimed_codex_bootstrap(
        &mut self,
        claimed: ResolvedClaimedBootstrap,
    ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
        self.send_claimed_bootstrap(claimed)
    }

    fn inspect_claimed_codex_bootstrap(
        &self,
        inspection: ResolvedClaimedBootstrapInspection,
    ) -> Result<BootstrapNativeObservation, BootstrapObservationError> {
        self.inspect_claimed_bootstrap(inspection)
    }
}

fn check_inspection_store(
    store: &mut PodBayStore,
    inspection: &ResolvedClaimedBootstrapInspection,
    binding: &BoundPeerManifest,
    manager: &LinuxPeerEvidence,
) -> Result<(), BootstrapObservationError> {
    use BootstrapObservationError::{Invalid, Unavailable};
    let selector: &BootstrapSendSelector = inspection.selector();
    let target = &selector.native_target;
    let proof = store
        .inspect_claimed_bootstrap_send(selector)
        .map_err(|_| Unavailable)?;
    let lease = store
        .inspect_native_writer_lease(target)
        .map_err(|_| Unavailable)?;
    let current = store
        .current_bound_pod_snapshot(target.scope_id.as_str(), target.pod_id.as_str())
        .map_err(|_| Unavailable)?;
    let manager_claim = store
        .current_manager_credential_claim(inspection.owner_epoch())
        .map_err(|_| Unavailable)?;
    if proof.receipt().command_id != selector.command_id.as_str()
        || proof.receipt().request_digest != inspection.expected_request_digest()
        || proof.native_target() != target
        || proof.writer_epoch() != inspection.writer_epoch()
        || proof.owner_epoch() != inspection.owner_epoch()
        || proof.manager_credential_epoch() != inspection.manager_credential_epoch()
        || proof.authority_revision() != inspection.authority_revision()
        || lease.writer_epoch() != proof.writer_epoch()
        || lease.target() != target
        || lease.holder_actor_id() != proof.holder_actor_id()
        || lease.holder_credential_generation() != proof.holder_credential_generation()
        || lease.expires_at_unix_seconds() != proof.lease_expires_at_unix_seconds()
        || current.store_lineage() != &target.store_lineage
        || current.owner_epoch().get() != inspection.owner_epoch()
        || current.authority_revision() != inspection.authority_revision()
        || current.launch().session_id != target.session_id.as_str()
        || current.launch().run_id != target.run_id.as_str()
        || current.launch().attempt_id != target.attempt_id.as_str()
        || current.launch().descriptor != binding.wire_descriptor
        || current.launch().effective_spec != binding.effective_spec
        || manager_claim.store_lineage() != target.store_lineage.as_str()
        || manager_claim.credential_epoch() != inspection.manager_credential_epoch()
        || !store
            .current_manager_peer_matches(&manager_claim, manager.attested_peer())
            .map_err(|_| Unavailable)?
    {
        return Err(Invalid);
    }
    Ok(())
}

fn inspection_status_matches(
    status: &PodStatus,
    target: &NativeWriterTarget,
    manifest: &PodManifest,
    binding: &BoundPeerManifest,
) -> bool {
    status.pod_id == target.pod_id.as_str()
        && status.attempt_id == target.attempt_id.as_str()
        && status.incarnation == target.pod_incarnation
        && status.manifest_digest == manifest.digest
        && status.unit_name == manifest.unit_name
        && status.bound.as_ref()
            == Some(&binding.status(target.resource_id.as_str(), target.scope_id.as_str()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RebindProcessEvidence {
    ppid: u32,
    start_ticks: u64,
    cgroup: String,
    uid: u32,
    gid: u32,
}

fn read_bounded_proc(path: &Path) -> Result<String, PodError> {
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref().take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(PodError::Refused("V2 rebind proc evidence exceeds bound"));
    }
    String::from_utf8(bytes).map_err(|_| PodError::Refused("V2 rebind proc evidence is malformed"))
}

fn read_rebind_manifest_bytes(path: &Path) -> Result<Vec<u8>, PodError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(1_048_577)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(PodError::Refused("V2 rebind manifest exceeds bound"));
    }
    Ok(bytes)
}

fn parse_rebind_stat(text: &str, expected_pid: u32) -> Result<(char, u32, u64), PodError> {
    let close = text
        .rfind(") ")
        .ok_or(PodError::Refused("V2 rebind proc stat is malformed"))?;
    let prefix = &text[..close];
    let (pid, _) = prefix
        .split_once(" (")
        .ok_or(PodError::Refused("V2 rebind proc stat is malformed"))?;
    if pid.parse::<u32>().ok() != Some(expected_pid) {
        return Err(PodError::Refused("V2 rebind proc PID changed"));
    }
    let fields = text[close + 2..].split_whitespace().collect::<Vec<_>>();
    let state = fields
        .first()
        .and_then(|value| value.chars().next())
        .ok_or(PodError::Refused("V2 rebind proc state is missing"))?;
    let ppid = fields
        .get(1)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(PodError::Refused("V2 rebind proc parent is malformed"))?;
    let start_ticks = fields
        .get(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(PodError::Refused("V2 rebind proc birth is malformed"))?;
    if matches!(state, 'Z' | 'X' | 'x') {
        return Err(PodError::Refused("V2 rebind process has exited"));
    }
    Ok((state, ppid, start_ticks))
}

fn parse_rebind_status(text: &str) -> Result<(u32, u32), PodError> {
    let mut state = None;
    let mut uid = None;
    let mut gid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("State:") {
            if state
                .replace(
                    value
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.chars().next()),
                )
                .is_some()
            {
                return Err(PodError::Refused("V2 rebind duplicate proc state"));
            }
        } else if let Some(value) = line.strip_prefix("Uid:") {
            if uid
                .replace(
                    value
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u32>().ok()),
                )
                .is_some()
            {
                return Err(PodError::Refused("V2 rebind duplicate proc UID"));
            }
        } else if let Some(value) = line.strip_prefix("Gid:") {
            if gid
                .replace(
                    value
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u32>().ok()),
                )
                .is_some()
            {
                return Err(PodError::Refused("V2 rebind duplicate proc GID"));
            }
        }
    }
    if state
        .flatten()
        .is_none_or(|value| matches!(value, 'Z' | 'X' | 'x'))
    {
        return Err(PodError::Refused("V2 rebind proc state is not live"));
    }
    Ok((
        uid.flatten()
            .ok_or(PodError::Refused("V2 rebind proc UID is missing"))?,
        gid.flatten()
            .ok_or(PodError::Refused("V2 rebind proc GID is missing"))?,
    ))
}

fn read_rebind_process(pid: u32) -> Result<RebindProcessEvidence, PodError> {
    if pid == 0 {
        return Err(PodError::Refused("V2 rebind process PID is zero"));
    }
    let root = PathBuf::from(format!("/proc/{pid}"));
    let first = parse_rebind_stat(&read_bounded_proc(&root.join("stat"))?, pid)?;
    let status = parse_rebind_status(&read_bounded_proc(&root.join("status"))?)?;
    let cgroup_text = read_bounded_proc(&root.join("cgroup"))?;
    let mut cgroups = cgroup_text.lines();
    let cgroup = cgroups
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/') && !path.chars().any(char::is_control))
        .ok_or(PodError::Refused("V2 rebind process cgroup is malformed"))?;
    if cgroups.next().is_some() {
        return Err(PodError::Refused("V2 rebind process cgroup is ambiguous"));
    }
    let second = parse_rebind_stat(&read_bounded_proc(&root.join("stat"))?, pid)?;
    if first.1 != second.1 || first.2 != second.2 {
        return Err(PodError::Refused("V2 rebind process birth changed"));
    }
    Ok(RebindProcessEvidence {
        ppid: first.1,
        start_ticks: first.2,
        cgroup: cgroup.to_owned(),
        uid: status.0,
        gid: status.1,
    })
}

fn attest_rebind_process_pair(
    response: &RebindInspection,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), PodError> {
    let boot = read_bounded_proc(Path::new("/proc/sys/kernel/random/boot_id"))?;
    if boot.trim() != response.boot_id {
        return Err(PodError::Refused("V2 rebind boot identity changed"));
    }
    let supervisor = read_rebind_process(response.supervisor_pid)?;
    let child = read_rebind_process(response.child_pid)?;
    if supervisor.start_ticks != response.supervisor_start_ticks
        || child.start_ticks != response.child_start_ticks
        || child.ppid != response.supervisor_pid
        || supervisor.cgroup != response.cgroup_path
        || child.cgroup != response.cgroup_path
        || supervisor.uid != expected_uid
        || supervisor.gid != expected_gid
        || child.uid != expected_uid
        || child.gid != expected_gid
        || read_rebind_process(response.supervisor_pid)? != supervisor
        || read_rebind_process(response.child_pid)? != child
        || read_bounded_proc(Path::new("/proc/sys/kernel/random/boot_id"))?.trim()
            != response.boot_id
    {
        return Err(PodError::Refused("V2 rebind process tree changed"));
    }
    Ok(())
}

fn attest_rebind_systemd_unit(
    unit: &str,
    supervisor_pid: u32,
    expected_cgroup: &str,
) -> Result<(), PodError> {
    if !unit.starts_with("podbay-pod-")
        || !unit.ends_with(".service")
        || unit.len() > 96
        || !unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(PodError::Refused("V2 rebind unit name is invalid"));
    }
    let mut query = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ControlGroup",
            unit,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = query.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = query.kill();
            let _ = query.wait();
            return Err(PodError::Refused("V2 rebind unit query timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = query
        .stdout
        .take()
        .ok_or(PodError::Refused("V2 rebind unit query lost stdout"))?;
    let mut bytes = Vec::new();
    stdout.take(4097).read_to_end(&mut bytes)?;
    if !status.success() || bytes.len() > 4096 {
        return Err(PodError::Refused("V2 rebind unit query failed"));
    }
    let response = String::from_utf8(bytes)
        .map_err(|_| PodError::Refused("V2 rebind unit response is malformed"))?;
    parse_rebind_systemd_unit(&response, supervisor_pid, expected_cgroup)
}

fn parse_rebind_systemd_unit(
    response: &str,
    supervisor_pid: u32,
    expected_cgroup: &str,
) -> Result<(), PodError> {
    let mut active = None;
    let mut pid = None;
    let mut cgroup = None;
    for line in response.lines() {
        if let Some(value) = line.strip_prefix("ActiveState=") {
            if active.replace(value).is_some() {
                return Err(PodError::Refused("V2 rebind duplicate unit state"));
            }
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            if pid.replace(value.parse::<u32>().ok()).is_some() {
                return Err(PodError::Refused("V2 rebind duplicate unit PID"));
            }
        } else if let Some(value) = line.strip_prefix("ControlGroup=") {
            if cgroup.replace(value).is_some() {
                return Err(PodError::Refused("V2 rebind duplicate unit cgroup"));
            }
        } else if !line.is_empty() {
            return Err(PodError::Refused(
                "V2 rebind unit response has unknown field",
            ));
        }
    }
    if active != Some("active")
        || pid.flatten() != Some(supervisor_pid)
        || cgroup != Some(expected_cgroup)
    {
        return Err(PodError::Refused("V2 rebind systemd unit differs"));
    }
    Ok(())
}

fn checked_store_file(path: &Path, expected_uid: u32) -> Result<(u64, u64), PodError> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != expected_uid
        || fs::canonicalize(path)? != path
    {
        return Err(PodError::Refused("claimed bootstrap store file changed"));
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn bootstrap_status_matches(
    status: &PodStatus,
    target: &NativeWriterTarget,
    claimed: &ResolvedClaimedBootstrap,
    manifest: &PodManifest,
) -> bool {
    let Some(bound) = status.bound.as_ref() else {
        return false;
    };
    status.child_running
        && status.pod_id == target.pod_id.as_str()
        && status.attempt_id == target.attempt_id.as_str()
        && status.incarnation == target.pod_incarnation
        && status.manifest_digest == manifest.digest
        && bound.capability == CODEX_V2_CAPABILITY
        && bound.scope_id == target.scope_id.as_str()
        && bound.resource_id == target.resource_id.as_str()
        && bound.resource_epoch == target.resource_epoch
        && bound.store_lineage == target.store_lineage.as_str()
        && bound.owner_epoch == claimed.owner_epoch()
        && bound.credential_epoch == claimed.manager_credential_epoch()
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

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Observation returned only by a live, bidirectionally attested inspect
/// exchange through this adapter. No public constructor, Clone or Deserialize
/// is provided. It is a point-in-time observation, not a grant or admission;
/// a future prepare operation must recheck its borrowed manager context.
pub struct VerifiedRebindInspection {
    prior: podbay_store::HostObservedPriorCheckpoint,
    store_path: PathBuf,
    owner_epoch: u64,
    credential_epoch: u64,
    manager_peer: podbay_core::AttestedPeer,
    input_epochs: std::collections::BTreeMap<podbay_core::ResourceId, podbay_core::InputEpoch>,
    authority_revision: u64,
    descriptor_digest: String,
    nonce: String,
    child_pid: u32,
    child_start_ticks: u64,
}

impl VerifiedRebindInspection {
    /// Diagnostic data only. Copying this DTO does not create another verified
    /// observation, and no adapter API accepts a DTO in place of this value.
    pub fn prior_checkpoint(&self) -> &podbay_store::HostObservedPriorCheckpoint {
        &self.prior
    }
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn credential_epoch(&self) -> u64 {
        self.credential_epoch
    }
    pub fn manager_peer(&self) -> &podbay_core::AttestedPeer {
        &self.manager_peer
    }
    pub fn resource_input_epochs(
        &self,
    ) -> &std::collections::BTreeMap<podbay_core::ResourceId, podbay_core::InputEpoch> {
        &self.input_epochs
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn child_pid(&self) -> u32 {
        self.child_pid
    }
    pub fn child_start_ticks(&self) -> u64 {
        self.child_start_ticks
    }
}

impl LinuxLaunchPort {
    fn recheck_prepared_rebind(
        &self,
        prepared: &PreparedCodexV2Rebind,
        phase: DurableRebindPhase,
        checkpoint_ref: Option<&str>,
    ) -> Result<PathBuf, PodError> {
        self.config.recheck()?;
        let manager = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("rebind manager OS identity unavailable"))?;
        if manager.attested_peer() != prepared.manager_peer()
            || checked_store_file(prepared.store_path(), manager.uid())?
                != prepared.store_file_identity()
        {
            return Err(PodError::Refused("rebind manager store path changed"));
        }
        let proposal = prepared.proposal();
        let mut store = PodBayStore::open_existing_read_only(prepared.store_path())
            .map_err(|_| PodError::Refused("rebind store unavailable"))?;
        let claim = store
            .current_manager_credential_claim(proposal.next_owner_epoch.get())
            .map_err(|_| PodError::Refused("rebind manager claim unavailable"))?;
        let current = store
            .current_bound_pod_snapshot(
                proposal.identity.scope_id.as_str(),
                proposal.identity.pod_id.as_str(),
            )
            .map_err(|_| PodError::Refused("rebind Pod binding unavailable"))?;
        let readback = store
            .lookup_prior_observed_rebind(proposal)
            .map_err(|_| PodError::Refused("rebind Pending proof unavailable"))?
            .ok_or(PodError::Refused("rebind Pending row absent"))?;
        let current_inputs = current
            .resources()
            .iter()
            .map(|resource| (resource.id().clone(), resource.input_epoch()))
            .collect::<BTreeMap<_, _>>();
        if claim.store_lineage() != proposal.identity.store_lineage.as_str()
            || claim.credential_epoch() != proposal.next_credential_epoch.get()
            || !store
                .current_manager_peer_matches(&claim, manager.attested_peer())
                .map_err(|_| PodError::Refused("rebind manager peer unavailable"))?
            || current.owner_epoch().get() != proposal.next_owner_epoch.get()
            || current.authority_revision() != prepared.authority_revision()
            || current.launch() != prepared.record()
            || current_inputs != proposal.next_input_epochs
            || readback.receipt.phase != phase
            || readback.receipt.pod_checkpoint_ref.as_deref() != checkpoint_ref
        {
            return Err(PodError::Refused("rebind destination or Pod changed"));
        }
        let path = podbay_pod::manifest_path_for_identity(
            &self.config.directory,
            &proposal.identity.pod_id,
            &proposal.identity.attempt_id,
            proposal.identity.incarnation,
        );
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != manager.uid()
            || metadata.mode() & 0o077 != 0
            || fs::canonicalize(&path)? != path
        {
            return Err(PodError::Refused("rebind manifest path changed"));
        }
        let manifest: PodManifest = serde_json::from_slice(&read_rebind_manifest_bytes(&path)?)?;
        let binding = manifest
            .peer_binding
            .as_ref()
            .ok_or(PodError::Refused("rebind manifest lacks V2 binding"))?;
        if binding.protocol != "podbay.peer-binding/2"
            || binding.capability != CODEX_V2_CAPABILITY
            || binding.wire_descriptor != prepared.record().descriptor
            || binding.effective_spec != prepared.record().effective_spec
            || binding.store_path != prepared.store_path()
            || binding.store_lineage != proposal.identity.store_lineage.as_str()
            || manifest.descriptor.pod_id != proposal.identity.pod_id.as_str()
            || manifest.descriptor.attempt_id != proposal.identity.attempt_id.as_str()
            || manifest.descriptor.incarnation != proposal.identity.incarnation.get()
        {
            return Err(PodError::Refused("rebind manifest immutable bytes differ"));
        }
        Ok(path)
    }

    /// Read-only V2 inspection used only by the host's Pending preparation.
    /// The committed profile and private credential locator are revalidated,
    /// but no credential bytes, old bearer, pod control or provider input are
    /// used. `PodClient::inspect_rebind` authenticates the connected supervisor
    /// through SO_PEERCRED and procfs; this port independently checks its
    /// direct child and the exact unit cgroup before returning.
    fn inspect_codex_v2_rebind(
        &self,
        launch: &ResolvedNativeCodexLaunch,
    ) -> Result<PortRebindObservation, PodError> {
        self.config.recheck()?;
        let record = launch.committed_record();
        let wire = launch.descriptor();
        let policy = launch.effective().codex_policy();
        if policy.credential_scope() != wire.scope_id() {
            return Err(PodError::Refused("V2 rebind credential scope differs"));
        }
        let scope =
            ScopeId::try_from(wire.scope_id()).map_err(|_| PodError::Invalid("V2 rebind scope"))?;
        let reference = CredentialRef::from_trusted_vault(scope.clone(), policy.credential_ref())
            .map_err(|_| PodError::Refused("V2 rebind credential mapping is absent"))?;
        let source = self
            .codex_credentials
            .get(&reference)
            .ok_or(PodError::Refused("V2 rebind credential source is absent"))?;
        preflight_committed_codex_v2_read_only(launch, source)?;
        let manager = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("manager process unavailable"))?;
        if manager.attested_peer() != launch.manager_peer()
            || checked_store_file(launch.store_path(), manager.uid())?
                != launch.store_file_identity()
        {
            return Err(PodError::Refused("V2 rebind manager or store changed"));
        }
        let identity = PodFenceIdentity {
            scope_id: scope,
            pod_id: PodId::try_from(record.pod_id.as_str())
                .map_err(|_| PodError::Invalid("V2 rebind Pod ID"))?,
            attempt_id: AttemptId::try_from(record.attempt_id.as_str())
                .map_err(|_| PodError::Invalid("V2 rebind Attempt ID"))?,
            incarnation: Epoch::new(record.pod_incarnation)
                .map_err(|_| PodError::Invalid("V2 rebind Pod incarnation"))?,
            store_lineage: StoreLineageId::try_from(launch.store_lineage())
                .map_err(|_| PodError::Invalid("V2 rebind lineage"))?,
        };
        let manifest_path = podbay_pod::manifest_path_for_identity(
            &self.config.directory,
            &identity.pod_id,
            &identity.attempt_id,
            identity.incarnation,
        );
        let manifest_meta = fs::symlink_metadata(&manifest_path)?;
        if !manifest_meta.is_file()
            || manifest_meta.nlink() != 1
            || manifest_meta.uid() != manager.uid()
            || manifest_meta.mode() & 0o077 != 0
            || !(1..=1_048_576).contains(&manifest_meta.len())
            || fs::canonicalize(&manifest_path)? != manifest_path
        {
            return Err(PodError::Refused("V2 rebind manifest identity differs"));
        }
        let manifest_bytes = read_rebind_manifest_bytes(&manifest_path)?;
        let manifest: PodManifest = serde_json::from_slice(&manifest_bytes)?;
        let binding = manifest
            .peer_binding
            .as_ref()
            .ok_or(PodError::Refused("V2 rebind manifest is unbound"))?;
        let expected_unit = format!(
            "podbay-pod-{}.service",
            manifest_path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or(PodError::Invalid("V2 rebind manifest slot"))?
        );
        let resource = wire
            .resource(0)
            .ok_or(PodError::Refused("V2 rebind Resource is absent"))?;
        if binding.protocol != "podbay.peer-binding/2"
            || binding.capability != CODEX_V2_CAPABILITY
            || binding.wire_descriptor != launch.descriptor_bytes()
            || binding.effective_spec != launch.effective_spec_bytes()
            || binding.descriptor_digest != wire.digest()
            || binding.effective_digest != launch.effective().digest()
            || binding.resource_epoch != resource.epoch
            || binding.store_path != launch.store_path()
            || binding.store_lineage != launch.store_lineage()
            || binding.canonical_executable != launch.executable()
            || binding.executable_sha256 != launch.executable_sha256()
            || manifest.unit_name != expected_unit
            || manifest.descriptor.scope_id != record.scope_id
            || manifest.descriptor.session_id != record.session_id
            || manifest.descriptor.run_id != record.run_id
            || manifest.descriptor.attempt_id != record.attempt_id
            || manifest.descriptor.pod_id != record.pod_id
            || manifest.descriptor.incarnation != record.pod_incarnation
            || manifest.descriptor.resource_id != resource.resource_id
            || manifest.descriptor.pty.is_some()
        {
            return Err(PodError::Refused(
                "V2 rebind manifest differs from committed launch",
            ));
        }
        let response = PodClient::inspect_rebind(
            &manifest_path,
            &identity,
            launch.owner_epoch(),
            launch.credential_epoch(),
        )?;
        if response.unit_name != expected_unit
            || response.cgroup_path.rsplit('/').next() != Some(expected_unit.as_str())
            || response.boot_id != manager.boot_id()
            || response.prior_owner_epoch == 0
            || response.prior_owner_epoch >= launch.owner_epoch()
            || response.prior_credential_epoch == 0
            || response.prior_credential_epoch >= launch.credential_epoch()
            || response.prior_input_epochs.len() != launch.resource_input_epochs().len()
        {
            return Err(PodError::Refused("V2 rebind checkpoint differs"));
        }
        let mut prior_inputs = BTreeMap::new();
        for (id, next) in launch.resource_input_epochs() {
            let old = response
                .prior_input_epochs
                .get(id)
                .ok_or(PodError::Refused("V2 rebind Resource set differs"))?;
            if *old == 0 || *old >= *next {
                return Err(PodError::Refused("V2 rebind input epoch did not advance"));
            }
            prior_inputs.insert(
                ResourceId::try_from(id.as_str())
                    .map_err(|_| PodError::Invalid("V2 rebind Resource ID"))?,
                InputEpoch::new(*old)
                    .map_err(|_| PodError::Invalid("V2 rebind prior input epoch"))?,
            );
        }
        attest_rebind_process_pair(&response, manager.uid(), manager.gid())?;
        attest_rebind_systemd_unit(
            &response.unit_name,
            response.supervisor_pid,
            &response.cgroup_path,
        )?;
        self.config.recheck()?;
        preflight_committed_codex_v2_read_only(launch, source)?;
        let final_meta = fs::symlink_metadata(&manifest_path)?;
        if (final_meta.dev(), final_meta.ino()) != (manifest_meta.dev(), manifest_meta.ino())
            || read_rebind_manifest_bytes(&manifest_path)? != manifest_bytes
            || !LinuxPeerEvidence::for_current_process().is_ok_and(|peer| peer == manager)
        {
            return Err(PodError::Refused("V2 rebind manifest or manager changed"));
        }
        attest_rebind_process_pair(&response, manager.uid(), manager.gid())?;
        attest_rebind_systemd_unit(
            &response.unit_name,
            response.supervisor_pid,
            &response.cgroup_path,
        )?;
        let prior = HostObservedPriorCheckpoint {
            identity,
            phase: RebindPhase::Active,
            owner_epoch: OwnerEpoch::new(response.prior_owner_epoch)
                .map_err(|_| PodError::Invalid("V2 rebind prior owner"))?,
            credential_epoch: CredentialEpoch::new(response.prior_credential_epoch)
                .map_err(|_| PodError::Invalid("V2 rebind prior credential"))?,
            input_epochs: prior_inputs,
            checkpoint_digest: response.checkpoint_digest,
            supervisor_pid: response.supervisor_pid,
            supervisor_start_ticks: response.supervisor_start_ticks,
            boot_id: response.boot_id,
            unit_name: response.unit_name,
            cgroup_path: response.cgroup_path,
        };
        PortRebindObservation::from_trusted_port(
            prior,
            wire.digest().to_owned(),
            response.child_pid,
            response.child_start_ticks,
        )
        .map_err(|_| PodError::Refused("V2 rebind port observation is invalid"))
    }

    /// Inspect an already-running pod without its old bearer. The path comes
    /// only from trusted adapter configuration and store-derived identities.
    /// This method performs no launch, rebind preparation or authority write.
    pub fn inspect_existing(
        &self,
        context: &mut podbay_host::ManagerRebindContext<'_>,
    ) -> Result<VerifiedRebindInspection, PodError> {
        self.inspect_with(context, |path, identity, owner, credential| {
            podbay_pod::PodClient::inspect_rebind(path, identity, owner, credential)
        })
    }

    // A private seam for deterministic validation tests. Production supplies
    // only PodClient::inspect_rebind; callers cannot inject an inspection DTO.
    fn inspect_with(
        &self,
        context: &mut podbay_host::ManagerRebindContext<'_>,
        inspect: impl FnOnce(
            &Path,
            &podbay_core::PodFenceIdentity,
            u64,
            u64,
        ) -> Result<podbay_pod::RebindInspection, PodError>,
    ) -> Result<VerifiedRebindInspection, PodError> {
        self.config.recheck()?;
        context
            .recheck_current()
            .map_err(|_| PodError::Refused("manager rebind context changed"))?;
        let wire =
            podbay_wire::ImmutableLaunchDescriptor::decode_json(&context.launch().descriptor)
                .map_err(|_| PodError::Refused("committed rebind descriptor is malformed"))?;
        let identity = context.identity();
        if wire.scope_id() != identity.scope_id.as_str()
            || wire.pod_id() != identity.pod_id.as_str()
            || wire.attempt_id() != identity.attempt_id.as_str()
            || wire.pod_incarnation() != identity.incarnation.get()
            || wire.cwd() != self.config.directory.to_string_lossy()
            || identity.store_lineage.as_str() != context.store_lineage()
        {
            return Err(PodError::Refused(
                "trusted rebind directory or identity differs",
            ));
        }
        let manifest = podbay_pod::manifest_path_for_identity(
            &self.config.directory,
            &identity.pod_id,
            &identity.attempt_id,
            identity.incarnation,
        );
        let response = inspect(
            &manifest,
            identity,
            context.owner_epoch(),
            context.credential_epoch(),
        )?;
        self.config.recheck()?;
        context
            .recheck_current()
            .map_err(|_| PodError::Refused("manager rebind context changed during inspect"))?;
        let identity = context.identity();
        let expected_unit = format!(
            "podbay-pod-{}.service",
            manifest
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or(PodError::Invalid("rebind manifest slot"))?
        );
        if response.protocol != "podbay.rebind-inspect/1"
            || response.scope_id != identity.scope_id.as_str()
            || response.pod_id != identity.pod_id.as_str()
            || response.attempt_id != identity.attempt_id.as_str()
            || response.incarnation != identity.incarnation.get()
            || response.store_lineage != context.store_lineage()
            || response.prior_owner_epoch == 0
            || response.prior_owner_epoch >= context.owner_epoch()
            || response.prior_credential_epoch == 0
            || response.prior_credential_epoch >= context.credential_epoch()
            || response.prior_input_epochs.len() != context.resource_input_epochs().len()
            || response.prior_input_epochs.is_empty()
            || response.checkpoint_digest.len() != 64
            || !response
                .checkpoint_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || response.nonce.len() != 64
            || !response
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || response.supervisor_pid == 0
            || response.supervisor_start_ticks == 0
            || response.child_pid == 0
            || response.child_start_ticks == 0
            || response.unit_name != expected_unit
            || !response.cgroup_path.starts_with('/')
            || response.cgroup_path.rsplit('/').next() != Some(expected_unit.as_str())
            || response.cgroup_path.chars().any(char::is_control)
            || format!("linux.boot.{}", response.boot_id) != context.manager_peer().boot_identity()
        {
            return Err(PodError::Refused(
                "inspection does not match current manager context",
            ));
        }
        let mut prior_inputs = std::collections::BTreeMap::new();
        for (id, current) in context.resource_input_epochs() {
            let prior = response
                .prior_input_epochs
                .get(id.as_str())
                .ok_or(PodError::Refused("inspection resource set differs"))?;
            if *prior == 0 || *prior >= current.get() {
                return Err(PodError::Refused(
                    "inspection resource input did not advance",
                ));
            }
            prior_inputs.insert(
                id.clone(),
                podbay_core::InputEpoch::new(*prior)
                    .map_err(|_| PodError::Invalid("prior input epoch"))?,
            );
        }
        let prior = podbay_store::HostObservedPriorCheckpoint {
            identity: identity.clone(),
            phase: podbay_core::RebindPhase::Active,
            owner_epoch: podbay_core::OwnerEpoch::new(response.prior_owner_epoch)
                .map_err(|_| PodError::Invalid("prior owner epoch"))?,
            credential_epoch: podbay_core::CredentialEpoch::new(response.prior_credential_epoch)
                .map_err(|_| PodError::Invalid("prior credential epoch"))?,
            input_epochs: prior_inputs,
            checkpoint_digest: response.checkpoint_digest,
            supervisor_pid: response.supervisor_pid,
            supervisor_start_ticks: response.supervisor_start_ticks,
            boot_id: response.boot_id,
            unit_name: response.unit_name,
            cgroup_path: response.cgroup_path,
        };
        Ok(VerifiedRebindInspection {
            prior,
            store_path: context.store_path().to_path_buf(),
            owner_epoch: context.owner_epoch(),
            credential_epoch: context.credential_epoch(),
            manager_peer: context.manager_peer().clone(),
            input_epochs: context.resource_input_epochs().clone(),
            authority_revision: context.authority_revision(),
            descriptor_digest: wire.digest().into(),
            nonce: response.nonce,
            child_pid: response.child_pid,
            child_start_ticks: response.child_start_ticks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podbay_core::*;
    use podbay_host::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Clone, Copy)]
    enum Mode {
        Good,
        LostReply,
        WrongStatus,
        SettledOutbox,
        Native,
    }
    struct HarnessPort {
        inner: LinuxLaunchPort,
        mode: Mode,
        calls: Arc<AtomicUsize>,
    }
    impl HostDispatchPort for HarnessPort {
        type Receipt = PortReceiptRef;
        fn dispatch(
            &mut self,
            _: AuthorisedDispatch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            Err(PortDispatchError::RefusedBeforeEffect)
        }
        fn launch_bound(
            &mut self,
            _: AuthorisedBoundLaunch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            panic!("unbound fallback")
        }
        fn accepts_resolved_native_launch(&self) -> bool {
            true
        }
        fn launch_resolved(
            &mut self,
            launch: ResolvedNativeLaunch,
        ) -> Result<PortDispatchOutcome<Self::Receipt>, PortDispatchError> {
            if matches!(self.mode, Mode::Native) {
                return self.inner.launch_resolved(launch);
            }
            if matches!(self.mode, Mode::SettledOutbox) {
                let mut store = PodBayStore::open(launch.store_path()).unwrap();
                let r = launch.committed().record();
                store
                    .record_launch_port_result(
                        launch.outbox_id(),
                        &r.scope_id,
                        &r.pod_id,
                        launch.owner_epoch(),
                        &format!("claim.{}", r.receipt.command_id),
                        podbay_store::LaunchPortResult::RefusedBeforeEffect,
                    )
                    .unwrap();
            }
            let calls = self.calls.clone();
            let mode = self.mode;
            let expected_descriptor = launch.descriptor_bytes().to_vec();
            let expected_effective = launch.effective_spec_bytes().to_vec();
            let expected_peer = launch.manager_peer().clone();
            self.inner
                .launch_with(launch, move |record, bootstrap, directory, binary| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(record.descriptor, expected_descriptor);
                    assert_eq!(record.effective_spec, expected_effective);
                    assert_eq!(bootstrap.expected_manager_peer, expected_peer);
                    assert_eq!(bootstrap.resource_input_epochs.len(), 1);
                    assert!(directory.is_absolute() && binary.is_absolute());
                    if matches!(mode, Mode::LostReply) {
                        return Err(PodError::Uncertain("simulated lost reply"));
                    }
                    let wire =
                        podbay_wire::ImmutableLaunchDescriptor::decode_json(&record.descriptor)
                            .unwrap();
                    let peer = &bootstrap.expected_manager_peer;
                    let mut status = BoundPodStatus {
                        capability: "synthetic_fixture_only".into(),
                        descriptor_digest: wire.digest().into(),
                        effective_digest: wire.effective_spec_digest().into(),
                        resource_id: record.resources[0].id.clone(),
                        resource_epoch: 1,
                        scope_id: record.scope_id,
                        store_lineage: bootstrap.store_lineage,
                        owner_epoch: bootstrap.owner_epoch,
                        credential_epoch: bootstrap.credential_epoch,
                        manager_os_identity: peer.os_identity().into(),
                        manager_process_id: peer.native_process_id().into(),
                        manager_boot_identity: peer.boot_identity().into(),
                        manager_birth_identity: peer.birth_identity().into(),
                        manager_containment: peer.containment_identity().into(),
                    };
                    if matches!(mode, Mode::WrongStatus) {
                        status.descriptor_digest = "0".repeat(64);
                    }
                    Ok(status)
                })
        }
    }
    #[derive(Clone)]
    struct Transport(AuthenticatedPeer);
    impl AuthenticatedTransport for Transport {
        fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
            Ok(self.0.clone())
        }
    }
    struct Fixture {
        directory: PathBuf,
        native: bool,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.native {
                if let Ok(entries) = fs::read_dir(&self.directory) {
                    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
                        if path.extension().is_some_and(|ext| ext == "json") {
                            if let Some(stem) = path.file_stem().and_then(|value| value.to_str()) {
                                if stem.len() == 32 && stem.bytes().all(|b| b.is_ascii_hexdigit()) {
                                    let _ = std::process::Command::new("systemctl")
                                        .args([
                                            "--user",
                                            "stop",
                                            &format!("podbay-pod-{stem}.service"),
                                        ])
                                        .stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null())
                                        .status();
                                }
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    struct Admitted;
    impl CommandAdmission for Admitted {
        fn admits_run(&self, _: &CommandId, _: &RunId, kind: RunCommandKind) -> bool {
            kind == RunCommandKind::Launch
        }
    }

    fn setup(
        mode: Mode,
        pod_binary: PathBuf,
    ) -> (
        Fixture,
        DurableAuthority<HarnessPort>,
        Transport,
        BoundLaunchPodRequest,
        Arc<AtomicUsize>,
    ) {
        let directory = std::env::temp_dir().join(format!(
            "pb-launch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let binary = fs::canonicalize(pod_binary).unwrap();
        let config = TrustedLinuxLaunchConfig::from_trusted_policy(
            binary.clone(),
            sha256_file(&binary).unwrap(),
            directory.clone(),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut host = DurableAuthority::open(
            directory.join("store.sqlite"),
            HarnessPort {
                inner: LinuxLaunchPort::new(config),
                mode,
                calls: calls.clone(),
            },
        )
        .unwrap();
        let scope = ScopeId::try_from("scope.synthetic").unwrap();
        let actor = ActorId::try_from("actor.synthetic").unwrap();
        let pod_id = PodId::try_from("pod.synthetic").unwrap();
        let process = AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
            1000, 4242, 777, "/fixture",
        )
        .unwrap();
        let transport = Transport(AuthenticatedPeer::owner_cli_from_authenticated_transport(
            process.clone(),
            CredentialGeneration::new(1).unwrap(),
        ));
        host.register_actor_from_trusted_policy(ActorRegistration::owner_cli_from_trusted_policy(
            actor.clone(),
            scope.clone(),
            process,
            CredentialGeneration::new(1).unwrap(),
        ))
        .unwrap();
        let grant = host
            .install_grant_from_trusted_policy(
                &actor,
                GrantSpec {
                    scope_id: scope.clone(),
                    mode: GrantMode::Controller,
                    rights: BTreeSet::from([Right::new(
                        Operation::LaunchPod,
                        Target::Pod(pod_id.clone()),
                    )]),
                    remaining_delegation_depth: 0,
                },
            )
            .unwrap();
        let executable = fs::canonicalize("/bin/sleep").unwrap();
        let executable_sha256 = sha256_file(&executable).unwrap();
        host.register_launch_profile_from_trusted_policy(
            RegisteredLaunchProfile::from_trusted_policy(TrustedLaunchProfileInput {
                profile_ref: "podbay.fixture.process.exec".into(),
                profile_generation: 1,
                executable: executable.to_string_lossy().into_owned(),
                binary_generation: format!("sha256:{executable_sha256}"),
                executable_sha256,
                workspace_root: directory.clone(),
                resource_layout: vec![TrustedDriverTemplate {
                    kind: ResourceKind::Auxiliary,
                    driver: ResourceDriver::Auxiliary {
                        driver_ref: "process.exec".into(),
                    },
                }],
                execution_mode: ExecutionMode::LinuxCooperative,
                fixed_arguments: vec!["60".into()],
                permitted_extra_arguments: BTreeSet::new(),
                default_model: "none".into(),
                allowed_models: BTreeSet::from(["none".into()]),
                default_effort: "none".into(),
                allowed_efforts: BTreeSet::from(["none".into()]),
                workspace_scope: scope.clone(),
                workspace_basis_ref: "basis.synthetic".into(),
                allowed_cwd_prefix: ".".into(),
                allow_write: true,
                allowed_tool_bundle_refs: BTreeSet::new(),
                environment_refs: vec![],
                credential_refs: vec![],
                max_wall_seconds: 60,
                max_children: 0,
                allow_fallback: false,
            })
            .unwrap(),
        )
        .unwrap();
        host.register_native_host_from_trusted_policy(
            TrustedNativeHostConfig::for_compiled_backend("host.synthetic".into())
                .unwrap()
                .with_auxiliary_driver("process.exec".into())
                .unwrap(),
        )
        .unwrap();
        let mut session = Session::new(
            SessionId::try_from("session.synthetic").unwrap(),
            actor,
            scope.clone(),
        );
        let mut run = Run::new(
            RunId::try_from("run.synthetic").unwrap(),
            &session,
            Role::Worker,
            WorkKind::Task,
            None,
        );
        run.admit(
            run.revision(),
            &CommandId::try_from("command.synthetic").unwrap(),
            &Admitted,
        )
        .unwrap();
        session.bind_run(session.revision(), &run).unwrap();
        let mut attempt = Attempt::new(
            AttemptId::try_from("attempt.synthetic").unwrap(),
            run.id().clone(),
            1,
            Epoch::new(1).unwrap(),
        )
        .unwrap();
        run.start_attempt(run.revision(), &attempt).unwrap();
        let mut pod = Pod::new(pod_id.clone(), attempt.id().clone(), Epoch::new(1).unwrap());
        attempt.attach_pod(attempt.revision(), &pod).unwrap();
        let resource = Resource::new(
            ResourceId::try_from("resource.synthetic").unwrap(),
            pod_id.clone(),
            ResourceKind::Auxiliary,
            Epoch::new(1).unwrap(),
        );
        pod.attach_resource(pod.revision(), &resource).unwrap();
        let binding =
            LaunchBinding::from_aggregates(&session, &run, &attempt, &pod, &[resource]).unwrap();
        let request = BoundLaunchPodRequest {
            host_request: HostRequest {
                scope_id: scope.clone(),
                grant_id: grant,
                guards: GuardSet {
                    manager_epoch: ManagerEpoch::new(1).unwrap(),
                    pod_incarnation: PodIncarnation::new(1).unwrap(),
                    resource_epoch: None,
                    credential_generation: CredentialGeneration::new(1).unwrap(),
                },
                command_key: "launch.synthetic".into(),
                correlation_id: "correlation.synthetic".into(),
                deadline: Instant::now() + Duration::from_secs(30),
                action: HostAction::LaunchPod {
                    pod_id,
                    role: Role::Worker,
                    credential: None,
                },
            },
            canonical_request: b"synthetic launch".to_vec(),
            proposal: Some(BoundHostLaunchProposal {
                session,
                run,
                binding,
                selection: LaunchSelection {
                    profile_ref: "podbay.fixture.process.exec".into(),
                    profile_generation: 1,
                    model_id: None,
                    reasoning_effort: None,
                    fallback_approved: false,
                    workspace: WorkspaceSelection {
                        scope_id: scope,
                        basis_ref: "basis.synthetic".into(),
                        relative_cwd: ".".into(),
                        access: WorkspaceAccess::ReadWrite,
                    },
                    arguments: vec![],
                    tool_bundle_refs: vec![],
                    authority_ref: format!("grant.{}", grant.get()),
                    wall_seconds: 60,
                    max_children: 0,
                    parent_run_id: None,
                },
            }),
        };
        (
            Fixture {
                directory,
                native: matches!(mode, Mode::Native),
            },
            host,
            transport,
            request,
            calls,
        )
    }

    #[test]
    fn exact_handoff_accepts_once_and_duplicate_never_reenters_runner() {
        let (_fixture, mut host, transport, request, calls) = setup(Mode::Good, "/bin/true".into());
        let first = host.launch_bound_pod(&transport, request.clone()).unwrap();
        assert_eq!(first.status.stage, LaunchDispatchStage::HostAccepted);
        assert!(
            first
                .status
                .receipt_ref
                .as_deref()
                .unwrap()
                .starts_with("podbay.launch.")
        );
        let again = host.launch_bound_pod(&transport, request).unwrap();
        assert_eq!(again.receipt, first.receipt);
        assert!(!again.port_called);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ambiguous_or_wrong_status_never_claims_acceptance_or_retries() {
        for mode in [Mode::LostReply, Mode::WrongStatus] {
            let (_fixture, mut host, transport, request, calls) = setup(mode, "/bin/true".into());
            let first = host.launch_bound_pod(&transport, request.clone()).unwrap();
            assert_eq!(
                first.status.stage,
                LaunchDispatchStage::UncertainAfterPossibleEffect
            );
            let again = host.launch_bound_pod(&transport, request).unwrap();
            assert_eq!(again.status, first.status);
            assert!(!again.port_called);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn settled_outbox_refuses_before_runner() {
        let (_fixture, mut host, transport, request, calls) =
            setup(Mode::SettledOutbox, "/bin/true".into());
        let result = host.launch_bound_pod(&transport, request).unwrap();
        assert_eq!(
            result.status.stage,
            LaunchDispatchStage::RefusedBeforeEffect
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn changed_private_directory_refuses_before_runner() {
        let (fixture, mut host, transport, request, calls) = setup(Mode::Good, "/bin/true".into());
        fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755)).unwrap();
        let result = host.launch_bound_pod(&transport, request).unwrap();
        assert_eq!(
            result.status.stage,
            LaunchDispatchStage::RefusedBeforeEffect
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[ignore = "requires disposable user systemd and PODBAY_TEST_POD_BINARY"]
    fn native_disposable_sleep_fixture() {
        let binary = std::env::var_os("PODBAY_TEST_POD_BINARY").expect("explicit pod binary");
        let (fixture, mut host, transport, request, _) = setup(Mode::Native, PathBuf::from(binary));
        let result = host.launch_bound_pod(&transport, request.clone()).unwrap();
        assert_eq!(result.status.stage, LaunchDispatchStage::HostAccepted);
        let manifest = fs::read_dir(&fixture.directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|e| e == "json"))
            .unwrap();
        let client = podbay_pod::PodClient::connect(manifest).unwrap();
        let status = client.status().unwrap();
        assert!(status.child_running);
        let again = host.launch_bound_pod(&transport, request).unwrap();
        assert!(!again.port_called);
        let after_duplicate = client.status().unwrap();
        assert_eq!(after_duplicate.supervisor, status.supervisor);
        assert_eq!(after_duplicate.child, status.child);
        assert!(!client.stop().unwrap().child_running);
    }

    fn inspect_adapter(fixture: &Fixture) -> LinuxLaunchPort {
        let binary = fs::canonicalize("/bin/true").unwrap();
        LinuxLaunchPort::new(
            TrustedLinuxLaunchConfig::from_trusted_policy(
                binary.clone(),
                sha256_file(&binary).unwrap(),
                fixture.directory.clone(),
            )
            .unwrap(),
        )
    }

    fn inspect_setup() -> (Fixture, DurableAuthority<HarnessPort>, LinuxLaunchPort) {
        let (fixture, mut first, transport, request, calls) = setup(Mode::Good, "/bin/true".into());
        first.admit_bound_pod(&transport, request).unwrap();
        drop(first);
        let adapter = inspect_adapter(&fixture);
        let host = DurableAuthority::open(
            fixture.directory.join("store.sqlite"),
            HarnessPort {
                inner: inspect_adapter(&fixture),
                mode: Mode::Good,
                calls,
            },
        )
        .unwrap();
        (fixture, host, adapter)
    }

    fn inspect_response(path: &Path, identity: &PodFenceIdentity) -> podbay_pod::RebindInspection {
        let peer = LinuxPeerEvidence::for_current_process().unwrap();
        let unit = format!(
            "podbay-pod-{}.service",
            path.file_stem().unwrap().to_str().unwrap()
        );
        podbay_pod::RebindInspection {
            protocol: "podbay.rebind-inspect/1".into(),
            nonce: "a".repeat(64),
            scope_id: identity.scope_id.as_str().into(),
            pod_id: identity.pod_id.as_str().into(),
            attempt_id: identity.attempt_id.as_str().into(),
            incarnation: identity.incarnation.get(),
            store_lineage: identity.store_lineage.as_str().into(),
            prior_owner_epoch: 1,
            prior_credential_epoch: 1,
            prior_input_epochs: std::collections::BTreeMap::from([(
                "resource.synthetic".into(),
                1,
            )]),
            checkpoint_digest: "c".repeat(64),
            supervisor_pid: 1234,
            supervisor_start_ticks: 5678,
            child_pid: 1235,
            child_start_ticks: 5679,
            boot_id: peer.boot_id().into(),
            cgroup_path: format!("/user.slice/{unit}"),
            unit_name: unit,
        }
    }

    #[test]
    fn inspect_existing_derives_manifest_and_returns_bound_read_only_observation() {
        let (fixture, mut host, adapter) = inspect_setup();
        let mut store = PodBayStore::open(fixture.directory.join("store.sqlite")).unwrap();
        let before = store.authority_snapshot().unwrap();
        let mut context = host
            .rebind_context(
                &ScopeId::try_from("scope.synthetic").unwrap(),
                &PodId::try_from("pod.synthetic").unwrap(),
            )
            .unwrap();
        let expected_path = podbay_pod::manifest_path_for_identity(
            &fixture.directory,
            &context.identity().pod_id,
            &context.identity().attempt_id,
            context.identity().incarnation,
        );
        let verified = adapter
            .inspect_with(&mut context, |path, identity, owner, credential| {
                assert_eq!(path, expected_path);
                assert_eq!((owner, credential), (2, 2));
                Ok(inspect_response(path, identity))
            })
            .unwrap();
        assert_eq!(verified.prior_checkpoint().identity, *context.identity());
        assert_eq!(verified.prior_checkpoint().phase, RebindPhase::Active);
        assert_eq!(verified.prior_checkpoint().owner_epoch.get(), 1);
        assert_eq!(
            verified.prior_checkpoint().input_epochs
                [&ResourceId::try_from("resource.synthetic").unwrap()]
                .get(),
            1
        );
        assert_eq!(verified.owner_epoch(), 2);
        assert_eq!(verified.credential_epoch(), 2);
        assert_eq!(verified.manager_peer(), context.manager_peer());
        assert_eq!(
            verified.resource_input_epochs(),
            context.resource_input_epochs()
        );
        assert_eq!(verified.store_path(), context.store_path());
        assert_eq!(verified.authority_revision(), context.authority_revision());
        assert_eq!(verified.nonce(), "a".repeat(64));
        assert_eq!(verified.child_pid(), 1235);
        assert_eq!(verified.child_start_ticks(), 5679);
        assert_eq!(store.authority_snapshot().unwrap(), before);
    }

    #[test]
    fn inspect_existing_refuses_foreign_or_nonadvancing_inspection_vectors() {
        let (_fixture, mut host, adapter) = inspect_setup();
        let mut context = host
            .rebind_context(
                &ScopeId::try_from("scope.synthetic").unwrap(),
                &PodId::try_from("pod.synthetic").unwrap(),
            )
            .unwrap();
        for case in 0..10 {
            let result = adapter.inspect_with(&mut context, |path, identity, owner, credential| {
                let mut response = inspect_response(path, identity);
                match case {
                    0 => response.store_lineage = "store.foreign".into(),
                    1 => response.attempt_id = "attempt.foreign".into(),
                    2 => response.prior_owner_epoch = owner,
                    3 => response.prior_credential_epoch = credential,
                    4 => {
                        response
                            .prior_input_epochs
                            .insert("resource.synthetic".into(), 2);
                    }
                    5 => {
                        response
                            .prior_input_epochs
                            .insert("resource.extra".into(), 1);
                    }
                    6 => response.prior_input_epochs.clear(),
                    7 => response.boot_id = "boot.foreign".into(),
                    8 => response.cgroup_path = "/user.slice/foreign.service".into(),
                    _ => response.checkpoint_digest = "not-a-digest".into(),
                }
                Ok(response)
            });
            assert!(result.is_err(), "case {case}");
        }
    }

    #[test]
    fn inspect_existing_rechecks_context_before_and_after_transport() {
        for stale_before in [true, false] {
            let (fixture, mut host, adapter) = inspect_setup();
            let mut context = host
                .rebind_context(
                    &ScopeId::try_from("scope.synthetic").unwrap(),
                    &PodId::try_from("pod.synthetic").unwrap(),
                )
                .unwrap();
            let mut other = PodBayStore::open(fixture.directory.join("store.sqlite")).unwrap();
            let mut called = false;
            if stale_before {
                other.begin_authority_replay(2, 3).unwrap();
            }
            let result = adapter.inspect_with(&mut context, |path, identity, _, _| {
                called = true;
                let response = inspect_response(path, identity);
                other.begin_authority_replay(2, 3).unwrap();
                Ok(response)
            });
            assert!(result.is_err());
            assert_eq!(called, !stale_before);
        }
    }

    #[test]
    fn inspect_existing_rechecks_pinned_config_after_transport() {
        let (fixture, mut host, adapter) = inspect_setup();
        let mut context = host
            .rebind_context(
                &ScopeId::try_from("scope.synthetic").unwrap(),
                &PodId::try_from("pod.synthetic").unwrap(),
            )
            .unwrap();
        assert!(
            adapter
                .inspect_with(&mut context, |path, identity, _, _| {
                    let response = inspect_response(path, identity);
                    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o755))
                        .unwrap();
                    Ok(response)
                })
                .is_err()
        );
    }

    #[test]
    fn rebind_proc_evidence_requires_exact_live_direct_child_birth_and_cgroup() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let mut sibling = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let result = (|| {
            let manager = LinuxPeerEvidence::for_current_process().unwrap();
            let parent = read_rebind_process(std::process::id()).unwrap();
            let direct = read_rebind_process(child.id()).unwrap();
            let other = read_rebind_process(sibling.id()).unwrap();
            let mut response = RebindInspection {
                protocol: "podbay.rebind-inspect/1".into(),
                nonce: "a".repeat(64),
                scope_id: "scope.fixture".into(),
                pod_id: "pod.fixture".into(),
                attempt_id: "attempt.fixture".into(),
                incarnation: 1,
                store_lineage: "lineage.fixture".into(),
                prior_owner_epoch: 1,
                prior_credential_epoch: 1,
                prior_input_epochs: BTreeMap::from([("resource.fixture".into(), 1)]),
                checkpoint_digest: "c".repeat(64),
                supervisor_pid: std::process::id(),
                supervisor_start_ticks: parent.start_ticks,
                child_pid: child.id(),
                child_start_ticks: direct.start_ticks,
                boot_id: manager.boot_id().into(),
                unit_name: "unit.fixture".into(),
                cgroup_path: manager.cgroup().into(),
            };
            assert!(attest_rebind_process_pair(&response, manager.uid(), manager.gid()).is_ok());
            response.child_start_ticks += 1;
            assert!(attest_rebind_process_pair(&response, manager.uid(), manager.gid()).is_err());
            response.child_start_ticks -= 1;
            response.supervisor_pid = sibling.id();
            response.supervisor_start_ticks = other.start_ticks;
            assert!(attest_rebind_process_pair(&response, manager.uid(), manager.gid()).is_err());
            response.supervisor_pid = std::process::id();
            response.supervisor_start_ticks = parent.start_ticks;
            response.cgroup_path = "/wrong.scope".into();
            assert!(attest_rebind_process_pair(&response, manager.uid(), manager.gid()).is_err());
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = sibling.kill();
        let _ = sibling.wait();
        result
    }

    #[test]
    fn rebind_systemd_main_pid_and_control_group_must_match_exactly() {
        let good = "ActiveState=active\nMainPID=42\nControlGroup=/user.slice/app.slice/podbay-pod-abc.service\n";
        assert!(
            parse_rebind_systemd_unit(good, 42, "/user.slice/app.slice/podbay-pod-abc.service")
                .is_ok()
        );
        for bad in [
            good.replace("MainPID=42", "MainPID=43"),
            good.replace("ActiveState=active", "ActiveState=inactive"),
            good.replace("podbay-pod-abc.service", "podbay-pod-sibling.service"),
            format!("{good}MainPID=42\n"),
            format!("{good}Unexpected=field\n"),
        ] {
            assert!(
                parse_rebind_systemd_unit(&bad, 42, "/user.slice/app.slice/podbay-pod-abc.service")
                    .is_err()
            );
        }
    }

    #[test]
    fn bootstrap_port_accepts_only_fsynced_submitted_stage() {
        let receipt = PortReceiptRef::from_port("receipt.bootstrap.fixture").unwrap();
        assert!(matches!(
            bootstrap_port_stage(
                BootstrapControlStage::Submitted {
                    native_thread_id: "thread.fixture".into(),
                    native_session_id: "session.native.fixture".into(),
                    native_turn_id: "turn.fixture".into(),
                },
                receipt.clone(),
            ),
            Ok(PortDispatchOutcome::Accepted(_))
        ));
        assert!(matches!(
            bootstrap_port_stage(BootstrapControlStage::RefusedBeforeEffect, receipt.clone()),
            Err(PortDispatchError::RefusedBeforeEffect)
        ));
        for stage in [
            BootstrapControlStage::ClaimedUnobserved,
            BootstrapControlStage::ThreadCreateUncertain,
            BootstrapControlStage::ThreadCreated {
                native_thread_id: "thread.fixture".into(),
                native_session_id: "session.native.fixture".into(),
            },
            BootstrapControlStage::BootstrapUncertain {
                native_thread_id: "thread.fixture".into(),
                native_session_id: "session.native.fixture".into(),
            },
        ] {
            assert!(matches!(
                bootstrap_port_stage(stage, receipt.clone()),
                Err(PortDispatchError::UncertainAfterPossibleEffect {
                    receipt_ref: Some(_)
                })
            ));
        }
    }
}

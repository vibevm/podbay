//! Pod-owned structured Codex child startup after exact V2 manifest review.
//! Initialize is transport evidence only: no thread, turn, or provider
//! readiness is inferred here.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_adapter_codex::{
    ApprovalPolicy, BlockReason, BootstrapReadPoll, BootstrapState, BootstrapTurnStage, ChildExitObservation, ChildLaunchSpec,
    CodexError, CodexResource,
    KernelChildBirthObservation, NativeObservationKind, NativeObservationStatus,
    PinnedCodexConfig, ProcessJsonlTransport, ResourceIdentity, Sandbox, WriterPermit,
};
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId};
use podbay_store::{BootstrapSendRecord, LaterCodexSendRecord};
use podbay_wire::{
    EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2, NativeResourceKind, ResourceDriver,
    TargetOs,
};

use crate::codex_credential::{
    CODEX_AUTH_CREDENTIAL_NAME, PreparedCodexHome, codex_private_slot_directory,
    prepare_codex_home_from_systemd_credential,
};
use crate::codex_bootstrap::{BootstrapControlStage, BootstrapSettlementStage};
use crate::codex_journal::{CodexCommandJournal, CodexJournalIdentity, CodexJournalIntentResult, CodexJournalStage, CodexJournalView};
use crate::codex_later_turn;
use crate::codex_turn_journal::{CodexLaterTurnJournal, LaterTurnStage, LaterTurnView};
use crate::linux_peer::LinuxPeerEvidence;
use crate::native_events::{
    NativeEventAppend, NativeEventCursor, NativeEventIdentity, NativeEventKind, NativeEventRead,
    NativeEventStatus,
};
use crate::segmented_native_events::SegmentedNativeEventSpool;
use crate::manifest::{
    BoundPeerManifest, CODEX_V2_CAPABILITY, CODEX_V3_CAPABILITY, LaunchDescriptor,
    PEER_BINDING_V2_PROTOCOL, PEER_BINDING_V3_PROTOCOL, PodError, manifest_path,
    private_directory, unit_name,
};
use crate::ports::DurableFiles;
use crate::runtime::LinuxBackend;

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ARGV: [&str; 3] = ["app-server", "--listen", "stdio://"];

/// An opaque, typed manifest preflight. Construction rechecks the V2 peer
/// binding and canonical paths; it does not prove durable store admission,
/// manager authority, or a current resource grant.
pub struct ValidatedCodexResourceLaunch {
    descriptor: ImmutableLaunchDescriptorV2,
    effective: EffectiveLaunchContractV2,
    peer_binding: BoundPeerManifest,
    legacy: LaunchDescriptor,
    pod_directory: PathBuf,
    expected_unit: String,
}

impl ValidatedCodexResourceLaunch {
    pub fn from_peer_binding(
        binding: &BoundPeerManifest,
        launch: &LaunchDescriptor,
        pod_directory: &Path,
    ) -> Result<Self, PodError> {
        private_directory(pod_directory)?;
        if !matches!(
            (binding.protocol.as_str(), binding.capability.as_str()),
            (PEER_BINDING_V2_PROTOCOL, CODEX_V2_CAPABILITY)
                | (PEER_BINDING_V3_PROTOCOL, CODEX_V3_CAPABILITY)
        ) {
            return Err(PodError::Unsupported("Codex peer binding is required"));
        }
        binding.validate(launch, pod_directory)?;
        let descriptor = ImmutableLaunchDescriptorV2::decode_json(&binding.wire_descriptor)
            .map_err(|_| PodError::Invalid("Codex V2 descriptor changed"))?;
        let effective = EffectiveLaunchContractV2::decode(&binding.effective_spec)
            .map_err(|_| PodError::Invalid("Codex V2 effective launch changed"))?;
        effective
            .compare_with_descriptor(&descriptor)
            .map_err(|_| PodError::Invalid("Codex V2 launch relation changed"))?;
        let expected_unit = unit_name(&manifest_path(pod_directory, launch)?)?;
        Ok(Self {
            descriptor,
            effective,
            peer_binding: binding.clone(),
            legacy: launch.clone(),
            pod_directory: pod_directory.to_path_buf(),
            expected_unit,
        })
    }

    pub fn expected_unit(&self) -> &str {
        &self.expected_unit
    }
}

/// Owns the structured adapter and its direct child. Later-turn input is
/// available only through a claimed store proof and current pod control.
pub struct PodCodexResource {
    resource: CodexResource<ProcessJsonlTransport>,
    journal: Option<CodexCommandJournal>,
    journal_path: PathBuf,
    later_journal: Option<CodexLaterTurnJournal>,
    later_journal_path: PathBuf,
    later_identity: Option<CodexJournalIdentity>,
    pending_later_proof: Option<LaterCodexSendRecord>,
    native_events: SegmentedNativeEventSpool,
    child_birth: KernelChildBirthObservation,
    pod_boot_id: String,
    pod_cgroup: String,
}

fn open_current_native_events(
    private_slot: &Path,
    identity: NativeEventIdentity,
) -> Result<SegmentedNativeEventSpool, PodError> {
    // There are no deployed clients of the former single-file format. Reject
    // an old slot instead of silently migrating or mixing event histories.
    match fs::symlink_metadata(private_slot.join("codex.native-events.log")) {
        Ok(_) => return Err(PodError::Unsupported("old native event format")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    SegmentedNativeEventSpool::open(private_slot.to_path_buf(), identity)
}

impl PodCodexResource {
    /// Spawn the exact reviewed app-server child with only explicit HOME and
    /// CODEX_HOME. A lost initialize result is uncertain; no turn is sent.
    pub fn spawn_initialized(
        launch: ValidatedCodexResourceLaunch,
        home: PreparedCodexHome,
    ) -> Result<Self, PodError> {
        private_directory(&launch.pod_directory)?;
        launch
            .peer_binding
            .validate(&launch.legacy, &launch.pod_directory)?;
        let private_slot = codex_private_slot_directory(
            &launch.pod_directory, &launch.expected_unit, false,
        )?;
        if home.isolated_home() != private_slot.join("home")
            || home.codex_home() != private_slot.join("home/codex")
        {
            return Err(PodError::Refused("Codex HOME belongs to another pod"));
        }
        let credential = fs::read_link(home.credential_reference())?;
        if credential.file_name() != Some(CODEX_AUTH_CREDENTIAL_NAME.as_ref())
            || credential
                .parent()
                .and_then(Path::file_name)
                .is_none_or(|unit| unit != launch.expected_unit.as_str())
            || !fs::metadata(home.credential_reference())?.is_file()
        {
            return Err(PodError::Refused("Codex credential reference is stale"));
        }
        let source_directory = credential
            .parent()
            .ok_or(PodError::Refused("Codex credential directory is absent"))?;
        let rechecked_home = prepare_codex_home_from_systemd_credential(
            &launch.expected_unit,
            &launch.pod_directory,
            source_directory,
        )?;
        if rechecked_home.isolated_home() != home.isolated_home()
            || rechecked_home.codex_home() != home.codex_home()
            || rechecked_home.credential_reference() != home.credential_reference()
        {
            return Err(PodError::Refused("Codex HOME changed before spawn"));
        }
        let descriptor = &launch.descriptor;
        launch
            .effective
            .compare_with_descriptor(descriptor)
            .map_err(|_| PodError::Refused("Codex V2 launch relation changed"))?;
        let resource = descriptor
            .resource(0)
            .ok_or(PodError::Invalid("Codex V2 resource is absent"))?;
        if descriptor.target_os() != TargetOs::Linux
            || descriptor.resources_len() != 1
            || resource.kind != NativeResourceKind::StructuredProvider
            || !matches!(resource.driver, ResourceDriver::Structured { .. })
            || descriptor.arguments() != ARGV
        {
            return Err(PodError::Unsupported(
                "Codex structured child selection changed",
            ));
        }
        let identity = ResourceIdentity {
            session_id: SessionId::try_from(descriptor.session_id())
                .map_err(|_| PodError::Invalid("Codex session identity"))?,
            run_id: RunId::try_from(descriptor.run_id())
                .map_err(|_| PodError::Invalid("Codex run identity"))?,
            attempt_id: AttemptId::try_from(descriptor.attempt_id())
                .map_err(|_| PodError::Invalid("Codex attempt identity"))?,
            pod_id: PodId::try_from(descriptor.pod_id())
                .map_err(|_| PodError::Invalid("Codex pod identity"))?,
            resource_id: ResourceId::try_from(resource.resource_id)
                .map_err(|_| PodError::Invalid("Codex resource identity"))?,
            resource_epoch: Epoch::new(resource.epoch)
                .map_err(|_| PodError::Invalid("Codex resource epoch"))?,
        };
        let event_identity = NativeEventIdentity::from_resource(
            &StoreLineageId::try_from(launch.peer_binding.store_lineage.as_str())
                .map_err(|_| PodError::Invalid("Codex event store lineage"))?,
            &ScopeId::try_from(descriptor.scope_id())
                .map_err(|_| PodError::Invalid("Codex event scope"))?,
            &identity.session_id,
            &identity.run_id,
            &identity.attempt_id,
            &identity.pod_id,
            Epoch::new(launch.legacy.incarnation)
                .map_err(|_| PodError::Invalid("Codex event Pod incarnation"))?,
            &identity.resource_id,
            identity.resource_epoch,
        );
        let native_events = open_current_native_events(&private_slot, event_identity)?;
        let config = PinnedCodexConfig::new(
            descriptor.model_id(),
            descriptor.reasoning_effort(),
            PathBuf::from(descriptor.cwd()),
            ApprovalPolicy::Never,
            Sandbox::DangerFullAccess,
        )
        .map_err(|_| PodError::Invalid("Codex pinned native configuration"))?;
        let owner = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("pod process identity unavailable"))?;
        let pod_boot_id = owner.boot_id().to_owned();
        let pod_cgroup = owner.cgroup().to_owned();
        if pod_cgroup.rsplit('/').next() != Some(launch.expected_unit.as_str()) {
            return Err(PodError::Refused(
                "Codex child constructor is outside its pod unit",
            ));
        }
        let spec = ChildLaunchSpec::new(
            PathBuf::from(descriptor.executable()),
            ARGV.into_iter().map(OsString::from).collect(),
            PathBuf::from(descriptor.cwd()),
            home.isolated_home().to_path_buf(),
            home.codex_home().to_path_buf(),
            IO_TIMEOUT,
            IO_TIMEOUT,
        )
        .map_err(PodError::Io)?;
        let mut transport = ProcessJsonlTransport::spawn(spec)?;
        let child_birth = transport
            .attest_kernel_birth()
            .map_err(|_| PodError::Uncertain("Codex child birth unavailable after spawn"))?;
        require_child_in_pod(&child_birth, &pod_boot_id, &pod_cgroup)?;
        let mut resource = CodexResource::new(transport, identity, config);
        resource
            .initialize()
            .map_err(|_| PodError::Uncertain("Codex initialize outcome unknown"))?;
        let after = resource
            .attest_owned_child_birth()
            .map_err(|_| PodError::Uncertain("Codex child birth unavailable after initialize"))?;
        if after != child_birth {
            return Err(PodError::Refused(
                "Codex child birth changed during initialize",
            ));
        }
        require_child_in_pod(&after, &pod_boot_id, &pod_cgroup)?;
        Ok(Self {
            resource,
            journal: None,
            journal_path: private_slot.join("codex.commands.log"),
            later_journal: None,
            later_journal_path: private_slot.join("codex.turns.log"),
            later_identity: None,
            pending_later_proof: None,
            native_events,
            child_birth,
            pod_boot_id,
            pod_cgroup,
        })
    }

    pub fn identity(&self) -> &ResourceIdentity {
        self.resource.identity()
    }

    pub fn child_birth(&self) -> &KernelChildBirthObservation {
        &self.child_birth
    }

    pub fn pid(&self) -> u32 {
        self.child_birth.pid
    }

    /// This private source is current only after all state-applied native
    /// facts have crossed a held fsynced append. A failed append stops native
    /// publication and leaves the pod's control channel available.
    fn flush_native_events(&mut self) -> Result<(), PodError> {
        flush_native_events_from(&mut self.resource, &mut self.native_events)
    }

    pub(crate) fn submit_claimed_later_turn(
        &mut self,
        proof: &LaterCodexSendRecord,
        mut recheck: impl FnMut() -> Result<(), PodError>,
    ) -> Result<LaterTurnView, PodError> {
        self.recheck_child()?;
        recheck()?;
        let target = proof.native_target();
        if target.session_id != self.resource.identity().session_id
            || target.run_id != self.resource.identity().run_id
            || target.attempt_id != self.resource.identity().attempt_id
            || target.pod_id != self.resource.identity().pod_id
            || target.resource_id != self.resource.identity().resource_id
            || target.resource_epoch != self.resource.identity().resource_epoch.get()
        { return Err(PodError::Refused("later turn Resource differs from child")); }
        self.flush_native_events()?;
        let identity = CodexJournalIdentity::from_resource(
            &target.store_lineage, &target.scope_id, &target.session_id,
            &target.run_id, &target.attempt_id, &target.pod_id,
            Epoch::new(target.pod_incarnation)
                .map_err(|_| PodError::Invalid("later turn Pod incarnation"))?,
            &target.resource_id, self.resource.identity().resource_epoch,
        );
        let bootstrap = self.journal.as_mut()
            .ok_or(PodError::Refused("bootstrap journal is absent"))?;
        if !bootstrap.matches_identity(&identity) {
            return Err(PodError::Refused("bootstrap journal Resource differs"));
        }
        if self.later_journal.is_none() {
            self.later_journal = Some(CodexLaterTurnJournal::open_after_completed_bootstrap(
                &LinuxBackend, &self.later_journal_path, identity.clone(), bootstrap,
            )?);
            self.later_identity = Some(identity.clone());
        }
        if self.later_identity.as_ref() != Some(&identity)
            || !self.later_journal.as_ref().is_some_and(|journal| journal.matches_identity(&identity))
        { return Err(PodError::Refused("later-turn journal Resource differs")); }
        let expected_child = self.child_birth.clone();
        let expected_boot = self.pod_boot_id.clone();
        let expected_cgroup = self.pod_cgroup.clone();
        let result = codex_later_turn::submit_store_claimed(
            &mut self.resource, bootstrap,
            self.later_journal.as_mut().expect("checked held later journal"), proof,
            &mut |native| {
                recheck_native_child(native, &expected_child, &expected_boot, &expected_cgroup)?;
                recheck()
            },
        );
        if result.as_ref().is_ok_and(|view| view.stage == LaterTurnStage::IntentDurable)
            && self.resource.has_pending_nonblocking_later_turn()
        {
            self.pending_later_proof = Some(proof.clone());
        }
        self.flush_native_events()?;
        result
    }

    pub(crate) fn pending_later_proof(&self) -> Option<&LaterCodexSendRecord> {
        self.pending_later_proof.as_ref()
    }

    pub(crate) fn inspect_claimed_later_turn(
        &mut self,
        proof: &LaterCodexSendRecord,
    ) -> Result<Option<LaterTurnView>, PodError> {
        let target = proof.native_target();
        if target.session_id != self.resource.identity().session_id
            || target.run_id != self.resource.identity().run_id
            || target.attempt_id != self.resource.identity().attempt_id
            || target.pod_id != self.resource.identity().pod_id
            || target.resource_id != self.resource.identity().resource_id
            || target.resource_epoch != self.resource.identity().resource_epoch.get()
        { return Err(PodError::Refused("later-turn inspection Resource differs")); }
        let bootstrap = self.journal.as_mut()
            .ok_or(PodError::Refused("bootstrap journal is absent"))?;
        bootstrap.recheck_held_file()?;
        let anchor = bootstrap.view();
        if anchor.stage != CodexJournalStage::BootstrapCompleted
            || anchor.native_thread_id.as_deref() != Some(proof.native_thread_id())
        { return Err(PodError::Refused("later-turn bootstrap anchor is not complete")); }
        let Some(later) = self.later_journal.as_mut() else {
            return match fs::symlink_metadata(&self.later_journal_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(PodError::Uncertain("later-turn journal exists without held identity")),
            };
        };
        later.recheck_held_file()?;
        let view = later.view(&proof.receipt().command_id);
        if view.as_ref().is_some_and(|view| {
            view.payload_digest != proof.receipt().request_digest
                || view.writer_epoch != proof.writer_epoch()
                || view.native_thread_id != proof.native_thread_id()
        }) { return Err(PodError::Conflict("later-turn journal command differs")); }
        Ok(view)
    }

    pub(crate) fn prior_later_view(&mut self, command_id: &str) -> Option<LaterTurnView> {
        let journal = self.later_journal.as_mut()?;
        let mut view = journal.view(command_id)?;
        if journal.recheck_held_file().is_err() {
            view.stage = LaterTurnStage::StorageUncertain;
        }
        Some(view)
    }

    pub(crate) fn poll_native_notification_once(
        &mut self,
        mut recheck_before_journal: impl FnMut() -> Result<(), PodError>,
    ) -> Result<bool, PodError> {
        let (Some(later), Some(identity), Some(bootstrap)) = (
            self.later_journal.as_mut(), self.later_identity.as_ref(), self.journal.as_mut(),
        ) else {
            return self.poll_bootstrap_notification_once(recheck_before_journal);
        };
        let expected_child = self.child_birth.clone();
        let expected_boot = self.pod_boot_id.clone();
        let expected_cgroup = self.pod_cgroup.clone();
        let result = codex_later_turn::poll_once(
            &mut self.resource, bootstrap, later, identity,
            &mut |native| {
                recheck_native_child(native, &expected_child, &expected_boot, &expected_cgroup)?;
                recheck_before_journal()
            },
            &mut |native| flush_native_events_from(native, &mut self.native_events),
        );
        if later.active_view().is_none_or(|view| view.stage != LaterTurnStage::IntentDurable) {
            self.pending_later_proof = None;
        }
        result
    }

    pub(crate) fn mark_native_events_unknown(&mut self) {
        let _ = self.native_events.mark_continuity_unknown();
    }

    pub(crate) fn read_native_events(
        &mut self,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<NativeEventRead, PodError> {
        if self.resource.has_unspooled_native_notifications() {
            return Err(PodError::Uncertain("native event source awaits durable append"));
        }
        self.native_events.read_after(cursor, limit)
    }

    /// Advance at most one already available native notification while the
    /// pod remains able to answer control IPC. A matching completed turn is
    /// journaled only as pending a separate fresh `thread/read` proof.
    pub(crate) fn poll_bootstrap_notification_once(
        &mut self,
        mut recheck_before_journal: impl FnMut() -> Result<(), PodError>,
    ) -> Result<bool, PodError> {
        let stage = self.journal.as_ref().map(|journal| journal.view().stage);
        if stage.is_none() {
            let consumed = self.resource.poll_available_once()
                .map_err(|_| PodError::Uncertain("Codex native notification outcome unknown"))?;
            self.flush_native_events()?;
            return Ok(consumed);
        }
        let stage = stage.expect("checked journal stage");
        if stage == CodexJournalStage::BootstrapCompletionObservedPendingIdleProof {
            let view = self.journal.as_ref()
                .ok_or(PodError::Uncertain("held Codex journal disappeared"))?.view();
            let thread_id = view.native_thread_id.as_deref()
                .ok_or(PodError::Uncertain("pending completion lacks native thread"))?;
            let session_id = view.native_session_id.as_deref()
                .ok_or(PodError::Uncertain("pending completion lacks native Session"))?;
            let turn_id = view.native_turn_id.as_deref()
                .ok_or(PodError::Uncertain("pending completion lacks native turn"))?;
            let progress = self.resource.poll_bootstrap_read_proof_once(
                thread_id, session_id, turn_id,
            ).map_err(|_| PodError::Uncertain("Codex completion read outcome unknown"))?;
            self.flush_native_events()?;
            return match progress {
                BootstrapReadPoll::Pending => Ok(false),
                BootstrapReadPoll::Advanced => Ok(true),
                BootstrapReadPoll::Verified => {
                    recheck_before_journal()?;
                    self.recheck_child()?;
                    match self.resource.poll_bootstrap_read_proof_once(
                        thread_id, session_id, turn_id,
                    ).map_err(|_| PodError::Uncertain("Codex completion read changed before journal"))? {
                        BootstrapReadPoll::Pending => return Ok(false),
                        BootstrapReadPoll::Advanced => return Ok(true),
                        BootstrapReadPoll::Verified => {}
                    }
                    self.flush_native_events()?;
                    let journal = self.journal.as_mut()
                        .ok_or(PodError::Uncertain("held Codex journal disappeared"))?;
                    journal.recheck_held_file()?;
                    if journal.view() != view {
                        return Err(PodError::Uncertain("completion journal changed before final proof"));
                    }
                    let key = view.command_key.as_deref()
                        .ok_or(PodError::Uncertain("pending completion lacks command key"))?;
                    let digest = view.payload_digest.as_deref()
                        .ok_or(PodError::Uncertain("pending completion lacks request digest"))?;
                    journal.record_bootstrap_completed(key, digest, turn_id)?;
                    Ok(true)
                }
            };
        }
        if stage != CodexJournalStage::BootstrapSubmitted {
            let consumed = self.resource.poll_available_once()
                .map_err(|_| PodError::Uncertain("Codex native notification outcome unknown"))?;
            self.flush_native_events()?;
            return Ok(consumed);
        }
        let consumed = self.resource.poll_available_once()
            .map_err(|_| PodError::Uncertain("Codex native notification outcome unknown"))?;
        self.flush_native_events()?;
        let view = self.journal.as_ref()
            .ok_or(PodError::Uncertain("held Codex journal disappeared"))?.view();
        let terminal = self.resource.bootstrap_state().clone();
        let terminal_turn = match &terminal {
            BootstrapState::Completed { turn_id }
            | BootstrapState::Failed { turn_id }
            | BootstrapState::Interrupted { turn_id } => Some(turn_id.as_str()),
            _ => None,
        };
        if view.stage == CodexJournalStage::BootstrapSubmitted
            && let Some(turn_id) = terminal_turn
            && view.native_turn_id.as_deref() == Some(turn_id)
            && !self.resource.turn_control_state().external_conflict
        {
            let key = view.command_key.as_deref()
                .ok_or(PodError::Uncertain("submitted journal lacks command key"))?;
            let digest = view.payload_digest.as_deref()
                .ok_or(PodError::Uncertain("submitted journal lacks request digest"))?;
            recheck_before_journal()?;
            self.recheck_child()?;
            let journal = self.journal.as_mut()
                .ok_or(PodError::Uncertain("held Codex journal disappeared"))?;
            journal.recheck_held_file()?;
            match terminal {
                BootstrapState::Completed { .. } => {
                    journal.record_bootstrap_completion_observed(key, digest, turn_id)?;
                }
                BootstrapState::Failed { .. } => {
                    journal.record_bootstrap_failed(key, digest, turn_id)?;
                }
                BootstrapState::Interrupted { .. } => {
                    journal.record_bootstrap_interrupted(key, digest, turn_id)?;
                }
                _ => unreachable!("checked terminal state"),
            }
            return Ok(true);
        }
        Ok(consumed)
    }

    /// Read only the held, identity-checked journal for this exact claimed
    /// command. Absence is a distinct fact; no native adapter method is used.
    pub(crate) fn inspect_claimed_bootstrap(
        &mut self,
        proof: &BootstrapSendRecord,
    ) -> Result<(BootstrapControlStage, Option<BootstrapSettlementStage>), PodError> {
        let target = proof.native_target();
        let native = self.resource.identity().clone();
        if target.session_id != native.session_id
            || target.run_id != native.run_id
            || target.attempt_id != native.attempt_id
            || target.pod_id != native.pod_id
            || target.resource_id != native.resource_id
            || target.resource_epoch != native.resource_epoch.get()
            || target.pod_incarnation == 0
            || proof.writer_epoch() == 0
        {
            return Err(PodError::Refused("bootstrap journal target differs"));
        }
        if self.resource.has_unspooled_native_notifications() {
            return Err(PodError::Uncertain("native observations await durable append"));
        }
        let identity = CodexJournalIdentity::from_resource(
            &target.store_lineage,
            &target.scope_id,
            &target.session_id,
            &target.run_id,
            &target.attempt_id,
            &target.pod_id,
            Epoch::new(target.pod_incarnation)
                .map_err(|_| PodError::Invalid("bootstrap Pod incarnation"))?,
            &target.resource_id,
            native.resource_epoch,
        );
        let Some(journal) = self.journal.as_mut() else {
            return match fs::symlink_metadata(&self.journal_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok((BootstrapControlStage::ClaimedUnobserved, None))
                }
                _ => Err(PodError::Uncertain(
                    "Codex journal path exists without held identity",
                )),
            };
        };
        if !journal.matches_identity(&identity) {
            return Err(PodError::Refused("held Codex journal belongs to another resource"));
        }
        journal.recheck_held_file()?;
        let view = journal.view();
        if view.command_key.as_deref().is_some_and(|key| key != proof.receipt().command_id)
            || view.payload_digest.as_deref().is_some_and(|digest|
                digest != proof.receipt().request_digest)
        {
            return Err(PodError::Conflict("held Codex journal belongs to another command"));
        }
        let settlement = match view.stage {
            CodexJournalStage::BootstrapCompletionObservedPendingIdleProof =>
                Some(BootstrapSettlementStage::CompletionObservedPendingIdleProof),
            CodexJournalStage::BootstrapFailed => Some(BootstrapSettlementStage::Failed),
            CodexJournalStage::BootstrapInterrupted => Some(BootstrapSettlementStage::Interrupted),
            CodexJournalStage::BootstrapCompleted => Some(BootstrapSettlementStage::Completed),
            _ => None,
        };
        Ok((inspect_stage_from_journal_view(&view)?, settlement))
    }

    pub(crate) fn inspect_current_codex_anchor(
        &mut self,
        bootstrap: &BootstrapSendRecord,
        current: &podbay_store::NativeWriterTarget,
    ) -> Result<CodexJournalView, PodError> {
        self.recheck_child()?;
        let original = bootstrap.native_target();
        if original.store_lineage != current.store_lineage
            || original.scope_id != current.scope_id
            || original.session_id != current.session_id
            || original.run_id != current.run_id
            || original.attempt_id != current.attempt_id
            || original.pod_id != current.pod_id
            || original.pod_incarnation != current.pod_incarnation
            || original.resource_id != current.resource_id
            || original.resource_epoch != current.resource_epoch
            || original.resource_input_epoch > current.resource_input_epoch
        { return Err(PodError::Refused("Codex bootstrap lineage differs from current Resource")); }
        let journal = self.journal.as_mut()
            .ok_or(PodError::Refused("Codex bootstrap journal is absent"))?;
        let identity = CodexJournalIdentity::from_resource(
            &current.store_lineage, &current.scope_id, &current.session_id,
            &current.run_id, &current.attempt_id, &current.pod_id,
            Epoch::new(current.pod_incarnation).map_err(|_| PodError::Invalid("Pod incarnation"))?,
            &current.resource_id,
            Epoch::new(current.resource_epoch).map_err(|_| PodError::Invalid("Resource epoch"))?,
        );
        if !journal.matches_identity(&identity) {
            return Err(PodError::Refused("held bootstrap journal Resource differs"));
        }
        journal.recheck_held_file()?;
        let view = journal.view();
        if view.stage != CodexJournalStage::BootstrapCompleted
            || view.command_key.as_deref() != Some(bootstrap.receipt().command_id.as_str())
            || view.payload_digest.as_deref() != Some(bootstrap.receipt().request_digest.as_str())
            || view.native_thread_id.is_none() || view.native_session_id.is_none()
        { return Err(PodError::Refused("Codex bootstrap completion is not fsynced")); }
        Ok(view)
    }

    /// A current authority failure cannot erase an earlier fsynced native
    /// intent. This read returns a conservative stage for the same CommandId.
    pub(crate) fn prior_uncertain_stage(
        &mut self,
        command_id: &str,
    ) -> Option<(String, BootstrapControlStage)> {
        let journal = self.journal.as_mut()?;
        let before = journal.view();
        if before.command_key.as_deref() != Some(command_id)
            || before.stage == CodexJournalStage::Empty
        {
            return None;
        }
        let digest = before.payload_digest.clone()?;
        if journal.recheck_held_file().is_err() {
            return Some((digest, conservative_prior_stage(&before)));
        }
        let view = journal.view();
        Some((digest, conservative_prior_stage(&view)))
    }

    /// Consume one already-claimed, store-verified bootstrap. `recheck` must
    /// reattest the same manager socket and exact current store proof each
    /// time it is called. This method never treats a local WriterPermit as the
    /// source of authority and never retries an uncertain native RPC.
    pub(crate) fn submit_claimed_bootstrap(
        &mut self,
        proof: &BootstrapSendRecord,
        files: &impl DurableFiles,
        mut recheck: impl FnMut() -> Result<(), PodError>,
    ) -> BootstrapControlStage {
        let target = proof.native_target();
        let identity = self.resource.identity().clone();
        if target.session_id != identity.session_id
            || target.run_id != identity.run_id
            || target.attempt_id != identity.attempt_id
            || target.pod_id != identity.pod_id
            || target.resource_id != identity.resource_id
            || target.resource_epoch != identity.resource_epoch.get()
            || target.pod_incarnation == 0
            || proof.writer_epoch() == 0
        {
            return self.prior_uncertain_stage(&proof.receipt().command_id)
                .map(|(_, stage)| stage)
                .unwrap_or(BootstrapControlStage::RefusedBeforeEffect);
        }
        if self.recheck_child().is_err() || recheck().is_err() {
            return self.prior_uncertain_stage(&proof.receipt().command_id)
                .map(|(_, stage)| stage)
                .unwrap_or(BootstrapControlStage::RefusedBeforeEffect);
        }
        let journal_identity = CodexJournalIdentity::from_resource(
            &target.store_lineage,
            &target.scope_id,
            &target.session_id,
            &target.run_id,
            &target.attempt_id,
            &target.pod_id,
            match Epoch::new(target.pod_incarnation) {
                Ok(value) => value,
                Err(_) => return BootstrapControlStage::RefusedBeforeEffect,
            },
            &target.resource_id,
            identity.resource_epoch,
        );
        let mut journal = match self.journal.take() {
            Some(journal) if journal.matches_identity(&journal_identity) => journal,
            Some(journal) => {
                self.journal = Some(journal);
                return self.prior_uncertain_stage(&proof.receipt().command_id)
                    .map(|(_, stage)| stage)
                    .unwrap_or(BootstrapControlStage::RefusedBeforeEffect);
            }
            None => match CodexCommandJournal::open(files, &self.journal_path, journal_identity) {
                Ok(journal) => journal,
                Err(_) => return BootstrapControlStage::ThreadCreateUncertain,
            },
        };
        let stage = self.submit_with_journal(proof, &mut journal, &mut recheck);
        self.journal = Some(journal);
        stage
    }

    fn submit_with_journal(
        &mut self,
        proof: &BootstrapSendRecord,
        journal: &mut CodexCommandJournal,
        recheck: &mut impl FnMut() -> Result<(), PodError>,
    ) -> BootstrapControlStage {
        let key = proof.receipt().command_id.as_str();
        let digest = proof.receipt().request_digest.as_str();
        let before = journal.view();
        if self.flush_native_events().is_err() {
            return conservative_prior_stage(&before);
        }
        if journal.recheck_held_file().is_err() {
            return conservative_prior_stage(&before);
        }
        let view = journal.view();
        if view.command_key.as_deref().is_some_and(|value| value != key)
            || view.payload_digest.as_deref().is_some_and(|value| value != digest)
        {
            return if view.command_key.as_deref() == Some(key) {
                conservative_prior_stage(&view)
            } else {
                BootstrapControlStage::RefusedBeforeEffect
            };
        }
        match view.stage {
            CodexJournalStage::BootstrapSubmitted
            | CodexJournalStage::BootstrapCompletionObservedPendingIdleProof
            | CodexJournalStage::BootstrapFailed
            | CodexJournalStage::BootstrapInterrupted
            | CodexJournalStage::BootstrapCompleted => {
                return submitted_from_view(&view);
            }
            CodexJournalStage::BootstrapIntentDurable
            | CodexJournalStage::BootstrapUnknownAfterReopen
            | CodexJournalStage::BootstrapUncertain => {
                return bootstrap_uncertain_from_view(&view);
            }
            CodexJournalStage::ThreadCreateIntentDurable
            | CodexJournalStage::ThreadCreateUnknownAfterReopen
            | CodexJournalStage::StorageUncertain => {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            CodexJournalStage::Empty | CodexJournalStage::ThreadCreated => {}
        }
        let (thread_id, session_id) = if view.stage == CodexJournalStage::Empty {
            if !matches!(journal.begin_thread_create(key, digest), Ok(CodexJournalIntentResult::NewlyDurable)) {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            if self.recheck_before_native(journal, recheck).is_err() {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            let thread = match self.resource.start_thread_without_turn() {
                Ok(thread) => thread,
                Err(_) => return BootstrapControlStage::ThreadCreateUncertain,
            };
            if self.flush_native_events().is_err() {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            if journal.checkpoint_thread_created(key, digest, &thread.thread_id, &thread.session_id).is_err() {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            (thread.thread_id, thread.session_id)
        } else {
            let Some(thread_id) = view.native_thread_id else {
                return BootstrapControlStage::ThreadCreateUncertain;
            };
            let Some(session_id) = view.native_session_id else {
                return BootstrapControlStage::ThreadCreateUncertain;
            };
            if self.resource.native_thread().is_none_or(|native| {
                native.thread_id != thread_id || native.session_id != session_id
            }) {
                return BootstrapControlStage::ThreadCreateUncertain;
            }
            (thread_id, session_id)
        };
        if self.recheck_before_native(journal, recheck).is_err() {
            return BootstrapControlStage::ThreadCreated {
                native_thread_id: thread_id,
                native_session_id: session_id,
            };
        }
        let client_message_id = format!("message.{key}");
        if !matches!(journal.begin_bootstrap_intent(key, digest, &client_message_id),
            Ok(CodexJournalIntentResult::NewlyDurable))
        {
            return BootstrapControlStage::BootstrapUncertain {
                native_thread_id: thread_id,
                native_session_id: session_id,
            };
        }
        if self.recheck_before_native(journal, recheck).is_err() {
            return BootstrapControlStage::BootstrapUncertain {
                native_thread_id: thread_id,
                native_session_id: session_id,
            };
        }
        let writer_epoch = match Epoch::new(proof.writer_epoch()) {
            Ok(epoch) => epoch,
            Err(_) => return BootstrapControlStage::BootstrapUncertain {
                native_thread_id: thread_id,
                native_session_id: session_id,
            },
        };
        if self.resource.install_writer_epoch_from_trusted_boundary(writer_epoch).is_err() {
            return BootstrapControlStage::BootstrapUncertain {
                native_thread_id: thread_id,
                native_session_id: session_id,
            };
        }
        let permit = WriterPermit::from_trusted_boundary(self.resource.identity().clone(), writer_epoch);
        let expected_birth = self.child_birth.clone();
        let expected_boot = self.pod_boot_id.clone();
        let expected_cgroup = self.pod_cgroup.clone();
        let submission = self.resource.submit_bootstrap_after_checkpoint_checked(
            &permit, &thread_id, &session_id, proof.prompt_text(), &client_message_id,
            |resource| {
                let blocked = || CodexError::Blocked(BlockReason::ObservationUnknown);
                journal.recheck_held_file().map_err(|_| blocked())?;
                recheck().map_err(|_| blocked())?;
                let pod = LinuxPeerEvidence::for_current_process().map_err(|_| blocked())?;
                if pod.boot_id() != expected_boot || pod.cgroup() != expected_cgroup {
                    return Err(blocked());
                }
                let child = resource.attest_owned_child_birth().map_err(|_| blocked())?;
                if child != expected_birth {
                    return Err(blocked());
                }
                require_child_in_pod(&child, &expected_boot, &expected_cgroup)
                    .map_err(|_| blocked())
            },
        );
        match submission {
            Ok(submission) => match submission.stage {
                BootstrapTurnStage::Submitted { turn_id } => {
                    if journal.record_bootstrap_submitted(key, digest, &turn_id).is_err() {
                        return BootstrapControlStage::BootstrapUncertain {
                            native_thread_id: thread_id,
                            native_session_id: session_id,
                        };
                    }
                    if self.flush_native_events().is_err() {
                        return BootstrapControlStage::BootstrapUncertain {
                            native_thread_id: thread_id,
                            native_session_id: session_id,
                        };
                    }
                    BootstrapControlStage::Submitted {
                        native_thread_id: thread_id,
                        native_session_id: session_id,
                        native_turn_id: turn_id,
                    }
                }
                BootstrapTurnStage::Uncertain => {
                    let _ = journal.record_bootstrap_uncertain(key, digest);
                    let _ = self.flush_native_events();
                    BootstrapControlStage::BootstrapUncertain {
                        native_thread_id: thread_id,
                        native_session_id: session_id,
                    }
                }
            },
            Err(_) => {
                let _ = journal.record_bootstrap_uncertain(key, digest);
                let _ = self.flush_native_events();
                BootstrapControlStage::BootstrapUncertain {
                    native_thread_id: thread_id,
                    native_session_id: session_id,
                }
            }
        }
    }

    fn recheck_before_native(
        &mut self,
        journal: &mut CodexCommandJournal,
        recheck: &mut impl FnMut() -> Result<(), PodError>,
    ) -> Result<(), PodError> {
        self.recheck_child()?;
        journal.recheck_held_file()?;
        recheck()
    }

    /// Observe the retained direct-child handle. The outer None means the
    /// child was running at observation; an inner None means it exited by
    /// signal, which must not be reported as exit code zero.
    pub fn try_wait(&mut self) -> Result<Option<Option<i32>>, PodError> {
        if let Some(exit) = self.resource.observe_owned_child_exit()? {
            return self.checked_exit_code(exit).map(Some);
        }
        let live = self.recheck_child();
        if let Some(exit) = self.resource.observe_owned_child_exit()? {
            return self.checked_exit_code(exit).map(Some);
        }
        live?;
        Ok(None)
    }

    /// Stop only the exact observed direct child after checking its birth and
    /// pod cgroup. Success means the retained child handle observed a reap;
    /// the pod unit remains responsible for any descendant processes.
    pub fn stop(&mut self) -> Result<(), PodError> {
        if let Some(exit) = self.resource.observe_owned_child_exit()? {
            self.checked_exit_code(exit)?;
            return Ok(());
        }
        if let Err(live_error) = self.recheck_child() {
            if let Some(exit) = self.resource.observe_owned_child_exit()? {
                self.checked_exit_code(exit)?;
                return Ok(());
            }
            return Err(live_error);
        }
        let exit = self
            .resource
            .dispose_owned_child()
            .map_err(|_| PodError::Uncertain("Codex direct-child reap was not observed"))?;
        self.checked_exit_code(exit)?;
        Ok(())
    }

    fn checked_exit_code(&self, exit: ChildExitObservation) -> Result<Option<i32>, PodError> {
        if exit.pid != self.child_birth.pid {
            return Err(PodError::Refused("Codex child exit belongs to another PID"));
        }
        Ok(exit.status.code())
    }

    /// Recheck the same live direct child and exact pod boot/cgroup. A future
    /// command path must call this again at its own effect boundary.
    pub fn recheck_child(&mut self) -> Result<KernelChildBirthObservation, PodError> {
        let owner = LinuxPeerEvidence::for_current_process()
            .map_err(|_| PodError::Refused("pod process identity unavailable"))?;
        if owner.boot_id() != self.pod_boot_id || owner.cgroup() != self.pod_cgroup {
            return Err(PodError::Refused("pod boot or cgroup changed"));
        }
        let current = self
            .resource
            .attest_owned_child_birth()
            .map_err(|_| PodError::Refused("Codex child process is unavailable"))?;
        if current != self.child_birth {
            return Err(PodError::Refused("Codex child birth changed"));
        }
        require_child_in_pod(&current, &self.pod_boot_id, &self.pod_cgroup)?;
        Ok(current)
    }
}

fn flush_native_events_from(
    resource: &mut CodexResource<ProcessJsonlTransport>,
    events: &mut SegmentedNativeEventSpool,
) -> Result<(), PodError> {
    while resource.has_unspooled_native_notifications() {
        // Segmented output reserves its next durable source position before
        // the adapter notification can be taken from memory.
        let sequence = events.reserve_native_take()?;
        let observed = match resource.take_applied_native_notification() {
            Some(observed) => observed,
            None => {
                let _ = events.mark_continuity_unknown();
                return Err(PodError::Uncertain("native notification disappeared after take reservation"));
            }
        };
        let kind = match observed.kind() {
            NativeObservationKind::Status => NativeEventKind::Status,
            NativeObservationKind::Output => NativeEventKind::Output,
            NativeObservationKind::Question => NativeEventKind::Question,
            NativeObservationKind::Permission => NativeEventKind::Permission,
            NativeObservationKind::Opaque => NativeEventKind::Opaque,
        };
        let status = observed.status().map(|status| match status {
            NativeObservationStatus::Idle => NativeEventStatus::Idle,
            NativeObservationStatus::Active => NativeEventStatus::Active,
            NativeObservationStatus::Waiting => NativeEventStatus::Waiting,
            NativeObservationStatus::Completed => NativeEventStatus::Completed,
            NativeObservationStatus::Failed => NativeEventStatus::Failed,
            NativeObservationStatus::Interrupted => NativeEventStatus::Interrupted,
            NativeObservationStatus::SystemError => NativeEventStatus::SystemError,
        });
        let appended = events.append_applied(
            sequence, observed.private_jsonl(), kind, status, observed.external_conflict(),
        );
        if appended.is_err() {
            let _ = events.mark_continuity_unknown();
        }
        if !matches!(appended?, NativeEventAppend::Committed(_)) {
            return Err(PodError::Conflict("native event source sequence repeated"));
        }
    }
    Ok(())
}

fn recheck_native_child(
    resource: &mut CodexResource<ProcessJsonlTransport>,
    expected: &KernelChildBirthObservation,
    boot_id: &str,
    cgroup: &str,
) -> Result<(), PodError> {
    let owner = LinuxPeerEvidence::for_current_process()
        .map_err(|_| PodError::Refused("pod process identity unavailable"))?;
    if owner.boot_id() != boot_id || owner.cgroup() != cgroup {
        return Err(PodError::Refused("pod boot or cgroup changed"));
    }
    let current = resource.attest_owned_child_birth()
        .map_err(|_| PodError::Refused("Codex child process is unavailable"))?;
    if &current != expected { return Err(PodError::Refused("Codex child birth changed")); }
    require_child_in_pod(&current, boot_id, cgroup)
}

fn require_child_in_pod(
    child: &KernelChildBirthObservation,
    boot_id: &str,
    cgroup: &str,
) -> Result<(), PodError> {
    if child.pid == 0
        || child.start_ticks == 0
        || child.boot_id != boot_id
        || child.cgroup_path != cgroup
    {
        return Err(PodError::Refused(
            "Codex child differs from pod boot or cgroup",
        ));
    }
    Ok(())
}

fn submitted_from_view(view: &CodexJournalView) -> BootstrapControlStage {
    match (&view.native_thread_id, &view.native_session_id, &view.native_turn_id) {
        (Some(thread), Some(session), Some(turn)) => BootstrapControlStage::Submitted {
            native_thread_id: thread.clone(),
            native_session_id: session.clone(),
            native_turn_id: turn.clone(),
        },
        _ => BootstrapControlStage::ThreadCreateUncertain,
    }
}

fn bootstrap_uncertain_from_view(view: &CodexJournalView) -> BootstrapControlStage {
    match (&view.native_thread_id, &view.native_session_id) {
        (Some(thread), Some(session)) => BootstrapControlStage::BootstrapUncertain {
            native_thread_id: thread.clone(),
            native_session_id: session.clone(),
        },
        _ => BootstrapControlStage::ThreadCreateUncertain,
    }
}

fn conservative_prior_stage(view: &CodexJournalView) -> BootstrapControlStage {
    match view.stage {
        CodexJournalStage::ThreadCreated => match (&view.native_thread_id, &view.native_session_id) {
            (Some(thread), Some(session)) => BootstrapControlStage::ThreadCreated {
                native_thread_id: thread.clone(),
                native_session_id: session.clone(),
            },
            _ => BootstrapControlStage::ThreadCreateUncertain,
        },
        CodexJournalStage::BootstrapIntentDurable
        | CodexJournalStage::BootstrapUnknownAfterReopen
        | CodexJournalStage::BootstrapUncertain
        | CodexJournalStage::BootstrapSubmitted
        | CodexJournalStage::BootstrapCompletionObservedPendingIdleProof
        | CodexJournalStage::BootstrapFailed
        | CodexJournalStage::BootstrapInterrupted
        | CodexJournalStage::BootstrapCompleted => bootstrap_uncertain_from_view(view),
        _ => BootstrapControlStage::ThreadCreateUncertain,
    }
}

fn inspect_stage_from_journal_view(view: &CodexJournalView) -> Result<BootstrapControlStage, PodError> {
    let identities = || -> Result<(String, String), PodError> {
        Ok((
            view.native_thread_id.clone().ok_or(PodError::Uncertain("journal lacks thread ID"))?,
            view.native_session_id.clone().ok_or(PodError::Uncertain("journal lacks native Session ID"))?,
        ))
    };
    match view.stage {
        CodexJournalStage::Empty => Ok(BootstrapControlStage::ClaimedUnobserved),
        CodexJournalStage::ThreadCreateIntentDurable
        | CodexJournalStage::ThreadCreateUnknownAfterReopen =>
            Ok(BootstrapControlStage::ThreadCreateUncertain),
        CodexJournalStage::ThreadCreated => {
            let (native_thread_id, native_session_id) = identities()?;
            Ok(BootstrapControlStage::ThreadCreated { native_thread_id, native_session_id })
        }
        CodexJournalStage::BootstrapIntentDurable
        | CodexJournalStage::BootstrapUnknownAfterReopen
        | CodexJournalStage::BootstrapUncertain => {
            let (native_thread_id, native_session_id) = identities()?;
            Ok(BootstrapControlStage::BootstrapUncertain { native_thread_id, native_session_id })
        }
        CodexJournalStage::BootstrapSubmitted
        | CodexJournalStage::BootstrapCompletionObservedPendingIdleProof
        | CodexJournalStage::BootstrapFailed
        | CodexJournalStage::BootstrapInterrupted
        | CodexJournalStage::BootstrapCompleted => {
            let (native_thread_id, native_session_id) = identities()?;
            let native_turn_id = view.native_turn_id.clone()
                .ok_or(PodError::Uncertain("journal lacks native turn ID"))?;
            Ok(BootstrapControlStage::Submitted { native_thread_id, native_session_id, native_turn_id })
        }
        CodexJournalStage::StorageUncertain =>
            Err(PodError::Uncertain("Codex journal storage outcome unknown")),
    }
}

#[cfg(test)]
mod bootstrap_stage_tests {
    use super::*;

    fn view(stage: CodexJournalStage) -> CodexJournalView {
        CodexJournalView {
            stage,
            command_key: Some("command.fixture".into()),
            payload_digest: Some("a".repeat(64)),
            native_thread_id: Some("thread.fixture".into()),
            native_session_id: Some("session.fixture".into()),
            client_message_id: Some("message.fixture".into()),
            native_turn_id: Some("turn.fixture".into()),
        }
    }

    #[test]
    fn stale_authority_never_relabels_prior_intent_as_refused_before_effect() {
        assert_eq!(
            conservative_prior_stage(&view(CodexJournalStage::ThreadCreateIntentDurable)),
            BootstrapControlStage::ThreadCreateUncertain,
        );
        assert!(matches!(
            conservative_prior_stage(&view(CodexJournalStage::ThreadCreated)),
            BootstrapControlStage::ThreadCreated { .. }
        ));
        assert!(matches!(
            conservative_prior_stage(&view(CodexJournalStage::BootstrapSubmitted)),
            BootstrapControlStage::BootstrapUncertain { .. }
        ));
    }

    #[test]
    fn read_only_inspection_separates_empty_claim_from_fsynced_submission() {
        let mut empty = view(CodexJournalStage::Empty);
        empty.command_key = None;
        empty.payload_digest = None;
        empty.native_thread_id = None;
        empty.native_session_id = None;
        empty.native_turn_id = None;
        assert_eq!(
            inspect_stage_from_journal_view(&empty).unwrap(),
            BootstrapControlStage::ClaimedUnobserved,
        );
        assert_eq!(
            inspect_stage_from_journal_view(&view(CodexJournalStage::BootstrapSubmitted)).unwrap(),
            BootstrapControlStage::Submitted {
                native_thread_id: "thread.fixture".into(),
                native_session_id: "session.fixture".into(),
                native_turn_id: "turn.fixture".into(),
            },
        );
    }
}

#[cfg(test)]
mod native_format_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn identity() -> NativeEventIdentity {
        NativeEventIdentity {
            store_lineage: "lineage.fixture".into(), scope_id: "scope.fixture".into(),
            session_id: "session.fixture".into(), run_id: "run.fixture".into(),
            attempt_id: "attempt.fixture".into(), pod_id: "pod.fixture".into(),
            pod_incarnation: 1, resource_id: "resource.fixture".into(), resource_epoch: 1,
        }
    }

    #[test]
    fn old_native_log_is_refused_without_creating_a_checkpoint() {
        let root = std::env::temp_dir().join(format!(
            "podbay-native-format-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let old = root.join("codex.native-events.log");
        fs::write(&old, []).unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(open_current_native_events(&root, identity()), Err(PodError::Unsupported(_))));
        assert!(!root.join("native-events.checkpoint").exists());
        fs::remove_dir_all(root).unwrap();
    }
}

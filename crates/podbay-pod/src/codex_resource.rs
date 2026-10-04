//! Pod-owned structured Codex child startup after exact V2 manifest review.
//! Initialize is transport evidence only: no thread, turn, or provider
//! readiness is inferred here.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podbay_adapter_codex::{
    ApprovalPolicy, BlockReason, BootstrapTurnStage, ChildExitObservation, ChildLaunchSpec,
    CodexError, CodexResource,
    KernelChildBirthObservation, PinnedCodexConfig, ProcessJsonlTransport, ResourceIdentity,
    Sandbox, WriterPermit,
};
use podbay_core::{AttemptId, Epoch, PodId, ResourceId, RunId, SessionId};
use podbay_store::BootstrapSendRecord;
use podbay_wire::{
    EffectiveLaunchContractV2, ImmutableLaunchDescriptorV2, NativeResourceKind, ResourceDriver,
    TargetOs,
};

use crate::codex_credential::{
    CODEX_AUTH_CREDENTIAL_NAME, PreparedCodexHome, prepare_codex_home_from_systemd_credential,
};
use crate::codex_bootstrap::BootstrapControlStage;
use crate::codex_journal::{CodexCommandJournal, CodexJournalIdentity, CodexJournalIntentResult, CodexJournalStage, CodexJournalView};
use crate::linux_peer::LinuxPeerEvidence;
use crate::manifest::{
    BoundPeerManifest, CODEX_V2_CAPABILITY, LaunchDescriptor, PEER_BINDING_V2_PROTOCOL, PodError,
    manifest_path, private_directory, unit_name,
};
use crate::ports::DurableFiles;

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
        if binding.protocol != PEER_BINDING_V2_PROTOCOL || binding.capability != CODEX_V2_CAPABILITY
        {
            return Err(PodError::Unsupported("Codex V2 peer binding is required"));
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

/// Owns the structured adapter and its direct child. Exposes lifecycle
/// observation and bounded disposal, but cannot submit a model turn.
pub struct PodCodexResource {
    resource: CodexResource<ProcessJsonlTransport>,
    journal: Option<CodexCommandJournal>,
    journal_path: PathBuf,
    child_birth: KernelChildBirthObservation,
    pod_boot_id: String,
    pod_cgroup: String,
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
        if home.isolated_home() != launch.pod_directory.join("home")
            || home.codex_home() != launch.pod_directory.join("home/codex")
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
            journal_path: launch.pod_directory.join("codex.commands.log"),
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
            CodexJournalStage::BootstrapSubmitted | CodexJournalStage::BootstrapCompleted => {
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
                    BootstrapControlStage::Submitted {
                        native_thread_id: thread_id,
                        native_session_id: session_id,
                        native_turn_id: turn_id,
                    }
                }
                BootstrapTurnStage::Uncertain => {
                    let _ = journal.record_bootstrap_uncertain(key, digest);
                    BootstrapControlStage::BootstrapUncertain {
                        native_thread_id: thread_id,
                        native_session_id: session_id,
                    }
                }
            },
            Err(_) => {
                let _ = journal.record_bootstrap_uncertain(key, digest);
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
        | CodexJournalStage::BootstrapCompleted => bootstrap_uncertain_from_view(view),
        _ => BootstrapControlStage::ThreadCreateUncertain,
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
}

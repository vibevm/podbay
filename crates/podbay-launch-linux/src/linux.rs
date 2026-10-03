use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use podbay_host::{
    AuthorisedBoundLaunch, AuthorisedDispatch, HostDispatchPort, PortDispatchError,
    PortDispatchOutcome, PortReceiptRef, ResolvedNativeLaunch,
};
use podbay_pod::{BoundPodStatus, LinuxPeerEvidence, PodError, PodPeerBootstrap};
use podbay_store::{BoundLaunchRecord, EffectState, LaunchDispatchStage, PodBayStore};
use podbay_wire::{NativeResourceKind, NativeRole, NativeWorkKind, ResourceDriver, TargetOs};
use sha2::{Digest, Sha256};

/// Trusted host configuration. This adapter supports only the explicit local
/// synthetic sleep fixture; pinning is cooperative, not same-UID isolation.
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
}

impl LinuxLaunchPort {
    pub fn new(config: TrustedLinuxLaunchConfig) -> Self {
        Self { config }
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
}

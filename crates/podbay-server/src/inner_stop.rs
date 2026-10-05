//! One authenticated local root stop. The SQLite outbox claim is durable
//! before the sole PodClient stop call; retries only inspect terminal proof.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use podbay_core::{AttemptId, Epoch, PodId, ScopeId};
use podbay_host::{
    AuthenticatedTransport, CredentialRef, DurableAuthority, HostDispatchPort,
    ResolvedNativeCodexLaunch, TrustedWireRootLaunchPolicy,
};
use podbay_pod::{CODEX_V2_CAPABILITY, PodClient, PodManifest, manifest_path_for_identity};
use podbay_store::{EffectState, Receipt as StoreReceipt};
use podbay_wire::{
    CommandBody, CommandEnvelope, CommandStage, DecimalString, EventCursor, ProtocolVersion,
    Receipt, RuntimeError, RuntimeErrorCode, StopScope, Target,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopIntent {
    schema: String,
    stop_key: String,
    actor_id: String,
    scope_id: String,
    run_id: String,
    pod_id: String,
    attempt_id: String,
    pod_incarnation: u64,
    credential_ref: String,
    profile_ref: String,
    profile_generation: u64,
    lifetime: podbay_wire::LifetimeLimit,
    launch_command_id: String,
    store_lineage: String,
    descriptor_digest: String,
    manifest_digest: String,
    unit_name: String,
    socket_dev: u64,
    socket_ino: u64,
    supervisor_pid: u32,
    supervisor_birth: u64,
    child_pid: u32,
    child_birth: u64,
}

fn error(code: RuntimeErrorCode, message: &str, command_id: Option<String>) -> RuntimeError {
    RuntimeError {
        code,
        message: message.into(),
        retry: if command_id.is_some() {
            "query_command"
        } else {
            "never"
        }
        .into(),
        command_id,
    }
}

fn path(directory: &Path, intent: &StopIntent) -> Result<std::path::PathBuf, RuntimeError> {
    let pod = PodId::try_from(intent.pod_id.as_str()).map_err(|_| {
        error(
            RuntimeErrorCode::StorageFailure,
            "stop Pod ID changed",
            None,
        )
    })?;
    let attempt = AttemptId::try_from(intent.attempt_id.as_str()).map_err(|_| {
        error(
            RuntimeErrorCode::StorageFailure,
            "stop Attempt ID changed",
            None,
        )
    })?;
    let incarnation = Epoch::new(intent.pod_incarnation).map_err(|_| {
        error(
            RuntimeErrorCode::StorageFailure,
            "stop incarnation changed",
            None,
        )
    })?;
    Ok(manifest_path_for_identity(
        directory,
        &pod,
        &attempt,
        incarnation,
    ))
}

fn unit_state(unit: &str) -> Result<(String, u32), RuntimeError> {
    let output = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "--property=LoadState",
            "--property=MainPID",
            unit,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| {
            error(
                RuntimeErrorCode::Unavailable,
                "stop unit observation unavailable",
                None,
            )
        })?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(error(
            RuntimeErrorCode::Unavailable,
            "stop unit observation unavailable",
            None,
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "stop unit observation malformed",
            None,
        )
    })?;
    let mut load = None;
    let mut pid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            if load.replace(value.to_owned()).is_some() {
                return Err(error(
                    RuntimeErrorCode::Unavailable,
                    "duplicate unit state",
                    None,
                ));
            }
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            if pid
                .replace(value.parse::<u32>().map_err(|_| {
                    error(RuntimeErrorCode::Unavailable, "unit PID malformed", None)
                })?)
                .is_some()
            {
                return Err(error(
                    RuntimeErrorCode::Unavailable,
                    "duplicate unit PID",
                    None,
                ));
            }
        } else {
            return Err(error(
                RuntimeErrorCode::Unavailable,
                "unit observation changed",
                None,
            ));
        }
    }
    Ok((
        load.ok_or_else(|| error(RuntimeErrorCode::Unavailable, "unit state missing", None))?,
        pid.ok_or_else(|| error(RuntimeErrorCode::Unavailable, "unit PID missing", None))?,
    ))
}

fn birth_matches(pid: u32, birth: u64) -> Result<bool, RuntimeError> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(io) if io.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {
            return Err(error(
                RuntimeErrorCode::Unavailable,
                "process observation unavailable",
                None,
            ));
        }
    };
    let observed = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            error(
                RuntimeErrorCode::Unavailable,
                "process birth malformed",
                None,
            )
        })?;
    Ok(observed == birth)
}

fn read_manifest(
    directory: &Path,
    intent: &StopIntent,
) -> Result<(std::path::PathBuf, PodManifest), RuntimeError> {
    let path = path(directory, intent)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "stop manifest unavailable",
            None,
        )
    })?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 65_536
        || fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
    {
        return Err(error(
            RuntimeErrorCode::Unavailable,
            "stop manifest identity changed",
            None,
        ));
    }
    let manifest: PodManifest = serde_json::from_slice(&fs::read(&path).map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "stop manifest unreadable",
            None,
        )
    })?)
    .map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "stop manifest malformed",
            None,
        )
    })?;
    if manifest.digest != intent.manifest_digest
        || manifest.unit_name != intent.unit_name
        || manifest.descriptor.pod_id != intent.pod_id
        || manifest.descriptor.attempt_id != intent.attempt_id
        || manifest.descriptor.incarnation != intent.pod_incarnation
        || manifest.socket_path != path.with_extension("sock")
        || manifest.peer_binding.as_ref().is_none_or(|binding| {
            binding.capability != CODEX_V2_CAPABILITY
                || binding.descriptor_digest != intent.descriptor_digest
                || binding.store_lineage != intent.store_lineage
        })
    {
        return Err(error(
            RuntimeErrorCode::StaleGuard,
            "stop manifest differs from intent",
            None,
        ));
    }
    Ok((path, manifest))
}

fn prepare(
    directory: &Path,
    reviewed: &ResolvedNativeCodexLaunch,
    key: &str,
) -> Result<(StopIntent, PodClient), RuntimeError> {
    let descriptor = reviewed.descriptor();
    let resource = descriptor
        .resource(0)
        .ok_or_else(|| error(RuntimeErrorCode::StaleGuard, "stop resource missing", None))?;
    let stub = StopIntent {
        schema: "podbay.inner-stop-intent/1".into(),
        stop_key: key.into(),
        actor_id: descriptor.actor_id().into(),
        scope_id: descriptor.scope_id().into(),
        run_id: descriptor.run_id().into(),
        pod_id: descriptor.pod_id().into(),
        attempt_id: descriptor.attempt_id().into(),
        pod_incarnation: descriptor.pod_incarnation(),
        credential_ref: descriptor.credential_refs()[0].clone(),
        profile_ref: descriptor.profile_ref().into(),
        profile_generation: descriptor.profile_generation(),
        lifetime: descriptor.lifetime(),
        launch_command_id: reviewed.committed_record().receipt.command_id.clone(),
        store_lineage: reviewed.store_lineage().into(),
        descriptor_digest: descriptor.digest().into(),
        manifest_digest: String::new(),
        unit_name: String::new(),
        socket_dev: 0,
        socket_ino: 0,
        supervisor_pid: 0,
        supervisor_birth: 0,
        child_pid: 0,
        child_birth: 0,
    };
    let manifest_path = path(directory, &stub)?;
    let client = PodClient::connect(&manifest_path).map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "current stop Pod unavailable",
            None,
        )
    })?;
    let status = client.attested_status().map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "current stop Pod unattested",
            None,
        )
    })?;
    let metadata = fs::symlink_metadata(manifest_path.with_extension("sock")).map_err(|_| {
        error(
            RuntimeErrorCode::Unavailable,
            "stop socket unavailable",
            None,
        )
    })?;
    let (_, manifest): (std::path::PathBuf, PodManifest) = {
        let bytes = fs::read(&manifest_path).map_err(|_| {
            error(
                RuntimeErrorCode::Unavailable,
                "stop manifest unavailable",
                None,
            )
        })?;
        (
            manifest_path.clone(),
            serde_json::from_slice(&bytes).map_err(|_| {
                error(
                    RuntimeErrorCode::Unavailable,
                    "stop manifest malformed",
                    None,
                )
            })?,
        )
    };
    let bound = status.bound.as_ref().ok_or_else(|| {
        error(
            RuntimeErrorCode::StaleGuard,
            "stop peer binding missing",
            None,
        )
    })?;
    if !status.child_running
        || status.pod_id != stub.pod_id
        || status.attempt_id != stub.attempt_id
        || status.incarnation != stub.pod_incarnation
        || status.manifest_digest != manifest.digest
        || status.unit_name != manifest.unit_name
        || bound.capability != CODEX_V2_CAPABILITY
        || bound.descriptor_digest != stub.descriptor_digest
        || bound.resource_id != resource.resource_id
        || bound.resource_epoch != resource.epoch
        || bound.scope_id != stub.scope_id
        || bound.store_lineage != stub.store_lineage
        || bound.owner_epoch != reviewed.owner_epoch()
        || bound.credential_epoch != reviewed.credential_epoch()
        || !metadata.file_type().is_socket()
        || metadata.ino() == 0
        || status.supervisor_pid == 0
        || status.supervisor_start_ticks == 0
        || status.child_pid == 0
        || status.child_start_ticks == 0
    {
        return Err(error(
            RuntimeErrorCode::StaleGuard,
            "stop Pod differs from committed launch",
            None,
        ));
    }
    let (load, pid) = unit_state(&status.unit_name)?;
    if load != "loaded"
        || pid != status.supervisor_pid
        || !birth_matches(pid, status.supervisor_start_ticks)?
        || !birth_matches(status.child_pid, status.child_start_ticks)?
    {
        return Err(error(
            RuntimeErrorCode::StaleGuard,
            "stop unit or process birth changed",
            None,
        ));
    }
    Ok((
        StopIntent {
            manifest_digest: manifest.digest,
            unit_name: manifest.unit_name,
            socket_dev: metadata.dev(),
            socket_ino: metadata.ino(),
            supervisor_pid: status.supervisor_pid,
            supervisor_birth: status.supervisor_start_ticks,
            child_pid: status.child_pid,
            child_birth: status.child_start_ticks,
            ..stub
        },
        client,
    ))
}

fn terminal(directory: &Path, intent: &StopIntent) -> Result<bool, RuntimeError> {
    let (path, _) = read_manifest(directory, intent)?;
    let (load, pid) = unit_state(&intent.unit_name)?;
    if load != "not-found" {
        if pid == 0 {
            return Ok(false);
        }
        if pid != intent.supervisor_pid || !birth_matches(pid, intent.supervisor_birth)? {
            return Err(error(
                RuntimeErrorCode::StaleGuard,
                "stop unit was substituted",
                None,
            ));
        }
        return Ok(false);
    }
    if pid != 0
        || birth_matches(intent.supervisor_pid, intent.supervisor_birth)?
        || birth_matches(intent.child_pid, intent.child_birth)?
    {
        return Ok(false);
    }
    let socket = path.with_extension("sock");
    if socket.exists() {
        let metadata = fs::symlink_metadata(&socket).map_err(|_| {
            error(
                RuntimeErrorCode::Unavailable,
                "stop socket observation failed",
                None,
            )
        })?;
        if !metadata.file_type().is_socket()
            || (metadata.dev(), metadata.ino()) != (intent.socket_dev, intent.socket_ino)
        {
            return Err(error(
                RuntimeErrorCode::StaleGuard,
                "stop socket was substituted",
                None,
            ));
        }
        fs::remove_file(&socket).map_err(|_| {
            error(
                RuntimeErrorCode::Unavailable,
                "stale stop socket cleanup failed",
                None,
            )
        })?;
        fs::File::open(directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| {
                error(
                    RuntimeErrorCode::Unavailable,
                    "stop directory sync failed",
                    None,
                )
            })?;
    }
    Ok(!socket.exists())
}

fn wait_terminal(directory: &Path, intent: &StopIntent) -> Result<bool, RuntimeError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if terminal(directory, intent)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn project<P: HostDispatchPort>(
    authority: &DurableAuthority<P>,
    receipt: StoreReceipt,
    effect: EffectState,
    observation: Option<i64>,
    scope: &str,
    pod: &str,
    duplicate: bool,
) -> Result<Receipt<Value>, RuntimeError> {
    let sequence = observation.unwrap_or(receipt.event_sequence);
    let sequence = u64::try_from(sequence).map_err(|_| {
        error(
            RuntimeErrorCode::StorageFailure,
            "stop event cursor invalid",
            Some(receipt.command_id.clone()),
        )
    })?;
    let response = Receipt {
        protocol: ProtocolVersion::V1,
        command_id: receipt.command_id,
        state: if effect == EffectState::Observed {
            CommandStage::Settled
        } else {
            CommandStage::Uncertain
        },
        value: json!({"podId":pod,"effectState":if effect == EffectState::Observed { "pod_stopped" } else { "claimed_uncertain" },
            "duplicate":duplicate,"portCalled":!duplicate}),
        revision: DecimalString::new(sequence),
        cursor: EventCursor {
            store_lineage: authority.store_lineage_for_receipt().into(),
            scope_id: scope.into(),
            sequence: DecimalString::new(sequence),
        },
    };
    Ok(response)
}

pub(crate) fn dispatch<P: HostDispatchPort, T: AuthenticatedTransport>(
    authority: &mut DurableAuthority<P>,
    transport: &T,
    request: CommandEnvelope,
    policy: &TrustedWireRootLaunchPolicy,
    directory: &Path,
) -> Result<Receipt<Value>, RuntimeError> {
    let Target::Run { run_id } = &request.target else {
        return Err(error(
            RuntimeErrorCode::InvalidInput,
            "exact Run target required",
            None,
        ));
    };
    let CommandBody::RunStop(body) = &request.body else {
        return Err(error(
            RuntimeErrorCode::InvalidInput,
            "run.stop body required",
            None,
        ));
    };
    if body.scope != StopScope::SelfOnly {
        return Err(error(
            RuntimeErrorCode::Forbidden,
            "only self_only root stop is available",
            None,
        ));
    }
    let pod = PodId::try_from(body.pod_id.as_deref().ok_or_else(|| {
        error(
            RuntimeErrorCode::InvalidInput,
            "exact Pod ID required",
            None,
        )
    })?)
    .map_err(|_| error(RuntimeErrorCode::InvalidInput, "Pod ID invalid", None))?;
    let existing = authority
        .lookup_inner_codex_stop(transport, &request, &pod)
        .map_err(|_| {
            error(
                RuntimeErrorCode::Forbidden,
                "stop caller or key unavailable",
                None,
            )
        })?;
    if let Some((receipt, effect, actor, scope)) = existing {
        let intent: StopIntent = serde_json::from_slice(&effect.payload).map_err(|_| {
            error(
                RuntimeErrorCode::StorageFailure,
                "stop intent malformed",
                Some(receipt.command_id.clone()),
            )
        })?;
        if intent.schema != "podbay.inner-stop-intent/1"
            || intent.stop_key != request.key
            || intent.actor_id != actor.as_str()
            || intent.scope_id != scope.as_str()
            || intent.run_id != *run_id
            || intent.pod_id != pod.as_str()
            || intent.store_lineage != authority.store_lineage_for_receipt()
            || effect.target_id != pod.as_str()
        {
            return Err(error(
                RuntimeErrorCode::Conflict,
                "stop intent identity changed",
                Some(receipt.command_id),
            ));
        }
        let credential = CredentialRef::from_trusted_vault(scope.clone(), &intent.credential_ref)
            .map_err(|_| {
            error(
                RuntimeErrorCode::StorageFailure,
                "stop credential intent invalid",
                Some(receipt.command_id.clone()),
            )
        })?;
        authority
            .review_inner_codex_stop_retry(
                transport,
                policy,
                &actor,
                &scope,
                &credential,
                &intent.profile_ref,
                intent.profile_generation,
                intent.lifetime,
            )
            .map_err(|_| {
                error(
                    RuntimeErrorCode::Forbidden,
                    "stop retry authority unavailable",
                    Some(receipt.command_id.clone()),
                )
            })?;
        let stopped = if effect.state == EffectState::ClaimedUncertain {
            wait_terminal(directory, &intent).map_err(|cause| {
                error(
                    RuntimeErrorCode::Uncertain,
                    &format!("stop observation unavailable: {}", cause.message),
                    Some(receipt.command_id.clone()),
                )
            })?
        } else {
            false
        };
        if stopped {
            let evidence = serde_json::to_vec(
                &json!({"kind":"pod_stopped","intentCommandId":receipt.command_id}),
            )
            .map_err(|_| {
                error(
                    RuntimeErrorCode::StorageFailure,
                    "stop evidence encoding failed",
                    Some(receipt.command_id.clone()),
                )
            })?;
            let sequence = authority
                .observe_inner_codex_stop(&receipt, &scope, &pod, intent.pod_incarnation, &evidence)
                .map_err(|_| {
                    error(
                        RuntimeErrorCode::StorageFailure,
                        "stop terminal receipt unavailable",
                        Some(receipt.command_id.clone()),
                    )
                })?;
            return project(
                authority,
                receipt,
                EffectState::Observed,
                Some(sequence),
                scope.as_str(),
                pod.as_str(),
                true,
            );
        }
        return project(
            authority,
            receipt,
            effect.state,
            effect.observation_event_sequence,
            scope.as_str(),
            pod.as_str(),
            true,
        );
    }
    let reviewed = authority
        .review_current_inner_codex_stop(transport, &request, policy)
        .map_err(|_| {
            error(
                RuntimeErrorCode::Forbidden,
                "exact current Service stop refused",
                None,
            )
        })?;
    let scope = ScopeId::try_from(reviewed.descriptor().scope_id())
        .map_err(|_| error(RuntimeErrorCode::StaleGuard, "stop scope invalid", None))?;
    let (intent, client) = prepare(directory, &reviewed, &request.key)?;
    if intent.run_id != *run_id || intent.pod_id != pod.as_str() {
        return Err(error(
            RuntimeErrorCode::StaleGuard,
            "stop Run or Pod changed",
            None,
        ));
    }
    let bytes = serde_json::to_vec(&intent).map_err(|_| {
        error(
            RuntimeErrorCode::StorageFailure,
            "stop intent encoding failed",
            None,
        )
    })?;
    let (receipt, duplicate) = authority
        .admit_inner_codex_stop(transport, &request, &reviewed, bytes)
        .map_err(|_| {
            error(
                RuntimeErrorCode::StorageFailure,
                "stop intent admission failed",
                None,
            )
        })?;
    if duplicate {
        return Err(error(
            RuntimeErrorCode::Uncertain,
            "stop duplicate requires readback",
            Some(receipt.command_id),
        ));
    }
    let stop_result = client.stop();
    #[cfg(debug_assertions)]
    if std::env::var_os("PODBAY_TEST_INNER_STOP_DROP_REPLY").is_some() {
        let _ = stop_result;
        return Err(error(
            RuntimeErrorCode::Uncertain,
            "test-only lost stop reply",
            Some(receipt.command_id),
        ));
    }
    if !wait_terminal(directory, &intent).map_err(|cause| {
        error(
            RuntimeErrorCode::Uncertain,
            &format!("stop observation unavailable: {}", cause.message),
            Some(receipt.command_id.clone()),
        )
    })? {
        return Err(error(
            RuntimeErrorCode::Uncertain,
            &format!("stop remains uncertain after one Pod call: {stop_result:?}"),
            Some(receipt.command_id),
        ));
    }
    let evidence =
        serde_json::to_vec(&json!({"kind":"pod_stopped","intentCommandId":receipt.command_id}))
            .map_err(|_| {
                error(
                    RuntimeErrorCode::StorageFailure,
                    "stop evidence encoding failed",
                    Some(receipt.command_id.clone()),
                )
            })?;
    let sequence = authority
        .observe_inner_codex_stop(&receipt, &scope, &pod, intent.pod_incarnation, &evidence)
        .map_err(|_| {
            error(
                RuntimeErrorCode::StorageFailure,
                "stop terminal receipt unavailable",
                Some(receipt.command_id.clone()),
            )
        })?;
    project(
        authority,
        receipt,
        EffectState::Observed,
        Some(sequence),
        scope.as_str(),
        pod.as_str(),
        false,
    )
}

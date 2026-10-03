//! PB06 raw PTY observation and input leases. No TUI application meaning is inferred.
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use vt100::Parser;

use crate::manifest::{LaunchDescriptor, PodError, PtySpec, hex};
use crate::ports::TerminalResource;
use crate::spool::{CommandStage, PodSpool, digest_command};

pub use crate::terminal_protocol::*;

struct LeaseState {
    view: InputLease,
    deadline: Instant,
}
struct TerminalState {
    parser: Parser,
    fidelity: ScreenFidelity,
    rows: u16,
    cols: u16,
    revision: u64,
    sequence: u64,
    byte_position: u64,
    events: VecDeque<TerminalEvent>,
    retention: usize,
    lease_epoch: u64,
    lease: Option<LeaseState>,
    spool: Option<PodSpool>,
}

#[derive(Clone)]
pub struct TerminalProjection {
    resource_id: String,
    incarnation: u64,
    state: Arc<Mutex<TerminalState>>,
}

impl TerminalProjection {
    pub fn new(resource_id: String, incarnation: u64, spec: PtySpec) -> Self {
        Self {
            resource_id,
            incarnation,
            state: Arc::new(Mutex::new(TerminalState {
                parser: Parser::new(spec.rows, spec.cols, 0),
                fidelity: ScreenFidelity::Partial {
                    reason: "PB06 parser profile and disk checkpoint are not yet verified".into(),
                },
                rows: spec.rows,
                cols: spec.cols,
                revision: 0,
                sequence: 0,
                byte_position: 0,
                events: VecDeque::new(),
                retention: spec.retention_events,
                lease_epoch: 0,
                lease: None,
                spool: None,
            })),
        }
    }

    fn with_spool(
        resource_id: String,
        incarnation: u64,
        spec: PtySpec,
        manifest_path: &Path,
    ) -> Result<Self, PodError> {
        let result = Self::new(resource_id, incarnation, spec);
        let spool = PodSpool::open(
            manifest_path,
            spec.retention_events,
            &result.resource_id,
            incarnation,
        )?;
        // A previous pod process is not reattached here. Its WAL is retained
        // as evidence, and fresh child admission must not rewrite that history.
        if spool.has_history() || !spool.integrity() {
            return Err(PodError::Uncertain(
                "prior PTY spool requires explicit recovery",
            ));
        }
        result.state.lock().expect("terminal state poisoned").spool = Some(spool);
        Ok(result)
    }

    pub fn apply_output(&self, bytes: &[u8]) {
        let mut state = self.state.lock().expect("terminal state poisoned");
        for chunk in bytes.chunks(4_096) {
            let event = TerminalEvent {
                sequence: state.sequence + 1,
                resource_id: self.resource_id.clone(),
                incarnation: self.incarnation,
                value: TerminalEventKind::Output {
                    bytes: chunk.to_vec(),
                    source_byte_position: state.byte_position + chunk.len() as u64,
                },
            };
            if let Some(spool) = &mut state.spool
                && spool.append_event(&event).is_err()
            {
                state.fidelity = ScreenFidelity::Unknown {
                    reason: "PTY output WAL did not commit".into(),
                };
                return;
            }
            state.parser.process(chunk);
            state.byte_position += chunk.len() as u64;
            state.revision += 1;
            state.sequence += 1;
            retain(&mut state, event);
            if checkpoint_spool(&mut state).is_err() {
                state.fidelity = ScreenFidelity::Unknown {
                    reason: "PTY screen checkpoint failed".into(),
                };
                return;
            }
        }
    }

    pub fn mark_unknown(&self, reason: &str) {
        let mut state = self.state.lock().expect("terminal state poisoned");
        state.fidelity = ScreenFidelity::Unknown {
            reason: reason.into(),
        };
    }

    pub fn snapshot(&self) -> TerminalView {
        let state = self.state.lock().expect("terminal state poisoned");
        let screen = state.parser.screen();
        let (cursor_row, cursor_col) = screen.cursor_position();
        let mut plain_text = screen.contents();
        let mut formatted_bytes = screen.contents_formatted();
        let truncated = plain_text.len() > 64 * 1_024 || formatted_bytes.len() > 128 * 1_024;
        if plain_text.len() > 64 * 1_024 {
            let mut end = 64 * 1_024;
            while !plain_text.is_char_boundary(end) {
                end -= 1;
            }
            plain_text.truncate(end);
        }
        formatted_bytes.truncate(128 * 1_024);
        let checkpoint = ScreenCheckpoint {
            parser_version: "vt100/0.16.2-pb06".into(),
            revision: state.revision,
            through: state.sequence,
            source_byte_position: state.byte_position,
            rows: state.rows,
            cols: state.cols,
            cursor_row,
            cursor_col,
            alternate_screen: screen.alternate_screen(),
            plain_text,
            formatted_bytes,
            fidelity: if truncated {
                ScreenFidelity::Partial {
                    reason: "PB06 current-screen representation exceeded its response bound".into(),
                }
            } else {
                state.fidelity.clone()
            },
        };
        TerminalView {
            resource_id: self.resource_id.clone(),
            incarnation: self.incarnation,
            through: state.sequence,
            screen: checkpoint,
        }
    }

    pub fn events_after(&self, after: u64, limit: usize) -> Result<TerminalEventPage, PodError> {
        if !(1..=256).contains(&limit) {
            return Err(PodError::Invalid("terminal event page limit"));
        }
        let state = self.state.lock().expect("terminal state poisoned");
        if after > state.sequence {
            return Err(PodError::Refused("terminal cursor is ahead of source"));
        }
        let first = state
            .events
            .front()
            .map_or(state.sequence + 1, |event| event.sequence);
        let gap = if after.saturating_add(1) < first {
            Some(first)
        } else {
            None
        };
        let mut events = Vec::new();
        let mut bytes = 0_usize;
        for event in state.events.iter().filter(|event| event.sequence > after) {
            let size = match &event.value {
                TerminalEventKind::Output { bytes, .. } => bytes.len(),
                TerminalEventKind::Resize { .. } => 32,
            };
            if events.len() >= limit || (!events.is_empty() && bytes + size > 64 * 1_024) {
                break;
            }
            bytes += size;
            events.push(event.clone());
        }
        let next_cursor = events.last().map_or(after, |event| event.sequence);
        Ok(TerminalEventPage {
            events,
            through: state.sequence,
            next_cursor,
            has_more: next_cursor < state.sequence,
            gap,
        })
    }

    pub fn acquire(
        &self,
        actor_id: &str,
        kind: LeaseKind,
        expected_epoch: u64,
        ttl_ms: u64,
    ) -> Result<InputLease, PodError> {
        if actor_id.len() < 3 || actor_id.len() > 160 || !(100..=30_000).contains(&ttl_ms) {
            return Err(PodError::Invalid("input lease actor or TTL"));
        }
        let mut state = self.state.lock().expect("terminal state poisoned");
        if expected_epoch != state.lease_epoch {
            return Err(PodError::Refused("input epoch is stale"));
        }
        if state
            .lease
            .as_ref()
            .is_some_and(|lease| lease.deadline > Instant::now())
            && kind != LeaseKind::Human
        {
            return Err(PodError::Refused("input lease already held"));
        }
        state.lease_epoch += 1;
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let expires_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PodError::Invalid("system time"))?
            .as_millis() as u64
            + ttl_ms;
        let view = InputLease {
            lease_id: format!("lease.{}", hex(&random)),
            resource_id: self.resource_id.clone(),
            incarnation: self.incarnation,
            actor_id: actor_id.into(),
            kind,
            epoch: state.lease_epoch,
            expires_at_ms,
        };
        state.lease = Some(LeaseState {
            view: view.clone(),
            deadline: Instant::now() + Duration::from_millis(ttl_ms),
        });
        Ok(view)
    }

    pub fn require_lease(
        &self,
        actor_id: &str,
        lease_id: &str,
        epoch: u64,
    ) -> Result<(), PodError> {
        let state = self.state.lock().expect("terminal state poisoned");
        let lease = state
            .lease
            .as_ref()
            .ok_or(PodError::Refused("input lease absent"))?;
        if lease.deadline <= Instant::now()
            || lease.view.actor_id != actor_id
            || lease.view.lease_id != lease_id
            || lease.view.epoch != epoch
            || state.lease_epoch != epoch
            || lease.view.resource_id != self.resource_id
            || lease.view.incarnation != self.incarnation
        {
            return Err(PodError::Refused("input lease stale or outside resource"));
        }
        Ok(())
    }

    pub fn release(&self, actor_id: &str, lease_id: &str, epoch: u64) -> Result<(), PodError> {
        self.require_lease(actor_id, lease_id, epoch)?;
        self.state.lock().expect("terminal state poisoned").lease = None;
        Ok(())
    }

    pub fn resize_with(
        &self,
        rows: u16,
        cols: u16,
        physical_resize: impl FnOnce() -> Result<(), PodError>,
    ) -> Result<(), PodError> {
        let mut state = self.state.lock().expect("terminal state poisoned");
        // The reader cannot append post-resize output until the geometry event
        // follows the actual master resize under this same projection barrier.
        physical_resize()?;
        let event = TerminalEvent {
            sequence: state.sequence + 1,
            resource_id: self.resource_id.clone(),
            incarnation: self.incarnation,
            value: TerminalEventKind::Resize { rows, cols },
        };
        if let Some(spool) = &mut state.spool
            && spool.append_event(&event).is_err()
        {
            state.fidelity = ScreenFidelity::Unknown {
                reason: "PTY resize WAL did not commit".into(),
            };
            return Err(PodError::Uncertain(
                "PTY resize occurred without durable event",
            ));
        }
        state.rows = rows;
        state.cols = cols;
        state.parser.screen_mut().set_size(rows, cols);
        state.revision += 1;
        state.sequence += 1;
        retain(&mut state, event);
        if checkpoint_spool(&mut state).is_err() {
            state.fidelity = ScreenFidelity::Unknown {
                reason: "PTY screen checkpoint failed".into(),
            };
            return Err(PodError::Uncertain(
                "PTY resize event committed but checkpoint failed",
            ));
        }
        Ok(())
    }

    fn durable_effect(
        &self,
        command_id: &str,
        digest: &str,
        actor: &str,
        lease: &str,
        epoch: u64,
        kind: &str,
        effect: impl FnOnce() -> Result<(), PodError>,
    ) -> Result<(), PodError> {
        {
            let mut state = self.state.lock().expect("terminal state poisoned");
            let spool = state
                .spool
                .as_mut()
                .ok_or(PodError::Uncertain("PTY spool absent"))?;
            match spool.lookup_command(command_id, digest)? {
                Some(CommandStage::BytesWritten) => return Ok(()),
                Some(CommandStage::Intent | CommandStage::Uncertain) => {
                    return Err(PodError::Uncertain(
                        "PTY command outcome unknown; do not replay",
                    ));
                }
                None => {}
            }
        }
        self.require_lease(actor, lease, epoch)?;
        {
            let mut state = self.state.lock().expect("terminal state poisoned");
            state.spool.as_mut().unwrap().record_command(
                command_id,
                digest,
                &self.resource_id,
                self.incarnation,
                epoch,
                kind,
                CommandStage::Intent,
            )?;
        }
        effect()?;
        let mut state = self.state.lock().expect("terminal state poisoned");
        state.spool.as_mut().unwrap().record_command(
            command_id,
            digest,
            &self.resource_id,
            self.incarnation,
            epoch,
            kind,
            CommandStage::BytesWritten,
        )
    }
}

fn retain(state: &mut TerminalState, event: TerminalEvent) {
    state.events.push_back(event);
    while state.events.len() > state.retention {
        state.events.pop_front();
    }
}

fn checkpoint_spool(state: &mut TerminalState) -> Result<(), PodError> {
    if !state.spool.as_ref().is_some_and(PodSpool::needs_checkpoint) {
        return Ok(());
    }
    let screen = state.parser.screen();
    let (cursor_row, cursor_col) = screen.cursor_position();
    let mut plain_text = screen.contents();
    let mut formatted_bytes = screen.contents_formatted();
    let truncated = plain_text.len() > 64 * 1_024 || formatted_bytes.len() > 128 * 1_024;
    if plain_text.len() > 64 * 1_024 {
        let mut end = 64 * 1_024;
        while !plain_text.is_char_boundary(end) {
            end -= 1;
        }
        plain_text.truncate(end);
    }
    formatted_bytes.truncate(128 * 1_024);
    let checkpoint = ScreenCheckpoint {
        parser_version: "vt100/0.16.2-pb06".into(),
        revision: state.revision,
        through: state.sequence,
        source_byte_position: state.byte_position,
        rows: state.rows,
        cols: state.cols,
        cursor_row,
        cursor_col,
        alternate_screen: screen.alternate_screen(),
        plain_text,
        formatted_bytes,
        fidelity: if truncated {
            ScreenFidelity::Partial {
                reason: "checkpoint screen exceeded response bound".into(),
            }
        } else {
            state.fidelity.clone()
        },
    };
    let spool = state.spool.as_mut().unwrap();
    spool.checkpoint_if_needed(&checkpoint)?;
    let first_retained = spool.events().front().map(|event| event.sequence);
    if let Some(first) = first_retained {
        while state
            .events
            .front()
            .is_some_and(|event| event.sequence < first)
        {
            state.events.pop_front();
        }
    }
    Ok(())
}

pub struct PtyProcess {
    pub master: Box<dyn MasterPty + Send>,
    pub writer: Box<dyn Write + Send>,
    pub child: Box<dyn portable_pty::Child + Send + Sync>,
    pub projection: TerminalProjection,
}

impl PtyProcess {
    pub fn spawn(
        descriptor: &LaunchDescriptor,
        spec: PtySpec,
        manifest_path: &Path,
    ) -> Result<Self, PodError> {
        let projection = TerminalProjection::with_spool(
            descriptor.resource_id.clone(),
            descriptor.incarnation,
            spec,
            manifest_path,
        )?;
        let system = NativePtySystem::default();
        let pair = system
            .openpty(PtySize {
                rows: spec.rows,
                cols: spec.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| PodError::Invalid("PTY allocation failed"))?;
        let mut command = CommandBuilder::new(&descriptor.executable);
        command.cwd(&descriptor.cwd);
        command.env_clear();
        for arg in &descriptor.args {
            command.arg(arg);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|_| PodError::Invalid("PTY child spawn failed"))?;
        drop(pair.slave);
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|_| PodError::Invalid("PTY reader unavailable"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|_| PodError::Invalid("PTY writer unavailable"))?;
        let feed = projection.clone();
        std::thread::spawn(move || read_output(reader, feed));
        Ok(Self {
            master: pair.master,
            writer,
            child,
            projection,
        })
    }

    pub fn process_id(&self) -> Result<u32, PodError> {
        self.child
            .process_id()
            .ok_or(PodError::Invalid("PTY process identity absent"))
    }

    pub fn try_wait(&mut self) -> Result<Option<i32>, PodError> {
        self.child
            .try_wait()
            .map(|status| status.map(|value| value.exit_code() as i32))
            .map_err(|_| PodError::Uncertain("PTY child exit observation failed"))
    }

    pub fn kill(&mut self) -> Result<(), PodError> {
        self.child
            .kill()
            .map_err(|_| PodError::Uncertain("PTY child stop outcome unknown"))
    }

    pub fn handle(&mut self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        let (resource, incarnation) = command.resource();
        if resource != self.projection.resource_id || incarnation != self.projection.incarnation {
            return Err(PodError::Refused("resource ID or incarnation is stale"));
        }
        match command {
            TerminalCommand::Attach { .. } => Ok(TerminalReply::View {
                value: self.projection.snapshot(),
            }),
            TerminalCommand::Events { after, limit, .. } => Ok(TerminalReply::Events {
                value: self.projection.events_after(after, limit)?,
            }),
            TerminalCommand::Acquire {
                actor_id,
                holder,
                expected_epoch,
                ttl_ms,
                ..
            } => Ok(TerminalReply::Lease {
                value: self
                    .projection
                    .acquire(&actor_id, holder, expected_epoch, ttl_ms)?,
            }),
            TerminalCommand::Write {
                command_id,
                actor_id,
                lease_id,
                epoch,
                bytes,
                ..
            } => {
                let id = command_id.ok_or(PodError::Invalid("PTY command ID required"))?;
                let digest = digest_command(&(
                    "write",
                    &self.projection.resource_id,
                    self.projection.incarnation,
                    &actor_id,
                    &lease_id,
                    epoch,
                    &bytes,
                ))?;
                let projection = self.projection.clone();
                projection.durable_effect(
                    &id,
                    &digest,
                    &actor_id,
                    &lease_id,
                    epoch,
                    "write",
                    || self.write(&actor_id, &lease_id, epoch, &bytes),
                )?;
                Ok(TerminalReply::BytesWritten)
            }
            TerminalCommand::Resize {
                command_id,
                actor_id,
                lease_id,
                epoch,
                rows,
                cols,
                ..
            } => {
                let id = command_id.ok_or(PodError::Invalid("PTY command ID required"))?;
                let digest = digest_command(&(
                    "resize",
                    &self.projection.resource_id,
                    self.projection.incarnation,
                    &actor_id,
                    &lease_id,
                    epoch,
                    rows,
                    cols,
                ))?;
                let projection = self.projection.clone();
                projection.durable_effect(
                    &id,
                    &digest,
                    &actor_id,
                    &lease_id,
                    epoch,
                    "resize",
                    || self.resize(&actor_id, &lease_id, epoch, rows, cols),
                )?;
                Ok(TerminalReply::Resized {
                    through: self.projection.snapshot().through,
                })
            }
            TerminalCommand::Release {
                actor_id,
                lease_id,
                epoch,
                ..
            } => {
                self.projection.release(&actor_id, &lease_id, epoch)?;
                Ok(TerminalReply::Released { epoch })
            }
        }
    }

    pub fn write(
        &mut self,
        actor: &str,
        lease: &str,
        epoch: u64,
        bytes: &[u8],
    ) -> Result<(), PodError> {
        // The pod's single command loop owns &mut self. Only the output reader
        // shares projection state; takeover cannot interleave check and write.
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(PodError::Invalid("PTY input bound"));
        }
        self.projection.require_lease(actor, lease, epoch)?;
        self.writer.write_all(bytes).map_err(|_| {
            PodError::Uncertain("PTY input may have been partially written; do not replay blindly")
        })
    }

    pub fn resize(
        &mut self,
        actor: &str,
        lease: &str,
        epoch: u64,
        rows: u16,
        cols: u16,
    ) -> Result<(), PodError> {
        if rows == 0 || rows > 200 || cols == 0 || cols > 400 {
            return Err(PodError::Invalid("PTY resize bounds"));
        }
        self.projection.require_lease(actor, lease, epoch)?;
        self.projection.resize_with(rows, cols, || {
            self.master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|_| PodError::Uncertain("PTY resize outcome not observed"))
        })
    }
}

impl TerminalResource for PtyProcess {
    fn process_identity(&self) -> Result<String, PodError> {
        self.process_id().map(|pid| pid.to_string())
    }
    fn try_wait(&mut self) -> Result<Option<i32>, PodError> {
        PtyProcess::try_wait(self)
    }
    fn stop(&mut self) -> Result<(), PodError> {
        PtyProcess::kill(self)
    }
    fn command(&mut self, command: TerminalCommand) -> Result<TerminalReply, PodError> {
        PtyProcess::handle(self, command)
    }
}

fn read_output(mut reader: Box<dyn Read + Send>, projection: TerminalProjection) {
    let mut buffer = [0_u8; 4_096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => projection.apply_output(&buffer[..length]),
            Err(_) => {
                projection.mark_unknown("PTY output stream failed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parser_checkpoint_and_retention_gap_are_explicit() {
        let projection = TerminalProjection::new(
            "resource.fixture".into(),
            7,
            PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 2,
            },
        );
        projection.apply_output(b"PRIMARY");
        projection.apply_output(b"\x1b[?1049hALT");
        let alternate = projection.snapshot();
        assert!(alternate.screen.alternate_screen);
        assert!(alternate.screen.plain_text.contains("ALT"));
        assert!(matches!(
            alternate.screen.fidelity,
            ScreenFidelity::Partial { .. }
        ));
        projection.apply_output(b"\x1b[?1049l");
        let primary = projection.snapshot();
        assert!(!primary.screen.alternate_screen);
        assert!(primary.screen.plain_text.contains("PRIMARY"));
        assert_eq!(primary.through, primary.screen.through);
        let page = projection.events_after(0, 10).unwrap();
        assert_eq!(page.gap, Some(2));
        assert_eq!(page.events.len(), 2);
        assert!(projection.events_after(primary.through + 1, 1).is_err());
    }

    #[test]
    fn human_takeover_invalidates_old_automation_epoch() {
        let projection = TerminalProjection::new(
            "resource.fixture".into(),
            7,
            PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 8,
            },
        );
        let automation = projection
            .acquire("actor.automation", LeaseKind::Automation, 0, 5_000)
            .unwrap();
        projection
            .require_lease(&automation.actor_id, &automation.lease_id, automation.epoch)
            .unwrap();
        let human = projection
            .acquire("actor.human", LeaseKind::Human, automation.epoch, 5_000)
            .unwrap();
        assert!(human.epoch > automation.epoch);
        assert!(
            projection
                .require_lease(&automation.actor_id, &automation.lease_id, automation.epoch)
                .is_err()
        );
        projection
            .release(&human.actor_id, &human.lease_id, human.epoch)
            .unwrap();
        let short = projection
            .acquire("actor.short", LeaseKind::Automation, human.epoch, 100)
            .unwrap();
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            projection
                .require_lease(&short.actor_id, &short.lease_id, short.epoch)
                .is_err()
        );
        assert!(
            projection
                .require_lease(&automation.actor_id, &automation.lease_id, automation.epoch)
                .is_err()
        );
    }

    #[test]
    fn large_output_pages_remain_bounded_and_continue_without_a_gap() {
        let projection = TerminalProjection::new(
            "resource.fixture".into(),
            3,
            PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 64,
            },
        );
        projection.apply_output(&vec![b'X'; 4_096 * 40]);
        let first = projection.events_after(0, 256).unwrap();
        assert!(first.has_more);
        assert!(first.next_cursor < first.through);
        assert!(first.events.len() <= 16);
        let next = projection.events_after(first.next_cursor, 256).unwrap();
        assert_eq!(next.gap, None);
        assert_eq!(next.events.first().unwrap().sequence, first.next_cursor + 1);
    }

    #[test]
    fn physical_resize_and_event_precede_subsequent_reader_output() {
        let projection = TerminalProjection::new(
            "resource.fixture".into(),
            3,
            PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 8,
            },
        );
        let feed = projection.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            receiver.recv().unwrap();
            feed.apply_output(b"after resize");
        });
        projection
            .resize_with(30, 90, || {
                assert!(
                    projection.state.try_lock().is_err(),
                    "geometry barrier is held"
                );
                sender.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(20));
                Ok(())
            })
            .unwrap();
        reader.join().unwrap();
        let events = projection.events_after(0, 8).unwrap().events;
        assert!(matches!(
            events[0].value,
            TerminalEventKind::Resize { rows: 30, cols: 90 }
        ));
        assert!(matches!(events[1].value, TerminalEventKind::Output { .. }));
    }

    #[test]
    fn failed_physical_input_stays_uncertain_and_retry_never_replays() {
        let directory = std::env::temp_dir().join(format!("podbay-input-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("fixture.json");
        let projection = TerminalProjection::with_spool(
            "resource.fixture".into(),
            3,
            PtySpec {
                rows: 24,
                cols: 80,
                retention_events: 8,
            },
            &path,
        )
        .unwrap();
        let lease = projection
            .acquire("actor.fixture", LeaseKind::Automation, 0, 5_000)
            .unwrap();
        let mut physical_calls = 0;
        assert!(matches!(
            projection.durable_effect(
                "command.failed",
                &"a".repeat(64),
                &lease.actor_id,
                &lease.lease_id,
                lease.epoch,
                "write",
                || {
                    physical_calls += 1;
                    Err(PodError::Uncertain("synthetic partial write"))
                }
            ),
            Err(PodError::Uncertain(_))
        ));
        assert!(matches!(
            projection.durable_effect(
                "command.failed",
                &"a".repeat(64),
                &lease.actor_id,
                &lease.lease_id,
                lease.epoch,
                "write",
                || {
                    physical_calls += 1;
                    Ok(())
                }
            ),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(physical_calls, 1);
        projection
            .durable_effect(
                "command.success",
                &"b".repeat(64),
                &lease.actor_id,
                &lease.lease_id,
                lease.epoch,
                "write",
                || {
                    physical_calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        projection
            .durable_effect(
                "command.success",
                &"b".repeat(64),
                &lease.actor_id,
                &lease.lease_id,
                lease.epoch,
                "write",
                || {
                    physical_calls += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(physical_calls, 2);
        drop(projection);
        assert!(matches!(
            TerminalProjection::with_spool(
                "resource.fixture".into(),
                3,
                PtySpec {
                    rows: 24,
                    cols: 80,
                    retention_events: 8
                },
                &path
            ),
            Err(PodError::Uncertain(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}

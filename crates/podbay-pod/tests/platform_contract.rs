use podbay_pod::{
    DurableFiles, LaunchDescriptor, LocalControlTransport, PodControlPort, PodObservation,
    ProcessIdentity, SupervisorBackend, SupervisorEvidence, TerminalBackend, TerminalCommand,
    TerminalResource, TerminalViewerPort,
};

fn assert_public_ports<B, C, T, D>()
where
    B: SupervisorBackend + TerminalBackend,
    C: PodControlPort + TerminalViewerPort,
    T: LocalControlTransport,
    D: DurableFiles,
{
}

#[test]
fn portable_contract_serializes_without_native_handle_requirements() {
    let value = PodObservation {
        protocol: "podbay-pod/1".into(),
        pod_id: "pod.fixture".into(),
        attempt_id: "attempt.fixture".into(),
        incarnation: 1,
        manifest_digest: "digest".into(),
        supervisor: ProcessIdentity {
            native_id: "opaque-supervisor".into(),
            start_identity: Some("opaque-start".into()),
        },
        child: ProcessIdentity {
            native_id: "opaque-child".into(),
            start_identity: None,
        },
        child_running: true,
        exit_code: None,
        evidence: SupervisorEvidence::LinuxSystemd {
            unit_name: "unit".into(),
            cgroup_path: "group".into(),
            boot_id: "boot".into(),
        },
    };
    let encoded = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        serde_json::from_slice::<PodObservation>(&encoded).unwrap(),
        value
    );
    let _ = std::mem::size_of::<Option<LaunchDescriptor>>();
    let _ = std::mem::size_of::<Option<TerminalCommand>>();
    let _ = assert_public_ports::<TestBackend, TestControl, TestTransport, TestFiles>;
}

struct TestBackend;
struct TestControl;
struct TestTransport;
struct TestFiles;

impl SupervisorBackend for TestBackend {
    fn launch(
        &self,
        _: LaunchDescriptor,
        _: &std::path::Path,
        _: &std::path::Path,
    ) -> Result<Box<dyn PodControlPort>, podbay_pod::PodError> {
        unreachable!()
    }
    fn connect(
        &self,
        _: &std::path::Path,
    ) -> Result<Box<dyn PodControlPort>, podbay_pod::PodError> {
        unreachable!()
    }
}
impl TerminalBackend for TestBackend {
    fn spawn(
        &self,
        _: &LaunchDescriptor,
        _: podbay_pod::PtySpec,
        _: &std::path::Path,
    ) -> Result<Box<dyn TerminalResource>, podbay_pod::PodError> {
        unreachable!()
    }
}
impl PodControlPort for TestControl {
    fn status(&self) -> Result<PodObservation, podbay_pod::PodError> {
        unreachable!()
    }
    fn stop(&self) -> Result<PodObservation, podbay_pod::PodError> {
        unreachable!()
    }
    fn terminal_control(
        &self,
        _: TerminalCommand,
    ) -> Result<podbay_pod::TerminalReply, podbay_pod::PodError> {
        unreachable!()
    }
    fn viewer(&self) -> Result<Box<dyn TerminalViewerPort>, podbay_pod::PodError> {
        unreachable!()
    }
}
impl TerminalViewerPort for TestControl {
    fn attach(&self) -> Result<podbay_pod::TerminalView, podbay_pod::PodError> {
        unreachable!()
    }
    fn events_after(
        &self,
        _: u64,
        _: usize,
    ) -> Result<podbay_pod::TerminalEventPage, podbay_pod::PodError> {
        unreachable!()
    }
}
impl LocalControlTransport for TestTransport {
    fn exchange(&self, _: &std::path::Path, _: &[u8]) -> Result<Vec<u8>, podbay_pod::PodError> {
        unreachable!()
    }
}
impl DurableFiles for TestFiles {
    fn create_private(&self, _: &std::path::Path, _: &[u8]) -> Result<(), podbay_pod::PodError> {
        unreachable!()
    }
    fn append_durable(&self, _: &std::path::Path, _: &[u8]) -> Result<(), podbay_pod::PodError> {
        unreachable!()
    }
    fn replace_durable(&self, _: &std::path::Path, _: &[u8]) -> Result<(), podbay_pod::PodError> {
        unreachable!()
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unavailable_native_backend_refuses_before_effect() {
    assert!(matches!(
        podbay_pod::PodClient::connect("unused"),
        Err(podbay_pod::PodError::Unsupported(_))
    ));
}

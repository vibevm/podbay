use podbay_wire::decode_command_json;

#[test]
fn launch_workspace_path_is_portable_and_scope_relative() {
    let fixture = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema/v1/command-launch.json"),
    )
    .unwrap();
    let mut command: serde_json::Value = serde_json::from_slice(&fixture).unwrap();
    for path in [
        "C:",
        "/tmp/work",
        "../other",
        "sub\\tree",
        "sub//tree",
        "bad\u{0000}path",
    ] {
        command["body"]["workspace"]["relativeCwd"] = serde_json::json!(path);
        assert!(
            decode_command_json(&serde_json::to_vec(&command).unwrap()).is_err(),
            "{path:?}"
        );
    }
}

use podbay_wire::{
    CommandBody, CommandEnvelope, DecimalString, SessionWriterLeaseRenewBody, Target,
    decode_command_json,
};

#[test]
fn writer_renewal_is_strict_session_mutation() {
    let command = CommandEnvelope::new(
        "request.renew.1", "key.renew.1",
        Target::Session { session_id: "session.renew.1".into() },
        None, None,
        CommandBody::SessionWriterLeaseRenew(SessionWriterLeaseRenewBody {
            expected_writer_epoch: DecimalString::new(3),
            expected_lease_expires_at_unix_seconds: DecimalString::new(1_800_000_000),
        }),
    ).unwrap();
    assert_eq!(decode_command_json(&command.encode_json().unwrap()).unwrap(), command);
    assert!(CommandEnvelope::new(
        "request.renew.2", "key.renew.2",
        Target::Session { session_id: "session.renew.1".into() },
        None, None,
        CommandBody::SessionWriterLeaseRenew(SessionWriterLeaseRenewBody {
            expected_writer_epoch: DecimalString::new(0),
            expected_lease_expires_at_unix_seconds: DecimalString::new(1_800_000_000),
        }),
    ).is_err());
}

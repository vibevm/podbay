//! Mandatory reviewed Codex app-server policy for internal native launch v2.
use podbay_core::ScopeId;
use serde::{Deserialize, Serialize};

const MAX_POLICY_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CodexSandboxV2 {
    #[serde(rename = "danger_full_access")]
    DangerFullAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CodexApprovalPolicyV2 {
    #[serde(rename = "never")]
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum PolicyKindV2 {
    #[serde(rename = "codex_app_server")]
    CodexAppServer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopedCredentialRefV2 {
    scope_id: String,
    reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodexAppServerPolicyV2 {
    kind: PolicyKindV2,
    sandbox: CodexSandboxV2,
    approval_policy: CodexApprovalPolicyV2,
    required_credential: ScopedCredentialRefV2,
    driver_ref: String,
    protocol_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexPolicyV2Error {
    InvalidField,
    Truncated,
    TrailingBytes,
    TooLarge,
}

impl CodexAppServerPolicyV2 {
    pub fn new(
        credential_scope: &ScopeId,
        credential_ref: String,
        driver_ref: String,
        protocol_ref: String,
    ) -> Result<Self, CodexPolicyV2Error> {
        let policy = Self {
            kind: PolicyKindV2::CodexAppServer,
            sandbox: CodexSandboxV2::DangerFullAccess,
            approval_policy: CodexApprovalPolicyV2::Never,
            required_credential: ScopedCredentialRefV2 {
                scope_id: credential_scope.as_str().to_owned(),
                reference: credential_ref,
            },
            driver_ref,
            protocol_ref,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn sandbox(&self) -> CodexSandboxV2 {
        self.sandbox
    }
    pub fn approval_policy(&self) -> CodexApprovalPolicyV2 {
        self.approval_policy
    }
    pub fn credential_scope(&self) -> &str {
        &self.required_credential.scope_id
    }
    pub fn credential_ref(&self) -> &str {
        &self.required_credential.reference
    }
    pub fn driver_ref(&self) -> &str {
        &self.driver_ref
    }
    pub fn protocol_ref(&self) -> &str {
        &self.protocol_ref
    }

    pub(crate) fn validate(&self) -> Result<(), CodexPolicyV2Error> {
        ScopeId::try_from(self.credential_scope()).map_err(|_| CodexPolicyV2Error::InvalidField)?;
        if !valid_credential_ref(self.credential_ref())
            || !valid_driver_ref(self.driver_ref())
            || !valid_driver_ref(self.protocol_ref())
        {
            return Err(CodexPolicyV2Error::InvalidField);
        }
        Ok(())
    }

    pub(crate) fn binary_bytes(&self) -> Result<Vec<u8>, CodexPolicyV2Error> {
        self.validate()?;
        let mut bytes = vec![1, 1, 1]; // kind, sandbox, approval policy
        for value in [
            self.credential_scope(),
            self.credential_ref(),
            self.driver_ref(),
            self.protocol_ref(),
        ] {
            let length = u16::try_from(value.len()).map_err(|_| CodexPolicyV2Error::TooLarge)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(CodexPolicyV2Error::TooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn decode_binary(bytes: &[u8]) -> Result<Self, CodexPolicyV2Error> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(CodexPolicyV2Error::TooLarge);
        }
        if bytes.len() < 3 {
            return Err(CodexPolicyV2Error::Truncated);
        }
        if bytes[..3] != [1, 1, 1] {
            return Err(CodexPolicyV2Error::InvalidField);
        }
        let mut at: usize = 3;
        let mut fields = Vec::with_capacity(4);
        for _ in 0..4 {
            let end = at.checked_add(2).ok_or(CodexPolicyV2Error::TooLarge)?;
            let length_bytes: [u8; 2] = bytes
                .get(at..end)
                .ok_or(CodexPolicyV2Error::Truncated)?
                .try_into()
                .expect("two bytes");
            at = end;
            let length = u16::from_be_bytes(length_bytes) as usize;
            let end = at.checked_add(length).ok_or(CodexPolicyV2Error::TooLarge)?;
            let text =
                std::str::from_utf8(bytes.get(at..end).ok_or(CodexPolicyV2Error::Truncated)?)
                    .map_err(|_| CodexPolicyV2Error::InvalidField)?;
            fields.push(text.to_owned());
            at = end;
        }
        if at != bytes.len() {
            return Err(CodexPolicyV2Error::TrailingBytes);
        }
        let scope =
            ScopeId::try_from(fields[0].as_str()).map_err(|_| CodexPolicyV2Error::InvalidField)?;
        let policy = Self::new(
            &scope,
            fields[1].clone(),
            fields[2].clone(),
            fields[3].clone(),
        )?;
        if policy.binary_bytes()? != bytes {
            return Err(CodexPolicyV2Error::InvalidField);
        }
        Ok(policy)
    }
}

fn valid_credential_ref(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_driver_ref(value: &str) -> bool {
    (3..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

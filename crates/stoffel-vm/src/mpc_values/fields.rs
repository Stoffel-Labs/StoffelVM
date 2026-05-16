/// Field name constants for Share objects.
pub mod share_fields {
    pub const TYPE: &str = "__type";
    pub const SHARE_TYPE: &str = "__share_type";
    pub const DATA: &str = "__data";
    pub const PARTY_ID: &str = "__party_id";
    pub const BIT_LENGTH: &str = "__bit_length";
    pub const PRECISION_K: &str = "__precision_k";
    pub const PRECISION_F: &str = "__precision_f";

    pub const TYPE_VALUE: &str = "Share";
    pub const SECRET_INT: &str = "SecretInt";
    pub const SECRET_FIXED_POINT: &str = "SecretFixedPoint";
}

/// Field name constants for RBC session objects.
pub mod rbc_fields {
    pub const TYPE: &str = "__type";
    pub const SESSION_ID: &str = "__session_id";
    pub const TYPE_VALUE: &str = "RbcSession";
}

/// Field name constants for ABA session objects.
pub mod aba_fields {
    pub const TYPE: &str = "__type";
    pub const SESSION_ID: &str = "__session_id";
    pub const TYPE_VALUE: &str = "AbaSession";
}

/// Field name constants for AVSS share objects.
#[cfg(feature = "avss")]
pub mod avss_fields {
    pub const TYPE: &str = "__type";
    pub const KEY_NAME: &str = "__key_name";
    pub const SHARE_DATA: &str = "__share_data";
    pub const COMMITMENTS: &str = "__commitments";
    pub const PARTY_ID: &str = "__party_id";
    pub const TYPE_VALUE: &str = "AvssShare";
}

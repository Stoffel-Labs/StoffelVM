use blake3::Hasher;

const PROTOCOL_INSTANCE_ID_DOMAIN: &[u8] = b"stoffel-mpc-protocol-instance-v1";

pub(crate) fn derive_protocol_instance_id_u32(protocol: &[u8], instance_id: u64) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(PROTOCOL_INSTANCE_ID_DOMAIN);
    hasher.update(protocol);
    hasher.update(&instance_id.to_le_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash.as_bytes()[..4]);
    u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_instance_ids_are_stable_for_full_width_vm_instance_ids() {
        let instance_id = u64::MAX - 17;

        assert_eq!(
            derive_protocol_instance_id_u32(b"honeybadger", instance_id),
            derive_protocol_instance_id_u32(b"honeybadger", instance_id)
        );
    }

    #[test]
    fn protocol_instance_ids_are_domain_separated() {
        let instance_id = u64::from(u32::MAX) + 1;

        assert_ne!(
            derive_protocol_instance_id_u32(b"honeybadger", instance_id),
            derive_protocol_instance_id_u32(b"avss", instance_id)
        );
    }
}

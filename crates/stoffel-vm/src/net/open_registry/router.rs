use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::sync::{Arc, Weak};

use super::instance::InstanceRegistry;
use super::wire::{
    ExpOpenWireMessage, OpenRegistryWireMessage, AVSS_EXP_WIRE_PREFIX, AVSS_G2_EXP_WIRE_PREFIX,
    HB_EXP_OPEN_WIRE_PREFIX, MAX_WIRE_MESSAGE_LEN, OPEN_REGISTRY_WIRE_PREFIX, UNKNOWN_SENDER_ID,
};

/// Session-local router for open-share and open-in-exponent wire messages.
///
/// A single runtime should own one router and pass it to all receive loops and
/// MPC engines that belong to that runtime. Different runtimes in the same
/// process should use different routers.
#[derive(Default)]
pub struct OpenMessageRouter {
    registries: DashMap<u64, Weak<InstanceRegistry>>,
}

impl OpenMessageRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a registry for the given instance_id within this router.
    pub fn register_instance(&self, instance_id: u64) -> Arc<InstanceRegistry> {
        if let Some(existing) = self.get_instance_registry(instance_id) {
            return existing;
        }

        let registry = Arc::new(InstanceRegistry::new(instance_id));
        match self.registries.entry(instance_id) {
            Entry::Occupied(mut occupied) => {
                if let Some(existing) = occupied.get().upgrade() {
                    existing
                } else {
                    occupied.insert(Arc::downgrade(&registry));
                    registry
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Arc::downgrade(&registry));
                registry
            }
        }
    }

    /// Look up an instance registry within this router.
    pub fn get_instance_registry(&self, instance_id: u64) -> Option<Arc<InstanceRegistry>> {
        self.registries
            .get(&instance_id)
            .and_then(|entry| entry.value().upgrade())
    }

    pub fn clear(&self) {
        self.registries.clear();
    }

    /// Attempt to consume an incoming transport payload as an open-registry wire message.
    ///
    /// Returns `Ok(true)` when the payload is recognized and handled.
    /// Returns `Ok(false)` when the payload is not an open-registry message,
    /// or when no registry is registered for the `instance_id`.
    pub fn try_handle_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
    ) -> Result<bool, String> {
        if payload.len() < OPEN_REGISTRY_WIRE_PREFIX.len()
            || &payload[..OPEN_REGISTRY_WIRE_PREFIX.len()] != OPEN_REGISTRY_WIRE_PREFIX
        {
            return Ok(false);
        }

        let body = &payload[OPEN_REGISTRY_WIRE_PREFIX.len()..];
        if body.len() > MAX_WIRE_MESSAGE_LEN {
            return Err(format!(
                "open wire payload too large: {} bytes (max {})",
                body.len(),
                MAX_WIRE_MESSAGE_LEN
            ));
        }

        let decoded: OpenRegistryWireMessage = bincode::deserialize(body)
            .map_err(|e| format!("deserialize open wire payload: {}", e))?;

        let (instance_id, sender_party_id) = match &decoded {
            OpenRegistryWireMessage::Single {
                instance_id,
                sender_party_id,
                ..
            } => (*instance_id, *sender_party_id),
            OpenRegistryWireMessage::Batch {
                instance_id,
                sender_party_id,
                ..
            } => (*instance_id, *sender_party_id),
        };

        if authenticated_sender_id == UNKNOWN_SENDER_ID {
            tracing::warn!(
                sender_party_id,
                "Rejecting open wire message from unauthenticated connection"
            );
            return Err("open wire rejected: sender identity not authenticated".to_string());
        }
        if sender_party_id != authenticated_sender_id {
            return Err(format!(
                "open wire sender mismatch: transport={} payload={}",
                authenticated_sender_id, sender_party_id
            ));
        }

        let registry = match self.get_instance_registry(instance_id) {
            Some(registry) => registry,
            None => return Ok(false),
        };

        match decoded {
            OpenRegistryWireMessage::Single {
                type_key,
                sender_party_id,
                share,
                ..
            } => registry.insert_single(&type_key, sender_party_id, share),
            OpenRegistryWireMessage::Batch {
                type_key,
                sender_party_id,
                shares,
                ..
            } => registry.insert_batch(&type_key, sender_party_id, shares),
        }
        Ok(true)
    }

    pub fn try_handle_hb_open_exp_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
    ) -> Result<bool, String> {
        if payload.len() < HB_EXP_OPEN_WIRE_PREFIX.len()
            || &payload[..HB_EXP_OPEN_WIRE_PREFIX.len()] != HB_EXP_OPEN_WIRE_PREFIX
        {
            return Ok(false);
        }

        let body = &payload[HB_EXP_OPEN_WIRE_PREFIX.len()..];
        if body.len() > MAX_WIRE_MESSAGE_LEN {
            return Err(format!(
                "open-exp wire payload too large: {} bytes (max {})",
                body.len(),
                MAX_WIRE_MESSAGE_LEN
            ));
        }

        let message: ExpOpenWireMessage = bincode::deserialize(body)
            .map_err(|e| format!("deserialize open-exp payload: {}", e))?;

        if authenticated_sender_id == UNKNOWN_SENDER_ID {
            tracing::warn!(
                sender_party_id = message.sender_party_id,
                "Rejecting open-exp wire message from unauthenticated connection"
            );
            return Err("open-exp wire rejected: sender identity not authenticated".to_string());
        }
        if message.sender_party_id != authenticated_sender_id {
            return Err(format!(
                "open-exp sender mismatch: transport={} payload={}",
                authenticated_sender_id, message.sender_party_id
            ));
        }
        if message.share_id != message.sender_party_id {
            return Err(format!(
                "open-exp share_id mismatch: sender_party_id={} share_id={}",
                message.sender_party_id, message.share_id
            ));
        }

        let registry = match self.get_instance_registry(message.instance_id) {
            Some(registry) => registry,
            None => return Ok(false),
        };
        registry.insert_exp(
            message.sender_party_id,
            message.share_id,
            message.partial_point,
        );
        Ok(true)
    }

    pub fn try_handle_avss_open_exp_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
    ) -> Result<bool, String> {
        self.try_handle_avss_exp_wire_message(
            authenticated_sender_id,
            payload,
            AVSS_EXP_WIRE_PREFIX,
            false,
        )
    }

    pub fn try_handle_avss_g2_exp_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
    ) -> Result<bool, String> {
        self.try_handle_avss_exp_wire_message(
            authenticated_sender_id,
            payload,
            AVSS_G2_EXP_WIRE_PREFIX,
            true,
        )
    }

    fn try_handle_avss_exp_wire_message(
        &self,
        authenticated_sender_id: usize,
        payload: &[u8],
        prefix: &[u8; 4],
        use_g2_registry: bool,
    ) -> Result<bool, String> {
        if payload.len() < prefix.len() || &payload[..prefix.len()] != prefix {
            return Ok(false);
        }

        let body = &payload[prefix.len()..];
        if body.len() > MAX_WIRE_MESSAGE_LEN {
            return Err(if use_g2_registry {
                format!(
                    "avss g2 open-exp wire payload too large: {} bytes (max {})",
                    body.len(),
                    MAX_WIRE_MESSAGE_LEN
                )
            } else {
                format!(
                    "avss open-exp wire payload too large: {} bytes (max {})",
                    body.len(),
                    MAX_WIRE_MESSAGE_LEN
                )
            });
        }

        let message: ExpOpenWireMessage = bincode::deserialize(body).map_err(|e| {
            if use_g2_registry {
                format!("deserialize avss g2 open-exp payload: {}", e)
            } else {
                format!("deserialize avss open-exp payload: {}", e)
            }
        })?;

        if authenticated_sender_id == UNKNOWN_SENDER_ID {
            tracing::warn!(
                sender_party_id = message.sender_party_id,
                "Rejecting AVSS open-exp wire message from unauthenticated connection"
            );
            return Err(if use_g2_registry {
                "avss g2 open-exp wire rejected: sender identity not authenticated".to_string()
            } else {
                "avss open-exp wire rejected: sender identity not authenticated".to_string()
            });
        }
        if message.sender_party_id != authenticated_sender_id {
            return Err(if use_g2_registry {
                format!(
                    "avss g2 open-exp sender mismatch: transport={} payload={}",
                    authenticated_sender_id, message.sender_party_id
                )
            } else {
                format!(
                    "avss open-exp sender mismatch: transport={} payload={}",
                    authenticated_sender_id, message.sender_party_id
                )
            });
        }
        if message.share_id != message.sender_party_id + 1 {
            return Err(if use_g2_registry {
                format!(
                    "avss g2 open-exp share_id mismatch: sender_party_id={} share_id={}",
                    message.sender_party_id, message.share_id
                )
            } else {
                format!(
                    "avss open-exp share_id mismatch: sender_party_id={} share_id={}",
                    message.sender_party_id, message.share_id
                )
            });
        }

        let registry = match self.get_instance_registry(message.instance_id) {
            Some(registry) => registry,
            None => return Ok(false),
        };
        if use_g2_registry {
            registry.insert_exp_g2(
                message.sender_party_id,
                message.share_id,
                message.partial_point,
            );
        } else {
            registry.insert_exp(
                message.sender_party_id,
                message.share_id,
                message.partial_point,
            );
        }
        Ok(true)
    }
}

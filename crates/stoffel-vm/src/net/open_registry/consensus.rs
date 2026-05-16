use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::InstanceRegistry;

fn wait_for_registry_result<T, Check>(
    notify: &Notify,
    timeout_ms: u64,
    timeout_message: impl Fn() -> String,
    mut check: Check,
) -> Result<T, String>
where
    Check: FnMut() -> Option<T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let deadline = tokio::time::Instant::now()
                        + tokio::time::Duration::from_millis(timeout_ms);
                    loop {
                        let notified = notify.notified();
                        if let Some(result) = check() {
                            return Ok(result);
                        }
                        if tokio::time::Instant::now() >= deadline {
                            return Err(timeout_message());
                        }
                        tokio::select! {
                            _ = notified => {}
                            _ = tokio::time::sleep_until(deadline) => {}
                        }
                    }
                })
            });
        }
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Some(result) = check() {
            return Ok(result);
        }
        if Instant::now() >= deadline {
            return Err(timeout_message());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn wait_for_registry_result_async<T, Check>(
    notify: &Notify,
    timeout_ms: u64,
    timeout_message: impl Fn() -> String,
    mut check: Check,
) -> Result<T, String>
where
    Check: FnMut() -> Option<T>,
{
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

    loop {
        let notified = notify.notified();
        if let Some(result) = check() {
            return Ok(result);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(timeout_message());
        }
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

impl InstanceRegistry {
    pub fn rbc_broadcast(&self, party_id: usize, message: &[u8]) -> Result<u64, String> {
        let mut registry = self.rbc.lock();

        let mut session_id = 0u64;
        while registry.messages.contains_key(&(session_id, party_id)) {
            session_id = session_id
                .checked_add(1)
                .ok_or_else(|| "RBC session id overflow".to_string())?;
        }

        registry
            .messages
            .insert((session_id, party_id), message.to_vec());
        drop(registry);

        self.rbc_notify.notify_waiters();

        tracing::info!(
            instance_id = self.instance_id(),
            session_id = session_id,
            party_id = party_id,
            message_len = message.len(),
            "RBC broadcast initiated"
        );

        Ok(session_id)
    }

    pub async fn rbc_broadcast_async(
        &self,
        party_id: usize,
        message: &[u8],
    ) -> Result<u64, String> {
        self.rbc_broadcast(party_id, message)
    }

    pub fn rbc_receive(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result(
            &self.rbc_notify,
            timeout_ms,
            || format!("RBC receive timeout waiting for message from party {from_party}"),
            || {
                let mut registry = self.rbc.lock();
                let mut next: Option<(u64, Vec<u8>)> = None;
                for ((session_id, party), message) in registry.messages.iter() {
                    if *party != from_party {
                        continue;
                    }
                    let delivery_key = (receiver_party_id, from_party, *session_id);
                    if registry.delivered.contains(&delivery_key) {
                        continue;
                    }
                    match next {
                        Some((best_session, _)) if *session_id >= best_session => {}
                        _ => next = Some((*session_id, message.clone())),
                    }
                }
                if let Some((session_id, message)) = next {
                    registry
                        .delivered
                        .insert((receiver_party_id, from_party, session_id));
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        from_party = from_party,
                        message_len = message.len(),
                        "RBC receive delivered message"
                    );
                    return Some(message);
                }
                None
            },
        )
    }

    pub async fn rbc_receive_async(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result_async(
            &self.rbc_notify,
            timeout_ms,
            || format!("RBC receive timeout waiting for message from party {from_party}"),
            || self.try_deliver_rbc_from(instance_id, receiver_party_id, from_party),
        )
        .await
    }

    pub fn rbc_receive_any(
        &self,
        receiver_party_id: usize,
        timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let instance_id = self.instance_id();
        wait_for_registry_result(
            &self.rbc_notify,
            timeout_ms,
            || "RBC receive_any timeout waiting for message from any party".to_string(),
            || {
                let mut registry = self.rbc.lock();
                let mut next: Option<(u64, usize, Vec<u8>)> = None;
                for ((session_id, party), message) in registry.messages.iter() {
                    if *party == receiver_party_id {
                        continue;
                    }
                    let delivery_key = (receiver_party_id, *party, *session_id);
                    if registry.delivered.contains(&delivery_key) {
                        continue;
                    }
                    match next {
                        Some((best_session, best_party, _))
                            if (*session_id, *party) >= (best_session, best_party) => {}
                        _ => next = Some((*session_id, *party, message.clone())),
                    }
                }
                if let Some((session_id, party, message)) = next {
                    registry
                        .delivered
                        .insert((receiver_party_id, party, session_id));
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        from_party = party,
                        message_len = message.len(),
                        "RBC receive_any delivered message"
                    );
                    return Some((party, message));
                }
                None
            },
        )
    }

    pub async fn rbc_receive_any_async(
        &self,
        receiver_party_id: usize,
        timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let instance_id = self.instance_id();
        wait_for_registry_result_async(
            &self.rbc_notify,
            timeout_ms,
            || "RBC receive_any timeout waiting for message from any party".to_string(),
            || self.try_deliver_rbc_any(instance_id, receiver_party_id),
        )
        .await
    }

    pub fn aba_propose(&self, party_id: usize, value: bool) -> Result<u64, String> {
        let mut registry = self.aba.lock();

        let mut session_id = 0u64;
        while registry.proposals.contains_key(&(session_id, party_id)) {
            session_id = session_id
                .checked_add(1)
                .ok_or_else(|| "ABA session id overflow".to_string())?;
        }

        registry.proposals.insert((session_id, party_id), value);
        drop(registry);

        self.aba_notify.notify_waiters();

        tracing::info!(
            instance_id = self.instance_id(),
            session_id = session_id,
            party_id = party_id,
            value = value,
            "ABA propose initiated"
        );

        Ok(session_id)
    }

    pub async fn aba_propose_async(&self, party_id: usize, value: bool) -> Result<u64, String> {
        self.aba_propose(party_id, value)
    }

    pub fn aba_result(
        &self,
        required: usize,
        session_id: u64,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result(
            &self.aba_notify,
            timeout_ms,
            || format!("ABA result timeout waiting for agreement on session {session_id}"),
            || {
                let mut registry = self.aba.lock();

                if let Some(&result) = registry.results.get(&session_id) {
                    return Some(result);
                }

                let mut true_count = 0usize;
                let mut false_count = 0usize;

                for ((sess_id, _party), &proposal) in registry.proposals.iter() {
                    if *sess_id == session_id {
                        if proposal {
                            true_count += 1;
                        } else {
                            false_count += 1;
                        }
                    }
                }

                if true_count >= required {
                    registry.results.insert(session_id, true);
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        result = true,
                        true_count = true_count,
                        "ABA agreement reached"
                    );
                    return Some(true);
                }

                if false_count >= required {
                    registry.results.insert(session_id, false);
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        result = false,
                        false_count = false_count,
                        "ABA agreement reached"
                    );
                    return Some(false);
                }

                None
            },
        )
    }

    pub async fn aba_result_async(
        &self,
        required: usize,
        session_id: u64,
        timeout_ms: u64,
    ) -> Result<bool, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result_async(
            &self.aba_notify,
            timeout_ms,
            || format!("ABA result timeout waiting for agreement on session {session_id}"),
            || self.try_aba_result(instance_id, required, session_id),
        )
        .await
    }

    fn try_deliver_rbc_from(
        &self,
        instance_id: u64,
        receiver_party_id: usize,
        from_party: usize,
    ) -> Option<Vec<u8>> {
        let mut registry = self.rbc.lock();
        let mut next: Option<(u64, Vec<u8>)> = None;
        for ((session_id, party), message) in registry.messages.iter() {
            if *party != from_party {
                continue;
            }
            let delivery_key = (receiver_party_id, from_party, *session_id);
            if registry.delivered.contains(&delivery_key) {
                continue;
            }
            match next {
                Some((best_session, _)) if *session_id >= best_session => {}
                _ => next = Some((*session_id, message.clone())),
            }
        }
        if let Some((session_id, message)) = next {
            registry
                .delivered
                .insert((receiver_party_id, from_party, session_id));
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                from_party = from_party,
                message_len = message.len(),
                "RBC receive delivered message"
            );
            return Some(message);
        }
        None
    }

    fn try_deliver_rbc_any(
        &self,
        instance_id: u64,
        receiver_party_id: usize,
    ) -> Option<(usize, Vec<u8>)> {
        let mut registry = self.rbc.lock();
        let mut next: Option<(u64, usize, Vec<u8>)> = None;
        for ((session_id, party), message) in registry.messages.iter() {
            if *party == receiver_party_id {
                continue;
            }
            let delivery_key = (receiver_party_id, *party, *session_id);
            if registry.delivered.contains(&delivery_key) {
                continue;
            }
            match next {
                Some((best_session, best_party, _))
                    if (*session_id, *party) >= (best_session, best_party) => {}
                _ => next = Some((*session_id, *party, message.clone())),
            }
        }
        if let Some((session_id, party, message)) = next {
            registry
                .delivered
                .insert((receiver_party_id, party, session_id));
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                from_party = party,
                message_len = message.len(),
                "RBC receive_any delivered message"
            );
            return Some((party, message));
        }
        None
    }

    fn try_aba_result(&self, instance_id: u64, required: usize, session_id: u64) -> Option<bool> {
        let mut registry = self.aba.lock();

        if let Some(&result) = registry.results.get(&session_id) {
            return Some(result);
        }

        let mut true_count = 0usize;
        let mut false_count = 0usize;

        for ((sess_id, _party), &proposal) in registry.proposals.iter() {
            if *sess_id == session_id {
                if proposal {
                    true_count += 1;
                } else {
                    false_count += 1;
                }
            }
        }

        if true_count >= required {
            registry.results.insert(session_id, true);
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                result = true,
                true_count = true_count,
                "ABA agreement reached"
            );
            return Some(true);
        }

        if false_count >= required {
            registry.results.insert(session_id, false);
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                result = false,
                false_count = false_count,
                "ABA agreement reached"
            );
            return Some(false);
        }

        None
    }
}

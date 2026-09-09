use super::wire::MAX_WIRE_MESSAGE_LEN;
use super::{InstanceRegistry, RbcProgress, RbcRelay, RbcRelayPhase, RbcState};

const MAX_RBC_PAYLOAD_LEN: usize = MAX_WIRE_MESSAGE_LEN / 4;
const MAX_PENDING_RBC_CANDIDATES_PER_SENDER: usize = 1;
const MAX_PENDING_RBC_PAYLOAD_BYTES_PER_SENDER: usize = MAX_RBC_PAYLOAD_LEN;
const MAX_PENDING_RBC_CANDIDATES: usize = 256;
const MAX_PENDING_RBC_PAYLOAD_BYTES: usize = 64 * MAX_WIRE_MESSAGE_LEN;
const MAX_ORPHAN_READY_KEYS_PER_SENDER: usize = 16;

fn reclaim_delivered_rbc_state(registry: &mut RbcState) {
    if registry.receivers.is_empty() {
        return;
    }
    let completed = registry
        .candidates
        .keys()
        .filter_map(|(session_id, party, _)| {
            registry
                .receivers
                .iter()
                .all(|receiver| {
                    *receiver == *party
                        || registry
                            .delivered
                            .contains(&(*receiver, *party, *session_id))
                })
                .then_some((*session_id, *party))
        })
        .collect::<std::collections::HashSet<_>>();
    if completed.is_empty() {
        return;
    }
    registry
        .messages
        .retain(|(session_id, party), _| !completed.contains(&(*session_id, *party)));
    registry
        .candidates
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .candidate_sources
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .echoes
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .readies
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .sent_echoes
        .retain(|(_, party, session_id)| !completed.contains(&(*session_id, *party)));
    registry
        .sent_readies
        .retain(|(_, party, session_id)| !completed.contains(&(*session_id, *party)));
}

fn admit_rbc_candidate(
    registry: &mut RbcState,
    key: &(u64, usize, [u8; 32]),
    source_sender: usize,
    message_len: usize,
) -> Result<(), String> {
    if registry.candidates.contains_key(key) {
        return Ok(());
    }
    reclaim_delivered_rbc_state(registry);
    if message_len > MAX_RBC_PAYLOAD_LEN {
        return Err(format!(
            "RBC payload is {message_len} bytes (max {MAX_RBC_PAYLOAD_LEN})"
        ));
    }
    if registry.candidates.len() >= MAX_PENDING_RBC_CANDIDATES {
        return Err(format!(
            "RBC aggregate candidate budget is full (max {MAX_PENDING_RBC_CANDIDATES})"
        ));
    }
    let sender_candidates = registry
        .candidate_sources
        .values()
        .filter(|sender| **sender == source_sender)
        .count();
    if sender_candidates >= MAX_PENDING_RBC_CANDIDATES_PER_SENDER {
        return Err(format!(
            "RBC sender {source_sender} candidate quota is full (max {MAX_PENDING_RBC_CANDIDATES_PER_SENDER})"
        ));
    }
    let retained = registry
        .candidates
        .iter()
        .filter(|(candidate_key, _)| {
            registry.candidate_sources.get(candidate_key) == Some(&source_sender)
        })
        .try_fold(0usize, |total, (_, message)| {
            total.checked_add(message.len())
        })
        .and_then(|total| total.checked_add(message_len))
        .ok_or_else(|| "RBC retained payload byte count overflowed".to_string())?;
    if retained > MAX_PENDING_RBC_PAYLOAD_BYTES_PER_SENDER {
        return Err(format!(
            "RBC sender {source_sender} retained payload budget exceeded: {retained} bytes (max {MAX_PENDING_RBC_PAYLOAD_BYTES_PER_SENDER})"
        ));
    }
    let aggregate_retained = registry
        .candidates
        .values()
        .try_fold(0usize, |total, message| total.checked_add(message.len()))
        .and_then(|total| total.checked_add(message_len))
        .ok_or_else(|| "RBC aggregate retained payload byte count overflowed".to_string())?;
    if aggregate_retained > MAX_PENDING_RBC_PAYLOAD_BYTES {
        return Err(format!(
            "RBC aggregate retained payload budget exceeded: {aggregate_retained} bytes (max {MAX_PENDING_RBC_PAYLOAD_BYTES})"
        ));
    }
    Ok(())
}

impl InstanceRegistry {
    pub(crate) fn insert_rbc_broadcast(
        &self,
        session_id: u64,
        party_id: usize,
        message: Vec<u8>,
    ) -> Result<(), String> {
        let mut registry = self.rbc.lock();
        if registry
            .delivered
            .iter()
            .any(|(_, party, session)| *party == party_id && *session == session_id)
        {
            return Ok(());
        }

        let digest = *blake3::hash(&message).as_bytes();
        if let Some(existing) = registry.messages.get(&(session_id, party_id)) {
            if existing == &digest {
                return Ok(());
            }
            return Err(format!(
                "conflicting RBC payload for session {session_id} from party {party_id}"
            ));
        }

        let candidate_key = (session_id, party_id, digest);
        admit_rbc_candidate(&mut registry, &candidate_key, party_id, message.len())?;
        registry.candidates.insert(candidate_key, message.clone());
        registry.candidate_sources.insert(candidate_key, party_id);
        registry.messages.insert((session_id, party_id), digest);
        drop(registry);
        self.rbc_notify.notify_waiters();
        Ok(())
    }

    pub fn rbc_broadcast(&self, party_id: usize, message: &[u8]) -> Result<u64, String> {
        let mut registry = self.rbc.lock();
        registry.receivers.insert(party_id);
        let next_session = registry.next_sessions.entry(party_id).or_default();
        let session_id = *next_session;
        *next_session = next_session
            .checked_add(1)
            .ok_or_else(|| "RBC session id overflow".to_string())?;

        let message = message.to_vec();
        let message_len = message.len();
        let digest = *blake3::hash(&message).as_bytes();
        let candidate_key = (session_id, party_id, digest);
        admit_rbc_candidate(&mut registry, &candidate_key, party_id, message.len())?;
        registry.candidates.insert(candidate_key, message.clone());
        registry.candidate_sources.insert(candidate_key, party_id);
        registry.messages.insert((session_id, party_id), digest);
        drop(registry);

        self.rbc_notify.notify_waiters();

        tracing::info!(
            instance_id = self.instance_id(),
            session_id = session_id,
            party_id = party_id,
            message_len,
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

    /// Direct registry delivery is intentionally disabled. Reliable broadcast requires the
    /// engine to exchange authenticated ECHO/READY relays through the network first.
    pub fn rbc_receive(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        _timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let _ = receiver_party_id;
        Err(format!(
            "RBC receive from party {from_party} requires network quorum processing"
        ))
    }

    pub fn rbc_receive_any(
        &self,
        receiver_party_id: usize,
        _timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let _ = receiver_party_id;
        Err("RBC receive_any requires network quorum processing".to_string())
    }

    pub(crate) fn insert_rbc_relay(
        &self,
        ready: bool,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
        message: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let mut registry = self.rbc.lock();
        if registry
            .delivered
            .iter()
            .any(|(_, party, session)| *party == broadcaster_party_id && *session == session_id)
        {
            return Ok(());
        }
        if let Some(message) = message {
            if *blake3::hash(&message).as_bytes() != digest {
                return Err("RBC ECHO payload digest mismatch".to_string());
            }
            let candidate_key = (session_id, broadcaster_party_id, digest);
            admit_rbc_candidate(
                &mut registry,
                &candidate_key,
                sender_party_id,
                message.len(),
            )?;
            registry.candidates.entry(candidate_key).or_insert(message);
            registry
                .candidate_sources
                .entry(candidate_key)
                .or_insert(sender_party_id);
        }
        let relays = if ready {
            let relay_key = (session_id, broadcaster_party_id, digest);
            if !registry.candidates.contains_key(&relay_key)
                && !registry.readies.contains_key(&relay_key)
            {
                let sender_orphans = registry
                    .readies
                    .iter()
                    .filter(|(key, senders)| {
                        !registry.candidates.contains_key(key) && senders.contains(&sender_party_id)
                    })
                    .count();
                if sender_orphans >= MAX_ORPHAN_READY_KEYS_PER_SENDER {
                    return Err(format!(
                        "RBC sender {sender_party_id} exceeded orphan READY limit of {MAX_ORPHAN_READY_KEYS_PER_SENDER}"
                    ));
                }
            }
            &mut registry.readies
        } else {
            &mut registry.echoes
        };
        relays
            .entry((session_id, broadcaster_party_id, digest))
            .or_default()
            .insert(sender_party_id);
        drop(registry);
        self.rbc_notify.notify_waiters();
        Ok(())
    }

    pub(crate) fn rbc_progress(
        &self,
        receiver_party_id: usize,
        from_party: Option<usize>,
        n_parties: usize,
        threshold: usize,
    ) -> Result<RbcProgress, String> {
        let minimum_parties = threshold
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "RBC topology threshold overflowed".to_string())?;
        if n_parties == 0 || threshold >= n_parties || n_parties < minimum_parties {
            return Err(format!(
                "invalid RBC topology n={n_parties}, t={threshold}; require n >= 3t + 1"
            ));
        }
        if receiver_party_id >= n_parties
            || from_party.is_some_and(|party_id| party_id >= n_parties)
        {
            return Err(format!(
                "RBC party id is outside topology of {n_parties} parties"
            ));
        }
        let mut registry = self.rbc.lock();
        registry.receivers.insert(receiver_party_id);
        let mut candidates = registry
            .candidates
            .iter()
            .filter_map(|((session_id, party, digest), message)| {
                if from_party.is_some_and(|expected| expected != *party)
                    || (from_party.is_none() && *party == receiver_party_id)
                    || *party >= n_parties
                {
                    return None;
                }
                let delivery_key = (receiver_party_id, *party, *session_id);
                if registry.delivered.contains(&delivery_key) {
                    return None;
                }
                Some((*session_id, *party, *digest, message.clone()))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(session_id, party, digest, _)| (*session_id, *party, *digest));
        if candidates.is_empty() {
            return Ok(RbcProgress {
                relays: Vec::new(),
                delivery: None,
            });
        }

        let mut relays = Vec::new();
        let mut delivery = None;
        let mut offset = 0;
        while offset < candidates.len() {
            let session_id = candidates[offset].0;
            let party = candidates[offset].1;
            let group_end = candidates[offset..]
                .iter()
                .position(|(candidate_session, candidate_party, _, _)| {
                    *candidate_session != session_id || *candidate_party != party
                })
                .map_or(candidates.len(), |relative| offset + relative);
            let sent_key = (receiver_party_id, party, session_id);

            if let Some(digest) = registry.messages.get(&(session_id, party)).copied() {
                let relay_key = (session_id, party, digest);
                registry
                    .echoes
                    .entry(relay_key)
                    .or_default()
                    .insert(receiver_party_id);
                if registry.sent_echoes.insert(sent_key) {
                    relays.push(RbcRelay {
                        phase: RbcRelayPhase::Echo,
                        session_id,
                        broadcaster_party_id: party,
                        digest,
                        message: registry.candidates.get(&relay_key).cloned(),
                    });
                }
            }

            for (_, _, digest, message) in &candidates[offset..group_end] {
                let relay_key = (session_id, party, *digest);
                let echo_count = registry.echoes.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                let ready_count = registry.readies.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                if (echo_count >= n_parties - threshold || ready_count > threshold)
                    && registry.sent_readies.insert(sent_key)
                {
                    registry
                        .readies
                        .entry(relay_key)
                        .or_default()
                        .insert(receiver_party_id);
                    relays.push(RbcRelay {
                        phase: RbcRelayPhase::Ready,
                        session_id,
                        broadcaster_party_id: party,
                        digest: *digest,
                        message: None,
                    });
                }

                let ready_count = registry.readies.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                if ready_count > 2 * threshold {
                    registry
                        .delivered
                        .insert((receiver_party_id, party, session_id));
                    tracing::info!(
                        instance_id = self.instance_id(),
                        session_id,
                        from_party = party,
                        message_len = message.len(),
                        "RBC quorum delivered message"
                    );
                    delivery = Some((party, message.clone()));
                    break;
                }
            }
            if delivery.is_some() {
                break;
            }
            offset = group_end;
        }

        Ok(RbcProgress { relays, delivery })
    }
}

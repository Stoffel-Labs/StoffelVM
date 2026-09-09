use super::{registration_token_is_valid, send_ctrl, send_session_announce, DiscoveryMessage};
use crate::net::session::{
    derive_instance_id_for_execution, ExecutionId, SessionInfo, SessionMessage,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use stoffelnet::network_utils::{NodePublicKey, PartyId};
use stoffelnet::transports::quic::PeerConnection;
use tokio::sync::{broadcast, mpsc, watch, Mutex};

#[derive(Debug, Clone)]
struct PendingSession {
    execution_id: ExecutionId,
    program_id: [u8; 32],
    entry: String,
    n_parties: usize,
    threshold: usize,
    parties: HashMap<PartyId, SocketAddr>,
    tls_ids: HashMap<PartyId, PartyId>,
    tls_public_keys: HashMap<PartyId, Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistration {
    pub execution_id: ExecutionId,
    pub party_id: PartyId,
    pub listen_addr: SocketAddr,
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    pub tls_derived_id: Option<PartyId>,
    pub tls_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistrationReport {
    pub registered_parties: usize,
    pub target_parties: usize,
    pub ready_session: Option<SessionInfo>,
}

#[derive(Clone)]
pub(super) struct BootnodeState {
    session: Arc<Mutex<SessionState>>,
    expected_parties: usize,
    session_tx: watch::Sender<Option<SessionInfo>>,
    ice_tx: broadcast::Sender<DiscoveryMessage>,
}

#[derive(Debug, Default)]
struct SessionState {
    pending: Option<PendingSession>,
    active: Option<SessionInfo>,
}

impl BootnodeState {
    pub fn new(expected_parties: usize) -> Self {
        let (session_tx, _session_rx) = watch::channel(None);
        let (ice_tx, _ice_rx) = broadcast::channel(256);
        Self {
            session: Arc::new(Mutex::new(SessionState::default())),
            expected_parties,
            session_tx,
            ice_tx,
        }
    }

    pub fn subscribe_session(&self) -> watch::Receiver<Option<SessionInfo>> {
        self.session_tx.subscribe()
    }

    pub fn subscribe_ice(&self) -> broadcast::Receiver<DiscoveryMessage> {
        self.ice_tx.subscribe()
    }

    pub fn publish_ice(&self, message: DiscoveryMessage) {
        let _ = self.ice_tx.send(message);
    }

    pub async fn register_session(
        &self,
        registration: SessionRegistration,
    ) -> Result<SessionRegistrationReport, String> {
        if registration.execution_id.is_zero() {
            return Err("the zero execution ID cannot identify a mesh session".to_string());
        }

        let tls_public_key = match (registration.tls_derived_id, &registration.tls_public_key) {
            (Some(compact_id), Some(public_key))
                if !public_key.is_empty()
                    && NodePublicKey(public_key.clone()).derive_id() == compact_id =>
            {
                public_key.clone()
            }
            _ => return Err("invalid TLS identity".to_string()),
        };

        let target_parties = self.expected_parties;
        if target_parties == 0
            || registration.n_parties != target_parties
            || registration.party_id >= target_parties
            || registration.threshold >= target_parties
        {
            return Err("invalid party count, party ID, or threshold".to_string());
        }
        let mut state = self.session.lock().await;

        if let Some(active) = &state.active {
            let exact_retry = active.execution_id == registration.execution_id
                && active.program_id == registration.program_id
                && active.entry == registration.entry
                && active.n_parties == target_parties
                && active.threshold == registration.threshold
                && active
                    .parties
                    .contains(&(registration.party_id, registration.listen_addr))
                && active
                    .tls_ids
                    .contains(&(registration.party_id, registration.tls_derived_id.unwrap()))
                && active
                    .tls_public_keys
                    .contains(&(registration.party_id, tls_public_key.clone()));
            if !exact_retry {
                return Err("bootnode mesh session is already immutable".to_string());
            }
            return Ok(SessionRegistrationReport {
                registered_parties: active.parties.len(),
                target_parties: active.n_parties,
                ready_session: Some(active.clone()),
            });
        }

        let pending = state.pending.get_or_insert_with(|| PendingSession {
            execution_id: registration.execution_id,
            program_id: registration.program_id,
            entry: registration.entry.clone(),
            n_parties: target_parties,
            threshold: registration.threshold,
            parties: HashMap::new(),
            tls_ids: HashMap::new(),
            tls_public_keys: HashMap::new(),
        });

        if pending.execution_id != registration.execution_id
            || pending.program_id != registration.program_id
            || pending.entry != registration.entry
            || pending.n_parties != target_parties
            || pending.threshold != registration.threshold
        {
            return Err("registration does not match the pending mesh session".to_string());
        }

        if let Some(existing_addr) = pending.parties.get(&registration.party_id) {
            let exact_retry = *existing_addr == registration.listen_addr
                && pending.tls_ids.get(&registration.party_id)
                    == registration.tls_derived_id.as_ref()
                && pending.tls_public_keys.get(&registration.party_id) == Some(&tls_public_key);
            if !exact_retry {
                return Err(format!(
                    "party {} is already registered with different identity or address",
                    registration.party_id
                ));
            }
        } else {
            if pending
                .tls_public_keys
                .values()
                .any(|existing| existing == &tls_public_key)
                || pending
                    .tls_ids
                    .values()
                    .any(|existing| Some(existing) == registration.tls_derived_id.as_ref())
            {
                return Err("one TLS identity cannot represent two logical parties".to_string());
            }
            pending
                .parties
                .insert(registration.party_id, registration.listen_addr);
            pending.tls_ids.insert(
                registration.party_id,
                registration.tls_derived_id.expect("validated TLS identity"),
            );
            pending
                .tls_public_keys
                .insert(registration.party_id, tls_public_key);
        }

        let registered_parties = pending.parties.len();
        if registered_parties < pending.n_parties {
            return Ok(SessionRegistrationReport {
                registered_parties,
                target_parties: pending.n_parties,
                ready_session: None,
            });
        }

        let pending = state
            .pending
            .take()
            .ok_or_else(|| "pending mesh session disappeared".to_string())?;
        let ready_session =
            pending.into_session_info(derive_instance_id_for_execution(&registration.execution_id));
        state.active = Some(ready_session.clone());
        self.session_tx.send_replace(Some(ready_session.clone()));

        Ok(SessionRegistrationReport {
            registered_parties,
            target_parties,
            ready_session: Some(ready_session),
        })
    }
}

pub(super) fn spawn_connection_handler(
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    required_auth_token: String,
) {
    tokio::spawn(async move {
        BootnodeConnection::new(conn, state, required_auth_token)
            .run()
            .await;
    });
}

struct BootnodeConnection {
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    session_rx: watch::Receiver<Option<SessionInfo>>,
    ice_rx: broadcast::Receiver<DiscoveryMessage>,
    required_auth_token: String,
    waiting_for_session: bool,
    my_execution_id: Option<ExecutionId>,
    my_party_id: Option<PartyId>,
}

impl BootnodeConnection {
    fn new(
        conn: Arc<dyn PeerConnection>,
        state: BootnodeState,
        required_auth_token: String,
    ) -> Self {
        let session_rx = state.subscribe_session();
        let ice_rx = state.subscribe_ice();
        Self {
            conn,
            state,
            session_rx,
            ice_rx,
            required_auth_token,
            waiting_for_session: false,
            my_execution_id: None,
            my_party_id: None,
        }
    }

    async fn run(mut self) {
        // `receive()` is not cancellation-safe, so one task owns the socket read
        // while this task reacts to complete frames and state notifications.
        let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(8);
        let reader_conn = Arc::clone(&self.conn);
        let reader = tokio::spawn(async move {
            loop {
                match reader_conn.receive().await {
                    Ok(buf) => {
                        if msg_tx.send(buf).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        loop {
            tokio::select! {
                message = msg_rx.recv() => match message {
                    Some(buf) => self.handle_buffer(buf).await,
                    None => break,
                },
                changed = self.session_rx.changed() => {
                    if changed.is_ok() {
                        self.send_ready_session_if_waiting().await;
                    }
                },
                message = self.ice_rx.recv() => {
                    if let Ok(message) = message {
                        self.relay_ice_message(message).await;
                    }
                },
            }
        }

        reader.abort();
    }

    async fn send_ready_session_if_waiting(&mut self) {
        if !self.waiting_for_session {
            return;
        }

        let session = self.session_rx.borrow().clone();
        if let Some(info) = session.filter(|info| Some(info.execution_id) == self.my_execution_id) {
            if let Err(err) = send_session_announce(&*self.conn, &info).await {
                eprintln!("[bootnode] Failed to send SessionAnnounce: {}", err);
            }
            self.waiting_for_session = false;
        }
    }

    async fn relay_ice_message(&self, ice_msg: DiscoveryMessage) {
        let Some(party_id) = self.my_party_id else {
            return;
        };

        let should_forward = match &ice_msg {
            DiscoveryMessage::IceCandidates {
                execution_id,
                to_party_id,
                ..
            }
            | DiscoveryMessage::IceExchangeRequest {
                execution_id,
                to_party_id,
                ..
            } => Some(*execution_id) == self.my_execution_id && *to_party_id == party_id,
            _ => false,
        };

        if should_forward {
            let _ = send_ctrl(&*self.conn, &ice_msg).await;
        }
    }

    async fn handle_buffer(&mut self, buf: Vec<u8>) {
        if let Ok(message) = bincode::deserialize::<DiscoveryMessage>(&buf) {
            self.handle_discovery_message(message).await;
        } else if let Ok(message) = bincode::deserialize::<SessionMessage>(&buf) {
            self.handle_session_message(message);
        }
    }

    async fn handle_discovery_message(&mut self, message: DiscoveryMessage) {
        match message {
            DiscoveryMessage::RegisterWithSession {
                execution_id,
                party_id,
                listen_addr,
                program_id,
                entry,
                n_parties,
                threshold,
                auth_token,
                tls_derived_id,
                tls_public_key,
            } => {
                let registration = SessionRegistration {
                    execution_id,
                    party_id,
                    listen_addr,
                    program_id,
                    entry,
                    n_parties,
                    threshold,
                    tls_derived_id,
                    tls_public_key,
                };
                self.handle_session_registration(registration, auth_token)
                    .await;
            }
            DiscoveryMessage::IceCandidates {
                execution_id,
                from_party_id,
                to_party_id,
                ufrag,
                pwd,
                candidates,
            } => {
                if !self.authenticated_sender_matches("IceCandidates", execution_id, from_party_id)
                {
                    return;
                }
                eprintln!(
                    "[bootnode] Relaying {} ICE candidates from party {} to party {}",
                    candidates.len(),
                    from_party_id,
                    to_party_id
                );
                self.state.publish_ice(DiscoveryMessage::IceCandidates {
                    execution_id,
                    from_party_id,
                    to_party_id,
                    ufrag,
                    pwd,
                    candidates,
                });
            }
            DiscoveryMessage::IceExchangeRequest {
                execution_id,
                from_party_id,
                to_party_id,
            } => {
                if !self.authenticated_sender_matches(
                    "IceExchangeRequest",
                    execution_id,
                    from_party_id,
                ) {
                    return;
                }
                eprintln!(
                    "[bootnode] ICE exchange request from party {} to party {}",
                    from_party_id, to_party_id
                );
                self.state
                    .publish_ice(DiscoveryMessage::IceExchangeRequest {
                        execution_id,
                        from_party_id,
                        to_party_id,
                    });
            }
        }
    }

    fn authenticated_party_id(&self, message_kind: &str) -> Option<PartyId> {
        let party_id = self.my_party_id;
        if party_id.is_none() {
            eprintln!(
                "[bootnode] Rejected {} from unauthenticated connection",
                message_kind
            );
        }
        party_id
    }

    fn authenticated_sender_matches(
        &self,
        message_kind: &str,
        execution_id: ExecutionId,
        from_party_id: PartyId,
    ) -> bool {
        match self.authenticated_party_id(message_kind) {
            Some(party_id)
                if party_id == from_party_id && self.my_execution_id == Some(execution_id) =>
            {
                true
            }
            Some(party_id) if party_id == from_party_id => {
                eprintln!(
                    "[bootnode] Rejected {} from party {} for unrelated execution",
                    message_kind, party_id
                );
                false
            }
            Some(party_id) => {
                eprintln!(
                    "[bootnode] Rejected {} from party {} spoofing party {}",
                    message_kind, party_id, from_party_id
                );
                false
            }
            None => false,
        }
    }

    async fn handle_session_registration(
        &mut self,
        registration: SessionRegistration,
        auth_token: String,
    ) {
        let party_id = registration.party_id;
        if !registration_token_is_valid(&self.required_auth_token, &auth_token) {
            eprintln!(
                "[bootnode] Rejected RegisterWithSession from party {} (invalid auth token)",
                party_id
            );
            self.waiting_for_session = false;
            return;
        }

        let execution_id = registration.execution_id;
        let program_id = registration.program_id;
        eprintln!(
            "[bootnode] Party {} registering for mesh (program: {}, n={}, t={})",
            party_id,
            hex::encode(&program_id[..8]),
            registration.n_parties,
            registration.threshold
        );

        let report = match self.state.register_session(registration).await {
            Ok(report) => report,
            Err(err) => {
                eprintln!(
                    "[bootnode] Rejected party {} from mesh session: {}",
                    party_id, err
                );
                self.waiting_for_session = false;
                return;
            }
        };

        self.my_party_id = Some(party_id);
        self.my_execution_id = Some(execution_id);
        self.waiting_for_session = report.ready_session.is_none();

        if let Some(session_info) = report.ready_session {
            eprintln!(
                "[bootnode] Mesh ready: instance_id={}, n_parties={}",
                session_info.instance_id, session_info.n_parties
            );
            if let Err(err) = send_session_announce(&*self.conn, &session_info).await {
                eprintln!(
                    "[bootnode] Failed to send immediate SessionAnnounce to party {}: {}",
                    party_id, err
                );
            }
            self.waiting_for_session = false;
        } else {
            eprintln!(
                "[bootnode] Mesh registration {}/{}",
                report.registered_parties, report.target_parties
            );
        }
    }

    fn handle_session_message(&self, message: SessionMessage) {
        match message {
            SessionMessage::SessionAnnounce(_) => {}
            SessionMessage::SessionAck {
                execution_id,
                party_id,
                instance_id,
                ..
            } => {
                eprintln!(
                    "[bootnode] Received SessionAck from party {} for execution {} (instance {})",
                    party_id, execution_id, instance_id
                );
            }
            _ => {}
        }
    }
}

impl PendingSession {
    fn into_session_info(self, instance_id: u64) -> SessionInfo {
        SessionInfo {
            execution_id: self.execution_id,
            program_id: self.program_id,
            instance_id,
            entry: self.entry,
            parties: self.parties.into_iter().collect(),
            n_parties: self.n_parties,
            threshold: self.threshold,
            tls_ids: self.tls_ids.into_iter().collect(),
            tls_public_keys: self.tls_public_keys.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as StdMutex};
    use stoffelnet::network_utils::ClientType;
    use stoffelnet::transports::quic::{ConnectionState, PeerConnection};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn execution_id(byte: u8) -> ExecutionId {
        ExecutionId::from([byte; 32])
    }

    fn tls_public_key(party_id: PartyId) -> Vec<u8> {
        format!("test-party-{party_id}-spki").into_bytes()
    }

    fn registration(party_id: PartyId, program_id: [u8; 32]) -> SessionRegistration {
        registration_for(execution_id(1), party_id, program_id)
    }

    fn registration_for(
        execution_id: ExecutionId,
        party_id: PartyId,
        program_id: [u8; 32],
    ) -> SessionRegistration {
        let tls_public_key = tls_public_key(party_id);
        SessionRegistration {
            execution_id,
            party_id,
            listen_addr: addr(10_000 + party_id as u16),
            program_id,
            entry: "main".to_string(),
            n_parties: 2,
            threshold: 1,
            tls_derived_id: Some(NodePublicKey(tls_public_key.clone()).derive_id()),
            tls_public_key: Some(tls_public_key),
        }
    }

    #[derive(Default)]
    struct RecordingConnection {
        sent: StdMutex<Vec<Vec<u8>>>,
    }

    impl PeerConnection for RecordingConnection {
        fn send<'a>(
            &'a self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.sent
                    .lock()
                    .expect("sent lock poisoned")
                    .push(data.to_vec());
                Ok(())
            })
        }

        fn receive<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async { Err("no scripted receive".to_string()) })
        }

        fn remote_address(&self) -> SocketAddr {
            addr(20_000)
        }

        fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>> {
            Box::pin(async { ConnectionState::Connected })
        }

        fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async { true })
        }

        fn get_connection_role(&self) -> ClientType {
            ClientType::Server
        }

        fn remote_party_id(&self) -> Option<PartyId> {
            None
        }

        fn set_remote_party_id(&self, _party_id: PartyId) {}
    }

    #[tokio::test]
    async fn ice_relay_rejects_unauthenticated_and_spoofed_senders() {
        let state = BootnodeState::new(2);
        let mut ice_rx = state.subscribe_ice();
        let conn = Arc::new(RecordingConnection::default());
        let mut handler = BootnodeConnection::new(conn, state, "test-secret".to_string());
        let execution_id = execution_id(1);

        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                execution_id,
                from_party_id: 1,
                to_party_id: 2,
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler.my_party_id = Some(1);
        handler.my_execution_id = Some(execution_id);
        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                execution_id,
                from_party_id: 2,
                to_party_id: 3,
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler
            .handle_discovery_message(DiscoveryMessage::IceCandidates {
                execution_id,
                from_party_id: 2,
                to_party_id: 3,
                ufrag: "ufrag".to_string(),
                pwd: "pwd".to_string(),
                candidates: Vec::new(),
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                execution_id,
                from_party_id: 1,
                to_party_id: 3,
            })
            .await;
        let relayed = ice_rx.try_recv().expect("matching sender relayed");
        assert!(matches!(
            relayed,
            DiscoveryMessage::IceExchangeRequest {
                execution_id: relayed_execution_id,
                from_party_id: 1,
                to_party_id: 3
            } if relayed_execution_id == execution_id
        ));

        handler
            .handle_discovery_message(DiscoveryMessage::IceCandidates {
                execution_id,
                from_party_id: 1,
                to_party_id: 3,
                ufrag: "ufrag".to_string(),
                pwd: "pwd".to_string(),
                candidates: Vec::new(),
            })
            .await;
        let relayed = ice_rx.try_recv().expect("matching candidates relayed");
        assert!(matches!(
            relayed,
            DiscoveryMessage::IceCandidates {
                execution_id: relayed_execution_id,
                from_party_id: 1,
                to_party_id: 3,
                ..
            } if relayed_execution_id == execution_id
        ));
    }

    #[tokio::test]
    async fn registration_forms_one_pinned_immutable_mesh() {
        let state = BootnodeState::new(2);
        let program_id = [7u8; 32];

        let first = state
            .register_session(registration(0, program_id))
            .await
            .expect("first party registers");
        assert_eq!((first.registered_parties, first.target_parties), (1, 2));
        assert!(first.ready_session.is_none());

        let session = state
            .register_session(registration(1, program_id))
            .await
            .expect("second party registers")
            .ready_session
            .expect("mesh is ready");
        assert_eq!(session.execution_id, execution_id(1));
        assert_eq!(session.parties.len(), 2);
        assert_eq!(session.tls_ids.len(), 2);
        assert_eq!(session.tls_public_keys.len(), 2);

        assert!(state
            .register_session(registration_for(execution_id(2), 0, program_id))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn invalid_or_reused_tls_identity_does_not_poison_pending_mesh() {
        let state = BootnodeState::new(2);
        let program_id = [8u8; 32];
        let mut invalid = registration(0, program_id);
        invalid.tls_derived_id = invalid.tls_derived_id.map(|id| id ^ 1);
        assert!(state.register_session(invalid).await.is_err());

        state
            .register_session(registration(0, program_id))
            .await
            .expect("valid first identity registers");
        let duplicate_key = tls_public_key(0);
        let mut duplicate = registration(1, program_id);
        duplicate.tls_derived_id = Some(NodePublicKey(duplicate_key.clone()).derive_id());
        duplicate.tls_public_key = Some(duplicate_key);
        assert!(state.register_session(duplicate).await.is_err());

        assert!(state
            .register_session(registration(1, program_id))
            .await
            .expect("valid second identity registers")
            .ready_session
            .is_some());
    }

    #[tokio::test]
    async fn mismatched_registration_is_rejected_without_poisoning_mesh() {
        let state = BootnodeState::new(2);
        state
            .register_session(registration(0, [1u8; 32]))
            .await
            .expect("first party registers");
        assert!(state
            .register_session(registration(1, [2u8; 32]))
            .await
            .is_err());
        assert!(state
            .register_session(registration(1, [1u8; 32]))
            .await
            .expect("matching party still completes mesh")
            .ready_session
            .is_some());
    }

    #[tokio::test]
    async fn exact_registration_retries_are_idempotent() {
        let state = BootnodeState::new(2);
        let first = registration(0, [3u8; 32]);
        state
            .register_session(first.clone())
            .await
            .expect("initial registration succeeds");
        let retry = state
            .register_session(first)
            .await
            .expect("pending retry succeeds");
        assert_eq!(retry.registered_parties, 1);

        let second = registration(1, [3u8; 32]);
        state
            .register_session(second.clone())
            .await
            .expect("mesh completes");
        assert!(state
            .register_session(second)
            .await
            .expect("active retry succeeds")
            .ready_session
            .is_some());
    }

    #[tokio::test]
    async fn zero_execution_id_is_rejected() {
        let state = BootnodeState::new(1);
        assert!(state
            .register_session(registration_for(ExecutionId::from([0; 32]), 0, [3u8; 32]))
            .await
            .is_err());
    }
}

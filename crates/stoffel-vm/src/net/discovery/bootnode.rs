use super::{registration_token_is_valid, send_ctrl, send_session_announce, DiscoveryMessage};
use crate::net::{
    program_sync::{send_ctrl as send_prog_ctrl, send_program_bytes, ProgramSyncMessage},
    session::{derive_instance_id, random_instance_id, SessionInfo, SessionMessage},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::PeerConnection;
use tokio::sync::{broadcast, watch, Mutex};

#[derive(Debug, Clone)]
struct PendingSession {
    program_id: [u8; 32],
    entry: String,
    n_parties: usize,
    threshold: usize,
    parties: HashMap<PartyId, SocketAddr>,
    tls_ids: HashMap<PartyId, PartyId>,
    nonce: u64,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistration {
    pub party_id: PartyId,
    pub listen_addr: SocketAddr,
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    pub tls_derived_id: Option<PartyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionRegistrationEvent {
    Created {
        target_parties: usize,
    },
    Joined {
        registered_parties: usize,
        target_parties: usize,
    },
    RejectedProgramMismatch,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistrationReport {
    pub event: SessionRegistrationEvent,
    pub ready_session: Option<SessionInfo>,
}

#[derive(Clone)]
pub(super) struct BootnodeState {
    parties: Arc<Mutex<HashMap<PartyId, SocketAddr>>>,
    active_session: Arc<Mutex<Option<SessionInfo>>>,
    program_bytes: Arc<Mutex<Option<Arc<Vec<u8>>>>>,
    pending_session: Arc<Mutex<Option<PendingSession>>>,
    expected_parties: Option<usize>,
    session_tx: watch::Sender<Option<SessionInfo>>,
    ice_tx: broadcast::Sender<DiscoveryMessage>,
}

impl BootnodeState {
    pub fn new(expected_parties: Option<usize>) -> Self {
        let (session_tx, _session_rx) = watch::channel(None);
        let (ice_tx, _ice_rx) = broadcast::channel(256);
        Self {
            parties: Arc::new(Mutex::new(HashMap::new())),
            active_session: Arc::new(Mutex::new(None)),
            program_bytes: Arc::new(Mutex::new(None)),
            pending_session: Arc::new(Mutex::new(None)),
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

    pub async fn register_peer_and_list_others(
        &self,
        party_id: PartyId,
        listen_addr: SocketAddr,
    ) -> PeerRegistration {
        let mut parties = self.parties.lock().await;
        let is_new = !parties.contains_key(&party_id);
        parties.insert(party_id, listen_addr);
        let peers = parties
            .iter()
            .filter(|(pid, _)| **pid != party_id)
            .map(|(pid, addr)| (*pid, *addr))
            .collect();
        PeerRegistration { is_new, peers }
    }

    pub async fn register_peer(&self, party_id: PartyId, listen_addr: SocketAddr) {
        self.parties.lock().await.insert(party_id, listen_addr);
    }

    pub async fn peer_list(&self) -> Vec<(PartyId, SocketAddr)> {
        self.parties
            .lock()
            .await
            .iter()
            .map(|(pid, addr)| (*pid, *addr))
            .collect()
    }

    pub async fn store_program_bytes_if_missing(&self, bytes: Vec<u8>) -> bool {
        let mut program_bytes = self.program_bytes.lock().await;
        if program_bytes.is_some() {
            return false;
        }
        *program_bytes = Some(Arc::new(bytes));
        true
    }

    pub async fn program_bytes(&self) -> Option<Arc<Vec<u8>>> {
        self.program_bytes.lock().await.clone()
    }

    pub async fn register_session(
        &self,
        registration: SessionRegistration,
    ) -> Result<SessionRegistrationReport, String> {
        let mut pending = self.pending_session.lock().await;
        let target_parties = self.expected_parties.unwrap_or(registration.n_parties);

        let event = match pending.as_mut() {
            Some(session) => {
                if session.program_id != registration.program_id {
                    SessionRegistrationEvent::RejectedProgramMismatch
                } else {
                    session
                        .parties
                        .insert(registration.party_id, registration.listen_addr);
                    if let Some(tls_derived_id) = registration.tls_derived_id {
                        session
                            .tls_ids
                            .insert(registration.party_id, tls_derived_id);
                    }
                    SessionRegistrationEvent::Joined {
                        registered_parties: session.parties.len(),
                        target_parties: session.n_parties,
                    }
                }
            }
            None => {
                let mut parties = HashMap::new();
                parties.insert(registration.party_id, registration.listen_addr);
                let mut tls_ids = HashMap::new();
                if let Some(tls_derived_id) = registration.tls_derived_id {
                    tls_ids.insert(registration.party_id, tls_derived_id);
                }
                *pending = Some(PendingSession {
                    program_id: registration.program_id,
                    entry: registration.entry,
                    n_parties: target_parties,
                    threshold: registration.threshold,
                    parties,
                    tls_ids,
                    nonce: session_nonce(),
                });
                SessionRegistrationEvent::Created { target_parties }
            }
        };

        if matches!(event, SessionRegistrationEvent::RejectedProgramMismatch) {
            return Ok(SessionRegistrationReport {
                event,
                ready_session: None,
            });
        }

        let ready = pending
            .as_ref()
            .is_some_and(|session| session.parties.len() >= session.n_parties);

        let ready_session = if ready {
            let Some(session) = pending.take() else {
                return Err("pending session disappeared while announcing readiness".to_string());
            };
            let session_info = session.into_session_info();
            *self.active_session.lock().await = Some(session_info.clone());
            let _ = self.session_tx.send(Some(session_info.clone()));
            Some(session_info)
        } else {
            None
        };

        Ok(SessionRegistrationReport {
            event,
            ready_session,
        })
    }
}

pub(super) fn spawn_connection_handler(
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    required_auth_token: Option<String>,
) {
    tokio::spawn(async move {
        BootnodeConnection::new(conn, state, required_auth_token)
            .run()
            .await;
    });
}

#[derive(Debug, Clone)]
pub(super) struct PeerRegistration {
    pub is_new: bool,
    pub peers: Vec<(PartyId, SocketAddr)>,
}

struct BootnodeConnection {
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    session_rx: watch::Receiver<Option<SessionInfo>>,
    ice_rx: broadcast::Receiver<DiscoveryMessage>,
    required_auth_token: Option<String>,
    waiting_for_session: bool,
    my_party_id: Option<PartyId>,
}

impl BootnodeConnection {
    fn new(
        conn: Arc<dyn PeerConnection>,
        state: BootnodeState,
        required_auth_token: Option<String>,
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
            my_party_id: None,
        }
    }

    async fn run(mut self) {
        loop {
            self.send_ready_session_if_waiting().await;
            self.relay_pending_ice_messages().await;

            match tokio::time::timeout(Duration::from_millis(50), self.conn.receive()).await {
                Ok(Ok(buf)) => self.handle_buffer(buf).await,
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    }

    async fn send_ready_session_if_waiting(&mut self) {
        if !self.waiting_for_session {
            return;
        }

        let session_info = self.session_rx.borrow().clone();
        if let Some(info) = session_info {
            if let Err(err) = send_session_announce(&*self.conn, &info).await {
                eprintln!("[bootnode] Failed to send SessionAnnounce: {}", err);
            }
            self.waiting_for_session = false;
        }
    }

    async fn relay_pending_ice_messages(&mut self) {
        let Some(party_id) = self.my_party_id else {
            return;
        };

        while let Ok(ice_msg) = self.ice_rx.try_recv() {
            let should_forward = match &ice_msg {
                DiscoveryMessage::IceCandidates { to_party_id, .. }
                | DiscoveryMessage::IceExchangeRequest { to_party_id, .. } => {
                    *to_party_id == party_id
                }
                _ => false,
            };

            if should_forward {
                let _ = send_ctrl(&*self.conn, &ice_msg).await;
            }
        }
    }

    async fn handle_buffer(&mut self, buf: Vec<u8>) {
        if let Ok(message) = bincode::deserialize::<DiscoveryMessage>(&buf) {
            self.handle_discovery_message(message).await;
        } else if let Ok(message) = bincode::deserialize::<ProgramSyncMessage>(&buf) {
            self.handle_program_sync_message(message).await;
        } else if let Ok(message) = bincode::deserialize::<SessionMessage>(&buf) {
            self.handle_session_message(message);
        }
    }

    async fn handle_discovery_message(&mut self, message: DiscoveryMessage) {
        match message {
            DiscoveryMessage::Register {
                party_id,
                listen_addr,
                auth_token,
            } => {
                self.handle_register(party_id, listen_addr, auth_token)
                    .await;
            }
            DiscoveryMessage::RegisterWithSession {
                party_id,
                listen_addr,
                program_id,
                entry,
                n_parties,
                threshold,
                program_bytes,
                auth_token,
                tls_derived_id,
            } => {
                let registration = SessionRegistration {
                    party_id,
                    listen_addr,
                    program_id,
                    entry,
                    n_parties,
                    threshold,
                    tls_derived_id,
                };
                self.handle_session_registration(registration, program_bytes, auth_token)
                    .await;
            }
            DiscoveryMessage::RequestPeers => {
                let peers = self.state.peer_list().await;
                let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerList { peers }).await;
            }
            DiscoveryMessage::Heartbeat => {}
            DiscoveryMessage::ProgramFetchRequest { program_id } => {
                self.handle_program_fetch_request(program_id).await;
            }
            DiscoveryMessage::IceCandidates {
                from_party_id,
                to_party_id,
                ufrag,
                pwd,
                candidates,
            } => {
                eprintln!(
                    "[bootnode] Relaying {} ICE candidates from party {} to party {}",
                    candidates.len(),
                    from_party_id,
                    to_party_id
                );
                self.state.publish_ice(DiscoveryMessage::IceCandidates {
                    from_party_id,
                    to_party_id,
                    ufrag,
                    pwd,
                    candidates,
                });
            }
            DiscoveryMessage::IceExchangeRequest {
                from_party_id,
                to_party_id,
            } => {
                eprintln!(
                    "[bootnode] ICE exchange request from party {} to party {}",
                    from_party_id, to_party_id
                );
                self.state
                    .publish_ice(DiscoveryMessage::IceExchangeRequest {
                        from_party_id,
                        to_party_id,
                    });
            }
            _ => {}
        }
    }

    async fn handle_register(
        &mut self,
        party_id: PartyId,
        listen_addr: SocketAddr,
        auth_token: Option<String>,
    ) {
        if !registration_token_is_valid(self.required_auth_token.as_deref(), auth_token.as_deref())
        {
            eprintln!(
                "[bootnode] Rejected Register from party {} (invalid auth token)",
                party_id
            );
            return;
        }

        self.my_party_id = Some(party_id);
        let registration = self
            .state
            .register_peer_and_list_others(party_id, listen_addr)
            .await;
        let peers = registration.peers;
        let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerList { peers }).await;

        if registration.is_new {
            let joined = DiscoveryMessage::PeerJoined {
                party_id,
                listen_addr,
            };
            let _ = send_ctrl(&*self.conn, &joined).await;
        }
    }

    async fn handle_session_registration(
        &mut self,
        registration: SessionRegistration,
        program_bytes: Option<Vec<u8>>,
        auth_token: Option<String>,
    ) {
        let party_id = registration.party_id;
        if !registration_token_is_valid(self.required_auth_token.as_deref(), auth_token.as_deref())
        {
            eprintln!(
                "[bootnode] Rejected RegisterWithSession from party {} (invalid auth token)",
                party_id
            );
            self.waiting_for_session = false;
            return;
        }

        self.my_party_id = Some(party_id);
        eprintln!(
            "[bootnode] Party {} registering for session (program: {}, n={}, t={}, has_bytes={})",
            party_id,
            hex::encode(&registration.program_id[..8]),
            registration.n_parties,
            registration.threshold,
            program_bytes.is_some()
        );

        if let Some(bytes) = program_bytes {
            let byte_len = bytes.len();
            if self.state.store_program_bytes_if_missing(bytes).await {
                eprintln!(
                    "[bootnode] Storing program bytes from party {} ({} bytes)",
                    party_id, byte_len
                );
            }
        }

        self.state
            .register_peer(party_id, registration.listen_addr)
            .await;
        self.waiting_for_session = true;

        let report = match self.state.register_session(registration).await {
            Ok(report) => report,
            Err(err) => {
                eprintln!(
                    "[bootnode] Failed to register party {} for session: {}",
                    party_id, err
                );
                self.waiting_for_session = false;
                return;
            }
        };

        match report.event {
            SessionRegistrationEvent::Created { target_parties } => {
                eprintln!(
                    "[bootnode] Created pending session, waiting for {} parties (have 1)",
                    target_parties
                );
            }
            SessionRegistrationEvent::Joined {
                registered_parties,
                target_parties,
            } => {
                eprintln!(
                    "[bootnode] Party {} joined, have {}/{} parties",
                    party_id, registered_parties, target_parties
                );
            }
            SessionRegistrationEvent::RejectedProgramMismatch => {
                eprintln!(
                    "[bootnode] Warning: party {} has different program_id",
                    party_id
                );
                let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerLeft { party_id }).await;
                self.waiting_for_session = false;
                return;
            }
        }

        if let Some(session_info) = report.ready_session {
            eprintln!(
                "[bootnode] Session ready! instance_id={}, n_parties={}",
                session_info.instance_id, session_info.n_parties
            );
        }
    }

    async fn handle_program_fetch_request(&self, program_id: [u8; 32]) {
        if let Some(bytes) = self.state.program_bytes().await {
            eprintln!(
                "[bootnode] Sending program bytes ({} bytes) for {}",
                bytes.len(),
                hex::encode(&program_id[..8])
            );
            let resp = DiscoveryMessage::ProgramFetchResponse {
                program_id,
                bytes: bytes.to_vec(),
            };
            let _ = send_ctrl(&*self.conn, &resp).await;
        } else {
            eprintln!(
                "[bootnode] Program fetch request for {} but no bytes cached",
                hex::encode(&program_id[..8])
            );
        }
    }

    async fn handle_program_sync_message(&self, message: ProgramSyncMessage) {
        match message {
            ProgramSyncMessage::ProgramAnnounce { .. } => {
                let _ = send_prog_ctrl(&*self.conn, &message).await;
            }
            ProgramSyncMessage::ProgramFetchRequest { program_id } => {
                if let Some(bytes) = self.state.program_bytes().await {
                    let _ = send_program_bytes(&*self.conn, program_id, bytes).await;
                }
            }
            _ => {}
        }
    }

    fn handle_session_message(&self, message: SessionMessage) {
        match message {
            SessionMessage::SessionAnnounce(_) => {}
            SessionMessage::SessionAck {
                party_id,
                instance_id,
                ..
            } => {
                eprintln!(
                    "[bootnode] Received SessionAck from party {} for instance {}",
                    party_id, instance_id
                );
            }
            _ => {}
        }
    }
}

impl PendingSession {
    fn into_session_info(self) -> SessionInfo {
        SessionInfo {
            program_id: self.program_id,
            instance_id: derive_instance_id(&self.program_id, self.nonce),
            entry: self.entry,
            parties: self.parties.into_iter().collect(),
            n_parties: self.n_parties,
            threshold: self.threshold,
            tls_ids: self.tls_ids.into_iter().collect(),
        }
    }
}

fn session_nonce() -> u64 {
    random_instance_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn registration(party_id: PartyId, program_id: [u8; 32]) -> SessionRegistration {
        SessionRegistration {
            party_id,
            listen_addr: addr(10_000 + party_id as u16),
            program_id,
            entry: "main".to_string(),
            n_parties: 2,
            threshold: 1,
            tls_derived_id: Some(100 + party_id),
        }
    }

    #[tokio::test]
    async fn session_registration_announces_ready_without_manual_unwraps() {
        let state = BootnodeState::new(None);
        let program_id = [7u8; 32];

        let first = state
            .register_session(registration(0, program_id))
            .await
            .expect("first party registers");
        assert_eq!(
            first.event,
            SessionRegistrationEvent::Created { target_parties: 2 }
        );
        assert!(first.ready_session.is_none());

        let second = state
            .register_session(registration(1, program_id))
            .await
            .expect("second party registers");
        assert_eq!(
            second.event,
            SessionRegistrationEvent::Joined {
                registered_parties: 2,
                target_parties: 2
            }
        );
        let session = second.ready_session.expect("session is ready");
        assert_eq!(session.n_parties, 2);
        assert_eq!(session.threshold, 1);
        assert_eq!(session.parties.len(), 2);
        assert_eq!(session.tls_ids.len(), 2);
    }

    #[tokio::test]
    async fn session_registration_rejects_mismatched_program_without_poisoning_pending_session() {
        let state = BootnodeState::new(Some(2));

        state
            .register_session(registration(0, [1u8; 32]))
            .await
            .expect("first party registers");

        let mismatch = state
            .register_session(registration(1, [2u8; 32]))
            .await
            .expect("mismatched party is handled");
        assert_eq!(
            mismatch.event,
            SessionRegistrationEvent::RejectedProgramMismatch
        );
        assert!(mismatch.ready_session.is_none());

        let valid = state
            .register_session(registration(1, [1u8; 32]))
            .await
            .expect("matching party registers after mismatch");
        let session = valid.ready_session.expect("session becomes ready");
        assert!(session
            .parties
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 1 && *listen_addr == addr(10_001)));
    }
}

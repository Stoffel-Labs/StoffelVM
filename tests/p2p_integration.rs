#[cfg(test)]
mod p2p_integration_tests {
    use stoffel_vm::net::light_udp::{PacketHeader, PacketFlags, StreamState, SentPacketInfo, parse_packet, serialize_packet, MAX_PAYLOAD_SIZE};
    use stoffel_vm::net::p2p::{NetworkManager as P2PNetworkManager, PeerConnection as P2PPeerConnection};
    use bytes::{Bytes, BytesMut};
    use std::collections::{HashMap, VecDeque, BTreeMap};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::future::Future;
    use std::time::{Duration, Instant};
    use std::sync::Arc;
    use tokio::sync::{Mutex, mpsc::{self, Sender, Receiver}};

    // --- Redefine Traits for Stream-Aware Communication ---

    /// Represents a stream-aware connection to a peer.
    pub trait StreamPeerConnection: Send + Sync {
        /// Sends data on a specific stream.
        fn send<'a>(&'a mut self, stream_id: u64, data: &'a [u8]) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>>;

        /// Receives data, returning the stream ID and the data.
        fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(u64, Vec<u8>), String>> + Send + 'a>>;

        /// Returns the address of the remote peer.
        fn remote_address(&self) -> SocketAddr;

        /// Closes a specific stream gracefully.
        fn close_stream<'a>(&'a mut self, stream_id: u64) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>>;

        /// Closes the entire connection immediately.
        fn close_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>>;
    }

    /// Manages stream-aware connections.
    pub trait StreamNetworkManager: Send + Sync {
        /// Establishes a connection to a new peer.
        fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<Box<dyn StreamPeerConnection>, String>> + Send + 'a>>;

        /// Listens for incoming connections and returns a receiver for new connections.
        /// The receiver yields Box<dyn StreamPeerConnection>.
        fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<mpsc::Receiver<Box<dyn StreamPeerConnection>>, String>> + Send + 'a>>;
    }

    // --- Mock Implementations ---

    // Simulate packet loss and reordering
    const MOCK_PACKET_LOSS_RATE: f64 = 0.05; // 5% loss
    const MOCK_MAX_REORDER_DELAY: Duration = Duration::from_millis(50); // Max delay for reordering

    // Represents one end of a simulated connection using the lightweight UDP protocol concepts
    struct MockPeerConnection {
        remote_addr: SocketAddr,
        // Underlying raw packet channel (simulates UDP socket)
        raw_tx: Sender<Bytes>,
        raw_rx: Arc<Mutex<Receiver<Bytes>>>,
        // Per-stream state management
        streams: Arc<Mutex<BTreeMap<u64, StreamState>>>,
        // Buffer for application data ready to be delivered (Stream ID, Data)
        delivery_queue: Arc<Mutex<VecDeque<(u64, Bytes)>>>,
        // Task handle for the background processing loop (receiving, ACKing, retransmitting)
        _process_handle: tokio::task::JoinHandle<()>,
        close_signal: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>, // To signal closure
        // Shared sender for waking up the processing loop
        notify_tx: Arc<tokio::sync::Notify>,
    }

    impl StreamPeerConnection for MockPeerConnection {
        fn send<'a>(&'a mut self, stream_id: u64, data: &'a [u8]) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            // Clone necessary data to move into the async block
            let streams_clone = Arc::clone(&self.streams);
            let notify_clone = Arc::clone(&self.notify_tx);
            let data_bytes = Bytes::copy_from_slice(data); // Own the data

            Box::pin(async move {
                let mut streams_guard = streams_clone.lock().await;
                let stream = streams_guard.entry(stream_id).or_insert_with(|| StreamState::new(0, 10)); // Get or create stream state

                // TODO: Respect congestion window and flow control limits

                // Buffer the data to be sent
                stream.send_buffer.push_back(data_bytes);

                // Notify the processing loop to potentially send the data
                notify_clone.notify_one();

                Ok(())
            })
        }

        fn receive<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(u64, Vec<u8>), String>> + Send + 'a>> {
            // Clone Arc for async block
            let delivery_queue_clone = Arc::clone(&self.delivery_queue);
            let notify_clone = Arc::clone(&self.notify_tx);

            Box::pin(async move {
                loop {
                    // Try to get data from the delivery queue first
                    { // Scope for mutex guard
                        let mut queue_guard = delivery_queue_clone.lock().await;
                        if let Some((stream_id, data)) = queue_guard.pop_front() {
                            return Ok((stream_id, data.to_vec()));
                        }
                    } // Mutex guard dropped

                    // If queue is empty, wait for the processing loop to notify us
                    // This waits until notify_one() is called OR the Notify is dropped.
                    notify_clone.notified().await;

                    // Need to handle the case where the connection is closed while waiting.
                    // A more robust implementation would use a select!{} with a close signal.
                    // For simplicity, we rely on the processing loop exiting and dropping the Notify.
                }
            })
        }

        fn remote_address(&self) -> SocketAddr {
            self.remote_addr
        }

        fn close_stream<'a>(&'a mut self, stream_id: u64) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            // Clone necessary data
            let streams_clone = Arc::clone(&self.streams);
            let notify_clone = Arc::clone(&self.notify_tx);

            Box::pin(async move {
                let mut streams_guard = streams_clone.lock().await;
                if let Some(stream) = streams_guard.get_mut(&stream_id) {
                    if !stream.fin_sent {
                        stream.fin_sent = true;
                        // TODO: Queue a FIN packet to be sent by the processing loop
                        println!("Mock: Queuing FIN for stream {}", stream_id);
                        notify_clone.notify_one(); // Wake up processor to send FIN
                    }
                } else {
                    // Stream doesn't exist or already closed locally
                }
                Ok(())
            })
        }

        fn close_connection<'a>(&'a mut self) -> Pin<Box<dyn Future<Output=Result<(), String>> + Send + 'a>> {
            let close_signal_clone = Arc::clone(&self.close_signal);
            Box::pin(async move {
                if let Some(sender) = self.close_signal.lock().await.take() {
                    let _ = sender.send(()); // Signal the other side
                }
                
                // Closing is implicit by dropping channels/sender
                Ok(())
            })
        }
    }

    // The NetworkManager now manages connections that speak the mock light_udp protocol
    #[derive(Clone, Default)]
    struct MockNetworkManager {
        // Map listening address to a channel where new connections are sent
        // The tuple now contains channels for raw byte packets (simulating UDP)
        listeners: Arc<Mutex<HashMap<SocketAddr, Sender<(SocketAddr, Sender<Bytes>, Arc<Mutex<Receiver<Bytes>>>)>>>>,
    }

    impl StreamNetworkManager for MockNetworkManager {
        fn connect<'a>(&'a mut self, address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<Box<dyn StreamPeerConnection>, String>> + Send + 'a>> {
            Box::pin(async move {
                let listener_tx = {                    // Lock the Tokio Mutex asynchronously
                    let listeners = self.listeners.lock().await;
                    let listener_tx = listeners.get(&address).cloned();
                    drop(listeners);
                    listener_tx
                };


                if let Some(listener_tx) = listener_tx {
                    // Create raw packet channels (Client perspective)
                    // Use Bytes for efficiency
                    let (client_raw_tx, server_raw_rx) = mpsc::channel::<Bytes>(100); // Client sends raw, Server receives raw
                    let (server_raw_tx, client_raw_rx) = mpsc::channel::<Bytes>(100); // Server sends raw, Client receives raw

                    // Create closure signals
                    let (client_close_tx, server_close_rx) = tokio::sync::oneshot::channel::<()>();
                    let (server_close_tx, _client_close_rx) = tokio::sync::oneshot::channel::<()>(); // Client doesn't need server's signal directly

                    // Simulate the client's address (can be arbitrary for mock)
                    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345); // Example client address

                    // Send connection details to the listener (using Tokio Mutex for Arc fields)
                    listener_tx.send((
                        client_addr,
                        server_raw_tx, // Give listener the sender to send raw *to* the client
                        Arc::new(Mutex::new(server_raw_rx)), // Wrap raw Receiver in Tokio Mutex
                    )).await.map_err(|_| "Listener closed".to_string())?;

                    // Wait for the server to potentially acknowledge closure
                    // let _ = server_close_rx.await; // This might block indefinitely if server doesn't signal

                    // Create the client-side connection object
                    let client_streams = Arc::new(Mutex::new(BTreeMap::new()));
                    let client_delivery_queue = Arc::new(Mutex::new(VecDeque::new()));
                    let client_notify = Arc::new(tokio::sync::Notify::new());
                    let client_raw_rx_arc = Arc::new(Mutex::new(client_raw_rx));

                    let process_handle = tokio::spawn(connection_processing_loop(
                        client_raw_tx.clone(), client_raw_rx_arc.clone(), client_streams.clone(), client_delivery_queue.clone(), client_notify.clone(), address, client_addr
                    ));

                    Ok(Box::new(MockPeerConnection {
                        remote_addr: address,
                        raw_tx: client_raw_tx,
                        raw_rx: client_raw_rx_arc,
                        streams: client_streams,
                        delivery_queue: client_delivery_queue,
                        _process_handle: process_handle,
                        close_signal: Arc::new(Mutex::new(Some(client_close_tx))), // Wrap Sender Option in Tokio Mutex
                        notify_tx: client_notify,
                    }) as Box<dyn StreamPeerConnection>)
                } else {
                    Err(format!("No listener found at {}", address))
                }
            })
        }

        fn listen<'a>(&'a mut self, bind_address: SocketAddr) -> Pin<Box<dyn Future<Output=Result<mpsc::Receiver<Box<dyn StreamPeerConnection>>, String>> + Send + 'a>> {
            Box::pin(async move {
                // Channel for the NetworkManager to receive connection details from connecting clients
                let (conn_details_tx, mut conn_details_rx) = mpsc::channel::<(SocketAddr, Sender<Bytes>, Arc<Mutex<Receiver<Bytes>>>)>(10);

                { // Scope for mutex guard
                    let mut listeners = self.listeners.lock().await;
                    if listeners.contains_key(&bind_address) {
                        return Err(format!("Address {} already in use", bind_address));
                    }
                    listeners.insert(bind_address, conn_details_tx);
                } // Mutex guard dropped

                println!("Mock server listening on {}", bind_address);

                // Channel to send newly accepted connection objects back to the caller of listen()
                let (new_conn_tx, new_conn_rx) = mpsc::channel::<Box<dyn StreamPeerConnection>>(10);

                // Spawn the listener task
                tokio::spawn(async move {
                    // Receive connection details (remote addr, channel to send *to* remote, channel to receive *from* remote)
                    while let Some((remote_addr, peer_raw_tx, peer_raw_rx_arc)) = conn_details_rx.recv().await {
                        println!("Listener on {} accepted connection from {}", bind_address, remote_addr);

                        // Create the server-side connection object for this peer
                        let server_streams = Arc::new(Mutex::new(BTreeMap::new()));
                        let server_delivery_queue = Arc::new(Mutex::new(VecDeque::new()));
                        let server_notify = Arc::new(tokio::sync::Notify::new());
                        let (server_close_tx, _server_close_rx) = tokio::sync::oneshot::channel::<()>(); // Server needs a way to signal close too

                        let process_handle = tokio::spawn(connection_processing_loop(
                            peer_raw_tx.clone(), // Use the TX channel provided by the client
                            peer_raw_rx_arc.clone(), // Use the RX channel provided by the client
                            server_streams.clone(),
                            server_delivery_queue.clone(),
                            server_notify.clone(),
                            bind_address, // Local addr
                            remote_addr // Remote addr
                        ));

                        let server_conn = MockPeerConnection {
                            remote_addr,
                            raw_tx: peer_raw_tx,
                            raw_rx: peer_raw_rx_arc,
                            streams: server_streams,
                            delivery_queue: server_delivery_queue,
                            _process_handle: process_handle,
                            close_signal: Arc::new(Mutex::new(Some(server_close_tx))), // Allow server to signal close
                            notify_tx: server_notify,
                        };

                        // Send the new connection object back to the application that called listen
                        if new_conn_tx.send(Box::new(server_conn)).await.is_err() {
                            eprintln!("Listener on {}: Failed to send new connection to application, receiver dropped.", bind_address);
                            // Optionally break or handle cleanup
                        }
                    }
                    println!("Listener on {} stopped.", bind_address);
                });

                Ok(new_conn_rx) // Return the receiver end for the application
            })
        }
    }

    // --- Background Processing Loop ---
    // This simulates the core protocol logic: packetizing, sending, receiving, ACKing, retransmitting
    async fn connection_processing_loop(
        raw_tx: Sender<Bytes>, // To send raw packets
        raw_rx: Arc<Mutex<Receiver<Bytes>>>, // To receive raw packets
        streams: Arc<Mutex<BTreeMap<u64, StreamState>>>, // Shared stream state
        delivery_queue: Arc<Mutex<VecDeque<(u64, Bytes)>>>, // Queue for received application data
        notify_rx: Arc<tokio::sync::Notify>, // Wakes up receiver task
        _local_addr: SocketAddr, // For logging/debugging
        remote_addr: SocketAddr, // For logging/debugging
    ) {
        println!("Starting processing loop for peer {}", remote_addr);
        let mut tick_interval = tokio::time::interval(Duration::from_millis(10)); // Check periodically
        let mut packets_to_send: VecDeque<(PacketHeader, Option<Bytes>)> = VecDeque::new(); // Packets ready to go out

        loop {
            tokio::select! {
                // Wait for notification from send() or receive() or timer tick
                _ = notify_rx.notified() => {
                    // Potential work to do (sending buffered data, ACKs, etc.)
                    println!("Processing loop notified for {}", remote_addr);
                }
                // Periodic tick for timers (RTO, probes)
                _ = tick_interval.tick() => {
                     // Check RTO timers, idle timers etc.
                     // println!("Processing loop tick for {}", remote_addr);
                }
                // Received a raw packet from the "network"
                maybe_packet = async { raw_rx.lock().await.recv().await }, if !raw_rx.lock().await.is_closed() => {
                    match maybe_packet {
                        Some(raw_data) => {
                            println!("Processing loop for {}: Received raw packet ({} bytes)", remote_addr, raw_data.len());
                            // Simulate potential packet loss
                            if rand::random::<f64>() < MOCK_PACKET_LOSS_RATE {
                                println!("Simulating packet loss for {}", remote_addr);
                                continue;
                            }
                            // Simulate reordering
                            if rand::random::<f64>() < 0.1 { // 10% chance of reorder
                                let delay = Duration::from_millis(rand::random::<u64>() % MOCK_MAX_REORDER_DELAY.as_millis() as u64);
                                println!("Simulating reorder delay ({:?}) for {}", delay, remote_addr);
                                let raw_tx_clone = raw_tx.clone();
                                // Spawn a task to re-inject the packet later
                                // THIS IS WRONG - should re-inject into the *receiver* side, not sender
                                // For mock, maybe just delay processing here?
                                tokio::time::sleep(delay).await;
                            }

                            match parse_packet(&raw_data) {
                                Ok((header, payload)) => {
                                    // Process the received packet (update ACKs, handle data, queue ACKs)
                                    handle_received_packet(header, payload, &streams, &delivery_queue, &mut packets_to_send, &notify_rx).await;
                                }
                                Err(e) => {
                                    eprintln!("Error parsing packet from {}: {}", remote_addr, e);
                                }
                            }
                        },
                        None => {
                            println!("Processing loop for {}: Raw receive channel closed.", remote_addr);
                            break; // Exit loop if channel is closed
                        }
                    }
                }
            } // end select!

            // --- Prepare packets to send ---
            prepare_packets_to_send(&streams, &mut packets_to_send).await;

            // --- Send queued packets ---
            while let Some((header, payload)) = packets_to_send.pop_front() {
                let packet_bytes = serialize_packet(&header, payload.as_ref());
                println!("Processing loop for {}: Sending packet Stream={}, Seq={}, Flags={:02x}, Len={}",
                         remote_addr, header.stream_id, header.sequence_number, header.flags, header.payload_length);
                if raw_tx.send(packet_bytes).await.is_err() {
                    eprintln!("Processing loop for {}: Failed to send raw packet, channel closed.", remote_addr);
                    break; // Exit loop if send fails
                }
                // Update stream state (bytes in flight, timers) after successful send
                if header.has_flag(PacketFlags::Data) || header.has_flag(PacketFlags::Fin) {
                    let mut streams_guard = streams.lock().await;
                    if let Some(stream) = streams_guard.get_mut(&header.stream_id) {
                        let packet_size = header.header_size() + header.payload_length as usize;
                        stream.bytes_in_flight += packet_size as u32;
                        stream.last_data_sent_time = Some(Instant::now());
                        // TODO: Set RTO timer if not already set
                        stream.sent_packets.insert(header.sequence_number, SentPacketInfo {
                            send_time: Instant::now(),
                            size: packet_size,
                            retransmission_count: 0,
                        });
                    }
                }
            }

            // TODO: Check RTOs and queue retransmissions
            check_timeouts_and_retransmit(&streams, &mut packets_to_send).await;
        } // end loop

        println!("Exiting processing loop for peer {}", remote_addr);
        // Ensure receiver waiting on notify_rx wakes up if loop exits
        notify_rx.notify_waiters();
    }

    // Helper function to process a received packet
    async fn handle_received_packet(
        header: PacketHeader,
        payload: Bytes,
        streams: &Arc<Mutex<BTreeMap<u64, StreamState>>>,
        delivery_queue: &Arc<Mutex<VecDeque<(u64, Bytes)>>>,
        packets_to_send: &mut VecDeque<(PacketHeader, Option<Bytes>)>, // To queue ACKs
        notify_rx: &Arc<tokio::sync::Notify>, // To wake up application receiver
    ) {
        let mut streams_guard = streams.lock().await;
        let stream = streams_guard.entry(header.stream_id).or_insert_with(|| StreamState::new(0, 10));

        println!("Handling packet for Stream={}, Seq={}, Flags={:02x}, Ack={}, PayloadLen={}",
                 header.stream_id, header.sequence_number, header.flags, header.ack_number, header.payload_length);

        // --- Process ACKs/SACKs ---
        if header.has_flag(PacketFlags::Ack) || header.has_flag(PacketFlags::Sack) {
            let mut acked_something = false;
            // Process contiguous ACKs
            if header.has_flag(PacketFlags::Ack) {
                let newly_acked = header.ack_number;
                // Remove acknowledged packets from sent_packets and update RTT
                let mut packets_to_remove = Vec::new();
                let mut rtt_samples = Vec::new();
                for (&seq, info) in stream.sent_packets.range(..=newly_acked) {
                    println!("ACK processing: Packet {} acked contiguously", seq);
                    let rtt_sample = info.send_time.elapsed();
                    rtt_samples.push(rtt_sample);
                    stream.bytes_in_flight = stream.bytes_in_flight.saturating_sub(info.size as u32);
                    packets_to_remove.push(seq);
                    acked_something = true;
                }
                // Update RTT with all samples after the immutable borrow is released
                for rtt_sample in rtt_samples {
                    stream.update_rtt(rtt_sample);
                }
                for seq in packets_to_remove {
                    stream.sent_packets.remove(&seq);
                }
                stream.highest_acked_seq = stream.highest_acked_seq.max(newly_acked);
            }
            // Process SACK ranges (TODO)
            if header.has_flag(PacketFlags::Sack) {
                for &(start, end) in &header.sack_ranges {
                    println!("SACK processing: Range {}-{} acked", start, end);
                    // Similar logic to ACK, but for specific ranges
                    // Remove from sent_packets, update bytes_in_flight
                    // Don't update RTT from SACKs usually
                }
            }
            if acked_something {
                // TODO: Update congestion window based on ACKs (e.g., increase cwnd)
                // TODO: Reset RTO timer if necessary
                stream.last_ack_received_time = Some(Instant::now());
            }
        }

        // --- Process Data ---
        if header.has_flag(PacketFlags::Data) {
            let seq = header.sequence_number;
            if seq >= stream.next_expected_seq {
                // Store data (even if out of order)
                // Avoid duplicates: check if already received or buffered
                if seq == stream.next_expected_seq {
                    // In-order packet
                    println!("Received in-order data for stream {}, seq {}", header.stream_id, seq);
                    stream.next_expected_seq += 1;
                    // Add to delivery queue
                    delivery_queue.lock().await.push_back((header.stream_id, payload.clone()));
                    notify_rx.notify_one(); // Notify application receiver

                    // Check buffer for next packets
                    while let Some(buffered_payload) = stream.received_buffer.remove(&stream.next_expected_seq) {
                        println!("Processing buffered data for stream {}, seq {}", header.stream_id, stream.next_expected_seq);
                        delivery_queue.lock().await.push_back((header.stream_id, buffered_payload));
                        notify_rx.notify_one();
                        stream.next_expected_seq += 1;
                    }
                } else {
                    // Out-of-order packet
                    println!("Received out-of-order data for stream {}, seq {} (expected {})", header.stream_id, seq, stream.next_expected_seq);
                    if !stream.received_buffer.contains_key(&seq) {
                        stream.received_buffer.insert(seq, payload.clone());
                    }
                }
                // TODO: Update received_ranges for SACK generation
                // TODO: Queue an ACK/SACK packet to be sent back
                queue_ack(header.stream_id, stream, packets_to_send);
            } else {
                // Duplicate or old packet, ignore data but maybe ACK it
                println!("Received duplicate/old data for stream {}, seq {} (expected {})", header.stream_id, seq, stream.next_expected_seq);
                // TODO: Queue an ACK/SACK packet
                queue_ack(header.stream_id, stream, packets_to_send);
            }
        }

        // --- Process FIN ---
        if header.has_flag(PacketFlags::Fin) {
            println!("Received FIN for stream {}", header.stream_id);
            stream.fin_received = true;
            // TODO: Need mechanism to signal FIN to application via receive()
            // TODO: Queue ACK for FIN
            queue_ack(header.stream_id, stream, packets_to_send);
        }

        // --- Process RST ---
        if header.has_flag(PacketFlags::Rst) {
            println!("Received RST for stream {}", header.stream_id);
            // TODO: Abort stream immediately, signal application
        }
    }

    // Helper to queue an ACK/SACK packet
    fn queue_ack(
        stream_id: u64,
        stream: &mut StreamState,
        packets_to_send: &mut VecDeque<(PacketHeader, Option<Bytes>)>
    ) {
        // Basic ACK for highest contiguous sequence number received
        let ack_header = PacketHeader {
            stream_id,
            sequence_number: 0, // Sequence number not used for pure ACKs
            flags: PacketFlags::Ack.bits(), // TODO: Add SACK flag if needed
            num_acks_or_sacks: 0, // TODO: Set non-zero if SACK ranges included
            ack_number: stream.next_expected_seq.saturating_sub(1), // Ack up to highest received contiguous
            sack_ranges: vec![], // TODO: Populate SACK ranges from stream.received_ranges
            payload_length: 0,
        };
        println!("Queueing ACK for stream {}, ack_num={}", stream_id, ack_header.ack_number);
        // Avoid sending redundant ACKs immediately? Maybe coalesce ACKs.
        packets_to_send.push_back((ack_header, None));
    }

    // Helper to prepare data packets from send buffers
    async fn prepare_packets_to_send(
        streams: &Arc<Mutex<BTreeMap<u64, StreamState>>>,
        packets_to_send: &mut VecDeque<(PacketHeader, Option<Bytes>)>
    ) {
        let mut streams_guard = streams.lock().await;
        for (stream_id, stream) in streams_guard.iter_mut() {
            // Check congestion window and bytes in flight
            while stream.bytes_in_flight < stream.congestion_window * MAX_PAYLOAD_SIZE as u32 { // Simple window check
                if let Some(data_chunk) = stream.send_buffer.pop_front() {
                    // TODO: Handle data larger than MAX_PAYLOAD_SIZE - needs fragmentation logic
                    if data_chunk.len() > MAX_PAYLOAD_SIZE {
                        eprintln!("Error: Data chunk too large for single packet ({} > {})", data_chunk.len(), MAX_PAYLOAD_SIZE);
                        // Put it back for now, needs proper handling
                        stream.send_buffer.push_front(data_chunk);
                        break;
                    }

                    let seq_num = stream.next_sequence_number;
                    stream.next_sequence_number += 1;

                    let data_header = PacketHeader {
                        stream_id: *stream_id,
                        sequence_number: seq_num,
                        flags: PacketFlags::Data.bits(),
                        num_acks_or_sacks: 0, // ACKs can be piggybacked later
                        ack_number: 0,
                        sack_ranges: vec![],
                        payload_length: data_chunk.len() as u16,
                    };
                    println!("Preparing DATA packet for stream {}, seq {}", *stream_id, seq_num);
                    packets_to_send.push_back((data_header, Some(data_chunk)));
                    // Note: bytes_in_flight updated after successful send in main loop
                } else if stream.fin_sent && !stream.fin_acked {
                    // If buffer empty and FIN needs sending (and hasn't been sent/acked)
                    // TODO: Check if FIN already in sent_packets
                    let fin_seq_num = stream.next_sequence_number;
                    stream.next_sequence_number += 1;
                    let fin_header = PacketHeader {
                        stream_id: *stream_id,
                        sequence_number: fin_seq_num,
                        flags: PacketFlags::Fin.bits(),
                        num_acks_or_sacks: 0,
                        ack_number: 0,
                        sack_ranges: vec![],
                        payload_length: 0,
                    };
                    println!("Preparing FIN packet for stream {}, seq {}", *stream_id, fin_seq_num);
                    packets_to_send.push_back((fin_header, None));
                    break; // Only send one control packet per check for now
                } else {
                    // No data or FIN to send for this stream right now
                    break;
                }
            }
        }
    }

    // Helper to check for timeouts and queue retransmissions
    async fn check_timeouts_and_retransmit(
        streams: &Arc<Mutex<BTreeMap<u64, StreamState>>>,
        packets_to_send: &mut VecDeque<(PacketHeader, Option<Bytes>)>
    ) {
        // TODO: Implement RTO checking and retransmission logic
        // Iterate through streams, check stream.sent_packets
        // If oldest packet send_time + stream.rto < now:
        //   - Queue retransmission (get original packet data somehow or re-read from buffer?)
        //   - Increment retransmission_count
        //   - Handle RTO backoff (stream.handle_rto_timeout())
        //   - Reset RTO timer
    }

    // --- Test Cases --- (Need to be adapted for Stream API)

    // Example handler for a server-side mock connection
    async fn handle_mock_connection(mut conn: Box<dyn StreamPeerConnection>) {
        println!("Handling connection from {}", conn.remote_address());
        loop {
            // Use the StreamPeerConnection trait methods
            tokio::select! {                result = conn.receive() => {
                    match result {
                        Ok((stream_id, data)) => {
                            println!("Server received on stream {} from {}: {} bytes", stream_id, conn.remote_address(), data.len());
                            // Example: Echo back
                            if conn.send(stream_id, &data).await.is_err() {
                                println!("Failed to echo back to {}", conn.remote_address());
                                break;
                            }
                        }
                        Err(e) => {
                            println!("Receive error from {}: {}", conn.remote_address(), e);
                            break; // Connection likely closed
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => { // Shorter timeout for tests
                    println!("Connection handler for {} idle.", conn.remote_address());
                }
            }
        }
        println!("Connection handler for {} finished.", conn.remote_address());
        let _ = conn.close_connection().await; // Ensure close is called
    }

    fn create_mock_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    // --- Test Cases ---

    #[tokio::test]
    async fn test_mock_connect_listen() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9001);

        // Start listener in the background
        let mut listener_rx = manager.listen(server_addr).await.expect("Listen failed");

        // Allow listener task to potentially start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Attempt to connect
        let connect_result = manager.connect(server_addr).await;

        // Server accepts the connection
        let server_conn_result = tokio::time::timeout(Duration::from_secs(1), listener_rx.recv()).await;

        assert!(connect_result.is_ok(), "Client connect failed: {:?}", connect_result.err());
        assert!(server_conn_result.is_ok(), "Server timed out waiting for connection");
        assert!(server_conn_result.unwrap().is_some(), "Server failed to accept connection");
        println!("Made it here!");
        assert!(connect_result.is_ok(), "Connect failed:");
        let _ = connect_result.unwrap().close_connection().await;
    }

    #[tokio::test]
    async fn test_basic_data_transfer() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9002);
        let mut listener_rx = manager.listen(server_addr).await.expect("Listen failed");

        let client_task = tokio::spawn(async move {
            let mut client_conn = manager.connect(server_addr).await.expect("Client connect failed");
            println!("Client connected to {}", client_conn.remote_address());

            // Client sends "hello" on stream 1
            let send_data = b"hello";
            client_conn.send(1, send_data).await.expect("Client send failed");
            println!("Client sent 'hello' on stream 1");

            // Client receives "world" on stream 1
            let (recv_stream_id, recv_data) = client_conn.receive().await.expect("Client receive failed");
            println!("Client received '{}' on stream {}", String::from_utf8_lossy(&recv_data), recv_stream_id);

            assert_eq!(recv_stream_id, 1);
            assert_eq!(recv_data, b"world");

            client_conn.close_connection().await.expect("Client close failed");
        });

        let server_task = tokio::spawn(async move {
            let mut server_conn = listener_rx.recv().await.expect("Server failed to accept connection");
            println!("Server accepted connection from {}", server_conn.remote_address());

            // Server receives "hello" on stream 1
            let (recv_stream_id, recv_data) = server_conn.receive().await.expect("Server receive failed");
            println!("Server received '{}' on stream {}", String::from_utf8_lossy(&recv_data), recv_stream_id);
            assert_eq!(recv_stream_id, 1);
            assert_eq!(recv_data, b"hello");

            // Server sends "world" on stream 1
            let send_data = b"world";
            server_conn.send(1, send_data).await.expect("Server send failed");
            println!("Server sent 'world' on stream 1");

            // Wait a bit for client to potentially close
            tokio::time::sleep(Duration::from_millis(100)).await;
            server_conn.close_connection().await.expect("Server close failed");
        });

        tokio::try_join!(client_task, server_task).expect("Test tasks failed");
    }

    #[tokio::test]
    async fn test_multiple_stream_data_transfer() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9003);
        let mut listener_rx = manager.listen(server_addr).await.expect("Listen failed");

        let client_task = tokio::spawn(async move {
            let mut client_conn = manager.connect(server_addr).await.expect("Client connect failed");

            // Send on two streams
            client_conn.send(1, b"stream1_data").await.expect("Client send stream 1 failed");
            client_conn.send(2, b"stream2_data").await.expect("Client send stream 2 failed");
            println!("Client sent data on streams 1 and 2");

            // Give server time to process and potentially send ACKs
            tokio::time::sleep(Duration::from_millis(200)).await;
            client_conn.close_connection().await.expect("Client close failed");
        });

        let server_task = tokio::spawn(async move {
            let mut server_conn = listener_rx.recv().await.expect("Server failed to accept connection");
            println!("Server accepted connection");

            let mut received_stream1 = false;
            let mut received_stream2 = false;

            // Receive data for both streams (order might vary)
            for _ in 0..2 {
                let (stream_id, data) = server_conn.receive().await.expect("Server receive failed");
                println!("Server received '{}' on stream {}", String::from_utf8_lossy(&data), stream_id);
                if stream_id == 1 {
                    assert_eq!(data, b"stream1_data");
                    received_stream1 = true;
                } else if stream_id == 2 {
                    assert_eq!(data, b"stream2_data");
                    received_stream2 = true;
                } else {
                    panic!("Received data on unexpected stream: {}", stream_id);
                }
            }

            assert!(received_stream1, "Did not receive data on stream 1");
            assert!(received_stream2, "Did not receive data on stream 2");

            server_conn.close_connection().await.expect("Server close failed");
        });

        tokio::try_join!(client_task, server_task).expect("Test tasks failed");
    }

    #[tokio::test]
    async fn test_bidirectional_data_transfer() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9004);
        let mut listener_rx = manager.listen(server_addr).await.expect("Listen failed");

        let client_task = tokio::spawn(async move {
            let mut client_conn = manager.connect(server_addr).await.expect("Client connect failed");

            // Send client message
            client_conn.send(5, b"client_msg").await.expect("Client send failed");
            println!("Client sent 'client_msg' on stream 5");

            // Receive server message
            let (recv_stream_id, recv_data) = client_conn.receive().await.expect("Client receive failed");
            println!("Client received '{}' on stream {}", String::from_utf8_lossy(&recv_data), recv_stream_id);
            assert_eq!(recv_stream_id, 5);
            assert_eq!(recv_data, b"server_msg");

            client_conn.close_connection().await.expect("Client close failed");
        });

        let server_task = tokio::spawn(async move {
            let mut server_conn = listener_rx.recv().await.expect("Server failed to accept connection");

            // Receive client message
            let (recv_stream_id, recv_data) = server_conn.receive().await.expect("Server receive failed");
            println!("Server received '{}' on stream {}", String::from_utf8_lossy(&recv_data), recv_stream_id);
            assert_eq!(recv_stream_id, 5);
            assert_eq!(recv_data, b"client_msg");

            // Send server message
            server_conn.send(5, b"server_msg").await.expect("Server send failed");
            println!("Server sent 'server_msg' on stream 5");

            // Wait a bit for client to potentially close
            tokio::time::sleep(Duration::from_millis(100)).await;
            server_conn.close_connection().await.expect("Server close failed");
        });

        tokio::try_join!(client_task, server_task).expect("Test tasks failed");
    }

    // Note: The following tests (packet loss, reordering, stream close) depend heavily
    // on the mock implementation's reliability features (ACKs, retransmissions, FIN handling)
    // which are currently marked with TODOs. These tests might fail or hang until
    // those features are more fully implemented in connection_processing_loop.

    #[tokio::test]
    #[ignore] // Ignore until mock reliability is implemented
    async fn test_data_transfer_with_packet_loss() {
        // TODO: Implement this test similar to test_basic_data_transfer,
        // but set MOCK_PACKET_LOSS_RATE to a non-zero value (e.g., 0.1)
        // Requires the mock to handle retransmissions correctly.
        assert!(false, "Test not implemented / mock lacks retransmission");
    }

    #[tokio::test]
    #[ignore] // Ignore until mock reliability is implemented
    async fn test_data_transfer_with_reordering() {
        // TODO: Implement this test similar to test_basic_data_transfer,
        // but set MOCK_MAX_REORDER_DELAY to a non-zero value (e.g., 50ms)
        // Requires the mock to handle sequence numbers and reassembly correctly.
        assert!(false, "Test not implemented / mock lacks reordering handling");
    }

    #[tokio::test]
    #[ignore] // Ignore until mock reliability is implemented
    async fn test_graceful_stream_close() {
        // TODO: Implement test:
        // 1. Client connects, sends data on stream 3.
        // 2. Client calls `close_stream(3)`.
        // 3. Server receives data on stream 3.
        // 4. Server calls `receive()` again. It should return an error or signal indicating the stream is closed.
        // Requires mock to handle FIN packets and signal closure on receive.
        assert!(false, "Test not implemented / mock lacks FIN handling");
    }

    #[tokio::test]
    async fn test_abrupt_connection_close() {
        let mut manager = MockNetworkManager::default();
        let server_addr = create_mock_addr(9005);
        let mut listener_rx = manager.listen(server_addr).await.expect("Listen failed");

        let client_conn_handle = Arc::new(Mutex::new(Option::<Box<dyn StreamPeerConnection>>::None));
        let client_conn_handle_clone = client_conn_handle.clone();

        let client_task = tokio::spawn(async move {
            let mut client_conn = manager.connect(server_addr).await.expect("Client connect failed");
            client_conn.send(1, b"initial data").await.expect("Client initial send failed");
            *client_conn_handle_clone.lock().await = Some(client_conn); // Store connection for later use

            // Keep task alive, waiting for server to close
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Try receiving after server closed - this should fail
            let mut guard = client_conn_handle_clone.lock().await;
            if let Some(conn) = guard.as_mut() {
                let receive_result = conn.receive().await;
                assert!(receive_result.is_err(), "Client receive should fail after server closed connection");
                println!("Client receive correctly failed after server close: {:?}", receive_result.err());

                // Also verify send fails
                let send_result = conn.send(1, b"data after close").await;
                assert!(send_result.is_err(), "Client send should fail after server closed connection");
                println!("Client send correctly failed after server close: {:?}", send_result.err());
            } else {
                panic!("Client connection was not stored");
            }
        });

        let server_task = tokio::spawn(async move {
            let mut server_conn = listener_rx.recv().await.expect("Server failed to accept connection");
            // Receive initial data
            let _ = server_conn.receive().await.expect("Server receive failed");
            println!("Server received initial data");
            // Abruptly close connection
            server_conn.close_connection().await.expect("Server close failed");
            println!("Server closed connection");
        });

        // First wait for server to finish closing
        server_task.await.expect("Server task failed");

        // Then wait for client with timeout
        let timeout_result = tokio::time::timeout(Duration::from_secs(60), client_task).await;
        assert!(timeout_result.is_ok(), "Test timed out waiting for client task");
        timeout_result.unwrap().expect("Client task failed");
    }
}

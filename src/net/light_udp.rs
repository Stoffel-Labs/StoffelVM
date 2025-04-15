// src/net/light_udp.rs
//! Defines the structures and constants for the lightweight UDP protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

// --- Constants ---

/// Maximum payload size per packet to avoid IP fragmentation (conservative).
pub const MAX_PAYLOAD_SIZE: usize = 1200;
/// Default initial Retransmission Timeout (RTO).
const INITIAL_RTO: Duration = Duration::from_millis(200);
/// Minimum RTO.
const MIN_RTO: Duration = Duration::from_millis(50);
/// Maximum RTO.
const MAX_RTO: Duration = Duration::from_secs(5);
/// Factor to multiply RTO on timeout.
const RTO_BACKOFF_FACTOR: f64 = 2.0;
/// Smoothing factor for RTT variance (beta).
const RTT_VAR_FACTOR: f64 = 0.25;
/// Smoothing factor for Smoothed RTT (alpha).
const SRTT_FACTOR: f64 = 0.125;
/// How many packets without ACK before probing.
const PACKET_THRESHOLD_FOR_PROBE: u32 = 3;
/// How long to wait without receiving ACKs before sending a probe.
const IDLE_TIMEOUT_BEFORE_PROBE: Duration = Duration::from_secs(5); // Shorter than typical TCP keepalive
/// Default maximum idle time before a connection is considered timed out.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Default interval for sending keep-alive probes on an idle connection.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(10);

// --- Packet Header ---

/// Represents the flags in the packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketFlags {
    Data = 0b0000_0001, // Packet contains payload data
    Ack = 0b0000_0010, // Packet contains acknowledgment info
    Sack = 0b0000_0100, // Packet contains Selective ACK info
    Fin = 0b0000_1000, // Final packet for this stream (graceful close)
    Rst = 0b0001_0000, // Reset stream (error)
                       // Reserved bits for future use
}

impl PacketFlags {
    fn from_bits(bits: u8) -> Option<Self> {
        // This is a bit simplistic if multiple flags are intended.
        // A proper bitflags crate might be better.
        match bits {
            0b0000_0001 => Some(PacketFlags::Data),
            0b0000_0010 => Some(PacketFlags::Ack),
            0b0000_0100 => Some(PacketFlags::Sack),
            0b0000_1000 => Some(PacketFlags::Fin),
            0b0001_0000 => Some(PacketFlags::Rst),
            _ => None, // Or handle combined flags if needed
        }
    }

    pub fn bits(&self) -> u8 {
        *self as u8
    }
}

/// Represents the header of a lightweight UDP packet.
/// Wire format (example):
/// Stream ID (u64)       - 8 bytes
/// Sequence Number (u64) - 8 bytes
/// Flags (u8)            - 1 byte
/// Num ACKs/SACKs (u8)   - 1 byte (Number of ACK/SACK ranges following)
/// Ack Number (u64)      - 8 bytes (If ACK flag is set, highest contiguous seq acked)
/// SACK Ranges ([u64; 2]) - 16 bytes per range (If SACK flag is set)
/// Payload Length (u16)  - 2 bytes
/// --------------------------------
/// Total Header Size: 28 bytes (minimum, without SACKs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub stream_id: u64,
    pub sequence_number: u64, // For DATA packets
    pub flags: u8,            // Bitmask of PacketFlags
    pub num_acks_or_sacks: u8, // Number of ACK ranges or SACK ranges
    pub ack_number: u64,      // Highest contiguous sequence number acknowledged (if ACK flag)
    pub sack_ranges: Vec<(u64, u64)>, // Non-contiguous ranges acknowledged (if SACK flag)
    pub payload_length: u16,
}

impl PacketHeader {
    const BASE_HEADER_SIZE: usize = 8 + 8 + 1 + 1 + 8 + 2; // StreamID, SeqNum, Flags, NumAcks, AckNum, PayloadLen

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.stream_id);
        buf.put_u64(self.sequence_number);
        buf.put_u8(self.flags);
        buf.put_u8(self.num_acks_or_sacks);
        if self.flags & PacketFlags::Ack.bits() != 0 {
            buf.put_u64(self.ack_number);
        } else {
            buf.put_u64(0); // Put placeholder if no ACK flag
        }
        if self.flags & PacketFlags::Sack.bits() != 0 {
            for &(start, end) in &self.sack_ranges {
                buf.put_u64(start);
                buf.put_u64(end);
            }
        }
        buf.put_u16(self.payload_length);
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Self, String> {
        if buf.len() < Self::BASE_HEADER_SIZE {
            return Err("Buffer too small for base header".to_string());
        }

        let stream_id = buf.get_u64();
        let sequence_number = buf.get_u64();
        let flags = buf.get_u8();
        let num_acks_or_sacks = buf.get_u8();
        let ack_number = buf.get_u64(); // Always read, even if flag not set
        let payload_length = buf.get_u16();

        let mut sack_ranges = Vec::new();
        if flags & PacketFlags::Sack.bits() != 0 {
            let num_sacks = num_acks_or_sacks as usize;
            let expected_sack_bytes = num_sacks * 16; // 2 * u64 per range
            if buf.len() < expected_sack_bytes {
                return Err(format!(
                    "Buffer too small for SACK ranges. Need {}, have {}",
                    expected_sack_bytes,
                    buf.len()
                ));
            }
            for _ in 0..num_sacks {
                let start = buf.get_u64();
                let end = buf.get_u64();
                sack_ranges.push((start, end));
            }
        }

        Ok(PacketHeader {
            stream_id,
            sequence_number,
            flags,
            num_acks_or_sacks,
            ack_number,
            sack_ranges,
            payload_length,
        })
    }

    pub fn has_flag(&self, flag: PacketFlags) -> bool {
        self.flags & flag.bits() != 0
    }

    pub fn header_size(&self) -> usize {
        Self::BASE_HEADER_SIZE + if self.has_flag(PacketFlags::Sack) {
            self.sack_ranges.len() * 16
        } else {
            0
        }
    }
}

// --- Stream State ---

/// State maintained for each active stream *per peer*.
#[derive(Debug)]
pub struct StreamState {
    // Sending side
    pub next_sequence_number: u64,
    pub sent_packets: BTreeMap<u64, SentPacketInfo>, // Track packets sent but not yet ACKed
    pub highest_acked_seq: u64,                      // Highest contiguous sequence number ACKed by the peer
    pub send_buffer: VecDeque<Bytes>,                // Data waiting to be packetized and sent
    pub fin_sent: bool,                              // Have we sent a FIN for this stream?
    pub fin_acked: bool,                             // Has the FIN been acknowledged?

    // Receiving side
    pub next_expected_seq: u64,
    pub received_buffer: BTreeMap<u64, Bytes>, // Out-of-order packets received
    pub received_ranges: VecDeque<(u64, u64)>, // Contiguous ranges received (for SACK generation)
    pub fin_received: bool,                    // Have we received a FIN for this stream?
    pub fin_processed: bool,                   // Has the application consumed the FIN?

    // Congestion Control / RTT Estimation (Simplified)
    pub rto: Duration,
    pub smoothed_rtt: Option<Duration>,
    pub rtt_variance: Duration,
    pub congestion_window: u32, // Max number of packets in flight
    pub bytes_in_flight: u32,

    // Timers
    pub rto_timer_expiry: Option<Instant>,
    pub last_ack_received_time: Option<Instant>,
    pub last_data_sent_time: Option<Instant>,
}

/// Information about a packet that has been sent but not yet acknowledged.
#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    pub send_time: Instant,
    pub size: usize,
    pub retransmission_count: u32,
}

impl StreamState {
    pub fn new(initial_seq: u64, initial_congestion_window: u32) -> Self {
        StreamState {
            next_sequence_number: initial_seq,
            sent_packets: BTreeMap::new(),
            highest_acked_seq: initial_seq.saturating_sub(1), // Nothing acked yet
            send_buffer: VecDeque::new(),
            fin_sent: false,
            fin_acked: false,

            next_expected_seq: 0, // Assume receiver starts expecting 0
            received_buffer: BTreeMap::new(),
            received_ranges: VecDeque::new(),
            fin_received: false,
            fin_processed: false,

            rto: INITIAL_RTO,
            smoothed_rtt: None,
            rtt_variance: INITIAL_RTO / 2,
            congestion_window: initial_congestion_window,
            bytes_in_flight: 0,

            rto_timer_expiry: None,
            last_ack_received_time: None,
            last_data_sent_time: None,
        }
    }

    /// Updates RTT estimate based on an ACK.
    pub fn update_rtt(&mut self, rtt_sample: Duration) {
        if let Some(srtt) = self.smoothed_rtt {
            let delta = if srtt > rtt_sample {
                srtt - rtt_sample
            } else {
                rtt_sample - srtt
            };
            // Update RTTVAR: rtt_variance = (1 - beta) * rtt_variance + beta * |SRTT - RTT_sample|
            self.rtt_variance = self.rtt_variance.mul_f64(1.0 - RTT_VAR_FACTOR)
                + delta.mul_f64(RTT_VAR_FACTOR);
            // Update SRTT: smoothed_rtt = (1 - alpha) * SRTT + alpha * RTT_sample
            self.smoothed_rtt = Some(srtt.mul_f64(1.0 - SRTT_FACTOR) + rtt_sample.mul_f64(SRTT_FACTOR));
        } else {
            // First sample
            self.smoothed_rtt = Some(rtt_sample);
            self.rtt_variance = rtt_sample / 2;
        }
        // Update RTO = SRTT + max(G, K * RTTVAR) where K=4
        let k_rttvar = self.rtt_variance.mul_f64(4.0);
        // Use a small clock granularity 'G' implicitly via MIN_RTO lower bound
        self.rto = (self.smoothed_rtt.unwrap_or(INITIAL_RTO) + k_rttvar)
            .max(MIN_RTO)
            .min(MAX_RTO);
    }

    /// Handles RTO timer expiration (exponential backoff).
    pub fn handle_rto_timeout(&mut self) {
        self.rto = (self.rto.mul_f64(RTO_BACKOFF_FACTOR)).min(MAX_RTO);
        // Reset congestion window (simple strategy)
        self.congestion_window = (self.congestion_window / 2).max(1); // Halve window, min 1 packet
        self.rto_timer_expiry = None; // RTO handled, clear timer until next send/ack
        // Caller needs to trigger retransmission of the oldest unacked packet.
    }

    /// Adds a received sequence number and updates contiguous ranges.
    /// Returns true if this sequence number filled a gap.
    pub fn add_received_seq(&mut self, seq: u64) -> bool {
        // TODO: Implement logic to merge seq into self.received_ranges
        // This is complex: needs to handle merging adjacent/overlapping ranges.
        // For now, just track the highest contiguous.
        let mut filled_gap = false;
        if seq == self.next_expected_seq {
            self.next_expected_seq += 1;
            filled_gap = true;
            // Check buffered packets to see if more are now contiguous
            while let Some(data) = self.received_buffer.remove(&self.next_expected_seq) {
                 // Process data (or just advance counter for now)
                 self.next_expected_seq += 1;
            }
        } else if seq > self.next_expected_seq {
            // Out of order, buffer it (if not already buffered/processed)
            // self.received_buffer.insert(seq, data_payload); // Payload stored elsewhere
        }
        // Update self.received_ranges based on 'seq' and merging logic...
        filled_gap
    }
}

// --- Connection State ---

/// State maintained for each connected peer.
pub struct PeerState {
    pub remote_addr: SocketAddr,
    pub streams: BTreeMap<u64, StreamState>, // Map Stream ID -> Stream State
    pub last_packet_received_time: Instant,
    pub last_packet_sent_time: Instant, // Tracks when we last sent *any* packet
    // Add other peer-level state if needed (e.g., connection ID, crypto state)
}

impl PeerState {
    pub fn new(remote_addr: SocketAddr) -> Self {
        PeerState {
            remote_addr,
            streams: BTreeMap::new(),
            last_packet_received_time: Instant::now(),
            last_packet_sent_time: Instant::now(), // Initialize to now
        }
    }

    pub fn get_or_create_stream_mut(&mut self, stream_id: u64) -> &mut StreamState {
        self.streams
            .entry(stream_id)
            .or_insert_with(|| StreamState::new(0, 10)) // Default: seq 0, cwnd 10 packets
    }

    /// Updates the last received time. Should be called whenever a valid packet
    /// is processed from this peer.
    pub fn record_packet_received(&mut self) {
        self.last_packet_received_time = Instant::now();
    }

    /// Updates the last sent time. Should be called whenever any packet
    /// (data, ack, probe) is sent to this peer.
    pub fn record_packet_sent(&mut self) {
        self.last_packet_sent_time = Instant::now();
    }

    // Note: The actual timeout checking logic needs to be implemented externally,
    // likely in the main network manager loop. It would look something like:
    //
    // for peer_state in active_peers.values_mut() {
    //     if peer_state.last_packet_received_time.elapsed() > CONNECTION_TIMEOUT {
    //         // Handle timeout: close connection, notify application, remove peer_state
    //     } else if peer_state.last_packet_sent_time.elapsed() > PROBE_INTERVAL && peer_state.last_packet_received_time.elapsed() > PROBE_INTERVAL {
    //         // Handle probing: queue a probe packet (e.g., empty ACK) to be sent
    //     }
    // }
}

// --- Utility Functions ---

/// Parses a raw UDP datagram into a header and payload.
pub fn parse_packet(datagram: &[u8]) -> Result<(PacketHeader, Bytes), String> {
    let mut buffer = BytesMut::from(datagram);
    let header = PacketHeader::decode(&mut buffer)?;
    let header_size = header.header_size();

    // Check if buffer has enough bytes for the declared payload
    if buffer.len() < header.payload_length as usize {
        return Err(format!(
            "Buffer too small for payload. Need {}, have {}",
            header.payload_length,
            buffer.len()
        ));
    }

    // Payload might be shorter than remaining buffer if padding exists or length is wrong
    let payload = buffer.split_to(header.payload_length as usize).freeze();

    Ok((header, payload))
}

/// Creates a raw datagram from a header and optional payload.
pub fn serialize_packet(header: &PacketHeader, payload: Option<&Bytes>) -> Bytes {
    let payload_len = payload.map(|p| p.len()).unwrap_or(0);
    assert!(payload_len == header.payload_length as usize); // Ensure consistency

    let mut buffer = BytesMut::with_capacity(header.header_size() + payload_len);
    header.encode(&mut buffer);
    if let Some(p) = payload {
        buffer.put_slice(p);
    }
    buffer.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_header_encode_decode_data() {
        let header = PacketHeader {
            stream_id: 12345,
            sequence_number: 100,
            flags: PacketFlags::Data.bits(),
            num_acks_or_sacks: 0,
            ack_number: 0,
            sack_ranges: vec![],
            payload_length: 50,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let decoded_header = PacketHeader::decode(&mut buf).expect("Decode failed");

        assert_eq!(header, decoded_header);
        assert_eq!(buf.len(), 0); // Ensure all bytes consumed
        assert_eq!(header.header_size(), PacketHeader::BASE_HEADER_SIZE);
    }

    #[test]
    fn test_header_encode_decode_ack_sack() {
         let header = PacketHeader {
            stream_id: 987,
            sequence_number: 0, // No data seq num needed for pure ACK/SACK
            flags: PacketFlags::Ack.bits() | PacketFlags::Sack.bits(),
            num_acks_or_sacks: 2, // Number of SACK ranges
            ack_number: 500,    // Highest contiguous ACK
            sack_ranges: vec![(505, 510), (520, 525)],
            payload_length: 0,
        };

        let mut buf = BytesMut::new();
        header.encode(&mut buf);

        let expected_size = PacketHeader::BASE_HEADER_SIZE + 2 * 16; // Base + 2 SACK ranges
        assert_eq!(buf.len(), expected_size);
        assert_eq!(header.header_size(), expected_size);

        let decoded_header = PacketHeader::decode(&mut buf).expect("Decode failed");

        assert_eq!(header, decoded_header);
        assert_eq!(buf.len(), 0); // Ensure all bytes consumed
    }

     #[test]
    fn test_parse_serialize_packet() {
        let header = PacketHeader {
            stream_id: 1,
            sequence_number: 2,
            flags: PacketFlags::Data.bits(),
            num_acks_or_sacks: 0,
            ack_number: 0,
            sack_ranges: vec![],
            payload_length: 11,
        };
        let payload = Bytes::from_static(b"hello world");

        let datagram = serialize_packet(&header, Some(&payload));

        assert_eq!(datagram.len(), header.header_size() + payload.len());

        let (parsed_header, parsed_payload) = parse_packet(&datagram).expect("Parse failed");

        assert_eq!(header, parsed_header);
        assert_eq!(payload, parsed_payload);
    }

    #[test]
    fn test_parse_packet_too_small() {
        let small_buf = Bytes::from_static(&[0u8; 10]); // Smaller than base header
        assert!(parse_packet(&small_buf).is_err());
    }

     #[test]
    fn test_parse_packet_payload_mismatch() {
        let header = PacketHeader {
            stream_id: 1, sequence_number: 2, flags: PacketFlags::Data.bits(),
            num_acks_or_sacks: 0, ack_number: 0, sack_ranges: vec![],
            payload_length: 20, // Declares 20 bytes payload
        };
        let payload = Bytes::from_static(b"only 10"); // But only provides 10

        let mut buf = BytesMut::with_capacity(header.header_size() + payload.len());
        header.encode(&mut buf);
        buf.put_slice(&payload); // Buffer contains header + 10 bytes

        let datagram = buf.freeze();

        let result = parse_packet(&datagram);
        assert!(result.is_err()); // Should fail because buffer doesn't contain declared payload length
        assert!(result.unwrap_err().contains("Buffer too small for payload"));
    }
}

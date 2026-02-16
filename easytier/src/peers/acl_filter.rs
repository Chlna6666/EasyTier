use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::Instant;
use std::{
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet as _,
};

use crate::common::scoped_task::ScopedTask;
use crate::proto::acl::{AclStats, AppProtocol, Protocol};
use crate::tunnel::packet_def::PacketType;
use crate::{
    common::acl_processor::{AclProcessor, AclResult, AclStatKey, AclStatType, PacketInfo},
    proto::acl::{Acl, Action, ChainType},
    tunnel::packet_def::ZCPacket,
};

#[derive(Debug, Eq, PartialEq, Hash)]
struct OutboundAllowRecord {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Protocol,
    app_protocol: AppProtocol,
}

impl OutboundAllowRecord {
    fn new_from_inbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            protocol: p.protocol,
            app_protocol: p.app_protocol,
        }
    }

    fn new_from_outbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.dst_ip,
            dst_ip: p.src_ip,
            src_port: p.dst_port,
            dst_port: p.src_port,
            protocol: p.protocol,
            app_protocol: p.app_protocol,
        }
    }
}

/// ACL filter that can be inserted into the packet processing pipeline
/// Optimized with lock-free hot reloading via atomic processor replacement
pub struct AclFilter {
    // Use ArcSwap for lock-free atomic replacement during hot reload
    acl_processor: ArcSwap<AclProcessor>,
    acl_enabled: Arc<AtomicBool>,

    // Track allowed outbound packets and automatically allow their corresponding inbound response
    // packets, even if they would normally be dropped by ACL rules
    outbound_allow_records: Arc<DashMap<OutboundAllowRecord, Instant>>,
    clean_task: ScopedTask<()>,
}

impl Default for AclFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AclFilter {
    #[inline]
    fn detect_udp_app_protocol(payload: &[u8]) -> AppProtocol {
        // WebRTC: STUN first (ICE)
        if Self::is_stun(payload) {
            return AppProtocol::WebRtcStun;
        }

        // WebRTC: DTLS (handshake / data channel)
        if Self::is_dtls(payload) {
            return AppProtocol::WebRtcDtls;
        }

        // RakNet (Minecraft Bedrock etc)
        if Self::is_raknet(payload) {
            return AppProtocol::RakNet;
        }

        // WebRTC media (SRTP) - best-effort heuristic.
        if Self::is_rtp(payload) {
            return AppProtocol::WebRtcRtp;
        }

        AppProtocol::Unknown
    }

    #[inline]
    fn is_stun(payload: &[u8]) -> bool {
        // RFC 5389: 20-byte header, magic cookie 0x2112A442 at bytes 4..8.
        if payload.len() < 20 {
            return false;
        }
        if (payload[0] & 0xC0) != 0x00 {
            return false;
        }
        if payload[4..8] != [0x21, 0x12, 0xA4, 0x42] {
            return false;
        }
        let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        20usize
            .checked_add(msg_len)
            .is_some_and(|total| total <= payload.len())
    }

    #[inline]
    fn is_dtls(payload: &[u8]) -> bool {
        // DTLS record header is 13 bytes:
        // type(1) version(2) epoch(2) seq(6) length(2)
        if payload.len() < 13 {
            return false;
        }
        let content_type = payload[0];
        if !(20..=23).contains(&content_type) {
            return false;
        }
        let ver_major = payload[1];
        let ver_minor = payload[2];
        if ver_major != 0xFE || !(ver_minor == 0xFF || ver_minor == 0xFD) {
            return false;
        }
        let rec_len = u16::from_be_bytes([payload[11], payload[12]]) as usize;
        13usize
            .checked_add(rec_len)
            .is_some_and(|total| total <= payload.len())
    }

    #[inline]
    fn is_raknet(payload: &[u8]) -> bool {
        // RakNet offline message data ID:
        // 00ffff00fefefefefdfdfdfd12345678
        const OFFLINE_MAGIC: [u8; 16] = [
            0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34,
            0x56, 0x78,
        ];
        let scan_len = payload.len().min(80);
        payload[..scan_len]
            .windows(OFFLINE_MAGIC.len())
            .any(|w| w == OFFLINE_MAGIC)
    }

    #[inline]
    fn is_rtp(payload: &[u8]) -> bool {
        // Very conservative RTP v2 check.
        if payload.len() < 12 {
            return false;
        }
        if (payload[0] & 0xC0) != 0x80 {
            return false;
        }
        // Avoid classifying all-zero buffers (common in random data or padding).
        if payload[..12].iter().all(|b| *b == 0) {
            return false;
        }
        true
    }

    pub fn new() -> Self {
        let outbound_allow_records = Arc::new(DashMap::new());
        let record_clone = outbound_allow_records.clone();
        Self {
            acl_processor: ArcSwap::from(Arc::new(AclProcessor::new(Acl::default()))),
            acl_enabled: Arc::new(AtomicBool::new(false)),
            outbound_allow_records,
            clean_task: tokio::spawn(async move {
                let max_life = std::time::Duration::from_secs(30);
                loop {
                    record_clone.retain(|_, v| v.elapsed() < max_life);
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            })
            .into(),
        }
    }

    /// Hot reload ACL rules by creating a new processor instance
    /// Preserves connection tracking and rate limiting state across reloads
    /// Now lock-free and doesn't require &mut self!
    pub fn reload_rules(&self, acl_config: Option<&Acl>) {
        let Some(acl_config) = acl_config else {
            self.acl_enabled.store(false, Ordering::Relaxed);
            return;
        };

        // Get current processor to extract shared state
        let current_processor = self.acl_processor.load();
        let (conn_track, rate_limiters, stats) = current_processor.get_shared_state();

        // Create new processor with preserved state
        let new_processor = AclProcessor::new_with_shared_state(
            acl_config.clone(),
            Some(conn_track),
            Some(rate_limiters),
            Some(stats),
        );

        // Atomic replacement - this is completely lock-free!
        self.acl_processor.store(Arc::new(new_processor));
        self.acl_enabled.store(true, Ordering::Relaxed);

        tracing::info!("ACL rules hot reloaded with preserved state (lock-free)");
    }

    /// Get current processor for processing packets
    pub fn get_processor(&self) -> Arc<AclProcessor> {
        self.acl_processor.load_full()
    }

    pub fn get_stats(&self) -> AclStats {
        let processor = self.get_processor();
        let global_stats = processor.get_stats();
        let (conn_track, _, _) = processor.get_shared_state();
        let rules_stats = processor.get_rules_stats();

        AclStats {
            global: global_stats.into_iter().collect(),
            conn_track: conn_track.iter().map(|x| *x.value()).collect(),
            rules: rules_stats,
        }
    }

    /// Extract packet information for ACL processing
    fn extract_packet_info(
        &self,
        packet: &ZCPacket,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
    ) -> Option<PacketInfo> {
        let payload = packet.payload();

        let src_ip;
        let dst_ip;
        let src_port;
        let dst_port;
        let protocol;
        let app_protocol;

        let ipv4_packet = Ipv4Packet::new(payload)?;
        if ipv4_packet.get_version() == 4 {
            src_ip = IpAddr::V4(ipv4_packet.get_source());
            dst_ip = IpAddr::V4(ipv4_packet.get_destination());
            protocol = ipv4_packet.get_next_level_protocol();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    // TODO: extend to TCP L7 signatures if needed.
                    app_protocol = AppProtocol::Unknown;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    app_protocol = Self::detect_udp_app_protocol(udp_packet.payload());
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => {
                    app_protocol = AppProtocol::Unknown;
                    (None, None)
                }
            };
        } else if ipv4_packet.get_version() == 6 {
            let ipv6_packet = Ipv6Packet::new(payload)?;
            src_ip = IpAddr::V6(ipv6_packet.get_source());
            dst_ip = IpAddr::V6(ipv6_packet.get_destination());
            protocol = ipv6_packet.get_next_header();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;
                    app_protocol = AppProtocol::Unknown;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv6_packet.payload())?;
                    app_protocol = Self::detect_udp_app_protocol(udp_packet.payload());
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => {
                    app_protocol = AppProtocol::Unknown;
                    (None, None)
                }
            };
        } else {
            return None;
        }

        let acl_protocol = match protocol {
            IpNextHeaderProtocols::Tcp => Protocol::Tcp,
            IpNextHeaderProtocols::Udp => Protocol::Udp,
            IpNextHeaderProtocols::Icmp => Protocol::Icmp,
            IpNextHeaderProtocols::Icmpv6 => Protocol::IcmPv6,
            _ => Protocol::Unspecified,
        };

        let src_groups = packet
            .get_src_peer_id()
            .map(|peer_id| route.get_peer_groups(peer_id))
            .unwrap_or_else(|| Arc::new(Vec::new()));
        let dst_groups = packet
            .get_dst_peer_id()
            .map(|peer_id| route.get_peer_groups(peer_id))
            .unwrap_or_else(|| Arc::new(Vec::new()));

        Some(PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: acl_protocol,
            app_protocol,
            packet_size: payload.len(),
            src_groups,
            dst_groups,
        })
    }

    /// Process ACL result and log if needed
    pub fn handle_acl_result(
        &self,
        result: &AclResult,
        packet_info: &PacketInfo,
        chain_type: ChainType,
        processor: &AclProcessor,
    ) {
        if result.should_log {
            if let Some(ref log_context) = result.log_context {
                let log_message = log_context.to_message();
                tracing::info!(
                    src_ip = %packet_info.src_ip,
                    dst_ip = %packet_info.dst_ip,
                    src_port = packet_info.src_port,
                    dst_port = packet_info.dst_port,
                    src_group = packet_info.src_groups.join(","),
                    dst_group = packet_info.dst_groups.join(","),
                    protocol = ?packet_info.protocol,
                    app_protocol = ?packet_info.app_protocol,
                    action = ?result.action,
                    rule = result.matched_rule_str().as_deref().unwrap_or("unknown"),
                    chain_type = ?chain_type,
                    "ACL: {}", log_message
                );
            }
        }

        // Update global statistics in the ACL processor
        match result.action {
            Action::Allow => {
                processor.increment_stat(AclStatKey::PacketsAllowed);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Allowed,
                ));
                tracing::trace!("ACL: Packet allowed");
            }
            Action::Drop => {
                processor.increment_stat(AclStatKey::PacketsDropped);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Dropped,
                ));
                tracing::debug!("ACL: Packet dropped");
            }
            Action::Noop => {
                processor.increment_stat(AclStatKey::PacketsNoop);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Noop,
                ));
                tracing::trace!("ACL: No operation");
            }
        }

        // Track total packets processed per chain
        processor.increment_stat(AclStatKey::from_chain_and_action(
            chain_type,
            AclStatType::Total,
        ));
        processor.increment_stat(AclStatKey::PacketsTotal);
    }

    /// Common ACL processing logic
    pub fn process_packet_with_acl(
        &self,
        packet: &ZCPacket,
        is_in: bool,
        my_ipv4: Option<Ipv4Addr>,
        my_ipv6: Option<Ipv6Addr>,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
    ) -> bool {
        if !self.acl_enabled.load(Ordering::Relaxed) {
            return true;
        }

        if packet.peer_manager_header().unwrap().packet_type != PacketType::Data as u8 {
            return true;
        }

        // Extract packet information
        let packet_info = match self.extract_packet_info(packet, route) {
            Some(info) => info,
            None => {
                tracing::warn!(
                    "Failed to extract packet info from {:?} packet, header: {:?}",
                    if is_in { "inbound" } else { "outbound" },
                    packet.peer_manager_header()
                );
                // allow all unknown packets
                return true;
            }
        };

        let chain_type = if is_in {
            if packet_info.dst_ip == my_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED)
                || packet_info.dst_ip == my_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED)
            {
                ChainType::Inbound
            } else {
                ChainType::Forward
            }
        } else {
            ChainType::Outbound
        };

        // Get current processor atomically
        let processor = self.get_processor();

        // Process through ACL rules
        let acl_result = processor.process_packet(&packet_info, chain_type);

        self.handle_acl_result(&acl_result, &packet_info, chain_type, &processor);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => {
                if matches!(chain_type, ChainType::Outbound) {
                    self.outbound_allow_records.insert(
                        OutboundAllowRecord::new_from_outbound_packet(&packet_info),
                        Instant::now(),
                    );
                }
                true
            }
            Action::Drop => {
                if is_in {
                    let record = OutboundAllowRecord::new_from_inbound_packet(&packet_info);
                    let entry = self.outbound_allow_records.entry(record);
                    if let dashmap::Entry::Occupied(mut entry) = entry {
                        entry.insert(Instant::now());
                        tracing::trace!(
                            "ACL: Allowing {:?} packet from {} to {} because of existing allow record, chain_type: {:?}",
                            packet_info.protocol,
                            packet_info.src_ip,
                            packet_info.dst_ip,
                            chain_type,
                        );
                        return true;
                    }
                }

                tracing::trace!(
                    "ACL: Dropping {:?} packet from {} to {}, chain_type: {:?}",
                    packet_info.protocol,
                    packet_info.src_ip,
                    packet_info.dst_ip,
                    chain_type,
                );

                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_udp_app_protocol_stun() {
        // STUN Binding Request with zero attributes.
        let mut buf = vec![0u8; 20];
        buf[0] = 0x00;
        buf[1] = 0x01; // Binding Request
        buf[2] = 0x00;
        buf[3] = 0x00; // length
        buf[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        buf[8..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]); // txid

        assert_eq!(
            AclFilter::detect_udp_app_protocol(&buf),
            AppProtocol::WebRtcStun
        );
    }

    #[test]
    fn test_detect_udp_app_protocol_dtls() {
        // Minimal DTLS record header: handshake, DTLS 1.2, length 0.
        let mut buf = vec![0u8; 13];
        buf[0] = 22; // handshake
        buf[1] = 0xFE;
        buf[2] = 0xFD; // DTLS 1.2
                       // epoch(2) + seq(6) already zero
        buf[11] = 0;
        buf[12] = 0; // length

        assert_eq!(
            AclFilter::detect_udp_app_protocol(&buf),
            AppProtocol::WebRtcDtls
        );
    }

    #[test]
    fn test_detect_udp_app_protocol_raknet() {
        // RakNet offline magic embedded in payload.
        let buf = [
            0x01, 0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12,
            0x34, 0x56, 0x78,
        ];

        assert_eq!(
            AclFilter::detect_udp_app_protocol(&buf),
            AppProtocol::RakNet
        );
    }
}

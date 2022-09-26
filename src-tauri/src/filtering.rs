use std::{collections::BTreeMap, sync::Arc};

use sniffer_parser::serializable_packet::{ParsedPacket, SerializablePacket};

use crate::{SniffingError, SniffingState};

pub struct PacketsCollection {
    pub packets: Vec<Arc<ParsedPacket>>,
    pub source_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub tcp_packets: Vec<Arc<ParsedPacket>>,
    pub udp_packets: Vec<Arc<ParsedPacket>>,
    pub icmp_packets: Vec<Arc<ParsedPacket>>,
    pub icmpv6_packets: Vec<Arc<ParsedPacket>>,
    pub http_packets: Vec<Arc<ParsedPacket>>,
    pub tls_packets: Vec<Arc<ParsedPacket>>,
    pub ipv4_packets: Vec<Arc<ParsedPacket>>,
    pub ipv6_packets: Vec<Arc<ParsedPacket>>,
    pub dns_packets: Vec<Arc<ParsedPacket>>,
    pub arp_packets: Vec<Arc<ParsedPacket>>,
}

impl PacketsCollection {
    pub fn new() -> Self {
        PacketsCollection {
            packets: vec![],
            source_ip_index: BTreeMap::new(),
            tcp_packets: vec![],
            udp_packets: vec![],
            icmp_packets: vec![],
            icmpv6_packets: vec![],
            http_packets: vec![],
            tls_packets: vec![],
            ipv4_packets: vec![],
            ipv6_packets: vec![],
            dns_packets: vec![],
            arp_packets: vec![]
        }
    }
}

pub fn contains_tcp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::TcpPacket(_)) =
    packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_udp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::UdpPacket(_)) =
    packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_icmp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::IcmpPacket(_)) |
    Some(SerializablePacket::EchoReplyPacket(_)) |
    Some(SerializablePacket::EchoRequestPacket(_)) =

    packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_icmp6(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Icmpv6Packet(_)) =
    packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_arp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::ArpPacket(_)) =
    packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv6(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Ipv6Packet(_)) =
    packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv4(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Ipv4Packet(_)) =
    packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_tls(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::TlsPacket(_)) =
    packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_dns(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::DnsPacket(_)) =
    packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_http(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::HttpRequestPacket(_)) |
    Some(SerializablePacket::HttpResponsePacket(_)) =
    packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

fn get_slice<'a>(
    packets: &'a Vec<Arc<ParsedPacket>>,
    start: usize,
    end: usize,
) -> &'a [Arc<ParsedPacket>] {
    match packets.get(start..end) {
        Some(values) => values,
        None => packets.get(start..).unwrap(),
    }
}

#[tauri::command]
pub fn get_packets(
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    if start > packets_collection.packets.len() {
        return Err(SniffingError::GetPacketsIndexNotValid(
            "The indexes are not valid".to_owned(),
        ));
    }

    return Ok(get_slice(&packets_collection.packets, start, end)
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect()
    );
}

#[tauri::command]
pub fn filter_by_source_ip(
    source_ip: String,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    if start > packets_collection.packets.len() {
        return Err(SniffingError::GetPacketsIndexNotValid(
            "The indexes are not valid".to_owned(),
        ));
    }

    let slice = match packets_collection.source_ip_index.get(&source_ip) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

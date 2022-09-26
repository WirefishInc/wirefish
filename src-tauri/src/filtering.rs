use std::{collections::BTreeMap, sync::Arc};

use sniffer_parser::serializable_packet::{ParsedPacket, SerializablePacket};

use crate::{SniffingError, SniffingState};

use self::FilterNamesValues::Filter;
#[allow(non_snake_case)]
mod FilterNamesValues {
    use serde::{Deserialize, Serialize};

    pub const ETHERNET: &str = "ethernet";
    pub const MALFORMED: &str = "malformed";
    pub const UNKNOWN: &str = "unknown";
    pub const TCP: &str = "tcp";
    pub const UDP: &str = "udp";
    pub const ICMPV6: &str = "icmpv6";
    pub const ICMP: &str = "icmp";
    pub const HTTP: &str = "http";
    pub const TLS: &str = "tls";
    pub const IPV4: &str = "ipv4";
    pub const IPV6: &str = "ipv6";
    pub const ARP: &str = "arp";
    pub const DNS: &str = "dns";
    pub const SRC_IP: &str = "src_ip";
    pub const DST_IP: &str = "dst_ip";
    pub const SRC_MAC: &str = "src_mac";
    pub const DST_MAC: &str = "dst_mac";
    pub const SRC_PORT: &str = "src_port";
    pub const DST_PORT: &str = "dst_port";

    #[derive(Serialize, Deserialize)]
    pub struct Filter<'a> {
        pub name: &'a str,
        pub value: bool,
    }
}

pub struct PacketsCollection {
    pub packets: Vec<Arc<ParsedPacket>>,

    pub source_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub dest_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub source_port_index: BTreeMap<u16, Vec<Arc<ParsedPacket>>>,
    pub dest_port_index: BTreeMap<u16, Vec<Arc<ParsedPacket>>>,
    pub source_mac_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub dest_mac_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,

    pub ethernet_packets: Vec<Arc<ParsedPacket>>,
    pub malformed_packets: Vec<Arc<ParsedPacket>>,
    pub unknown_packets: Vec<Arc<ParsedPacket>>,
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
            dest_ip_index: BTreeMap::new(),
            source_port_index: BTreeMap::new(),
            dest_port_index: BTreeMap::new(),
            source_mac_index: BTreeMap::new(),
            dest_mac_index: BTreeMap::new(),

            unknown_packets: vec![],
            ethernet_packets: vec![],
            malformed_packets: vec![],
            tcp_packets: vec![],
            udp_packets: vec![],
            icmp_packets: vec![],
            icmpv6_packets: vec![],
            http_packets: vec![],
            tls_packets: vec![],
            ipv4_packets: vec![],
            ipv6_packets: vec![],
            dns_packets: vec![],
            arp_packets: vec![],
        }
    }
}

pub fn contains_unknokn(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::UnknownPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_malformed(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_network_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ethernet(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::EthernetPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_tcp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::TcpPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_udp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::UdpPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_icmp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::IcmpPacket(_))
    | Some(SerializablePacket::EchoReplyPacket(_))
    | Some(SerializablePacket::EchoRequestPacket(_)) = packet.get_transport_layer_packet()
    {
        return true;
    }

    return false;
}

pub fn contains_icmp6(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Icmpv6Packet(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_arp(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::ArpPacket(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv6(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Ipv6Packet(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv4(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::Ipv4Packet(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_tls(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::TlsPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_dns(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::DnsPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_http(packet: Arc<ParsedPacket>) -> bool {
    if let Some(SerializablePacket::HttpRequestPacket(_))
    | Some(SerializablePacket::HttpResponsePacket(_)) = packet.get_application_layer_packet()
    {
        return true;
    }

    return false;
}

fn get_slice(packets: &Vec<Arc<ParsedPacket>>, start: usize, end: usize) -> &[Arc<ParsedPacket>] {
    match packets.get(start..end) {
        Some(values) => values,
        None => packets.get(start..).unwrap_or(&[]),
    }
}

#[tauri::command]
pub fn get_packets<'a>(
    start: usize,
    end: usize,
    filters_type: Vec<(&'a str, bool)>,
    filters_value: Vec<(&'a str, (bool, &'a str))>,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    if !filters_type.is_empty() && !filters_value.is_empty() {
        let mut filtered_packets: &[Arc<ParsedPacket>] = &[];

        for filter in filters_value {
            match filter {
                (FilterNamesValues::SRC_IP, (true, source_ip)) => {
                    filtered_packets = apply_filter(
                        source_ip.to_owned(),
                        &packets_collection.source_ip_index,
                        start,
                        end,
                    );
                }
                _ => (),
            }
        }

        return Ok(filtered_packets
            .iter()
            .map(|x| ParsedPacket::clone(&*x))
            .collect());
    } else {
        return Ok(get_slice(&packets_collection.packets, start, end)
            .iter()
            .map(|x| ParsedPacket::clone(&*x))
            .collect());
    }
}

pub fn apply_filter<'a>(
    name: String,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    start: usize,
    end: usize,
) -> &'a [Arc<ParsedPacket>] {
    match index.get(&name) {
        Some(values) => get_slice(values, start, end),
        _ => &[],
    }
}

pub fn filter_by_dest_ip(
    dest_ip: String,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    let slice = match packets_collection.dest_ip_index.get(&dest_ip) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

pub fn filter_by_source_port(
    source_port: u16,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();
    let slice = match packets_collection.source_port_index.get(&source_port) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

pub fn filter_by_dest_port(
    dest_port: u16,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    let slice = match packets_collection.dest_port_index.get(&dest_port) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

pub fn filter_by_source_mac(
    source_mac: String,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();
    let slice = match packets_collection.source_mac_index.get(&source_mac) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

/* source_port_index
dest_port_index
source_mac_index
dest_mac_index */

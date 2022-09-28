use std::{collections::BTreeMap, sync::Arc};

use sniffer_parser::serializable_packet::{ParsedPacket, SerializablePacket};

use crate::{SniffingError, SniffingState};

#[allow(non_snake_case)]
mod FilterNamesValues {
    use serde::{Deserialize, Serialize};

    /* pub const ETHERNET: &str = "ethernet";
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
    pub const DNS: &str = "dns"; */

    pub const SRC_IP: &str = "src_ip";
    pub const DST_IP: &str = "dst_ip";
    pub const SRC_MAC: &str = "src_mac";
    pub const DST_MAC: &str = "dst_mac";
    pub const SRC_PORT: &str = "src_port";
    pub const DST_PORT: &str = "dst_port";
}

pub struct PacketsCollection {
    pub packets: Vec<Arc<ParsedPacket>>,

    pub source_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub dest_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub source_port_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    pub dest_port_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
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
    let mut packets_collection = state.packets.lock().unwrap();
    get_packets_internal(
        start,
        end,
        filters_type,
        filters_value,
        &mut *packets_collection,
    )
}

fn get_packets_internal<'a>(
    start: usize,
    end: usize,
    filters_type: Vec<(&'a str, bool)>,
    filters_value: Vec<(&'a str, (bool, &'a str))>,
    packets_collection: &mut PacketsCollection,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    if !filters_type.is_empty() || !filters_value.is_empty() {
        let mut filtered_packets: Vec<Arc<ParsedPacket>> = vec![];

        for (name, (is_active, value)) in filters_value {
            if is_active {
                apply_specific_filter(
                    name,
                    value,
                    start,
                    end,
                    &mut *packets_collection,
                    &mut filtered_packets,
                )?;
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

pub fn apply_specific_filter<'a>(
    name: &'a str,
    value: &'a str,
    start: usize,
    end: usize,
    packets_collection: &mut PacketsCollection,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) -> Result<(), SniffingError> {
    return match name {
        FilterNamesValues::SRC_IP => {
            filter_by_src_ip(
                start,
                end,
                &packets_collection.source_ip_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_IP => {
            filter_by_dst_ip(
                start,
                end,
                &packets_collection.dest_ip_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::SRC_MAC => {
            filter_by_src_mac(
                start,
                end,
                &packets_collection.source_mac_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_MAC => {
            filter_by_dst_mac(
                start,
                end,
                &packets_collection.dest_mac_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::SRC_PORT => {
            filter_by_src_port(
                start,
                end,
                &packets_collection.source_port_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_PORT => {
            filter_by_dst_port(
                start,
                end,
                &packets_collection.dest_port_index,
                value,
                filtered_packets,
            );
            Ok(())
        }
        _ => Err(SniffingError::UnknownFilterType(format!(
            "Unknown filter type: {}",
            name
        ))),
    };
}

pub fn filter_by_src_ip<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    ip_address: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::Ipv4Packet(ip_packet)) = p.get_network_layer_packet() {
                if ip_packet.source.to_string() != ip_address {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&ip_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

pub fn filter_by_dst_ip<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    ip_address: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::Ipv4Packet(ip_packet)) = p.get_network_layer_packet() {
                if ip_packet.destination.to_string() != ip_address {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&ip_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

pub fn filter_by_src_mac<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    mac_address: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::EthernetPacket(ethernet_packet)) =
                p.get_link_layer_packet()
            {
                if ethernet_packet.source.to_string() != mac_address {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&mac_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

pub fn filter_by_dst_mac<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    mac_address: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::EthernetPacket(ethernet_packet)) =
                p.get_link_layer_packet()
            {
                if ethernet_packet.destination.to_string() != mac_address {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&mac_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

pub fn filter_by_src_port<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    src_port: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::TcpPacket(tcp_packet)) = p.get_transport_layer_packet()
            {
                if tcp_packet.source.to_string() != src_port {
                    return false;
                }
            }

            if let Some(SerializablePacket::UdpPacket(udp_packet)) = p.get_transport_layer_packet()
            {
                if udp_packet.source.to_string() != src_port {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&src_port.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

pub fn filter_by_dst_port<'a>(
    start: usize,
    end: usize,
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    dst_port: &'a str,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if !filtered_packets.is_empty() {
        filtered_packets.retain(|p| {
            if let Some(SerializablePacket::TcpPacket(tcp_packet)) = p.get_transport_layer_packet()
            {
                if tcp_packet.destination.to_string() != dst_port {
                    return false;
                }
            }

            if let Some(SerializablePacket::UdpPacket(udp_packet)) = p.get_transport_layer_packet()
            {
                if udp_packet.destination.to_string() != dst_port {
                    return false;
                }
            }

            return true;
        });
    } else {
        match index.get(&dst_port.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(get_slice(values, start, end)),
            _ => (),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use pnet::util::MacAddr;
    use sniffer_parser::{
        parse_ethernet_frame,
        serializable_packet::{
            network::SerializableIpv4Packet,
            transport::SerializableTcpPacket,
            util::{
                get_dest_ip, get_dest_mac, get_dest_port, get_source_ip, get_source_mac,
                get_source_port,
            },
            ParsedPacket, SerializableEthernetPacket, SerializablePacket,
        },
    };

    use crate::SniffingError;

    use super::{get_packets, get_packets_internal, FilterNamesValues, PacketsCollection};

    const SOURCE_IP : &str = "10.10.10.10";
    const DEST_IP : &str = "11.11.11.11";
    const SOURCE_MAC : &str = "10.10.10.10.10.10";
    const DEST_MAC : &str = "11.11.11.11.11.11";
    const SOURCE_PORT : u16 = 4444;
    const DEST_PORT : u16 = 443;

    #[test]
    fn unknown_selective_filter() {
        let filters_type = Vec::new();
        let filters_value = vec![
            (FilterNamesValues::SRC_IP, (true, SOURCE_IP)),
            ("RandomUnknownFilterType", (true, "random")),
        ];

        match get_packets_internal(
            0,
            100,
            filters_type,
            filters_value,
            &mut PacketsCollection::new(),
        ) {
            Err(SniffingError::UnknownFilterType(str)) => {
                assert_eq!(str, "Unknown filter type: RandomUnknownFilterType")
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn first_selective_filter_no_results() {
        let filters_type = Vec::new();
        let filters_value = vec![(FilterNamesValues::SRC_IP, (true, SOURCE_IP))];
        let parsed_packets = vec![build_test_parsed_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            Ipv4Addr::new(10, 10, 10, 10),
            Ipv4Addr::new(11, 11, 11, 11),
            4444,
            443,
        )];

        match get_packets_internal(
            0,
            100,
            filters_type,
            filters_value,
            &mut build_test_packets_collection(parsed_packets),
        ) {
            Ok(empty) => assert!(empty.is_empty()),
            _ => unreachable!()
        }
    }

    #[test]
    fn first_selective_filter_with_results() {
        let filters_type = Vec::new();
        let filters_value = vec![(FilterNamesValues::SRC_IP, (true, SOURCE_IP))];
        let parsed_packets = vec![build_test_parsed_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            Ipv4Addr::new(10, 10, 10, 10),
            Ipv4Addr::new(11, 11, 11, 11),
            4444,
            443,
        )];

        match get_packets_internal(
            0,
            100,
            filters_type,
            filters_value,
            &mut build_test_packets_collection(parsed_packets),
        ) {
            Ok(single) => {
                assert_eq!(single.len(), 1);
                assert_eq!(get_source_ip(single.get(0).unwrap()).unwrap(), SOURCE_IP);
            },
            _ => unreachable!()
        }
    }

    #[test]
    fn multiple_selective_filter_with_results() {
        let filters_type = Vec::new();
        let filters_value = vec![
            (FilterNamesValues::SRC_IP, (true, SOURCE_IP)),
            (FilterNamesValues::DST_IP, (true, DEST_IP)),
        ];
        let parsed_packets = vec![build_test_parsed_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            Ipv4Addr::new(10, 10, 10, 10),
            Ipv4Addr::new(11, 11, 11, 11),
            4444,
            443,
        )];

        match get_packets_internal(
            0,
            100,
            filters_type,
            filters_value,
            &mut build_test_packets_collection(parsed_packets),
        ) {
            Ok(single) => {
                assert_eq!(single.len(), 1);
                assert_eq!(get_source_ip(single.get(0).unwrap()).unwrap(), SOURCE_IP);
                assert_eq!(get_dest_ip(single.get(0).unwrap()).unwrap(), DEST_IP);
            },
            _ => unreachable!()
        }
    }

    // Utils

    fn build_test_packets_collection(parsed_packets: Vec<ParsedPacket>) -> PacketsCollection {
        let mut packet_collection = PacketsCollection::new();

        for parsed_packet in parsed_packets {
            let parsed_packet = Arc::new(parsed_packet);

            packet_collection.source_ip_index.insert(
                get_source_ip(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
            packet_collection.dest_ip_index.insert(
                get_dest_ip(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
            packet_collection.source_port_index.insert(
                get_source_port(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
            packet_collection.dest_port_index.insert(
                get_dest_port(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
            packet_collection.source_mac_index.insert(
                get_source_mac(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
            packet_collection.dest_mac_index.insert(
                get_dest_mac(&parsed_packet).unwrap(),
                vec![parsed_packet.clone()],
            );
        }

        packet_collection
    }

    fn build_test_parsed_packet(
        source_mac: MacAddr,
        dest_mac: MacAddr,
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
    ) -> ParsedPacket {
        let mut parsed_packet = ParsedPacket::new();

        parsed_packet.set_link_layer_packet(Some(SerializablePacket::EthernetPacket(
            SerializableEthernetPacket {
                destination: dest_mac,
                source: source_mac,
                ethertype: "Ipv4".to_owned(),
                payload: Vec::new(),
            },
        )));

        parsed_packet.set_network_layer_packet(Some(SerializablePacket::Ipv4Packet(
            SerializableIpv4Packet {
                version: 1,
                header_length: 1,
                dscp: 1,
                ecn: 1,
                total_length: 1,
                identification: 1,
                flags: 1,
                fragment_offset: 1,
                ttl: 1,
                next_level_protocol: "Tcp (6)".to_owned(),
                checksum: 1,
                source: source_ip,
                destination: dest_ip,
                length: 1,
            },
        )));

        parsed_packet.set_transport_layer_packet(Some(SerializablePacket::TcpPacket(
            SerializableTcpPacket {
                source: source_port,
                destination: dest_port,
                sequence: 1,
                acknowledgement: 1,
                data_offset: 1,
                reserved: 1,
                flags: 1,
                window: 1,
                checksum: 1,
                urgent_ptr: 1,
                options: Vec::new(),
                length: 1,
            },
        )));

        parsed_packet
    }
}

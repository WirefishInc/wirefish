use crate::{SniffingError, SniffingState};
use sniffer_parser::serializable_packet::{
    util::{
        get_dest_ip, get_dest_mac, get_dest_port, get_source_ip, get_source_mac, get_source_port,
    },
    ParsedPacket,
};
use std::{collections::BTreeMap, sync::Arc};

#[allow(non_snake_case)]
mod FilterNamesValues {
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

    /// Indexes as Binary Trees for fast selective searching
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

    pub fn clear(&mut self) {
        self.source_ip_index.clear();
        self.dest_ip_index.clear();
        self.source_port_index.clear();
        self.dest_port_index.clear();
        self.source_mac_index.clear();
        self.dest_mac_index.clear();
        self.ethernet_packets.clear();
        self.malformed_packets.clear();
        self.unknown_packets.clear();
        self.tcp_packets.clear();
        self.udp_packets.clear();
        self.icmp_packets.clear();
        self.icmpv6_packets.clear();
        self.http_packets.clear();
        self.tls_packets.clear();
        self.ipv4_packets.clear();
        self.ipv6_packets.clear();
        self.dns_packets.clear();
        self.arp_packets.clear();
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
        let mut is_index_used = true;

        // TODO
        /*
        filters_type.into_iter().for_each(|(name, value)| {
            match name {
                FilterNamesValues::UNKNOWN => if value { filtered_packets.extend_from_slice(&*packets_collection.unknown_packets) },
                FilterNamesValues::MALFORMED => if value { filtered_packets.extend_from_slice(&*packets_collection.malformed_packets) },
                FilterNamesValues::ETHERNET => if value { filtered_packets.extend_from_slice(&*packets_collection.ethernet_packets) },
                FilterNamesValues::IPV4 => if value { filtered_packets.extend_from_slice(&*packets_collection.ipv4_packets) },
                FilterNamesValues::IPV6 => if value { filtered_packets.extend_from_slice(&*packets_collection.ipv6_packets) },
                FilterNamesValues::ARP => if value { filtered_packets.extend_from_slice(&*packets_collection.arp_packets) },
                FilterNamesValues::TCP => if value { filtered_packets.extend_from_slice(&*packets_collection.tcp_packets) },
                FilterNamesValues::UDP => if value { filtered_packets.extend_from_slice(&*packets_collection.udp_packets) },
                FilterNamesValues::ICMP => if value { filtered_packets.extend_from_slice(&*packets_collection.icmp_packets) },
                FilterNamesValues::ICMPV6 => if value { filtered_packets.extend_from_slice(&*packets_collection.icmpv6_packets) },
                FilterNamesValues::HTTP => if value { filtered_packets.extend_from_slice(&*packets_collection.http_packets) },
                FilterNamesValues::TLS => if value { filtered_packets.extend_from_slice(&*packets_collection.tls_packets) },
                FilterNamesValues::DNS => if value { filtered_packets.extend_from_slice(&*packets_collection.dns_packets) },
                _ => ()
            }
        });*/

        for (name, (is_active, value)) in filters_value {
            if is_active {
                //reduced = true;
                apply_specific_filter(
                    name,
                    value,
                    end,
                    is_index_used,
                    &mut *packets_collection,
                    &mut filtered_packets,
                )?;

                println!("Done");

                if is_index_used {
                    is_index_used = false;
                }
            }
        }

        //if !reduced { filtered_packets = Vec::from(get_slice(&filtered_packets, start, end)) }

        return Ok(get_slice(&filtered_packets, start, end)
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
    end: usize,
    is_index_used: bool,
    packets_collection: &mut PacketsCollection,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) -> Result<(), SniffingError> {
    return match name {
        FilterNamesValues::SRC_IP => {
            filter_by_src_ip(
                &packets_collection.source_ip_index,
                end,
                value,
                is_index_used,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_IP => {
            filter_by_dst_ip(
                &packets_collection.dest_ip_index,
                end,
                value,
                is_index_used,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::SRC_MAC => {
            filter_by_src_mac(
                &packets_collection.source_mac_index,
                end,
                value,
                is_index_used,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_MAC => {
            filter_by_dst_mac(
                &packets_collection.dest_mac_index,
                end,
                value,
                is_index_used,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::SRC_PORT => {
            filter_by_src_port(
                &packets_collection.source_port_index,
                end,
                value,
                is_index_used,
                filtered_packets,
            );
            Ok(())
        }
        FilterNamesValues::DST_PORT => {
            filter_by_dst_port(
                &packets_collection.dest_port_index,
                end,
                value,
                is_index_used,
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
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    ip_address: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let source_ip = get_source_ip(p);
                if source_ip.is_some() && source_ip.unwrap() == ip_address {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&ip_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

pub fn filter_by_dst_ip<'a>(
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    ip_address: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let dest_ip = get_dest_ip(p);
                if dest_ip.is_some() && dest_ip.unwrap() == ip_address {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&ip_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

pub fn filter_by_src_mac<'a>(
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    mac_address: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let source_mac = get_source_mac(p);
                if source_mac.is_some() && source_mac.unwrap() == mac_address {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&mac_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

pub fn filter_by_dst_mac<'a>(
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    mac_address: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let dest_mac = get_dest_mac(p);
                if dest_mac.is_some() && dest_mac.unwrap() == mac_address {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&mac_address.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

pub fn filter_by_src_port<'a>(
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    src_port: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let source_port = get_source_port(p);
                if source_port.is_some() && source_port.unwrap() == src_port {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&src_port.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

pub fn filter_by_dst_port<'a>(
    index: &'a BTreeMap<String, Vec<Arc<ParsedPacket>>>,
    end: usize,
    dst_port: &'a str,
    is_index_used: bool,
    filtered_packets: &mut Vec<Arc<ParsedPacket>>,
) {
    if filtered_packets.is_empty() && !is_index_used {
        return;
    }

    if !is_index_used {
        let mut counter = 0;
        *filtered_packets = filtered_packets
            .iter()
            .filter_map(|p| {
                let dest_port = get_dest_port(p);
                if dest_port.is_some() && dest_port.unwrap() == dst_port {
                    return Some(Arc::clone(p));
                }

                return None;
            })
            .take_while(|_| {
                counter += 1;
                counter <= end
            })
            .collect();
    } else {
        match index.get(&dst_port.to_owned()) {
            Some(values) => filtered_packets.extend_from_slice(values),
            _ => (),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use pnet::util::MacAddr;
    use sniffer_parser::serializable_packet::{
        network::SerializableIpv4Packet,
        transport::SerializableTcpPacket,
        util::{
            get_dest_ip, get_dest_mac, get_dest_port, get_source_ip, get_source_mac,
            get_source_port,
        },
        ParsedPacket, SerializableEthernetPacket, SerializablePacket,
    };

    use crate::SniffingError;

    use super::{get_packets_internal, FilterNamesValues, PacketsCollection};

    const SOURCE_IP: &str = "10.10.10.10";
    const DEST_IP: &str = "11.11.11.11";
    const SOURCE_PORT: u16 = 4444;
    const DEST_PORT: u16 = 443;

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
        let filters_value = vec![(FilterNamesValues::SRC_IP, (true, "192.168.1.1"))];
        let parsed_packets = vec![build_test_parsed_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            Ipv4Addr::new(10, 10, 10, 10),
            Ipv4Addr::new(11, 11, 11, 11),
            SOURCE_PORT,
            DEST_PORT,
        )];

        match get_packets_internal(
            0,
            100,
            filters_type,
            filters_value,
            &mut build_test_packets_collection(parsed_packets),
        ) {
            Ok(empty) => assert!(empty.is_empty()),
            _ => unreachable!(),
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
            SOURCE_PORT,
            DEST_PORT,
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
            }
            _ => unreachable!(),
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
            SOURCE_PORT,
            DEST_PORT,
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
            }
            _ => unreachable!(),
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

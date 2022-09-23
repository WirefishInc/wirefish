use pnet::packet::arp::ArpPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::net::IpAddr;

use super::*;
use crate::serializable_packet::network::{
    SerializableArpPacket, SerializableIpv4Packet, SerializableIpv6Packet,
};
use crate::transport::*;

pub fn handle_ipv4_packet(packet: &[u8], parsed_packet: &mut ParsedPacket) {
    let header = Ipv4Packet::new(packet);
    if let Some(header) = header {
        parsed_packet.set_network_layer_packet(Some(SerializablePacket::Ipv4Packet(
            SerializableIpv4Packet::from(&header),
        )));
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            parsed_packet,
        );
    } else {
        debug!("Malformed IPv4 Packet");
        parsed_packet.set_network_layer_packet(Some(SerializablePacket::MalformedPacket(
            "Malformed IPv4 Packet".to_string(),
        )));
    }
}

pub fn handle_ipv6_packet(packet: &[u8], parsed_packet: &mut ParsedPacket) {
    let header = Ipv6Packet::new(packet);
    if let Some(header) = header {
        parsed_packet.set_network_layer_packet(Some(SerializablePacket::Ipv6Packet(
            SerializableIpv6Packet::from(&header),
        )));
        handle_transport_protocol(
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            parsed_packet,
        );
    } else {
        debug!("Malformed IPv6 Packet");
        parsed_packet.set_network_layer_packet(Some(SerializablePacket::MalformedPacket(
            "Malformed IPv6 Packet".to_string(),
        )));
    }
}

pub fn handle_arp_packet(
    packet: &[u8],
    source: MacAddr,
    dest: MacAddr,
    parsed_packet: &mut ParsedPacket,
) {
    let header = ArpPacket::new(packet);
    if let Some(header) = header {
        debug!(
            "ARP packet: {}({}) > {}({}); operation: {:?}",
            source,
            header.get_sender_proto_addr(),
            dest,
            header.get_target_proto_addr(),
            header.get_operation()
        );

        parsed_packet.set_network_layer_packet(Some(SerializablePacket::ArpPacket(
            SerializableArpPacket::from(&header),
        )));
    } else {
        debug!("Malformed ARP Packet");
        parsed_packet.set_network_layer_packet(Some(SerializablePacket::MalformedPacket(
            "Malformed ARP Packet".to_string(),
        )));
    }
}

#[cfg(test)]
pub mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    use crate::serializable_packet::{ParsedPacket, SerializablePacket};
    use crate::{handle_ipv4_packet, handle_ipv6_packet};

    use super::handle_arp_packet;

    #[test]
    fn valid_arp_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let ethernet_packet = build_test_arp_packet(ethernet_buffer.as_mut_slice());

        let mut parsed_packet = ParsedPacket::new();
        handle_arp_packet(
            ethernet_packet.payload(),
            ethernet_packet.get_source(),
            ethernet_packet.get_destination(),
            &mut parsed_packet,
        );

        let arp_packet = ArpPacket::new(ethernet_packet.payload()).unwrap();
        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::ArpPacket(new_arp_packet) => {
                assert_eq!(
                    new_arp_packet.hardware_type,
                    format!("{:?}", arp_packet.get_hardware_type())
                );
                assert_eq!(
                    new_arp_packet.protocol_type,
                    arp_packet.get_protocol_type().0
                );
                assert_eq!(new_arp_packet.hw_addr_len, arp_packet.get_hw_addr_len());
                assert_eq!(
                    new_arp_packet.proto_addr_len,
                    arp_packet.get_proto_addr_len()
                );
                assert_eq!(
                    new_arp_packet.operation,
                    format!("ARP Request ({})", arp_packet.get_operation().0)
                );
                assert_eq!(
                    new_arp_packet.sender_hw_addr,
                    arp_packet.get_sender_hw_addr()
                );
                assert_eq!(
                    new_arp_packet.sender_proto_addr,
                    arp_packet.get_sender_proto_addr()
                );
                assert_eq!(
                    new_arp_packet.target_hw_addr,
                    arp_packet.get_target_hw_addr()
                );
                assert_eq!(
                    new_arp_packet.target_proto_addr,
                    arp_packet.get_target_proto_addr()
                );
                assert_eq!(
                    new_arp_packet.length,
                    arp_packet.payload().len()
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn malformed_arp_packet() {
        let mut parsed_packet = ParsedPacket::new();
        handle_arp_packet(
            &[],
            MacAddr(10, 10, 10, 10, 10, 10),
            MacAddr(11, 11, 11, 11, 11, 11),
            &mut parsed_packet,
        );

        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::MalformedPacket(str) => assert_eq!(str, "Malformed ARP Packet"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_ip_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let ethernet_packet = build_test_ip_packet(ethernet_buffer.as_mut_slice());

        let mut parsed_packet = ParsedPacket::new();
        handle_ipv4_packet(ethernet_packet.payload(), &mut parsed_packet);

        let ip_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::Ipv4Packet(new_ip_packet) => {
                assert_eq!(new_ip_packet.version, ip_packet.get_version());
                assert_eq!(new_ip_packet.header_length, ip_packet.get_header_length());
                assert_eq!(new_ip_packet.dscp, ip_packet.get_dscp());
                assert_eq!(new_ip_packet.ecn, ip_packet.get_ecn());
                assert_eq!(new_ip_packet.total_length, ip_packet.get_total_length());
                assert_eq!(new_ip_packet.identification, ip_packet.get_identification());
                assert_eq!(new_ip_packet.flags, ip_packet.get_flags());
                assert_eq!(
                    new_ip_packet.fragment_offset,
                    ip_packet.get_fragment_offset()
                );
                assert_eq!(new_ip_packet.ttl, ip_packet.get_ttl());
                assert_eq!(
                    new_ip_packet.next_level_protocol,
                    format!(
                        "{} ({})",
                        ip_packet.get_next_level_protocol(),
                        ip_packet.get_next_level_protocol().0
                    )
                );
                assert_eq!(new_ip_packet.checksum, ip_packet.get_checksum());
                assert_eq!(new_ip_packet.source, ip_packet.get_source());
                assert_eq!(new_ip_packet.destination, ip_packet.get_destination());
                assert_eq!(
                    new_ip_packet.length,
                    ip_packet.payload().len()
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn malformed_ip_packet() {
        let mut parsed_packet = ParsedPacket::new();
        handle_ipv4_packet(&[], &mut parsed_packet);

        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::MalformedPacket(str) => assert_eq!(str, "Malformed IPv4 Packet"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_ipv6_packet() {
        let mut ethernet_buffer = [0u8; 256];
        let ethernet_packet = build_test_ipv6_packet(ethernet_buffer.as_mut_slice());

        let mut parsed_packet = ParsedPacket::new();
        handle_ipv6_packet(ethernet_packet.payload(), &mut parsed_packet);

        let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::Ipv6Packet(new_ipv6_packet) => {
                assert_eq!(new_ipv6_packet.version, ipv6_packet.get_version());
                assert_eq!(
                    new_ipv6_packet.traffic_class,
                    ipv6_packet.get_traffic_class()
                );
                assert_eq!(new_ipv6_packet.flow_label, ipv6_packet.get_flow_label());
                assert_eq!(
                    new_ipv6_packet.payload_length,
                    ipv6_packet.get_payload_length()
                );
                assert_eq!(
                    new_ipv6_packet.next_header,
                    format!(
                        "{} ({})",
                        ipv6_packet.get_next_header(),
                        ipv6_packet.get_next_header().0
                    )
                );
                assert_eq!(new_ipv6_packet.hop_limit, ipv6_packet.get_hop_limit());
                assert_eq!(new_ipv6_packet.source, ipv6_packet.get_source());
                assert_eq!(new_ipv6_packet.destination, ipv6_packet.get_destination());
                assert_eq!(new_ipv6_packet.length, ipv6_packet.payload().len());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn malformed_ipv6_packet() {
        let mut parsed_packet = ParsedPacket::new();
        handle_ipv6_packet(&[], &mut parsed_packet);

        match parsed_packet.get_network_layer_packet().unwrap() {
            SerializablePacket::MalformedPacket(str) => assert_eq!(str, "Malformed IPv6 Packet"),
            _ => unreachable!(),
        }
    }

    ///////////////////// Utils

    fn build_test_arp_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_operation(ArpOperations::Request);

        arp_packet.set_sender_hw_addr(MacAddr::new(10, 10, 10, 10, 10, 10));
        arp_packet.set_sender_proto_addr(Ipv4Addr::new(10, 10, 10, 10));

        arp_packet.set_target_hw_addr(MacAddr::new(11, 11, 11, 11, 11, 11));
        arp_packet.set_target_proto_addr(Ipv4Addr::new(11, 11, 11, 11));

        ethernet_packet.set_payload(arp_packet.packet());

        ethernet_packet.consume_to_immutable()
    }

    fn build_test_ip_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut ip_buffer = [0u8; 28];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();

        ip_packet.set_version(4);
        ip_packet.set_header_length(20);
        ip_packet.set_dscp(0);
        ip_packet.set_ecn(0);
        ip_packet.set_total_length(40);
        ip_packet.set_identification(0x1234);
        ip_packet.set_flags(1);
        ip_packet.set_fragment_offset(0);
        ip_packet.set_ttl(2);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_checksum(1234);
        ip_packet.set_source(Ipv4Addr::new(10, 10, 10, 10));
        ip_packet.set_destination(Ipv4Addr::new(11, 11, 11, 11));
        ip_packet.set_options(&[]);

        ethernet_packet.set_payload(ip_packet.packet());

        ethernet_packet.consume_to_immutable()
    }

    fn build_test_ipv6_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut ip_buffer = [0u8; 128];
        let mut ipv6_packet = MutableIpv6Packet::new(&mut ip_buffer).unwrap();

        ipv6_packet.set_version(6);
        ipv6_packet.set_traffic_class(1);
        ipv6_packet.set_flow_label(2);
        ipv6_packet.set_payload_length(20);
        ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ipv6_packet.set_hop_limit(2);
        ipv6_packet.set_source(Ipv6Addr::new(10, 10, 10, 10, 10, 10, 10, 10));
        ipv6_packet.set_destination(Ipv6Addr::new(11, 11, 11, 11, 11, 11, 11, 11));

        ethernet_packet.set_payload(ipv6_packet.packet());

        ethernet_packet.consume_to_immutable()
    }
}

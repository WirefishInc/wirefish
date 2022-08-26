use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use std::net::IpAddr;

use super::*;
use crate::serializable_packet::network::{
    SerializableArpPacket, SerializableIpv4Packet, SerializableIpv6Packet,
};
use crate::transport::*;

pub fn handle_ipv4_packet(
    ethernet: &EthernetPacket,
    packets: &mut Vec<Box<dyn SerializablePacket>>,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        packets.push(Box::new(SerializableIpv4Packet::from(&header)));
        handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[]: Malformed IPv4 Packet");
    }
}

pub fn handle_ipv6_packet(
    ethernet: &EthernetPacket,
    packets: &mut Vec<Box<dyn SerializablePacket>>,
) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        packets.push(Box::new(SerializableIpv6Packet::from(&header)));
        handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[]: Malformed IPv6 Packet");
    }
}

pub fn handle_arp_packet(
    ethernet: &EthernetPacket,
    packets: &mut Vec<Box<dyn SerializablePacket>>,
) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[]: ARP packet: {}({}) > {}({}); operation: {:?}",
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );

        packets.push(Box::new(SerializableArpPacket::from(&header)));
    } else {
        println!("[]: Malformed ARP Packet");
    }
}

/*
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    use super::handle_arp_packet;

    #[test]
    fn valid_arp_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let mock_packet = build_test_arp_packet(ethernet_buffer.as_mut_slice());

        let new_packet = handle_arp_packet(&mock_packet);

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();

        assert_eq!(new_packet.packet_type, "ARP");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10");
        assert_eq!(new_packet.ip_destination, "11.11.11.11");
        assert_eq!(new_packet.info, "-");
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn malformed_arp_packet() {
        let ethernet_buffer = [10; 42];
        let mock_packet = EthernetPacket::new(&ethernet_buffer).unwrap();

        println!("{:?}", mock_packet.payload());

        let _new_packet = handle_arp_packet(&mock_packet);

        // TODO: Understand how to create a malformed packet... It seems impossible using the library
        // since the correct structure is enforced at every step. Maybe this case can be triggered just
        // by writing random raw bytes (or in real case)

        assert!(true);
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
}*/

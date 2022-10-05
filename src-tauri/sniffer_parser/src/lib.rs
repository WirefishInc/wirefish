mod application;
mod network;
mod transport;

pub use crate::application::*;
pub use crate::network::*;
use crate::serializable_packet::SerializableUnknownPacket;
pub use crate::transport::*;

pub mod serializable_packet;

use log::debug;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serializable_packet::ParsedPacket;
use serializable_packet::SerializableEthernetPacket;
use serializable_packet::SerializablePacket;

#[allow(non_snake_case)]
pub mod HeaderLength {
    pub const ETHERNET: usize = 14;
}

pub fn cleanup_sniffing_state() {
    ACTIVE_HTTP_PARSERS.with(|parsers| parsers.borrow_mut().clear());
    ACTIVE_TLS_PARSERS.with(|parsers| parsers.borrow_mut().clear());
}

pub fn parse_ethernet_frame(ethernet: &EthernetPacket, id: usize) -> ParsedPacket {
    let mut parsed_packet = ParsedPacket::new(id);

    parsed_packet.set_link_layer_packet(Some(SerializablePacket::EthernetPacket(
        SerializableEthernetPacket::from(ethernet),
    )));

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet.payload(), &mut parsed_packet),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet.payload(), &mut parsed_packet),
        EtherTypes::Arp => handle_arp_packet(
            ethernet.payload(),
            ethernet.get_source(),
            ethernet.get_destination(),
            &mut parsed_packet,
        ),
        _ => {
            debug!(
                "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            );

            parsed_packet.set_link_layer_packet(Some(SerializablePacket::UnknownPacket(
                SerializableUnknownPacket::from(ethernet),
            )));
        }
    }

    parsed_packet
}

#[cfg(test)]
mod tests {
    use crate::parse_ethernet_frame;
    use crate::serializable_packet::SerializablePacket;
    use pnet::packet::ethernet::EtherType;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    #[test]
    fn valid_ethernet_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let ethernet_packet = build_test_ethernet_packet(ethernet_buffer.as_mut_slice());

        let parsed_packet = parse_ethernet_frame(&ethernet_packet, 0);
        match parsed_packet.get_link_layer_packet().unwrap() {
            SerializablePacket::EthernetPacket(new_ethernet_packet) => {
                assert_eq!(
                    new_ethernet_packet.destination,
                    ethernet_packet.get_destination()
                );
                assert_eq!(new_ethernet_packet.source, ethernet_packet.get_source());
                assert_eq!(
                    new_ethernet_packet.ethertype,
                    ethernet_packet.get_ethertype().to_string()
                );
                assert_eq!(
                    new_ethernet_packet.payload,
                    ethernet_packet.payload().to_vec()
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_ethernet_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let ethernet_packet = build_test_unknown_ethernet_packet(ethernet_buffer.as_mut_slice());

        let parsed_packet = parse_ethernet_frame(&ethernet_packet, 0);
        match parsed_packet.get_link_layer_packet().unwrap() {
            SerializablePacket::UnknownPacket(unknown_packet) => {
                assert_eq!(
                    unknown_packet.destination,
                    ethernet_packet.get_destination()
                );
                assert_eq!(unknown_packet.source, ethernet_packet.get_source());
                assert_eq!(
                    unknown_packet.ethertype,
                    ethernet_packet.get_ethertype().to_string()
                );
                assert_eq!(unknown_packet.length, ethernet_packet.packet().len());
            }
            _ => unreachable!(),
        }
    }

    ///////////////////// Utils

    fn build_test_ethernet_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        ethernet_packet.consume_to_immutable()
    }

    fn build_test_unknown_ethernet_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherType(0x9999));

        ethernet_packet.consume_to_immutable()
    }
}

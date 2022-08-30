mod network;
mod transport;
mod application;

pub use crate::network::*;
pub use crate::transport::*;

mod serializable_packet;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serde::Serialize;
use serializable_packet::ParsedPacket;
use serializable_packet::SerializableEthernetPacket;
use serializable_packet::SerializablePacket;

// JSON Packet fields:
// - Type (TCP, UDP, ...)
// - MAC Source
// - MAC Destination
// - IP Source
// - IP Destination
// - Length
// - Additional Info
// - (?) Payload

#[derive(Serialize, Debug)]
pub struct GenericPacket {
    packet_type: String,
    mac_source: MacAddr,
    mac_destination: MacAddr,
    ip_source: String,
    ip_destination: String,
    length: usize,
    info: String,
    payload: Option<Vec<u8>>,
}

impl GenericPacket {
    pub fn new(
        packet_type: String,
        mac_source: MacAddr,
        mac_destination: MacAddr,
        ip_source: String,
        ip_destination: String,
        length: usize,
        info: String,
        payload: Option<Vec<u8>>,
    ) -> Self {
        GenericPacket {
            packet_type,
            mac_source,
            mac_destination,
            ip_source,
            ip_destination,
            length,
            info,
            payload,
        }
    }
}

pub fn parse_ethernet_frame(ethernet: &EthernetPacket) -> ParsedPacket {
    let mut parsed_packet = ParsedPacket::new();

    parsed_packet.set_link_layer_packet(Some(SerializablePacket::EthernetPacket(
        SerializableEthernetPacket::from(ethernet),
    )));

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, &mut parsed_packet),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, &mut parsed_packet),
        EtherTypes::Arp => handle_arp_packet(ethernet, &mut parsed_packet),
        _ => {
            println!(
                "[]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            );
        }
    }

    parsed_packet
}

#[cfg(test)]
mod tests {
    use crate::parse_ethernet_frame;
    use crate::serializable_packet::SerializablePacket;
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    #[test]
    fn valid_ethernet_packet() {
        let mut ethernet_buffer = [0u8; 42];
        let ethernet_packet = build_test_ethernet_packet(ethernet_buffer.as_mut_slice());

        let parsed_packet = parse_ethernet_frame(&ethernet_packet);

        if let SerializablePacket::EthernetPacket(new_ethernet_packet) =
            parsed_packet.get_link_layer_packet().unwrap()
        {
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
    }

    ///////////////////// Utils

    fn build_test_ethernet_packet<'a>(ethernet_buffer: &'a mut [u8]) -> EthernetPacket<'a> {
        let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::new(11, 11, 11, 11, 11, 11));
        ethernet_packet.set_source(MacAddr::new(10, 10, 10, 10, 10, 10));
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        ethernet_packet.consume_to_immutable()
    }
}

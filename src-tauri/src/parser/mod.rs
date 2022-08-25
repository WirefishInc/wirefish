pub mod network;
pub mod transport;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serde::Serialize;

use crate::parser::network::*;

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

pub fn handle_ethernet_frame(ethernet: &EthernetPacket) -> Option<GenericPacket> {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet),
        EtherTypes::Arp => handle_arp_packet(ethernet),
        _ => {
            println!(
                "[]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                ethernet.get_source(),
                ethernet.get_destination(),
                ethernet.get_ethertype(),
                ethernet.packet().len()
            );

            None
        }
    }
}

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{Packet};
use std::net::IpAddr;

use super::GenericPacket;
use crate::parser::transport::*;

pub fn handle_ipv4_packet(ethernet: &EthernetPacket) -> Option<GenericPacket> {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        return handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[]: Malformed IPv4 Packet");
        return None;
    }
}

pub fn handle_ipv6_packet(ethernet: &EthernetPacket) -> Option<GenericPacket> {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        return handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[]: Malformed IPv6 Packet");
        return None;
    }
}

pub fn handle_arp_packet(ethernet: &EthernetPacket) -> Option<GenericPacket> {
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

        return Some(GenericPacket::new(
            "ARP".to_owned(),
            ethernet.get_source(),
            ethernet.get_destination(),
            header.get_sender_proto_addr().to_string(),
            header.get_target_proto_addr().to_string(),
            ethernet.payload().len(),
            "-".to_owned(),
            None
        ));

    } else {
        println!("[]: Malformed ARP Packet");
        return None;
    }
}

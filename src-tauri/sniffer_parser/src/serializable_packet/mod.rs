pub mod network;
pub mod transport;

use pnet::packet::Packet;
use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};
use serde::Serialize;

use self::network::{SerializableArpPacket, SerializableIpv4Packet, SerializableIpv6Packet};
use self::transport::{
    SerializableEchoReplyPacket, SerializableEchoRequestPacket, SerializableIcmpPacket,
    SerializableIcmpv6Packet, SerializableTcpPacket, SerializableUdpPacket,
};

// pub trait SerializablePacket: erased_serde::Serialize {}
// erased_serde::serialize_trait_object!(SerializablePacket);

#[derive(Serialize, Debug)]
pub enum SerializablePacket {
    EthernetPacket(SerializableEthernetPacket),
    ArpPacket(SerializableArpPacket),
    Ipv4Packet(SerializableIpv4Packet),
    Ipv6Packet(SerializableIpv6Packet),
    EchoReplyPacket(SerializableEchoReplyPacket),
    EchoRequestPacket(SerializableEchoRequestPacket),
    IcmpPacket(SerializableIcmpPacket),
    Icmpv6Packet(SerializableIcmpv6Packet),
    TcpPacket(SerializableTcpPacket),
    UdpPacket(SerializableUdpPacket),
}

/// Ethernet Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableEthernetPacket {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: String,
    pub payload: Vec<u8>,
}

// impl SerializablePacket for SerializableEthernetPacket {}

impl<'a> From<&EthernetPacket<'a>> for SerializableEthernetPacket {
    fn from(packet: &EthernetPacket<'a>) -> Self {
        SerializableEthernetPacket {
            destination: packet.get_destination(),
            source: packet.get_source(),
            ethertype: packet.get_ethertype().to_string(),
            payload: packet.payload().to_vec(),
        }
    }
}

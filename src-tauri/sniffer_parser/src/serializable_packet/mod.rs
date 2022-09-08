pub mod application;
pub mod network;
pub mod transport;

use pnet::packet::Packet;
use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};
use serde::Serialize;

use self::application::{
    SerializableDnsPacket, SerializableHttpRequestPacket, SerializableHttpResponsePacket,
    SerializableTlsPacket,
};
use self::network::{SerializableArpPacket, SerializableIpv4Packet, SerializableIpv6Packet};
use self::transport::{
    SerializableEchoReplyPacket, SerializableEchoRequestPacket, SerializableIcmpPacket,
    SerializableIcmpv6Packet, SerializableTcpPacket, SerializableUdpPacket,
};

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ParsedPacket {
    link_layer_packet: Option<SerializablePacket>,
    network_layer_packet: Option<SerializablePacket>,
    transport_layer_packet: Option<SerializablePacket>,
    application_layer_packet: Option<SerializablePacket>,
}

impl ParsedPacket {
    pub fn new() -> Self {
        ParsedPacket {
            link_layer_packet: None,
            network_layer_packet: None,
            transport_layer_packet: None,
            application_layer_packet: None,
        }
    }

    pub fn get_link_layer_packet(&self) -> Option<&SerializablePacket> {
        self.link_layer_packet.as_ref()
    }

    pub fn get_network_layer_packet(&self) -> Option<&SerializablePacket> {
        self.network_layer_packet.as_ref()
    }

    pub fn get_transport_layer_packet(&self) -> Option<&SerializablePacket> {
        self.transport_layer_packet.as_ref()
    }

    pub fn get_application_layer_packet(&self) -> Option<&SerializablePacket> {
        self.application_layer_packet.as_ref()
    }

    pub fn set_link_layer_packet(&mut self, link_layer_packet: Option<SerializablePacket>) {
        self.link_layer_packet = link_layer_packet;
    }

    pub fn set_network_layer_packet(&mut self, network_layer_packet: Option<SerializablePacket>) {
        self.network_layer_packet = network_layer_packet;
    }

    pub fn set_transport_layer_packet(
        &mut self,
        transport_layer_packet: Option<SerializablePacket>,
    ) {
        self.transport_layer_packet = transport_layer_packet;
    }

    pub fn set_application_layer_packet(
        &mut self,
        application_layer_packet: Option<SerializablePacket>,
    ) {
        self.application_layer_packet = application_layer_packet;
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "packet")]
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
    HttpRequestPacket(SerializableHttpRequestPacket),
    HttpResponsePacket(SerializableHttpResponsePacket),
    TlsPacket(SerializableTlsPacket),
    DnsPacket(SerializableDnsPacket),

    MalformedPacket(String),
    UnknownPacket(SerializableUnknownPacket),
}

/// Ethernet Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableEthernetPacket {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: String,
    pub payload: Vec<u8>,
}

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

/// Unknown Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableUnknownPacket {
    pub destination: MacAddr,
    pub source: MacAddr,
    pub ethertype: String,
    pub length: usize,
}

impl<'a> From<&EthernetPacket<'a>> for SerializableUnknownPacket {
    fn from(packet: &EthernetPacket<'a>) -> Self {
        SerializableUnknownPacket {
            destination: packet.get_destination(),
            source: packet.get_source(),
            ethertype: packet.get_ethertype().to_string(),
            length: packet.packet().len(),
        }
    }
}

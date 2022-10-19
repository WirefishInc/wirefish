//! Transport level Packets Representation

use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Type, Icmpv6Types};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Serialize;

/// TCP Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableTcpPacket {
    pub source: u16,
    pub destination: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
    pub length: usize,
}

impl<'a> From<&TcpPacket<'a>> for SerializableTcpPacket {
    fn from(packet: &TcpPacket<'a>) -> Self {
        SerializableTcpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            sequence: packet.get_sequence(),
            acknowledgement: packet.get_acknowledgement(),
            data_offset: packet.get_data_offset(),
            reserved: packet.get_reserved(),
            flags: packet.get_flags(),
            window: packet.get_window(),
            checksum: packet.get_checksum(),
            urgent_ptr: packet.get_urgent_ptr(),
            options: packet.get_options_raw().to_vec(),
            length: packet.payload().len(),
        }
    }
}

/// UDP Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableUdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
}

impl<'a> From<&UdpPacket<'a>> for SerializableUdpPacket {
    fn from(packet: &UdpPacket<'a>) -> Self {
        SerializableUdpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
        }
    }
}

/// ICMPv6 Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableIcmpv6Packet {
    pub icmpv6_type: String,
    pub icmpv6_code: u8,
    pub checksum: u16,
    pub length: usize,
}

impl<'a> From<&Icmpv6Packet<'a>> for SerializableIcmpv6Packet {
    fn from(packet: &Icmpv6Packet<'a>) -> Self {
        SerializableIcmpv6Packet {
            icmpv6_type: icmpv6_type_to_string(packet.get_icmpv6_type()),
            icmpv6_code: packet.get_icmpv6_code().0,
            checksum: packet.get_checksum(),
            length: packet.payload().len(),
        }
    }
}

/// Get ICMPv6 Message Type
pub fn icmpv6_type_to_string(icmp_type: Icmpv6Type) -> String {
    return match icmp_type {
        Icmpv6Types::DestinationUnreachable => format!("DestinationUnreachable ({})", icmp_type.0),
        Icmpv6Types::PacketTooBig => format!("PacketTooBig ({})", icmp_type.0),
        Icmpv6Types::TimeExceeded => format!("TimeExceeded ({})", icmp_type.0),
        Icmpv6Types::ParameterProblem => format!("ParameterProblem ({})", icmp_type.0),
        Icmpv6Types::EchoRequest => format!("EchoRequest ({})", icmp_type.0),
        Icmpv6Types::EchoReply => format!("EchoReply ({})", icmp_type.0),
        Icmpv6Types::RouterSolicit => format!("RouterSolicit ({})", icmp_type.0),
        Icmpv6Types::RouterAdvert => format!("RouterAdvert ({})", icmp_type.0),
        Icmpv6Types::NeighborSolicit => format!("NeighborSolicit ({})", icmp_type.0),
        Icmpv6Types::NeighborAdvert => format!("NeighborAdvert ({})", icmp_type.0),
        Icmpv6Types::Redirect => format!("Redirect ({})", icmp_type.0),
        _ => format!("Unknown ({})", icmp_type.0),
    };
}

/// ICMP Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableIcmpPacket {
    pub icmp_type: String,
    pub icmp_code: u8,
    pub checksum: u16,
    pub length: usize,
}

impl<'a> From<&IcmpPacket<'a>> for SerializableIcmpPacket {
    fn from(packet: &IcmpPacket<'a>) -> Self {
        SerializableIcmpPacket {
            icmp_type: icmp_type_to_string(packet.get_icmp_type()),
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            length: packet.payload().len(),
        }
    }
}

/// Get ICMPv4 Message Type
pub fn icmp_type_to_string(icmp_type: IcmpType) -> String {
    return match icmp_type {
        IcmpTypes::EchoReply => format!("EchoReply ({})", icmp_type.0),
        IcmpTypes::DestinationUnreachable => format!("DestinationUnreachable ({})", icmp_type.0),
        IcmpTypes::SourceQuench => format!("SourceQuench ({})", icmp_type.0),
        IcmpTypes::RedirectMessage => format!("RedirectMessage ({})", icmp_type.0),
        IcmpTypes::EchoRequest => format!("EchoRequest ({})", icmp_type.0),
        IcmpTypes::RouterAdvertisement => format!("RouterAdvertisement ({})", icmp_type.0),
        IcmpTypes::RouterSolicitation => format!("RouterSolicitation ({})", icmp_type.0),
        IcmpTypes::TimeExceeded => format!("TimeExceeded ({})", icmp_type.0),
        IcmpTypes::ParameterProblem => format!("ParameterProblem ({})", icmp_type.0),
        IcmpTypes::Timestamp => format!("Timestamp ({})", icmp_type.0),
        IcmpTypes::TimestampReply => format!("TimestampReply ({})", icmp_type.0),
        IcmpTypes::InformationRequest => format!("InformationRequest ({})", icmp_type.0),
        IcmpTypes::InformationReply => format!("InformationReply ({})", icmp_type.0),
        IcmpTypes::AddressMaskRequest => format!("AddressMaskRequest ({})", icmp_type.0),
        IcmpTypes::AddressMaskReply => format!("AddressMaskReply ({})", icmp_type.0),
        IcmpTypes::Traceroute => format!("Traceroute ({})", icmp_type.0),
        _ => format!("Unknown ({})", icmp_type.0),
    };
}

/// ICMP Echo Reply Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableEchoReplyPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub length: usize,
}

impl<'a> From<&EchoReplyPacket<'a>> for SerializableEchoReplyPacket {
    fn from(packet: &EchoReplyPacket<'a>) -> Self {
        SerializableEchoReplyPacket {
            icmp_type: packet.get_icmp_type().0,
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            identifier: packet.get_checksum(),
            sequence_number: packet.get_sequence_number(),
            length: packet.payload().len(),
        }
    }
}

/// ICMP Echo Request Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableEchoRequestPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub length: usize,
}

impl<'a> From<&EchoRequestPacket<'a>> for SerializableEchoRequestPacket {
    fn from(packet: &EchoRequestPacket<'a>) -> Self {
        SerializableEchoRequestPacket {
            icmp_type: packet.get_icmp_type().0,
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            identifier: packet.get_identifier(),
            sequence_number: packet.get_sequence_number(),
            length: packet.payload().len(),
        }
    }
}

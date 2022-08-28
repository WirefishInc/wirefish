use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Serialize;

/// TCP Packet Representation

#[derive(Serialize, Debug)]
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
    pub payload: Vec<u8>,
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
            payload: packet.payload().to_vec(),
        }
    }
}

/// UDP Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableUdpPacket {
    pub source: u16,
    pub destination: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl<'a> From<&UdpPacket<'a>> for SerializableUdpPacket {
    fn from(packet: &UdpPacket<'a>) -> Self {
        SerializableUdpPacket {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
}

/// UDP Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableIcmpv6Packet {
    pub icmpv6_type: u8,
    pub icmpv6_code: u8,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl<'a> From<&Icmpv6Packet<'a>> for SerializableIcmpv6Packet {
    fn from(packet: &Icmpv6Packet<'a>) -> Self {
        SerializableIcmpv6Packet {
            icmpv6_type: packet.get_icmpv6_type().0,
            icmpv6_code: packet.get_icmpv6_code().0,
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
}

/// ICMP Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableIcmpPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl<'a> From<&IcmpPacket<'a>> for SerializableIcmpPacket {
    fn from(packet: &IcmpPacket<'a>) -> Self {
        SerializableIcmpPacket {
            icmp_type: packet.get_icmp_type().0,
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            payload: packet.payload().to_vec(),
        }
    }
}

/// ICMP Echo Reply Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableEchoReplyPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: Vec<u8>,
}

impl<'a> From<&EchoReplyPacket<'a>> for SerializableEchoReplyPacket {
    fn from(packet: &EchoReplyPacket<'a>) -> Self {
        SerializableEchoReplyPacket {
            icmp_type: packet.get_icmp_type().0,
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            identifier: packet.get_checksum(),
            sequence_number: packet.get_sequence_number(),
            payload: packet.payload().to_vec(),
        }
    }
}

/// ICMP Echo Request Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableEchoRequestPacket {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence_number: u16,
    pub payload: Vec<u8>,
}

impl<'a> From<&EchoRequestPacket<'a>> for SerializableEchoRequestPacket {
    fn from(packet: &EchoRequestPacket<'a>) -> Self {
        SerializableEchoRequestPacket {
            icmp_type: packet.get_icmp_type().0,
            icmp_code: packet.get_icmp_code().0,
            checksum: packet.get_checksum(),
            identifier: packet.get_identifier(),
            sequence_number: packet.get_sequence_number(),
            payload: packet.payload().to_vec(),
        }
    }
}

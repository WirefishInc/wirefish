use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::util::MacAddr;
use std::net::IpAddr;

use super::GenericPacket;

pub fn handle_udp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> Option<GenericPacket> {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[]: UDP Packet: {}:{} > {}:{}; length: {}",
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );

        return Some(GenericPacket::new(
            "UDP".to_owned(),
            mac_source,
            mac_destination,
            format!("{}:{}", source, udp.get_source()),
            format!("{}:{}", destination, udp.get_destination()),
            udp.get_length().into(),
            "-".to_owned(),
            None,
        ));
    } else {
        println!("[]: Malformed UDP Packet");
        return None;
    }
}

pub fn handle_tcp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> Option<GenericPacket> {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[]: TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );

        return Some(GenericPacket::new(
            "TCP".to_owned(),
            mac_source,
            mac_destination,
            format!("{}:{}", source, tcp.get_source()),
            format!("{}:{}", destination, tcp.get_destination()),
            packet.len(),
            "-".to_owned(),
            None,
        ));
    } else {
        println!("[]: Malformed TCP Packet");
        return None;
    }
}

pub fn handle_transport_protocol(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) -> Option<GenericPacket> {
    return match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(mac_source, mac_destination, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(mac_source, mac_destination, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(mac_source, mac_destination, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(mac_source, mac_destination, source, destination, packet)
        }
        _ => {
            println!(
                "[]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                source,
                destination,
                protocol,
                packet.len()
            );

            None
        }
    };
}

pub fn handle_icmp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> Option<GenericPacket> {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );

                return Some(GenericPacket::new(
                    "ICMP echo reply".to_owned(),
                    mac_source,
                    mac_destination,
                    source.to_string(),
                    destination.to_string(),
                    packet.len(),
                    format!(
                        "seq={:?}, id={:?}",
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    ),
                    None,
                ));
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );

                return Some(GenericPacket::new(
                    "ICMP echo request".to_owned(),
                    mac_source,
                    mac_destination,
                    source.to_string(),
                    destination.to_string(),
                    packet.len(),
                    format!(
                        "seq={:?}, id={:?}",
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier()
                    ),
                    None,
                ));
            }
            _ => {
                println!(
                    "[]: ICMP packet {} -> {} (code={:?}, type={:?})",
                    source,
                    destination,
                    icmp_packet.get_icmp_code(),
                    icmp_packet.get_icmp_type()
                );

                return Some(GenericPacket::new(
                    "ICMP".to_owned(),
                    mac_source,
                    mac_destination,
                    source.to_string(),
                    destination.to_string(),
                    packet.len(),
                    format!(
                        "code={:?}, type={:?}",
                        icmp_packet.get_icmp_code(),
                        icmp_packet.get_icmp_type()
                    ),
                    None,
                ));
            }
        }
    } else {
        println!("[]: Malformed ICMP Packet");
        return None;
    }
}

pub fn handle_icmpv6_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
) -> Option<GenericPacket> {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[]: ICMPv6 packet {} -> {} (type={:?})",
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        );

        return Some(GenericPacket::new(
            "ICMP-V6".to_owned(),
            mac_source,
            mac_destination,
            source.to_string(),
            destination.to_string(),
            packet.len(),
            format!(
                "code={:?}, type={:?}",
                icmpv6_packet.get_icmpv6_code(),
                icmpv6_packet.get_icmpv6_type()
            ),
            None,
        ));
    } else {
        println!("[]: Malformed ICMPv6 Packet");
        return None;
    }
}

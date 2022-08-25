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
                    echo_reply_packet.get_identifier(),
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    use pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::icmp::IcmpType;
    use pnet::packet::icmpv6::Icmpv6Code;
    use pnet::packet::icmpv6::Icmpv6Types;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;
    use pnet::packet::icmpv6::echo_reply::Icmpv6Codes;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::udp::UdpPacket;
    use pnet::packet::Packet;
    use pnet::util::MacAddr;

    use super::*;

    #[test]
    fn valid_udp_packet() {
        let mut udp_buffer = [0u8; 42];
        let mock_packet = build_test_udp_packet(&mut udp_buffer);

        let new_packet = handle_udp_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();

        assert_eq!(new_packet.packet_type, "UDP");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10:4444");
        assert_eq!(new_packet.ip_destination, "11.11.11.11:4445");
        assert_eq!(new_packet.info, "-");
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn valid_tcp_packet() {
        let mut tcp_buffer = [0u8; 42];
        let mock_packet = build_test_tcp_packet(&mut tcp_buffer);

        let new_packet = handle_tcp_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();

        assert_eq!(new_packet.packet_type, "TCP");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10:4444");
        assert_eq!(new_packet.ip_destination, "11.11.11.11:4445");
        assert_eq!(new_packet.info, "-");
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn valid_icmp_echo_reply_packet() {
        let mut icmp_buffer = [0u8; 42];
        let mock_packet = echo_reply::EchoReplyPacket::new(&mut icmp_buffer).unwrap();

        println!("Reply: {:?}", mock_packet.get_icmp_type());

        let new_packet = handle_icmp_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();

        assert_eq!(new_packet.packet_type, "ICMP echo reply");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10");
        assert_eq!(new_packet.ip_destination, "11.11.11.11");
        assert_eq!(
            new_packet.info,
            format!(
                "seq={:?}, id={:?}",
                mock_packet.get_sequence_number(),
                mock_packet.get_identifier()
            )
        );
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn valid_icmp_echo_request_packet() {
        let mut icmp_buffer = [0u8; 42];
        let mut mock_packet =
            echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();

        mock_packet.set_icmp_type(IcmpTypes::EchoRequest);

        let new_packet = handle_icmp_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();
        println!("{:?}", new_packet);

        assert_eq!(new_packet.packet_type, "ICMP echo request");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10");
        assert_eq!(new_packet.ip_destination, "11.11.11.11");
        assert_eq!(
            new_packet.info,
            format!(
                "seq={:?}, id={:?}",
                mock_packet.get_sequence_number(),
                mock_packet.get_identifier()
            )
        );
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn unrecognized_icmp_packet() {
        let mut icmp_buffer = [0u8; 42];
        let mut mock_packet = MutableDestinationUnreachablePacket::new(&mut icmp_buffer).unwrap();

        mock_packet.set_icmp_type(IcmpTypes::DestinationUnreachable);

        let new_packet = handle_icmp_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();
        println!("{:?}", new_packet);

        assert_eq!(new_packet.packet_type, "ICMP");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10");
        assert_eq!(new_packet.ip_destination, "11.11.11.11");
        assert_eq!(
            new_packet.info,
            format!(
                "code={:?}, type={:?}",
                mock_packet.get_icmp_code(),
                mock_packet.get_icmp_type()
            )
        );
        assert_eq!(new_packet.payload, None);
    }

    #[test]
    fn valid_icmpv6_packet() {
        let mut icmpv6_buffer = [0u8; 42];
        let mock_packet = build_test_icmpv6_packet(&mut icmpv6_buffer);

        let new_packet = handle_icmpv6_packet(
            MacAddr::new(10, 10, 10, 10, 10, 10),
            MacAddr::new(11, 11, 11, 11, 11, 11),
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            mock_packet.packet(),
        );

        assert!(new_packet.is_some());
        let new_packet = new_packet.unwrap();
        println!("{:?}", new_packet);

        assert_eq!(new_packet.packet_type, "ICMP-V6");
        assert_eq!(new_packet.mac_source, MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(
            new_packet.mac_destination,
            MacAddr::new(11, 11, 11, 11, 11, 11)
        );
        assert_eq!(new_packet.ip_source, "10.10.10.10");
        assert_eq!(new_packet.ip_destination, "11.11.11.11");
        assert_eq!(
            new_packet.info,
            format!(
                "code={:?}, type={:?}",
                mock_packet.get_icmpv6_code(),
                mock_packet.get_icmpv6_type()
            )
        );
        assert_eq!(new_packet.payload, None);
    }

    ///////////////////// Utils

    fn build_test_udp_packet<'a>(udp_buffer: &'a mut [u8]) -> UdpPacket<'a> {
        let mut udp_packet = MutableUdpPacket::new(udp_buffer).unwrap();

        udp_packet.set_source(4444);
        udp_packet.set_destination(4445);

        udp_packet.consume_to_immutable()
    }

    fn build_test_tcp_packet<'a>(tcp_buffer: &'a mut [u8]) -> TcpPacket<'a> {
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        tcp_packet.set_source(4444);
        tcp_packet.set_destination(4445);

        tcp_packet.consume_to_immutable()
    }

    fn build_test_icmpv6_packet<'a>(icmpv6_buffer: &'a mut [u8]) -> Icmpv6Packet<'a> {
        let mut icmpv6_packet = MutableIcmpv6Packet::new(icmpv6_buffer).unwrap();

        icmpv6_packet.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoReply);

        icmpv6_packet.consume_to_immutable()
    }
}

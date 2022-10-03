use super::{ParsedPacket, SerializablePacket};

pub fn get_source_mac(packet: &ParsedPacket) -> Option<String> {
    if let Some(SerializablePacket::EthernetPacket(ethernet_packet)) =
        packet.get_link_layer_packet()
    {
        return Some(ethernet_packet.source.to_string());
    }

    return None;
}

pub fn get_dest_mac(packet: &ParsedPacket) -> Option<String> {
    if let Some(SerializablePacket::EthernetPacket(ethernet_packet)) =
        packet.get_link_layer_packet()
    {
        return Some(ethernet_packet.destination.to_string());
    }

    return None;
}

pub fn get_source_ip(packet: &ParsedPacket) -> Option<String> {
    return match packet.get_network_layer_packet() {
        Some(SerializablePacket::ArpPacket(network_packet)) => {
            Some(network_packet.sender_proto_addr.to_string())
        }
        Some(SerializablePacket::Ipv4Packet(network_packet)) => {
            Some(network_packet.source.to_string())
        }
        Some(SerializablePacket::Ipv6Packet(network_packet)) => {
            Some(network_packet.source.to_string())
        }
        _ => None,
    };
}

pub fn get_dest_ip(packet: &ParsedPacket) -> Option<String> {
    return match packet.get_network_layer_packet() {
        Some(SerializablePacket::ArpPacket(network_packet)) => {
            Some(network_packet.target_proto_addr.to_string())
        }
        Some(SerializablePacket::Ipv4Packet(network_packet)) => {
            Some(network_packet.destination.to_string())
        }
        Some(SerializablePacket::Ipv6Packet(network_packet)) => {
            Some(network_packet.destination.to_string())
        }
        _ => None,
    };
}

pub fn get_source_port(packet: &ParsedPacket) -> Option<String> {
    return match packet.get_transport_layer_packet() {
        Some(SerializablePacket::TcpPacket(transport_packet)) => {
            Some(transport_packet.source.to_string())
        }
        Some(SerializablePacket::UdpPacket(transport_packet)) => {
            Some(transport_packet.source.to_string())
        }
        _ => None,
    };
}

pub fn get_dest_port(packet: &ParsedPacket) -> Option<String> {
    return match packet.get_transport_layer_packet() {
        Some(SerializablePacket::TcpPacket(transport_packet)) => {
            Some(transport_packet.destination.to_string())
        }
        Some(SerializablePacket::UdpPacket(transport_packet)) => {
            Some(transport_packet.destination.to_string())
        }
        _ => None,
    };
}

pub fn contains_unknokn(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::UnknownPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_malformed(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_network_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    if let Some(SerializablePacket::MalformedPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ethernet(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::EthernetPacket(_)) = packet.get_link_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_tcp(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::TcpPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_udp(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::UdpPacket(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_icmp(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::IcmpPacket(_))
    | Some(SerializablePacket::EchoReplyPacket(_))
    | Some(SerializablePacket::EchoRequestPacket(_)) = packet.get_transport_layer_packet()
    {
        return true;
    }

    return false;
}

pub fn contains_icmp6(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::Icmpv6Packet(_)) = packet.get_transport_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_arp(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::ArpPacket(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv6(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::Ipv6Packet(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_ipv4(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::Ipv4Packet(_)) = packet.get_network_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_tls(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::TlsPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_dns(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::DnsPacket(_)) = packet.get_application_layer_packet() {
        return true;
    }

    return false;
}

pub fn contains_http(packet: &ParsedPacket) -> bool {
    if let Some(SerializablePacket::HttpRequestPacket(_))
    | Some(SerializablePacket::HttpResponsePacket(_)) = packet.get_application_layer_packet()
    {
        return true;
    }

    return false;
}
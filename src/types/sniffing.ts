import {EchoReply, EchoRequest, IcmpPacket, Icmpv6Packet, TcpPacket, UdpPacket} from "../serializable_packet/transport";
import {EthernetPacket} from "../serializable_packet/link";
import {ArpPacket, Ipv4Packet, Ipv6Packet} from "../serializable_packet/network";

export enum SniffingStatus {
    Inactive,
    Paused,
    Active
}

export type FeedbackMessage = {
    text: string,
    isError: boolean,
    duration: number
}

export interface SerializableTransportLayerPacket {
    toDisplay(): any;
    toString(): string;
    getType(): string;
    getInfo(): string;
}

export interface SerializableNetworkLayerPacket {
    toDisplay(): any;
    toString(): string;
    getSource(): string;
    getDestination(): string;
}

export interface SerializableLinkLayerPacket {
    toDisplay(): any;
    toString(): string;
    getPayload(): number[];
    getSource(): string;
    getDestination(): string;
}

export class GeneralPacket {
    id: number;
    type: string;
    length: number;
    info: string;
    sourceMAC: string;
    destinationMAC: string;
    sourceIP: string;
    destinationIP: string;
    packet: Packet;

    constructor(id: number, packet: any) {
        this.id = id;

        let link_layer: SerializableLinkLayerPacket | null = null;
        let network_layer: SerializableNetworkLayerPacket | null = null;
        let transport_layer: SerializableTransportLayerPacket | null = null;

        link_layer = make_link_level_packet(packet.linkLayerPacket);
        network_layer = make_network_level_packet(packet.networkLayerPacket);
        transport_layer = make_transport_level_packet(packet.transportLayerPacket);

        this.type = transport_layer ? transport_layer.getType() : ""; // todo last when add application layer
        this.info = transport_layer ? transport_layer.getInfo() : ""; // todo last when add application layer
        this.sourceMAC = link_layer ? link_layer.getSource() : "";
        this.destinationMAC = link_layer ? link_layer.getDestination() : "";
        this.sourceIP = network_layer ? network_layer.getSource() : "";
        this.destinationIP = network_layer ? network_layer.getDestination() : "";
        this.length = link_layer ? link_layer.getPayload().length : 0;
        this.packet = new Packet(link_layer, network_layer, transport_layer);
    }

}

/* ParsedPacket */

export class Packet {
    link_layer_packet: SerializableLinkLayerPacket | null;
    network_layer_packet: SerializableNetworkLayerPacket | null;
    transport_layer_packet: SerializableTransportLayerPacket | null;

    constructor(
        link_layer_packet: SerializableLinkLayerPacket | null,
        network_layer_packet: SerializableNetworkLayerPacket | null,
        transport_layer_packet: SerializableTransportLayerPacket | null
    ) {
        this.link_layer_packet = link_layer_packet;
        this.network_layer_packet = network_layer_packet;
        this.transport_layer_packet = transport_layer_packet;
    }
}

const make_transport_level_packet = (transport: any) => {
    if (!transport) return null;
    let transport_layer: SerializableTransportLayerPacket | null = null

    switch (transport.type) {
        case "TcpPacket":
            transport_layer = new TcpPacket(
                transport.packet.source,
                transport.packet.destination,
                transport.packet.sequence,
                transport.packet.acknowledgement,
                transport.packet.data_offset,
                transport.packet.reserved,
                transport.packet.flags,
                transport.packet.window,
                transport.packet.checksum,
                transport.packet.urgent_ptr,
                transport.packet.options,
                transport.packet.payload
            )
            break;

        case "UdpPacket":
            transport_layer = new UdpPacket(
                transport.packet.source,
                transport.packet.destination,
                transport.packet.length,
                transport.packet.checksum,
                transport.packet.payload
            )
            break;

        case "Icmpv6Packet":
            transport_layer = new Icmpv6Packet(
                transport.packet.icmpv6_type,
                transport.packet.icmpv6_code,
                transport.packet.checksum,
                transport.packet.payload
            )
            break;

        case "IcmpPacket":
            transport_layer = new IcmpPacket(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.payload
            )
            break;

        case "EchoReplyPacket":
            transport_layer = new EchoReply(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.identifier,
                transport.packet.sequence_number,
                transport.packet.payload
            )
            break;

        case "EchoRequestPacket":
            transport_layer = new EchoRequest(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.identifier,
                transport.packet.sequence_number,
                transport.packet.payload
            )
            break;

        default:
            console.log("Malformed packet") // TODO
    }

    return transport_layer;
}

const make_link_level_packet = (link: any) => {
    if (!link) return null;
    let link_layer: SerializableLinkLayerPacket | null = null;

    switch (link.type) {
        case "EthernetPacket":
            link_layer = new EthernetPacket(
                link.packet.destination,
                link.packet.source,
                link.packet.ethertype,
                link.packet.payload
            )
            break;

        default:
            console.log("Malformed packet") // TODO
    }

    return link_layer;
}

const make_network_level_packet = (network: any) => {
    if (!network) return null;
    let network_layer: SerializableNetworkLayerPacket | null = null;

    switch (network.type) {
        case "ArpPacket":
            network_layer = new ArpPacket(
                network.packet.hardware_type,
                network.packet.protocol_type,
                network.packet.hw_addr_len,
                network.packet.proto_addr_len,
                network.packet.operation,
                network.packet.sender_hw_addr,
                network.packet.sender_proto_addr,
                network.packet.target_hw_addr,
                network.packet.target_proto_addr,
                network.packet.payload
            )
            break;

        case "Ipv4Packet":
            network_layer = new Ipv4Packet(
                network.packet.version,
                network.packet.header_length,
                network.packet.dscp,
                network.packet.ecn,
                network.packet.total_length,
                network.packet.identification,
                network.packet.flags,
                network.packet.fragment_offset,
                network.packet.ttl,
                network.packet.next_level_protocol,
                network.packet.checksum,
                network.packet.source,
                network.packet.destination,
                network.packet.payload
            )
            break;

        case "Ipv6Packet":
            network_layer = new Ipv6Packet(
                network.packet.version,
                network.packet.traffic_class,
                network.packet.flow_label,
                network.packet.payload_length,
                network.packet.next_header,
                network.packet.hop_limit,
                network.packet.source,
                network.packet.destination,
                network.packet.payload
            )
            break;

        default:
            console.log("Malformed packet") // TODO
    }

    return network_layer;
}

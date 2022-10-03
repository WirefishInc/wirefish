import {EchoReply, EchoRequest, IcmpPacket, Icmpv6Packet, TcpPacket, UdpPacket} from "./serializable_packets/transport";
import {EthernetPacket, UnknownLinkPacket} from "./serializable_packets/link";
import {ArpPacket, Ipv4Packet, Ipv6Packet} from "./serializable_packets/network";
import {DnsPacket, HttpRequestPacket, HttpResponsePacket, TlsPacket} from "./serializable_packets/application";

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
    type: string;

    toDisplay(): any;

    toString(): string;

    getType(): string;

    getInfo(): string;
}

export interface SerializableNetworkLayerPacket {
    type: string;

    toDisplay(): any;

    toString(): string;

    getSource(): string;

    getDestination(): string;

    getType(): string;

    getInfo(): string;
}

export interface SerializableLinkLayerPacket {
    type: string;

    toDisplay(): any;

    toString(): string;

    getPayload(): number[];

    getSource(): string;

    getDestination(): string;

    getType(): string;

    getInfo(): string;
}

export interface SerializableApplicationLayerPacket {
    type: string;

    toDisplay(): any;

    toString(): string;

    getType(): string;

    getInfo(): string;
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
    sourcePort: number | null;
    destinationPort: number | null;
    layers: string[]
    packet: Packet;

    constructor(id: number, packet: any) {
        this.id = id;
        this.layers = [];
        this.sourcePort = null;
        this.destinationPort = null;

        let link_layer: SerializableLinkLayerPacket | MalformedPacket | UnknownLinkPacket | UnknownPacket;
        let network_layer: SerializableNetworkLayerPacket | MalformedPacket | UnknownPacket | null;
        let transport_layer: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket | null;
        let application_layer: SerializableApplicationLayerPacket | MalformedPacket | UnknownPacket | null;

        link_layer = make_link_level_packet(packet.linkLayerPacket);
        network_layer = make_network_level_packet(packet.networkLayerPacket);
        transport_layer = make_transport_level_packet(packet.transportLayerPacket);
        application_layer = make_application_level(packet.applicationLayerPacket);

        if (application_layer) {
            this.type = application_layer.getType();
            this.info = application_layer.getInfo();

        } else if (transport_layer) {
            this.type = transport_layer.getType();
            this.info = transport_layer.getInfo();

        } else if (network_layer) {
            this.type = network_layer.getType();
            this.info = network_layer.getInfo();

        } else {
            this.type = link_layer.getType();
            this.info = link_layer.getInfo();
        }

        this.sourceMAC = link_layer.getSource();
        this.destinationMAC = link_layer.getDestination();
        this.sourceIP = network_layer ? network_layer.getSource() : "";
        this.destinationIP = network_layer ? network_layer.getDestination() : "";
        this.length = link_layer.getPayload().length;

        if (application_layer) this.layers.push(application_layer.getType());
        if (transport_layer) this.layers.push(transport_layer.getType());
        if (transport_layer instanceof UdpPacket || transport_layer instanceof TcpPacket) {
            this.sourcePort = transport_layer.source;
            this.destinationPort = transport_layer.destination;
        }
        if (network_layer)
            this.layers.push(network_layer.getType());
        this.layers.push(link_layer.getType());

        this.packet = new Packet(link_layer, network_layer, transport_layer, application_layer);
    }
}

/* Parsed Packet */

export class Packet {
    link_layer_packet: SerializableLinkLayerPacket | UnknownLinkPacket | MalformedPacket | UnknownPacket;
    network_layer_packet: SerializableNetworkLayerPacket | MalformedPacket | UnknownPacket | null;
    transport_layer_packet: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket | null;
    application_layer_packet: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket | null;

    constructor(
        link_layer_packet: SerializableLinkLayerPacket | UnknownLinkPacket | MalformedPacket | UnknownPacket,
        network_layer_packet: SerializableNetworkLayerPacket | MalformedPacket | UnknownPacket | null,
        transport_layer_packet: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket | null,
        application_layer_packet: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket | null
    ) {
        this.link_layer_packet = link_layer_packet;
        this.network_layer_packet = network_layer_packet;
        this.transport_layer_packet = transport_layer_packet;
        this.application_layer_packet = application_layer_packet;
    }
}

const make_transport_level_packet = (transport: any) => {
    if (!transport) return null;
    let transport_layer: SerializableTransportLayerPacket | MalformedPacket | UnknownPacket;

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
                transport.packet.length,
                transport.packet.options,
            )
            break;

        case "UdpPacket":
            transport_layer = new UdpPacket(
                transport.packet.source,
                transport.packet.destination,
                transport.packet.length,
                transport.packet.checksum,
            )
            break;

        case "Icmpv6Packet":
            transport_layer = new Icmpv6Packet(
                transport.packet.icmpv6_type,
                transport.packet.icmpv6_code,
                transport.packet.checksum,
                transport.packet.length
            )
            break;

        case "IcmpPacket":
            transport_layer = new IcmpPacket(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.length
            )
            break;

        case "EchoReplyPacket":
            transport_layer = new EchoReply(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.identifier,
                transport.packet.sequence_number,
                transport.packet.length
            )
            break;

        case "EchoRequestPacket":
            transport_layer = new EchoRequest(
                transport.packet.icmp_type,
                transport.packet.icmp_code,
                transport.packet.checksum,
                transport.packet.identifier,
                transport.packet.sequence_number,
                transport.packet.length
            )
            break;

        case "MalformedPacket":
            transport_layer = new MalformedPacket();
            break;

        default:
            transport_layer = new UnknownPacket();
    }

    return transport_layer;
}

const make_link_level_packet = (link: any) => {
    let link_layer: SerializableLinkLayerPacket | MalformedPacket | UnknownLinkPacket | UnknownPacket;

    switch (link.type) {
        case "EthernetPacket":
            link_layer = new EthernetPacket(
                link.packet.destination,
                link.packet.source,
                link.packet.ethertype,
                link.packet.payload
            )
            break;

        case "UnknownPacket":
            link_layer = new UnknownLinkPacket(
                link.packet.destination,
                link.packet.source,
                link.packet.ethertype,
                link.packet.length
            )
            break;

        case "MalformedPacket":
            link_layer = new MalformedPacket();
            break;

        default:
            link_layer = new UnknownPacket();
    }

    return link_layer;
}

const make_network_level_packet = (network: any) => {
    if (!network) return null;
    let network_layer: SerializableNetworkLayerPacket | MalformedPacket | UnknownPacket;

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
                network.packet.length
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
                network.packet.length
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
            )
            break;

        case "MalformedPacket":
            network_layer = new MalformedPacket();
            break;

        default:
            network_layer = new UnknownPacket();
    }

    return network_layer;
}

const make_application_level = (application: any) => {
    if (!application) return null;
    let application_layer: SerializableApplicationLayerPacket | MalformedPacket | UnknownPacket;

    switch (application.type) {
        case "TlsPacket":
            application_layer = new TlsPacket(
                application.packet.version,
                application.packet.messages,
                application.packet.length
            )
            break;

        case "HttpRequestPacket":
            application_layer = new HttpRequestPacket(
                application.packet.method,
                application.packet.path,
                application.packet.version,
                application.packet.headers,
                application.packet.payload
            )
            break;

        case "HttpResponsePacket":
            application_layer = new HttpResponsePacket(
                application.packet.version,
                application.packet.code,
                application.packet.reason,
                application.packet.headers,
                application.packet.payload
            )
            break;

        case "DnsPacket":
            application_layer = new DnsPacket(
                application.packet.header,
                application.packet.questions,
                application.packet.answers,
                application.packet.nameservers,
                application.packet.additional
            )
            break;

        case "MalformedPacket":
            application_layer = new MalformedPacket();
            break;

        default:
            application_layer = new UnknownPacket();
    }

    return application_layer;
}

/* Malformed and Unknown Packets */

export class MalformedPacket {
    type: string;

    constructor() {
        this.type = "Malformed"
    }

    toDisplay() {
        return []
    }

    toString(): string {
        return "Malformed Packet"
    }

    getType(): string {
        return this.type
    }

    getInfo(): string {
        return "Malformed Packet"
    }

    getSource(): string {
        return ""
    }

    getDestination(): string {
        return ""
    }

    getPayload(): number[] {
        return []
    }
}

export class UnknownPacket {
    type: string;

    constructor() {
        this.type = "Unknown"
    }

    toDisplay() {
        return []
    }

    toString(): string {
        return "Unknown Packet"
    }

    getType(): string {
        return this.type
    }

    getInfo(): string {
        return "Unknown Packet"
    }

    getSource(): string {
        return ""
    }

    getDestination(): string {
        return ""
    }

    getPayload(): number[] {
        return []
    }
}
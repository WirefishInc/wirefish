import {SerializableNetworkLayerPacket} from "../types/sniffing";

export class ArpPacket implements SerializableNetworkLayerPacket {
    hardware_type: string;
    protocol_type: number;
    hw_addr_len: number;
    proto_addr_len: number;
    operation: string;
    sender_hw_addr: string;
    sender_proto_addr: string;
    target_hw_addr: string;
    target_proto_addr: string;
    payload: [];
    type: string;

    constructor(
        hardware_type: string,
        protocol_type: number,
        hw_addr_len: number,
        proto_addr_len: number,
        operation: string,
        sender_hw_addr: string,
        sender_proto_addr: string,
        target_hw_addr: string,
        target_proto_addr: string,
        payload: []
    ) {
        this.hardware_type = hardware_type;
        this.protocol_type = protocol_type;
        this.hw_addr_len = hw_addr_len;
        this.proto_addr_len = proto_addr_len;
        this.operation = operation;
        this.sender_hw_addr = sender_hw_addr;
        this.sender_proto_addr = sender_proto_addr;
        this.target_hw_addr = target_hw_addr;
        this.target_proto_addr = target_proto_addr;
        this.payload = payload;
        this.type = "Arp Packet"
    }
}

export class Ipv6Packet implements SerializableNetworkLayerPacket{
    version: number;
    traffic_class: number;
    flow_label: number;
    payload_length: number;
    next_header: string;
    hop_limit: number;
    source: string;
    destination: string;
    payload: [];
    type: string;

    constructor(
        version: number,
        traffic_class: number,
        flow_label: number,
        payload_length: number,
        next_header: string,
        hop_limit: number,
        source: string,
        destination: string,
        payload: []
    ) {
        this.version = version;
        this.traffic_class = traffic_class;
        this.flow_label = flow_label;
        this.payload_length = payload_length;
        this.next_header = next_header;
        this.hop_limit = hop_limit;
        this.source = source;
        this.destination = destination;
        this.payload = payload;
        this.type = "Ipv6 Packet"
    }
}


export class Ipv4Packet implements SerializableNetworkLayerPacket {
    version: number;
    header_length: number;
    dscp: number;
    ecn: number;
    total_length: number;
    identification: number;
    flags: number;
    fragment_offset: number;
    ttl: number;
    next_level_protocol: string;
    checksum: number;
    source: string;
    destination: string;
    payload: [];
    type: string;

    constructor(
        version: number,
        header_length: number,
        dscp: number,
        ecn: number,
        total_length: number,
        identification: number,
        flags: number,
        fragment_offset: number,
        ttl: number,
        next_level_protocol: string,
        checksum: number,
        source: string,
        destination: string,
        payload: [],
    ) {
        this.version = version;
        this.header_length = header_length;
        this.dscp = dscp;
        this.ecn = ecn;
        this.total_length = total_length;
        this.identification = identification;
        this.flags = flags;
        this.fragment_offset = fragment_offset;
        this.ttl = ttl;
        this.next_level_protocol = next_level_protocol;
        this.checksum = checksum;
        this.source = source;
        this.destination = destination;
        this.payload = payload;
        this.type = "Ipv4 Packet"
    }
}
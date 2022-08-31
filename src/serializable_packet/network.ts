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
        this.hw_addr_len = hw_addr_len; // todo
        this.proto_addr_len = proto_addr_len; // todo
        this.operation = operation;
        this.sender_hw_addr = sender_hw_addr; // todo
        this.sender_proto_addr = sender_proto_addr; // todo
        this.target_hw_addr = target_hw_addr; // todo
        this.target_proto_addr = target_proto_addr; // todo
        this.payload = payload;
        this.type = "Arp Packet"
    }
    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Hardware Type" : this.hardware_type});
        packet_info.push( {"Protocol Type" : this.protocol_type});
        packet_info.push( {"Operation" : this.operation});

        return packet_info;
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
        this.type = "Internet Protocol Version 6"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Protocol Version" : this.version});
        packet_info.push( {"Traffic Class" : this.traffic_class});
        packet_info.push( {"Flow Label" : this.flow_label});
        packet_info.push( {"Payload Length" : this.payload_length});
        packet_info.push( {"Next Header" : this.next_header});
        packet_info.push( {"Hop Limit" : this.hop_limit});
        packet_info.push( {"Source IP" : this.source});
        packet_info.push( {"Destination IP" : this.destination});

        return packet_info;
    }

    public toString(): string {
        return this.type+", Src: "+this.source+", Dst: "+this.destination
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
        this.dscp = dscp; // todo
        this.ecn = ecn; // todo
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
        this.type = "Internet Protocol Version 4"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Protocol Version" : this.version});
        packet_info.push( {"Header Length" : this.header_length});
        packet_info.push( {"Total Length" : this.total_length});
        packet_info.push( {"Identidication" : this.identification});
        packet_info.push( {"Flags" : this.flags});
        packet_info.push( {"Fragment Offset" : this.fragment_offset});
        packet_info.push( {"Time To Live (TTL)" : this.ttl});
        packet_info.push( {"Next Level Protocol" : this.next_level_protocol});
        packet_info.push( {"Checksum" : this.checksum});
        packet_info.push( {"Source IP" : this.source});
        packet_info.push( {"Destination IP" : this.destination});

        return packet_info;
    }

    public toString(): string {
        return this.type+", Src: "+this.source+", Dst: "+this.destination
    }
}
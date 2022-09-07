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
        this.type = "Address Resolution Protocol (request/gratuitous ARP)"
    }
    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Hardware Type" : this.hardware_type});
        packet_info.push( {"Protocol Type" : this.protocol_type});
        packet_info.push( {"Operation" : this.operation});
        packet_info.push( {"Hardware size" : this.hw_addr_len});
        packet_info.push( {"Protocol size" : this.proto_addr_len});
        packet_info.push( {"Sender MAC Address" : this.sender_hw_addr});
        packet_info.push( {"Sender IP Address" : this.sender_proto_addr});
        packet_info.push( {"Target MAC Address" : this.target_hw_addr});
        packet_info.push( {"Target IP Address" : this.target_proto_addr});

        return packet_info;
    }

    public toString(): string {
        return this.type
    }

    getDestination(): string {
        return this.target_proto_addr;
    }

    getSource(): string {
        return this.sender_proto_addr;
    }

    getInfo(): string {
        return "Who has "+this.target_proto_addr+"?";
    }

    getType(): string {
        return "ARP";
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

    getDestination(): string {
        return this.destination;
    }

    getSource(): string {
        return this.source;
    }

    getInfo(): string {
        return "";
    }

    getType(): string {
        return "IPv6";
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
        this.type = "Internet Protocol Version 4"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Protocol Version" : this.version});
        packet_info.push( {"Header Length" : this.header_length});
        packet_info.push( {"Total Length" : this.total_length});
        packet_info.push( {"Identidication" : this.identification});
        packet_info.push( {"Differentiated Services Field (DSCP)" : this.dscp});
        packet_info.push( {"ECN" : this.ecn});
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

    getDestination(): string {
        return this.destination;
    }

    getSource(): string {
        return this.source;
    }

    getInfo(): string {
        return "";
    }

    getType(): string {
        return "IPv4";
    }
}
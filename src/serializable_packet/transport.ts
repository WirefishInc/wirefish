import {SerializableTransportLayerPacket} from "../types/sniffing";

export class TcpPacket implements SerializableTransportLayerPacket {
    source: number;
    destination: number;
    sequence: number;
    acknowledgement: number;
    data_offset: number;
    reserved: number;
    flags: number;
    window: number;
    checksum: number;
    urgent_ptr: number;
    options: [];
    payload: [];
    type: string;

    constructor(
        source: number,
        destination: number,
        sequence: number,
        acknowledgement: number,
        data_offset: number,
        reserved: number,
        flags: number,
        window: number,
        checksum: number,
        urgent_ptr: number,
        options: [],
        payload: [],
    ) {
        this.source = source;
        this.destination = destination;
        this.sequence = sequence;
        this.acknowledgement = acknowledgement;
        this.data_offset = data_offset;
        this.reserved = reserved;
        this.flags = flags;
        this.window = window;
        this.checksum = checksum;
        this.urgent_ptr = urgent_ptr;
        this.options = options;
        this.payload = payload;
        this.type = "Tcp Packet"
    }
}

export class UdpPacket implements SerializableTransportLayerPacket {
    source: number;
    destination: number;
    length: number;
    checksum: number;
    payload: [];
    type: string;

    constructor(
        source: number,
        destination: number,
        length: number,
        checksum: number,
        payload: []
    ) {
        this.source = source;
        this.destination = destination;
        this.length = length;
        this.checksum = checksum;
        this.payload = payload;
        this.type ="Udp Packet"
    }
}

export class Icmpv6Packet implements SerializableTransportLayerPacket {
    icmpv6_type: number;
    icmpv6_code: number;
    checksum: number;
    payload: [];
    type: string;

    constructor(
        icmpv6_type: number,
        icmpv6_code: number,
        checksum: number,
        payload: []
    ) {
        this.icmpv6_type = icmpv6_type;
        this.icmpv6_code = icmpv6_code;
        this.checksum = checksum;
        this.payload = payload;
        this.type = "Icmpv6 Packet"
    }
}

export class IcmpPacket implements SerializableTransportLayerPacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    payload: [];
    type: string;

    constructor(
        icmp_type: number,
        icmp_code: number,
        checksum: number,
        payload: []
    ) {
        this.icmp_type = icmp_type;
        this.icmp_code = icmp_code;
        this.checksum = checksum;
        this.payload = payload;
        this.type = "Icmp packet"
    }
}

export class EchoReply implements SerializableTransportLayerPacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    identifier: number;
    sequence_number: number;
    payload: [];
    type: string;

    constructor(
        icmp_type: number,
        icmp_code: number,
        checksum: number,
        identifier: number,
        sequence_number: number,
        payload: []
    ) {
        this.icmp_type = icmp_type;
        this.icmp_code = icmp_code;
        this.checksum = checksum;
        this.identifier = identifier;
        this.sequence_number = sequence_number;
        this.payload = payload;
        this.type = "EchoReply Packet";
    }
}

export class EchoRequest implements SerializableTransportLayerPacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    identifier: number;
    sequence_number: number;
    payload: [];
    type: string;

    constructor(
        icmp_type: number,
        icmp_code: number,
        checksum: number,
        identifier: number,
        sequence_number: number,
        payload: []
    ) {
        this.icmp_type = icmp_type;
        this.icmp_code = icmp_code;
        this.checksum = checksum;
        this.identifier = identifier;
        this.sequence_number = sequence_number;
        this.payload = payload;
        this.type = "Echo Request Packet";
    }
}


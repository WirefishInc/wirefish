import {SerializablePacket} from "../types/sniffing";

export class TcpPacket implements SerializablePacket {
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
    }
}

export class UdpPacket implements SerializablePacket {
    source: number;
    destination: number;
    length: number;
    checksum: number;
    payload: [];

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
    }
}

export class Icmpv6Packet implements SerializablePacket {
    icmpv6_type: number;
    icmpv6_code: number;
    checksum: number;
    payload: [];

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
    }
}

export class IcmpPacket implements SerializablePacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    payload: [];

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
    }
}

export class EchoReply implements SerializablePacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    identifier: number;
    sequence_number: number;
    payload: []

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
    }
}

export class EchoRequest implements SerializablePacket {
    icmp_type: number;
    icmp_code: number;
    checksum: number;
    identifier: number;
    sequence_number: number;
    payload: []

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
    }
}


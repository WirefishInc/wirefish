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

//udp
//icmpv6
//icmp
//echo reply
//echo request
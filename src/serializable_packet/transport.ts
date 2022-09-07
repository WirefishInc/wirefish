import {SerializableTransportLayerPacket} from "../types/sniffing";

/* rev */
const TCPflags = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECN", "CWR", "Nonce", "Reserved"]

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
        this.type = "Transmission Control Protocol"
    }

    getType(): string {
        return "TCP";
    }

    getInfo(): string {
        return this.source + " -> " + this.destination + " " + this.getFlags(this.flags) + " " +
            "Seq=" + this.sequence + " Ack=" + this.acknowledgement + " " +
            "Win=" + this.window + " Len=" + this.payload.length;
    }

    getFlags(flags: number): string {
        let f = flags.toString(2);

        let res = "[";

        for (let i = f.length - 1; i >= 0; i--) {
            if (f[i] === "1")
                res += TCPflags[i] + ",";
        }

        return res.slice(0, -1) + "]";
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"Destination Port": this.destination});
        packet_info.push({"Source Port": this.source});
        packet_info.push({"Sequence": this.sequence});
        packet_info.push({"Acknowledgment (ACK)": this.acknowledgement});
        packet_info.push({"Data Offset": this.data_offset});
        packet_info.push({"Reserved": this.reserved});
        packet_info.push({"Flags": this.flags});
        packet_info.push({"Windows": this.window});
        packet_info.push({"Checksum": this.checksum});
        packet_info.push({"Urgent Pointer": this.urgent_ptr});
        packet_info.push({"Options MAC": this.options});

        return packet_info;
    }

    public toString(): string {
        return this.type + ", Src Port: " + this.source + ", Dst Port: " + this.destination + ", Seq: " + this.sequence +
            ", Ack: " + this.acknowledgement
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
        this.type = "User Datagram Protocol"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"Source": this.source});
        packet_info.push({"Destination": this.destination});
        packet_info.push({"Length": this.length});
        packet_info.push({"Checksum": this.checksum});

        return packet_info;
    }

    public toString(): string {
        return this.type + ", Src Port: " + this.source + ", Dst Port: " + this.destination
    }

    getInfo(): string {
        return this.source + " -> " + this.destination + " Len=" + this.payload.length;
    }

    getType(): string {
        return "UDP";
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
        this.type = "Internet Control Message Protocol v6"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"ICMP v6 Type": this.icmpv6_type});
        packet_info.push({"ICMP v6 Code": this.icmpv6_code});
        packet_info.push({"Checksum": this.checksum});

        return packet_info;
    }

    public toString(): string {
        return this.type
    }

    getInfo(): string {
        return ""; // TODO
    }

    getType(): string {
        return "ICMPv6";
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
        this.type = "Internet Control Message Protocol"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"ICMP Type": this.icmp_type});
        packet_info.push({"ICMP Code": this.icmp_code});
        packet_info.push({"Checksum": this.checksum});

        return packet_info;
    }

    public toString(): string {
        return this.type
    }

    getInfo(): string {
        return ""; // TODO
    }

    getType(): string {
        return "ICMP";
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
        this.type = "Internet Control Message Protocol - Echo Reply";
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"ICMP Type": this.icmp_type});
        packet_info.push({"ICMP Code": this.icmp_code});
        packet_info.push({"Checksum": this.checksum});
        packet_info.push({"Identifier": this.identifier});
        packet_info.push({"Sequence Number": this.sequence_number});

        return packet_info;
    }

    public toString(): string {
        return this.type
    }

    getInfo(): string {
        return ""; // TODO
    }

    getType(): string {
        return ""; // TODO
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
        this.type = "Internet Control Message Protocol - Echo Request";
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"ICMP Type": this.icmp_type});
        packet_info.push({"ICMP Code": this.icmp_code});
        packet_info.push({"Checksum": this.checksum});
        packet_info.push({"Identifier": this.identifier});
        packet_info.push({"Sequence Number": this.sequence_number});

        return packet_info;
    }

    public toString(): string {
        return this.type
    }

    getInfo(): string {
        return ""; // TODO
    }

    getType(): string {
        return ""; // TODO
    }
}


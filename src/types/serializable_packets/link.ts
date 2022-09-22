import {SerializableLinkLayerPacket} from "../sniffing"

export class EthernetPacket implements SerializableLinkLayerPacket {
    destination: string;
    source: string;
    ethertype: string;
    payload: number[];
    type: string;

    constructor(destination: string, source: string, ethertype: string, payload: number[]) {
        this.destination = destination;
        this.source = source;
        this.ethertype = ethertype;
        this.payload = payload;
        this.type = "Ethernet"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push({"Destination MAC": this.destination});
        packet_info.push({"Source MAC": this.source});
        packet_info.push({"Ethertype": this.ethertype});

        return packet_info;
    }

    public toString(): string {
        return this.type + ", src: " + this.source + ", dst: " + this.destination
    }

    public getPayload(): number[] {
        return this.payload;
    }

    getDestination(): string {
        return this.destination;
    }

    getSource(): string {
        return this.source;
    }

    getInfo(): string {
        return "Ethernet Packet";
    }

    getType(): string {
        return this.type;
    }
}

export class UnknownLinkPacket implements SerializableLinkLayerPacket {
    destination: string;
    source: string;
    ethertype: string;
    length: number;
    type: string;

    constructor(
        destination: string,
        source: string,
        ethertype: string,
        length: number
    ) {
        this.destination = destination;
        this.source = source;
        this.ethertype = ethertype;
        this.length = length;
        this.type = "Unknown Packet";
    }

    getDestination(): string {
        return this.destination;
    }

    getPayload(): number[] {
        return [];
    }

    getSource(): string {
        return this.source;
    }

    toDisplay(): any[] {
        let result = [];

        result.push({"Destination": this.destination})
        result.push({"Source": this.source})
        result.push({"Ethertype": this.ethertype})
        result.push({"Length": this.length})

        return result;
    }

    getInfo(): string {
        return "Unknown Packet";
    }

    getType(): string {
        return "Unknown";
    }

    toString(): string {
        return this.type
    }
}
